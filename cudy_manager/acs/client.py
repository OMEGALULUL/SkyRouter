"""Blocking client for the GenieACS 1.2 northbound REST API (the NBI).

Written against the documented behaviour of GenieACS 1.2.10-1.2.16; no GenieACS
code is used. Call it from async code through asyncio.to_thread.

Three properties of the NBI shape everything here:

* It has no authentication and exposes secrets through its generic collection
  route (F3), so the client only talks to a loopback address unless told otherwise,
  and only ever reads the handful of collections SkyRouter needs.
* Input it cannot handle kills the worker serving it instead of returning 400, and
  repeated crashes stop the service (F13). Every ID, name, query, projection and
  task is therefore checked here before any request is made.
* Several outcomes are reported only in the HTTP reason phrase (F10-F12), which is
  why HttpResponse carries it.
"""

import ipaddress
import json
import logging
import re
import urllib.parse
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, NoReturn, TypeVar

from ..adapters import AdapterError
from ..http_client import HttpError, HttpResponse, HttpSession
from ..models import ValidationError
from .tasks import ALLOWED_TASK_NAMES, JOB_RE, STEP_RE, UNIQUE_KEY_RE, Task, validate_task

logger = logging.getLogger(__name__)

T = TypeVar("T")


class AcsError(AdapterError):
    """Anything the ACS did that SkyRouter cannot use. web.py maps AdapterError to 502."""

    def __init__(self, message: str, *, status: int | None = None, reason: str = ""):
        super().__init__(message)
        self.status = status
        self.reason = reason


class AcsUnavailable(AcsError):
    """No usable reply: refused, reset, timed out, or cut short (a probable worker crash, F13).

    ``outcome_unknown`` is set when a write may have taken effect and the client
    could not find out whether it did.
    """

    def __init__(self, message: str, *, outcome_unknown: bool = False, **kwargs: Any):
        super().__init__(message, **kwargs)
        self.outcome_unknown = outcome_unknown


class AcsNotFound(AcsError):
    """404: "No such device" or "Task not found"."""


class AcsBusy(AcsError):
    """503 "Device is in session": the router is mid-session, so try again shortly."""


class AcsRejected(AcsError):
    """400. Local validation should make this impossible, so it points at a SkyRouter bug."""


@dataclass(frozen=True)
class Page:
    items: list[dict[str, Any]]
    # From the NBI's total header: every match, ignoring skip and limit (F8).
    total: int


@dataclass(frozen=True)
class CrResult:
    # True only means the router answered the connection request, not that a session ran (F11).
    ok: bool
    reason: str


VERSION_HEADER = "Genieacs-Version"
TOTAL_HEADER = "Total"
# The bare connection request waits a couple of seconds per attempt on the router,
# twice with Digest authentication; anything past this is a hung NBI.
CONNECTION_REQUEST_TIMEOUT = 30.0

# Exactly what GenieACS generates (F5): each part escapes everything outside
# [A-Za-z0-9_] as uppercase %XX, and the parts are joined with "-".
_DEVICE_ID_RE = re.compile(r"(?:[A-Za-z0-9_]|%[0-9A-F]{2})+(?:-(?:[A-Za-z0-9_]|%[0-9A-F]{2})+){1,2}")
MAX_DEVICE_ID_LENGTH = 256
# Names and tags never need "." or "~", which the NBI's routes refuse raw (F6).
_NAME_RE = re.compile(r"[a-z0-9_-]{1,48}")
_TASK_ID_RE = re.compile(r"[0-9a-f]{24}")
# A task channel's suffix becomes a MongoDB ObjectId, which throws on anything but hex.
_CHANNEL_RE = re.compile(r"task_[0-9a-f]{24}|(?!task_)[A-Za-z0-9_-]{1,64}")
_FAULT_CODE_RE = re.compile(r"[A-Za-z0-9_.]{1,64}")
# Free text uses GenieACS's own "*" wildcard (F8) rather than a regex. A value shaped
# like /re/ would be run as one, so "/" is not allowed, and an interior "*" is not
# either because only the first is expanded.
_SEARCH_RE = re.compile(r"\*?[A-Za-z0-9_.:-]{1,64}\*?")
_TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z")
_PROJECTION_RE = re.compile(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*")
_VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)(?:[-+][0-9A-Za-z.+-]*)?")
_UNPRINTABLE_RE = re.compile(r"[\x00-\x1f\x7f]+")

MAX_LIMIT = 200
MAX_SKIP = 1_000_000
MAX_LISTED = 1000
MAX_IN_VALUES = 200
MAX_PROJECTION = 64
MAX_QUERY_KEYS = 16
MAX_SCRIPT_BYTES = 256 * 1024


# --- validation -------------------------------------------------------------------


def validate_device_id(device_id: Any) -> str:
    if (
        not isinstance(device_id, str)
        or len(device_id) > MAX_DEVICE_ID_LENGTH
        or not _DEVICE_ID_RE.fullmatch(device_id)
    ):
        raise ValidationError("not a GenieACS device ID")
    return device_id


def validate_tag(tag: Any) -> str:
    if not isinstance(tag, str) or not _NAME_RE.fullmatch(tag):
        raise ValidationError("tags must be 1-48 lowercase letters, digits, '_' or '-'")
    return tag


def validate_name(name: Any, what: str = "name") -> str:
    if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
        raise ValidationError(f"{what} must be 1-48 lowercase letters, digits, '_' or '-'")
    return name


def validate_task_id(task_id: Any) -> str:
    if not isinstance(task_id, str) or not _TASK_ID_RE.fullmatch(task_id):
        raise ValidationError("task IDs are 24 lowercase hex characters")
    return task_id


def validate_fault_id(fault_id: Any) -> str:
    """``<device id>:<channel>``; a device ID never contains ":" because GenieACS escapes it."""
    if not isinstance(fault_id, str) or ":" not in fault_id:
        raise ValidationError("fault IDs look like <device id>:<channel>")
    device_id, _, channel = fault_id.partition(":")
    validate_device_id(device_id)
    if not _CHANNEL_RE.fullmatch(channel):
        raise ValidationError("fault channel must be task_<24 hex> or 1-64 letters, digits, '_' or '-'")
    return fault_id


def is_supported_version(version: str) -> bool:
    """1.2.10 to any later 1.2 release: the NBI contract this client is written against.

    1.3 (master) changes preset argument parsing and task handling (F1, F19); before
    1.2.10 unknown devices are not reported on tag writes and a crash still answers 500.
    """
    match = _VERSION_RE.fullmatch(version.strip())
    if not match:
        return False
    major, minor, patch = (int(part) for part in match.groups())
    return (major, minor) == (1, 2) and patch >= 10


def device_search_query(text: str) -> dict[str, Any]:
    """A free-text device search, as a query find() accepts."""
    if not isinstance(text, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,62}", text):
        raise ValidationError("search text may only contain letters, digits and _ . : -")
    pattern = f"*{text}*"
    return {
        "$or": [
            {"_id": pattern},
            {"_deviceId._SerialNumber": pattern},
            {"_deviceId._ProductClass": pattern},
            {"_deviceId._Manufacturer": pattern},
        ]
    }


def _match(regex: re.Pattern[str], what: str) -> Callable[[Any], Any]:
    def check(value: Any) -> Any:
        if not isinstance(value, str) or not regex.fullmatch(value):
            raise ValidationError(f"invalid {what} in ACS query")
        return value

    return check


def _one_of(allowed: frozenset[str], what: str) -> Callable[[Any], Any]:
    def check(value: Any) -> Any:
        if value not in allowed:
            raise ValidationError(f"invalid {what} in ACS query")
        return value

    return check


def _device_id_or_search(value: Any) -> Any:
    if isinstance(value, str) and (_SEARCH_RE.fullmatch(value) or _DEVICE_ID_RE.fullmatch(value)):
        return value
    raise ValidationError("invalid device ID in ACS query")


def _timestamp(value: Any) -> Any:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ValidationError("ACS query times must carry a timezone")
        return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    if isinstance(value, str) and _TIMESTAMP_RE.fullmatch(value):
        return value
    raise ValidationError("ACS query times must be UTC ISO-8601 strings such as 2026-09-28T09:15:02Z")


def _device_id_field(value: Any) -> Any:
    return validate_device_id(value)


def _task_id_field(value: Any) -> Any:
    return validate_task_id(value)


def _fault_id_field(value: Any) -> Any:
    return validate_fault_id(value)


@dataclass(frozen=True)
class _Collection:
    fields: Mapping[str, Callable[[Any], Any]]
    # Applied when the caller gives none, and the only fields a caller may project.
    # Set for tasks and faults: a Wi-Fi write stores the passphrase in a task's
    # parameterValues and in its fault's provisions, so those are never fetched.
    safe_projection: tuple[str, ...] | None = None


_TASK_FIELDS = (
    "_id",
    "name",
    "device",
    "timestamp",
    "expiry",
    "uniqueKey",
    "skyrouterJob",
    "skyrouterStep",
    "parameterNames",
    "objectName",
)
_FAULT_FIELDS = ("_id", "device", "channel", "timestamp", "code", "message", "detail", "retries", "expiry")

_COLLECTIONS: dict[str, _Collection] = {
    "devices": _Collection(
        {
            "_id": _device_id_or_search,
            "_tags": _match(_NAME_RE, "tag"),
            "_deviceId._Manufacturer": _match(_SEARCH_RE, "manufacturer"),
            "_deviceId._OUI": _match(_SEARCH_RE, "OUI"),
            "_deviceId._ProductClass": _match(_SEARCH_RE, "product class"),
            "_deviceId._SerialNumber": _match(_SEARCH_RE, "serial number"),
            "_lastInform": _timestamp,
            "_registered": _timestamp,
            "_lastBoot": _timestamp,
            "_lastBootstrap": _timestamp,
        }
    ),
    "tasks": _Collection(
        {
            "_id": _task_id_field,
            "device": _device_id_field,
            "name": _one_of(ALLOWED_TASK_NAMES, "task name"),
            "skyrouterJob": _match(JOB_RE, "job ID"),
            "skyrouterStep": _match(STEP_RE, "job step"),
            "uniqueKey": _match(UNIQUE_KEY_RE, "uniqueKey"),
            "timestamp": _timestamp,
        },
        safe_projection=_TASK_FIELDS,
    ),
    "faults": _Collection(
        {
            "_id": _fault_id_field,
            "device": _device_id_field,
            "channel": _match(_CHANNEL_RE, "fault channel"),
            "code": _match(_FAULT_CODE_RE, "fault code"),
            "timestamp": _timestamp,
        },
        safe_projection=_FAULT_FIELDS,
    ),
    "presets": _Collection({"_id": lambda value: validate_name(value, "preset name")}),
    "provisions": _Collection({"_id": lambda value: validate_name(value, "provision name")}),
}

# $ne and $not are left out on purpose: mixing either with another operator on one
# key throws inside GenieACS's query rewriting (F13).
_OPERATORS = frozenset({"$eq", "$in", "$lt", "$gt"})
_LOGICAL = frozenset({"$or", "$and"})


def _validate_condition(check: Callable[[Any], Any], condition: Any) -> Any:
    if not isinstance(condition, Mapping):
        return check(condition)
    if not condition or not set(condition) <= _OPERATORS:
        raise ValidationError(f"ACS query operators are limited to {', '.join(sorted(_OPERATORS))}")
    result: dict[str, Any] = {}
    for operator, operand in condition.items():
        if operator == "$in":
            if isinstance(operand, str) or not isinstance(operand, (list, tuple)):
                raise ValidationError("$in takes a list")
            if not 1 <= len(operand) <= MAX_IN_VALUES:
                raise ValidationError(f"$in takes 1-{MAX_IN_VALUES} values")
            result[operator] = [check(item) for item in operand]
        else:
            result[operator] = check(operand)
    return result


def _validate_query(spec: _Collection, query: Any, nested: bool = False) -> dict[str, Any]:
    if not isinstance(query, Mapping):
        raise ValidationError("ACS query must be an object")
    if len(query) > MAX_QUERY_KEYS:
        raise ValidationError("ACS query has too many conditions")
    result: dict[str, Any] = {}
    for key, condition in query.items():
        if key in _LOGICAL:
            # One level only, and never empty: GenieACS throws on a logical operator
            # whose value is not a list of objects.
            if nested:
                raise ValidationError("ACS queries cannot nest $or/$and")
            if isinstance(condition, str) or not isinstance(condition, (list, tuple)):
                raise ValidationError(f"{key} takes a list of conditions")
            if not 1 <= len(condition) <= MAX_QUERY_KEYS:
                raise ValidationError(f"{key} takes 1-{MAX_QUERY_KEYS} conditions")
            parts = [_validate_query(spec, part, nested=True) for part in condition]
            if any(not part for part in parts):
                raise ValidationError(f"{key} conditions cannot be empty")
            result[key] = parts
        elif isinstance(key, str) and key in spec.fields:
            result[key] = _validate_condition(spec.fields[key], condition)
        else:
            raise ValidationError(f"ACS queries cannot filter on {str(key)[:64]!r}")
    return result


def _validate_projection(spec: _Collection, projection: Sequence[str] | None) -> list[str] | None:
    if projection is None:
        return list(spec.safe_projection) if spec.safe_projection else None
    if isinstance(projection, str) or not isinstance(projection, (list, tuple)):
        raise ValidationError("projection must be a list of field paths")
    # An empty projection becomes {"": 1}, which MongoDB rejects inside the NBI (F8).
    if not 1 <= len(projection) <= MAX_PROJECTION:
        raise ValidationError(f"projection takes 1-{MAX_PROJECTION} field paths")
    for path in projection:
        if not isinstance(path, str) or len(path) > 256 or not _PROJECTION_RE.fullmatch(path):
            raise ValidationError("projection paths are dotted names of letters, digits, '_' and '-'")
        if spec.safe_projection is not None and path.split(".", 1)[0] not in spec.safe_projection:
            raise ValidationError(f"projection cannot include {path!r}")
    # MongoDB refuses a path together with its own ancestor on most collections, so
    # the ancestor alone is sent; it already covers the descendant.
    kept: list[str] = []
    for path in projection:
        if path in kept or any(path.startswith(other + ".") for other in projection if other != path):
            continue
        kept.append(path)
    return kept


def _validate_sort(spec: _Collection, sort: Mapping[str, int] | None) -> dict[str, int] | None:
    if sort is None:
        return None
    if not isinstance(sort, Mapping) or not 1 <= len(sort) <= 3:
        raise ValidationError("sort takes 1-3 fields")
    result: dict[str, int] = {}
    for key, direction in sort.items():
        if key not in spec.fields:
            raise ValidationError(f"ACS results cannot be sorted on {str(key)[:64]!r}")
        if isinstance(direction, bool) or direction not in (1, -1):
            raise ValidationError("sort direction must be 1 or -1")
        result[key] = direction
    return result


def _validate_page(skip: Any, limit: Any) -> tuple[int, int]:
    # parseInt on anything else gives NaN, which the MongoDB driver throws on (F13);
    # and limit=0 means "no limit" to MongoDB, not "nothing".
    if isinstance(skip, bool) or not isinstance(skip, int) or not 0 <= skip <= MAX_SKIP:
        raise ValidationError(f"skip must be a whole number from 0 to {MAX_SKIP}")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_LIMIT:
        raise ValidationError(f"limit must be a whole number from 1 to {MAX_LIMIT}")
    return skip, limit


_PRESET_CONFIGURATION_TYPES = frozenset(
    {"value", "age", "add_tag", "delete_tag", "provision", "add_object", "delete_object"}
)


def _check_preset_shape(preset: Any) -> None:
    """The structure genieacs-cwmp iterates without guarding (F19, F20).

    One preset it trips over stalls preset loading for every router, so the shape
    is enforced here whoever the caller is. bootstrap.py applies SkyRouter's much
    narrower policy on top.
    """
    if not isinstance(preset, Mapping):
        raise ValidationError("a preset must be an object")
    if "_id" in preset:
        raise ValidationError("a preset's _id comes from its name")
    configurations = preset.get("configurations")
    if not isinstance(configurations, list) or not configurations:
        raise ValidationError("a preset needs a non-empty configurations list")
    for entry in configurations:
        if not isinstance(entry, Mapping) or entry.get("type") not in _PRESET_CONFIGURATION_TYPES:
            raise ValidationError("preset configurations need a type GenieACS 1.2 knows")
        if "args" in entry and entry["args"] is not None and not isinstance(entry["args"], list):
            raise ValidationError("preset configuration args must be a list")
    if "weight" in preset and (isinstance(preset["weight"], bool) or not isinstance(preset["weight"], int)):
        raise ValidationError("preset weight must be an integer")
    for key in ("channel", "precondition", "schedule"):
        if key in preset and not isinstance(preset[key], str):
            raise ValidationError(f"preset {key} must be a string")
    events = preset.get("events", {})
    if not isinstance(events, Mapping) or not all(
        isinstance(k, str) and isinstance(v, bool) for k, v in events.items()
    ):
        raise ValidationError("preset events must map event codes to true or false")


def _validate_base_url(base_url: Any, allow_remote: bool) -> str:
    if not isinstance(base_url, str):
        raise ValidationError("ACS URL must be a string")
    try:
        parts = urllib.parse.urlsplit(base_url.strip())
        host = parts.hostname
        parts.port  # noqa: B018 - raises ValueError on a malformed port
    except ValueError as exc:
        raise ValidationError("ACS URL is malformed") from exc
    if parts.scheme not in ("http", "https"):
        raise ValidationError("ACS URL must be http or https")
    if parts.username is not None or parts.password is not None:
        raise ValidationError("ACS URL must not contain credentials")
    # Every NBI route hangs off the root; a path or query would be silently dropped.
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ValidationError("ACS URL must not have a path, query or fragment")
    if not host:
        raise ValidationError("ACS URL has no host")
    if not allow_remote and not _is_loopback(host):
        # The NBI has no authentication (F3); a remote one would hand its secrets,
        # and control of every router, to anyone who can reach it.
        raise ValidationError("ACS URL must be a loopback address unless remote access is explicitly allowed")
    return f"{parts.scheme}://{parts.netloc}"


def _is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _printable(text: str, limit: int = 200) -> str:
    return _UNPRINTABLE_RE.sub(" ", text).strip()[:limit]


def _redact_task(doc: dict[str, Any]) -> dict[str, Any]:
    # A write's values are the NBI's plaintext copy of what SkyRouter sent, which for
    # a Wi-Fi change is the passphrase. Callers already know what they sent.
    return {key: value for key, value in doc.items() if key != "parameterValues"}


def _redact_fault(doc: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in doc.items() if key != "provisions"}


# --- client -------------------------------------------------------------------------


class AcsClient:
    def __init__(self, base_url: str, timeout: float = 15.0, *, allow_remote: bool = False):
        self.base_url = _validate_base_url(base_url, allow_remote)
        self.timeout = timeout
        self._session = HttpSession(self.base_url, timeout=timeout)
        self._version: str | None = None

    # -- transport --------------------------------------------------------------------

    def _send(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, str] | None = None,
        body: bytes | None = None,
        content_type: str | None = None,
        timeout: float | None = None,
    ) -> HttpResponse:
        # urlencode, because the NBI reads "+" in a query string as a space (F7).
        target = f"{path}?{urllib.parse.urlencode(params)}" if params else path
        headers = {"Content-Type": content_type} if content_type else None
        try:
            response = self._session.request(method, target, data=body, headers=headers, timeout=timeout)
        except HttpError as exc:
            raise AcsUnavailable(f"ACS unavailable ({method} {path}): {_transport_detail(exc)}") from exc
        self._check_version(response)
        return response

    def _check_version(self, response: HttpResponse) -> None:
        # Every NBI reply carries the header (F4), so an upgrade behind SkyRouter's back
        # is noticed on the next reply rather than at the next restart.
        value = _printable(response.headers.get(VERSION_HEADER, ""), 64)
        if not value:
            raise AcsError("the ACS reply did not come from GenieACS (no GenieACS-Version header)")
        if value == self._version:
            return
        if not is_supported_version(value):
            raise AcsError(f"GenieACS {value} is not supported; SkyRouter needs 1.2.10 or a later 1.2 release")
        self._version = value

    def _ensure_version(self) -> None:
        """Check the version before the first write, so an unsupported NBI never receives one."""
        if self._version is None:
            self.version()

    def _read(self, method: str, path: str, params: Mapping[str, str] | None, decode: Callable[[HttpResponse], T]) -> T:
        # Reads change nothing, so one retry rides out a worker that crashed or a
        # reply that was cut short while the cluster respawned it.
        try:
            return decode(self._send(method, path, params=params))
        except AcsUnavailable as exc:
            logger.warning("retrying ACS read once after: %s", exc)
            return decode(self._send(method, path, params=params))

    def _fail(self, response: HttpResponse, method: str, path: str, *, sensitive: bool = False) -> NoReturn:
        status, reason = response.status, _printable(response.reason, 80)
        # A 400 body can quote the request, and a task request may hold a passphrase.
        detail = "" if sensitive else _printable(response.text)
        if status == 400:
            logger.error("ACS rejected %s %s as invalid (%s); local validation missed it", method, path, reason)
            raise AcsRejected(
                f"ACS rejected the request as invalid{': ' + detail if detail else ''}", status=status, reason=reason
            )
        if status == 404:
            raise AcsNotFound(_printable(response.text) or "not found on the ACS", status=status, reason=reason)
        if status == 503:
            raise AcsBusy("the router is mid-session; try again", status=status, reason=reason)
        raise AcsError(f"unexpected ACS reply to {method} {path}: {status} {reason}", status=status, reason=reason)

    # -- health -----------------------------------------------------------------------

    def version(self) -> str:
        """GenieACS's version, from GET / (404 plus the header, without touching MongoDB, F4)."""
        response = self._read("GET", "/", None, lambda response: response)
        # _check_version has already refused a missing or unsupported value.
        return _printable(response.headers.get(VERSION_HEADER, ""), 64)

    def check_db(self) -> None:
        """HEAD /presets, which only succeeds if the NBI can reach MongoDB."""

        def decode(response: HttpResponse) -> None:
            if response.status != 200:
                self._fail(response, "HEAD", "/presets")
            _total(response)

        self._read("HEAD", "/presets", None, decode)

    # -- reads ------------------------------------------------------------------------

    def find(
        self,
        collection: str,
        query: Mapping[str, Any],
        projection: Sequence[str] | None = None,
        sort: Mapping[str, int] | None = None,
        skip: int = 0,
        limit: int = 50,
    ) -> Page:
        spec = _COLLECTIONS.get(collection) if isinstance(collection, str) else None
        if spec is None:
            raise ValidationError(f"the ACS client does not read {str(collection)[:32]!r}")
        checked_query = _validate_query(spec, query)
        checked_projection = _validate_projection(spec, projection)
        checked_sort = _validate_sort(spec, sort)
        skip, limit = _validate_page(skip, limit)

        params = {"query": json.dumps(checked_query, separators=(",", ":"))}
        if checked_projection:
            params["projection"] = ",".join(checked_projection)
        if checked_sort:
            params["sort"] = json.dumps(checked_sort, separators=(",", ":"))
        params["skip"] = str(skip)
        params["limit"] = str(limit)
        path = f"/{collection}"

        def decode(response: HttpResponse) -> Page:
            if response.status != 200:
                self._fail(response, "GET", path)
            total = _total(response)
            items = _json(response)
            if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
                raise AcsError(f"the ACS returned something other than a list of {collection}")
            if collection == "tasks":
                items = [_redact_task(item) for item in items]
            elif collection == "faults":
                items = [_redact_fault(item) for item in items]
            return Page(items=items, total=total)

        return self._read("GET", path, params, decode)

    def _find_all(self, collection: str, query: Mapping[str, Any], sort: Mapping[str, int]) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        while True:
            page = self.find(collection, query, sort=sort, skip=len(items), limit=MAX_LIMIT)
            if page.total > MAX_LISTED:
                # A silently truncated task or fault list would read as "nothing pending".
                raise AcsError(f"the ACS holds {page.total} matching {collection}; narrow the query")
            items.extend(page.items)
            if not page.items or len(items) >= page.total:
                return items

    def get_device(self, device_id: str, projection: Sequence[str]) -> dict[str, Any] | None:
        """One device document, or None. The NBI has no GET /devices/<id> (F8)."""
        validate_device_id(device_id)
        if projection is None:
            raise ValidationError("get_device needs a projection")
        page = self.find("devices", {"_id": device_id}, projection=projection, limit=1)
        for item in page.items:
            if item.get("_id") == device_id:
                return item
        return None

    def tasks(
        self, ids: list[str] | None = None, device_id: str | None = None, job: str | None = None
    ) -> list[dict[str, Any]]:
        """Pending or faulted tasks, oldest first. A task that succeeded is gone (F16).

        Write values are never included.
        """
        query: dict[str, Any] = {}
        if ids is not None:
            if isinstance(ids, str) or not isinstance(ids, (list, tuple)):
                raise ValidationError("ids must be a list of task IDs")
            if not ids:
                return []
            query["_id"] = {"$in": [validate_task_id(task_id) for task_id in ids]}
        if device_id is not None:
            query["device"] = validate_device_id(device_id)
        if job is not None:
            query["skyrouterJob"] = job
        return self._find_all("tasks", query, sort={"_id": 1})

    def faults(
        self, ids: list[str] | None = None, device_id: str | None = None, channels: list[str] | None = None
    ) -> list[dict[str, Any]]:
        """Faults, oldest first, without the provisions field (it can hold a written passphrase)."""
        query: dict[str, Any] = {}
        if ids is not None:
            if isinstance(ids, str) or not isinstance(ids, (list, tuple)):
                raise ValidationError("ids must be a list of fault IDs")
            if not ids:
                return []
            query["_id"] = {"$in": [validate_fault_id(fault_id) for fault_id in ids]}
        if device_id is not None:
            query["device"] = validate_device_id(device_id)
        if channels is not None:
            if isinstance(channels, str) or not isinstance(channels, (list, tuple)):
                raise ValidationError("channels must be a list")
            if not channels:
                return []
            query["channel"] = {"$in": list(channels)}
        return self._find_all("faults", query, sort={"timestamp": 1})

    def get_provision(self, name: str) -> str | None:
        validate_name(name, "provision name")
        page = self.find("provisions", {"_id": name}, projection=["_id", "script"], limit=1)
        for item in page.items:
            if item.get("_id") == name:
                script = item.get("script")
                if not isinstance(script, str):
                    raise AcsError(f"provision {name} has no script")
                return script
        return None

    def get_preset(self, name: str) -> dict[str, Any] | None:
        """The stored preset without its _id, so it compares equal to what put_preset sent."""
        validate_name(name, "preset name")
        page = self.find("presets", {"_id": name}, limit=1)
        for item in page.items:
            if item.get("_id") == name:
                return {key: value for key, value in item.items() if key != "_id"}
        return None

    # -- writes: never retried --------------------------------------------------------
    #
    # A write whose reply was lost may still have happened, so repeating it blindly
    # could queue a task twice or send a second connection request mid-session.

    def queue_task(self, device_id: str, task: Task) -> dict[str, Any]:
        """Queue one task (202 "Accepted"). Returns the stored task: _id, timestamp, expiry, ...

        The returned document leaves out parameterValues. If the reply is lost, the
        task is looked up by its skyrouterJob/skyrouterStep instead of re-sent.
        """
        validate_device_id(device_id)
        if not isinstance(task, Task):
            raise ValidationError("queue_task takes a Task built by cudy_manager.acs.tasks")
        payload = task.to_json()
        validate_task(payload)
        self._ensure_version()
        path = f"/devices/{_segment(device_id)}/tasks"
        body = json.dumps(payload, separators=(",", ":"), allow_nan=False).encode()
        try:
            response = self._send("POST", path, body=body, content_type="application/json")
            if response.status == 202 and response.reason.strip().lower() == "accepted":
                stored = _json(response)
                if (
                    not isinstance(stored, dict)
                    or not isinstance(stored.get("_id"), str)
                    or not _TASK_ID_RE.fullmatch(stored["_id"])
                    or not isinstance(stored.get("timestamp"), str)
                ):
                    raise AcsError(f"the ACS accepted {task.name} but returned no usable task record")
                return _redact_task(stored)
        except AcsUnavailable as exc:
            return self._recover_lost_task(device_id, task, exc)
        if response.status == 202:
            raise AcsError(
                f"unexpected ACS reply to {task.name}: 202 {_printable(response.reason, 80)}",
                status=202,
                reason=response.reason,
            )
        self._fail(response, "POST", path, sensitive=True)

    def _recover_lost_task(self, device_id: str, task: Task, cause: AcsUnavailable) -> dict[str, Any]:
        try:
            found = [
                item
                for item in self.tasks(device_id=device_id, job=task.job)
                if item.get("skyrouterStep") == task.step and item.get("name") == task.name
            ]
        except AcsUnavailable as exc:
            raise AcsUnavailable(
                f"ACS unavailable while queueing {task.name}; whether it was queued is unknown",
                outcome_unknown=True,
            ) from exc
        if found:
            logger.warning("ACS reply to %s was lost, but task %s was queued", task.name, found[-1].get("_id"))
            return found[-1]
        # Not pending does not rule out "queued and already run", which the job's
        # parameter timestamps settle; it does rule out a task still waiting to run.
        raise AcsUnavailable(f"ACS unavailable while queueing {task.name}; the task is not queued") from cause

    def connection_request(self, device_id: str) -> CrResult:
        """Ask the router to check in now, without waiting for the session (F11)."""
        validate_device_id(device_id)
        self._ensure_version()
        path = f"/devices/{_segment(device_id)}/tasks"
        response = self._send(
            "POST",
            path,
            params={"connection_request": ""},
            body=b"",
            timeout=max(self.timeout, CONNECTION_REQUEST_TIMEOUT),
        )
        if response.status == 200:
            return CrResult(ok=True, reason="")
        if response.status == 504:
            # The NBI puts the connection-request status in both reason and body.
            reason = _printable(response.reason) or _printable(response.text) or "connection request failed"
            return CrResult(ok=False, reason=reason)
        self._fail(response, "POST", path)

    def delete_task(self, task_id: str) -> None:
        """Cancel a task. AcsBusy while the router is mid-session, AcsNotFound once it has gone."""
        validate_task_id(task_id)
        self._write("DELETE", f"/tasks/{task_id}")

    def delete_fault(self, fault_id: str) -> None:
        """Clear a fault. For a task_<id> channel this also deletes the task (F16)."""
        validate_fault_id(fault_id)
        self._write("DELETE", f"/faults/{_segment(fault_id)}")

    def retry_fault_task(self, task_id: str) -> None:
        """Clear a task's fault so it runs at the next check-in. Sends no connection request."""
        validate_task_id(task_id)
        # GenieACS 1.2 dereferences the missing task and the worker dies (F13).
        if not self.tasks(ids=[task_id]):
            raise AcsNotFound("Task not found", status=404)
        self._write("POST", f"/tasks/{task_id}/retry", body=b"")

    def add_tag(self, device_id: str, tag: str) -> None:
        validate_device_id(device_id)
        validate_tag(tag)
        self._write("POST", f"/devices/{_segment(device_id)}/tags/{_segment(tag)}", body=b"")

    def remove_tag(self, device_id: str, tag: str) -> None:
        validate_device_id(device_id)
        validate_tag(tag)
        self._write("DELETE", f"/devices/{_segment(device_id)}/tags/{_segment(tag)}")

    def put_provision(self, name: str, script: str) -> None:
        """Store a provision script. A JavaScript syntax error comes back as AcsRejected (F18)."""
        validate_name(name, "provision name")
        if not isinstance(script, str) or not script.strip():
            raise ValidationError("a provision needs a script")
        body = script.encode("utf-8")
        if len(body) > MAX_SCRIPT_BYTES:
            raise ValidationError("provision script is too large")
        self._write("PUT", f"/provisions/{_segment(name)}", body=body, content_type="application/javascript")

    def put_preset(self, name: str, preset: Mapping[str, Any]) -> None:
        """Store a preset exactly as given (F18); only its basic shape is checked here."""
        validate_name(name, "preset name")
        _check_preset_shape(preset)
        try:
            body = json.dumps(preset, separators=(",", ":"), allow_nan=False).encode()
        except (TypeError, ValueError) as exc:
            raise ValidationError("a preset must be plain JSON") from exc
        self._write("PUT", f"/presets/{_segment(name)}", body=body, content_type="application/json")

    def delete_preset(self, name: str) -> None:
        validate_name(name, "preset name")
        self._write("DELETE", f"/presets/{_segment(name)}")

    def _write(self, method: str, path: str, *, body: bytes | None = None, content_type: str | None = None) -> None:
        self._ensure_version()
        response = self._send(method, path, body=body, content_type=content_type)
        if response.status != 200:
            self._fail(response, method, path)


def _segment(value: str) -> str:
    # The NBI decodes each path segment exactly once, and device IDs contain a
    # literal "%", so it must travel as "%25" (F5).
    return urllib.parse.quote(value, safe="")


def _total(response: HttpResponse) -> int:
    raw = response.headers.get(TOTAL_HEADER, "").strip()
    if not raw.isdigit():
        raise AcsError("the ACS reply has no usable total header")
    return int(raw)


def _json(response: HttpResponse) -> Any:
    try:
        return json.loads(response.body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        # The NBI sends its headers before streaming results, so a MongoDB failure
        # part-way through arrives as a 200 with a truncated array.
        raise AcsUnavailable("the ACS reply was cut short (probable NBI worker crash)") from exc


def _transport_detail(exc: HttpError) -> str:
    cause: BaseException | None = exc.__cause__
    reason = getattr(cause, "reason", None)
    if isinstance(reason, BaseException):
        cause = reason
    if cause is None:
        return "no reply"
    return _printable(str(cause) or type(cause).__name__, 120)
