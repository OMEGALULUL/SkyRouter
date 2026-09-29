"""A stand-in GenieACS 1.2.16 NBI with a router check-in simulator, for fully mocked tests.

Written from the documented NBI behaviour (brief F5-F18, §5.1); no GenieACS code.
It reproduces the parts SkyRouter depends on, including the awkward ones:

* each path segment is decoded exactly once, so a raw "%2D" device ID is looked up
  as "-" and gets 404 "No such device", and a raw DELETE /devices/<id> answers 200
  while deleting nothing;
* outcomes carried in the reason phrase (202 "Accepted", 504 "Device is offline");
* the ``total`` and ``GenieACS-Version`` headers, with a version override;
* crash mode: input GenieACS 1.2.16 throws on (an invalid task, a non-hex task ID,
  retry on a missing task, limit=abc, an empty projection, ...) closes the socket
  with no reply, as a dying worker does (F13). ``crash_next``, ``truncate_next`` and
  ``reply_next`` script failures on demand.

Two layers of state are kept apart, because the Wi-Fi flow depends on the gap
between them: ``devices`` holds GenieACS's cached documents (what the NBI serves),
while ``cpes`` holds what each router really has. ``run_session`` plays one
check-in: queued tasks run oldest first, GetParameterValues copies router values
into the cache (secret leaves read back per the router's ``readback``), and
SetParameterValues is only sent for a cached, writable, changed leaf, then cached
as the plaintext sent, stamped session time + 1 ms (F15).

Firmware: PUT /files/<name> stores a file with its metadata taken from the fileType,
oui, productClass and version request headers (201), DELETE removes it (200, or 404),
and GET /files lists the GridFS fs.files documents. A download task is taken as
the router accepting the Download RPC; the transfer then completes in a later
session by default (``set_download``): the router boots into the file's version,
or reports a TransferComplete fault on the task's channel.

Typical fixture::

    @pytest.fixture
    def nbi():
        with FakeNbi() as fake:
            yield fake
"""

import contextlib
import copy
import functools
import itertools
import json
import re
import threading
import urllib.parse
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

DEFAULT_VERSION = "1.2.16+20260329"

_SEGMENT = r"[A-Za-z0-9\-_%]+"
_PRESET_ROUTE = re.compile(rf"/presets/({_SEGMENT})/?")
_PROVISION_ROUTE = re.compile(rf"/provisions/({_SEGMENT})/?")
_TAG_ROUTE = re.compile(rf"/devices/({_SEGMENT})/tags/({_SEGMENT})/?")
_FAULT_ROUTE = re.compile(r"/faults/([A-Za-z0-9\-_%:]+)/?")
_FILE_ROUTE = re.compile(rf"/files/({_SEGMENT})/?")
_DEVICE_TASKS_ROUTE = re.compile(rf"/devices/({_SEGMENT})/tasks/?")
_TASK_ROUTE = re.compile(rf"/tasks/({_SEGMENT})(/[A-Za-z_]*)?")
_DEVICE_ROUTE = re.compile(rf"/devices/({_SEGMENT})/?")
_COLLECTION_ROUTE = re.compile(r"/([A-Za-z0-9_]+)/?")
_HEX24 = re.compile(r"[0-9a-f]{24}")

# Collections the 1.2.10+ generic route serves. Only the first six hold data here.
_COLLECTIONS = {
    "devices",
    "tasks",
    "faults",
    "presets",
    "provisions",
    "objects",
    "files",
    "virtualParameters",
    "operations",
    "permissions",
    "users",
    "config",
    "cache",
    "locks",
}

_SECRET_NAMES = {"KeyPassphrase", "PreSharedKey", "SAEPassphrase", "WEPKey", "X_TP_PreSharedKey", "UserPwd", "PIN"}


def is_secret_path(path: str) -> bool:
    """The write-only leaves that read back empty on a spec-following router (F27)."""
    name = path.rsplit(".", 1)[-1]
    return name in _SECRET_NAMES or name.endswith(("Password", "Secret", "Passphrase"))


def iso(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


def make_device_id(oui: str, product_class: str, serial: str) -> str:
    """The ID GenieACS gives a router (F5), so tests can build realistic ones."""

    def esc(part: str) -> str:
        return "".join(
            char if re.fullmatch(r"[A-Za-z0-9_]", char) else "".join(f"%{byte:02X}" for byte in char.encode())
            for char in part
        )

    parts = [esc(oui), esc(product_class), esc(serial)] if product_class else [esc(oui), esc(serial)]
    return "-".join(parts)


def _type_of(value: Any) -> str:
    if isinstance(value, bool):
        return "xsd:boolean"
    if isinstance(value, int):
        return "xsd:unsignedInt" if value >= 0 else "xsd:int"
    return "xsd:string"


def _leaf_spec(spec: Any) -> tuple[Any, str, bool]:
    if isinstance(spec, Mapping):
        value = spec.get("value", "")
        return value, spec.get("type") or _type_of(value), bool(spec.get("writable", True))
    return spec, _type_of(spec), True


def _set_cached_leaf(doc: dict[str, Any], path: str, leaf: dict[str, Any], stamp: str) -> None:
    node = doc
    for part in path.split(".")[:-1]:
        child = node.get(part)
        if not isinstance(child, dict):
            child = {"_object": True, "_writable": False, "_timestamp": stamp}
            node[part] = child
        node = child
    node[path.rsplit(".", 1)[-1]] = leaf


def build_device(
    *,
    oui: str = "202BC1",
    product_class: str = "BM632w",
    serial: str = "000000",
    manufacturer: str = "Acme",
    leaves: Mapping[str, Any] | None = None,
    tags: Iterable[str] = (),
    last_inform: datetime | None = None,
) -> dict[str, Any]:
    """A GenieACS device document. ``leaves`` maps a path to a value or {value, type, writable}."""
    stamp = iso(last_inform or datetime.now(UTC))
    doc: dict[str, Any] = {
        "_id": make_device_id(oui, product_class, serial),
        "_deviceId": {
            "_Manufacturer": manufacturer,
            "_OUI": oui,
            "_ProductClass": product_class,
            "_SerialNumber": serial,
        },
        "_registered": stamp,
        "_lastInform": stamp,
    }
    if tags:
        doc["_tags"] = list(tags)
    for path, spec in (leaves or {}).items():
        value, type_, writable = _leaf_spec(spec)
        leaf = {"_object": False, "_value": value, "_type": type_, "_writable": writable, "_timestamp": stamp}
        _set_cached_leaf(doc, path, leaf, stamp)
    return doc


def iter_cached_leaves(node: Mapping[str, Any], prefix: str = "") -> Iterator[tuple[str, dict[str, Any]]]:
    """Every parameter leaf in a device document, as (path, leaf)."""
    for key, child in node.items():
        if key.startswith("_") or not isinstance(child, dict):
            continue
        path = f"{prefix}{key}"
        if "_value" in child or child.get("_object") is False:
            yield path, child
        else:
            yield from iter_cached_leaves(child, path + ".")


@dataclass
class CpeLeaf:
    value: Any
    type: str = "xsd:string"
    writable: bool = True


@dataclass
class FakeCpe:
    """What the router itself holds, as opposed to GenieACS's cached copy."""

    leaves: dict[str, CpeLeaf] = field(default_factory=dict)
    # "empty" follows the spec; "plaintext" and "masked" are the non-conforming routers.
    readback: str = "empty"
    leaf_faults: dict[str, tuple[str, str]] = field(default_factory=dict)
    task_faults: dict[str, tuple[str, str]] = field(default_factory=dict)
    hidden: Callable[[str], bool] = is_secret_path
    reboots: int = 0
    # How the router handles a Download it accepted: "next_session" installs it and
    # reports from the boot session that follows, "same_session" before this one
    # ends, "ignore" never does anything with it.
    download: str = "next_session"
    # A TransferComplete fault (code, message) instead of installing.
    download_fault: tuple[str, str] | None = None
    # The version it reports after installing; None means the file's own version.
    download_version: str | None = None
    pending_transfer: dict[str, Any] | None = None

    def read(self, path: str) -> Any:
        leaf = self.leaves[path]
        if not self.hidden(path) or self.readback == "plaintext":
            return leaf.value
        return "********" if self.readback == "masked" else ""


@dataclass
class CrOutcome:
    status: int = 200
    reason: str = ""
    # With 200, run a check-in before answering, so the next poll sees its effects.
    session: bool = False


@dataclass
class RecordedRequest:
    method: str
    path: str  # as sent, still percent-encoded
    query: dict[str, str]  # decoded once, as URLSearchParams would
    body: bytes
    headers: dict[str, str]
    target: str = ""  # the raw request target, query string included
    outcome: str = "answered"  # "answered", "crashed", "truncated" or "scripted"
    status: int | None = None


@dataclass
class _Reply:
    status: int = 200
    body: bytes = b""
    reason: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    crash: bool = False
    truncate: bool = False
    streamed: bool = False


class _Crash(Exception):
    """GenieACS would throw here and the worker would die without replying."""


_MISSING = object()


def _lookup(doc: Any, path: str) -> Any:
    node = doc
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return _MISSING
        node = node[part]
    return node


def _same(actual: Any, expected: Any) -> bool:
    # MongoDB does not treat true as 1, although Python does.
    if isinstance(actual, bool) or isinstance(expected, bool):
        return type(actual) is type(expected) and actual == expected
    return bool(actual == expected)


def _wildcard(text: str) -> re.Pattern[str]:
    # GenieACS's documented "*" handling (F8): outer stars unanchor that end, and the
    # first inner star matches anything.
    anchored_start, anchored_end = not text.startswith("*"), not text.endswith("*")
    core = text.strip("*")
    head, star, tail = core.partition("*")
    pattern = re.escape(head) + (".*" + re.escape(tail) if star else "")
    return re.compile(("^" if anchored_start else "") + pattern + ("$" if anchored_end else ""))


def _alternatives(value: Any) -> list[Any]:
    """What a string in a devices query also matches: a number, a date, a wildcard (F8)."""
    if not isinstance(value, str):
        return [value]
    options: list[Any] = [value]
    if re.fullmatch(r"\s*[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?\s*", value):
        number = float(value)
        options.append(int(number) if number.is_integer() else number)
    moment = parse_iso(value)
    if len(value) >= 8 and moment is not None and moment.year > 1983:
        options.append(moment)
    if "*" in value:
        options.append(_wildcard(value))
    return options


def _equals(actual: Any, expected: Any) -> bool:
    if actual is _MISSING:
        return expected is None
    if isinstance(expected, re.Pattern):
        values = actual if isinstance(actual, list) else [actual]
        return any(isinstance(item, str) and expected.search(item) for item in values)
    if isinstance(expected, datetime):
        return parse_iso(actual) == expected
    if isinstance(actual, list) and not isinstance(expected, list):
        return any(_same(item, expected) for item in actual)
    return _same(actual, expected)


def _compare(actual: Any, operand: Any, operator: str) -> bool:
    left: Any
    right: Any
    if isinstance(operand, datetime) or (parse_iso(actual) and parse_iso(operand)):
        left, right = parse_iso(actual), operand if isinstance(operand, datetime) else parse_iso(operand)
    elif (isinstance(actual, (int, float)) and isinstance(operand, (int, float))) or (
        isinstance(actual, str) and isinstance(operand, str)
    ):
        left, right = actual, operand
    else:
        return False
    if left is None or right is None:
        return False
    return {
        "$lt": left < right,
        "$lte": left <= right,
        "$gt": left > right,
        "$gte": left >= right,
    }[operator]


def _condition(actual: Any, condition: Any, expand: Callable[[Any], list[Any]]) -> bool:
    if isinstance(condition, dict) and condition and all(str(key).startswith("$") for key in condition):
        for operator, operand in condition.items():
            if operator in ("$eq", "$ne"):
                hit = any(_equals(actual, option) for option in expand(operand))
                ok = hit if operator == "$eq" else not hit
            elif operator in ("$in", "$nin"):
                if not isinstance(operand, list):
                    raise _Crash("$in needs an array")
                hit = any(_equals(actual, option) for item in operand for option in expand(item))
                ok = hit if operator == "$in" else not hit
            elif operator in ("$lt", "$lte", "$gt", "$gte"):
                ok = any(_compare(actual, option, operator) for option in expand(operand))
            elif operator == "$exists":
                ok = (actual is not _MISSING) == bool(operand)
            else:
                raise _Crash(f"MongoDB rejects {operator}")
            if not ok:
                return False
        return True
    return any(_equals(actual, option) for option in expand(condition))


def _field_matches(path: str, condition: Any, expand: Callable[[Any], list[Any]], doc: dict[str, Any]) -> bool:
    return _condition(_lookup(doc, path), condition, expand)


def _logical(key: str, value: Any) -> list[dict[str, Any]]:
    if key not in ("$or", "$and", "$nor") or not isinstance(value, list):
        raise _Crash(f"bad logical operator {key}")
    if not all(isinstance(part, dict) for part in value):
        raise _Crash(f"{key} needs objects")
    return value


def _combine(key: str, predicates: list[Callable[[dict[str, Any]], bool]]) -> Callable[[dict[str, Any]], bool]:
    if key == "$or":
        return lambda doc: any(p(doc) for p in predicates)
    if key == "$and":
        return lambda doc: all(p(doc) for p in predicates)
    return lambda doc: not any(p(doc) for p in predicates)


def _device_filter(query: dict[str, Any]) -> Callable[[dict[str, Any]], bool]:
    predicates: list[Callable[[dict[str, Any]], bool]] = []
    for key, value in query.items():
        if key.startswith("$"):
            predicates.append(_combine(key, [_device_filter(part) for part in _logical(key, value)]))
            continue
        # GenieACS appends ._value to a parameter path, but not to _id, _tags and the like.
        path = key if key.rsplit(".", 1)[-1].startswith("_") else f"{key}._value"
        if isinstance(value, dict) and ("$ne" in value or "$not" in value) and len(value) > 1:
            raise _Crash("Cannot mix $ne or $not with other operators")
        predicates.append(functools.partial(_field_matches, path, value, _alternatives))
    return lambda doc: all(p(doc) for p in predicates)


_TYPED_OPERATORS = {"$in", "$nin", "$eq", "$gt", "$gte", "$lt", "$lte", "$ne", "$exists", "$type"}


def _typed_filter(query: dict[str, Any], types: Mapping[str, Callable[[Any], Any]]) -> Callable[[dict[str, Any]], bool]:
    """tasks and faults: a few keys are converted (ObjectId, Date), everything else is raw."""
    predicates: list[Callable[[dict[str, Any]], bool]] = []
    for key, value in query.items():
        if key.startswith("$"):
            predicates.append(_combine(key, [_typed_filter(part, types) for part in _logical(key, value)]))
            continue
        if key in types:
            convert = types[key]
            if isinstance(value, dict):
                if not set(value) <= _TYPED_OPERATORS:
                    raise _Crash("Operator not supported")
                for operator, operand in value.items():
                    if operator in ("$in", "$nin"):
                        if not isinstance(operand, list):
                            raise _Crash("$in needs an array")
                        for item in operand:
                            convert(item)
                    elif operator not in ("$exists", "$type"):
                        convert(operand)
            else:
                convert(value)

        def expand(operand: Any, k: str = key) -> list[Any]:
            if k in types and k != "_id":
                return [types[k](operand)]
            return [operand]

        predicates.append(functools.partial(_field_matches, key, value, expand))
    return lambda doc: all(p(doc) for p in predicates)


def _object_id(value: Any) -> str:
    if not isinstance(value, str) or not _HEX24.fullmatch(value):
        raise _Crash("new ObjectId() throws")
    return value


def _date(value: Any) -> datetime | None:
    return parse_iso(value)


def _number(value: Any) -> Any:
    return value


def _parse_int(raw: str) -> int:
    # parseInt semantics; NaN makes the MongoDB driver throw inside the NBI.
    match = re.match(r"\s*([+-]?\d+)", raw)
    if not match:
        raise _Crash("NaN skip or limit")
    return int(match.group(1))


def _project(doc: dict[str, Any], paths: list[str]) -> dict[str, Any]:
    result: dict[str, Any] = {"_id": doc.get("_id")}
    for path in paths:
        value = _lookup(doc, path)
        if value is _MISSING:
            continue
        node = result
        parts = path.split(".")
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = copy.deepcopy(value)
    return result


def _sort_rank(value: Any) -> tuple[int, Any]:
    if value is _MISSING or value is None:
        return (0, 0)
    if isinstance(value, bool):
        return (5, value)
    if isinstance(value, (int, float)):
        return (1, value)
    if isinstance(value, str):
        return (2, value)
    return (3, json.dumps(value, sort_keys=True, default=str))


def _sort_key(path: str, doc: dict[str, Any]) -> tuple[int, Any]:
    return _sort_rank(_lookup(doc, path))


def _coerce(value: Any, type_: str) -> Any:
    """GenieACS converts a written value to the leaf's cached type; the task's type is ignored (F15)."""
    if type_ == "xsd:boolean":
        if isinstance(value, str) and value.lower() in ("true", "1", "false", "0"):
            return value.lower() in ("true", "1")
        return bool(value) if isinstance(value, (bool, int)) else value
    if type_ in ("xsd:int", "xsd:unsignedInt"):
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, str) and re.fullmatch(r"[+-]?\d+", value.strip()):
            return int(value)
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _sanitize_task(task: dict[str, Any]) -> None:
    """GenieACS 1.2.16's task checks, as documented (F14); a failure kills the worker."""

    def valid_value(entry: Any) -> bool:
        return (
            isinstance(entry, list)
            and len(entry) >= 2
            and isinstance(entry[0], str)
            and bool(entry[0])
            and isinstance(entry[1], (str, bool, int, float))
            and (len(entry) < 3 or entry[2] is None or isinstance(entry[2], str))
        )

    name = task.get("name")
    if name == "getParameterValues":
        names = task.get("parameterNames")
        if not isinstance(names, list) or not names or not all(isinstance(n, str) and n for n in names):
            raise _Crash("Missing 'parameterNames' property")
    elif name == "setParameterValues":
        values = task.get("parameterValues")
        if not isinstance(values, list) or not values or not all(valid_value(v) for v in values):
            raise _Crash("Invalid parameter value")
    elif name == "refreshObject":
        if not isinstance(task.get("objectName"), str):
            raise _Crash("Missing 'objectName' property")
    elif name == "deleteObject":
        if not isinstance(task.get("objectName"), str) or not task["objectName"]:
            raise _Crash("Missing 'objectName' property")
    elif name == "addObject":
        values = task.get("parameterValues")
        if values is not None and (not isinstance(values, list) or not all(valid_value(v) for v in values)):
            raise _Crash("Invalid 'parameterValues' property")
    elif name == "download":
        if not task.get("file") and not (
            isinstance(task.get("fileType"), str)
            and task["fileType"]
            and isinstance(task.get("fileName"), str)
            and task["fileName"]
        ):
            raise _Crash("Missing 'fileType' property")
    elif name == "provisions":
        provisions = task.get("provisions")
        scalar = (str, bool, int, float, type(None))
        if not isinstance(provisions, list) or not all(
            isinstance(p, list) and all(isinstance(a, scalar) for a in p) for p in provisions
        ):
            raise _Crash("Invalid 'provisions' property")
    elif name not in ("reboot", "factoryReset"):
        raise _Crash("Invalid task name")


def _decode_segment(raw: str) -> str:
    # decodeURIComponent throws on a malformed escape, and that throw is uncaught.
    if re.search(r"%(?![0-9A-Fa-f]{2})", raw):
        raise _Crash("URIError")
    try:
        return urllib.parse.unquote(raw, errors="strict")
    except UnicodeDecodeError as exc:
        raise _Crash("URIError") from exc


def _camel(name: str) -> str:
    head, *rest = name.split("_")
    return head + "".join(part[:1].upper() + part[1:] for part in rest)


def _text(status: int, text: str = "", reason: str | None = None) -> _Reply:
    return _Reply(status=status, body=text.encode(), reason=reason, headers={"Content-Type": "text/plain"})


def _json_reply(status: int, payload: Any, reason: str | None = None) -> _Reply:
    return _Reply(
        status=status,
        body=json.dumps(payload).encode(),
        reason=reason,
        headers={"Content-Type": "application/json"},
    )


def _not_allowed(allow: str) -> _Reply:
    reply = _text(405, "405 Method Not Allowed")
    reply.headers["Allow"] = allow
    return reply


class FakeNbi:
    """The fake NBI server. Use as a context manager; ``url`` is its base URL."""

    def __init__(self, version: str | None = DEFAULT_VERSION):
        self.version = version
        self.devices: dict[str, dict[str, Any]] = {}
        self.cpes: dict[str, FakeCpe] = {}
        self.tasks: list[dict[str, Any]] = []
        self.faults: dict[str, dict[str, Any]] = {}
        self.presets: dict[str, dict[str, Any]] = {}
        self.provisions: dict[str, dict[str, Any]] = {}
        # GridFS: fs.files documents, and the content kept apart as the chunks are.
        self.files: dict[str, dict[str, Any]] = {}
        self.file_data: dict[str, bytes] = {}
        self.requests: list[RecordedRequest] = []
        self.sessions: list[dict[str, Any]] = []
        self.cr_requests: list[str] = []
        self.crashes = 0
        self.cache_invalidations = 0
        # Seconds GenieACS waits before retrying a faulted task: retry_delay * 2**retries.
        self.retry_delay = 300
        self.clock_offset = 0.0
        # Returns a SyntaxError message for a provision script, or None to accept it.
        self.check_script: Callable[[str], str | None] = lambda script: None
        self.lock = threading.RLock()
        self._cr: dict[str, CrOutcome] = {}
        self._busy: dict[str, int | None] = {}
        self._crash_plan: list[bool] = []
        self._truncate = 0
        self._scripted: list[_Reply] = []
        self._ids = itertools.count(1)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(self))
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        # shutdown() waits out one poll interval, which at the default 0.5 s dominates a test run.
        self._thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)

    # -- lifecycle ------------------------------------------------------------------

    def __enter__(self) -> "FakeNbi":
        self._thread.start()
        return self

    def __exit__(self, *args: Any) -> None:
        if self._thread.is_alive():
            self.server.shutdown()
        self.server.server_close()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def now(self) -> datetime:
        return datetime.now(UTC) + timedelta(seconds=self.clock_offset)

    def advance(self, seconds: float) -> None:
        """Move the fake's clock on, for expiry and fault-retry tests."""
        with self.lock:
            self.clock_offset += seconds

    # -- set-up ---------------------------------------------------------------------

    def add_device(
        self,
        doc: Mapping[str, Any],
        *,
        readback: str = "empty",
        cpe_leaves: Mapping[str, Any] | None = None,
    ) -> str:
        """Register a device document; the router starts out holding what the cache shows.

        ``cpe_leaves`` then overrides the router side: a value or {value, type,
        writable} per path, or None for a leaf GenieACS has cached but the router
        no longer has (it answers 9005).
        """
        with self.lock:
            stored = copy.deepcopy(dict(doc))
            device_id = stored["_id"]
            stored.setdefault("_lastInform", iso(self.now()))
            cpe = FakeCpe(readback=readback)
            for path, leaf in iter_cached_leaves(stored):
                cpe.leaves[path] = CpeLeaf(
                    value=leaf.get("_value"),
                    type=leaf.get("_type", "xsd:string"),
                    writable=leaf.get("_writable", True) is not False,
                )
            for path, spec in (cpe_leaves or {}).items():
                if spec is None:
                    cpe.leaves.pop(path, None)
                else:
                    value, type_, writable = _leaf_spec(spec)
                    cpe.leaves[path] = CpeLeaf(value, type_, writable)
            self.devices[device_id] = stored
            self.cpes[device_id] = cpe
            return device_id

    def set_cr_outcome(
        self, device_id: str, status: int = 200, reason: str | None = None, *, session: bool = False
    ) -> None:
        """How the next connection requests to this router go: 200, or 504 with a reason."""
        with self.lock:
            if reason is None:
                reason = "" if status == 200 else "Device is offline"
            self._cr[device_id] = CrOutcome(status=status, reason=reason, session=session)

    def inject_fault(
        self, device_id: str, path: str, code: str = "cwmp.9007", message: str = "Invalid parameter value"
    ) -> None:
        """The router refuses any SetParameterValues that includes ``path``."""
        with self.lock:
            self.cpes[device_id].leaf_faults[path] = (code, message)

    def inject_task_fault(
        self, device_id: str, task_name: str, code: str = "cwmp.9000", message: str = "Method not supported"
    ) -> None:
        with self.lock:
            self.cpes[device_id].task_faults[task_name] = (code, message)

    def set_download(
        self,
        device_id: str,
        when: str = "next_session",
        *,
        fault: tuple[str, str] | None = None,
        version: str | None = None,
    ) -> None:
        """How the router handles the next firmware Download it accepts (see FakeCpe.download)."""
        if when not in ("next_session", "same_session", "ignore"):
            raise ValueError(f"unknown download behaviour {when!r}")
        with self.lock:
            cpe = self.cpes[device_id]
            cpe.download, cpe.download_fault, cpe.download_version = when, fault, version

    def software_version(self, device_id: str) -> Any:
        """What the router itself reports as DeviceInfo.SoftwareVersion."""
        with self.lock:
            leaf = self.cpes[device_id].leaves.get(self._software_version_path(device_id))
            return leaf.value if leaf else None

    def set_busy(self, device_id: str, times: int | None = None) -> None:
        """The router is mid-session for the next ``times`` lock attempts (None: until cleared)."""
        with self.lock:
            self._busy[device_id] = times

    def clear_busy(self, device_id: str) -> None:
        with self.lock:
            self._busy.pop(device_id, None)

    def crash_next(self, count: int = 1, *, after: bool = False) -> None:
        """Drop the next ``count`` requests without a reply. ``after`` applies them first,
        the case where the worker died once the write had already happened."""
        with self.lock:
            self._crash_plan.extend([after] * count)

    def truncate_next(self, count: int = 1) -> None:
        """Cut the next ``count`` collection listings short, as a mid-stream MongoDB failure does."""
        with self.lock:
            self._truncate += count

    def reply_next(self, status: int, body: bytes = b"", *, reason: str | None = None, count: int = 1) -> None:
        """Answer the next ``count`` requests with this reply, without acting on them."""
        with self.lock:
            for _ in range(count):
                self._scripted.append(_Reply(status=status, body=body, reason=reason))

    # -- views ----------------------------------------------------------------------

    def device_tasks(self, device_id: str) -> list[dict[str, Any]]:
        with self.lock:
            return [copy.deepcopy(task) for task in self.tasks if task.get("device") == device_id]

    def cached(self, device_id: str, path: str) -> dict[str, Any] | None:
        """GenieACS's cached leaf for ``path``: {_value, _type, _timestamp, _writable, ...}."""
        with self.lock:
            leaf = _lookup(self.devices.get(device_id, {}), path)
            return copy.deepcopy(leaf) if isinstance(leaf, dict) else None

    def requests_for(self, method: str | None = None, prefix: str = "") -> list[RecordedRequest]:
        with self.lock:
            return [r for r in self.requests if (method is None or r.method == method) and r.path.startswith(prefix)]

    # -- internals ------------------------------------------------------------------

    def _new_id(self) -> str:
        # ObjectId-shaped, and increasing, so sorting on _id is insertion order.
        return f"{int(self.now().timestamp()):08x}{next(self._ids):016x}"

    def _locked(self, device_id: str) -> bool:
        if device_id not in self._busy:
            return False
        remaining = self._busy[device_id]
        if remaining is not None:
            if remaining <= 1:
                del self._busy[device_id]
            else:
                self._busy[device_id] = remaining - 1
        return True

    def _insert_task(self, task: dict[str, Any]) -> dict[str, Any]:
        _sanitize_task(task)
        now = self.now()
        stamp = parse_iso(task.get("timestamp")) or now
        task["timestamp"] = iso(stamp)
        expiry = task.get("expiry")
        if isinstance(expiry, (int, float)) and not isinstance(expiry, bool):
            task["expiry"] = iso(stamp + timedelta(seconds=expiry))
        if task.get("uniqueKey"):
            # GenieACS replaces one earlier task with the same key, and leaves its fault.
            for index, other in enumerate(self.tasks):
                if other.get("device") == task["device"] and other.get("uniqueKey") == task["uniqueKey"]:
                    del self.tasks[index]
                    break
        task["_id"] = self._new_id()
        self.tasks.append(task)
        return copy.deepcopy(task)

    def _handle(self, request: RecordedRequest) -> _Reply:
        with self.lock:
            self.requests.append(request)
            if self._scripted:
                request.outcome = "scripted"
                reply = self._scripted.pop(0)
                request.status = reply.status
                return reply
            if self._crash_plan:
                after = self._crash_plan.pop(0)
                if after:
                    with contextlib.suppress(_Crash):
                        self._route(request)
                self.crashes += 1
                request.outcome = "crashed"
                return _Reply(crash=True)
            try:
                reply = self._route(request)
            except _Crash:
                self.crashes += 1
                request.outcome = "crashed"
                return _Reply(crash=True)
            if reply.streamed and self._truncate:
                self._truncate -= 1
                reply.truncate = True
                request.outcome = "truncated"
            request.status = reply.status
            return reply

    def _route(self, request: RecordedRequest) -> _Reply:
        path, method = request.path, request.method
        if match := _PRESET_ROUTE.fullmatch(path):
            return self._preset(method, _decode_segment(match.group(1)), request.body)
        if match := _PROVISION_ROUTE.fullmatch(path):
            return self._provision(method, _decode_segment(match.group(1)), request.body)
        if match := _TAG_ROUTE.fullmatch(path):
            return self._tag(method, _decode_segment(match.group(1)), _decode_segment(match.group(2)))
        if match := _FAULT_ROUTE.fullmatch(path):
            if method != "DELETE":
                return _not_allowed("DELETE")
            return self._delete_fault(_decode_segment(match.group(1)))
        if match := _FILE_ROUTE.fullmatch(path):
            return self._file(method, _decode_segment(match.group(1)), request)
        if match := _DEVICE_TASKS_ROUTE.fullmatch(path):
            if method != "POST":
                return _not_allowed("POST")
            return self._post_task(_decode_segment(match.group(1)), request)
        if match := _TASK_ROUTE.fullmatch(path):
            return self._task(method, _decode_segment(match.group(1)), match.group(2))
        if match := _DEVICE_ROUTE.fullmatch(path):
            if method != "DELETE":
                return _not_allowed("DELETE")
            return self._delete_device(_decode_segment(match.group(1)))
        if match := _COLLECTION_ROUTE.fullmatch(path):
            return self._query(method, _camel(match.group(1)), request.query)
        return _text(404, "404 Not Found")

    def _preset(self, method: str, name: str, body: bytes) -> _Reply:
        if method == "PUT":
            try:
                preset = json.loads(body.decode())
            except ValueError as exc:
                return _text(400, f"SyntaxError: {exc}")
            if not isinstance(preset, dict):
                raise _Crash("preset body is not an object")
            preset["_id"] = name
            self.presets[name] = preset
            self.cache_invalidations += 1
            return _text(200)
        if method == "DELETE":
            self.presets.pop(name, None)
            self.cache_invalidations += 1
            return _text(200)
        return _not_allowed("PUT, DELETE")

    def _provision(self, method: str, name: str, body: bytes) -> _Reply:
        if method == "PUT":
            script = body.decode("utf-8", errors="replace")
            error = self.check_script(script)
            if error:
                return _text(400, error)
            self.provisions[name] = {"_id": name, "script": script}
            self.cache_invalidations += 1
            return _text(200)
        if method == "DELETE":
            self.provisions.pop(name, None)
            self.cache_invalidations += 1
            return _text(200)
        return _not_allowed("PUT, DELETE")

    def _file(self, method: str, name: str, request: RecordedRequest) -> _Reply:
        if method == "PUT":
            # Node lowercases header names, so any capitalisation reaches GenieACS.
            headers = {key.lower(): value for key, value in request.headers.items()}
            metadata = {
                key: headers.get(key.lower())
                for key in ("fileType", "oui", "productClass", "version")
                if headers.get(key.lower()) is not None
            }
            self.files[name] = {
                "_id": name,
                "length": len(request.body),
                "chunkSize": 261120,
                "uploadDate": iso(self.now()),
                "filename": name,
                "metadata": metadata,
            }
            self.file_data[name] = request.body
            return _text(201)
        if method == "DELETE":
            if self.files.pop(name, None) is None:
                return _text(404, "404 Not Found")
            self.file_data.pop(name, None)
            return _text(200)
        return _not_allowed("PUT, DELETE")

    def _tag(self, method: str, device_id: str, tag: str) -> _Reply:
        if method not in ("POST", "DELETE"):
            return _not_allowed("POST, DELETE")
        device = self.devices.get(device_id)
        if device is None:
            return _text(404, "No such device")
        tags = device.setdefault("_tags", [])
        if method == "POST" and tag not in tags:
            tags.append(tag)
        elif method == "DELETE" and tag in tags:
            tags.remove(tag)
        return _text(200)

    def _delete_fault(self, fault_id: str) -> _Reply:
        device_id, _, channel = fault_id.partition(":")
        if self._locked(device_id):
            return _text(503, "Device is in session")
        self.faults.pop(fault_id, None)
        if channel.startswith("task_"):
            task_id = _object_id(channel[5:])
            self.tasks = [task for task in self.tasks if task["_id"] != task_id]
        return _text(200)

    def _post_task(self, device_id: str, request: RecordedRequest) -> _Reply:
        wants_cr = "connection_request" in request.query
        task: dict[str, Any] | None = None
        if request.body:
            try:
                parsed = json.loads(request.body.decode())
            except ValueError as exc:
                return _text(400, f"SyntaxError: {exc}")
            if not isinstance(parsed, dict):
                return _text(400, "TypeError: Cannot create property 'device'")
            task = parsed
            task["device"] = device_id
        if task is None and not wants_cr:
            return _text(400)
        if task is None or not wants_cr:
            if device_id not in self.devices:
                return _text(404, "No such device")
            if task is not None:
                return _json_reply(202, self._insert_task(task))
            return self._connection_request(device_id)
        # Task plus connection request (F12). SkyRouter never sends this; it is kept so
        # a regression that starts using it fails on the reason phrase, not a hang.
        if self._locked(device_id):
            if device_id not in self.devices:
                return _text(404, "No such device")
            return _json_reply(202, self._insert_task(task), "Task queued but not processed")
        if device_id not in self.devices:
            return _text(404, "No such device")
        stored = self._insert_task(task)
        self.cr_requests.append(device_id)
        outcome = self._cr.get(device_id, CrOutcome())
        if outcome.status != 200:
            return _json_reply(202, stored, outcome.reason)
        if not outcome.session:
            return _json_reply(202, stored, "Task queued but not processed")
        self.run_session(device_id, cr=True)
        if f"{device_id}:task_{stored['_id']}" in self.faults:
            return _json_reply(202, stored, "Task faulted")
        return _json_reply(200, stored)

    def _connection_request(self, device_id: str) -> _Reply:
        self.cr_requests.append(device_id)
        outcome = self._cr.get(device_id, CrOutcome())
        if outcome.status == 200:
            if outcome.session:
                self.run_session(device_id, cr=True)
            return _text(200)
        return _text(outcome.status, outcome.reason, reason=outcome.reason)

    def _task(self, method: str, task_id: str, action: str | None) -> _Reply:
        if not action or action == "/":
            if method != "DELETE":
                return _not_allowed("PUT DELETE")
            _object_id(task_id)
            task = next((t for t in self.tasks if t["_id"] == task_id), None)
            if task is None:
                return _text(404, "Task not found")
            if self._locked(task["device"]):
                return _text(503, "Device is in session")
            self.tasks.remove(task)
            self.faults.pop(f"{task['device']}:task_{task_id}", None)
            return _text(200)
        if action == "/retry":
            if method != "POST":
                return _not_allowed("POST")
            _object_id(task_id)
            task = next((t for t in self.tasks if t["_id"] == task_id), None)
            if task is None:
                raise _Crash("retry dereferences the missing task")
            if self._locked(task["device"]):
                return _text(503, "Device is in session")
            self.faults.pop(f"{task['device']}:task_{task_id}", None)
            return _text(200)
        return _text(404)

    def _delete_device(self, device_id: str) -> _Reply:
        if self._locked(device_id):
            return _text(503, "Device is in session")
        # 200 whether or not anything matched: GenieACS never checks.
        if self.devices.pop(device_id, None) is not None:
            self.cpes.pop(device_id, None)
            self.tasks = [task for task in self.tasks if task.get("device") != device_id]
            self.faults = {key: value for key, value in self.faults.items() if not key.startswith(device_id + ":")}
        return _text(200)

    def _documents(self, collection: str) -> list[dict[str, Any]]:
        if collection == "devices":
            return list(self.devices.values())
        if collection == "tasks":
            return list(self.tasks)
        if collection == "faults":
            return list(self.faults.values())
        if collection == "presets":
            return list(self.presets.values())
        if collection == "provisions":
            return list(self.provisions.values())
        if collection == "files":
            return list(self.files.values())
        return []

    def _query(self, method: str, collection: str, params: dict[str, str]) -> _Reply:
        if method not in ("GET", "HEAD"):
            return _not_allowed("GET, HEAD")
        if collection not in _COLLECTIONS:
            return _text(404, "404 Not Found")
        query: Any = {}
        if "query" in params:
            try:
                query = json.loads(params["query"])
            except ValueError as exc:
                return _text(400, f"SyntaxError: {exc}")
        if not isinstance(query, dict):
            raise _Crash("query is not an object")
        if collection == "devices":
            matches = _device_filter(query)
        elif collection == "tasks":
            matches = _typed_filter(query, {"_id": _object_id, "timestamp": _date, "retries": _number})
        elif collection == "faults":
            matches = _typed_filter(query, {"timestamp": _date, "retries": _number})
        else:
            matches = _typed_filter(query, {})
        items = [doc for doc in self._documents(collection) if matches(doc)]

        if "sort" in params:
            try:
                sort = json.loads(params["sort"])
            except ValueError as exc:
                return _text(400, f"SyntaxError: {exc}")
            if not isinstance(sort, dict) or any(v not in (1, -1) or isinstance(v, bool) for v in sort.values()):
                raise _Crash("MongoDB rejects the sort")
            for key, direction in reversed(list(sort.items())):
                if collection == "devices" and not key.rsplit(".", 1)[-1].startswith("_"):
                    key = f"{key}._value"
                items.sort(key=functools.partial(_sort_key, key), reverse=direction == -1)

        total = len(items)
        reply_headers = {"Content-Type": "application/json", "total": str(total)}
        if method == "HEAD":
            return _Reply(status=200, headers=reply_headers)

        skip = _parse_int(params["skip"]) if "skip" in params else 0
        limit = _parse_int(params["limit"]) if "limit" in params else 0
        items = items[skip:]
        if limit:
            items = items[: abs(limit)]
        if "projection" in params:
            paths = [part.strip() for part in params["projection"].split(",")]
            if not all(paths):
                raise _Crash('MongoDB rejects the projection {"": 1}')
            # GenieACS drops a path already covered by its ancestor.
            paths = [p for p in paths if not any(p != q and p.startswith(q + ".") for q in paths)]
            items = [_project(doc, paths) for doc in items]
        body = "[\n" + ",\n".join(json.dumps(doc) for doc in items) + "\n]"
        return _Reply(status=200, body=body.encode(), headers=reply_headers, streamed=True)

    # -- the router check-in simulator ----------------------------------------------

    def run_session(self, device_id: str, cr: bool = True) -> dict[str, Any]:
        """One router check-in: expire, then run due tasks oldest first, as GenieACS does (F26).

        ``cr`` marks a session the router opened because of a connection request.
        Returns a report of what happened to each task, also kept in ``sessions``.
        """
        with self.lock:
            doc, cpe = self.devices[device_id], self.cpes[device_id]
            now = self.now()
            stamp = iso(now)
            doc["_lastInform"] = stamp
            report: dict[str, Any] = {
                "device": device_id,
                "timestamp": stamp,
                "events": ["6 CONNECTION REQUEST"] if cr else ["2 PERIODIC"],
                "tasks": [],
                "written": [],
            }
            if cpe.pending_transfer is not None:
                # The router opens this session with the outcome of a Download it
                # accepted in an earlier one.
                self._complete_transfer(device_id, doc, cpe, now, report)
            for task in [t for t in self.tasks if t.get("device") == device_id]:
                fault_id = f"{device_id}:task_{task['_id']}"
                expiry = parse_iso(task.get("expiry"))
                if expiry is not None and expiry <= now:
                    # Expired tasks go at the next session, their faults with them.
                    self.tasks.remove(task)
                    self.faults.pop(fault_id, None)
                    report["tasks"].append({"_id": task["_id"], "name": task["name"], "outcome": "expired"})
                    continue
                if (parse_iso(task.get("timestamp")) or now) > now:
                    continue
                fault = self.faults.get(fault_id)
                if fault is not None:
                    retry_at = parse_iso(fault["timestamp"]) or now
                    retry_at += timedelta(seconds=self.retry_delay * 2 ** fault.get("retries", 0))
                    if retry_at > now:
                        report["tasks"].append({"_id": task["_id"], "name": task["name"], "outcome": "waiting_retry"})
                        continue
                failure = self._run_task(task, doc, cpe, now, report)
                if failure is None:
                    self.tasks.remove(task)
                    self.faults.pop(fault_id, None)
                    outcome = "done"
                else:
                    code, message, detail = failure
                    self.faults[fault_id] = {
                        "_id": fault_id,
                        "device": device_id,
                        "channel": f"task_{task['_id']}",
                        "timestamp": stamp,
                        "code": code,
                        "message": message,
                        "detail": detail,
                        "retries": fault["retries"] + 1 if fault else 0,
                        "expiry": task.get("expiry"),
                        # GenieACS keeps the task's declarations here, written values
                        # included, as a JSON string.
                        "provisions": json.dumps(_task_provisions(task)),
                    }
                    outcome = "faulted"
                report["tasks"].append({"_id": task["_id"], "name": task["name"], "outcome": outcome})
            self.sessions.append(report)
            return copy.deepcopy(report)

    def _run_task(
        self, task: dict[str, Any], doc: dict[str, Any], cpe: FakeCpe, now: datetime, report: dict[str, Any]
    ) -> tuple[str, str, dict[str, Any]] | None:
        name = task["name"]
        if name in cpe.task_faults:
            code, message = cpe.task_faults[name]
            return code, message, {"faultCode": code.rsplit(".", 1)[-1], "faultString": message}
        if name == "getParameterValues":
            for path in task["parameterNames"]:
                self._refresh(doc, cpe, path, now)
        elif name == "refreshObject":
            self._refresh(doc, cpe, task["objectName"], now)
        elif name == "setParameterValues":
            return self._set_values(task, doc, cpe, now, report)
        elif name == "reboot":
            cpe.reboots += 1
            # The router comes back with a 1 BOOT inform, which moves _lastBoot (F30).
            doc["_lastBoot"] = iso(now + timedelta(milliseconds=1))
        elif name == "download":
            self._accept_download(task, doc, cpe, now, report)
        return None

    def _software_version_path(self, device_id: str) -> str:
        cpe = self.cpes[device_id]
        for path in cpe.leaves:
            if path.endswith(".DeviceInfo.SoftwareVersion"):
                return path
        root = "Device" if "Device" in self.devices[device_id] else "InternetGatewayDevice"
        return f"{root}.DeviceInfo.SoftwareVersion"

    def _accept_download(
        self, task: dict[str, Any], doc: dict[str, Any], cpe: FakeCpe, now: datetime, report: dict[str, Any]
    ) -> None:
        # The Download RPC succeeding only means the router took the job on; the
        # transfer's outcome comes in a TransferComplete, usually a session later.
        if cpe.download == "ignore":
            return
        stored = self.files.get(task.get("file", ""))
        fault = cpe.download_fault
        if stored is None and fault is None:
            # genieacs-fs answers 404, so the router's transfer fails.
            fault = ("cwmp.9010", "Download failure")
        version = cpe.download_version or (stored or {}).get("metadata", {}).get("version")
        cpe.pending_transfer = {"task_id": task["_id"], "file": task.get("file"), "version": version, "fault": fault}
        if cpe.download == "same_session":
            self._complete_transfer(task["device"], doc, cpe, now + timedelta(milliseconds=2), report)

    def _complete_transfer(
        self, device_id: str, doc: dict[str, Any], cpe: FakeCpe, now: datetime, report: dict[str, Any]
    ) -> None:
        transfer, cpe.pending_transfer = cpe.pending_transfer, None
        assert transfer is not None
        stamp = iso(now)
        if transfer["fault"] is not None:
            code, message = transfer["fault"]
            # No reboot: the router still runs its old image and only reports the failure.
            report["events"].append("7 TRANSFER COMPLETE")
            fault_id = f"{device_id}:task_{transfer['task_id']}"
            self.faults[fault_id] = {
                "_id": fault_id,
                "device": device_id,
                "channel": f"task_{transfer['task_id']}",
                "timestamp": stamp,
                "code": code,
                "message": message,
                "detail": {"faultCode": code.rsplit(".", 1)[-1], "faultString": message},
                "retries": 0,
                "provisions": json.dumps([["download", transfer["file"]]]),
            }
            return
        report["events"] += ["1 BOOT", "7 TRANSFER COMPLETE", "M Download"]
        cpe.reboots += 1
        doc["_lastBoot"] = stamp
        path = self._software_version_path(device_id)
        cpe.leaves[path] = CpeLeaf(transfer["version"], "xsd:string", False)
        # SoftwareVersion is a forced Inform parameter, so the boot inform recaches it.
        _set_cached_leaf(
            doc,
            path,
            {
                "_object": False,
                "_value": transfer["version"],
                "_type": "xsd:string",
                "_writable": False,
                "_timestamp": stamp,
            },
            stamp,
        )

    def _refresh(self, doc: dict[str, Any], cpe: FakeCpe, path: str, now: datetime) -> None:
        stamp = iso(now)

        def under(candidate: str) -> bool:
            return not path or candidate == path or candidate.startswith(path + ".")

        # Leaves the router no longer lists drop out of the cache.
        for cached_path, _ in list(iter_cached_leaves(doc)):
            if under(cached_path) and cached_path not in cpe.leaves:
                parent = _lookup(doc, cached_path.rsplit(".", 1)[0]) if "." in cached_path else doc
                if isinstance(parent, dict):
                    parent.pop(cached_path.rsplit(".", 1)[-1], None)
        for leaf_path, leaf in cpe.leaves.items():
            if under(leaf_path):
                cached = {
                    "_object": False,
                    "_value": cpe.read(leaf_path),
                    "_type": leaf.type,
                    "_writable": leaf.writable,
                    "_timestamp": stamp,
                }
                _set_cached_leaf(doc, leaf_path, cached, stamp)

    def _set_values(
        self, task: dict[str, Any], doc: dict[str, Any], cpe: FakeCpe, now: datetime, report: dict[str, Any]
    ) -> tuple[str, str, dict[str, Any]] | None:
        # GenieACS decides from its cache alone whether a value needs sending (F15).
        to_send: list[tuple[str, Any]] = []
        for entry in task["parameterValues"]:
            path, value = entry[0], entry[1]
            cached = _lookup(doc, path)
            if not isinstance(cached, dict) or cached.get("_writable") is not True:
                continue
            coerced = _coerce(value, cached.get("_type", "xsd:string"))
            if "_value" in cached and _same(cached["_value"], coerced):
                continue
            to_send.append((path, coerced))
        if not to_send:
            return None
        refused = [(path, cpe.leaf_faults[path]) for path, _ in to_send if path in cpe.leaf_faults]
        refused += [
            (path, ("cwmp.9008", "Attempt to set a non-writable parameter"))
            for path, _ in to_send
            if path in cpe.leaves and not cpe.leaves[path].writable and path not in cpe.leaf_faults
        ]
        if refused:
            code, message = refused[0][1]
            return (
                code,
                message,
                {
                    "faultCode": "9003",
                    "faultString": "Invalid arguments",
                    "setParameterValuesFault": [
                        {"parameterName": path, "faultCode": c.rsplit(".", 1)[-1], "faultString": m}
                        for path, (c, m) in refused
                    ],
                },
            )
        # A leaf GenieACS has cached but the router lacks draws 9005. GenieACS swallows
        # it, forgets the parameter and sends the rest again, so the task succeeds
        # without that leaf ever being written and without any fault.
        for path in [path for path, _ in to_send if path not in cpe.leaves]:
            parent = _lookup(doc, path.rsplit(".", 1)[0])
            if isinstance(parent, dict):
                parent.pop(path.rsplit(".", 1)[-1], None)
        stamp = iso(now + timedelta(milliseconds=1))
        for path, value in [(path, value) for path, value in to_send if path in cpe.leaves]:
            cpe.leaves[path].value = value
            leaf = _lookup(doc, path)
            leaf["_value"] = value
            leaf["_timestamp"] = stamp
            report["written"].append(path)
        return None


def _task_provisions(task: dict[str, Any]) -> list[list[Any]]:
    if task["name"] == "setParameterValues":
        return [["value", entry[0], entry[1]] for entry in task["parameterValues"]]
    if task["name"] == "getParameterValues":
        return [["refresh", name] for name in task["parameterNames"]]
    return [[task["name"]]]


def _make_handler(fake: FakeNbi) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        # HTTP/1.0: every reply ends with the connection, and a body with no length runs to the close.
        protocol_version = "HTTP/1.0"

        def log_message(self, *args: Any) -> None:
            return

        def _serve(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            split = urllib.parse.urlsplit(self.path)
            query = {
                key: values[0] for key, values in urllib.parse.parse_qs(split.query, keep_blank_values=True).items()
            }
            request = RecordedRequest(self.command, split.path, query, body, dict(self.headers.items()), self.path)
            reply = fake._handle(request)
            if reply.crash:
                # A dying worker writes nothing; the socket just closes.
                self.close_connection = True
                return
            self.send_response(reply.status, reply.reason)
            if fake.version is not None:
                self.send_header("GenieACS-Version", fake.version)
            for name, value in reply.headers.items():
                self.send_header(name, value)
            if reply.truncate:
                self.end_headers()
                self.wfile.write(reply.body[: max(1, len(reply.body) // 2)])
                self.close_connection = True
                return
            self.send_header("Content-Length", str(len(reply.body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(reply.body)

        do_GET = _serve
        do_HEAD = _serve
        do_POST = _serve
        do_PUT = _serve
        do_DELETE = _serve

    return Handler
