"""A permanent record of who changed what on which router.

Append-only JSON lines beside the vault. Entries hold no secrets: detail keys that
name one are refused rather than stored, because an audit log is copied, exported
and shown to people who were never meant to see a router or Wi-Fi password.
"""

import contextlib
import csv
import fcntl
import io
import json
import os
import re
import unicodedata
import uuid
from collections.abc import Callable, Iterator, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .models import ValidationError

KINDS = frozenset({"wifi", "reboot", "firmware", "setup", "credentials", "maintenance", "access"})
RESULTS = frozenset({"applied", "queued", "refused", "failed", "info"})

# Matched against detail keys at every depth. Deliberately broad: a refused entry
# is a bug report, a stored passphrase is an incident.
SECRET_KEY = re.compile(r"pass|key|secret|token|psk", re.IGNORECASE)

MAX_BYTES = 5 * 1024 * 1024
KEEP = 3
MAX_LIST = 1000
CSV_COLUMNS = ("at", "who", "router", "router_name", "kind", "result", "what", "details", "id")

_WHO_MAX = 100
_ROUTER_MAX = 100
_WHAT_MAX = 500
_DETAIL_TEXT_MAX = 200
_DETAIL_ITEMS_MAX = 20
_DETAIL_DEPTH_MAX = 2
_DETAIL_BYTES_MAX = 4096
_ID = re.compile(r"[0-9a-f]{32}")
# Bidirectional overrides can make a line read as a different router or result.
_BIDI = frozenset(chr(code) for code in (*range(0x202A, 0x202F), *range(0x2066, 0x206A)))
# LibreOffice and Excel evaluate a cell starting with one of these as a formula.
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")

_Entries = list[dict[str, Any]]


class ActivityError(ValidationError):
    """An entry or query the activity log will not accept."""


def _clean(value: Any, name: str, limit: int) -> str:
    if not isinstance(value, str):
        raise ActivityError(f"{name} must be a string")
    # Line and paragraph separators and control characters would let one entry
    # masquerade as several when the log is read as text.
    text = "".join(
        " " if char in _BIDI or unicodedata.category(char) in {"Cc", "Zl", "Zp"} else char for char in value
    ).strip()
    if len(text) > limit:
        text = text[: limit - 1] + "\u2026"
    return text


def _required(value: Any, name: str, limit: int) -> str:
    text = _clean(value, name, limit)
    if not text:
        raise ActivityError(f"{name} must not be empty")
    return text


def normalise_actor(actor: Any) -> str:
    """The actor as it will be stored, or ActivityError if there is none."""
    return _required(actor, "actor", _WHO_MAX)


def _detail(value: Any, depth: int) -> Any:
    # NaN and infinity are refused when the details are serialised (allow_nan=False).
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return _clean(value, "detail", _DETAIL_TEXT_MAX)
    if depth >= _DETAIL_DEPTH_MAX:
        raise ActivityError("activity details are nested too deeply")
    if isinstance(value, (list, tuple)):
        if len(value) > _DETAIL_ITEMS_MAX:
            raise ActivityError("activity details hold too many items")
        return [_detail(item, depth + 1) for item in value]
    if isinstance(value, Mapping):
        return _detail_map(value, depth + 1)
    raise ActivityError(f"activity details cannot hold {type(value).__name__}")


def _detail_map(value: Mapping[Any, Any], depth: int) -> dict[str, Any]:
    if len(value) > _DETAIL_ITEMS_MAX:
        raise ActivityError("activity details hold too many items")
    result: dict[str, Any] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key or len(key) > 64:
            raise ActivityError("activity detail keys must be short strings")
        if SECRET_KEY.search(key):
            # The value is never echoed: the error itself may be logged.
            raise ActivityError(f"refusing to store activity detail {key!r}: it looks like a secret")
        result[key] = _detail(item, depth)
    return result


def _details(value: Mapping[str, Any] | None) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ActivityError("activity details must be an object")
    details = _detail_map(value, 0)
    if len(_dumps(details).encode()) > _DETAIL_BYTES_MAX:
        raise ActivityError("activity details are too large")
    return details


def _dumps(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ActivityError(f"activity entry cannot be stored: {exc}") from exc


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        return None
    return moment.replace(tzinfo=UTC) if moment.tzinfo is None else moment


def _parse(line: str) -> dict[str, Any] | None:
    if not line.strip():
        return None
    try:
        entry = json.loads(line)
    except ValueError:
        # A line torn by a crash mid-write; the rest of the log is still good.
        return None
    required = ("id", "at", "who", "router", "kind", "what", "result")
    if not isinstance(entry, dict) or any(not isinstance(entry.get(field), str) for field in required):
        return None
    if not isinstance(entry.get("router_name"), str):
        entry["router_name"] = ""
    if not isinstance(entry.get("details"), dict):
        entry["details"] = {}
    return entry


def _csv_cell(value: Any) -> str:
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(_FORMULA_START) else text


class ActivityLog:
    def __init__(
        self,
        data_dir: str | Path,
        *,
        max_bytes: int = MAX_BYTES,
        keep: int = KEEP,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if max_bytes < 1 or keep < 1:
            raise ValueError("max_bytes and keep must be positive")
        self.data_dir = Path(data_dir).expanduser()
        self.path = self.data_dir / "activity.jsonl"
        # Separate from the log itself, which rotation renames: a writer queued on
        # the old file's lock would append to the rotated copy.
        self.lock_path = self.data_dir / "activity.lock"
        self.max_bytes = max_bytes
        self.keep = keep
        self._clock = clock or (lambda: datetime.now(UTC))

    def _rotated(self, index: int) -> Path:
        return self.path.with_name(f"{self.path.name}.{index}")

    @contextlib.contextmanager
    def _locked(self, mode: int) -> Iterator[None]:
        handle = os.open(self.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(handle, mode)
            yield
        finally:
            with contextlib.suppress(OSError):
                fcntl.flock(handle, fcntl.LOCK_UN)
            os.close(handle)

    def _rotate(self) -> None:
        for index in range(self.keep - 1, 0, -1):
            with contextlib.suppress(FileNotFoundError):
                os.replace(self._rotated(index), self._rotated(index + 1))
        os.replace(self.path, self._rotated(1))

    def _append(self, line: bytes) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self._locked(fcntl.LOCK_EX):
            try:
                size = self.path.stat().st_size
            except FileNotFoundError:
                size = 0
            if size and size + len(line) > self.max_bytes:
                self._rotate()
            handle = os.open(self.path, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                # The mode given to open only applies to a new file.
                os.fchmod(handle, 0o600)
                size = os.fstat(handle).st_size
                # A crash mid-write leaves a torn last line; appending straight after
                # it would glue this entry onto it and lose both.
                if size and os.pread(handle, 1, size - 1) != b"\n":
                    line = b"\n" + line
                view = memoryview(line)
                while view:
                    view = view[os.write(handle, view) :]
                os.fsync(handle)
            finally:
                os.close(handle)

    def record(
        self,
        *,
        who: str,
        router: str,
        kind: str,
        what: str,
        result: str,
        router_name: str = "",
        details: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Append one entry and return it as stored.

        Raises ActivityError, storing nothing, for an unknown kind or result, an
        empty actor, router or description, or a detail key that names a secret.
        """
        if kind not in KINDS:
            raise ActivityError(f"activity kind must be one of {', '.join(sorted(KINDS))}")
        if result not in RESULTS:
            raise ActivityError(f"activity result must be one of {', '.join(sorted(RESULTS))}")
        moment = self._clock()
        moment = moment.replace(tzinfo=UTC) if moment.tzinfo is None else moment.astimezone(UTC)
        entry = {
            "id": uuid.uuid4().hex,
            "at": moment.isoformat(),
            "who": normalise_actor(who),
            "router": _required(router, "router", _ROUTER_MAX),
            "router_name": _clean(router_name, "router_name", _ROUTER_MAX),
            "kind": kind,
            "what": _required(what, "what", _WHAT_MAX),
            "result": result,
            "details": _details(details),
        }
        text = _dumps(entry)
        self._append((text + "\n").encode("utf-8"))
        return json.loads(text)

    def _entries(self) -> Iterator[dict[str, Any]]:
        """Every readable entry, newest first. The caller holds the lock."""
        for path in (self.path, *(self._rotated(index) for index in range(1, self.keep + 1))):
            try:
                raw = path.read_bytes()
            except FileNotFoundError:
                continue
            # Split on newlines only: str.splitlines also breaks at U+2028 and
            # friends, which an SSID stored in the details may contain.
            for line in reversed(raw.decode("utf-8", "replace").split("\n")):
                entry = _parse(line)
                if entry is not None:
                    yield entry

    def _query(
        self,
        router: str | None,
        who: str | None,
        kind: str | None,
        limit: int | None,
        before: str | None,
    ) -> _Entries:
        if kind is not None and kind not in KINDS:
            raise ActivityError(f"activity kind must be one of {', '.join(sorted(KINDS))}")
        for name, value in (("router", router), ("who", who), ("before", before)):
            if value is not None and not isinstance(value, str):
                raise ActivityError(f"{name} must be a string")
        cursor = before if before is not None and _ID.fullmatch(before) else None
        cutoff = None
        if before is not None and cursor is None:
            cutoff = _time(before)
            if cutoff is None:
                raise ActivityError("before must be an activity entry id or an ISO 8601 time")
        if not self.data_dir.is_dir():
            return []
        found: _Entries = []
        with self._locked(fcntl.LOCK_SH):
            passed_cursor = cursor is None
            for entry in self._entries():
                if not passed_cursor:
                    passed_cursor = entry["id"] == cursor
                    continue
                if cutoff is not None:
                    moment = _time(entry["at"])
                    if moment is None or moment >= cutoff:
                        continue
                if router is not None and entry["router"] != router:
                    continue
                if who is not None and entry["who"] != who:
                    continue
                if kind is not None and entry["kind"] != kind:
                    continue
                found.append(entry)
                if limit is not None and len(found) >= limit:
                    break
        return found

    def list(
        self,
        router: str | None = None,
        who: str | None = None,
        kind: str | None = None,
        limit: int = 200,
        before: str | None = None,
    ) -> _Entries:
        """Entries newest first.

        ``before`` is either an entry id, for the page after that entry, or an ISO
        8601 time, for entries recorded strictly before it.
        """
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_LIST:
            raise ActivityError(f"limit must be an integer from 1 to {MAX_LIST}")
        return self._query(router, who, kind, limit, before)

    def export_csv(
        self,
        router: str | None = None,
        who: str | None = None,
        kind: str | None = None,
        limit: int | None = None,
        before: str | None = None,
    ) -> str:
        """The matching entries (every retained one without a limit) as CSV, newest first."""
        if limit is not None and (isinstance(limit, bool) or not isinstance(limit, int) or limit < 1):
            raise ActivityError("limit must be a positive integer, or omitted for every entry")
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(CSV_COLUMNS)
        for entry in self._query(router, who, kind, limit, before):
            row = {**entry, "details": _dumps(entry["details"]) if entry["details"] else ""}
            writer.writerow([_csv_cell(row.get(column)) for column in CSV_COLUMNS])
        return buffer.getvalue()
