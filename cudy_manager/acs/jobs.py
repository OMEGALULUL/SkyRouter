"""Persistent records of the ACS jobs SkyRouter starts (brief §3.6).

A job outlives the request that created it: a router behind CGNAT only takes a
task at its next periodic inform, minutes later, and SkyRouter may restart in
between. So every job lives in data_dir/acs_jobs.json, shared by the server and
the CLI. Writes happen under an flock and land through an atomic rename, like the
reboot scheduler's state; reads take no lock, because a reader only ever sees a
whole file.

Moving a job along means talking to the NBI, and a connection request alone can
take 30 s, far too long to hold the file lock. So a job is leased instead: the
holder of the lease advances it, everyone else leaves it alone, and a lease left
behind by a process that died runs out.

A record never holds a secret. A Wi-Fi change keeps its passphrase in the vault,
and the job only keeps the vault reference. A firmware job keeps the stored file's
name and checksum, never its content.

The firmware library's index (FirmwareIndex) lives beside the jobs, in
data_dir/acs_firmware.json, and the customer each adopted router was linked to
(AdoptionIndex) in data_dir/acs_adoptions.json, under the same locking and
atomic-rename rules.
"""

import contextlib
import copy
import fcntl
import json
import logging
import os
import re
import secrets
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from ..models import ValidationError
from .tree import iso, parse_time

logger = logging.getLogger(__name__)

JOBS_FILE = "acs_jobs.json"
FORMAT_VERSION = 1

QUEUED = "queued"
CONTACTING_ROUTER = "contacting_router"
# The connection request failed (NAT, CGNAT, offline), so the job waits for the
# router's own periodic inform.
WAITING_FOR_CHECKIN = "waiting_for_checkin"
ACKNOWLEDGED = "acknowledged"
VERIFIED = "verified"
NOT_APPLIED = "not_applied"
REJECTED = "rejected"
EXPIRED = "expired"
CANCELLED = "cancelled"
ERROR = "error"

ACTIVE_STATES = (QUEUED, CONTACTING_ROUTER, WAITING_FOR_CHECKIN)
TERMINAL_STATES = (ACKNOWLEDGED, VERIFIED, NOT_APPLIED, REJECTED, EXPIRED, CANCELLED, ERROR)
STATES = ACTIVE_STATES + TERMINAL_STATES

_ENDINGS = frozenset(TERMINAL_STATES)
_MOVING = frozenset({CONTACTING_ROUTER, WAITING_FOR_CHECKIN})
TRANSITIONS: dict[str, frozenset[str]] = {
    QUEUED: _MOVING | _ENDINGS,
    # A re-sent connection request can land either way, so both states re-enter.
    CONTACTING_ROUTER: _MOVING | _ENDINGS,
    WAITING_FOR_CHECKIN: _MOVING | _ENDINGS,
    # Only a read-back after the router accepted a change can still upgrade it.
    ACKNOWLEDGED: frozenset({VERIFIED}),
    VERIFIED: frozenset(),
    NOT_APPLIED: frozenset(),
    REJECTED: frozenset(),
    EXPIRED: frozenset(),
    CANCELLED: frozenset(),
    ERROR: frozenset(),
}

KIND_WIFI = "wifi"
KIND_REBOOT = "reboot"
KIND_REFRESH = "refresh"
KIND_FIRMWARE = "firmware"
KINDS = (KIND_WIFI, KIND_REBOOT, KIND_REFRESH, KIND_FIRMWARE)

# What a terminal job may still be watching for: the read-back of an acknowledged
# Wi-Fi change, or the 1 BOOT inform after an accepted reboot.
WATCH_SCRUB = "scrub"
WATCH_BOOT = "boot"

RETENTION = timedelta(days=7)
# Longer than the slowest single advance: a 30 s connection request plus a
# handful of 15 s NBI calls.
LEASE_TTL = timedelta(minutes=5)
MAX_HISTORY = 50

JOB_ID_RE = re.compile(r"[0-9a-f]{16}")


class JobStoreError(RuntimeError):
    pass


def _write_whole(path: Path, payload: bytes) -> None:
    """Replace ``path`` through a private temporary file, so a reader never sees half of it."""
    fd, temporary = tempfile.mkstemp(prefix=path.stem + ".", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        with contextlib.suppress(OSError):
            os.chmod(path, 0o600)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)


def new_job_id() -> str:
    return secrets.token_hex(8)


def validate_job_id(job_id: Any) -> str:
    if not isinstance(job_id, str) or not JOB_ID_RE.fullmatch(job_id):
        raise ValidationError("job IDs are 16 lowercase hex characters")
    return job_id


def is_active(job: dict[str, Any]) -> bool:
    """Still moving, or terminal but watching for a later confirmation."""
    return job.get("state") in ACTIVE_STATES or bool(job.get("watch"))


def new_job(job_id: str, acs_id: str, kind: str, now: datetime, *, request: dict[str, Any]) -> dict[str, Any]:
    if kind not in KINDS:
        raise ValueError(f"unknown ACS job kind {kind!r}")
    stamp = iso(now)
    return {
        "id": validate_job_id(job_id),
        "acs_id": acs_id,
        "kind": kind,
        "state": QUEUED,
        "message": "Queued on the ACS.",
        "phase": None,
        "watch": None,
        "request": request,
        "plan": None,
        "steps": [],
        "cr_attempts": [],
        "vault_refs": {},
        "fault": None,
        "result": {},
        "expected_by": None,
        "superseded_by": None,
        "last_error": None,
        "created": stamp,
        "updated": stamp,
        "history": [{"at": stamp, "state": QUEUED, "note": "Created."}],
    }


def note(job: dict[str, Any], text: str, now: datetime) -> None:
    stamp = iso(now)
    job["updated"] = stamp
    job["history"].append({"at": stamp, "state": job["state"], "note": text})
    del job["history"][:-MAX_HISTORY]


def transition(job: dict[str, Any], state: str, message: str, now: datetime, *, detail: str | None = None) -> None:
    """Move a job to ``state``, refusing any move §3.6 does not allow."""
    current = job.get("state")
    if state not in TRANSITIONS.get(str(current), frozenset()):
        raise JobStoreError(f"ACS job {job.get('id')}: {current} cannot become {state}")
    job["state"] = state
    job["message"] = message
    note(job, detail or message, now)


def public_view(job: dict[str, Any]) -> dict[str, Any]:
    view = {key: copy.deepcopy(value) for key, value in job.items() if key != "lease"}
    view["terminal"] = job.get("state") in TERMINAL_STATES
    # What a UI polls on: nothing further will change once this is true.
    view["done"] = view["terminal"] and not job.get("watch")
    return view


class JobStore:
    def __init__(self, data_dir: str | Path, clock: Callable[[], datetime] | None = None):
        self.path = Path(data_dir).expanduser() / JOBS_FILE
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._lock_path = self.path.with_name(self.path.name + ".lock")
        self.clock = clock or (lambda: datetime.now(UTC))
        self._lock = threading.RLock()

    # -- file access ------------------------------------------------------------------

    def _load(self) -> dict[str, dict[str, Any]]:
        try:
            raw = self.path.read_text()
        except FileNotFoundError:
            return {}
        except OSError as exc:
            raise JobStoreError("ACS job file is unreadable") from exc
        try:
            data = json.loads(raw)
        except ValueError as exc:
            # Never start afresh over it: a job may be the only record of a
            # pending vault entry.
            raise JobStoreError(f"ACS job file {self.path} is corrupt") from exc
        jobs = data.get("jobs") if isinstance(data, dict) else None
        if not isinstance(jobs, dict) or not all(
            isinstance(key, str) and isinstance(value, dict) for key, value in jobs.items()
        ):
            raise JobStoreError(f"ACS job file {self.path} has an invalid format")
        return jobs

    def _save(self, jobs: dict[str, dict[str, Any]]) -> None:
        payload = {"version": FORMAT_VERSION, "jobs": jobs}
        _write_whole(self.path, json.dumps(payload, indent=2, sort_keys=True).encode())

    @contextlib.contextmanager
    def _exclusive(self) -> Iterator[dict[str, dict[str, Any]]]:
        with self._lock:
            handle = os.open(self._lock_path, os.O_WRONLY | os.O_CREAT, 0o600)
            try:
                fcntl.flock(handle, fcntl.LOCK_EX)
                jobs = self._load()
                before = json.dumps(jobs, sort_keys=True)
                yield jobs
                # Most polls change nothing; rewriting the file every 3 s would be
                # pointless disk traffic.
                if json.dumps(jobs, sort_keys=True) != before:
                    self._save(jobs)
            finally:
                os.close(handle)

    # -- reads ------------------------------------------------------------------------

    def all(self) -> dict[str, dict[str, Any]]:
        return self._load()

    def get(self, job_id: str) -> dict[str, Any] | None:
        return self._load().get(job_id)

    # -- leases -----------------------------------------------------------------------

    def _lease(self, token: str | None = None) -> tuple[dict[str, Any], str]:
        token = token or secrets.token_hex(8)
        until = iso(self.clock() + LEASE_TTL)
        return {"token": token, "until": until, "pid": os.getpid()}, token

    def create(self, job: dict[str, Any]) -> str:
        """Store a new job, leased to the caller; returns the lease token."""
        with self._exclusive() as jobs:
            if job["id"] in jobs:
                raise JobStoreError(f"ACS job {job['id']} already exists")
            lease, token = self._lease()
            stored = copy.deepcopy(job)
            stored["lease"] = lease
            jobs[job["id"]] = stored
            return token

    def claim(self, job_id: str, *, wait: float = 0.0) -> tuple[dict[str, Any], str] | None:
        """Lease a job: (a copy of it, token), or None when someone else holds it."""
        deadline = time.monotonic() + wait
        while True:
            with self._exclusive() as jobs:
                job = jobs.get(job_id)
                if job is None:
                    return None
                lease = job.get("lease")
                until = parse_time(lease.get("until")) if isinstance(lease, dict) else None
                if until is None or until <= self.clock():
                    if lease:
                        logger.warning(
                            "ACS job %s: taking over a lease that ran out (pid %s)", job_id, lease.get("pid")
                        )
                    job["lease"], token = self._lease()
                    view = copy.deepcopy(job)
                    del view["lease"]
                    return view, token
            if time.monotonic() >= deadline:
                return None
            time.sleep(0.05)

    def _held(self, jobs: dict[str, dict[str, Any]], job_id: str, token: str) -> dict[str, Any] | None:
        stored = jobs.get(job_id)
        lease = stored.get("lease") if stored else None
        if not isinstance(lease, dict) or lease.get("token") != token:
            return None
        return stored

    def checkpoint(self, job_id: str, token: str, job: dict[str, Any]) -> None:
        """Save progress without giving the lease up, so a crash cannot lose a queued task's ID."""
        with self._exclusive() as jobs:
            if self._held(jobs, job_id, token) is None:
                raise JobStoreError(f"ACS job {job_id}: the lease was lost")
            stored = copy.deepcopy(job)
            stored["lease"], _ = self._lease(token)
            jobs[job_id] = stored

    def release(self, job_id: str, token: str, job: dict[str, Any] | None = None) -> bool:
        """Save ``job`` (if given) and give the lease up. False if the lease was lost meanwhile."""
        with self._exclusive() as jobs:
            stored = self._held(jobs, job_id, token)
            if stored is None:
                # Whoever took the lease over has the newer view; ours is dropped.
                logger.warning("ACS job %s: lease lost before the update was saved", job_id)
                return False
            if job is None:
                stored.pop("lease", None)
            else:
                updated = copy.deepcopy(job)
                updated.pop("lease", None)
                jobs[job_id] = updated
            return True

    # -- housekeeping -----------------------------------------------------------------

    def prune(self) -> int:
        """Drop terminal jobs untouched for RETENTION; returns how many went."""
        cutoff = self.clock() - RETENTION
        with self._exclusive() as jobs:
            stale = [
                job_id
                for job_id, job in jobs.items()
                if not is_active(job) and not job.get("lease") and (parse_time(job.get("updated")) or cutoff) < cutoff
            ]
            for job_id in stale:
                del jobs[job_id]
            return len(stale)


# --- the firmware library and the adoptions ----------------------------------------------

FIRMWARE_FILE = "acs_firmware.json"
ADOPTIONS_FILE = "acs_adoptions.json"


class _RecordFile:
    """One JSON object of records by key, written whole under an flock like the jobs.

    A damaged file is never started afresh: each subclass is the only copy of what
    it records.
    """

    FILE = ""
    SECTION = ""
    LABEL = ""

    def __init__(self, data_dir: str | Path):
        self.path = Path(data_dir).expanduser() / self.FILE
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._lock_path = self.path.with_name(self.path.name + ".lock")
        self._lock = threading.RLock()

    def _load(self) -> dict[str, dict[str, Any]]:
        try:
            raw = self.path.read_text()
        except FileNotFoundError:
            return {}
        except OSError as exc:
            raise JobStoreError(f"{self.LABEL} is unreadable") from exc
        try:
            data = json.loads(raw)
        except ValueError as exc:
            raise JobStoreError(f"{self.LABEL} {self.path} is corrupt") from exc
        records = data.get(self.SECTION) if isinstance(data, dict) else None
        if not isinstance(records, dict) or not all(
            isinstance(key, str) and isinstance(value, dict) for key, value in records.items()
        ):
            raise JobStoreError(f"{self.LABEL} {self.path} has an invalid format")
        return records

    @contextlib.contextmanager
    def _exclusive(self) -> Iterator[dict[str, dict[str, Any]]]:
        with self._lock:
            handle = os.open(self._lock_path, os.O_WRONLY | os.O_CREAT, 0o600)
            try:
                fcntl.flock(handle, fcntl.LOCK_EX)
                records = self._load()
                before = json.dumps(records, sort_keys=True)
                yield records
                if json.dumps(records, sort_keys=True) != before:
                    payload = {"version": FORMAT_VERSION, self.SECTION: records}
                    _write_whole(self.path, json.dumps(payload, indent=2, sort_keys=True).encode())
            finally:
                os.close(handle)

    def all(self) -> dict[str, dict[str, Any]]:
        return self._load()

    def get(self, key: str) -> dict[str, Any] | None:
        return self._load().get(key)


class FirmwareIndex(_RecordFile):
    """What SkyRouter knows about the firmware files it stored on the ACS.

    GenieACS keeps only fileType, oui, productClass and version with a file, so the
    checksum, size, original file name and upload time are kept here. A record never
    holds the file's content. It is the only record of which stored files are
    SkyRouter's and what their checksums are.
    """

    FILE = FIRMWARE_FILE
    SECTION = "files"
    LABEL = "ACS firmware index"

    def add(self, record: dict[str, Any]) -> None:
        with self._exclusive() as files:
            if record["name"] in files:
                raise JobStoreError(f"firmware {record['name']} is already in the library")
            files[record["name"]] = copy.deepcopy(record)

    def remove(self, name: str) -> dict[str, Any] | None:
        with self._exclusive() as files:
            return files.pop(name, None)


class AdoptionIndex(_RecordFile):
    """The Vexar customer each adopted TR-069 router was linked to, by ACS ID.

    GenieACS has nowhere to keep it: a tag cannot hold "#1080 Customer A", and a
    parameter would be the router's own to overwrite. Holds no secret.
    """

    FILE = ADOPTIONS_FILE
    SECTION = "routers"
    LABEL = "ACS adoption record"

    def put(self, acs_id: str, record: dict[str, Any] | None) -> dict[str, Any] | None:
        """Store ``record`` for the router, or drop its entry for None; returns what it replaced."""
        with self._exclusive() as routers:
            previous = routers.pop(acs_id, None)
            if record is not None:
                routers[acs_id] = copy.deepcopy(record)
            return previous
