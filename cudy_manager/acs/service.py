"""AcsService: what SkyRouter does with GenieACS, built on the NBI client.

Reads (health, the device list, one device) only read GenieACS and never reach a
router, so dashboard polling costs the routers nothing (brief §3.6). Actions
(refresh, reboot, Wi-Fi) each start a job and return at once; poll_jobs() moves
every job along from what the NBI reports, a few short GETs at a time, so no
thread ever waits inside a router session (decision 4).

The Wi-Fi flow (§3.7) is shaped by two GenieACS behaviours (F15, F27): it decides
from its cache alone whether a leaf needs writing, skipping an uncached, read-only
or unchanged one without a fault; and a passphrase reads back as "". Hence the
pre-flight against the cache, the read (task A) before the write (task B) so a
cached secret cannot make the write look unnecessary, and a verdict drawn from
each leaf's cached value and _timestamp against B's own timestamp, which is
GenieACS's clock and so immune to skew.

A firmware upgrade (a download task) is never taken as done when its task goes:
that only means the router accepted the Download RPC, and the transfer's outcome
arrives later, in a TransferComplete that may come in a later session. It is
verified only once the router reports the file's version as its SoftwareVersion
from a boot after the task was queued; a transfer fault on the task's channel
rejects it.

Everything here blocks: call it from async code through asyncio.to_thread.
"""

import contextlib
import hashlib
import logging
import re
import secrets
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from ..manager import validate_wifi_passphrase, validate_wifi_ssid
from ..models import ValidationError
from ..secrets import SecretStore, SecretStoreError
from . import bootstrap, params
from . import tasks as nbi_tasks
from .client import (
    FIRMWARE_FILE_TYPE,
    MAX_FILE_BYTES,
    AcsBusy,
    AcsClient,
    AcsError,
    AcsNotFound,
    AcsUnavailable,
    CrResult,
    device_search_query,
    validate_device_id,
    validate_fault_id,
    validate_file_metadata,
    validate_tag,
)
from .jobs import (
    ACKNOWLEDGED,
    ACTIVE_STATES,
    CANCELLED,
    CONTACTING_ROUTER,
    ERROR,
    EXPIRED,
    JOB_ID_RE,
    KIND_FIRMWARE,
    KIND_REBOOT,
    KIND_REFRESH,
    KIND_WIFI,
    NOT_APPLIED,
    QUEUED,
    REJECTED,
    TERMINAL_STATES,
    VERIFIED,
    WAITING_FOR_CHECKIN,
    WATCH_BOOT,
    WATCH_SCRUB,
    AdoptionIndex,
    FirmwareIndex,
    JobStore,
    JobStoreError,
    is_active,
    new_job,
    new_job_id,
    note,
    public_view,
    transition,
    validate_job_id,
)
from .tree import ROOT_TR098, ROOT_TR181, DeviceTree, clean_text, iso, parse_time

logger = logging.getLogger(__name__)

# §3.6: a session that ran without taking the task earns another connection
# request, at most twice more and never sooner than 20 s after the last one.
CR_RESENDS = 2
CR_SPACING = timedelta(seconds=20)
# A router that answered the connection request but never opened a session will
# still take the task at its periodic inform, so the job says that instead.
CONTACT_WAIT = timedelta(minutes=2)
# GenieACS drops an expired task only at the router's next session, which may never
# come, so a job gives up on its own this long after the expiry.
EXPIRY_GRACE = timedelta(minutes=1)
BOOT_WAIT = timedelta(minutes=15)
PRUNE_INTERVAL = 60.0
# How long a router that accepted a firmware download gets to install it and come
# back reporting the new version. Downloading, flashing and rebooting take a few
# minutes; an hour also covers a slow link, and past it the operator should look.
FIRMWARE_INSTALL_WAIT = timedelta(hours=1)
MAX_FIRMWARE_BYTES = MAX_FILE_BYTES
_FIRMWARE_PREFIX = "skybre-fw-"
# The activity log's kinds and results, for the jobs worth an entry there. A
# refresh changes nothing on the router, so it gets none.
_ACTIVITY_KINDS = {KIND_WIFI: "wifi", KIND_REBOOT: "reboot", KIND_FIRMWARE: "firmware"}
_ACTIVITY_RESULTS = {
    VERIFIED: "applied",
    ACKNOWLEDGED: "applied",
    REJECTED: "refused",
    NOT_APPLIED: "failed",
    EXPIRED: "failed",
    ERROR: "failed",
    CANCELLED: "info",
}
SYSTEM_ACTOR = "system"
# The longest Vexar customer the adopt dialog may link a router to: a customer number
# and name, with room for a site ("#1080 Customer A, shop 2").
CUSTOMER_MAX = 120

# §3.8 allows fewer characters than GenieACS or the client would.
_TAG_RE = re.compile(r"[a-z0-9_-]{1,32}")
_SSID_BAD_RE = re.compile(r"[\x00-\x1f\x7f-\x9f\ud800-\udfff]")
# Also line separators and bidirectional overrides, which can make a customer read as another.
_CUSTOMER_BAD_RE = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069\ud800-\udfff]")
# uniqueKey suffixes: one Wi-Fi change per band replaces the last (F14).
_BAND_KEYS = {"2.4GHz": "24ghz", "5GHz": "5ghz", "6GHz": "6ghz", params.BAND_ALL: "all"}
_REPLAN_CODES = frozenset({"9007", "9008"})
# What deploy/genieacs/ext/skyrouter.js answers when its HMAC key is missing: an
# ext.Error fault on the skybre-inform channel whose message names the variable.
_CR_HMAC_CHANNEL = "skybre-inform"
_CR_HMAC_MARKER = "SKYROUTER_CR_SECRET"  # noqa: S105 - an environment variable's name, not its value
_CR_HMAC_HINT = (
    "SKYROUTER_CR_SECRET is unset or shorter than 32 hex characters on the GenieACS host, so routers get no "
    "connection-request password; set it in /etc/genieacs/genieacs.env and restart genieacs-cwmp."
)

# Enough for _lastInform, _lastBoot and the router's own inform interval.
_POLL_PROJECTION: tuple[str, ...] = (
    "_id",
    "_lastInform",
    "_lastBoot",
    *(
        f"{root}.ManagementServer.{name}"
        for root in (ROOT_TR098, ROOT_TR181)
        for name in ("ConnectionRequestURL", "PeriodicInformEnable", "PeriodicInformInterval")
    ),
)


class AcsConfirmationRequired(ValidationError):
    """A single-band Wi-Fi change on a band SkyRouter inferred rather than read (§3.5).

    Send it again with confirm_guessed_band=True. ``plan`` is the public plan,
    which names the networks and how their bands were worked out.
    """

    def __init__(self, message: str, plan: dict[str, Any]):
        super().__init__(message)
        self.plan = plan


class FirmwareMismatch(AcsConfirmationRequired):
    """The file was stored for a different OUI or product class than the router reports.

    Send it again with confirm_model_mismatch=True. ``plan`` names both sides.
    """


class ActivitySink(Protocol):
    """What AcsService needs of cudy_manager.activity.ActivityLog."""

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
    ) -> Any: ...


def _actor(actor: Any) -> str:
    if not isinstance(actor, str) or not actor.strip():
        raise ValidationError("actor must be a non-empty string")
    return clean_text(actor.strip(), 100)


def _same_identity(first: Any, second: Any) -> bool:
    # Routers disagree on the case of their OUI, and GenieACS keeps what they sent.
    return str(first or "").strip().casefold() == str(second or "").strip().casefold()


def _stripped(value: Any) -> Any:
    return value.strip() if isinstance(value, str) else value


def _display_name(filename: Any) -> str | None:
    if filename is None:
        return None
    if not isinstance(filename, str):
        raise ValidationError("filename must be a string")
    # Only for showing: the stored name is SkyRouter's own, never this one.
    base = filename.replace("\\", "/").rsplit("/", 1)[-1]
    return clean_text(base, 128).strip() or None


def _vault_prefix(acs_id: str) -> str:
    # Device IDs carry "%", which vault references cannot, hence the hash.
    return f"acs-wifi-{hashlib.sha256(acs_id.encode('utf-8')).hexdigest()[:20]}-"


def vault_ref(acs_id: str, band: str, stage: str) -> str:
    """The vault reference for a Wi-Fi passphrase; stage is "pending" or "current"."""
    return f"{_vault_prefix(acs_id)}{band}-{stage}"


def validate_ssid(ssid: Any) -> str:
    """DeviceManager's SSID check (§3.7 step 1), and no control characters.

    Stricter than the direct path because the write task would refuse a control
    character anyway (tasks.py); refusing it here does so before anything is
    stored or queued, with a message about the SSID rather than a leaf path.
    """
    if isinstance(ssid, str) and _SSID_BAD_RE.search(ssid.strip()):
        raise ValidationError("SSID must not contain control characters")
    return validate_wifi_ssid(ssid)


def validate_customer(customer: Any) -> str | None:
    """The Vexar customer an adopted router is linked to, trimmed; None when not given.

    A tab or line break inside it is refused rather than turned into a space: it is
    shown on one line in the list and the activity log, and nobody types one there.
    """
    if customer is None:
        return None
    if not isinstance(customer, str):
        raise ValidationError("customer must be text")
    text = customer.strip()
    if not text:
        raise ValidationError("Enter the Vexar customer.")
    if _CUSTOMER_BAD_RE.search(text):
        raise ValidationError("customer must not contain control characters")
    if len(text) > CUSTOMER_MAX:
        raise ValidationError(f"customer must be at most {CUSTOMER_MAX} characters")
    return text


def _short(exc: BaseException | str, limit: int = 200) -> str:
    return clean_text(str(exc), limit)


def _expiry(value: Any, default: int) -> int:
    """How long a queued task may wait for the router, in whole seconds; ``default`` when None."""
    if value is None:
        return default
    lowest, highest = nbi_tasks.MIN_EXPIRY, nbi_tasks.MAX_EXPIRY
    if isinstance(value, bool) or not isinstance(value, int) or not lowest <= value <= highest:
        raise ValidationError(f"expiry must be whole seconds from {lowest} to {highest}")
    return value


def _bands_overlap(first: str, second: str) -> bool:
    return first == second or params.BAND_ALL in (first, second)


def _code(value: Any) -> str:
    return clean_text(value, 64).strip().removeprefix("cwmp.")


def _fault_summary(fault: dict[str, Any]) -> dict[str, Any]:
    """A fault as SkyRouter shows it: codes, messages and the parameter names, never values."""
    raw_detail = fault.get("detail")
    detail: dict[str, Any] = raw_detail if isinstance(raw_detail, dict) else {}
    entries = detail.get("setParameterValuesFault") or []
    if isinstance(entries, dict):
        entries = [entries]
    parameters = [
        {
            "path": clean_text(entry["parameterName"], 256),
            "code": _code(entry.get("faultCode", "")),
            "message": clean_text(entry.get("faultString", ""), 200),
        }
        for entry in entries
        if isinstance(entry, dict) and isinstance(entry.get("parameterName"), str)
    ]
    retries = fault.get("retries")
    return {
        "id": clean_text(fault.get("_id", ""), 320),
        "device": clean_text(fault.get("device", ""), 256),
        "channel": clean_text(fault.get("channel", ""), 64),
        "code": clean_text(fault.get("code", ""), 64),
        "message": clean_text(fault.get("message", ""), 300),
        "timestamp": fault.get("timestamp") if isinstance(fault.get("timestamp"), str) else None,
        "retries": retries if isinstance(retries, int) and not isinstance(retries, bool) else None,
        "parameters": parameters,
    }


def _fault_text(summary: dict[str, Any]) -> str:
    text = f"{summary['code']} {summary['message']}".strip() or "unknown fault"
    if summary["parameters"]:
        parts = (f"{p['path']}: {p['code']} {p['message']}".strip() for p in summary["parameters"])
        text += " (" + ", ".join(parts) + ")"
    return text


def _fault_codes(summary: dict[str, Any]) -> str:
    """A fault without the router's own wording: its codes and the parameters they are about."""
    text = str(summary.get("code") or "").strip() or "unknown fault"
    parameters = summary.get("parameters") or []
    if parameters:
        text += " (" + ", ".join(f"{p['path']}: {p['code']}".strip() for p in parameters) + ")"
    return text


class AcsService:
    def __init__(
        self,
        client: AcsClient,
        secrets: SecretStore,
        data_dir: str | Path,
        inform_interval: int = bootstrap.DEFAULT_INFORM_INTERVAL,
        scrub_secrets: bool = True,
        clock: Callable[[], datetime] | None = None,
        activity: ActivitySink | None = None,
    ):
        self.client = client
        self.secrets = secrets
        self.data_dir = Path(data_dir).expanduser()
        self.inform_interval = bootstrap.validate_inform_interval(inform_interval)
        self.scrub_secrets = bool(scrub_secrets)
        self.clock = clock or (lambda: datetime.now(UTC))
        self.jobs = JobStore(self.data_dir, self._now)
        self.firmware = FirmwareIndex(self.data_dir)
        self.adoptions = AdoptionIndex(self.data_dir)
        # Optional: the permanent who-changed-what log. Each Wi-Fi, reboot and
        # firmware job lands there once, when it first reaches a terminal state.
        self.activity = activity
        self._last_prune = float("-inf")
        # Two Wi-Fi changes to one band share a pending vault entry and a uniqueKey, so
        # superseding the older one and recording the newer one must not interleave.
        self._wifi_lock = threading.Lock()
        # Two upgrades of one router share the skyrouter-firmware uniqueKey, so the
        # second would silently replace the first's task (F14).
        self._firmware_lock = threading.Lock()

    def _now(self) -> datetime:
        now = self.clock()
        return now if now.tzinfo else now.replace(tzinfo=UTC)

    def _device(self, acs_id: str, projection: Sequence[str]) -> dict[str, Any]:
        doc = self.client.get_device(acs_id, projection)
        if doc is None:
            raise AcsNotFound("No such device", status=404)
        return doc

    def _expected_by(self, doc: dict[str, Any], now: datetime) -> str | None:
        """_lastInform plus the router's inform interval, as the device card shows it."""
        try:
            expected = params.summarize(doc, now, self.inform_interval)["expected_by"]
        except (ValueError, TypeError, KeyError):
            return None
        return expected if isinstance(expected, str) else None

    # -- reads ------------------------------------------------------------------------

    def health(self) -> dict[str, Any]:
        """GET /api/acs: {configured, reachable, version, bootstrap, channel_faults, problems, jobs}."""
        result: dict[str, Any] = {
            "configured": True,
            "reachable": False,
            "version": None,
            "error": None,
            "bootstrap": None,
            "channel_faults": [],
            "problems": [],
            "jobs": {"active": None},
        }
        try:
            result["jobs"]["active"] = sum(1 for job in self.jobs.all().values() if is_active(job))
        except JobStoreError as exc:
            result["problems"].append(str(exc))
        try:
            self.adoptions.all()
        except JobStoreError as exc:
            # The router list still loads without it, so this is where it shows.
            result["problems"].append(f"{exc}: the routers' customers cannot be shown and adopting is refused")
        try:
            result["version"] = self.client.version()
            self.client.check_db()
        except AcsError as exc:
            # An unsupported version still answered; only a transport failure is "unreachable".
            result["reachable"] = not isinstance(exc, AcsUnavailable)
            result["error"] = _short(exc)
            return result
        result["reachable"] = True
        try:
            result["bootstrap"] = bootstrap.drift(self.client, self.inform_interval)
        except (AcsError, OSError, ValueError) as exc:
            result["bootstrap"] = {"installed": False, "drift": [], "seeded_presets": [], "error": _short(exc)}
        try:
            faults = self.client.faults(channels=list(bootstrap.CHANNELS))
        except AcsError as exc:
            result["problems"].append(f"could not read the provisioning faults: {_short(exc)}")
            faults = []
        for fault in faults:
            view = _fault_summary(fault)
            view["hint"] = None
            if (
                view["channel"] == _CR_HMAC_CHANNEL
                and view["code"] == "ext.Error"
                and _CR_HMAC_MARKER in view["message"]
            ):
                view["hint"] = _CR_HMAC_HINT
                if _CR_HMAC_HINT not in result["problems"]:
                    result["problems"].append(_CR_HMAC_HINT)
            result["channel_faults"].append(view)
        return result

    def list_devices(
        self, q: str | None = None, tag: str | None = None, skip: int = 0, limit: int = 50
    ) -> dict[str, Any]:
        """GET /api/acs/devices: {devices: [summary], total}, most recent check-in first."""
        query: dict[str, Any] = {}
        if q is not None:
            if not isinstance(q, str):
                raise ValidationError("search text must be a string")
            if q.strip():
                query.update(device_search_query(q.strip()))
        if tag not in (None, ""):
            query["_tags"] = validate_tag(tag)
        page = self.client.find(
            "devices", query, projection=params.SUMMARY_PROJECTION, sort={"_lastInform": -1}, skip=skip, limit=limit
        )
        now = self._now()
        customers = self._customers()
        devices = []
        for doc in page.items:
            summary = self._summary(doc, now)
            summary["customer"] = customers.get(str(summary.get("acs_id")), {}).get("customer")
            devices.append(summary)
        return {"devices": devices, "total": page.total}

    def _customers(self) -> dict[str, dict[str, Any]]:
        """Every router's adoption record, or none while the file is damaged: the fleet must still list."""
        try:
            return self.adoptions.all()
        except JobStoreError as exc:
            logger.error("listing the TR-069 routers without their customers: %s", exc)
            return {}

    def _summary(self, doc: dict[str, Any], now: datetime) -> dict[str, Any]:
        try:
            return params.summarize(doc, now, self.inform_interval)
        except (ValueError, TypeError, KeyError, AttributeError):
            # One router's odd document must not hide the whole fleet.
            acs_id = doc.get("_id") if isinstance(doc.get("_id"), str) else None
            logger.exception("could not summarise ACS device %s", acs_id)
            return {"acs_id": acs_id, "error": "SkyRouter could not read this router's document"}

    def device_detail(self, acs_id: str) -> dict[str, Any]:
        """GET /api/acs/devices/{acs_id}: {device: {...params.detail(), pending_jobs, faults}}."""
        validate_device_id(acs_id)
        doc = self._device(acs_id, params.DETAIL_PROJECTION)
        device = params.detail(doc, self._now(), self.inform_interval)
        device["customer"] = self._customers().get(acs_id, {}).get("customer")
        device["pending_jobs"] = self.list_jobs(acs_id=acs_id, active_only=True)
        device["faults"] = [_fault_summary(fault) for fault in self.client.faults(device_id=acs_id)]
        return {"device": device}

    def list_jobs(self, acs_id: str | None = None, active_only: bool = False) -> list[dict[str, Any]]:
        """Jobs, newest first."""
        jobs = [
            job
            for job in self.jobs.all().values()
            if (acs_id is None or job.get("acs_id") == acs_id) and (not active_only or is_active(job))
        ]
        jobs.sort(key=lambda job: str(job.get("created", "")), reverse=True)
        return [public_view(job) for job in jobs]

    def has_active_jobs(self) -> bool:
        """For the poll loop: 3 s while this is true, 30 s otherwise (§3.6)."""
        return any(is_active(job) for job in self.jobs.all().values())

    def _running(
        self, acs_id: str, kind: str, match: Callable[[dict[str, Any]], bool] = lambda job: True
    ) -> dict[str, Any] | None:
        """The public view of a still-moving job of this kind for this router, if there is one."""
        for job in self.jobs.all().values():
            if (
                job.get("acs_id") == acs_id
                and job.get("kind") == kind
                and job.get("state") in ACTIVE_STATES
                and match(job)
            ):
                return public_view(job)
        return None

    def get_job(self, job_id: str) -> dict[str, Any]:
        validate_job_id(job_id)
        job = self.jobs.get(job_id)
        if job is None:
            raise AcsNotFound("No such job", status=404)
        return public_view(job)

    def known_secrets(self, acs_id: str) -> list[str]:
        """Passphrases SkyRouter holds for this router, so a raw dump can redact them by value."""
        prefix = _vault_prefix(validate_device_id(acs_id))
        values = []
        for reference in self.secrets.references():
            if reference.startswith(prefix):
                with contextlib.suppress(SecretStoreError):
                    values.append(self.secrets.get(reference))
        return values

    # -- actions ----------------------------------------------------------------------

    def refresh(self, acs_id: str, scope: str) -> dict[str, Any]:
        """Re-read one subtree of the router into GenieACS (refreshObject)."""
        validate_device_id(acs_id)
        if scope not in params.REFRESH_SCOPES:
            raise ValidationError(f"refresh scope must be one of {', '.join(params.REFRESH_SCOPES)}")
        doc = self._device(acs_id, params.DETAIL_PROJECTION)
        model = params.detect_model(doc)
        scopes = params.refresh_scopes(model, doc)
        if scope not in scopes:
            offered = ", ".join(sorted(scopes)) or "none"
            raise ValidationError(f"this router ({model}) has no {scope} scope to refresh; it offers: {offered}")
        # A second click would only replace the first task through its uniqueKey and
        # leave the first job watching a task that no longer exists.
        running = self._running(acs_id, KIND_REFRESH, lambda job: job["request"].get("scope") == scope)
        if running is not None:
            return running
        job = new_job(
            new_job_id(), acs_id, KIND_REFRESH, self._now(), request={"scope": scope, "object": scopes[scope]}
        )
        job["phase"] = "refresh"
        task = nbi_tasks.refresh_object(
            scopes[scope], job=job["id"], step="refresh", unique_key=f"skyrouter-refresh-{scope}"
        )
        return self._start(job, doc, [task])

    def reboot(self, acs_id: str, actor: str = SYSTEM_ACTOR, expiry: int | None = None) -> dict[str, Any]:
        """Reboot the router; verified once _lastBoot moves past the task's timestamp (F30).

        ``expiry`` (seconds, default an hour) bounds how long the task waits for a
        router that misses the connection request; a maintenance plan passes what
        is left of its window.
        """
        validate_device_id(acs_id)
        actor = _actor(actor)
        seconds = _expiry(expiry, nbi_tasks.DEFAULT_EXPIRY)
        doc = self._device(acs_id, _POLL_PROJECTION)
        # Never two reboots in a row from one impatient operator.
        running = self._running(acs_id, KIND_REBOOT)
        if running is not None:
            return running
        # A restart between the download and the router's own install restart can
        # leave it on a half-written image; maintenance plans already hold back here,
        # and the dashboard button must too.
        upgrading = self._running(acs_id, KIND_FIRMWARE)
        if upgrading is not None:
            raise AcsBusy(
                f"a firmware upgrade is in progress on this router (job {upgrading['id']}); "
                "reboot it after the upgrade finishes"
            )
        job = new_job(new_job_id(), acs_id, KIND_REBOOT, self._now(), request={})
        job["phase"] = "reboot"
        job["actor"] = actor
        return self._start(job, doc, [nbi_tasks.reboot(job=job["id"], step="reboot", expiry=seconds)])

    def set_wifi(
        self,
        acs_id: str,
        band: str,
        ssid: str | None = None,
        passphrase: str | None = None,
        confirm_guessed_band: bool = False,
        actor: str = SYSTEM_ACTOR,
    ) -> dict[str, Any]:
        """Change the SSID and/or passphrase of the primary network on one band or all (§3.7).

        The passphrase goes to the vault and into the write task, and nowhere else:
        not into the job, the logs, or any return value.
        """
        validate_device_id(acs_id)
        if band not in params.BAND_CHOICES:
            raise ValidationError(f"band must be one of {', '.join(params.BAND_CHOICES)}")
        if ssid is not None:
            ssid = validate_ssid(ssid)
        if passphrase is not None:
            validate_wifi_passphrase(passphrase)
        if ssid is None and passphrase is None:
            raise ValidationError("nothing to change: give a new SSID, a new passphrase, or both")
        if not isinstance(confirm_guessed_band, bool):
            raise ValidationError("confirm_guessed_band must be true or false")
        actor = _actor(actor)

        doc = self._device(acs_id, params.DETAIL_PROJECTION)
        plan = params.wifi_write_plan(doc, band, ssid, passphrase is not None)
        if not plan.ok and not plan.needs_refresh:
            raise ValidationError(f"the Wi-Fi change cannot be made: {plan.problem()}")
        if plan.needs_confirmation and not confirm_guessed_band:
            raise AcsConfirmationRequired(
                f"the router does not report which band this network is on; SkyRouter inferred {band}. "
                "Confirm the band to write it.",
                plan.to_public(),
            )

        job_id = new_job_id()
        job = new_job(
            job_id,
            acs_id,
            KIND_WIFI,
            self._now(),
            request={
                "band": band,
                "ssid": ssid,
                "passphrase": passphrase is not None,
                "confirm_guessed_band": confirm_guessed_band,
            },
        )
        job["plan"] = {"attempt": 0, "replans": 0, "avoid": [], "refreshed": False}
        job["actor"] = actor
        if passphrase is not None:
            job["vault_refs"] = {"pending": vault_ref(acs_id, band, "pending")}
        # Without the lock, two requests could each find nothing to supersede and both
        # go ahead. After it, the new job's lease keeps a later request from cancelling
        # it (and deleting the shared pending entry) until the passphrase is stored.
        with self._wifi_lock:
            self._supersede(acs_id, band, job_id)
            token = self.jobs.create(job)
        try:
            if passphrase is not None:
                # Before anything reaches the ACS (§3.7 step 3): from here on the vault
                # is the only place SkyRouter keeps it.
                self.secrets.put(passphrase, job["vault_refs"]["pending"])
            if plan.ok:
                self._queue_write(job, token, plan, doc, attempt=1)
            else:
                self._queue_wifi_refresh(job, token, plan, doc)
        except (AcsError, SecretStoreError, ValidationError) as exc:
            self._fail(job, exc)
        finally:
            self._release(job_id, token, job)
        return public_view(job)

    def cancel_job(self, job_id: str, actor: str | None = None) -> dict[str, Any]:
        """Delete the job's tasks. AcsBusy (409) while the router is mid-session."""
        validate_job_id(job_id)
        if actor is not None:
            actor = _actor(actor)
        stored = self.jobs.get(job_id)
        if stored is None:
            raise AcsNotFound("No such job", status=404)
        if stored.get("state") not in ACTIVE_STATES:
            return public_view(stored)
        claimed = self.jobs.claim(job_id, wait=5.0)
        if claimed is None:
            raise AcsBusy("this job is being updated right now; try again")
        job, token = claimed
        try:
            # A task that already ran is not cancelled after the fact: settle it first.
            self._advance(job, token, closing=True)
            if job["state"] in ACTIVE_STATES and self._delete_outstanding(job):
                self._advance(job, token, closing=True)
            if job["state"] in ACTIVE_STATES:
                job["cancelled_by"] = actor
                self._end(job, CANCELLED, self._cancel_message(job))
        finally:
            self._release(job_id, token, job)
        return public_view(job)

    def _cancel_message(self, job: dict[str, Any]) -> str:
        if job["kind"] == KIND_FIRMWARE and any(
            step["step"] == "download" and step.get("outcome") == "gone" for step in job["steps"]
        ):
            # Nothing takes a Download back once the router has it.
            return (
                "Stopped watching. The router had already accepted the firmware download, so it may still install it."
            )
        return "Cancelled before the router took the change."

    # -- firmware -------------------------------------------------------------------------

    def add_firmware(
        self,
        data: bytes,
        filename: str | None,
        model_hint: str | None,
        version: str,
        oui: str,
        product_class: str,
        actor: str = SYSTEM_ACTOR,
    ) -> dict[str, Any]:
        """Store a firmware image on the ACS and in SkyRouter's library; returns its record.

        ``version`` must be exactly what the router reports as DeviceInfo.SoftwareVersion
        once it runs this image, because that is how an upgrade is verified. ``oui``
        and ``product_class`` are those of the routers it is meant for (their
        DeviceId), which every upgrade is checked against. The stored name is random:
        genieacs-fs hands any stored file, unauthenticated, to whoever knows its name.
        """
        who = _actor(actor)
        if not isinstance(data, (bytes, bytearray)):
            raise ValidationError("the firmware must be given as bytes")
        if not data:
            raise ValidationError("the firmware file is empty")
        if len(data) > MAX_FIRMWARE_BYTES:
            raise ValidationError(f"the firmware file is larger than {MAX_FIRMWARE_BYTES // (1024 * 1024)} MiB")
        version = validate_file_metadata(_stripped(version), "version")
        oui = validate_file_metadata(_stripped(oui), "OUI")
        product_class = validate_file_metadata(_stripped(product_class), "product class")
        if model_hint is not None and not isinstance(model_hint, str):
            raise ValidationError("model hint must be a string")
        hint = (clean_text(model_hint, 64).strip() or None) if model_hint is not None else None
        name = f"{_FIRMWARE_PREFIX}{secrets.token_hex(16)}"
        record: dict[str, Any] = {
            "name": name,
            "filename": _display_name(filename),
            "model_hint": hint,
            "version": version,
            "oui": oui,
            "product_class": product_class,
            "file_type": FIRMWARE_FILE_TYPE,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "uploaded_at": iso(self._now()),
        }
        try:
            self.client.put_file(name, bytes(data), FIRMWARE_FILE_TYPE, oui, product_class, version)
        except AcsUnavailable as exc:
            if exc.outcome_unknown:
                # Without a library record it is never offered to a router, but a
                # stored copy would still be served to anyone who learnt its name.
                self._discard_file(name)
            raise
        try:
            self.firmware.add(record)
        except (JobStoreError, OSError):
            self._discard_file(name)
            raise
        self._log_library(who, record, f"Added {hint or product_class} {version} to the library")
        return {**record, "on_acs": True, "in_use_by": []}

    def list_firmware(self) -> list[dict[str, Any]]:
        """The library, newest first. ``on_acs`` is None while the ACS cannot be asked."""
        records = self.firmware.all()
        stored: set[str] | None
        try:
            stored = {str(item.get("name")) for item in self.client.list_files()}
        except AcsError as exc:
            logger.warning("could not list the firmware files on the ACS: %s", exc)
            stored = None
        users = self._firmware_users()
        views = []
        for record in records.values():
            name = str(record.get("name"))
            views.append(
                {**record, "on_acs": None if stored is None else name in stored, "in_use_by": users.get(name, [])}
            )
        views.sort(key=lambda view: str(view.get("uploaded_at", "")), reverse=True)
        return views

    def remove_firmware(self, name: str, actor: str = SYSTEM_ACTOR) -> dict[str, Any]:
        """Delete a library file from the ACS and the library. AcsBusy while an upgrade uses it."""
        nbi_tasks.validate_firmware_name(name)
        who = _actor(actor)
        record = self.firmware.get(name)
        if record is None:
            raise AcsNotFound("No such firmware in the library", status=404)
        # Under the lock, so an upgrade cannot start on the file between the check
        # and the delete and then have the router fetch a file that is gone.
        with self._firmware_lock:
            users = self._firmware_users().get(name)
            if users:
                raise AcsBusy(
                    f"firmware {name} is being installed by job {users[0]}; wait for it to finish or cancel it first"
                )
            with contextlib.suppress(AcsNotFound):
                self.client.delete_file(name)
            self.firmware.remove(name)
        model = record.get("model_hint") or record.get("product_class")
        self._log_library(who, record, f"Removed {model} {record.get('version')} from the library")
        return {"name": name, "removed": True}

    def _log_library(self, who: str, record: dict[str, Any], what: str) -> None:
        # Under the file's own name: the library is not a router, and "acs:" names one.
        self._log(
            who=who,
            router=f"library:{record.get('name')}",
            router_name="Firmware library",
            kind="firmware",
            what=what,
            result="applied",
            details={
                "file": record.get("name"),
                "version": record.get("version"),
                "oui": record.get("oui"),
                "product_class": record.get("product_class"),
                "size": record.get("size"),
            },
        )

    def _log(self, **entry: Any) -> None:
        """One activity entry for a change already made. Failing to record it never undoes the change."""
        if self.activity is None:
            return
        try:
            self.activity.record(**entry)
        except Exception:  # noqa: BLE001 - the audit log must never turn a change that happened into an error
            logger.exception("could not record in the activity log: %s", entry.get("what"))

    def _firmware_users(self) -> dict[str, list[str]]:
        users: dict[str, list[str]] = {}
        for job in self.jobs.all().values():
            if job.get("kind") == KIND_FIRMWARE and is_active(job):
                users.setdefault(str((job.get("request") or {}).get("firmware")), []).append(str(job.get("id")))
        return users

    def _discard_file(self, name: str) -> None:
        try:
            self.client.delete_file(name)
        except AcsNotFound:
            pass
        except AcsError as exc:
            logger.warning("could not delete firmware file %s from the ACS: %s", name, exc)

    def firmware_upgrade(
        self,
        acs_id: str,
        firmware_name: str,
        confirm_model_mismatch: bool = False,
        actor: str = SYSTEM_ACTOR,
        expiry: int | None = None,
    ) -> dict[str, Any]:
        """Install a library file on the router: a download task and a connection request.

        Refused unless the router is checking in, reports the OUI and product class
        the file was stored for (FirmwareMismatch, 409, unless confirm_model_mismatch),
        and runs something other than the file's version. The job is verified only
        when the router reports that version after a boot later than the task.
        ``expiry`` (seconds, default 24 h) bounds how long the download waits for the
        router to take it; installing can take up to FIRMWARE_INSTALL_WAIT after that.
        """
        validate_device_id(acs_id)
        nbi_tasks.validate_firmware_name(firmware_name)
        if not isinstance(confirm_model_mismatch, bool):
            raise ValidationError("confirm_model_mismatch must be true or false")
        actor = _actor(actor)
        seconds = _expiry(expiry, nbi_tasks.FIRMWARE_EXPIRY)
        record = self.firmware.get(firmware_name)
        if record is None:
            raise AcsNotFound("No such firmware in the library", status=404)
        running = self._running_firmware(acs_id, firmware_name)
        if running is not None:
            return running
        stored = self.client.get_file(firmware_name)
        if stored is None:
            raise ValidationError(
                f"firmware {firmware_name} is no longer on the ACS; remove it from the library and upload it again"
            )
        if stored.get("size") is not None and stored["size"] != record.get("size"):
            raise ValidationError(
                f"the ACS copy of firmware {firmware_name} is not the file SkyRouter stored; upload it again"
            )

        now = self._now()
        doc = self._device(acs_id, params.FIRMWARE_PROJECTION)
        device = params.firmware_identity(doc, now, self.inform_interval)
        if device["online"] is not True:
            # A router that stopped checking in may be half-way through something
            # already; firmware is the last thing to queue blind for it.
            raise ValidationError(
                f"the router has not checked in since {device['last_inform']}; "
                "SkyRouter only sends firmware to a router that is checking in"
            )
        mismatch = [key for key in ("oui", "product_class") if not _same_identity(device[key], record.get(key))]
        if mismatch and not confirm_model_mismatch:
            raise FirmwareMismatch(
                self._mismatch_message(record, device, mismatch), self._mismatch_plan(record, device, mismatch)
            )
        current = device["software_version"]
        if not current:
            raise ValidationError("the ACS does not know which firmware the router runs; refresh its info first")
        if current == record["version"]:
            raise ValidationError(f"the router already runs firmware {current}")

        job = new_job(
            new_job_id(),
            acs_id,
            KIND_FIRMWARE,
            now,
            request={
                "firmware": firmware_name,
                "version": record["version"],
                "from_version": current,
                "sha256": record.get("sha256"),
                "size": record.get("size"),
                "oui": device["oui"],
                "product_class": device["product_class"],
                "model": device["model"],
                "confirm_model_mismatch": confirm_model_mismatch,
                "model_mismatch": mismatch,
            },
        )
        job["phase"] = "firmware"
        job["actor"] = actor
        task = nbi_tasks.download(firmware_name, job=job["id"], step="download", expiry=seconds)
        with self._firmware_lock:
            running = self._running_firmware(acs_id, firmware_name)
            if running is not None:
                return running
            # remove_firmware may have deleted it since the look above.
            if self.firmware.get(firmware_name) is None:
                raise AcsNotFound("No such firmware in the library", status=404)
            token = self.jobs.create(job)
        return self._start(job, doc, [task], token=token)

    def _running_firmware(self, acs_id: str, name: str) -> dict[str, Any] | None:
        running = self._running(acs_id, KIND_FIRMWARE)
        if running is None or running["request"].get("firmware") == name:
            # The same file again is a second click, answered with the first job.
            return running
        raise AcsBusy(
            f"another firmware upgrade is under way on this router (job {running['id']}); wait for it or cancel it"
        )

    @staticmethod
    def _mismatch_plan(record: dict[str, Any], device: dict[str, Any], mismatch: list[str]) -> dict[str, Any]:
        return {
            "device": {
                key: device.get(key)
                for key in ("acs_id", "oui", "product_class", "manufacturer", "model", "software_version")
            },
            "firmware": {
                key: record.get(key) for key in ("name", "oui", "product_class", "model_hint", "version", "filename")
            },
            "mismatch": list(mismatch),
        }

    @staticmethod
    def _mismatch_message(record: dict[str, Any], device: dict[str, Any], mismatch: list[str]) -> str:
        labels = {"oui": "OUI", "product_class": "product class"}
        stored_for = ", ".join(f"{labels[key]} {record.get(key)}" for key in mismatch)
        reported = ", ".join(f"{labels[key]} {device.get(key) or 'unknown'}" for key in mismatch)
        return (
            f"firmware {record.get('name')} was stored for {stored_for}, but the router reports {reported}. "
            "Firmware built for another model can leave a router unusable; confirm to install it anyway."
        )

    # -- faults, tags and the bootstrap ---------------------------------------------------

    def retry_fault(self, fault_id: str) -> dict[str, Any]:
        """Run a faulted task again now, or clear a provisioning fault so it re-runs at the next check-in."""
        validate_fault_id(fault_id)
        device_id, _, channel = fault_id.partition(":")
        if channel.startswith("task_"):
            self.client.retry_fault_task(channel.removeprefix("task_"))
            action = "retried"
        else:
            # Preset channels have no retry route; without the fault they run again.
            self.client.delete_fault(fault_id)
            action = "cleared"
        # Retrying sends no connection request of its own (F16).
        try:
            result = self.client.connection_request(device_id)
        except AcsError as exc:
            result = CrResult(ok=False, reason=_short(exc))
        return {
            "fault_id": fault_id,
            "action": action,
            "connection_request": {"ok": result.ok, "reason": result.reason},
        }

    def clear_fault(self, fault_id: str) -> dict[str, Any]:
        """Delete a fault; for a task channel that deletes the task too (F16)."""
        validate_fault_id(fault_id)
        self.client.delete_fault(fault_id)
        return {"fault_id": fault_id, "cleared": True}

    def _tags(self, acs_id: str) -> list[str]:
        return DeviceTree(self._device(acs_id, ("_id", "_tags"))).tags

    def add_tag(self, acs_id: str, tag: str) -> dict[str, Any]:
        validate_device_id(acs_id)
        if not isinstance(tag, str) or not _TAG_RE.fullmatch(tag):
            raise ValidationError("tags must be 1-32 lowercase letters, digits, '_' or '-'")
        self.client.add_tag(acs_id, tag)
        return {"acs_id": acs_id, "tags": self._tags(acs_id)}

    def remove_tag(self, acs_id: str, tag: str) -> dict[str, Any]:
        validate_device_id(acs_id)
        if not isinstance(tag, str) or not _TAG_RE.fullmatch(tag):
            raise ValidationError("tags must be 1-32 lowercase letters, digits, '_' or '-'")
        self.client.remove_tag(acs_id, tag)
        return {"acs_id": acs_id, "tags": self._tags(acs_id)}

    def adopt(self, acs_id: str, customer: str | None = None, actor: str = SYSTEM_ACTOR) -> dict[str, Any]:
        """Take a router out of the "New devices" inbox (§3.9), linked to its Vexar customer when one is given.

        The link is stored before the tag goes, and put back if GenieACS refuses, so a
        router never leaves the inbox with its customer unrecorded. Adopting again
        replaces the customer.
        """
        validate_device_id(acs_id)
        who = _actor(actor)
        linked = validate_customer(customer)
        # Also the 404 for an unknown router, before anything is stored.
        summary = self._summary(self._device(acs_id, params.SUMMARY_PROJECTION), self._now())
        previous = None
        if linked is not None:
            record = {"customer": linked, "adopted_at": iso(self._now()), "adopted_by": who}
            previous = self.adoptions.put(acs_id, record)
        try:
            self.client.remove_tag(acs_id, bootstrap.NEW_DEVICE_TAG)
        except Exception as exc:
            # When the outcome is unknown the tag may be gone, so the link stays; if it
            # is not, the router is still in the inbox and its next adoption replaces it.
            if linked is not None and not (isinstance(exc, AcsUnavailable) and exc.outcome_unknown):
                try:
                    self.adoptions.put(acs_id, previous)
                except (JobStoreError, OSError):
                    logger.exception("could not undo the customer link of %s", acs_id)
            raise
        # The tag is gone, so from here the adoption stands: logged before the tags are
        # read back, which only reports them and may fail on its own.
        kept = linked if linked is not None else self._customers().get(acs_id, {}).get("customer")
        self._log(
            who=who,
            router=f"acs:{acs_id}",
            router_name=" · ".join(str(part) for part in (summary.get("model"), summary.get("serial")) if part),
            kind="setup",
            what=f"Adopted: linked to {linked}" if linked else "Adopted from the new routers list",
            result="applied",
            details={"customer": linked} if linked else None,
        )
        return {"acs_id": acs_id, "tags": self._tags(acs_id), "customer": kept}

    def bootstrap(self, remove_seeded: bool = False) -> dict[str, Any]:
        return bootstrap.install(self.client, self.inform_interval, remove_seeded=remove_seeded)

    def bootstrap_status(self) -> dict[str, Any]:
        return bootstrap.drift(self.client, self.inform_interval)

    # -- polling ----------------------------------------------------------------------

    def poll_jobs(self) -> None:
        """Advance every active job once. Safe from a background thread and from another process."""
        if time.monotonic() - self._last_prune >= PRUNE_INTERVAL:
            self._last_prune = time.monotonic()
            self.jobs.prune()
        jobs = sorted(self.jobs.all().values(), key=lambda job: str(job.get("created", "")))
        for job in jobs:
            if is_active(job):
                self._poll_one(job["id"])

    def _poll_one(self, job_id: str) -> None:
        claimed = self.jobs.claim(job_id)
        if claimed is None:
            return
        job, token = claimed
        try:
            self._advance(job, token)
            job["last_error"] = None
        except AcsNotFound:
            self._abandon(job, "The router is no longer in the ACS.")
        except AcsError as exc:
            # The ACS is down or mid-restart: the job waits, and says why.
            logger.warning("ACS job %s: %s", job_id, exc)
            job["last_error"] = _short(exc)
        except (ValidationError, SecretStoreError) as exc:
            self._abandon(job, f"SkyRouter could not continue this change: {_short(exc)}")
        except Exception:  # noqa: BLE001 - one broken job must not stop the others
            logger.exception("ACS job %s could not be advanced", job_id)
            job["last_error"] = "internal error; see the SkyRouter log"
        finally:
            self._release(job_id, token, job)

    def _abandon(self, job: dict[str, Any], message: str) -> None:
        if job["state"] in ACTIVE_STATES:
            self._end(job, ERROR, message)
        elif job.get("watch"):
            job["watch"] = None
            note(job, message, self._now())

    # -- job plumbing -------------------------------------------------------------------

    def _start(
        self, job: dict[str, Any], doc: dict[str, Any], steps: list[nbi_tasks.Task], token: str | None = None
    ) -> dict[str, Any]:
        """Queue the steps and ask the router to check in. ``token`` is the lease of a job already created."""
        if token is None:
            token = self.jobs.create(job)
        try:
            for task in steps:
                self._queue(job, token, task)
            self._contact(job, doc, steps[-1].step)
        except AcsError as exc:
            self._fail(job, exc)
        finally:
            self._release(job["id"], token, job)
        return public_view(job)

    def _release(self, job_id: str, token: str, job: dict[str, Any]) -> bool:
        self._record_activity(job)
        return self.jobs.release(job_id, token, job)

    # -- the activity log -----------------------------------------------------------------

    def _record_activity(self, job: dict[str, Any]) -> None:
        """Log a Wi-Fi, reboot or firmware job the first time it reaches a terminal state.

        Later upgrades (acknowledged to verified) are not logged again: the entry
        records that the change happened and who asked for it.
        """
        kind = _ACTIVITY_KINDS.get(job.get("kind", ""))
        if self.activity is None or kind is None or job.get("state") not in TERMINAL_STATES:
            return
        if job.get("activity_recorded"):
            return
        job["activity_recorded"] = True
        try:
            message, details = self._activity_text(job)
            self.activity.record(
                who=job.get("actor") or SYSTEM_ACTOR,
                # As the activity log names TR-069 routers, and as MaintenanceRunner
                # logs them: with the bare ID one router's history split in two.
                router=f"acs:{job['acs_id']}",
                kind=kind,
                what=f"{self._activity_label(job)} over TR-069: {message}",
                result=_ACTIVITY_RESULTS.get(job["state"], "info"),
                details=details,
            )
        except Exception:  # noqa: BLE001 - the audit log must never stop or undo a job
            logger.exception("ACS job %s: could not record it in the activity log", job["id"])

    def _activity_text(self, job: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        message, details = str(job.get("message") or ""), self._activity_details(job)
        fault = job.get("fault")
        if job.get("kind") == KIND_WIFI and (job.get("request") or {}).get("passphrase") and isinstance(fault, dict):
            # A router's FaultString can quote the value it refused, and the pending
            # password has already left the vault, so it cannot be looked for. The
            # log is permanent and exported: only the codes go in it.
            left_out = "the router's own wording is left out, as it can quote the new password"
            message = message.replace(_fault_text(fault), f"{_fault_codes(fault)}; {left_out}")
            wording = [fault.get("message"), *(entry.get("message") for entry in fault.get("parameters") or [])]
            for text in wording:
                # A WPA passphrase is at least 8 characters, so a shorter text cannot hold one.
                if isinstance(text, str) and len(text.strip()) >= 8 and text in message:
                    message = message.replace(text, f"({left_out})")
            details.pop("fault_message", None)
        return message, details

    def _activity_label(self, job: dict[str, Any]) -> str:
        request = job.get("request") or {}
        if job["kind"] == KIND_FIRMWARE:
            return f"Firmware upgrade to {request.get('version')}"
        if job["kind"] == KIND_WIFI:
            return f"Wi-Fi change ({request.get('band')})"
        return "Reboot"

    def _activity_details(self, job: dict[str, Any]) -> dict[str, Any]:
        # Keys the activity log would take for a secret's name (pass, key, token, ...)
        # are avoided; it refuses the whole entry over one.
        request = job.get("request") or {}
        details: dict[str, Any] = {"job": job["id"], "state": job["state"], "via": "tr069"}
        if job.get("cancelled_by"):
            details["cancelled_by"] = job["cancelled_by"]
        if job["kind"] == KIND_FIRMWARE:
            details.update(
                {
                    "firmware": request.get("firmware"),
                    "version": request.get("version"),
                    "from_version": request.get("from_version"),
                    "sha256": request.get("sha256"),
                    "model_mismatch_confirmed": bool(request.get("model_mismatch")),
                }
            )
        elif job["kind"] == KIND_WIFI:
            details["band"] = request.get("band")
            # Which settings changed; the passphrase itself is only ever in the vault.
            details["changed"] = []
            if request.get("ssid") is not None:
                details["changed"].append("ssid")
                details["ssid"] = request["ssid"]
            if request.get("passphrase"):
                details["changed"].append("passphrase")
        fault = job.get("fault")
        if isinstance(fault, dict):
            details["fault_code"] = fault.get("code")
            details["fault_message"] = fault.get("message")
        return details

    def _queue(self, job: dict[str, Any], token: str, task: nbi_tasks.Task) -> dict[str, Any]:
        stored = self.client.queue_task(job["acs_id"], task)
        submitted = stored.get("timestamp")
        expiry = parse_time(stored.get("expiry"))
        if expiry is None:
            expiry = (parse_time(submitted) or self._now()) + timedelta(seconds=task.expiry)
        step = {
            "step": task.step,
            "name": task.name,
            "task_id": stored["_id"],
            "submitted_ts": submitted,
            "expiry": iso(expiry),
            "unique_key": task.unique_key,
            "paths": list(task.paths),
        }
        job["steps"].append(step)
        # Saved at once: if SkyRouter dies now, the task is still found and settled.
        self.jobs.checkpoint(job["id"], token, job)
        return step

    def _find_step(self, job: dict[str, Any], name: str) -> dict[str, Any] | None:
        for step in reversed(job["steps"]):
            if step["step"] == name:
                return step
        # Queued, but SkyRouter lost the reply or stopped before recording it.
        for task in self.client.tasks(job=job["id"]):
            if task.get("skyrouterStep") == name and isinstance(task.get("_id"), str):
                step = {
                    "step": name,
                    "name": task.get("name"),
                    "task_id": task["_id"],
                    "submitted_ts": task.get("timestamp"),
                    "expiry": task.get("expiry") if isinstance(task.get("expiry"), str) else None,
                    "unique_key": task.get("uniqueKey") if isinstance(task.get("uniqueKey"), str) else None,
                    "paths": [],
                }
                job["steps"].append(step)
                note(job, f"Found the {name} task that was queued before its reply was lost.", self._now())
                return step
        return None

    def _statuses(self, job: dict[str, Any], steps: Sequence[dict[str, Any]]) -> dict[str, tuple[str, Any]]:
        """Per step: ("faulted", fault), ("pending", None), ("gone", None), or ("closed", None)
        for one SkyRouter already settled (cancelled, cleared, expired)."""
        acs_id = job["acs_id"]
        open_steps = [step for step in steps if not step.get("outcome")]
        result: dict[str, tuple[str, Any]] = {
            step["step"]: ("gone" if step["outcome"] == "gone" else "closed", None)
            for step in steps
            if step.get("outcome")
        }
        if not open_steps:
            return result
        ids = [step["task_id"] for step in open_steps]
        faults = {fault.get("_id"): fault for fault in self.client.faults(ids=[f"{acs_id}:task_{i}" for i in ids])}
        pending = {task.get("_id") for task in self.client.tasks(ids=ids)}
        for step in open_steps:
            fault = faults.get(f"{acs_id}:task_{step['task_id']}")
            if fault is not None:
                result[step["step"]] = ("faulted", fault)
            elif step["task_id"] in pending:
                result[step["step"]] = ("pending", None)
            else:
                step["outcome"] = "gone"
                result[step["step"]] = ("gone", None)
        return result

    def _clear(self, fault: dict[str, Any]) -> bool:
        """Delete a fault, which also deletes its task so it stops retrying (F16). False if busy."""
        try:
            self.client.delete_fault(str(fault.get("_id")))
        except AcsNotFound:
            pass
        except AcsBusy:
            return False
        return True

    def _contact(self, job: dict[str, Any], doc: dict[str, Any], step_name: str) -> None:
        now = self._now()
        try:
            result = self.client.connection_request(job["acs_id"])
        except AcsNotFound:
            raise
        except AcsError as exc:
            # The task is queued either way; the router takes it at its next inform.
            result = CrResult(ok=False, reason=_short(exc))
        job["cr_attempts"].append(
            {"at": iso(now), "step": step_name, "ok": result.ok, "result": "answered" if result.ok else result.reason}
        )
        if result.ok:
            job["expected_by"] = None
            transition(job, CONTACTING_ROUTER, "The router answered; waiting for it to check in.", now)
            return
        job["expected_by"] = self._expected_by(doc, now)
        transition(job, WAITING_FOR_CHECKIN, self._waiting_message(job, result.reason), now)

    def _waiting_message(self, job: dict[str, Any], reason: str) -> str:
        verb = {KIND_WIFI: "apply", KIND_FIRMWARE: "start"}.get(job["kind"], "run")
        when = f", expected around {job['expected_by']}" if job.get("expected_by") else ""
        why = f" ({reason})" if reason else ""
        return f"Queued. The router is not reachable right now{why}, so this will {verb} at its next check-in{when}."

    def _while_pending(self, job: dict[str, Any], step: dict[str, Any], closing: bool) -> None:
        now = self._now()
        expiry = parse_time(step.get("expiry"))
        if expiry is not None and now >= expiry + EXPIRY_GRACE:
            try:
                self.client.delete_task(step["task_id"])
            except (AcsNotFound, AcsBusy):
                # It went meanwhile, or a session is deciding it right now.
                return
            step["outcome"] = "expired"
            self._end(job, EXPIRED, f"The router did not check in before the change expired at {step['expiry']}.")
            return
        if closing:
            return
        doc = self._device(job["acs_id"], _POLL_PROJECTION)
        last_inform = DeviceTree(doc).last_inform
        submitted = parse_time(step.get("submitted_ts"))
        attempts = [attempt for attempt in job["cr_attempts"] if attempt.get("step") == step["step"]]
        last_at = parse_time(attempts[-1].get("at")) if attempts else None
        if last_inform and submitted and last_inform > submitted and (last_at is None or last_inform > last_at):
            # A session ran after the task was queued, and after the last request,
            # without taking it: the task probably arrived mid-session (§3.6).
            if len(attempts) < 1 + CR_RESENDS and (last_at is None or now - last_at >= CR_SPACING):
                note(job, "The router checked in without taking the task; asking it to check in again.", now)
                self._contact(job, doc, step["step"])
            return
        if job["state"] == CONTACTING_ROUTER and last_at and now - last_at >= CONTACT_WAIT:
            job["expected_by"] = self._expected_by(doc, now)
            transition(job, WAITING_FOR_CHECKIN, self._waiting_message(job, "it answered but has not checked in"), now)

    def _delete_outstanding(self, job: dict[str, Any]) -> bool:
        """Delete every open task of the job. AcsBusy propagates; True if one had already gone."""
        raced = False
        for step in job["steps"]:
            if step.get("outcome"):
                continue
            try:
                self.client.delete_task(step["task_id"])
            except AcsNotFound:
                # It ran or expired between the look and the delete; the caller looks again.
                raced = True
                continue
            step["outcome"] = "cancelled"
        return raced

    def _discard_tasks(self, job: dict[str, Any]) -> None:
        for step in job["steps"]:
            if step.get("outcome"):
                continue
            try:
                self.client.delete_task(step["task_id"])
            except AcsNotFound:
                pass
            except AcsError as exc:
                logger.warning("ACS job %s: could not delete leftover task %s: %s", job["id"], step["task_id"], exc)
                continue
            step["outcome"] = "discarded"

    def _end(self, job: dict[str, Any], state: str, message: str, *, keep_pending: bool = False) -> None:
        transition(job, state, message, self._now())
        job["phase"] = None
        self._discard_tasks(job)
        if not keep_pending:
            self._drop_pending(job)

    def _fail(self, job: dict[str, Any], exc: Exception) -> None:
        """A job that could not be started."""
        job["last_error"] = _short(exc)
        if isinstance(exc, AcsUnavailable) and exc.outcome_unknown:
            # The task may be queued: stay open so the next poll finds it by its
            # skyrouterJob field, or settles the job if it is not there.
            note(job, "The ACS stopped answering while the change was queued; looking for the task.", self._now())
            return
        if isinstance(exc, AcsNotFound):
            message = "The router is no longer in the ACS."
        else:
            message = f"The change could not be queued: {_short(exc)}"
        self._end(job, ERROR, message)

    def _lost(self, job: dict[str, Any]) -> None:
        """A job whose task was never recorded and cannot be found: SkyRouter stopped while queueing."""
        for task in self.client.tasks(job=job["id"]):
            with contextlib.suppress(AcsNotFound, AcsBusy):
                self.client.delete_task(str(task.get("_id")))
        # A write may have been queued and run before anyone recorded it, so the
        # new passphrase stays in the vault.
        self._end(
            job,
            ERROR,
            "SkyRouter stopped while queueing this change, so whether the router got it is unknown. "
            "Check the router, then try again.",
            keep_pending=True,
        )

    def _ensure_contacted(self, job: dict[str, Any], step: dict[str, Any], closing: bool) -> None:
        # A job left queued with its task recorded never sent its connection request.
        if job["state"] == QUEUED and not closing and not job["cr_attempts"]:
            self._contact(job, self._device(job["acs_id"], _POLL_PROJECTION), step["step"])

    # -- the vault ----------------------------------------------------------------------

    def _passphrase(self, job: dict[str, Any]) -> str:
        refs = job.get("vault_refs") or {}
        if refs.get("pending"):
            return self.secrets.get(refs["pending"])
        # Every current entry a change wrote holds the same passphrase.
        for reference in refs.get("current") or []:
            return self.secrets.get(reference)
        raise SecretStoreError("the new Wi-Fi passphrase is no longer in the vault")

    def _forget(self, job: dict[str, Any], reference: str) -> None:
        for other in self.jobs.all().values():
            if (
                other.get("id") != job["id"]
                and is_active(other)
                and (other.get("vault_refs") or {}).get("pending") == reference
            ):
                return
        try:
            self.secrets.delete(reference)
        except SecretStoreError as exc:
            logger.error("ACS job %s: could not delete vault entry %s: %s", job["id"], reference, exc)

    def _drop_pending(self, job: dict[str, Any]) -> None:
        reference = (job.get("vault_refs") or {}).pop("pending", None)
        if reference:
            self._forget(job, reference)

    def _promote(self, job: dict[str, Any]) -> None:
        """Make the pending passphrase the current one of every band the change wrote (§3.7 step 8).

        A change to "all" lands as one current entry per band, so the vault can always
        answer "what is the 5 GHz passphrase now", whichever kind of change set it.
        """
        pending = (job.get("vault_refs") or {}).get("pending")
        if not pending:
            return
        written = {
            leaf.get("band") or job["request"]["band"]
            for leaf in job["plan"].get("leaves", [])
            if leaf.get("kind") == params.PASSPHRASE
        } or {job["request"]["band"]}
        order = [*params.BANDS, params.BAND_ALL]
        bands = sorted(written, key=lambda band: order.index(band) if band in order else len(order))
        value = self.secrets.get(pending)
        current = [vault_ref(job["acs_id"], band, "current") for band in bands]
        for reference in current:
            self.secrets.put(value, reference)
        del value
        job["vault_refs"] = {"current": current}
        self._forget(job, pending)

    # -- superseding ------------------------------------------------------------------

    def _supersede(self, acs_id: str, band: str, new_id: str) -> None:
        """Cancel older Wi-Fi changes to the same band(s): the newest one is what the operator wants.

        An older change that already landed keeps its outcome, but stops waiting for
        its read-back: that compares against the band's current vault entry, which the
        new change is about to replace.
        """
        for other in self.jobs.all().values():
            if (
                other.get("kind") != KIND_WIFI
                or other.get("acs_id") != acs_id
                or not is_active(other)
                or not _bands_overlap(str((other.get("request") or {}).get("band")), band)
            ):
                continue
            claimed = self.jobs.claim(other["id"], wait=5.0)
            if claimed is None:
                raise AcsBusy("another change to this router's Wi-Fi is being processed; try again in a moment")
            old, token = claimed
            try:
                if old["state"] in ACTIVE_STATES:
                    # One that already ran keeps its real outcome.
                    self._advance(old, token, closing=True)
                    if old["state"] in ACTIVE_STATES and self._delete_outstanding(old):
                        self._advance(old, token, closing=True)
                    if old["state"] in ACTIVE_STATES:
                        old["superseded_by"] = new_id
                        self._end(old, CANCELLED, f"Replaced by a newer Wi-Fi change (job {new_id}).")
                if old.get("watch") == WATCH_SCRUB:
                    # The read-back task stays queued: it still clears GenieACS's copy.
                    old["watch"] = None
                    note(old, f"A newer Wi-Fi change (job {new_id}) replaces this one's read-back.", self._now())
            finally:
                self._release(old["id"], token, old)

    # -- advancing ------------------------------------------------------------------------

    def _advance(self, job: dict[str, Any], token: str, *, closing: bool = False) -> None:
        """Move a job on from what the NBI reports.

        ``closing`` is the last look before a cancel: decide what can be decided,
        but write nothing new and send no connection request. (A change found to have
        landed still queues its read-back, which only reads, so GenieACS does not keep
        the plaintext passphrase.)
        """
        if job["state"] in ACTIVE_STATES:
            phase = job.get("phase")
            if phase == "refresh" and job["kind"] == KIND_WIFI:
                self._advance_wifi_refresh(job, token, closing)
            elif phase == "write":
                self._advance_wifi_write(job, token, closing)
            elif phase == "reboot":
                self._advance_reboot(job, closing)
            elif phase == "refresh":
                self._advance_refresh(job, closing)
            elif phase == "firmware":
                self._advance_firmware(job, closing)
            else:
                self._lost(job)
        elif job.get("watch") == WATCH_SCRUB:
            self._advance_scrub(job)
        elif job.get("watch") == WATCH_BOOT:
            self._advance_boot(job)

    # Wi-Fi ------------------------------------------------------------------------------

    def _record_plan(self, job: dict[str, Any], plan: params.WritePlan, attempt: int) -> None:
        suffix = "" if attempt == 1 else str(attempt)
        job["plan"].update(
            {
                "attempt": attempt,
                "read_step": f"read{suffix}",
                "write_step": f"write{suffix}",
                "data_model": plan.data_model,
                "profile": plan.profile,
                "readback": plan.readback,
                "networks": list(plan.networks),
                "leaves": [
                    {"path": leaf.path, "kind": leaf.kind, "band": leaf.band, "network": leaf.network}
                    for leaf in plan.leaves
                ],
                "paths": list(plan.paths),
                "secret_paths": list(plan.secret_paths),
                "fallbacks": list(plan.fallbacks),
                "band_guessed": plan.band_guessed,
            }
        )

    def _queue_wifi_refresh(self, job: dict[str, Any], token: str, plan: params.WritePlan, doc: dict[str, Any]) -> None:
        # A leaf GenieACS has not cached, or cached without _writable, would be
        # skipped silently (F15): learn it from the router before writing anything.
        job["phase"] = "refresh"
        job["plan"]["refresh_path"] = plan.refresh_paths[0]
        note(job, f"Reading {plan.refresh_paths[0]} from the router before writing: {plan.problem()}", self._now())
        key = _BAND_KEYS[job["request"]["band"]]
        task = nbi_tasks.refresh_object(
            plan.refresh_paths[0],
            job=job["id"],
            step="refresh",
            unique_key=f"skyrouter-wifi-{key}-refresh",
            expiry=nbi_tasks.WIFI_EXPIRY,
        )
        self._queue(job, token, task)
        self._contact(job, doc, "refresh")

    def _queue_write(
        self, job: dict[str, Any], token: str, plan: params.WritePlan, doc: dict[str, Any], *, attempt: int
    ) -> None:
        request = job["request"]
        key = _BAND_KEYS[request["band"]]
        self._record_plan(job, plan, attempt)
        steps = job["plan"]
        # Task A: reading the leaves makes GenieACS cache a secret as "", so task B
        # cannot be skipped as unchanged (F15).
        read = nbi_tasks.get_parameter_values(
            plan.paths,
            job=job["id"],
            step=steps["read_step"],
            unique_key=f"skyrouter-wifi-{key}-read",
            expiry=nbi_tasks.WIFI_EXPIRY,
        )
        # Task B: one SetParameterValues, so the router applies it all or nothing (F29).
        # Both tasks are built before either is queued, so a bad value stops the job
        # before the router is touched.
        write = nbi_tasks.set_parameter_values(
            plan.values(ssid=request["ssid"], passphrase=self._passphrase(job) if request["passphrase"] else None),
            job=job["id"],
            step=steps["write_step"],
            unique_key=f"skyrouter-wifi-{key}",
            expiry=nbi_tasks.WIFI_EXPIRY,
        )
        job["phase"] = "write"
        self._queue(job, token, read)
        self._queue(job, token, write)
        self._contact(job, doc, write.step)

    def _advance_wifi_refresh(self, job: dict[str, Any], token: str, closing: bool) -> None:
        step = self._find_step(job, "refresh")
        if step is None:
            self._lost(job)
            return
        self._ensure_contacted(job, step, closing)
        status, fault = self._statuses(job, [step])[step["step"]]
        if status == "faulted":
            if not self._clear(fault):
                return
            step["outcome"] = "faulted"
            job["fault"] = _fault_summary(fault)
            self._end(
                job,
                ERROR,
                f"Could not read the router's Wi-Fi settings, so nothing was written: {_fault_text(job['fault'])}",
            )
            return
        if status == "pending":
            self._while_pending(job, step, closing)
            return
        if closing:
            # Nothing has been written yet; a cancel just ends the job here.
            return
        now = self._now()
        request = job["request"]
        doc = self._device(job["acs_id"], params.DETAIL_PROJECTION)
        plan = params.wifi_write_plan(
            doc, request["band"], request["ssid"], request["passphrase"], avoid=job["plan"]["avoid"]
        )
        job["plan"]["refreshed"] = True
        if not plan.ok:
            expiry = parse_time(step.get("expiry"))
            if expiry is not None and now >= expiry:
                self._end(job, EXPIRED, f"The router did not check in before the change expired at {step['expiry']}.")
            else:
                self._end(job, ERROR, f"Nothing was written: {plan.problem()}")
            return
        if plan.needs_confirmation and not request["confirm_guessed_band"]:
            self._end(
                job,
                ERROR,
                "Nothing was written: the router does not report this network's band, so SkyRouter inferred it. "
                "Repeat the change and confirm the band.",
            )
            return
        self._queue_write(job, token, plan, doc, attempt=1)

    def _advance_wifi_write(self, job: dict[str, Any], token: str, closing: bool) -> None:
        plan = job["plan"]
        write = self._find_step(job, plan["write_step"])
        if write is None:
            self._lost(job)
            return
        self._ensure_contacted(job, write, closing)
        read = self._find_step(job, plan["read_step"]) if not write.get("outcome") else None
        statuses = self._statuses(job, [step for step in (read, write) if step is not None])
        now = self._now()
        if read is not None and statuses.get(read["step"], ("", None))[0] == "faulted":
            # A failed read never blocks the write; it would only retry for hours.
            fault = statuses[read["step"]][1]
            if self._clear(fault):
                read["outcome"] = "faulted"
                note(job, f"The pre-write read faulted and was cleared: {_fault_text(_fault_summary(fault))}", now)
        status, fault = statuses[write["step"]]
        if status == "faulted":
            self._wifi_write_faulted(job, token, write, fault, closing)
        elif status == "pending":
            self._while_pending(job, write, closing)
        elif status == "gone":
            self._wifi_decide(job, token, write, closing)
        elif write.get("outcome") == "faulted":
            # The fault was cleared but the re-plan that follows it failed part-way
            # (the ACS stopped answering): pick the decision up again.
            self._after_write_fault(job, token, write, closing)

    def _faulted_passphrase_leaves(self, job: dict[str, Any], summary: dict[str, Any]) -> list[str]:
        secret = job["plan"]["secret_paths"]
        if summary["parameters"]:
            return [
                entry["path"]
                for entry in summary["parameters"]
                if entry["path"] in secret and _code(entry["code"]) in _REPLAN_CODES
            ]
        # No per-parameter detail: a 9007/9008 on a write that sets a passphrase is
        # taken to be about the passphrase, the leaf vendors disagree on.
        return list(secret) if _code(summary["code"]) in _REPLAN_CODES else []

    def _wifi_write_faulted(
        self, job: dict[str, Any], token: str, write: dict[str, Any], fault: dict[str, Any], closing: bool
    ) -> None:
        # Deleting the fault deletes the task, so the router is not asked again at
        # every retry interval (F16).
        if not self._clear(fault):
            return
        write["outcome"] = "faulted"
        write["fault"] = _fault_summary(fault)
        self._after_write_fault(job, token, write, closing)

    def _after_write_fault(self, job: dict[str, Any], token: str, write: dict[str, Any], closing: bool) -> None:
        summary = write["fault"]
        faulted = self._faulted_passphrase_leaves(job, summary)
        if faulted and job["plan"]["replans"] == 0 and not closing and self._replan(job, token, faulted, summary):
            return
        job["fault"] = summary
        self._end(job, REJECTED, f"The router refused the change: {_fault_text(summary)}")

    def _replan(self, job: dict[str, Any], token: str, faulted: list[str], summary: dict[str, Any]) -> bool:
        """One more try with the profile's next passphrase leaf after a 9007 or 9008 (§3.7)."""
        request = job["request"]
        avoid = [*job["plan"]["avoid"], *faulted]
        doc = self._device(job["acs_id"], params.DETAIL_PROJECTION)
        plan = params.wifi_write_plan(doc, request["band"], request["ssid"], request["passphrase"], avoid=avoid)
        if not plan.ok or (plan.needs_confirmation and not request["confirm_guessed_band"]):
            return False
        job["plan"]["replans"] = 1
        job["plan"]["avoid"] = avoid
        job["plan"]["first_fault"] = summary
        refused, instead = ", ".join(faulted), ", ".join(plan.secret_paths)
        note(job, f"The router refused {refused} ({summary['code']}); trying {instead} instead.", self._now())
        self._queue_write(job, token, plan, doc, attempt=2)
        return True

    def _wifi_decide(self, job: dict[str, Any], token: str, write: dict[str, Any], closing: bool) -> None:
        """Task B has gone without a fault: did the router take every value? (§3.7 step 7)"""
        now = self._now()
        plan, request = job["plan"], job["request"]
        doc = self._device(job["acs_id"], ("_id", "_lastInform", *plan["paths"]))
        tree = DeviceTree(doc)
        submitted = parse_time(write.get("submitted_ts"))
        passphrase = self._passphrase(job) if request["passphrase"] else None
        skipped = []
        for leaf in plan["leaves"]:
            desired = request["ssid"] if leaf["kind"] == params.SSID else passphrase
            cached = tree.leaf(leaf["path"])
            if cached is None:
                reason = "not on the router"
            elif cached.value != desired:
                reason = "not written"
            elif cached.timestamp is None or submitted is None or cached.timestamp < submitted:
                # GenieACS stamps a leaf only after a successful write or read (F15).
                reason = "no newer value"
            else:
                continue
            skipped.append({"path": leaf["path"], "kind": leaf["kind"], "reason": reason})
        del passphrase
        if not skipped:
            self._acknowledge(job, token)
            return
        replacement = self._replacement(job, write)
        if replacement is not None:
            # GenieACS deleted B when a newer task with the same uniqueKey was queued
            # (F14), by another SkyRouter process or a second request racing this one.
            job["superseded_by"] = replacement or None
            by = f" (job {replacement})" if replacement else ""
            self._end(job, CANCELLED, f"Replaced by a newer Wi-Fi change{by} before the router took this one.")
            return
        expiry = parse_time(write.get("expiry"))
        last_inform = tree.last_inform
        if expiry is not None and (now >= expiry or (last_inform is not None and last_inform >= expiry)):
            self._end(job, EXPIRED, f"The router did not check in before the change expired at {write['expiry']}.")
            return
        write["gone_checks"] = write.get("gone_checks", 0) + 1
        if write["gone_checks"] < 2 and not closing:
            # GenieACS saves the device and clears the tasks separately at the end of
            # a session; a poll in between sees the task gone before the new values.
            return
        job["result"]["skipped"] = skipped
        listed = ", ".join(f"{entry['path']} ({entry['reason']})" for entry in skipped)
        self._end(job, NOT_APPLIED, f"GenieACS finished the change without writing it to the router: {listed}.")

    def _replacement(self, job: dict[str, Any], step: dict[str, Any]) -> str | None:
        """The job ID ("" if not SkyRouter's) of a newer task holding this step's uniqueKey, or None."""
        key = step.get("unique_key")
        if not isinstance(key, str):
            return None
        page = self.client.find("tasks", {"device": job["acs_id"], "uniqueKey": key}, limit=5)
        for task in page.items:
            if task.get("_id") != step["task_id"] and task.get("skyrouterJob") != job["id"]:
                other = task.get("skyrouterJob")
                return other if isinstance(other, str) and JOB_ID_RE.fullmatch(other) else ""
        return None

    def _acknowledge(self, job: dict[str, Any], token: str) -> None:
        now = self._now()
        request = job["request"]
        job["result"]["leaves"] = [
            {"path": leaf["path"], "kind": leaf["kind"], "outcome": ACKNOWLEDGED} for leaf in job["plan"]["leaves"]
        ]
        if request["passphrase"] and request["ssid"] is not None:
            message = "The router accepted the new SSID and password. The password cannot be read back to double-check."
        elif request["passphrase"]:
            message = "The router accepted the new password. It cannot be read back to double-check."
        else:
            message = "The router accepted the new SSID."
        transition(job, ACKNOWLEDGED, message, now)
        job["phase"] = None
        self._discard_tasks(job)
        try:
            self._promote(job)
        except SecretStoreError as exc:
            logger.error("ACS job %s: could not promote the new passphrase in the vault: %s", job["id"], exc)
            note(job, f"The new password stays in its pending vault entry: {_short(exc)}", now)
        if self.scrub_secrets:
            self._queue_scrub(job, token)

    def _queue_scrub(self, job: dict[str, Any], token: str) -> None:
        # Task C, with no connection request: it runs at the next inform. Reading the
        # leaves replaces GenieACS's plaintext copy of the password with "" on a
        # router that follows the spec, and reads the SSID back (§3.7 step 8).
        key = _BAND_KEYS[job["request"]["band"]]
        task = nbi_tasks.get_parameter_values(
            job["plan"]["paths"],
            job=job["id"],
            step="scrub",
            unique_key=f"skyrouter-wifi-{key}-scrub",
            expiry=nbi_tasks.WIFI_EXPIRY,
        )
        try:
            self._queue(job, token, task)
        except AcsError as exc:
            note(job, f"Could not queue the read-back: {_short(exc)}", self._now())
            return
        job["watch"] = WATCH_SCRUB
        note(job, "Queued a read-back for the router's next check-in.", self._now())

    def _advance_scrub(self, job: dict[str, Any]) -> None:
        step = self._find_step(job, "scrub")
        if step is None:
            job["watch"] = None
            return
        now = self._now()
        status, fault = self._statuses(job, [step])[step["step"]]
        if status == "faulted":
            if not self._clear(fault):
                return
            step["outcome"] = "faulted"
            job["watch"] = None
            note(job, f"The read-back faulted: {_fault_text(_fault_summary(fault))}.", now)
            return
        if status == "pending":
            expiry = parse_time(step.get("expiry"))
            if expiry is not None and now >= expiry + EXPIRY_GRACE:
                try:
                    self.client.delete_task(step["task_id"])
                except (AcsNotFound, AcsBusy):
                    return
                step["outcome"] = "expired"
                job["watch"] = None
                note(job, "The read-back expired before the router checked in.", now)
            return

        request, plan = job["request"], job["plan"]
        doc = self._device(job["acs_id"], ("_id", "_lastInform", *plan["paths"]))
        tree = DeviceTree(doc)
        submitted = parse_time(step.get("submitted_ts"))
        passphrase = self._passphrase(job) if request["passphrase"] else None
        outcomes: list[dict[str, Any]] = []
        ran, plaintext, exposed = False, False, False
        for leaf in plan["leaves"]:
            cached = tree.leaf(leaf["path"])
            fresh = bool(cached and cached.timestamp and submitted and cached.timestamp >= submitted)
            ran = ran or fresh
            verified = False
            if cached is not None and leaf["kind"] == params.SSID:
                verified = fresh and cached.value == request["ssid"]
            elif cached is not None:
                # Spec-following routers read back "" (F27); only one that exposes
                # the key can prove the write.
                shown = cached.value if isinstance(cached.value, str) else ""
                verified = fresh and bool(shown) and shown == passphrase
                plaintext = plaintext or verified
                exposed = exposed or shown == passphrase
            outcome = VERIFIED if verified else ACKNOWLEDGED
            outcomes.append({"path": leaf["path"], "kind": leaf["kind"], "outcome": outcome})
        del passphrase
        if not ran:
            step["gone_checks"] = step.get("gone_checks", 0) + 1
            if step["gone_checks"] < 2:
                # The same end-of-session gap as for task B: gone, but not saved yet.
                return
            job["watch"] = None
            note(job, "The read-back task went without reading anything back.", now)
            return
        job["watch"] = None
        job["result"]["leaves"] = outcomes
        if request["passphrase"]:
            # False means GenieACS's database still holds the password in plaintext.
            job["result"]["scrubbed"] = not exposed
        if plaintext:
            job["result"]["readback"] = "plaintext"
            logger.warning(
                "ACS device %s reads its Wi-Fi password back in plaintext; profile %s should say readback=plaintext",
                job["acs_id"],
                plan.get("profile"),
            )
        if all(entry["outcome"] == VERIFIED for entry in outcomes):
            message = "The router reads the new settings back, so the change is verified."
            if plaintext:
                message += " This router exposes its Wi-Fi password to anything that can read its settings."
            transition(job, VERIFIED, message, now)
        elif any(entry["outcome"] == VERIFIED for entry in outcomes):
            job["message"] += " The new SSID reads back correctly."
            note(job, "Read back: the SSID matches; the password cannot be read back.", now)
        else:
            note(job, "Read back: nothing further could be confirmed.", now)

    # Reboot and refresh -----------------------------------------------------------------

    def _advance_reboot(self, job: dict[str, Any], closing: bool) -> None:
        step = self._find_step(job, "reboot")
        if step is None:
            self._lost(job)
            return
        self._ensure_contacted(job, step, closing)
        status, fault = self._statuses(job, [step])[step["step"]]
        if status == "faulted":
            if not self._clear(fault):
                return
            step["outcome"] = "faulted"
            job["fault"] = _fault_summary(fault)
            self._end(job, REJECTED, f"The router refused to reboot: {_fault_text(job['fault'])}")
            return
        if status == "pending":
            self._while_pending(job, step, closing)
            return
        now = self._now()
        tree = DeviceTree(self._device(job["acs_id"], _POLL_PROJECTION))
        submitted = parse_time(step.get("submitted_ts"))
        if tree.last_boot and submitted and tree.last_boot > submitted:
            self._end(job, VERIFIED, f"The router rebooted; it reported booting at {iso(tree.last_boot)}.")
            return
        expiry = parse_time(step.get("expiry"))
        if expiry is not None and now >= expiry:
            self._end(job, EXPIRED, f"The router did not check in before the reboot expired at {step['expiry']}.")
            return
        # The router accepted the Reboot RPC; its 1 BOOT inform moves _lastBoot (F30).
        transition(job, ACKNOWLEDGED, "The router accepted the reboot; waiting for it to report back.", now)
        job["phase"] = None
        job["watch"] = WATCH_BOOT
        job["result"]["accepted_at"] = iso(now)

    def _advance_boot(self, job: dict[str, Any]) -> None:
        step = self._find_step(job, "reboot")
        now = self._now()
        tree = DeviceTree(self._device(job["acs_id"], _POLL_PROJECTION))
        submitted = parse_time(step.get("submitted_ts")) if step else None
        if tree.last_boot and submitted and tree.last_boot > submitted:
            job["watch"] = None
            transition(job, VERIFIED, f"The router rebooted; it reported booting at {iso(tree.last_boot)}.", now)
            return
        accepted = parse_time(job["result"].get("accepted_at"))
        if accepted is None or now - accepted >= BOOT_WAIT:
            job["watch"] = None
            job["message"] = "The router accepted the reboot but has not reported booting since."
            note(job, job["message"], now)

    def _advance_refresh(self, job: dict[str, Any], closing: bool) -> None:
        step = self._find_step(job, "refresh")
        if step is None:
            self._lost(job)
            return
        self._ensure_contacted(job, step, closing)
        status, fault = self._statuses(job, [step])[step["step"]]
        if status == "faulted":
            if not self._clear(fault):
                return
            step["outcome"] = "faulted"
            job["fault"] = _fault_summary(fault)
            self._end(job, REJECTED, f"The router refused the refresh: {_fault_text(job['fault'])}")
            return
        if status == "pending":
            self._while_pending(job, step, closing)
            return
        now = self._now()
        path = job["request"]["object"]
        tree = DeviceTree(self._device(job["acs_id"], ("_id", "_lastInform", path)))
        submitted = parse_time(step.get("submitted_ts"))
        stamps = [leaf.timestamp for leaf in tree.iter_leaves(path)]
        node = tree.node(path)
        # An object refreshed with no leaves beneath it still carries its own stamp.
        stamps.append(parse_time(node.get("_timestamp")) if node is not None else None)
        newest = max((stamp for stamp in stamps if stamp is not None), default=None)
        if newest and submitted and newest >= submitted:
            self._end(job, VERIFIED, "Fresh data arrived from the router.")
            return
        expiry = parse_time(step.get("expiry"))
        if expiry is not None and now >= expiry:
            self._end(job, EXPIRED, f"The router did not check in before the refresh expired at {step['expiry']}.")
            return
        step["gone_checks"] = step.get("gone_checks", 0) + 1
        if step["gone_checks"] < 2 and not closing:
            return
        self._end(job, ACKNOWLEDGED, "GenieACS finished the refresh, but the router sent nothing newer.")

    # Firmware ---------------------------------------------------------------------------

    def _advance_firmware(self, job: dict[str, Any], closing: bool) -> None:
        step = self._find_step(job, "download")
        if step is None:
            self._lost(job)
            return
        self._ensure_contacted(job, step, closing)
        acs_id, request = job["acs_id"], job["request"]
        # A failed transfer is reported in TransferComplete, possibly sessions after
        # the task went, so the task's channel is looked at on every poll.
        faults = self.client.faults(ids=[f"{acs_id}:task_{step['task_id']}"])
        if faults:
            # Clearing it also stops GenieACS sending the Download again (F16).
            if not self._clear(faults[-1]):
                return
            step["outcome"] = "faulted"
            job["fault"] = _fault_summary(faults[-1])
            self._end(
                job,
                REJECTED,
                f"The router did not install firmware {request['version']}: {_fault_text(job['fault'])}",
            )
            return
        if not step.get("outcome"):
            if self.client.tasks(ids=[step["task_id"]]):
                self._while_pending(job, step, closing)
                return
            step["outcome"] = "gone"

        now = self._now()
        device = params.firmware_identity(self._device(acs_id, params.FIRMWARE_PROJECTION), now, self.inform_interval)
        target, running = request["version"], device["software_version"]
        submitted = parse_time(step.get("submitted_ts"))
        last_boot = parse_time(device["last_boot"])
        # Both times are GenieACS's, so clock skew cannot fake a boot.
        if running == target and last_boot and submitted and last_boot > submitted:
            job["result"].update({"running": running, "booted_at": iso(last_boot)})
            self._end(job, VERIFIED, f"The router restarted at {iso(last_boot)} and now runs firmware {target}.")
            return
        if closing:
            return
        if "accepted_at" not in job["result"]:
            self._firmware_accepted(job, step, device, now)
            return

        accepted_inform = parse_time(job["result"].get("accepted_inform"))
        if last_boot and accepted_inform and last_boot > accepted_inform:
            # It restarted after taking the download, but not into the new version.
            # GenieACS saves the device and the transfer's fault separately, so one
            # more look gives the fault the chance to explain why.
            step["boot_checks"] = step.get("boot_checks", 0) + 1
            if step["boot_checks"] < 2:
                return
            job["result"].update({"running": running, "booted_at": iso(last_boot)})
            if running == request["from_version"]:
                message = (
                    f"The router restarted after accepting the download but still runs firmware {running}; "
                    f"it did not install {target}."
                )
            else:
                message = (
                    f"The router restarted and reports firmware {running or 'unknown'}, not {target}. "
                    "Check that the version recorded for this file is exactly what the router reports."
                )
            self._end(job, NOT_APPLIED, message)
            return
        accepted_at = parse_time(job["result"].get("accepted_at"))
        if accepted_at is None or now - accepted_at < FIRMWARE_INSTALL_WAIT:
            return
        last_inform = parse_time(device["last_inform"])
        if last_inform and accepted_inform and last_inform > accepted_inform:
            message = (
                f"The router accepted the firmware download at {iso(accepted_at)} and has checked in since, "
                f"but still reports firmware {running}. It may install it later; check the router."
            )
        else:
            message = (
                f"The router accepted the firmware download at {iso(accepted_at)} but has not checked in since. "
                "It may still be installing, or it may not have come back; check it on site."
            )
        self._end(job, EXPIRED, message)

    def _firmware_accepted(
        self, job: dict[str, Any], step: dict[str, Any], device: dict[str, Any], now: datetime
    ) -> None:
        """The download task has gone without a fault: accepted, or dropped unrun as expired."""
        last_inform = parse_time(device["last_inform"])
        expiry = parse_time(step.get("expiry"))
        if expiry is not None and last_inform is not None and last_inform >= expiry:
            # GenieACS drops an expired task, unrun, at the first session after its
            # expiry, so a task that went in a session that late was never sent.
            self._end(job, EXPIRED, f"The router did not check in before the upgrade expired at {step['expiry']}.")
            return
        job["result"]["accepted_at"] = iso(now)
        # GenieACS's time for the session that took it, to compare _lastBoot with.
        job["result"]["accepted_inform"] = device["last_inform"]
        job["expected_by"] = None
        transition(
            job,
            WAITING_FOR_CHECKIN,
            f"The router accepted the download of firmware {job['request']['version']}; "
            "waiting for it to install it, restart and check in.",
            now,
        )
