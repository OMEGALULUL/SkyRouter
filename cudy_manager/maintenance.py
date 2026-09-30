"""Maintenance plans: routine work on a group of routers inside a chosen window.

A plan names its routers (direct ones by device id, TR-069 ones by GenieACS id,
or whole groups that are resolved each time it runs), a weekly or monthly window
in a timezone, the actions to take and the guards that hold them back.
MaintenanceRunner acts on each router at most once per window, an "occurrence"
keyed on the plan and the local date the window opens, and records every outcome
in the activity log under the plan's name.

Direct routers are reached through DeviceManager, so the per-router lock and the
rejected-credential latch apply exactly as they do to the dashboard. TR-069
routers get AcsService jobs, which settle later in poll_jobs(); a queued job is
all a plan can report, and the service logs how it ends.

Everything here blocks: call it from async code through asyncio.to_thread.
"""

import contextlib
import fcntl
import json
import logging
import os
import re
import secrets
import tempfile
import threading
import unicodedata
from collections.abc import Callable, Iterator, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from datetime import UTC, date, datetime, time, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .acs.bootstrap import NEW_DEVICE_TAG
from .acs.client import AcsBusy, AcsError, AcsNotFound, validate_device_id, validate_file_metadata
from .acs.jobs import KIND_FIRMWARE
from .acs.tasks import DEFAULT_EXPIRY, FIRMWARE_EXPIRY, MIN_EXPIRY, validate_firmware_name
from .activity import ActivityError, normalise_actor
from .adapters import AdapterError, UnsupportedOperation
from .manager import CredentialLatched, ManagerError
from .models import Device, ValidationError
from .secrets import SecretStoreError

if TYPE_CHECKING:
    from .acs.service import AcsService, ActivitySink
    from .manager import DeviceManager

logger = logging.getLogger(__name__)

# Always run in this order, whatever order a plan lists them in: a check before an
# update, and the restart last, so nothing is lost to a router going down mid-plan.
ACTIONS = ("firmware_check", "auto_update_on", "firmware_update", "reboot")
# These take the router down for its users, so the uptime, client and cooldown
# guards exist for them; the cooldown is only counted from these.
DISRUPTIVE = frozenset({"firmware_update", "reboot"})
DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
# Router groups a plan can name instead of listing ids: every enabled direct router,
# every adopted TR-069 router, and every Cudy of either kind. Each is resolved when
# the plan runs, so a router added later is included without editing the plan.
GROUPS = ("direct", "managed", "cudy")
# The groups that can hold a TR-069 router, and so need the ACS fleet listed.
_ACS_GROUPS = frozenset({"managed", "cudy"})

PLANS_FILE = "maintenance.json"
STATE_FILE = "maintenance_state.json"
FORMAT_VERSION = 1
MIN_DURATION = 15
MAX_DURATION = 480
MAX_PLANS = 200
MAX_TARGETS = 500
MAX_FIRMWARE_CHOICES = 50
NAME_MAX = 60
MAX_UPTIME_GUARD = 31_536_000
MAX_CLIENTS_GUARD = 10_000
MAX_COOLDOWN_HOURS = 720
# Shorter than the router lock's 60 s busy timeout, so a dashboard click that waits
# behind a plan's check is answered rather than told the router is busy.
CHECK_TIMEOUT = 45.0
# A Cudy update check alone can take most of a minute; one router at a time would
# stretch a fleet's run far past its window.
MAX_WORKERS = 4
# Longer than the longest cooldown, so pruning never forgets a restart still counted.
STATE_RETENTION = timedelta(days=45)
ACS_PAGE = 200
MAX_ACS_FLEET = 5000
# GenieACS's cached host and station tables are re-read hourly by skybre-refresh; a
# count older than this no longer says who is connected now.
MAX_CLIENT_COUNT_AGE = timedelta(hours=2)

_PLAN_FIELDS = (
    "id",
    "name",
    "enabled",
    "targets",
    "schedule",
    "actions",
    "firmware",
    "guards",
    "created_at",
    "updated_at",
)
_READ_ONLY = ("id", "created_at", "updated_at")
_PLAN_ID = re.compile(r"[0-9a-f]{12}")
# Device.validate's rule for identifiers.
_DEVICE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}")
_START = re.compile(r"(?:[01]\d|2[0-3]):[0-5]\d")
_ZONE = re.compile(r"[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+)*")
# Bidirectional overrides can make a plan's name read as another one in the log.
_BIDI = frozenset(chr(code) for code in (*range(0x202A, 0x202F), *range(0x2066, 0x206A)))

_ACTION_KIND = {
    "firmware_check": "firmware",
    "auto_update_on": "firmware",
    "firmware_update": "firmware",
    "reboot": "reboot",
}
_ATTEMPT = {
    "firmware_check": "Firmware check",
    "auto_update_on": "Turning on automatic firmware update",
    "firmware_update": "Firmware upgrade",
    "reboot": "Reboot",
}
# What a router or the ACS can raise that is not a SkyRouter bug; anything else is
# logged with its traceback before it is reported.
_EXPECTED = (AdapterError, SecretStoreError, ValidationError, ManagerError, OSError, RuntimeError)


class MaintenanceError(RuntimeError):
    """The plan or state file cannot be read or written; the operator has to look."""


class PlanNotFound(ValidationError):
    """No maintenance plan has this id."""


class MaintenanceBusy(ValidationError):
    """The plan is already being run by hand."""


class _Held(ValidationError):
    """SkyRouter held an action back itself: a guard, or nothing it could send."""


class _Logged(Exception):
    """An action's failure that DeviceManager has already put in the activity log."""

    def __init__(self, cause: Exception):
        super().__init__(str(cause))
        self.cause = cause


# --- small helpers --------------------------------------------------------------------


def _utc(moment: datetime) -> datetime:
    return moment.replace(tzinfo=UTC) if moment.tzinfo is None else moment.astimezone(UTC)


def _iso(moment: datetime) -> str:
    return _utc(moment).isoformat()


def _parse(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return _utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
    except ValueError:
        return None


def _short(value: BaseException | str, limit: int = 160) -> str:
    text = str(value) or type(value).__name__
    return " ".join(text.split())[:limit]


def _count(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, float) and value >= 0 and value.is_integer():
        return int(value)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _duration(seconds: float) -> str:
    minutes = int(seconds) // 60
    if minutes < 60:
        return f"{max(minutes, 0)} min"
    hours, minutes = divmod(minutes, 60)
    if hours < 48:
        return f"{hours} h {minutes} min" if minutes else f"{hours} h"
    days, hours = divmod(hours, 24)
    return f"{days} d {hours} h" if hours else f"{days} d"


def _window_text(hour: int) -> str:
    return f"{hour:02d}:00-{(hour + 2) % 24:02d}:00"


def _display_name(device: Device) -> str:
    name = device.metadata.get("name")
    return name.strip() if isinstance(name, str) and name.strip() else device.identifier


def _is_cudy_device(device: Device) -> bool:
    # The vendor picks the adapter, so it is the make SkyRouter actually talks to;
    # the model is free text.
    return device.vendor == "cudy"


def _direct_groups(device: Device) -> frozenset[str]:
    return frozenset({"direct", "cudy"} if _is_cudy_device(device) else {"direct"})


def _is_cudy_acs(summary: Mapping[str, Any]) -> bool:
    """Whether a TR-069 router's own DeviceInfo says it is a Cudy."""
    return any(
        isinstance(value, str) and "cudy" in value.casefold()
        for value in (summary.get("manufacturer"), summary.get("model"))
    )


def _refused(exc: BaseException) -> bool:
    """Whether SkyRouter declined the action itself, as opposed to trying and failing."""
    return isinstance(exc, (ValidationError, ManagerError, UnsupportedOperation, CredentialLatched, AcsBusy))


# --- validation -----------------------------------------------------------------------


def _fields(value: Any, name: str, allowed: Sequence[str]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValidationError(f"{name} must be an object")
    unknown = sorted(str(key)[:40] for key in value if key not in allowed)
    if unknown:
        raise ValidationError(f"{name} has unknown field(s): {', '.join(unknown)}")
    return dict(value)


def _flag(value: Any, name: str, default: bool) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ValidationError(f"{name} must be true or false")
    return value


def _whole(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"{name} must be a whole number")
    if not minimum <= value <= maximum:
        raise ValidationError(f"{name} must be from {minimum} to {maximum}")
    return value


def validate_plan_name(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("name must not be empty")
    # Line breaks and tabs become single spaces: the name heads activity entries.
    name = " ".join(value.split())
    if any(char in _BIDI or unicodedata.category(char) in {"Cc", "Zl", "Zp"} for char in name):
        raise ValidationError("name must not contain control characters")
    if len(name) > NAME_MAX:
        raise ValidationError(f"name must be at most {NAME_MAX} characters")
    return name


def validate_timezone(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("schedule.timezone must be a timezone name, such as Africa/Johannesburg")
    zone = value.strip()
    # Checked before ZoneInfo, which reads a file named after the key.
    if len(zone) > 64 or not _ZONE.fullmatch(zone):
        raise ValidationError("schedule.timezone must be a timezone name, such as Africa/Johannesburg")
    try:
        ZoneInfo(zone)
    except (ZoneInfoNotFoundError, ValueError, OSError):
        raise ValidationError(f"schedule.timezone {zone!r} is not a known timezone") from None
    return zone


@dataclass(frozen=True)
class PlanTargets:
    all_routers: bool = False
    devices: tuple[str, ...] = ()
    acs_devices: tuple[str, ...] = ()
    groups: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, value: Any) -> "PlanTargets":
        data = _fields(value, "targets", ("all", "devices", "acs_devices", "groups"))
        every = _flag(data.get("all"), "targets.all", False)
        devices = cls._ids(data.get("devices"), "targets.devices", "a SkyRouter device id", _DEVICE_ID.fullmatch)
        acs_devices = cls._ids(data.get("acs_devices"), "targets.acs_devices", "a GenieACS device ID", _is_acs_id)
        groups = cls._groups(data.get("groups"))
        if not (every or devices or acs_devices or groups):
            raise ValidationError("targets must name at least one router or group, or set all to true")
        return cls(every, devices, acs_devices, groups)

    @staticmethod
    def _groups(value: Any) -> tuple[str, ...]:
        if value is None:
            return ()
        if not isinstance(value, list):
            raise ValidationError("targets.groups must be a list")
        chosen = set()
        for item in value:
            group = item.strip().lower() if isinstance(item, str) else None
            if group not in GROUPS:
                raise ValidationError(f"targets.groups may only hold {', '.join(GROUPS)}")
            chosen.add(group)
        return tuple(group for group in GROUPS if group in chosen)

    @property
    def reaches_acs(self) -> bool:
        """Whether the plan can reach a TR-069 router at all."""
        return self.all_routers or bool(self.acs_devices) or not _ACS_GROUPS.isdisjoint(self.groups)

    @staticmethod
    def _ids(value: Any, name: str, what: str, check: Callable[[str], Any]) -> tuple[str, ...]:
        if value is None:
            return ()
        if not isinstance(value, list):
            raise ValidationError(f"{name} must be a list")
        if len(value) > MAX_TARGETS:
            raise ValidationError(f"{name} may name at most {MAX_TARGETS} routers")
        chosen: list[str] = []
        for index, item in enumerate(value):
            if not isinstance(item, str) or not check(item):
                raise ValidationError(f"{name}[{index}] is not {what}")
            if item not in chosen:
                chosen.append(item)
        return tuple(chosen)

    def to_dict(self) -> dict[str, Any]:
        return {
            "all": self.all_routers,
            "devices": list(self.devices),
            "acs_devices": list(self.acs_devices),
            "groups": list(self.groups),
        }


def _is_acs_id(value: str) -> bool:
    try:
        validate_device_id(value)
    except ValidationError:
        return False
    return True


@dataclass(frozen=True)
class PlanSchedule:
    start: str
    timezone: str
    duration_minutes: int = 60
    days: tuple[str, ...] = ()
    monthly_day: int | None = None

    @classmethod
    def from_dict(cls, value: Any) -> "PlanSchedule":
        data = _fields(value, "schedule", ("days", "monthly_day", "start", "duration_minutes", "timezone"))
        days = cls._days(data.get("days"))
        monthly_day = None
        if data.get("monthly_day") is not None:
            monthly_day = data["monthly_day"]
            if isinstance(monthly_day, bool) or not isinstance(monthly_day, int) or not 1 <= monthly_day <= 28:
                raise ValidationError("schedule.monthly_day must be a day from 1 to 28, so that every month has it")
        if days and monthly_day is not None:
            raise ValidationError("schedule takes either days (weekly) or monthly_day (monthly), not both")
        if not days and monthly_day is None:
            raise ValidationError("schedule needs days (weekly) or monthly_day (monthly)")
        start = data.get("start")
        if not isinstance(start, str) or not _START.fullmatch(start.strip()):
            raise ValidationError("schedule.start must be a time in HH:MM form, such as 03:00")
        duration = data.get("duration_minutes")
        duration = 60 if duration is None else _whole(duration, "schedule.duration_minutes", MIN_DURATION, MAX_DURATION)
        return cls(start.strip(), validate_timezone(data.get("timezone")), duration, days, monthly_day)

    @staticmethod
    def _days(value: Any) -> tuple[str, ...]:
        if value is None:
            return ()
        if not isinstance(value, list):
            raise ValidationError("schedule.days must be a list of weekdays")
        chosen = set()
        for item in value:
            day = item.strip().lower() if isinstance(item, str) else None
            if day not in DAYS:
                raise ValidationError(f"schedule.days may only hold {', '.join(DAYS)}")
            chosen.add(day)
        return tuple(day for day in DAYS if day in chosen)

    def to_dict(self) -> dict[str, Any]:
        return {
            "days": list(self.days),
            "monthly_day": self.monthly_day,
            "start": self.start,
            "duration_minutes": self.duration_minutes,
            "timezone": self.timezone,
        }

    @property
    def start_hour(self) -> int:
        return int(self.start.split(":")[0])

    def _zone(self) -> ZoneInfo:
        return ZoneInfo(self.timezone)

    def _matches(self, day: date) -> bool:
        if self.monthly_day is not None:
            return day.day == self.monthly_day
        return DAYS[day.weekday()] in self.days

    def window_for(self, day: date) -> tuple[datetime, datetime]:
        """The window that opens on this local date, as UTC instants."""
        hour, minute = (int(part) for part in self.start.split(":"))
        # fold=0 opens a start skipped by the spring-forward jump just after it, and a
        # start the fall-back repeats the first time round. The length is added in
        # UTC, so a DST change neither stretches nor shrinks the window.
        opens = datetime.combine(day, time(hour, minute), tzinfo=self._zone()).astimezone(UTC)
        return opens, opens + timedelta(minutes=self.duration_minutes)

    def occurrence_at(self, now: datetime) -> date | None:
        """The local date of the window that contains ``now``, if one does."""
        current = _utc(now)
        today = current.astimezone(self._zone()).date()
        # Yesterday's as well: a window may run past midnight.
        for day in (today, today - timedelta(days=1)):
            if self._matches(day):
                opens, closes = self.window_for(day)
                if opens <= current < closes:
                    return day
        return None

    def next_window(self, now: datetime) -> tuple[datetime, datetime] | None:
        """The window open now, or else the next one to open."""
        current = _utc(now)
        today = current.astimezone(self._zone()).date()
        for offset in range(-1, 63):
            day = today + timedelta(days=offset)
            if self._matches(day):
                opens, closes = self.window_for(day)
                if closes > current:
                    return opens, closes
        return None


@dataclass(frozen=True)
class PlanGuards:
    min_uptime_seconds: int = 3600
    skip_if_clients_over: int | None = None
    cooldown_hours: int = 20

    @classmethod
    def from_dict(cls, value: Any) -> "PlanGuards":
        allowed = ("min_uptime_seconds", "skip_if_clients_over", "cooldown_hours")
        data = _fields({} if value is None else value, "guards", allowed)
        uptime = data.get("min_uptime_seconds")
        clients = data.get("skip_if_clients_over")
        cooldown = data.get("cooldown_hours")
        return cls(
            3600 if uptime is None else _whole(uptime, "guards.min_uptime_seconds", 0, MAX_UPTIME_GUARD),
            None if clients is None else _whole(clients, "guards.skip_if_clients_over", 0, MAX_CLIENTS_GUARD),
            20 if cooldown is None else _whole(cooldown, "guards.cooldown_hours", 0, MAX_COOLDOWN_HOURS),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "min_uptime_seconds": self.min_uptime_seconds,
            "skip_if_clients_over": self.skip_if_clients_over,
            "cooldown_hours": self.cooldown_hours,
        }


def _actions(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ValidationError(f"actions must list at least one of {', '.join(ACTIONS)}")
    chosen = set()
    for item in value:
        if not isinstance(item, str) or item not in ACTIONS:
            raise ValidationError(f"actions may only include {', '.join(ACTIONS)}")
        chosen.add(item)
    return tuple(action for action in ACTIONS if action in chosen)


def _firmware(value: Any) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValidationError("firmware must map a product class to a firmware file name")
    if len(value) > MAX_FIRMWARE_CHOICES:
        raise ValidationError(f"firmware may name at most {MAX_FIRMWARE_CHOICES} product classes")
    chosen: dict[str, str] = {}
    for key, name in value.items():
        product = validate_file_metadata(key.strip() if isinstance(key, str) else key, "firmware product class")
        # Routers disagree on the case of their product class, so two keys differing
        # only in case would make the choice depend on dictionary order.
        if any(existing.casefold() == product.casefold() for existing in chosen):
            raise ValidationError(f"firmware names product class {product} more than once")
        chosen[product] = validate_firmware_name(name)
    return chosen


@dataclass(frozen=True)
class MaintenancePlan:
    id: str
    name: str
    enabled: bool
    targets: PlanTargets
    schedule: PlanSchedule
    actions: tuple[str, ...]
    guards: PlanGuards
    firmware: Mapping[str, str] = field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""

    @classmethod
    def from_dict(cls, data: Any, *, plan_id: str | None = None) -> "MaintenancePlan":
        fields = _fields(data, "plan", _PLAN_FIELDS)
        identifier = fields.get("id") if plan_id is None else plan_id
        if not isinstance(identifier, str) or not _PLAN_ID.fullmatch(identifier):
            raise ValidationError("not a maintenance plan id")
        if fields.get("id") not in (None, identifier):
            raise ValidationError("a plan's id cannot be changed")
        actions = _actions(fields.get("actions"))
        targets = PlanTargets.from_dict(fields.get("targets"))
        firmware = _firmware(fields.get("firmware"))
        if "firmware_update" in actions:
            if not firmware:
                raise ValidationError("firmware_update needs a firmware file chosen for at least one product class")
            if not targets.reaches_acs:
                raise ValidationError(
                    "firmware_update is only sent to TR-069 routers; add acs_devices, "
                    "the managed or cudy group, or set targets.all"
                )
        stamps = [fields.get(key) or "" for key in ("created_at", "updated_at")]
        if any(not isinstance(stamp, str) for stamp in stamps):
            raise ValidationError("created_at and updated_at must be strings")
        return cls(
            id=identifier,
            name=validate_plan_name(fields.get("name")),
            enabled=_flag(fields.get("enabled"), "enabled", True),
            targets=targets,
            schedule=PlanSchedule.from_dict(fields.get("schedule")),
            actions=actions,
            guards=PlanGuards.from_dict(fields.get("guards")),
            firmware=firmware,
            created_at=stamps[0],
            updated_at=stamps[1],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "enabled": self.enabled,
            "targets": self.targets.to_dict(),
            "schedule": self.schedule.to_dict(),
            "actions": list(self.actions),
            "firmware": dict(self.firmware),
            "guards": self.guards.to_dict(),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @property
    def disruptive(self) -> bool:
        return any(action in DISRUPTIVE for action in self.actions)

    def firmware_for(self, product_class: Any) -> str | None:
        if not isinstance(product_class, str) or not product_class.strip():
            return None
        wanted = product_class.strip().casefold()
        return next((name for key, name in self.firmware.items() if key.casefold() == wanted), None)


def _check_plan_id(plan_id: Any) -> str:
    if not isinstance(plan_id, str) or not _PLAN_ID.fullmatch(plan_id):
        raise ValidationError("not a maintenance plan id")
    return plan_id


def _write_json(path: Path, payload: Any, prefix: str) -> None:
    """Replace ``path`` in one step, 0600, so a crash leaves the old file or the new one."""
    data = json.dumps(payload, indent=2, sort_keys=True).encode()
    fd, temporary = tempfile.mkstemp(prefix=prefix, suffix=".tmp", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        with contextlib.suppress(OSError):
            os.chmod(path, 0o600)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)
    with contextlib.suppress(OSError):
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


@contextlib.contextmanager
def _flocked(lock_path: Path) -> Iterator[None]:
    lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    handle = os.open(lock_path, os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(handle, fcntl.LOCK_UN)
        os.close(handle)


class MaintenanceStore:
    """The plans, in data_dir/maintenance.json. Every change re-reads the file under an flock."""

    def __init__(self, data_dir: str | Path, *, clock: Callable[[], datetime] | None = None) -> None:
        self.data_dir = Path(data_dir).expanduser()
        self.path = self.data_dir / PLANS_FILE
        self.lock_path = self.data_dir / "maintenance.lock"
        self._clock = clock or (lambda: datetime.now(UTC))
        # flock alone would do across processes; this keeps one process's threads in line too.
        self._thread_lock = threading.Lock()

    def _read(self) -> dict[str, MaintenancePlan]:
        try:
            raw = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return {}
        except OSError as exc:
            raise MaintenanceError(f"maintenance plans are unreadable: {self.path}") from exc
        try:
            data = json.loads(raw)
        except ValueError as exc:
            raise MaintenanceError(f"maintenance plans are unreadable: {self.path}") from exc
        # Only a missing file means "no plans": an empty or reshaped one is what a
        # crash or a hand-edit leaves, and the next save would make the loss permanent.
        if not isinstance(data, dict) or not isinstance(data.get("plans"), dict):
            raise MaintenanceError(f"{self.path} has no plans mapping; refusing to treat it as empty")
        plans = {}
        for plan_id, entry in data["plans"].items():
            try:
                plans[plan_id] = MaintenancePlan.from_dict(entry, plan_id=plan_id)
            except ValidationError as exc:
                raise MaintenanceError(f"maintenance plan {plan_id!r} in {self.path} is invalid: {exc}") from exc
        return plans

    def _write(self, plans: Mapping[str, MaintenancePlan]) -> None:
        payload = {"version": FORMAT_VERSION, "plans": {plan_id: plan.to_dict() for plan_id, plan in plans.items()}}
        _write_json(self.path, payload, "maintenance.")

    @contextlib.contextmanager
    def _changing(self) -> Iterator[dict[str, MaintenancePlan]]:
        with self._thread_lock, _flocked(self.lock_path):
            plans = self._read()
            yield plans
            self._write(plans)

    def _now(self) -> str:
        return _iso(self._clock())

    @staticmethod
    def _unique(plans: Mapping[str, MaintenancePlan], plan: MaintenancePlan) -> None:
        # The name is what the activity log shows as the actor, so two plans sharing
        # one would make its entries ambiguous.
        for other in plans.values():
            if other.id != plan.id and other.name.casefold() == plan.name.casefold():
                raise ValidationError(f"a maintenance plan named {plan.name!r} already exists")

    def plans(self) -> list[MaintenancePlan]:
        return sorted(self._read().values(), key=lambda plan: (plan.name.casefold(), plan.id))

    def list(self) -> list[dict[str, Any]]:
        return [plan.to_dict() for plan in self.plans()]

    def plan(self, plan_id: str) -> MaintenancePlan:
        plan = self._read().get(_check_plan_id(plan_id))
        if plan is None:
            raise PlanNotFound("no such maintenance plan")
        return plan

    def get(self, plan_id: str) -> dict[str, Any]:
        return self.plan(plan_id).to_dict()

    def create(self, data: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(data, Mapping):
            raise ValidationError("plan must be an object")
        for key in _READ_ONLY:
            if key in data:
                raise ValidationError(f"{key} is set by SkyRouter")
        with self._changing() as plans:
            if len(plans) >= MAX_PLANS:
                raise ValidationError(f"there can be at most {MAX_PLANS} maintenance plans")
            plan_id = secrets.token_hex(6)
            while plan_id in plans:
                plan_id = secrets.token_hex(6)
            stamp = self._now()
            plan = MaintenancePlan.from_dict({**data, "created_at": stamp, "updated_at": stamp}, plan_id=plan_id)
            self._unique(plans, plan)
            plans[plan_id] = plan
        return plan.to_dict()

    def update(self, plan_id: str, changes: Mapping[str, Any]) -> dict[str, Any]:
        """Replace each top-level field given; the rest are kept. id and the timestamps are SkyRouter's."""
        _check_plan_id(plan_id)
        if not isinstance(changes, Mapping):
            raise ValidationError("plan changes must be an object")
        if changes.get("id") not in (None, plan_id):
            raise ValidationError("a plan's id cannot be changed")
        wanted = {key: value for key, value in changes.items() if key not in _READ_ONLY}
        with self._changing() as plans:
            existing = plans.get(plan_id)
            if existing is None:
                raise PlanNotFound("no such maintenance plan")
            merged = {**existing.to_dict(), **wanted, "created_at": existing.created_at, "updated_at": self._now()}
            plan = MaintenancePlan.from_dict(merged, plan_id=plan_id)
            self._unique(plans, plan)
            plans[plan_id] = plan
        return plan.to_dict()

    def delete(self, plan_id: str) -> dict[str, Any]:
        _check_plan_id(plan_id)
        with self._changing() as plans:
            plan = plans.pop(plan_id, None)
            if plan is None:
                raise PlanNotFound("no such maintenance plan")
        return {"id": plan.id, "name": plan.name, "deleted": True}


# --- running plans ----------------------------------------------------------------------


@dataclass(frozen=True)
class _Target:
    via: str  # "direct" or "acs"
    id: str
    # The plan groups it belongs to, as far as this pass has learned. A TR-069
    # router's make is only in the ACS fleet listing, which is read once per pass;
    # this is how the checks later in the pass still know it.
    groups: frozenset[str] = field(default=frozenset(), compare=False)

    @property
    def key(self) -> str:
        # Prefixed both ways: a direct device id may itself contain "acs:".
        return f"{self.via}:{self.id}"

    @property
    def router(self) -> str:
        """As the activity log names it: a device id, or acs:<GenieACS id>."""
        return self.id if self.via == "direct" else f"acs:{self.id}"


@dataclass
class _Visit:
    """One router in one occurrence of one plan."""

    plan: MaintenancePlan
    occurrence: str
    trigger: str  # "schedule" or "manual"
    who: str
    target: _Target
    router_name: str = ""
    # The local date the window opened, for a scheduled visit; None for a manual run.
    day: date | None = None
    # The pass's moment minus the runner's clock when the pass began: a pass given
    # its moment (a test, or a scheduler tick) keeps time from it.
    clock_offset: timedelta = timedelta(0)


def _outcome(action: str, status: str, detail: str, **extra: Any) -> dict[str, Any]:
    return {"action": action, "status": status, "detail": detail, **extra}


def _overall(outcomes: Sequence[dict[str, Any]]) -> str:
    statuses = [outcome["status"] for outcome in outcomes]
    if all(status == "skipped" for status in statuses):
        return "skipped"
    if "failed" in statuses:
        return "partial" if any(status in ("done", "queued") for status in statuses) else "failed"
    # A queued TR-069 job has not happened yet, and may still fail; it is never "done".
    return "queued" if "queued" in statuses else "done"


def _empty_state() -> dict[str, Any]:
    return {"version": FORMAT_VERSION, "occurrences": {}, "targets": {}}


def _section(state: Mapping[str, Any], occurrence: str, name: str) -> dict[str, Any]:
    """One part ("targets" reached, or reasons "held" back) of an occurrence in the state."""
    entry = state["occurrences"].get(occurrence)
    section = entry.get(name) if isinstance(entry, dict) else None
    return section if isinstance(section, dict) else {}


class MaintenanceRunner:
    """Runs the plans in a MaintenanceStore; RebootScheduler.tick() calls run_once."""

    def __init__(
        self,
        manager: "DeviceManager",
        acs_service: "AcsService | None",
        store: MaintenanceStore,
        activity: "ActivitySink | None" = None,
        *,
        state_path: str | Path | None = None,
        clock: Callable[[], datetime] | None = None,
        max_workers: int = MAX_WORKERS,
        check_timeout: float = CHECK_TIMEOUT,
    ) -> None:
        self.manager = manager
        self.acs = acs_service
        self.store = store
        self.activity = activity
        self.state_path = Path(state_path).expanduser() if state_path else store.data_dir / STATE_FILE
        self._lock_path = self.state_path.with_name(self.state_path.name + ".lock")
        self.clock = clock or (lambda: datetime.now(UTC))
        self.max_workers = max(1, int(max_workers))
        self.check_timeout = check_timeout
        # When RebootScheduler last rebooted a direct device, set by the scheduler this
        # runner is attached to, so a device's own schedule starts the cooldown too.
        self.reboot_history: Callable[[str], datetime | None] | None = None
        self._thread_lock = threading.Lock()
        self._manual: set[str] = set()
        self._manual_lock = threading.Lock()

    # -- state ----------------------------------------------------------------------------

    def _load(self) -> dict[str, Any]:
        try:
            raw = self.state_path.read_text()
        except FileNotFoundError:
            return _empty_state()
        except OSError as exc:
            raise MaintenanceError("maintenance state is unreadable") from exc
        try:
            data = json.loads(raw)
        except ValueError as exc:
            raise MaintenanceError("maintenance state is unreadable") from exc
        # Fails closed: forgetting which routers a window has reached would reboot them again.
        if (
            not isinstance(data, dict)
            or not isinstance(data.get("occurrences"), dict)
            or not isinstance(data.get("targets"), dict)
        ):
            raise MaintenanceError("maintenance state has an invalid format")
        return data

    @contextlib.contextmanager
    def _update(self) -> Iterator[dict[str, Any]]:
        """The state re-read under the lock, saved once the block finishes without raising."""
        with self._thread_lock, _flocked(self._lock_path):
            state = self._load()
            yield state
            _write_json(self.state_path, state, "maintenance-state.")

    @staticmethod
    def _occurrence(state: dict[str, Any], visit: _Visit, current: datetime) -> dict[str, Any]:
        entry = state["occurrences"].get(visit.occurrence)
        if not isinstance(entry, dict) or not isinstance(entry.get("targets"), dict):
            entry = {
                "plan": visit.plan.id,
                "plan_name": visit.plan.name,
                "trigger": visit.trigger,
                "created": _iso(current),
                "targets": {},
                "held": {},
            }
            state["occurrences"][visit.occurrence] = entry
        if not isinstance(entry.get("held"), dict):
            entry["held"] = {}
        return entry

    def get_state(self) -> dict[str, Any]:
        return self._load()

    def last_restart(self, device_id: str) -> datetime | None:
        """When a plan last rebooted this direct device, recorded as the reboot was sent."""
        try:
            entry = self._load()["targets"].get(f"direct:{device_id}")
        except MaintenanceError:
            return None
        return _parse(entry.get("last_disruptive")) if isinstance(entry, dict) else None

    def _prune(self, current: datetime) -> None:
        cutoff = current - STATE_RETENTION

        def stale(entry: Any, stamp: str) -> bool:
            moment = _parse(entry.get(stamp)) if isinstance(entry, dict) else None
            return moment is None or moment < cutoff

        state = self._load()
        if not any(stale(v, "created") for v in state["occurrences"].values()) and not any(
            stale(v, "last_disruptive") for v in state["targets"].values()
        ):
            return
        with self._update() as state:
            for name, stamp in (("occurrences", "created"), ("targets", "last_disruptive")):
                state[name] = {key: value for key, value in state[name].items() if not stale(value, stamp)}

    # -- entry points ----------------------------------------------------------------------

    def run_once(self, now: datetime | None = None) -> list[dict[str, Any]]:
        """Act on every router whose plan's window is open and that this window has not reached yet.

        Returns what happened in this pass: a result for each router acted on, and
        one for each router held back for a reason not already reported in this
        window. A router held back (offline, say) is tried again on later passes
        while the window lasts.
        """
        current = _utc(now or self.clock())
        visits: list[tuple[MaintenancePlan, str, str, str, date | None]] = []
        problems: list[dict[str, Any]] = []
        for plan in self.store.plans():
            if not plan.enabled:
                continue
            try:
                day = plan.schedule.occurrence_at(current)
            except (ZoneInfoNotFoundError, ValueError, OSError) as exc:
                # The timezone was valid when the plan was saved; tzdata may have changed since.
                problems.append(self._plan_problem(plan, f"the plan's timezone cannot be used: {_short(exc)}"))
                continue
            if day is not None:
                visits.append((plan, f"{plan.id}:{day.isoformat()}", "schedule", f"Maintenance: {plan.name}", day))
        results = problems + self._run(visits, current)
        try:
            self._prune(current)
        except (OSError, MaintenanceError) as exc:
            logger.warning("could not prune the maintenance state: %s", exc)
        return results

    def run_now(self, plan_id: str, actor: str) -> list[dict[str, Any]]:
        """Run a plan at once, window or not (enabled or not); the guards still apply."""
        requested_by = normalise_actor(actor)
        plan = self.store.plan(plan_id)
        with self._manual_lock:
            if plan.id in self._manual:
                raise MaintenanceBusy(f'maintenance plan "{plan.name}" is already running')
            self._manual.add(plan.id)
        try:
            current = _utc(self.clock())
            occurrence = f"{plan.id}:manual:{current.strftime('%Y%m%dT%H%M%S.%fZ')}"
            who = f"Maintenance: {plan.name} (run by {requested_by})"
            return self._run([(plan, occurrence, "manual", who, None)], current)
        finally:
            with self._manual_lock:
                self._manual.discard(plan.id)

    def overview(self, now: datetime | None = None) -> list[dict[str, Any]]:
        """Every plan with its next window and its latest run, for a dashboard."""
        current = _utc(now or self.clock())
        try:
            state = self._load()
        except MaintenanceError:
            state = _empty_state()
        occurrences = state["occurrences"]
        views = []
        for plan in self.store.plans():
            view = plan.to_dict()
            try:
                window = plan.schedule.next_window(current)
                view["window_open"] = plan.schedule.occurrence_at(current) is not None
            except (ZoneInfoNotFoundError, ValueError, OSError):
                window, view["window_open"] = None, False
            view["next_window"] = None if window is None else {"opens": _iso(window[0]), "closes": _iso(window[1])}
            runs = [
                (str(entry.get("created", "")), key, entry)
                for key, entry in occurrences.items()
                if isinstance(entry, dict) and entry.get("plan") == plan.id
            ]
            view["last_run"] = None
            if runs:
                created, key, entry = max(runs, key=lambda run: run[0])
                reached = _section(state, key, "targets")
                view["last_run"] = {
                    "occurrence": key,
                    "trigger": entry.get("trigger"),
                    "started": created,
                    "targets": {name: item.get("status") for name, item in reached.items() if isinstance(item, dict)},
                    "held": dict(_section(state, key, "held")),
                }
            views.append(view)
        return views

    # -- one pass --------------------------------------------------------------------------

    def _run(
        self, visits: Sequence[tuple[MaintenancePlan, str, str, str, date | None]], current: datetime
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        pending: list[_Visit] = []
        offset = current - _utc(self.clock())
        state = self._load()
        for plan, occurrence, trigger, who, day in visits:
            targets, problems = self._resolve(plan, occurrence, trigger, who, current)
            results.extend(problems)
            reached = _section(state, occurrence, "targets")
            pending.extend(
                _Visit(plan, occurrence, trigger, who, target, day=day, clock_offset=offset)
                for target in targets
                if target.key not in reached
            )
        if len(pending) <= 1 or self.max_workers == 1:
            visited = [self._visit(visit, current) for visit in pending]
        else:
            with ThreadPoolExecutor(min(self.max_workers, len(pending)), thread_name_prefix="maintenance") as pool:
                visited = list(pool.map(lambda visit: self._visit(visit, current), pending))
        results.extend(result for result in visited if result is not None)
        results.sort(key=lambda result: (str(result.get("plan_name", "")), str(result.get("target", ""))))
        return results

    def _resolve(
        self, plan: MaintenancePlan, occurrence: str, trigger: str, who: str, current: datetime
    ) -> tuple[list[_Target], list[dict[str, Any]]]:
        chosen: dict[str, _Target] = {}

        def add(target: _Target) -> None:
            # Once per router however many ways the plan names it, keeping what each
            # way learned of the groups it belongs to.
            existing = chosen.get(target.key)
            if existing is not None:
                target = replace(existing, groups=existing.groups | target.groups)
            chosen[target.key] = target

        targets = plan.targets
        groups = set(targets.groups)
        if targets.all_routers or groups & {"direct", "cudy"}:
            for device in self.manager.get_all_devices():
                # Disabling a device is how an operator stops SkyRouter contacting it;
                # one named in the plan is still reported as held back.
                member = _direct_groups(device)
                if device.enabled and (targets.all_routers or member & groups):
                    add(_Target("direct", device.identifier, member))
        for identifier in targets.devices:
            add(_Target("direct", identifier))
        for acs_id in targets.acs_devices:
            add(_Target("acs", acs_id))
        problems: list[dict[str, Any]] = []
        if self.acs is None and "managed" in groups:
            # Otherwise a plan for the TR-069 routers would quietly do nothing at all.
            visit = _Visit(plan, occurrence, trigger, who, _Target("acs", "*"))
            problem = self._held_back(
                visit, "TR-069 management is off, so the managed group has no routers", "skipped", current
            )
            if problem is not None:
                problems.append(problem)
        elif self.acs is not None and (targets.all_routers or groups & _ACS_GROUPS):
            try:
                for summary in self._acs_fleet():
                    # Every router in the listing is adopted, so it is in the managed group.
                    member = frozenset({"managed", "cudy"} if _is_cudy_acs(summary) else {"managed"})
                    if targets.all_routers or member & groups:
                        add(_Target("acs", summary["acs_id"], member))
            except (AcsError, ValidationError) as exc:
                visit = _Visit(plan, occurrence, trigger, who, _Target("acs", "*"))
                problem = self._held_back(visit, f"could not list the TR-069 routers: {_short(exc)}", "failed", current)
                if problem is not None:
                    problems.append(problem)
        return list(chosen.values()), problems

    def _acs_fleet(self) -> list[dict[str, Any]]:
        """The summary of every adopted TR-069 router. One still in the "new" inbox has not been vetted by anyone."""
        if self.acs is None:
            return []
        found: dict[str, dict[str, Any]] = {}
        skip = 0
        while skip < MAX_ACS_FLEET:
            page = self.acs.list_devices(skip=skip, limit=ACS_PAGE)
            devices = page.get("devices") or []
            for device in devices:
                acs_id = device.get("acs_id")
                if isinstance(acs_id, str) and NEW_DEVICE_TAG not in (device.get("tags") or []) and acs_id not in found:
                    found[acs_id] = device
            skip += len(devices)
            if not devices or skip >= int(page.get("total") or 0):
                break
        return list(found.values())

    def _plan_problem(self, plan: MaintenancePlan, reason: str) -> dict[str, Any]:
        logger.warning("maintenance plan %s: %s", plan.id, reason)
        return {
            "source": "maintenance",
            "plan": plan.id,
            "plan_name": plan.name,
            "device": None,
            "status": "failed",
            "reason": reason,
            "actions": [],
        }

    def _result(self, visit: _Visit, status: str) -> dict[str, Any]:
        return {
            "source": "maintenance",
            "plan": visit.plan.id,
            "plan_name": visit.plan.name,
            "trigger": visit.trigger,
            "occurrence": visit.occurrence,
            "target": visit.target.key,
            "via": visit.target.via,
            "device": visit.target.id,
            "router_name": visit.router_name,
            "status": status,
            "actions": [],
        }

    def _visit(self, visit: _Visit, current: datetime) -> dict[str, Any] | None:
        try:
            context: dict[str, Any] = {}
            held = self._still_due(visit)
            if held is None:
                held, context = self._guard(visit)
            if held is None:
                # Asked again: reading the router can take minutes.
                held = self._still_due(visit)
            if held is not None:
                return self._held_back(visit, held, "skipped", current)
            if not self._claim(visit, current):
                # Another process, or another thread of this one, got here first.
                return None
        except Exception as exc:
            # Nothing has been sent yet, so it is tried again on the next pass.
            if not isinstance(exc, _EXPECTED):
                logger.exception("maintenance of %s under plan %s could not start", visit.target.key, visit.plan.id)
            return self._held_back(visit, f"nothing was done: {_short(exc)}", "failed", current)
        result = self._result(visit, "done")
        try:
            result["actions"] = self._act(visit, context, current)
            result["status"] = _overall(result["actions"])
        except Exception as exc:
            logger.exception("maintenance of %s under plan %s stopped", visit.target.key, visit.plan.id)
            result["status"] = "failed"
            result["reason"] = _short(exc)
            self._record(visit, "maintenance", "failed", f"stopped by an unexpected error: {_short(exc)}")
        result["router_name"] = visit.router_name
        failures = [outcome["detail"] for outcome in result["actions"] if outcome["status"] == "failed"]
        if failures and "reason" not in result:
            result["reason"] = "; ".join(failures)[:300]
        if result["status"] == "queued":
            # Names the job, which the ACS follows and logs when it ends.
            queued = [outcome["detail"] for outcome in result["actions"] if outcome["status"] == "queued"]
            result["reason"] = "; ".join(queued)[:300]
        self._finish(visit, result, current)
        return result

    def _moment(self, visit: _Visit) -> datetime:
        """Now, on the pass's timeline."""
        return _utc(self.clock()) + visit.clock_offset

    def _names(self, plan: MaintenancePlan, target: _Target) -> bool:
        targets = plan.targets
        if targets.all_routers:
            return True
        if target.via == "acs":
            return target.id in targets.acs_devices or not target.groups.isdisjoint(targets.groups)
        if target.id in targets.devices or "direct" in targets.groups:
            return True
        if "cudy" not in targets.groups:
            return False
        try:
            return _is_cudy_device(self.manager.get_device(target.id))
        except ManagerError:
            # Gone from SkyRouter: the guard says so, which is the better reason to give.
            return True

    def _still_due(self, visit: _Visit) -> str | None:
        """Why the visit must stop now, if it must, with the plan re-read from the store.

        A pass can outlast its window (a slow router, a large fleet), and the plan can
        be turned off, edited or deleted while it runs; both are looked at again
        before a router is claimed and before each restart. The visit carries on with
        the plan as it now is.
        """
        try:
            plan = self.store.plan(visit.plan.id)
        except PlanNotFound:
            return "the plan was deleted"
        if visit.day is not None:
            if not plan.enabled:
                return "the plan was turned off"
            try:
                day = plan.schedule.occurrence_at(self._moment(visit))
            except (ZoneInfoNotFoundError, ValueError, OSError) as exc:
                return f"the plan's timezone cannot be used: {_short(exc)}"
            if day != visit.day:
                return "the plan's window has closed"
        if not self._names(plan, visit.target):
            return "the plan no longer names this router"
        visit.plan = plan
        return None

    def _held_back(self, visit: _Visit, reason: str, status: str, current: datetime) -> dict[str, Any] | None:
        """Report a router that was not acted on, once per reason per occurrence."""
        key = visit.target.key
        try:
            if _section(self._load(), visit.occurrence, "held").get(key) == reason:
                return None
            with self._update() as state:
                entry = self._occurrence(state, visit, current)
                if key in entry["targets"] or entry["held"].get(key) == reason:
                    return None
                entry["held"][key] = reason
        except (OSError, MaintenanceError) as exc:
            # Reported anyway; it will be reported again next pass, which beats silence.
            logger.warning("could not record that %s was held back: %s", key, exc)
        result = self._result(visit, status)
        result["reason"] = reason
        self._record(visit, "maintenance", "refused" if status == "skipped" else "failed", f"skipped: {reason}")
        return result

    def _claim(self, visit: _Visit, current: datetime) -> bool:
        """Mark the router reached in this occurrence before anything is sent to it.

        Recorded first because a request that times out may still have been carried
        out, and an unrecorded one would be sent again on every pass of the window.
        """
        with self._update() as state:
            entry = self._occurrence(state, visit, current)
            if visit.target.key in entry["targets"]:
                return False
            entry["targets"][visit.target.key] = {"status": "running", "at": _iso(self._moment(visit))}
            entry["held"].pop(visit.target.key, None)
        return True

    def _finish(self, visit: _Visit, result: dict[str, Any], current: datetime) -> None:
        try:
            with self._update() as state:
                entry = self._occurrence(state, visit, current)
                claimed = entry["targets"].get(visit.target.key)
                entry["targets"][visit.target.key] = {
                    "status": result["status"],
                    "at": claimed.get("at") if isinstance(claimed, dict) else _iso(current),
                    "finished": _iso(self._moment(visit)),
                    "actions": [{"action": item["action"], "status": item["status"]} for item in result["actions"]],
                }
        except (OSError, MaintenanceError) as exc:
            # The claim is already saved, so the router is not visited again regardless.
            logger.warning("could not record the outcome for %s: %s", visit.target.key, exc)

    # -- guards ----------------------------------------------------------------------------

    def _cooldown(self, visit: _Visit, current: datetime, state: dict[str, Any]) -> str | None:
        hours = visit.plan.guards.cooldown_hours
        if not hours or not visit.plan.disruptive:
            return None
        last = None
        entry = state["targets"].get(visit.target.key)
        # A second restart in the same occurrence (the reboot after a firmware upgrade
        # that could not be queued) is the plan's own and does not count against it.
        if isinstance(entry, dict) and entry.get("occurrence") != visit.occurrence:
            last = _parse(entry.get("last_disruptive"))
        if visit.target.via == "direct" and self.reboot_history is not None:
            scheduled = self.reboot_history(visit.target.id)
            if scheduled is not None and (last is None or scheduled > last):
                last = scheduled
        if last is None:
            return None
        age = current - last
        if age >= timedelta(hours=hours):
            return None
        return f"cooldown active: SkyRouter last restarted it {_duration(age.total_seconds())} ago (cooldown {hours} h)"

    def _uptime(self, visit: _Visit, uptime: int | None) -> str | None:
        minimum = visit.plan.guards.min_uptime_seconds
        if not minimum:
            return None
        if uptime is None:
            return "uptime unavailable; the minimum-uptime guard needs a reliable reading"
        if uptime < minimum:
            return f"minimum uptime not reached: up {_duration(uptime)}, the plan needs {_duration(minimum)}"
        return None

    @staticmethod
    def _clients(visit: _Visit, count: int) -> str | None:
        limit = visit.plan.guards.skip_if_clients_over
        if limit is not None and count > limit:
            return f"{count} clients connected, more than the {limit} the plan allows"
        return None

    def _guard(self, visit: _Visit) -> tuple[str | None, dict[str, Any]]:
        held = self._cooldown(visit, self._moment(visit), self._load())
        if held is not None:
            return held, {}
        if visit.target.via == "direct":
            return self._guard_direct(visit)
        return self._guard_acs(visit)

    def _guard_direct(self, visit: _Visit) -> tuple[str | None, dict[str, Any]]:
        try:
            device = self.manager.get_device(visit.target.id)
        except ManagerError:
            return "the router is no longer managed by SkyRouter", {}
        visit.router_name = _display_name(device)
        if not device.enabled:
            return "the router is disabled in SkyRouter", {}
        status = self.manager.get_status(device.identifier)
        if status.get("reason") == "credentials_rejected":
            return "the router rejected the stored credentials", {}
        if not status.get("online"):
            return "the router is offline", {}
        held = self._uptime(visit, _count(status.get("uptime_seconds")))
        if held is None and visit.plan.guards.skip_if_clients_over is not None:
            count = _count(status.get("clients"))
            if count is None:
                try:
                    count = len(self.manager.get_connected_clients(device.identifier))
                except UnsupportedOperation:
                    return "the router cannot report its connected clients, so the client limit cannot be checked", {}
                except _EXPECTED as exc:
                    return f"could not count the connected clients: {_short(exc)}", {}
            held = self._clients(visit, count)
        return held, {"device": device, "status": status}

    def _guard_acs(self, visit: _Visit) -> tuple[str | None, dict[str, Any]]:
        if self.acs is None:
            return "TR-069 management is off", {}
        try:
            detail = self.acs.device_detail(visit.target.id)["device"]
        except AcsNotFound:
            return "the router is no longer in the ACS", {}
        except (AcsError, ValidationError) as exc:
            return f"could not read the router from the ACS: {_short(exc)}", {}
        now = self._moment(visit)
        info = detail.get("info") or {}
        visit.router_name = str(info.get("model") or info.get("serial") or "")[:100]
        if detail.get("online") is not True:
            return "the router is not checking in with the ACS", {}
        twin = self._direct_twin(visit, detail)
        if twin is not None:
            return twin, {}
        if visit.plan.disruptive:
            # One started from the dashboard, or by another plan: a reboot, or a
            # second image, while it installs could interrupt it.
            for job in detail.get("pending_jobs") or []:
                if isinstance(job, Mapping) and job.get("kind") == KIND_FIRMWARE:
                    return (
                        f"a firmware upgrade is under way on this router (ACS job {job.get('id')}); "
                        "a restart now could interrupt it"
                    ), {}
        held = self._uptime(visit, self._acs_uptime(detail, now))
        if held is None and visit.plan.guards.skip_if_clients_over is not None:
            held = self._acs_clients(visit, detail, now)
        return held, {"detail": detail}

    def _direct_twin(self, visit: _Visit, detail: Mapping[str, Any]) -> str | None:
        """Why to leave a TR-069 router to the plan's visit of it as a direct router, if it is one.

        SkyRouter keeps no link between the two inventories, so each would restart
        the same router under its own cooldown. The address it is managed at
        directly being the one it reports to the ACS is the evidence there is.
        """
        address = (detail.get("wan") or {}).get("ip")
        if not isinstance(address, str) or not address.strip():
            return None
        wanted = address.strip().casefold()
        for device in self.manager.get_all_devices():
            if (
                device.enabled
                and device.host.strip().casefold() == wanted
                and self._names(visit.plan, _Target("direct", device.identifier))
            ):
                return (
                    f"the same router is managed directly as {device.identifier} ({address.strip()}); "
                    "the plan restarts it only there"
                )
        return None

    def _acs_clients(self, visit: _Visit, detail: Mapping[str, Any], now: datetime) -> str | None:
        """The client guard from GenieACS's cache, which may not know, or may be out of date."""
        counts: list[int] = []
        stamps: list[datetime | None] = []
        for network in detail.get("wifi") or []:
            number = _count(network.get("clients")) if isinstance(network, Mapping) else None
            if number is not None:
                counts.append(number)
                stamps.append(_parse((network.get("as_of") or {}).get("clients")))
        hosts = [host for host in detail.get("clients") or [] if isinstance(host, Mapping)]
        # No count and no table is not "none": params.detail reports [] for a router
        # whose tables GenieACS never fetched, and for TR-181 Issue 1.
        if not counts and not hosts:
            return (
                "the router has not reported its connected clients over TR-069, "
                "so the client limit cannot be checked"
            )
        active = [host for host in hosts if host.get("active") is not False]
        # The age of what was counted; with nobody active, of the table saying so.
        stamps.extend(_parse(host.get("as_of")) for host in active or hosts)
        count = max(sum(counts), len(active))
        held = self._clients(visit, count)
        if held is not None:
            return held
        if any(stamp is None for stamp in stamps):
            return "the connected-client count over TR-069 has no timestamp, so the client limit cannot be checked"
        age = now - min(stamp for stamp in stamps if stamp is not None)
        if age > MAX_CLIENT_COUNT_AGE:
            return (
                f"the connected-client count over TR-069 is {_duration(age.total_seconds())} old, "
                "so the client limit cannot be checked"
            )
        return None

    @staticmethod
    def _acs_uptime(detail: Mapping[str, Any], current: datetime) -> int | None:
        # GenieACS stamps _lastBoot at the Inform that reports a boot, which is exact;
        # a cached UpTime is only as fresh as the last time it was read.
        booted = _parse((detail.get("checkin") or {}).get("last_boot"))
        if booted is not None:
            return max(0, int((current - booted).total_seconds()))
        info = detail.get("info") or {}
        uptime = _count(info.get("uptime"))
        as_of = _parse((info.get("as_of") or {}).get("uptime"))
        if uptime is None or as_of is None:
            return None
        return uptime + max(0, int((current - as_of).total_seconds()))

    # -- actions ---------------------------------------------------------------------------

    def _manager_logs(self) -> bool:
        return getattr(self.manager, "activity", None) is not None

    def _act(self, visit: _Visit, context: dict[str, Any], current: datetime) -> list[dict[str, Any]]:
        outcomes: list[dict[str, Any]] = []
        upgrading = False
        for action in visit.plan.actions:
            if action == "reboot" and upgrading:
                text = "the firmware upgrade restarts the router itself, and a reboot now could interrupt it"
                self._record(visit, "reboot", "info", f"reboot skipped: {text}", action=action)
                outcomes.append(_outcome(action, "skipped", text))
                continue
            handler = getattr(self, f"_{visit.target.via}_{action}")
            # Another upgrade already under way on the router (AcsBusy) restarts it too.
            busy = False
            try:
                outcome = handler(visit, context, current)
            except _Logged as logged:
                refused = _refused(logged.cause)
                outcome = _outcome(action, "skipped" if refused else "failed", _short(logged.cause))
            except Exception as exc:
                if not isinstance(exc, _EXPECTED):
                    logger.exception("maintenance %s on %s raised an unexpected error", action, visit.target.key)
                refused = _refused(exc)
                busy = isinstance(exc, AcsBusy)
                verdict = "refused" if refused else "failed"
                text = _short(exc)
                what = f"{_ATTEMPT[action]} {verdict}: {text}"
                self._record(visit, _ACTION_KIND[action], verdict, what, action=action)
                outcome = _outcome(action, "skipped" if refused else "failed", text)
            upgrading = upgrading or (action == "firmware_update" and (outcome["status"] == "queued" or busy))
            outcomes.append(outcome)
        return outcomes

    @contextlib.contextmanager
    def _restart(self, visit: _Visit) -> Iterator[datetime]:
        """Count a restart towards the cooldown before it is sent, and take it back if it never was.

        Recorded first, as the occurrence claim is, and re-checked under the lock: a
        second plan (or a second dashboard) visiting the same router in this pass
        must see this one's restart rather than send its own. The window and the
        plan are looked at once more, since the actions before this one can take
        minutes. Yields the moment recorded, which is when the restart goes out.
        """
        key = visit.target.key
        try:
            held = self._still_due(visit)
        except MaintenanceError as exc:
            raise _Held(f"not sent, because the plans could not be read: {_short(exc)}") from exc
        if held is not None:
            raise _Held(f"not sent: {held}")
        try:
            with self._update() as state:
                now = self._moment(visit)
                held = self._cooldown(visit, now, state)
                previous = state["targets"].get(key)
                if held is None:
                    state["targets"][key] = {
                        "last_disruptive": _iso(now),
                        "occurrence": visit.occurrence,
                        "plan": visit.plan.id,
                    }
        except (OSError, MaintenanceError) as exc:
            raise _Held(f"not sent, because the attempt could not be recorded first: {_short(exc)}") from exc
        if held is not None:
            raise _Held(held)
        try:
            yield now
        except BaseException as exc:
            cause = exc.cause if isinstance(exc, _Logged) else exc
            # Only SkyRouter's own refusals are taken back: anything else may have
            # reached the router and restarted it.
            if isinstance(cause, Exception) and _refused(cause):
                self._restore(visit, previous)
            raise

    def _restore(self, visit: _Visit, previous: Any) -> None:
        try:
            with self._update() as state:
                entry = state["targets"].get(visit.target.key)
                if isinstance(entry, dict) and entry.get("occurrence") == visit.occurrence:
                    if previous is None:
                        state["targets"].pop(visit.target.key, None)
                    else:
                        state["targets"][visit.target.key] = previous
        except (OSError, MaintenanceError) as exc:
            logger.warning("could not take back the restart record for %s: %s", visit.target.key, exc)

    def _router(self, device: Device, operation: str, *args: Any) -> Any:
        # Through DeviceManager._call, so the per-router lock and the rejected-credential
        # latch apply, exactly as for the dashboard's own requests.
        return self.manager._call(device, operation, *args)

    def _record(self, visit: _Visit, kind: str, result: str, what: str, **details: Any) -> None:
        if self.activity is None:
            return
        try:
            self.activity.record(
                who=visit.who,
                router=visit.target.router,
                router_name=visit.router_name,
                kind=kind,
                what=f'Maintenance "{visit.plan.name}": {what}',
                result=result,
                details={"plan": visit.plan.id, "occurrence": visit.occurrence, "trigger": visit.trigger, **details},
            )
        except (ActivityError, OSError) as exc:
            # The router has already been acted on; a lost entry must not undo that.
            logger.warning("could not record maintenance activity for %s: %s", visit.target.key, exc)
        except Exception:
            logger.exception("recording maintenance activity for %s raised an unexpected error", visit.target.key)

    def _direct_firmware_check(self, visit: _Visit, context: dict[str, Any], current: datetime) -> dict[str, Any]:
        found = self._router(context["device"], "check_firmware_update", self.check_timeout)
        available = found.get("available")
        running = str(found.get("current") or "") or "unknown"
        latest = found.get("latest") if isinstance(found.get("latest"), str) else None
        note = str(found.get("note") or "")
        if available is True:
            text = f"{latest or 'newer firmware'} is available (running {running}); nothing was installed"
        elif available is False:
            text = f"no newer firmware than {running}"
        else:
            # Never read as "none available": the router's answer could not be understood.
            text = f"could not tell whether newer firmware exists: {note or 'the router gave no answer'}"
        self._record(
            visit,
            "firmware",
            "info",
            f"firmware check: {text}",
            action="firmware_check",
            available=available if isinstance(available, bool) else None,
            current=running,
            latest=latest,
            note=note,
        )
        return _outcome("firmware_check", "done", text, available=available, current=running, latest=latest)

    def _direct_auto_update_on(self, visit: _Visit, context: dict[str, Any], current: datetime) -> dict[str, Any]:
        device = context["device"]
        info = self._router(device, "firmware_info")
        auto = info.get("auto_update") if isinstance(info, dict) else None
        if not isinstance(auto, dict):
            raise _Held("this router has no automatic firmware update SkyRouter can switch on")
        # The plan's start is when its owner already accepts disruption. The router
        # installs in its own 2-hour slot from that hour, read on its own clock.
        hour = visit.plan.schedule.start_hour
        if auto.get("enabled") is True:
            text = f"automatic firmware update was already on (window {auto.get('window') or 'unset'})"
            if auto.get("window_start_hour") != hour:
                # Someone chose that slot on a router already updating itself; it is
                # reported rather than moved.
                text += (
                    f", not at the plan's start hour ({_window_text(hour)}), so the router installs "
                    "updates outside the plan's window; it was left as it is"
                )
            self._record(visit, "firmware", "info", text, action="auto_update_on")
            return _outcome("auto_update_on", "done", text)
        # Never the slot left selected while it was off, or the first of its list:
        # nobody chose either.
        if not self._router(device, "set_auto_update", True, hour):
            raise AdapterError("the router did not confirm the change")
        window = _window_text(hour)
        text = f"automatic firmware update turned on (window {window}, from the plan's start hour"
        text += ", on the router's own clock)"
        self._record(visit, "firmware", "applied", text, action="auto_update_on", window=window)
        return _outcome("auto_update_on", "done", text)

    def _direct_firmware_update(self, visit: _Visit, context: dict[str, Any], current: datetime) -> dict[str, Any]:
        raise _Held("firmware installs are only sent to TR-069 routers, and this one is managed directly")

    def _direct_reboot(self, visit: _Visit, context: dict[str, Any], current: datetime) -> dict[str, Any]:
        logged = self._manager_logs()
        with self._restart(visit):
            try:
                # DeviceManager records the reboot itself, under this plan's name.
                done = self.manager.reboot_device(visit.target.id, actor=visit.who)
            except Exception as exc:
                if logged:
                    raise _Logged(exc) from exc
                raise
        if not logged:
            what = "reboot started" if done else "reboot not confirmed by the router"
            self._record(visit, "reboot", "applied" if done else "failed", what, action="reboot")
        if not done:
            return _outcome("reboot", "failed", "the router did not confirm the reboot")
        return _outcome("reboot", "done", "reboot started")

    def _acs_firmware_check(self, visit: _Visit, context: dict[str, Any], current: datetime) -> dict[str, Any]:
        raise _Held("update checks run on the router's own web page, which TR-069 does not reach")

    def _acs_auto_update_on(self, visit: _Visit, context: dict[str, Any], current: datetime) -> dict[str, Any]:
        raise _Held("automatic update is a setting on the router's own web page, which TR-069 does not reach")

    def _acs_firmware_update(self, visit: _Visit, context: dict[str, Any], current: datetime) -> dict[str, Any]:
        if self.acs is None:
            raise _Held("TR-069 management is off")
        info = context["detail"].get("info") or {}
        product = info.get("product_class")
        name = visit.plan.firmware_for(product)
        if name is None:
            raise _Held(f"the plan chooses no firmware for product class {product or 'unknown'}")
        record = self.acs.firmware.get(name)
        if record is None:
            raise AdapterError(f"firmware {name} is no longer in the firmware library")
        version = str(record.get("version") or "")
        if version and version == info.get("firmware"):
            text = f"the router already runs firmware {version}"
            self._record(visit, "firmware", "info", f"firmware upgrade not needed: {text}", action="firmware_update")
            return _outcome("firmware_update", "done", text)
        with self._restart(visit) as now:
            expiry = self._task_expiry(visit, now, FIRMWARE_EXPIRY)
            # Never confirmed past a model mismatch: that needs a person looking at it.
            job = self.acs.firmware_upgrade(
                visit.target.id, name, confirm_model_mismatch=False, actor=visit.who, expiry=expiry
            )
        return self._queued(visit, "firmware_update", job, f"firmware upgrade to {version or name}", firmware=name)

    def _acs_reboot(self, visit: _Visit, context: dict[str, Any], current: datetime) -> dict[str, Any]:
        if self.acs is None:
            raise _Held("TR-069 management is off")
        with self._restart(visit) as now:
            expiry = self._task_expiry(visit, now, DEFAULT_EXPIRY)
            job = self.acs.reboot(visit.target.id, actor=visit.who, expiry=expiry)
        return self._queued(visit, "reboot", job, "reboot")

    @staticmethod
    def _task_expiry(visit: _Visit, now: datetime, longest: int) -> int | None:
        """Seconds a TR-069 task may wait for the router: never past the window's end.

        A router that misses the connection request takes a task at its next
        periodic inform, which may be hours away; GenieACS drops it unrun once it
        expires. A manual run has no window, so the ACS's own default applies.
        """
        if visit.day is None:
            return None
        closes = visit.plan.schedule.window_for(visit.day)[1]
        left = int((closes - now).total_seconds())
        if left < MIN_EXPIRY:
            raise _Held("not sent: the window closes in under a minute, too soon for the router to take it")
        return min(left, longest)

    def _queued(self, visit: _Visit, action: str, job: Mapping[str, Any], label: str, **details: Any) -> dict[str, Any]:
        job_id = str(job.get("id") or "")
        if job.get("terminal"):
            # The job ended before it started: the ACS refused the task or could not be reached.
            text = f"{label} could not be queued: {_short(str(job.get('message') or job.get('state')))}"
            self._record(visit, _ACTION_KIND[action], "failed", text, action=action, job=job_id, **details)
            return _outcome(action, "failed", text, job=job_id)
        text = f"{label} queued as ACS job {job_id}; the router takes it at its next check-in"
        self._record(visit, _ACTION_KIND[action], "queued", text, action=action, job=job_id, **details)
        return _outcome(action, "queued", text, job=job_id)
