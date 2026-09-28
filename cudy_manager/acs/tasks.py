"""The tasks SkyRouter queues on GenieACS, and the checks every one passes first.

GenieACS 1.2.16 validates a task only after accepting the request, and a task it
rejects throws inside the NBI worker: the caller gets no response at all, the
worker dies, and repeated crashes stop the whole service (brief F13). The same
failure logs the offending value, which for a Wi-Fi write is the passphrase. So
nothing reaches the NBI unless it already passes a check at least as strict as
GenieACS's own, plus SkyRouter's narrower policy on top.
"""

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from ..models import ValidationError

# factoryReset and download come in a later phase; addObject, deleteObject and
# provisions are never sent from SkyRouter.
ALLOWED_TASK_NAMES = frozenset({"getParameterValues", "setParameterValues", "refreshObject", "reboot"})

# Vendor names such as X_ZTE-COM_ServiceList contain "-". A trailing dot is not a
# parameter path in GenieACS's task syntax.
PATH_RE = re.compile(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*")
MAX_PATH_LENGTH = 256
MAX_READ_PATHS = 64
# GenieACS sends at most 32 parameters per SetParameterValues RPC (F15). A larger
# task would reach the router as several RPCs and lose the router's all-or-nothing
# application of one Wi-Fi change (F29).
MAX_WRITE_VALUES = 32
MAX_VALUE_LENGTH = 1024
# Anything beyond 2**53 changes value when the NBI parses it as a JS number.
MAX_SAFE_INT = 2**53 - 1

JOB_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
STEP_RE = re.compile(r"[A-Za-z0-9_-]{1,32}")
# The prefix keeps SkyRouter's uniqueKey replacement from ever deleting a task
# something else queued.
UNIQUE_KEY_RE = re.compile(r"skyrouter-[a-z0-9_-]{1,40}")
_TYPE_RE = re.compile(r"xsd:[A-Za-z]{1,32}")
# XML 1.0 cannot carry C0 controls, so the SOAP request would be invalid, and a
# lone surrogate becomes a broken string once the NBI parses the JSON.
_BAD_CHARS_RE = re.compile(r"[\x00-\x1f\x7f\ud800-\udfff]")

MIN_EXPIRY = 60
MAX_EXPIRY = 7 * 86400
DEFAULT_EXPIRY = 3600
# A Wi-Fi change must survive a router behind CGNAT that only checks in on its
# periodic inform (§3.4).
WIFI_EXPIRY = 21600

_COMMON_KEYS = frozenset({"name", "expiry", "uniqueKey", "skyrouterJob", "skyrouterStep"})
_TASK_KEYS = {
    "getParameterValues": frozenset({"parameterNames"}),
    "setParameterValues": frozenset({"parameterValues"}),
    "refreshObject": frozenset({"objectName"}),
    "reboot": frozenset(),
}

ParamValue = str | bool | int


def validate_path(path: Any, what: str = "parameter path") -> str:
    if not isinstance(path, str) or len(path) > MAX_PATH_LENGTH or not PATH_RE.fullmatch(path):
        raise ValidationError(f"{what} must be a dotted TR-069 path of letters, digits, '_' and '-'")
    return path


def _validate_value(value: Any, where: str) -> None:
    # Messages name the path, never the value: this runs on Wi-Fi passphrases.
    if isinstance(value, bool):
        return
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INT:
            raise ValidationError(f"{where}: integer value is out of range")
        return
    if isinstance(value, str):
        if len(value) > MAX_VALUE_LENGTH:
            raise ValidationError(f"{where}: value is too long")
        if _BAD_CHARS_RE.search(value):
            raise ValidationError(f"{where}: value contains control characters")
        return
    raise ValidationError(f"{where}: value must be a string, boolean or integer")


def _expect_list(value: Any, key: str, limit: int) -> Sequence[Any]:
    if not isinstance(value, (list, tuple)) or not value:
        raise ValidationError(f"task {key} must be a non-empty list")
    if len(value) > limit:
        raise ValidationError(f"task {key} holds at most {limit} entries")
    return value


def validate_task(task: Mapping[str, Any]) -> None:
    """Refuse anything GenieACS's sanitizeTask would throw on, and anything SkyRouter never sends.

    Raises ValidationError. The message never includes a parameter value.
    """
    if not isinstance(task, Mapping):
        raise ValidationError("task must be an object")
    name = task.get("name")
    if name not in ALLOWED_TASK_NAMES:
        raise ValidationError(f"task name must be one of {', '.join(sorted(ALLOWED_TASK_NAMES))}")
    # _id and device are the NBI's to set, and a timestamp would defer or reorder the task.
    unknown = set(task) - _COMMON_KEYS - _TASK_KEYS[name]
    if unknown:
        raise ValidationError(f"task has unsupported fields: {', '.join(sorted(map(str, unknown)))}")
    missing = (_COMMON_KEYS | _TASK_KEYS[name]) - set(task)
    if missing:
        raise ValidationError(f"task is missing fields: {', '.join(sorted(missing))}")

    expiry = task["expiry"]
    if isinstance(expiry, bool) or not isinstance(expiry, int) or not MIN_EXPIRY <= expiry <= MAX_EXPIRY:
        raise ValidationError(f"task expiry must be whole seconds between {MIN_EXPIRY} and {MAX_EXPIRY}")
    if not isinstance(task["uniqueKey"], str) or not UNIQUE_KEY_RE.fullmatch(task["uniqueKey"]):
        raise ValidationError("task uniqueKey must look like skyrouter-<name>")
    if not isinstance(task["skyrouterJob"], str) or not JOB_RE.fullmatch(task["skyrouterJob"]):
        raise ValidationError("task skyrouterJob must be 1-64 letters, digits, '_' or '-'")
    if not isinstance(task["skyrouterStep"], str) or not STEP_RE.fullmatch(task["skyrouterStep"]):
        raise ValidationError("task skyrouterStep must be 1-32 letters, digits, '_' or '-'")

    if name == "getParameterValues":
        for path in _expect_list(task["parameterNames"], "parameterNames", MAX_READ_PATHS):
            validate_path(path)
    elif name == "setParameterValues":
        seen: set[str] = set()
        for index, entry in enumerate(_expect_list(task["parameterValues"], "parameterValues", MAX_WRITE_VALUES)):
            if not isinstance(entry, (list, tuple)) or len(entry) not in (2, 3):
                raise ValidationError(f"parameterValues[{index}] must be [path, value] or [path, value, type]")
            path = validate_path(entry[0])
            if path in seen:
                raise ValidationError(f"parameterValues sets {path} more than once")
            seen.add(path)
            _validate_value(entry[1], f"parameterValues[{index}] ({path})")
            if len(entry) == 3 and (not isinstance(entry[2], str) or not _TYPE_RE.fullmatch(entry[2])):
                raise ValidationError(f"parameterValues[{index}] ({path}): type must look like xsd:string")
    elif name == "refreshObject":
        # GenieACS reads "" as the whole data model, which on a large router is a long
        # session SkyRouter never needs: refreshing one root covers the same ground.
        validate_path(task["objectName"], "refreshObject objectName")


def _paths(values: Sequence[str], what: str) -> tuple[str, ...]:
    # A bare string is a Sequence too, and would otherwise become one path per character.
    if isinstance(values, str) or not isinstance(values, (list, tuple)):
        raise ValidationError(f"{what} must be a list")
    return tuple(values)


@dataclass(frozen=True, repr=False)
class Task:
    """One NBI task. Build it with the constructors below; construction validates it.

    ``job`` and ``step`` are stored on the task as skyrouterJob and skyrouterStep so a
    POST whose reply was lost can be found again with ``AcsClient.tasks(job=...)``.
    """

    name: str
    job: str
    step: str
    unique_key: str
    expiry: int = DEFAULT_EXPIRY
    parameter_names: tuple[str, ...] = ()
    parameter_values: tuple[tuple[str, ParamValue], ...] = ()
    object_name: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "parameter_names", _paths(self.parameter_names, "parameter_names"))
        values = self.parameter_values
        if isinstance(values, str) or not isinstance(values, (list, tuple)):
            raise ValidationError("parameter_values must be a list of (path, value) pairs")
        if any(not isinstance(entry, (list, tuple)) or len(entry) != 2 for entry in values):
            raise ValidationError("parameter_values must be a list of (path, value) pairs")
        object.__setattr__(self, "parameter_values", tuple((entry[0], entry[1]) for entry in values))
        # to_json only sends the fields that belong to the task name, so anything else
        # given here would be dropped without the caller noticing.
        stray = {
            "parameter_names": bool(self.parameter_names) and self.name != "getParameterValues",
            "parameter_values": bool(self.parameter_values) and self.name != "setParameterValues",
            "object_name": self.object_name is not None and self.name != "refreshObject",
        }
        if any(stray.values()):
            raise ValidationError(f"{self.name} does not take {', '.join(k for k, v in stray.items() if v)}")
        validate_task(self.to_json())

    def to_json(self) -> dict[str, Any]:
        body: dict[str, Any] = {"name": self.name}
        if self.name == "getParameterValues":
            body["parameterNames"] = list(self.parameter_names)
        elif self.name == "setParameterValues":
            body["parameterValues"] = [[path, value] for path, value in self.parameter_values]
        elif self.name == "refreshObject":
            body["objectName"] = self.object_name
        body["expiry"] = self.expiry
        body["uniqueKey"] = self.unique_key
        body["skyrouterJob"] = self.job
        body["skyrouterStep"] = self.step
        return body

    @property
    def paths(self) -> tuple[str, ...]:
        """Every parameter path the task touches, without any value."""
        if self.name == "setParameterValues":
            return tuple(path for path, _ in self.parameter_values)
        if self.name == "refreshObject" and self.object_name is not None:
            return (self.object_name,)
        return self.parameter_names

    def __repr__(self) -> str:
        # Values stay out so a task in a log line or a traceback cannot leak a passphrase.
        return (
            f"Task(name={self.name!r}, job={self.job!r}, step={self.step!r}, "
            f"unique_key={self.unique_key!r}, expiry={self.expiry!r}, paths={self.paths!r})"
        )


def get_parameter_values(
    names: Sequence[str], *, job: str, step: str, unique_key: str, expiry: int = DEFAULT_EXPIRY
) -> Task:
    return Task("getParameterValues", job, step, unique_key, expiry, parameter_names=_paths(names, "parameter names"))


def set_parameter_values(
    values: Mapping[str, ParamValue] | Sequence[tuple[str, ParamValue]],
    *,
    job: str,
    step: str,
    unique_key: str,
    expiry: int = DEFAULT_EXPIRY,
) -> Task:
    """One atomic write. GenieACS ignores a type element (F15), so none is sent."""
    pairs = tuple(values.items()) if isinstance(values, Mapping) else values
    return Task("setParameterValues", job, step, unique_key, expiry, parameter_values=tuple(pairs))


def refresh_object(object_name: str, *, job: str, step: str, unique_key: str, expiry: int = DEFAULT_EXPIRY) -> Task:
    return Task("refreshObject", job, step, unique_key, expiry, object_name=object_name)


def reboot(*, job: str, step: str, unique_key: str = "skyrouter-reboot", expiry: int = DEFAULT_EXPIRY) -> Task:
    return Task("reboot", job, step, unique_key, expiry)
