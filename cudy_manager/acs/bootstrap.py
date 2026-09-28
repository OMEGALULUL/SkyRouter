"""SkyRouter's own provisioning content in GenieACS, and the only code that writes it.

GenieACS provisions nothing out of the box. Its default presets come from the UI's
first-run wizard, and SkyRouter never runs the UI (F23). So SkyRouter installs its
own content through the NBI: three provisions and four presets, all named skybre-*.

Presets are where GenieACS is most fragile. The NBI stores whatever JSON it is
given (F18). genieacs-cwmp then reads presets without guarding against shapes it
does not expect, so one bad preset stops preset loading for every router, not
only one (F19, F20). validate_preset() therefore accepts far less than GenieACS
would, and install() writes nothing until every preset has passed it.

Blocking: call from async code through asyncio.to_thread, as with AcsClient.
"""

import functools
import json
import logging
import re
from collections.abc import Mapping, Sequence
from importlib import resources
from typing import Any, Protocol

from ..models import ValidationError
from .client import AcsError, Page

logger = logging.getLogger(__name__)

# 1.3 (master) parses preset args as expressions and changes how presets are read
# (F1, F19), so content written for 1.2 could mean something else there.
SUPPORTED_VERSION_PREFIX = "1.2."
# Only the UI's first-run wizard creates these. The seeded "inform" preset writes
# the same ManagementServer leaves as skybre-inform, with a different
# connection-request password, so running both would make them overwrite each
# other every day.
SEEDED_PRESETS = ("bootstrap", "default", "inform")

PROVISION_NAMES = ("skybre-bootstrap", "skybre-inform", "skybre-refresh")
# One channel per preset, named after it. A fault only blocks its own channel, and
# /api/acs finds SkyRouter's faults by these names.
CHANNELS = ("skybre-bootstrap", "skybre-registered", "skybre-inform", "skybre-refresh")
NEW_DEVICE_TAG = "skybre_new"

DEFAULT_INFORM_INTERVAL = 300
# skybre-inform.js enforces the same bounds.
MIN_INFORM_INTERVAL = 60
MAX_INFORM_INTERVAL = 86400

# A provision with a built-in's name replaces the built-in everywhere, including
# inside the NBI's own tasks.
BUILTIN_PROVISIONS = frozenset({"refresh", "value", "tag", "reboot", "reset", "download", "instances"})
_NAME_RE = re.compile(r"skybre-[a-z0-9-]{1,40}")
# Matches the tag rule for web routes. The "tag" built-in declares Tags.<tag>, so
# the tag has to be a legal path segment.
_TAG_RE = re.compile(r"[a-z0-9_-]{1,32}")
# The TR-069 event codes, plus GenieACS's own "Registered". GenieACS compares event
# keys after turning spaces into "_", so any stray character would only produce a
# preset that never matches.
_EVENT_RE = re.compile(r"[0-9]{1,2} [A-Z]+(?: [A-Z]+)*|M [A-Za-z]{1,32}|Registered")
# A precondition that is not a valid expression gets parsed as legacy JSON, and one
# that fails both parsers throws while presets load (F20). The expression parser
# also reads "-" as minus. So preconditions come from this fixed list and are
# never built from input.
_PRECONDITION_TAGS = frozenset({NEW_DEVICE_TAG})
PRECONDITIONS = frozenset({""} | {f"Tags.{tag} IS NOT NULL" for tag in _PRECONDITION_TAGS})
# "schedule" is left out on purpose: SkyRouter has no use for it, and a cron
# expression GenieACS cannot parse is another way to break preset loading.
_PRESET_KEYS = frozenset({"weight", "channel", "events", "precondition", "configurations"})
_PROVISION_ENTRY_KEYS = frozenset({"type", "name", "args"})
_TAG_ENTRY_KEYS = frozenset({"type", "tag"})
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")

MAX_WEIGHT = 1000
MAX_EVENTS = 8
MAX_CONFIGURATIONS = 8
MAX_ARGS = 8
MAX_ARG_LENGTH = 256
# An integer outside this range changes value when GenieACS parses it as a JS number.
MAX_SAFE_INT = 2**53 - 1
# Far more than any real install has. Listing stops here rather than paging forever.
MAX_PRESETS = 1000
_PAGE = 200


class BootstrapRefused(AcsError):
    """GenieACS is in a state the bootstrap will not change. Nothing was written."""

    def __init__(self, message: str, *, seeded: Sequence[str] = (), version: str = ""):
        super().__init__(message)
        self.seeded = list(seeded)
        self.version = version


class BootstrapClient(Protocol):
    """The part of AcsClient the bootstrap uses."""

    def version(self) -> str: ...

    def find(
        self,
        collection: str,
        query: Mapping[str, Any],
        projection: Sequence[str] | None = None,
        sort: Mapping[str, int] | None = None,
        skip: int = 0,
        limit: int = 50,
    ) -> Page: ...

    def get_provision(self, name: str) -> str | None: ...

    def put_provision(self, name: str, script: str) -> None: ...

    def get_preset(self, name: str) -> dict[str, Any] | None: ...

    def put_preset(self, name: str, preset: Mapping[str, Any]) -> None: ...

    def delete_preset(self, name: str) -> None: ...


# --- validation -----------------------------------------------------------------------


def _check_name(name: Any, what: str) -> str:
    if not isinstance(name, str) or not _NAME_RE.fullmatch(name) or name in BUILTIN_PROVISIONS:
        raise ValidationError(f"{what} names must be skybre- followed by 1-40 lowercase letters, digits or '-'")
    return name


def _check_arg(where: str, arg: Any) -> None:
    if isinstance(arg, bool):
        return
    if isinstance(arg, int):
        if abs(arg) > MAX_SAFE_INT:
            raise ValidationError(f"{where}: integer argument is out of range")
        return
    if isinstance(arg, str):
        if len(arg) > MAX_ARG_LENGTH or _CONTROL_RE.search(arg):
            raise ValidationError(f"{where}: string arguments are at most {MAX_ARG_LENGTH} printable characters")
        return
    raise ValidationError(f"{where}: arguments must be strings, integers or booleans")


def _check_configuration(where: str, entry: Any) -> None:
    if not isinstance(entry, dict):
        raise ValidationError(f"{where}: each configuration must be an object")
    kind = entry.get("type")
    if kind == "provision":
        if set(entry) != _PROVISION_ENTRY_KEYS:
            raise ValidationError(f"{where}: a provision configuration has exactly type, name and args")
        _check_name(entry["name"], f"{where}: provision")
        args = entry["args"]
        # 1.2.16 passes args to the script exactly as stored (F19). A null is accepted
        # by GenieACS, but a list is the only shape SkyRouter's scripts read.
        if not isinstance(args, list) or len(args) > MAX_ARGS:
            raise ValidationError(f"{where}: provision args must be a list of at most {MAX_ARGS} values")
        for arg in args:
            _check_arg(where, arg)
    elif kind in ("add_tag", "delete_tag"):
        if set(entry) != _TAG_ENTRY_KEYS:
            raise ValidationError(f"{where}: a tag configuration has exactly type and tag")
        tag = entry["tag"]
        if not isinstance(tag, str) or not _TAG_RE.fullmatch(tag):
            raise ValidationError(f"{where}: tags must be 1-32 lowercase letters, digits, '_' or '-'")
    else:
        # genieacs-cwmp throws on a type it does not know (F19). "value", "age" and the
        # object types are known to it, but SkyRouter never writes them.
        raise ValidationError(f"{where}: configuration type {str(kind)[:32]!r} is not provision, add_tag or delete_tag")


def validate_preset(name: str, preset: Mapping[str, Any]) -> None:
    """Refuse any preset SkyRouter does not need to write. Raises ValidationError (a ValueError)."""
    _check_name(name, "preset")
    where = f"preset {name}"
    if not isinstance(preset, dict):
        raise ValidationError(f"{where}: must be an object")
    missing = sorted(_PRESET_KEYS - set(preset))
    if missing:
        raise ValidationError(f"{where}: missing {', '.join(missing)}")
    extra = sorted(str(key)[:32] for key in set(preset) - _PRESET_KEYS)
    if extra:
        raise ValidationError(f"{where}: unsupported fields {', '.join(extra)}")

    weight = preset["weight"]
    if isinstance(weight, bool) or not isinstance(weight, int) or abs(weight) > MAX_WEIGHT:
        raise ValidationError(f"{where}: weight must be an integer from -{MAX_WEIGHT} to {MAX_WEIGHT}")
    if preset["channel"] != name:
        raise ValidationError(f"{where}: channel must be the preset's own name")

    events = preset["events"]
    if not isinstance(events, dict) or len(events) > MAX_EVENTS:
        raise ValidationError(f"{where}: events must be an object of at most {MAX_EVENTS} event codes")
    for code, wanted in events.items():
        if not isinstance(code, str) or not _EVENT_RE.fullmatch(code) or not isinstance(wanted, bool):
            raise ValidationError(f"{where}: events must map TR-069 event codes to true or false")

    precondition = preset["precondition"]
    if not isinstance(precondition, str) or precondition not in PRECONDITIONS:
        raise ValidationError(f"{where}: precondition must be empty or one of SkyRouter's fixed tag checks")

    configurations = preset["configurations"]
    # An empty or missing list is one of the shapes that throws inside cwmp (F20).
    if not isinstance(configurations, list) or not 1 <= len(configurations) <= MAX_CONFIGURATIONS:
        raise ValidationError(f"{where}: configurations must be a list of 1-{MAX_CONFIGURATIONS} entries")
    for entry in configurations:
        _check_configuration(where, entry)


def validate_inform_interval(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not MIN_INFORM_INTERVAL <= value <= MAX_INFORM_INTERVAL:
        raise ValidationError(
            f"the inform interval must be whole seconds from {MIN_INFORM_INTERVAL} to {MAX_INFORM_INTERVAL}"
        )
    return value


# --- desired state --------------------------------------------------------------------


@functools.cache
def _script(name: str) -> str:
    return (resources.files("cudy_manager.acs") / "provisions" / f"{name}.js").read_text(encoding="utf-8")


def _preset(name: str, weight: int, events: dict[str, bool], configurations: list[dict[str, Any]]) -> dict[str, Any]:
    # The raw MongoDB shape, which the NBI stores exactly as sent (F18).
    return {"weight": weight, "channel": name, "events": events, "precondition": "", "configurations": configurations}


def _run(provision: str, *args: str | int | bool) -> dict[str, Any]:
    return {"type": "provision", "name": provision, "args": list(args)}


def desired_objects(inform_interval: int) -> tuple[dict[str, str], dict[str, dict[str, Any]]]:
    """What GenieACS should hold: ({provision name: script}, {preset name: preset}).

    Presets run in weight order, and a later declaration wins a conflict. Only
    skybre-inform declares values, so the order only decides which runs first.
    """
    interval = validate_inform_interval(inform_interval)
    provisions = {name: _script(name) for name in PROVISION_NAMES}
    presets = {
        # Forget what was cached before a factory reset or an ACS change.
        "skybre-bootstrap": _preset("skybre-bootstrap", 0, {"0 BOOTSTRAP": True}, [_run("skybre-bootstrap")]),
        # First contact, for the dashboard's "New devices" inbox.
        "skybre-registered": _preset(
            "skybre-registered", 0, {"Registered": True}, [{"type": "add_tag", "tag": NEW_DEVICE_TAG}]
        ),
        # No events and no precondition, so these run every session. A new router
        # has no tags yet, and each script decides from timestamps what is due.
        "skybre-inform": _preset("skybre-inform", 10, {}, [_run("skybre-inform", interval)]),
        "skybre-refresh": _preset("skybre-refresh", 20, {}, [_run("skybre-refresh")]),
    }
    return provisions, presets


def _check_references(provisions: Mapping[str, str], presets: Mapping[str, Mapping[str, Any]]) -> None:
    # GenieACS silently skips a provision name it does not know, so a typo here
    # would show up only as a feature that never runs.
    for name, preset in presets.items():
        for entry in preset["configurations"]:
            if entry["type"] == "provision" and entry["name"] not in provisions:
                raise ValidationError(f"preset {name} runs {entry['name']}, which SkyRouter does not install")


def _checked_desired(inform_interval: int) -> tuple[dict[str, str], dict[str, dict[str, Any]]]:
    provisions, presets = desired_objects(inform_interval)
    for name, preset in presets.items():
        validate_preset(name, preset)
    _check_references(provisions, presets)
    return provisions, presets


# --- reading GenieACS -----------------------------------------------------------------


def _canonical(value: Any) -> str | None:
    # Compared as canonical JSON rather than with ==, where True == 1: a stored
    # {"0 BOOTSTRAP": 1} is not the preset SkyRouter wrote. Key order carries no
    # meaning in a preset, so it is ignored.
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError):
        return None


def _same(stored: Any, desired: Any) -> bool:
    canonical = _canonical(stored)
    return canonical is not None and canonical == _canonical(desired)


def _list_presets(client: BootstrapClient) -> dict[str, dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    seen = 0
    while True:
        page = client.find("presets", {}, skip=seen, limit=_PAGE)
        if page.total > MAX_PRESETS:
            raise AcsError(f"GenieACS holds {page.total} presets; SkyRouter expects a handful")
        for item in page.items:
            name = item.get("_id")
            if isinstance(name, str):
                found[name] = {key: value for key, value in item.items() if key != "_id"}
        seen += len(page.items)
        if not page.items or seen >= page.total:
            return found


def _unexpected(stored: Mapping[str, Any], desired: Mapping[str, Any]) -> list[str]:
    # Left behind by an older SkyRouter that installed a preset under another name.
    return sorted(name for name in stored if _NAME_RE.fullmatch(name) and name not in desired)


def _seeded(stored: Mapping[str, Any]) -> list[str]:
    return [name for name in SEEDED_PRESETS if name in stored]


# --- install and drift ----------------------------------------------------------------


def install(
    client: BootstrapClient, inform_interval: int = DEFAULT_INFORM_INTERVAL, remove_seeded: bool = False
) -> dict[str, Any]:
    """Make GenieACS hold exactly SkyRouter's provisions and presets.

    Idempotent: an object already stored as desired is not written again, so a
    second run makes no writes. Everything written is read back and compared.
    Raises BootstrapRefused, having written nothing, for a GenieACS other than
    1.2, or while the UI's seeded presets exist and ``remove_seeded`` is false.

    Returns {"version", "removed_seeded", "provisions": {name: action},
    "presets": {name: action}, "writes"}, where each action is "created",
    "updated", "unchanged" or "removed".
    """
    # Every check that needs no ACS runs first, so a SkyRouter bug stops the
    # install before anything is deleted or written.
    provisions, presets = _checked_desired(inform_interval)

    version = client.version()
    if not version.startswith(SUPPORTED_VERSION_PREFIX):
        raise BootstrapRefused(
            f"GenieACS {version[:64]} is not a 1.2 release; SkyRouter's presets are written for 1.2",
            version=version,
        )
    stored_presets = _list_presets(client)
    seeded = _seeded(stored_presets)
    if seeded and not remove_seeded:
        raise BootstrapRefused(
            f"GenieACS still has the presets its UI seeds ({', '.join(seeded)}), which would overwrite "
            "SkyRouter's inform settings; run the bootstrap with remove_seeded to delete them",
            seeded=seeded,
            version=version,
        )

    writes = 0
    for name in seeded:
        client.delete_preset(name)
        logger.info("ACS bootstrap: removed seeded preset %s", name)
        writes += 1

    # Provisions first: a preset naming a provision that does not exist yet is
    # skipped without a fault.
    provision_actions: dict[str, str] = {}
    for name, script in provisions.items():
        current = client.get_provision(name)
        if current == script:
            provision_actions[name] = "unchanged"
            continue
        client.put_provision(name, script)
        writes += 1
        if client.get_provision(name) != script:
            raise AcsError(f"GenieACS did not store provision {name} as sent")
        provision_actions[name] = "created" if current is None else "updated"
        logger.info("ACS bootstrap: %s provision %s", provision_actions[name], name)

    preset_actions: dict[str, str] = {}
    for name, preset in presets.items():
        current_preset = stored_presets.get(name)
        if current_preset is not None and _same(current_preset, preset):
            preset_actions[name] = "unchanged"
            continue
        client.put_preset(name, preset)
        writes += 1
        if not _same(client.get_preset(name), preset):
            raise AcsError(f"GenieACS did not store preset {name} as sent")
        preset_actions[name] = "created" if current_preset is None else "updated"
        logger.info("ACS bootstrap: %s preset %s", preset_actions[name], name)

    for name in _unexpected(stored_presets, presets):
        client.delete_preset(name)
        writes += 1
        preset_actions[name] = "removed"
        logger.info("ACS bootstrap: removed stale preset %s", name)

    return {
        "version": version,
        "removed_seeded": seeded,
        "provisions": provision_actions,
        "presets": preset_actions,
        "writes": writes,
    }


def drift(client: BootstrapClient, inform_interval: int = DEFAULT_INFORM_INTERVAL) -> dict[str, Any]:
    """Compare GenieACS with what install() would write, without writing anything.

    Returns {"installed", "drift", "seeded_presets"}. ``drift`` lists
    {"kind", "name", "state"}, where state is "missing", "changed" or
    "unexpected" (a skybre-* preset SkyRouter no longer installs). ``installed``
    is true only when the list is empty.
    """
    provisions, presets = _checked_desired(inform_interval)
    items: list[dict[str, str]] = []
    for name, script in provisions.items():
        current = client.get_provision(name)
        if current != script:
            items.append({"kind": "provision", "name": name, "state": "missing" if current is None else "changed"})
    stored_presets = _list_presets(client)
    for name, preset in presets.items():
        if name not in stored_presets:
            items.append({"kind": "preset", "name": name, "state": "missing"})
        elif not _same(stored_presets[name], preset):
            items.append({"kind": "preset", "name": name, "state": "changed"})
    for name in _unexpected(stored_presets, presets):
        items.append({"kind": "preset", "name": name, "state": "unexpected"})
    return {"installed": not items, "drift": items, "seeded_presets": _seeded(stored_presets)}
