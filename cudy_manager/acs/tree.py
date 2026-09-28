"""Read-only access to a GenieACS device document.

A document nests one JSON object per path segment, with instance numbers as keys,
and marks every node with underscore attributes: leaves carry _value, _type,
_timestamp and _writable, objects carry _object: true (brief F9). What a router
never reported, or a projection left out, is simply absent, so every accessor
here answers None instead of raising: the normalisers treat "not cached" as a
first-class state, because it decides whether a write needs a refresh first.
"""

import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

ROOT_TR098 = "InternetGatewayDevice"
ROOT_TR181 = "Device"

_INSTANCE_RE = re.compile(r"[0-9]{1,9}")
# C0/C1 controls and the bidi overrides can rewrite what a terminal or a log line
# shows, and every string here was chosen by whoever configured the router.
_UNPRINTABLE_RE = re.compile(r"[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")
MAX_TEXT = 256


def parse_time(value: Any) -> datetime | None:
    """GenieACS dates arrive as ISO strings with a Z suffix; anything else is None."""
    if isinstance(value, datetime):
        moment = value
    elif isinstance(value, str) and value:
        try:
            moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


def iso(moment: datetime | None) -> str | None:
    if moment is None:
        return None
    return moment.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def clean_text(value: Any, limit: int = MAX_TEXT) -> str:
    return _UNPRINTABLE_RE.sub(" ", str(value))[:limit]


def normalise_ref(value: Any) -> list[str]:
    """A TR-069 reference or reference list as bare object paths.

    Both "Device.WiFi.Radio.1." and "Device.WiFi.Radio.1" occur in the field (the
    trailing dot differs by vendor), and LowerLayers is a comma-separated list.
    """
    if not isinstance(value, str):
        return []
    refs = []
    for part in value.split(","):
        ref = part.strip().rstrip(".")
        if ref:
            refs.append(ref)
    return refs


def instance_key(path: str) -> tuple[int, ...]:
    """Sort key that orders SSID.2 before SSID.10 and LANDevice.1 before LANDevice.2."""
    return tuple(int(part) for part in path.split(".") if _INSTANCE_RE.fullmatch(part))


def is_leaf(node: Any) -> bool:
    if not isinstance(node, Mapping):
        return False
    if node.get("_object") is True:
        return False
    return node.get("_object") is False or "_value" in node


@dataclass(frozen=True)
class Leaf:
    path: str
    # Kept out of repr so a leaf in a log line or traceback cannot leak a passphrase.
    value: Any = field(repr=False)
    type: str | None
    # None means GenieACS has never been told: leaves that only arrived in an Inform
    # carry no _writable until a GetParameterNames covers them.
    writable: bool | None
    timestamp: datetime | None
    has_value: bool

    @property
    def as_of(self) -> str | None:
        return iso(self.timestamp)


class DeviceTree:
    def __init__(self, doc: Mapping[str, Any]):
        if not isinstance(doc, Mapping):
            raise TypeError("a GenieACS device document must be a mapping")
        self.doc = doc

    # -- top-level system fields ---------------------------------------------------

    @property
    def id(self) -> str | None:
        value = self.doc.get("_id")
        return value if isinstance(value, str) else None

    @property
    def device_id(self) -> Mapping[str, Any]:
        value = self.doc.get("_deviceId")
        return value if isinstance(value, Mapping) else {}

    def device_field(self, name: str) -> str | None:
        value = self.device_id.get(name)
        if isinstance(value, (str, int)) and not isinstance(value, bool) and str(value):
            return clean_text(value)
        return None

    @property
    def tags(self) -> list[str]:
        value = self.doc.get("_tags")
        if not isinstance(value, list):
            return []
        return [clean_text(tag, 64) for tag in value if isinstance(tag, str)]

    @property
    def last_inform(self) -> datetime | None:
        return parse_time(self.doc.get("_lastInform"))

    @property
    def last_boot(self) -> datetime | None:
        return parse_time(self.doc.get("_lastBoot"))

    @property
    def registered(self) -> datetime | None:
        return parse_time(self.doc.get("_registered"))

    # -- the parameter tree --------------------------------------------------------

    def node(self, path: str) -> Mapping[str, Any] | None:
        current: Any = self.doc
        if not path:
            return self.doc
        for part in path.split("."):
            # "_" keys are attributes, never children, so "X._value" is not a path.
            if not part or part.startswith("_") or not isinstance(current, Mapping):
                return None
            current = current.get(part)
        return current if isinstance(current, Mapping) else None

    def exists(self, path: str) -> bool:
        return self.node(path) is not None

    def is_object(self, path: str) -> bool:
        node = self.node(path)
        return node is not None and not is_leaf(node)

    def leaf(self, path: str) -> Leaf | None:
        node = self.node(path)
        if node is None or not is_leaf(node):
            return None
        writable = node.get("_writable")
        type_ = node.get("_type")
        return Leaf(
            path=path,
            value=node.get("_value"),
            type=type_ if isinstance(type_, str) else None,
            writable=writable if isinstance(writable, bool) else None,
            timestamp=parse_time(node.get("_timestamp")),
            has_value="_value" in node,
        )

    def value(self, path: str, default: Any = None) -> Any:
        leaf = self.leaf(path)
        if leaf is None or not leaf.has_value:
            return default
        return leaf.value

    def text(self, path: str, limit: int = MAX_TEXT) -> str | None:
        """The leaf's value as display text, or None when it is not cached."""
        value = self.value(path)
        if value is None or isinstance(value, (dict, list)):
            return None
        if isinstance(value, bool):
            return "true" if value else "false"
        return clean_text(value, limit)

    def integer(self, path: str) -> int | None:
        value = self.value(path)
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            return value
        if isinstance(value, float) and value.is_integer():
            return int(value)
        # xsd:long and friends are strings in the document (F9).
        if isinstance(value, str) and re.fullmatch(r"-?[0-9]{1,18}", value.strip()):
            return int(value.strip())
        return None

    def boolean(self, path: str) -> bool | None:
        value = self.value(path)
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            return value != 0 if value in (0, 1) else None
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in ("true", "1", "yes", "on", "enabled"):
                return True
            if lowered in ("false", "0", "no", "off", "disabled"):
                return False
        return None

    def children(self, path: str) -> list[str]:
        node = self.node(path)
        if node is None or is_leaf(node):
            return []
        return [key for key, child in node.items() if not key.startswith("_") and isinstance(child, Mapping)]

    def instances(self, path: str) -> list[str]:
        """Full paths of the numbered instances under a table object, in numeric order."""
        names = [name for name in self.children(path) if _INSTANCE_RE.fullmatch(name)]
        return [f"{path}.{name}" for name in sorted(names, key=int)]

    def iter_leaves(self, path: str = "") -> Iterator[Leaf]:
        node = self.node(path)
        if node is None:
            return
        if is_leaf(node):
            leaf = self.leaf(path)
            if leaf is not None:
                yield leaf
            return
        for name in self.children(path):
            yield from self.iter_leaves(f"{path}.{name}" if path else name)


def as_tree(doc: "Mapping[str, Any] | DeviceTree") -> DeviceTree:
    return doc if isinstance(doc, DeviceTree) else DeviceTree(doc)
