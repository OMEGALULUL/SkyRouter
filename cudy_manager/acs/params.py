"""Turn a GenieACS device document into what SkyRouter shows and writes.

Everything here is pure: it reads a document the NBI already returned and never
contacts GenieACS or a router, so dashboard polling costs nothing on the router.

Three rules run through the module:

* TR-098 and TR-181 are normalised here, in Python, driven by vendor profiles
  (brief §3.5); GenieACS gets no virtual parameters for this.
* Every value carries the _timestamp GenieACS stamped on it, shown as "as of",
  because the cache can be hours old and a refresh is a router session.
* No secret value ever leaves this module. GenieACS caches the plaintext of every
  value SkyRouter writes (F15), so a Wi-Fi passphrase sits in the document until
  the next read replaces it with "". Secret leaves are reported only as
  {present, writable}, in the normalised views and in the raw dump alike.
"""

import copy
import re
from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from ..models import ValidationError
from .profiles import REPORTED_BAND_SOURCES, TR098, TR181, Profile, select_profile
from .tree import (
    ROOT_TR098,
    ROOT_TR181,
    DeviceTree,
    Leaf,
    as_tree,
    clean_text,
    instance_key,
    is_leaf,
    iso,
    normalise_ref,
)

MODEL_TR098 = TR098
MODEL_TR181 = TR181
# TR-181 Issue 1 (Device:1.x) describes non-gateway devices and has no Device.WiFi,
# so such routers get no Wi-Fi writes.
MODEL_TR181_ISSUE1 = "tr181-issue1"
# Both roots carry Wi-Fi objects; the vendor profile decides which one is managed.
MODEL_MIXED = "mixed"
MODEL_UNKNOWN = "unknown"
DATA_MODELS = (MODEL_TR098, MODEL_TR181, MODEL_TR181_ISSUE1, MODEL_MIXED, MODEL_UNKNOWN)

BANDS = ("2.4GHz", "5GHz", "6GHz")
BAND_ALL = "all"
BAND_CHOICES = (*BANDS, BAND_ALL)

SECURITY_MODES = ("open", "wep", "wpa", "wpa2", "wpa-wpa2", "wpa3", "wpa3-transition", "unknown")
# The modes with a personal passphrase. Setting one on an open, WEP or enterprise
# network would need a security-mode change first, which is a separate action
# (the same refusal as OpenWrtAdapter.set_wifi_password).
PASSPHRASE_SECURITY = frozenset({"wpa", "wpa2", "wpa-wpa2", "wpa3", "wpa3-transition"})
_SAE_SECURITY = frozenset({"wpa3", "wpa3-transition"})

REFRESH_SCOPES = ("wifi", "hosts", "wan", "info", "all")

SSID = "ssid"
PASSPHRASE = "passphrase"  # noqa: S105 - the name of a leaf kind, not a password

_IGD_CR_URL = f"{ROOT_TR098}.ManagementServer.ConnectionRequestURL"
_DEV_CR_URL = f"{ROOT_TR181}.ManagementServer.ConnectionRequestURL"
_ROOTS = {TR098: ROOT_TR098, TR181: ROOT_TR181}

# What summarize() reads. The device list asks the NBI for only these (F8: always
# project), so a card never pulls a router's whole tree.
SUMMARY_PROJECTION: tuple[str, ...] = (
    "_id",
    "_deviceId",
    "_registered",
    "_lastInform",
    "_lastBoot",
    "_tags",
    f"{ROOT_TR098}.DeviceInfo",
    f"{ROOT_TR098}.ManagementServer",
    f"{ROOT_TR098}.LANDevice",
    f"{ROOT_TR181}.RootDataModelVersion",
    f"{ROOT_TR181}.DeviceSummary",
    f"{ROOT_TR181}.DeviceInfo",
    f"{ROOT_TR181}.ManagementServer",
    f"{ROOT_TR181}.WiFi",
    f"{ROOT_TR181}.LAN",
)
# What detail() and wifi_write_plan() read: both whole roots.
DETAIL_PROJECTION: tuple[str, ...] = (
    "_id",
    "_deviceId",
    "_registered",
    "_lastInform",
    "_lastBoot",
    "_lastBootstrap",
    "_tags",
    ROOT_TR098,
    ROOT_TR181,
)
# What firmware_identity() reads: who the router says it is, what it runs, and
# enough of ManagementServer to tell whether it is still checking in.
FIRMWARE_PROJECTION: tuple[str, ...] = (
    "_id",
    "_deviceId",
    "_lastInform",
    "_lastBoot",
    f"{ROOT_TR098}.DeviceInfo",
    f"{ROOT_TR098}.ManagementServer",
    f"{ROOT_TR181}.RootDataModelVersion",
    f"{ROOT_TR181}.DeviceSummary",
    f"{ROOT_TR181}.DeviceInfo",
    f"{ROOT_TR181}.ManagementServer",
)

# --- secrets -----------------------------------------------------------------------

# Write-only leaves read back as "" on a router that follows the spec (F27), but
# GenieACS keeps whatever SkyRouter last wrote, and some routers break the spec.
# Matching is deliberately broad: hiding a harmless leaf costs a line in a dump,
# showing a passphrase cannot be undone.
_SECRET_WORDS = ("password", "passwd", "passphrase", "secret", "presharedkey", "wepkey", "privatekey", "credential")
_SECRET_SUFFIXES = ("key", "pwd", "psk", "pin", "token")
# ManagementServer.ParameterKey and a Download's CommandKey are change markers.
_NOT_SECRET = frozenset({"parameterkey", "commandkey"})


def is_secret_name(name: str) -> bool:
    """True for a parameter name that holds, or may hold, a credential."""
    lowered = name.lower()
    if lowered in _NOT_SECRET:
        return False
    return any(word in lowered for word in _SECRET_WORDS) or lowered.endswith(_SECRET_SUFFIXES)


def is_secret_path(path: str) -> bool:
    """True when the leaf, or any object it sits in, is named like a secret.

    The object test covers TR-098's WEPKey.{i}.WEPKey and PreSharedKey.{i}.* tables
    and vendor credential objects whose leaves have generic names.
    """
    return any(is_secret_name(part) for part in path.split(".") if part and not part.isdigit())


def _redacted_leaf(node: Mapping[str, Any]) -> dict[str, Any]:
    writable = node.get("_writable")
    return {
        "_object": False,
        "_redacted": True,
        "present": True,
        "writable": writable if isinstance(writable, bool) else None,
    }


def _holds_known(value: Any, known: tuple[str, ...]) -> bool:
    return isinstance(value, str) and any(secret in value for secret in known)


def _redact_node(node: Mapping[str, Any], names: list[str], known: tuple[str, ...]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, child in node.items():
        if not isinstance(key, str):
            continue
        if key.startswith("_"):
            # Top-level system fields and object attributes; a leaf's _value is
            # never reached here because leaves are handled whole below.
            out[key] = copy.deepcopy(child)
            continue
        path = [*names, key]
        if isinstance(child, Mapping):
            if is_leaf(child):
                secret = is_secret_path(".".join(path)) or _holds_known(child.get("_value"), known)
                out[key] = _redacted_leaf(child) if secret else copy.deepcopy(dict(child))
            else:
                out[key] = _redact_node(child, path, known)
        elif is_secret_path(".".join(path)) or _holds_known(child, known):
            # Not the GenieACS shape, so there is no writable flag to keep.
            out[key] = {"_redacted": True}
        else:
            out[key] = copy.deepcopy(child)
    return out


def redact(doc: Mapping[str, Any] | DeviceTree, *, known_values: Iterable[str] = ()) -> dict[str, Any]:
    """A deep copy of the document with every secret leaf reduced to {present, writable}.

    ``known_values`` are secrets the caller holds, such as a passphrase it just
    wrote; any leaf whose value contains one is redacted too, whatever its name.
    Values shorter than 4 characters are ignored so a stray "1" cannot blank the
    tree. The input is not modified.
    """
    tree = as_tree(doc)
    known = tuple(value for value in known_values if isinstance(value, str) and len(value) >= 4)
    return _redact_node(tree.doc, [], known)


# --- small parsers -------------------------------------------------------------------

# A unit is required: a bare "2" or "5" in a vendor leaf could as well be an enum code.
_BAND_RE = re.compile(r"(2\.4|24|2|5(?:\.[0-9])?|6)(?:ghz|g|e)|2\.4")
_STANDARD_TOKEN_RE = re.compile(r"ac|ax|be|a|b|g|n")
_MAC_RE = re.compile(r"[0-9A-Fa-f]{2}([:-]?)[0-9A-Fa-f]{2}(?:\1[0-9A-Fa-f]{2}){4}")
_DBM_RE = re.compile(r"\s*(-?[0-9]{1,3})(?:\s*dBm)?\s*", re.IGNORECASE)


def parse_band(value: Any) -> str | None:
    """One of BANDS from text such as "2.4GHz", "5G" or "6E"; a list of bands gives None."""
    if not isinstance(value, str):
        return None
    parts = [part for part in re.sub(r"[\s_]", "", value).lower().split(",") if part]
    bands = set()
    for part in parts:
        match = _BAND_RE.fullmatch(part)
        if not match:
            return None
        number = match.group(1) or match.group(0)
        bands.add("2.4GHz" if number.startswith("2") else "6GHz" if number == "6" else "5GHz")
    return bands.pop() if len(bands) == 1 else None


def band_from_channels(value: Any) -> str | None:
    """1-14 is 2.4 GHz and 32 or above is 5 GHz. 6 GHz numbering overlaps both, so never 6 GHz."""
    if isinstance(value, bool):
        return None
    numbers = [int(number) for number in re.findall(r"[0-9]{1,3}", str(value))] if value is not None else []
    numbers = [number for number in numbers if number > 0]
    if not numbers:
        return None
    if all(number <= 14 for number in numbers):
        return "2.4GHz"
    if all(32 <= number <= 196 for number in numbers):
        return "5GHz"
    return None


def band_from_standard(value: Any) -> str | None:
    """The band an 802.11 standard string implies: "a"/"ac" exist only on 5 GHz, "b"/"g" only
    on 2.4 GHz, and "n", "ax" and "be" say nothing."""
    if not isinstance(value, str):
        return None
    tokens: set[str] = set()
    text = value.lower().replace("802.11", " ").replace("ieee", " ")
    for chunk in re.split(r"[^a-z0-9]+", text):
        chunk = chunk.removeprefix("11")
        position, parsed = 0, list[str]()
        # Compact vendor forms such as "bgn" or "anac".
        while position < len(chunk):
            match = _STANDARD_TOKEN_RE.match(chunk, position)
            if not match:
                parsed = []
                break
            parsed.append(match.group())
            position = match.end()
        tokens.update(parsed)
    five, two = tokens & {"a", "ac"}, tokens & {"b", "g"}
    if five and not two:
        return "5GHz"
    if two and not five:
        return "2.4GHz"
    return None


def normalise_security_mode(value: Any) -> str | None:
    """A TR-181 ModeEnabled or vendor security string as one of SECURITY_MODES, or None."""
    if not isinstance(value, str):
        return None
    text = re.sub(r"[^a-z0-9]", "", value.lower())
    if not text:
        return None
    # OWE ("enhanced open") encrypts but has no passphrase either.
    if text in ("none", "open", "disabled", "off", "owe"):
        return "open"
    if any(word in text for word in ("enterprise", "eap", "radius", "8021x")):
        # No personal passphrase to set; the raw mode is shown next to it.
        return "unknown"
    if text.startswith("wep"):
        return "wep"
    if "wpa3" in text or "sae" in text:
        return "wpa3-transition" if any(word in text for word in ("transition", "compat", "wpa2", "mixed")) else "wpa3"
    if "wpaand11i" in text or (text.count("wpa") >= 2 and "wpa2" in text) or ("wpa2" in text and "mixed" in text):
        return "wpa-wpa2"
    if "wpa2" in text or "11i" in text:
        return "wpa2"
    if text.startswith("wpa"):
        return "wpa"
    return None


def _mac(value: Any) -> str | None:
    if not isinstance(value, str) or not _MAC_RE.fullmatch(value.strip()):
        return None
    digits = re.sub(r"[^0-9a-f]", "", value.strip().lower())
    return ":".join(digits[index : index + 2] for index in range(0, 12, 2))


def _dbm(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and (match := _DBM_RE.fullmatch(value)):
        number = int(match.group(1))
    else:
        return None
    # Some firmware reports a positive "quality" in the same leaf; that is not dBm.
    return number if -127 <= number < 0 else None


def _instance_number(path: str) -> int | None:
    last = path.rsplit(".", 1)[-1]
    return int(last) if last.isdigit() else None


# --- data-model detection -------------------------------------------------------------


def _igd_has_wifi(tree: DeviceTree) -> bool:
    for lan in tree.instances(f"{ROOT_TR098}.LANDevice"):
        # LANDevice.{i}.WiFi is Huawei's hybrid of the two models.
        if tree.instances(f"{lan}.WLANConfiguration") or tree.instances(f"{lan}.WiFi.Radio"):
            return True
    return False


def _dev_has_wifi(tree: DeviceTree) -> bool:
    return any(tree.instances(f"{ROOT_TR181}.WiFi.{table}") for table in ("SSID", "AccessPoint", "Radio"))


def detect_model(doc: Mapping[str, Any] | DeviceTree) -> str:
    """One of DATA_MODELS: tr098, tr181, tr181-issue1, mixed or unknown."""
    tree = as_tree(doc)
    if _igd_has_wifi(tree) and _dev_has_wifi(tree):
        return MODEL_MIXED
    # The connection-request URL marks the root GenieACS itself uses for the device.
    if tree.exists(_IGD_CR_URL):
        return MODEL_TR098
    if tree.exists(ROOT_TR181):
        version = tree.text(f"{ROOT_TR181}.RootDataModelVersion") or ""
        summary = tree.text(f"{ROOT_TR181}.DeviceSummary") or ""
        if tree.exists(f"{ROOT_TR181}.WiFi") or tree.exists(f"{ROOT_TR181}.IP") or version.startswith("2."):
            return MODEL_TR181
        if tree.exists(f"{ROOT_TR181}.LAN") or summary.startswith("Device:1."):
            return MODEL_TR181_ISSUE1
    if tree.exists(ROOT_TR098):
        return MODEL_TR098
    if tree.exists(ROOT_TR181):
        # Nothing tells the issues apart yet. Issue 2 is by far the common case, and a
        # Wi-Fi write still needs the Wi-Fi objects to exist before it is planned.
        return MODEL_TR181
    return MODEL_UNKNOWN


def _primary_root(tree: DeviceTree, model: str) -> str | None:
    """The root that holds the device's identity, management server and WAN."""
    if model == MODEL_TR098:
        return TR098
    if model in (MODEL_TR181, MODEL_TR181_ISSUE1):
        return TR181
    if model == MODEL_MIXED:
        if tree.exists(_IGD_CR_URL):
            return TR098
        return TR181 if tree.exists(_DEV_CR_URL) else TR098
    return None


# --- networks ---------------------------------------------------------------------------


@dataclass
class _Network:
    path: str
    root: str
    ssid_leaf: str
    # Where the security settings live: the WLANConfiguration itself for TR-098,
    # the AccessPoint whose SSIDReference names this SSID for TR-181.
    security_base: str | None
    # The object that carries Channel and friends: the WLANConfiguration for TR-098,
    # the Radio named by SSID.LowerLayers for TR-181.
    radio: str | None
    # An SSID used by a Wi-Fi EndPoint is the uplink to another network; renaming
    # it would cut the router off.
    uplink: bool = False
    band: str | None = None
    band_source: str | None = None
    band_method: str | None = None
    role: str | None = None


@dataclass
class _Context:
    tree: DeviceTree
    model: str
    primary: str | None
    wifi_root: str | None
    profile: Profile | None
    networks: list[_Network]


def _tr098_networks(tree: DeviceTree) -> list[_Network]:
    networks = []
    for lan in tree.instances(f"{ROOT_TR098}.LANDevice"):
        for wlan in tree.instances(f"{lan}.WLANConfiguration"):
            networks.append(_Network(wlan, TR098, f"{wlan}.SSID", wlan, wlan))
    return networks


def _tr181_networks(tree: DeviceTree) -> list[_Network]:
    wifi = f"{ROOT_TR181}.WiFi"
    access_points: dict[str, str] = {}
    for ap in tree.instances(f"{wifi}.AccessPoint"):
        for ref in normalise_ref(tree.value(f"{ap}.SSIDReference")):
            # Instances come in numeric order, so the lowest AccessPoint wins.
            access_points.setdefault(ref, ap)
    endpoint_ssids = {
        ref
        for endpoint in tree.instances(f"{wifi}.EndPoint")
        for ref in normalise_ref(tree.value(f"{endpoint}.SSIDReference"))
    }
    networks = []
    for ssid in tree.instances(f"{wifi}.SSID"):
        radio = next(
            (
                ref
                for ref in normalise_ref(tree.value(f"{ssid}.LowerLayers"))
                if ref.startswith(f"{wifi}.Radio.") and tree.exists(ref)
            ),
            None,
        )
        access_point = access_points.get(ssid)
        uplink = access_point is None and ssid in endpoint_ssids
        networks.append(_Network(ssid, TR181, f"{ssid}.SSID", access_point, radio, uplink=uplink))
    return networks


def _radio_band(tree: DeviceTree, radio: str) -> str | None:
    band = parse_band(tree.value(f"{radio}.OperatingFrequencyBand"))
    # A radio that supports exactly one band can only be operating on it.
    return band or parse_band(tree.value(f"{radio}.SupportedFrequencyBands"))


def _channel_band(tree: DeviceTree, node: str | None) -> str | None:
    if node is None:
        return None
    # Channel 0 means "auto" on some firmware, so fall back to the possible channels.
    return band_from_channels(tree.value(f"{node}.Channel")) or band_from_channels(
        tree.value(f"{node}.PossibleChannels")
    )


def _standard_band(tree: DeviceTree, node: str | None, root: str) -> str | None:
    if node is None:
        return None
    names = ("Standard", "X_HW_Standard") if root == TR098 else ("OperatingStandards", "SupportedStandards")
    for name in names:
        band = band_from_standard(tree.value(f"{node}.{name}"))
        if band:
            return band
    return None


def _band_by(method: str, tree: DeviceTree, network: _Network, radios: list[str]) -> str | None:
    if method == "lowerlayers":
        if network.root == TR181:
            return _radio_band(tree, network.radio) if network.radio else None
        # Huawei's hybrid: a TR-098 WLANConfiguration pointing at a TR-181-style radio.
        for ref in normalise_ref(tree.value(f"{network.path}.LowerLayers")):
            if tree.exists(ref):
                return _radio_band(tree, ref)
        return None
    if method in ("X_HW_RFBand", "X_TP_Band"):
        return parse_band(tree.value(f"{network.path}.{method}"))
    if method == "channel":
        return _channel_band(tree, network.radio)
    if method == "standard":
        return _standard_band(tree, network.radio, network.root)
    if method == "single_radio":
        # With one radio every SSID must sit on it, even when LowerLayers is not cached.
        if network.radio is None and len(radios) == 1:
            radio = radios[0]
            return _radio_band(tree, radio) or _channel_band(tree, radio) or _standard_band(tree, radio, TR181)
        return None
    number = _instance_number(network.path)
    if number is None:
        return None
    if method == "index_1_5":
        return "2.4GHz" if 1 <= number <= 4 else "5GHz" if 5 <= number <= 8 else None
    if method == "index_1_2":
        return {1: "2.4GHz", 2: "5GHz"}.get(number)
    return None


def _assign_bands_and_roles(tree: DeviceTree, networks: list[_Network], profile: Profile) -> None:
    radios = tree.instances(f"{ROOT_TR181}.WiFi.Radio")
    by_band: dict[str, list[_Network]] = {}
    for network in networks:
        for method in profile.band_source:
            band = _band_by(method, tree, network, radios)
            if band:
                network.band = band
                network.band_source = "reported" if method in REPORTED_BAND_SOURCES else "guessed"
                network.band_method = method
                break
        if network.uplink:
            network.role = "uplink"
        elif network.band:
            by_band.setdefault(network.band, []).append(network)
    for group in by_band.values():
        group.sort(key=lambda network: instance_key(network.path))
        # The lowest instance with a real SSID; guest networks come after it, and an
        # empty SSID is a disabled slot, not a network anyone joins.
        primary = next((network for network in group if (tree.text(network.ssid_leaf) or "").strip()), None)
        for network in group:
            network.role = "primary" if network is primary else "secondary"


def _manufacturer_and_model(tree: DeviceTree, primary: str | None) -> tuple[str, str]:
    manufacturer = _info_leaf(tree, primary, "Manufacturer")[0] or tree.device_field("_Manufacturer") or ""
    model_name = _info_leaf(tree, primary, "ModelName")[0] or ""
    return manufacturer, model_name


def _context(doc: Mapping[str, Any] | DeviceTree) -> _Context:
    tree = as_tree(doc)
    model = detect_model(tree)
    primary = _primary_root(tree, model)
    manufacturer, model_name = _manufacturer_and_model(tree, primary)
    profile = select_profile(model, manufacturer, model_name, prefer=primary or TR098)
    wifi_root: str | None = None
    if model in (MODEL_TR098, MODEL_TR181):
        wifi_root = model
    elif model == MODEL_MIXED and profile is not None:
        wifi_root = profile.data_model
    networks: list[_Network] = []
    if wifi_root is not None and profile is not None:
        networks = _tr098_networks(tree) if wifi_root == TR098 else _tr181_networks(tree)
        _assign_bands_and_roles(tree, networks, profile)
    return _Context(tree, model, primary, wifi_root, profile, networks)


# --- security -------------------------------------------------------------------------


@dataclass(frozen=True)
class _Security:
    mode: str
    raw: str | None
    # False when the leaves that decide the mode are not cached: a refresh can tell.
    complete: bool
    leaf: str | None
    as_of: str | None


def _psk_variant(base: str, auth: str | None) -> str:
    if auth is None:
        return base
    lowered = auth.lower()
    if "eap" in lowered and "psk" not in lowered:
        return "unknown"
    if "sae" in lowered or "wpa3" in lowered:
        return "wpa3-transition" if "psk" in lowered or "wpa2" in lowered else "wpa3"
    return base


def _security(tree: DeviceTree, network: _Network) -> _Security:
    if network.root == TR181:
        if network.security_base is None:
            return _Security("unknown", None, False, None, None)
        path = f"{network.security_base}.Security.ModeEnabled"
        leaf = tree.leaf(path)
        raw = tree.text(path, 64)
        if not raw:
            return _Security("unknown", None, False, path, None)
        return _Security(normalise_security_mode(raw) or "unknown", raw, True, path, leaf.as_of if leaf else None)

    base = network.path
    path = f"{base}.BeaconType"
    leaf = tree.leaf(path)
    raw = tree.text(path, 64)
    if not raw:
        return _Security("unknown", None, False, path, None)
    as_of = leaf.as_of if leaf else None
    beacon = raw.strip().lower()
    if beacon == "basic":
        encryption_path = f"{base}.BasicEncryptionModes"
        encryption = tree.text(encryption_path, 64)
        if encryption is None:
            return _Security("unknown", raw, False, encryption_path, as_of)
        mode = {"wepencryption": "wep", "none": "open"}.get(encryption.strip().lower(), "unknown")
        return _Security(mode, f"{raw}/{encryption}", True, path, as_of)
    if beacon == "none":
        # The spec says no station can associate at all; there is nothing to set.
        return _Security("unknown", raw, True, path, as_of)
    if beacon == "wpa":
        return _Security(_psk_variant("wpa", tree.text(f"{base}.WPAAuthenticationMode", 64)), raw, True, path, as_of)
    if beacon == "11i":
        mode = _psk_variant("wpa2", tree.text(f"{base}.IEEE11iAuthenticationMode", 64))
        return _Security(mode, raw, True, path, as_of)
    if beacon == "wpaand11i":
        auth = tree.text(f"{base}.IEEE11iAuthenticationMode", 64) or tree.text(f"{base}.WPAAuthenticationMode", 64)
        return _Security(_psk_variant("wpa-wpa2", auth), raw, True, path, as_of)
    return _Security(normalise_security_mode(raw) or "unknown", raw, True, path, as_of)


# --- normalised views -------------------------------------------------------------------


def _as_of(leaf: Leaf | None) -> str | None:
    return leaf.as_of if leaf else None


def _info_leaf(tree: DeviceTree, primary: str | None, name: str) -> tuple[str | None, Leaf | None]:
    roots = [primary] if primary else []
    roots += [root for root in (TR098, TR181) if root not in roots]
    for root in roots:
        path = f"{_ROOTS[root]}.DeviceInfo.{name}"
        text = tree.text(path)
        if text:
            return text, tree.leaf(path)
    return None, None


_INFO_FIELDS = (
    ("manufacturer", "Manufacturer", "_Manufacturer"),
    ("oui", "ManufacturerOUI", "_OUI"),
    ("model", "ModelName", None),
    ("product_class", "ProductClass", "_ProductClass"),
    ("serial", "SerialNumber", "_SerialNumber"),
    ("firmware", "SoftwareVersion", None),
    ("hw", "HardwareVersion", None),
)


def _info(ctx: _Context) -> dict[str, Any]:
    tree = ctx.tree
    info: dict[str, Any] = {}
    as_of: dict[str, str | None] = {}
    for key, leaf_name, fallback in _INFO_FIELDS:
        text, leaf = _info_leaf(tree, ctx.primary, leaf_name)
        if text is None and fallback:
            text = tree.device_field(fallback)
        info[key] = text
        as_of[key] = _as_of(leaf)
    if info["model"] is None:
        # ProductClass is often junk ("IGD", "Device"), so it is only the last resort.
        info["model"] = info["product_class"]
    uptime = None
    roots = [ctx.primary] if ctx.primary else [TR098, TR181]
    for root in roots:
        path = f"{_ROOTS[root]}.DeviceInfo.UpTime"
        uptime = tree.integer(path)
        if uptime is not None:
            as_of["uptime"] = _as_of(tree.leaf(path))
            break
    info["uptime"] = uptime if uptime is None or uptime >= 0 else None
    as_of.setdefault("uptime", None)
    info["data_model"] = ctx.model
    info["as_of"] = as_of
    return info


def _checkin(ctx: _Context, now: datetime, inform_interval: int) -> dict[str, Any]:
    tree = ctx.tree
    interval, source = inform_interval, "configured"
    if ctx.primary:
        management = f"{_ROOTS[ctx.primary]}.ManagementServer"
        device_interval = tree.integer(f"{management}.PeriodicInformInterval")
        # The router's own schedule is what it keeps; SkyRouter's setting only
        # reaches it through the skybre-inform preset.
        if tree.boolean(f"{management}.PeriodicInformEnable") is not False and device_interval and device_interval > 0:
            interval, source = device_interval, "device"
    last = tree.last_inform
    online: bool | None = None
    expected_by = None
    if last is not None:
        online = now - last <= timedelta(seconds=2 * interval + 60)
        expected_by = last + timedelta(seconds=interval)
    return {
        "online": online,
        "last_inform": iso(last),
        "expected_by": iso(expected_by),
        "last_boot": iso(tree.last_boot),
        "registered": iso(tree.registered),
        "inform_interval": interval,
        "interval_source": source,
    }


def _clean_ip(value: str | None) -> str | None:
    if not value or value in ("0.0.0.0", "::") or value.startswith("127."):
        return None
    return value


def _empty_wan() -> dict[str, Any]:
    return {
        "ip": None,
        "status": None,
        "connected": None,
        "uptime": None,
        "type": None,
        "path": None,
        "selected_by": None,
        "as_of": {"ip": None, "status": None, "uptime": None},
    }


def _looks_like_internet(tree: DeviceTree, connection: str) -> bool:
    # ONTs often carry a management WAN next to the Internet one; vendors label the
    # service in Name or in an X_*ServiceList/ServiceType leaf.
    labels = [tree.text(f"{connection}.Name") or ""]
    for name in tree.children(connection):
        if name.startswith("X_") and ("ServiceList" in name or "ServiceType" in name):
            labels.append(tree.text(f"{connection}.{name}") or "")
    return any("INTERNET" in label.upper() for label in labels)


def _wan_tr098(tree: DeviceTree) -> dict[str, Any]:
    candidates: list[tuple[str, str]] = []
    for wan_device in tree.instances(f"{ROOT_TR098}.WANDevice"):
        for connection_device in tree.instances(f"{wan_device}.WANConnectionDevice"):
            for kind, table in (("ip", "WANIPConnection"), ("ppp", "WANPPPConnection")):
                candidates += [(kind, path) for path in tree.instances(f"{connection_device}.{table}")]
    chosen: tuple[str, str] | None = None
    selected_by = None
    for ref in normalise_ref(tree.value(f"{ROOT_TR098}.Layer3Forwarding.DefaultConnectionService"))[:1]:
        if tree.is_object(ref):
            chosen = ("ppp" if ".WANPPPConnection." in f"{ref}." else "ip", ref)
            selected_by = "DefaultConnectionService"
    if chosen is None:

        def status(candidate: tuple[str, str]) -> str:
            return tree.text(f"{candidate[1]}.ConnectionStatus") or ""

        def address(candidate: tuple[str, str]) -> str | None:
            return _clean_ip(tree.text(f"{candidate[1]}.ExternalIPAddress"))

        connected = [c for c in candidates if status(c) == "Connected" and address(c)]
        internet = [c for c in connected if _looks_like_internet(tree, c[1])]
        with_address = [c for c in candidates if address(c)]
        ranked = ((internet, "internet_service"), (connected, "first_connected"), (with_address, "first_address"))
        for group, how in ranked:
            if group:
                chosen, selected_by = group[0], how
                break
    if chosen is None:
        return _empty_wan()
    kind, path = chosen
    status_text = tree.text(f"{path}.ConnectionStatus", 64)
    connected_now = None if status_text is None else status_text == "Connected"
    uptime = tree.integer(f"{path}.Uptime")
    return {
        "ip": _clean_ip(tree.text(f"{path}.ExternalIPAddress", 64)),
        "status": status_text,
        "connected": connected_now,
        "uptime": uptime if connected_now and uptime is not None and uptime >= 0 else None,
        "type": kind,
        "path": path,
        "selected_by": selected_by,
        "as_of": {
            "ip": _as_of(tree.leaf(f"{path}.ExternalIPAddress")),
            "status": _as_of(tree.leaf(f"{path}.ConnectionStatus")),
            "uptime": _as_of(tree.leaf(f"{path}.Uptime")),
        },
    }


def _ipv4_address(tree: DeviceTree, interface: str) -> tuple[str | None, str | None]:
    # Cudy populates one IPv4Address instance per WAN protocol and leaves the
    # others empty, so the first non-empty enabled one is the live address.
    for address in tree.instances(f"{interface}.IPv4Address"):
        if tree.boolean(f"{address}.Enable") is False:
            continue
        ip = _clean_ip(tree.text(f"{address}.IPAddress", 64))
        if ip:
            return ip, f"{address}.IPAddress"
    return None, None


def _wan_tr181(tree: DeviceTree) -> dict[str, Any]:
    interfaces = tree.instances(f"{ROOT_TR181}.IP.Interface")
    chosen, selected_by = None, None
    # TR-181 has no "Internet WAN" flag [I]; the interface the default route leaves by is it.
    for router in tree.instances(f"{ROOT_TR181}.Routing.Router"):
        for route in tree.instances(f"{router}.IPv4Forwarding"):
            if chosen or tree.boolean(f"{route}.Enable") is False:
                continue
            destination = tree.text(f"{route}.DestIPAddress") or ""
            mask = tree.text(f"{route}.DestSubnetMask") or ""
            if destination in ("", "0.0.0.0") and mask in ("", "0.0.0.0"):
                refs = normalise_ref(tree.value(f"{route}.Interface"))
                chosen = next((ref for ref in refs if ref in interfaces), None)
                selected_by = "default_route" if chosen else None
    if chosen is None:
        for setting in tree.instances(f"{ROOT_TR181}.NAT.InterfaceSetting"):
            if tree.boolean(f"{setting}.Enable") is False:
                continue
            chosen = next((ref for ref in normalise_ref(tree.value(f"{setting}.Interface")) if ref in interfaces), None)
            if chosen:
                selected_by = "nat"
                break
    if chosen is None:
        for interface in interfaces:
            if tree.boolean(f"{interface}.Loopback"):
                continue
            dynamic = any(
                (tree.text(f"{address}.AddressingType") or "") in ("DHCP", "IPCP")
                and _clean_ip(tree.text(f"{address}.IPAddress"))
                for address in tree.instances(f"{interface}.IPv4Address")
            )
            if dynamic:
                chosen, selected_by = interface, "first_dynamic"
                break
    if chosen is None:
        return _empty_wan()
    ip, ip_leaf = _ipv4_address(tree, chosen)
    ppp = next(
        (
            ref
            for ref in normalise_ref(tree.value(f"{chosen}.LowerLayers"))
            if ref.startswith(f"{ROOT_TR181}.PPP.Interface.") and tree.exists(ref)
        ),
        None,
    )
    if ppp:
        if ip is None:
            ip = _clean_ip(tree.text(f"{ppp}.IPCP.LocalIPAddress", 64))
            ip_leaf = f"{ppp}.IPCP.LocalIPAddress" if ip else None
        status_path = f"{ppp}.ConnectionStatus"
        status_text = tree.text(status_path, 64)
        connected_now = None if status_text is None else status_text == "Connected"
        change_path = f"{ppp}.LastChange"
        kind = "ppp"
    else:
        status_path = f"{chosen}.Status"
        status_text = tree.text(status_path, 64)
        connected_now = None if status_text is None else status_text == "Up" and ip is not None
        change_path = f"{chosen}.LastChange"
        kind = "ip"
    # LastChange counts seconds in the current state, which is the uptime only while up.
    last_change = tree.integer(change_path)
    return {
        "ip": ip,
        "status": status_text,
        "connected": connected_now,
        "uptime": last_change if connected_now and last_change is not None and last_change >= 0 else None,
        "type": kind,
        "path": chosen,
        "selected_by": selected_by,
        "as_of": {
            "ip": _as_of(tree.leaf(ip_leaf)) if ip_leaf else None,
            "status": _as_of(tree.leaf(status_path)),
            "uptime": _as_of(tree.leaf(change_path)),
        },
    }


def _wan(ctx: _Context) -> dict[str, Any]:
    if ctx.model == MODEL_TR181_ISSUE1:
        return _empty_wan()
    if ctx.primary == TR098:
        return _wan_tr098(ctx.tree)
    if ctx.primary == TR181:
        return _wan_tr181(ctx.tree)
    return _empty_wan()


def _passphrase_candidates(network: _Network, profile: Profile) -> list[str]:
    if network.security_base is None:
        return []
    return [f"{network.security_base}.{relative}" for relative in profile.passphrase_leaves]


def _enable_paths(network: _Network) -> list[str]:
    paths = [f"{network.path}.Enable"]
    # TR-181 splits the switch: the SSID and its AccessPoint must both be on.
    if network.root == TR181 and network.security_base:
        paths.append(f"{network.security_base}.Enable")
    return paths


def _enabled(tree: DeviceTree, network: _Network) -> bool | None:
    known = [value for value in (tree.boolean(path) for path in _enable_paths(network)) if value is not None]
    return all(known) if known else None


def _wifi_entry(ctx: _Context, network: _Network) -> dict[str, Any]:
    tree = ctx.tree
    ssid_leaf = tree.leaf(network.ssid_leaf)
    enable_paths = _enable_paths(network)
    if network.root == TR098:
        radio_enable = f"{network.path}.RadioEnabled"
        status_path = f"{network.path}.Status"
        count_path = f"{network.path}.TotalAssociations"
        associated = f"{network.path}.AssociatedDevice"
    else:
        ap = network.security_base
        radio_enable = f"{network.radio}.Enable" if network.radio else ""
        status_path = f"{network.path}.Status"
        count_path = f"{ap}.AssociatedDeviceNumberOfEntries" if ap else ""
        associated = f"{ap}.AssociatedDevice" if ap else ""
    clients = tree.integer(count_path) if count_path else None
    if clients is None and associated and tree.exists(associated):
        clients = len(tree.instances(associated))
    channel_path = f"{network.radio}.Channel" if network.radio else ""
    channel = tree.integer(channel_path) if channel_path else None
    security = _security(tree, network)
    candidates = _passphrase_candidates(network, ctx.profile) if ctx.profile else []
    passphrase_leaf = next((tree.leaf(path) for path in candidates if tree.leaf(path) is not None), None)
    return {
        "id": network.path,
        "band": network.band,
        "band_source": network.band_source,
        "band_method": network.band_method,
        "role": network.role,
        "ssid": tree.text(network.ssid_leaf, 64),
        "enabled": _enabled(tree, network),
        "radio_enabled": tree.boolean(radio_enable) if radio_enable else None,
        "status": tree.text(status_path, 64),
        "channel": channel if channel and channel > 0 else None,
        "security": security.mode,
        "security_mode": security.raw,
        "clients": clients if clients is None or clients >= 0 else None,
        # Presence and writability only, never the value (brief §3.5).
        "passphrase": {
            "present": passphrase_leaf is not None,
            "writable": passphrase_leaf.writable if passphrase_leaf else None,
        },
        "writable": {
            "ssid": ssid_leaf.writable if ssid_leaf else None,
            "passphrase": passphrase_leaf.writable if passphrase_leaf else None,
        },
        "leaves": {
            "ssid": network.ssid_leaf,
            "passphrase": passphrase_leaf.path if passphrase_leaf else (candidates[0] if candidates else None),
            "security": security.leaf,
        },
        "access_point": network.security_base if network.root == TR181 else None,
        "radio": network.radio if network.root == TR181 else None,
        "as_of": {
            "ssid": _as_of(ssid_leaf),
            "enabled": _as_of(tree.leaf(enable_paths[0])),
            "channel": _as_of(tree.leaf(channel_path)) if channel_path else None,
            "security": security.as_of,
            "clients": _as_of(tree.leaf(count_path)) if count_path else None,
        },
    }


def _connection(interface_type: str | None, ref: str | None, network: _Network | None) -> str | None:
    kind = (interface_type or "").strip().lower()
    ref = ref or ""
    if network is not None or kind in ("802.11", "wi-fi", "wifi", "wlan") or ".WLANConfiguration." in f"{ref}.":
        return "wifi"
    if ref.startswith(f"{ROOT_TR181}.WiFi."):
        return "wifi"
    if kind == "ethernet" or "LANEthernetInterfaceConfig" in ref or ref.startswith(f"{ROOT_TR181}.Ethernet."):
        return "ethernet"
    return clean_text(kind, 32) or None


def _resolve(tree: DeviceTree, value: Any, bases: Iterable[str]) -> str | None:
    """First reference that names a cached object; some firmware writes them relative."""
    for ref in normalise_ref(value):
        if tree.exists(ref):
            return ref
        for base in bases:
            if tree.exists(f"{base}.{ref}"):
                return f"{base}.{ref}"
        return ref
    return None


def _client(
    mac: str,
    ip: str | None,
    hostname: str | None,
    active: bool | None,
    connection: str | None,
    network: _Network | None,
    signal: int | None,
    as_of: str | None,
) -> dict[str, Any]:
    return {
        "mac": mac,
        "ip": _clean_ip(ip),
        "hostname": hostname or None,
        "active": active,
        "connection": connection,
        "band": network.band if network else None,
        "network": network.path if network else None,
        "signal_dbm": signal,
        "as_of": as_of,
    }


def _merge_associated(
    clients: dict[str, dict[str, Any]],
    mac: str,
    ip: str | None,
    network: _Network,
    signal: int | None,
    active: bool | None,
    as_of: str | None,
) -> None:
    existing = clients.get(mac)
    if existing is None:
        # An associated station missing from the hosts table (thin SOHO trees have none).
        clients[mac] = _client(mac, ip, None, True if active is None else active, "wifi", network, signal, as_of)
        return
    existing["connection"] = "wifi"
    if existing["network"] is None:
        existing["network"], existing["band"] = network.path, network.band
    if existing["signal_dbm"] is None:
        existing["signal_dbm"] = signal


def _clients_tr098(ctx: _Context) -> list[dict[str, Any]]:
    tree = ctx.tree
    by_path = {network.path: network for network in ctx.networks}
    clients: dict[str, dict[str, Any]] = {}
    for lan in tree.instances(f"{ROOT_TR098}.LANDevice"):
        for host in tree.instances(f"{lan}.Hosts.Host"):
            mac_leaf = tree.leaf(f"{host}.MACAddress")
            mac = _mac(mac_leaf.value if mac_leaf else None)
            if mac is None or mac in clients:
                continue
            ref = _resolve(tree, tree.value(f"{host}.Layer2Interface"), (ROOT_TR098, lan))
            network = by_path.get(ref or "")
            clients[mac] = _client(
                mac,
                tree.text(f"{host}.IPAddress", 64),
                tree.text(f"{host}.HostName", 64),
                tree.boolean(f"{host}.Active"),
                _connection(tree.text(f"{host}.InterfaceType", 32), ref, network),
                network,
                _dbm(tree.value(f"{host}.X_HW_RSSI")),
                _as_of(mac_leaf),
            )
    for network in ctx.networks:
        for station in tree.instances(f"{network.path}.AssociatedDevice"):
            mac_leaf = tree.leaf(f"{station}.AssociatedDeviceMACAddress")
            mac = _mac(mac_leaf.value if mac_leaf else None)
            if mac is None:
                continue
            _merge_associated(
                clients,
                mac,
                tree.text(f"{station}.AssociatedDeviceIPAddress", 64),
                network,
                _dbm(tree.value(f"{station}.X_HW_RSSI")),
                tree.boolean(f"{station}.AssociatedDeviceAuthenticationState"),
                _as_of(mac_leaf),
            )
    return list(clients.values())


def _clients_tr181(ctx: _Context) -> list[dict[str, Any]]:
    tree = ctx.tree
    by_path = {network.path: network for network in ctx.networks}
    stations: dict[str, tuple[str, _Network, int | None, bool | None, str | None]] = {}
    for network in ctx.networks:
        if network.security_base is None:
            continue
        for station_path in tree.instances(f"{network.security_base}.AssociatedDevice"):
            mac_leaf = tree.leaf(f"{station_path}.MACAddress")
            mac = _mac(mac_leaf.value if mac_leaf else None)
            if mac:
                signal = _dbm(tree.value(f"{station_path}.SignalStrength"))
                active = tree.boolean(f"{station_path}.Active")
                stations[station_path] = (mac, network, signal, active, _as_of(mac_leaf))
    by_mac = {entry[0]: entry for entry in stations.values()}
    clients: dict[str, dict[str, Any]] = {}
    for host in tree.instances(f"{ROOT_TR181}.Hosts.Host"):
        # PhysAddress in TR-181; a few firmwares keep the TR-098 name.
        mac_leaf = tree.leaf(f"{host}.PhysAddress") or tree.leaf(f"{host}.MACAddress")
        mac = _mac(mac_leaf.value if mac_leaf else None)
        if mac is None or mac in clients:
            continue
        ip = tree.text(f"{host}.IPAddress", 64)
        if not _clean_ip(ip):
            ip = next(
                (
                    tree.text(f"{address}.IPAddress", 64)
                    for address in tree.instances(f"{host}.IPv4Address")
                    if _clean_ip(tree.text(f"{address}.IPAddress", 64))
                ),
                None,
            )
        layer1 = _resolve(tree, tree.value(f"{host}.Layer1Interface"), ())
        station_ref = _resolve(tree, tree.value(f"{host}.AssociatedDevice"), ())
        station = stations.get(station_ref or "") or by_mac.get(mac)
        host_network = by_path.get(layer1 or "") or (station[1] if station else None)
        clients[mac] = _client(
            mac,
            ip,
            tree.text(f"{host}.HostName", 64),
            tree.boolean(f"{host}.Active"),
            _connection(tree.text(f"{host}.InterfaceType", 32), layer1, host_network),
            host_network,
            station[2] if station else None,
            _as_of(mac_leaf),
        )
    for mac, network, signal, active, as_of in stations.values():
        _merge_associated(clients, mac, None, network, signal, active, as_of)
    return list(clients.values())


def _clients(ctx: _Context) -> list[dict[str, Any]]:
    # Hosts are read from the root that carries the managed Wi-Fi, so a client's
    # band comes from the same networks the dashboard shows.
    root = ctx.wifi_root or ctx.primary
    if root == TR098:
        return _clients_tr098(ctx)
    if root == TR181 and ctx.model != MODEL_TR181_ISSUE1:
        return _clients_tr181(ctx)
    return []


def _check_inputs(now: datetime, inform_interval: int) -> datetime:
    if not isinstance(now, datetime):
        raise TypeError("now must be a datetime")
    if isinstance(inform_interval, bool) or not isinstance(inform_interval, int) or inform_interval < 1:
        raise ValidationError("inform interval must be a positive whole number of seconds")
    return now if now.tzinfo else now.replace(tzinfo=UTC)


def _primary_networks(ctx: _Context) -> list[_Network]:
    primaries = [network for network in ctx.networks if network.role == "primary"]
    return sorted(primaries, key=lambda network: BANDS.index(network.band) if network.band in BANDS else len(BANDS))


def summarize(doc: Mapping[str, Any] | DeviceTree, now: datetime, inform_interval: int) -> dict[str, Any]:
    """The device card: identity, check-in state and the primary SSID of each band.

    Reads only what SUMMARY_PROJECTION fetches.
    """
    now = _check_inputs(now, inform_interval)
    ctx = _context(doc)
    info = _info(ctx)
    checkin = _checkin(ctx, now, inform_interval)
    return {
        "acs_id": ctx.tree.id,
        "manufacturer": info["manufacturer"],
        "model": info["model"],
        "serial": info["serial"],
        "firmware": info["firmware"],
        "data_model": ctx.model,
        "profile": ctx.profile.name if ctx.profile else None,
        "online": checkin["online"],
        "last_inform": checkin["last_inform"],
        "expected_by": checkin["expected_by"],
        "inform_interval": checkin["inform_interval"],
        "tags": ctx.tree.tags,
        "wifi": [
            {
                "band": network.band,
                "band_source": network.band_source,
                "ssid": ctx.tree.text(network.ssid_leaf, 64),
                "enabled": _enabled(ctx.tree, network),
                "as_of": _as_of(ctx.tree.leaf(network.ssid_leaf)),
            }
            for network in _primary_networks(ctx)
        ],
    }


def detail(doc: Mapping[str, Any] | DeviceTree, now: datetime, inform_interval: int) -> dict[str, Any]:
    """Everything the device page shows. No value of a secret leaf is included."""
    now = _check_inputs(now, inform_interval)
    ctx = _context(doc)
    checkin = _checkin(ctx, now, inform_interval)
    return {
        "acs_id": ctx.tree.id,
        "data_model": ctx.model,
        "mixed": ctx.model == MODEL_MIXED,
        "wifi_root": ctx.wifi_root,
        "profile": ctx.profile.name if ctx.profile else None,
        "profile_notes": ctx.profile.notes if ctx.profile else None,
        "info": _info(ctx),
        "online": checkin["online"],
        "checkin": checkin,
        "wan": _wan(ctx),
        "wifi": [_wifi_entry(ctx, network) for network in ctx.networks],
        "clients": _clients(ctx),
        "tags": ctx.tree.tags,
        "refresh_scopes": sorted(_scopes(ctx)),
    }


def firmware_identity(doc: Mapping[str, Any] | DeviceTree, now: datetime, inform_interval: int) -> dict[str, Any]:
    """What a firmware upgrade is checked against: identity, running version and check-in state.

    Reads only what FIRMWARE_PROJECTION fetches. The OUI and product class come from
    the DeviceId every Inform carries, which is what GenieACS builds the device ID
    from and what a stored file's metadata is meant to match; DeviceInfo is only the
    fallback. SoftwareVersion is a forced Inform parameter, so the router reports it
    again in the Inform that follows its restart.
    """
    now = _check_inputs(now, inform_interval)
    ctx = _context(doc)
    info = _info(ctx)
    checkin = _checkin(ctx, now, inform_interval)
    tree = ctx.tree
    return {
        "acs_id": tree.id,
        "oui": tree.device_field("_OUI") or info["oui"],
        "product_class": tree.device_field("_ProductClass") or info["product_class"],
        "manufacturer": info["manufacturer"],
        "model": info["model"],
        "software_version": info["firmware"],
        "software_version_as_of": info["as_of"]["firmware"],
        "hardware_version": info["hw"],
        "online": checkin["online"],
        "last_inform": checkin["last_inform"],
        "last_boot": checkin["last_boot"],
    }


# --- refresh scopes -------------------------------------------------------------------


def _tr098_lan_paths(tree: DeviceTree | None) -> tuple[str, str]:
    lans = tree.instances(f"{ROOT_TR098}.LANDevice") if tree is not None else []
    if len(lans) == 1:
        return f"{lans[0]}.WLANConfiguration", f"{lans[0]}.Hosts"
    # Task paths take no wildcards, so without one known LANDevice the whole table
    # is refreshed; that covers Wi-Fi and hosts on every instance at once.
    table = f"{ROOT_TR098}.LANDevice"
    return table, table


def _root_scopes(root: str, tree: DeviceTree | None) -> dict[str, str]:
    if root == TR098:
        wifi, hosts = _tr098_lan_paths(tree)
        return {
            "wifi": wifi,
            "hosts": hosts,
            "wan": f"{ROOT_TR098}.WANDevice",
            "info": f"{ROOT_TR098}.DeviceInfo",
            "all": ROOT_TR098,
        }
    return {
        "wifi": f"{ROOT_TR181}.WiFi",
        "hosts": f"{ROOT_TR181}.Hosts",
        # IP.Interface carries the address and status; PPP state is refreshed with "all".
        "wan": f"{ROOT_TR181}.IP",
        "info": f"{ROOT_TR181}.DeviceInfo",
        "all": ROOT_TR181,
    }


def _scopes_for(model: str, primary: str | None, wifi_root: str | None, tree: DeviceTree | None) -> dict[str, str]:
    if model == MODEL_UNKNOWN or primary is None:
        return {}
    if model == MODEL_TR181_ISSUE1:
        return {"info": f"{ROOT_TR181}.DeviceInfo", "all": ROOT_TR181}
    scopes = _root_scopes(primary, tree)
    if wifi_root and wifi_root != primary:
        wifi_scopes = _root_scopes(wifi_root, tree)
        scopes["wifi"], scopes["hosts"] = wifi_scopes["wifi"], wifi_scopes["hosts"]
    return scopes


def _scopes(ctx: _Context) -> dict[str, str]:
    return _scopes_for(ctx.model, ctx.primary, ctx.wifi_root, ctx.tree)


def refresh_scopes(model: str, doc: Mapping[str, Any] | DeviceTree | None = None) -> dict[str, str]:
    """Scope name -> refreshObject path, for the scopes this data model has.

    Paths have no trailing dot and never are "" (the whole tree), so each passes
    tasks.validate_task. Given the device document, TR-098 paths name its one
    LANDevice and a mixed device's Wi-Fi scopes follow its vendor profile; without
    it a mixed device is treated as TR-098, the root GenieACS picks for it.
    """
    if model not in DATA_MODELS:
        raise ValidationError(f"data model must be one of {', '.join(DATA_MODELS)}")
    if doc is not None:
        ctx = _context(doc)
        if ctx.model != model:
            raise ValidationError(f"the device document is {ctx.model}, not {model}")
        return _scopes(ctx)
    primary = {MODEL_TR098: TR098, MODEL_MIXED: TR098, MODEL_TR181: TR181, MODEL_TR181_ISSUE1: TR181}.get(model)
    return _scopes_for(model, primary, primary, None)


# --- Wi-Fi write planning -------------------------------------------------------------


@dataclass(frozen=True)
class PlannedLeaf:
    path: str
    # SSID or PASSPHRASE: which caller-supplied value goes here.
    kind: str
    network: str
    band: str | None

    @property
    def placeholder(self) -> str:
        return f"<{self.kind}>"


@dataclass(frozen=True)
class WritePlan:
    """Which leaves one Wi-Fi change writes, and whether it can be written yet.

    The plan never holds a value: leaves carry placeholders, and ``values()`` fills
    them only at the moment the setParameterValues task is built.
    """

    acs_id: str | None
    data_model: str
    profile: str | None
    band: str
    readback: str = "empty"
    networks: tuple[str, ...] = ()
    leaves: tuple[PlannedLeaf, ...] = ()
    # Leaves GenieACS has not cached: a SetParameterValues would silently skip them (F15).
    missing: tuple[str, ...] = ()
    # Cached as read-only: no refresh will make the write land.
    unwritable: tuple[str, ...] = ()
    # Cached without _writable (seen only in an Inform): a refresh settles it.
    unknown_writable: tuple[str, ...] = ()
    refresh_paths: tuple[str, ...] = ()
    band_guessed: bool = False
    # Passphrase leaves that could replace the chosen ones after a 9007 or 9008 fault;
    # re-plan with avoid=<the faulted leaves> to use them.
    fallbacks: tuple[str, ...] = ()
    refusal: str | None = None

    @property
    def needs_refresh(self) -> bool:
        return self.refusal is None and bool(self.missing or self.unknown_writable)

    @property
    def ok(self) -> bool:
        return (
            self.refusal is None
            and not self.missing
            and not self.unwritable
            and not self.unknown_writable
            and bool(self.leaves)
        )

    @property
    def needs_confirmation(self) -> bool:
        """A single-band write whose band SkyRouter inferred; writing to all bands is always allowed."""
        return self.band != BAND_ALL and self.band_guessed

    @property
    def paths(self) -> tuple[str, ...]:
        return tuple(leaf.path for leaf in self.leaves)

    @property
    def secret_paths(self) -> tuple[str, ...]:
        return tuple(leaf.path for leaf in self.leaves if leaf.kind == PASSPHRASE)

    def problem(self) -> str | None:
        """Why the plan cannot be written as it stands, in words for the operator."""
        if self.refusal:
            return self.refusal
        parts = []
        if self.missing:
            parts.append("not known to the ACS yet: " + ", ".join(self.missing))
        if self.unknown_writable:
            parts.append("writability not known yet: " + ", ".join(self.unknown_writable))
        if self.unwritable:
            parts.append("read-only on this router: " + ", ".join(self.unwritable))
        if not parts and not self.leaves:
            parts.append("nothing to write")
        return "; ".join(parts) or None

    def values(self, *, ssid: str | None = None, passphrase: str | None = None) -> tuple[tuple[str, str], ...]:
        """(path, value) pairs for tasks.set_parameter_values, in plan order."""
        if not self.ok:
            raise ValidationError(f"the Wi-Fi change cannot be written: {self.problem()}")
        filled = []
        for leaf in self.leaves:
            value = ssid if leaf.kind == SSID else passphrase
            if not isinstance(value, str):
                # The message names the leaf, never a value.
                raise ValidationError(f"a {leaf.kind} is needed for {leaf.path}")
            filled.append((leaf.path, value))
        return tuple(filled)

    def to_public(self) -> dict[str, Any]:
        return {
            "acs_id": self.acs_id,
            "data_model": self.data_model,
            "profile": self.profile,
            "band": self.band,
            "readback": self.readback,
            "networks": list(self.networks),
            "leaves": [
                {
                    "path": leaf.path,
                    "kind": leaf.kind,
                    "network": leaf.network,
                    "band": leaf.band,
                    "value": leaf.placeholder,
                }
                for leaf in self.leaves
            ],
            "missing": list(self.missing),
            "unwritable": list(self.unwritable),
            "unknown_writable": list(self.unknown_writable),
            "needs_refresh": self.needs_refresh,
            "refresh_paths": list(self.refresh_paths),
            "band_guessed": self.band_guessed,
            "needs_confirmation": self.needs_confirmation,
            "fallbacks": list(self.fallbacks),
            "refusal": self.refusal,
            "ok": self.ok,
        }


def _leaf_state(tree: DeviceTree, path: str) -> str:
    leaf = tree.leaf(path)
    if leaf is None:
        return "missing"
    if leaf.writable is None:
        return "unknown"
    return "ok" if leaf.writable else "unwritable"


def _dedupe(items: list[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(items))


def _network_label(network: _Network) -> str:
    return f"{network.band} network ({network.path})" if network.band else network.path


def wifi_write_plan(
    doc: Mapping[str, Any] | DeviceTree,
    band: str,
    ssid: str | None,
    passphrase_present: bool,
    *,
    avoid: Collection[str] = (),
) -> WritePlan:
    """Resolve the leaves a Wi-Fi change writes on each targeted band (brief §3.7 step 2).

    ``band`` is one of BAND_CHOICES. ``ssid`` is the new SSID or None to leave it; the
    plan only needs to know whether one is written, and it is not kept.
    ``passphrase_present`` says whether a new passphrase is written. ``avoid`` lists
    passphrase leaves that already faulted, so a re-plan picks the profile's next one.

    Only the primary network of each band is targeted. The plan is not ``ok`` while
    a leaf is missing or its writability unknown (``needs_refresh``: refresh
    ``refresh_paths`` and plan again), while a leaf is read-only, or when the change
    is refused outright (``refusal``).
    """
    if band not in BAND_CHOICES:
        raise ValidationError(f"band must be one of {', '.join(BAND_CHOICES)}")
    if ssid is not None and not isinstance(ssid, str):
        raise ValidationError("SSID must be text")
    if not isinstance(passphrase_present, bool):
        raise ValidationError("passphrase_present must be true or false")
    if ssid is None and not passphrase_present:
        raise ValidationError("nothing to change: give a new SSID, a new passphrase, or both")
    avoided = set(avoid)
    ctx = _context(doc)
    tree = ctx.tree
    base: dict[str, Any] = {
        "acs_id": tree.id,
        "data_model": ctx.model,
        "profile": ctx.profile.name if ctx.profile else None,
        "band": band,
        "readback": ctx.profile.readback if ctx.profile else "empty",
    }
    if ctx.model == MODEL_TR181_ISSUE1:
        return WritePlan(**base, refusal="this router speaks TR-181 Issue 1, which has no Wi-Fi objects to write")
    if ctx.profile is None or ctx.wifi_root is None:
        return WritePlan(**base, refusal="the router's data model is not known yet; refresh the device first")
    profile = ctx.profile
    scope = _scopes(ctx)["wifi"]
    networks = [network for network in ctx.networks if not network.uplink]
    if not networks:
        return WritePlan(**base, missing=(scope,), refresh_paths=(scope,))
    in_band = [network for network in networks if band == BAND_ALL or network.band == band]
    targets = [network for network in in_band if network.role == "primary"]
    targets.sort(key=lambda network: BANDS.index(network.band) if network.band in BANDS else len(BANDS))
    if not targets:
        unread = [network.ssid_leaf for network in in_band if tree.value(network.ssid_leaf) is None]
        if unread:
            return WritePlan(**base, missing=tuple(unread), refresh_paths=(scope,))
        undetermined = sum(1 for network in networks if network.band is None)
        wanted = "Wi-Fi" if band == BAND_ALL else band
        reason = f"no {wanted} network with an SSID was found on this router"
        if undetermined:
            reason += f"; the band of {undetermined} network(s) could not be determined"
        return WritePlan(**base, refusal=reason)

    leaves: list[PlannedLeaf] = []
    missing: list[str] = []
    unwritable: list[str] = []
    unknown: list[str] = []
    fallbacks: list[str] = []
    refusal: str | None = None
    buckets = {"missing": missing, "unwritable": unwritable, "unknown": unknown}

    for network in targets:
        if ssid is not None:
            state = _leaf_state(tree, network.ssid_leaf)
            if state == "ok":
                leaves.append(PlannedLeaf(network.ssid_leaf, SSID, network.path, network.band))
            else:
                buckets[state].append(network.ssid_leaf)
        if not passphrase_present:
            continue
        security = _security(tree, network)
        if not security.complete:
            missing.append(security.leaf or f"{ROOT_TR181}.WiFi.AccessPoint")
        elif security.mode not in PASSPHRASE_SECURITY:
            refusal = refusal or (
                f"the {_network_label(network)} uses {security.raw or security.mode} security, which has no "
                "passphrase to change; set up WPA2 or WPA3 on the router first"
            )
            continue
        candidates = [path for path in _passphrase_candidates(network, profile) if path not in avoided]
        if network.security_base is None:
            continue
        if not candidates:
            refusal = refusal or f"every passphrase leaf known for {network.path} has already been tried"
            continue
        chosen = None
        for index, path in enumerate(candidates):
            state = _leaf_state(tree, path)
            if state == "ok":
                chosen = path
                fallbacks += [later for later in candidates[index + 1 :] if _leaf_state(tree, later) == "ok"]
                break
            if state == "unknown":
                # The profile prefers this leaf; learn whether it is writable before
                # settling for a later one.
                unknown.append(path)
                break
        else:
            states = {path: _leaf_state(tree, path) for path in candidates}
            unwritable += [path for path, state in states.items() if state == "unwritable"]
            missing += [path for path, state in states.items() if state == "missing"]
        if chosen:
            leaves.append(PlannedLeaf(chosen, PASSPHRASE, network.path, network.band))
        if profile.sae_leaf and security.mode in _SAE_SECURITY:
            sae = f"{network.security_base}.{profile.sae_leaf}"
            sae_state = _leaf_state(tree, sae)
            if sae not in avoided and sae_state == "ok":
                leaves.append(PlannedLeaf(sae, PASSPHRASE, network.path, network.band))
            elif sae not in avoided and sae_state == "unknown":
                unknown.append(sae)
            # Absent or read-only: WPA3 routers without a writable SAE leaf derive the
            # SAE password from KeyPassphrase.

    missing_t = _dedupe(missing)
    unknown_t = _dedupe(unknown)
    return WritePlan(
        **base,
        networks=tuple(network.path for network in targets),
        leaves=tuple(leaves),
        missing=missing_t,
        unwritable=_dedupe(unwritable),
        unknown_writable=unknown_t,
        refresh_paths=(scope,) if (missing_t or unknown_t) and refusal is None else (),
        band_guessed=any(network.band_source == "guessed" for network in targets),
        fallbacks=_dedupe(fallbacks),
        refusal=refusal,
    )
