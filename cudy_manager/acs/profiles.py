"""Vendor profiles: where each router family keeps its Wi-Fi passphrase and band.

The standards leave both open. TR-098 has no band parameter at all (F28), and the
passphrase leaf that works differs by vendor: Huawei and TP-Link answer a write to
WLANConfiguration.{i}.KeyPassphrase with fault 9007, ZTE firmware accepts it. Every
entry here is COMMUNITY-sourced [I] and is confirmed per fleet model from
`router-manager acs dump` output before it is trusted.

Leaf paths are relative: to the WLANConfiguration.{i} object for TR-098, and to
the Device.WiFi.AccessPoint.{i} object for TR-181.
"""

import re
from dataclasses import dataclass, field

from ..models import ValidationError
from .tasks import PATH_RE

TR098 = "tr098"
TR181 = "tr181"

# Where a network's band can come from, and whether the router itself said so.
# "reported" sources are the router naming the band; the rest are inferences, and
# a single-band write on an inferred band needs explicit confirmation in the UI.
REPORTED_BAND_SOURCES = frozenset({"lowerlayers", "X_HW_RFBand", "X_TP_Band"})
GUESSED_BAND_SOURCES = frozenset({"channel", "standard", "single_radio", "index_1_5", "index_1_2"})
BAND_SOURCES = REPORTED_BAND_SOURCES | GUESSED_BAND_SOURCES
# Instance conventions only mean something for TR-098; TR-181 numbers SSIDs,
# access points and radios independently (the Cudy fixture has SSID.1 on Radio.2).
_TR098_ONLY_SOURCES = frozenset({"X_HW_RFBand", "X_TP_Band", "index_1_5", "index_1_2"})
_TR181_ONLY_SOURCES = frozenset({"single_radio"})

# "empty" follows the spec (F27). "plaintext" routers expose the key when read, so a
# write can be verified; "masked" ones return a placeholder such as "********".
READBACK_MODES = frozenset({"empty", "plaintext", "masked"})


@dataclass(frozen=True)
class Profile:
    name: str
    data_model: str
    passphrase_leaves: tuple[str, ...]
    band_source: tuple[str, ...]
    # Regular expressions matched case-insensitively against DeviceInfo.Manufacturer
    # and ModelName; None matches anything, which makes the profile a generic one.
    manufacturer: str | None = None
    model: str | None = None
    # TR-181 only: written alongside the passphrase when the network runs WPA3.
    sae_leaf: str | None = None
    readback: str = "empty"
    notes: str = ""
    _manufacturer_re: re.Pattern[str] | None = field(default=None, init=False, repr=False, compare=False)
    _model_re: re.Pattern[str] | None = field(default=None, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.manufacturer is not None:
            object.__setattr__(self, "_manufacturer_re", re.compile(self.manufacturer, re.IGNORECASE))
        if self.model is not None:
            object.__setattr__(self, "_model_re", re.compile(self.model, re.IGNORECASE))

    @property
    def generic(self) -> bool:
        return self.manufacturer is None and self.model is None

    def matches(self, manufacturer: str, model_name: str) -> bool:
        if self._manufacturer_re is not None and not self._manufacturer_re.search(manufacturer or ""):
            return False
        return self._model_re is None or bool(self._model_re.search(model_name or ""))

    def to_public(self) -> dict[str, object]:
        return {
            "name": self.name,
            "data_model": self.data_model,
            "passphrase_leaves": list(self.passphrase_leaves),
            "sae_leaf": self.sae_leaf,
            "band_source": list(self.band_source),
            "readback": self.readback,
            "notes": self.notes,
        }


PROFILES: tuple[Profile, ...] = (
    Profile(
        name="cudy-tr181",
        data_model=TR181,
        manufacturer=r"\bcudy\b",
        passphrase_leaves=("Security.KeyPassphrase",),
        sae_leaf="Security.SAEPassphrase",
        band_source=("lowerlayers", "channel", "standard", "single_radio"),
        notes=(
            "Cudy routers expose System > TR069 with a selectable data model; the fleet standardises on "
            "TR-181 so one path set covers Cudy, newer TP-Link and ZTE. Instance numbers of SSID, "
            "AccessPoint and Radio do not line up, so bands always come from the reference chain."
        ),
    ),
    Profile(
        name="tplink-tr098",
        data_model=TR098,
        manufacturer=r"tp-?link",
        # X_TP_PreSharedKey is a passphrase despite its name; the TR-098 hex
        # PreSharedKey.{i}.PreSharedKey is never written.
        passphrase_leaves=("X_TP_PreSharedKey", "PreSharedKey.1.KeyPassphrase"),
        band_source=("X_TP_Band", "channel", "standard", "index_1_2"),
        notes=(
            "Older SOHO and xPON TP-Link firmware: TR-098 with X_TP_ extensions. The top-level KeyPassphrase "
            "answers 9007. X_TP_PreSharedKey may read back in plaintext; SOHO firmware often has no Hosts table."
        ),
    ),
    Profile(
        name="huawei-tr098",
        data_model=TR098,
        manufacturer=r"huawei",
        passphrase_leaves=("PreSharedKey.1.KeyPassphrase",),
        band_source=("X_HW_RFBand", "lowerlayers", "channel", "standard", "index_1_5"),
        notes=(
            "EchoLife/OptiXstar ONTs: WLANConfiguration.1-4 are 2.4 GHz and 5-8 are 5 GHz on most firmware, "
            "but Wi-Fi 7 units break that, so X_HW_RFBand wins when present. The top-level KeyPassphrase "
            "answers 9007."
        ),
    ),
    Profile(
        name="zte-tr098",
        data_model=TR098,
        manufacturer=r"\bzte\b",
        passphrase_leaves=("KeyPassphrase", "PreSharedKey.1.KeyPassphrase"),
        band_source=("channel", "standard", "index_1_5"),
        notes="ZTE F6xx ONTs: 2.4 GHz on WLANConfiguration.1, 5 GHz on .5; the top-level KeyPassphrase is accepted.",
    ),
    Profile(
        name="generic-tr181",
        data_model=TR181,
        passphrase_leaves=("Security.KeyPassphrase",),
        sae_leaf="Security.SAEPassphrase",
        band_source=("lowerlayers", "channel", "standard", "single_radio"),
        notes="TR-181 Issue 2 as the Broadband Forum defines it.",
    ),
    Profile(
        name="generic-tr098",
        data_model=TR098,
        # The spec describes the top-level KeyPassphrase in WEP terms and as a mirror
        # of PreSharedKey.1.KeyPassphrase, so the latter goes first.
        passphrase_leaves=("PreSharedKey.1.KeyPassphrase", "KeyPassphrase"),
        band_source=("X_HW_RFBand", "X_TP_Band", "lowerlayers", "channel", "standard", "index_1_2"),
        notes="TR-098 with no vendor profile; band numbering is a guess until the model is profiled.",
    ),
)

PROFILES_BY_NAME = {profile.name: profile for profile in PROFILES}


def _check_profiles(profiles: tuple[Profile, ...]) -> None:
    """Refuse at import a profile that could make SkyRouter write the wrong leaf."""
    names = [profile.name for profile in profiles]
    if len(set(names)) != len(names):
        raise ValueError("vendor profile names must be unique")
    for model in (TR098, TR181):
        if not any(profile.generic and profile.data_model == model for profile in profiles):
            raise ValueError(f"no generic profile for {model}")
    for profile in profiles:
        if profile.data_model not in (TR098, TR181):
            raise ValueError(f"{profile.name}: unknown data model {profile.data_model!r}")
        if profile.readback not in READBACK_MODES:
            raise ValueError(f"{profile.name}: unknown readback {profile.readback!r}")
        if not profile.passphrase_leaves or not profile.band_source:
            raise ValueError(f"{profile.name}: needs passphrase leaves and band sources")
        wrong = _TR181_ONLY_SOURCES if profile.data_model == TR098 else _TR098_ONLY_SOURCES
        for source in profile.band_source:
            if source not in BAND_SOURCES or source in wrong:
                raise ValueError(f"{profile.name}: band source {source!r} does not apply to {profile.data_model}")
        leaves = profile.passphrase_leaves + ((profile.sae_leaf,) if profile.sae_leaf else ())
        for leaf in leaves:
            if not PATH_RE.fullmatch(leaf):
                raise ValueError(f"{profile.name}: {leaf!r} is not a relative parameter path")
            # A hex PSK leaf next to a passphrase leaf is undefined behaviour in the
            # spec, and phase 1 never sends a hex key at all.
            if leaf.rsplit(".", 1)[-1] == "PreSharedKey":
                raise ValueError(f"{profile.name}: {leaf!r} holds a hex key, not a passphrase")
        if profile.sae_leaf and profile.data_model != TR181:
            raise ValueError(f"{profile.name}: SAEPassphrase only exists in TR-181")


_check_profiles(PROFILES)


def get_profile(name: str) -> Profile:
    try:
        return PROFILES_BY_NAME[name]
    except KeyError:
        raise ValidationError(f"unknown vendor profile {name!r}") from None


def select_profile(
    data_model: str, manufacturer: str = "", model_name: str = "", *, prefer: str = TR098
) -> Profile | None:
    """The profile for a device, or None when its data model has no Wi-Fi to manage.

    ``data_model`` is what params.detect_model returned. A "mixed" device (both roots
    carry Wi-Fi objects) takes a vendor profile of either model, preferring the
    ``prefer`` root, and otherwise the generic profile of ``prefer``: the root that
    holds the connection-request URL, which is the one GenieACS itself uses.
    """
    if data_model in (TR098, TR181):
        roots = [data_model]
    elif data_model == "mixed":
        if prefer not in (TR098, TR181):
            raise ValidationError("prefer must be tr098 or tr181")
        roots = [prefer, TR181 if prefer == TR098 else TR098]
    else:
        return None
    for root in roots:
        for profile in PROFILES:
            if profile.data_model == root and not profile.generic and profile.matches(manufacturer, model_name):
                return profile
    for profile in PROFILES:
        if profile.data_model == roots[0] and profile.generic:
            return profile
    return None
