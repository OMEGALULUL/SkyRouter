"""Data-model detection, normalisation, write planning and redaction over GenieACS documents.

The fixtures in tests/fixtures/acs/ are constructed, not captured. Every secret leaf
that holds a value there carries the marker "zz-secret", and no output may contain it.
"""

import copy
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from cudy_manager.acs import params, profiles, tasks
from cudy_manager.acs.tree import DeviceTree, instance_key, normalise_ref, parse_time
from cudy_manager.models import ValidationError

FIXTURES = Path(__file__).parent / "fixtures" / "acs"
FIXTURE_NAMES = ("tr098_sim", "tr098_huawei_1_5", "tr098_tplink_xtp", "tr181_cudy", "tr181_issue1", "dual_root")
MARKER = "zz-secret"
LAST_INFORM = datetime(2026, 9, 28, 9, 15, 2, 311000, tzinfo=UTC)
NOW = LAST_INFORM + timedelta(minutes=3)
TS = "2026-09-28T09:00:00.000Z"

IGD_WLAN = "InternetGatewayDevice.LANDevice.1.WLANConfiguration"
WIFI = "Device.WiFi"


def load(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def node_at(doc: dict[str, Any], path: str) -> dict[str, Any]:
    node = doc
    for part in path.split("."):
        node = node[part]
    return node


def set_leaf(doc: dict[str, Any], path: str, value: Any, writable: bool | None = True) -> None:
    node = doc
    for part in path.split(".")[:-1]:
        node = node.setdefault(part, {"_object": True, "_writable": False, "_timestamp": TS})
    leaf = {"_object": False, "_timestamp": TS, "_type": "xsd:string", "_value": value}
    if writable is not None:
        leaf["_writable"] = writable
    node[path.rsplit(".", 1)[-1]] = leaf


def drop(doc: dict[str, Any], path: str) -> None:
    parent, _, name = path.rpartition(".")
    del node_at(doc, parent)[name]


def project(doc: dict[str, Any], paths: tuple[str, ...]) -> dict[str, Any]:
    """What the NBI returns for a projection: only the named subtrees, plus _id (F8)."""
    out: dict[str, Any] = {"_id": doc["_id"]}
    for path in paths:
        parts = path.split(".")
        source: Any = doc
        for part in parts:
            if not isinstance(source, dict) or part not in source:
                source = None
                break
            source = source[part]
        if source is None:
            continue
        target = out
        for part in parts[:-1]:
            target = target.setdefault(part, {})
        target[parts[-1]] = copy.deepcopy(source)
    return out


def wifi_by_id(detail: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {entry["id"]: entry for entry in detail["wifi"]}


def clients_by_mac(detail: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {entry["mac"]: entry for entry in detail["clients"]}


# --- tree ------------------------------------------------------------------------------


def test_tree_reads_leaves_objects_and_instances_in_numeric_order():
    tree = DeviceTree(load("tr098_sim"))
    hosts = tree.instances("InternetGatewayDevice.LANDevice.1.Hosts.Host")
    assert [path.rsplit(".", 1)[-1] for path in hosts] == ["1", "2", "3", "10"]
    leaf = tree.leaf(f"{IGD_WLAN}.1.SSID")
    assert leaf is not None and leaf.value == "Skybre-Sim" and leaf.writable is True
    assert leaf.as_of == "2026-09-28T08:30:00.000Z"
    # Leaves that only arrived in an Inform have no _writable yet.
    assert tree.leaf("InternetGatewayDevice.DeviceInfo.SoftwareVersion").writable is None
    assert tree.leaf(IGD_WLAN) is None and tree.is_object(IGD_WLAN)
    assert tree.leaf("InternetGatewayDevice.Nope.Missing") is None
    assert tree.node(f"{IGD_WLAN}.1.SSID._value") is None
    assert tree.integer("InternetGatewayDevice.DeviceInfo.UpTime") == 213138
    assert tree.boolean(f"{IGD_WLAN}.1.Enable") is True


def test_leaf_repr_never_shows_the_value():
    tree = DeviceTree(load("tr098_sim"))
    leaf = tree.leaf(f"{IGD_WLAN}.1.KeyPassphrase")
    assert leaf is not None and MARKER in leaf.value
    assert MARKER not in repr(leaf)


def test_references_lose_trailing_dots_and_split_on_commas():
    assert normalise_ref("Device.WiFi.Radio.1.") == ["Device.WiFi.Radio.1"]
    radios = ["Device.WiFi.Radio.1", "Device.WiFi.Radio.2"]
    assert normalise_ref(" Device.WiFi.Radio.1., Device.WiFi.Radio.2 ") == radios
    assert normalise_ref("") == [] and normalise_ref(None) == []
    assert instance_key("Device.WiFi.SSID.10") > instance_key("Device.WiFi.SSID.2")
    assert parse_time("2026-09-28T09:15:02.311Z") == LAST_INFORM
    assert parse_time("not a date") is None


def test_router_text_loses_control_characters():
    doc = load("tr181_cudy")
    set_leaf(doc, f"{WIFI}.SSID.1.SSID", "Evil\x1b[2J\u202eNet")
    ssid = wifi_by_id(params.detail(doc, NOW, 300))[f"{WIFI}.SSID.1"]["ssid"]
    assert ssid == "Evil [2J Net"


# --- data-model detection ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "model"),
    [
        ("tr098_sim", "tr098"),
        ("tr098_huawei_1_5", "tr098"),
        ("tr098_tplink_xtp", "tr098"),
        ("tr181_cudy", "tr181"),
        ("tr181_issue1", "tr181-issue1"),
        ("dual_root", "mixed"),
    ],
)
def test_detect_model_on_fixtures(name, model):
    assert params.detect_model(load(name)) == model


def test_detect_model_on_partial_documents():
    assert params.detect_model({"_id": "x"}) == "unknown"
    base = {"_id": "x", "Device": {"_object": True}}
    version = copy.deepcopy(base)
    set_leaf(version, "Device.RootDataModelVersion", "2.11", None)
    assert params.detect_model(version) == "tr181"
    summary = copy.deepcopy(base)
    set_leaf(summary, "Device.DeviceSummary", "Device:1.0[](Baseline:1)", None)
    assert params.detect_model(summary) == "tr181-issue1"
    # Nothing tells the issues apart: the common case, and writes still need Wi-Fi objects.
    assert params.detect_model(base) == "tr181"
    assert params.detect_model({"_id": "x", "InternetGatewayDevice": {"_object": True}}) == "tr098"
    # The connection-request URL wins over a stray Device root without Wi-Fi.
    both = load("tr098_sim")
    set_leaf(both, "Device.DeviceInfo.SoftwareVersion", "1", None)
    assert params.detect_model(both) == "tr098"


# --- profiles --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "profile"),
    [
        ("tr098_sim", "huawei-tr098"),
        ("tr098_huawei_1_5", "huawei-tr098"),
        ("tr098_tplink_xtp", "tplink-tr098"),
        ("tr181_cudy", "cudy-tr181"),
        ("tr181_issue1", None),
        ("dual_root", "huawei-tr098"),
    ],
)
def test_profile_selection_on_fixtures(name, profile):
    assert params.detail(load(name), NOW, 300)["profile"] == profile


def test_generic_profiles_and_mixed_preference():
    assert profiles.select_profile("tr098", "Acme", "X1").name == "generic-tr098"
    assert profiles.select_profile("tr181", "TP-Link", "EC220-G5").name == "generic-tr181"
    assert profiles.select_profile("tr181", "CUDY Technology", "WR3000").name == "cudy-tr181"
    assert profiles.select_profile("tr098", "ZTE Corporation", "F660").name == "zte-tr098"
    assert profiles.select_profile("tr181-issue1", "Cudy", "WR3000") is None
    assert profiles.select_profile("unknown") is None
    # A mixed device takes a vendor profile of either root, else the generic one of the preferred root.
    assert profiles.select_profile("mixed", "Cudy", "", prefer="tr098").name == "cudy-tr181"
    assert profiles.select_profile("mixed", "Acme", "", prefer="tr181").name == "generic-tr181"
    with pytest.raises(ValidationError):
        profiles.select_profile("mixed", "Acme", "", prefer="nope")


def test_profiles_never_write_a_hex_key_and_all_leaves_are_paths():
    for profile in profiles.PROFILES:
        for leaf in (*profile.passphrase_leaves, *((profile.sae_leaf,) if profile.sae_leaf else ())):
            assert tasks.PATH_RE.fullmatch(leaf)
            assert leaf.rsplit(".", 1)[-1] != "PreSharedKey"
        assert set(profile.band_source) <= profiles.BAND_SOURCES
    assert profiles.get_profile("cudy-tr181").data_model == "tr181"
    with pytest.raises(ValidationError):
        profiles.get_profile("nope")


def test_profile_registry_refuses_a_hex_psk_leaf():
    bad = profiles.Profile("bad", "tr098", ("PreSharedKey.1.PreSharedKey",), ("channel",))
    with pytest.raises(ValueError, match="hex key"):
        profiles._check_profiles((*profiles.PROFILES, bad))
    wrong_source = profiles.Profile("bad2", "tr181", ("Security.KeyPassphrase",), ("index_1_5",))
    with pytest.raises(ValueError, match="does not apply"):
        profiles._check_profiles((*profiles.PROFILES, wrong_source))


# --- bands and roles -------------------------------------------------------------------------


def test_tr181_band_follows_the_reference_chain_not_instance_numbers():
    wifi = wifi_by_id(params.detail(load("tr181_cudy"), NOW, 300))
    first, second, guest = wifi[f"{WIFI}.SSID.1"], wifi[f"{WIFI}.SSID.2"], wifi[f"{WIFI}.SSID.3"]
    # SSID.1 -> Radio.2 (2.4 GHz), served by AccessPoint.2; trailing dots throughout.
    assert (first["band"], first["band_source"], first["band_method"]) == ("2.4GHz", "reported", "lowerlayers")
    assert first["access_point"] == f"{WIFI}.AccessPoint.2" and first["radio"] == f"{WIFI}.Radio.2"
    assert first["security"] == "wpa3-transition" and first["channel"] == 6 and first["clients"] == 1
    assert (second["band"], second["access_point"], second["security"]) == ("5GHz", f"{WIFI}.AccessPoint.1", "wpa2")
    assert first["role"] == second["role"] == "primary"
    assert guest["role"] == "secondary" and guest["enabled"] is False


def test_tr098_band_sources_in_profile_order():
    huawei = wifi_by_id(params.detail(load("tr098_huawei_1_5"), NOW, 300))
    assert [(w["band"], w["band_source"], w["role"]) for w in huawei.values()] == [
        ("2.4GHz", "reported", "primary"),
        # An empty SSID is a disabled slot, never the primary network.
        ("2.4GHz", "reported", "secondary"),
        ("5GHz", "reported", "primary"),
        ("5GHz", "reported", "secondary"),
    ]
    tplink = wifi_by_id(params.detail(load("tr098_tplink_xtp"), NOW, 300))
    assert [(w["band"], w["band_method"]) for w in tplink.values()] == [("2.4GHz", "X_TP_Band"), ("5GHz", "X_TP_Band")]
    sim = wifi_by_id(params.detail(load("tr098_sim"), NOW, 300))
    assert [(w["band"], w["band_source"], w["band_method"]) for w in sim.values()] == [
        ("2.4GHz", "guessed", "channel"),
        ("5GHz", "guessed", "channel"),
    ]


def test_tr098_band_falls_back_to_channels_standard_then_instance_convention():
    doc = load("tr098_huawei_1_5")
    for n in (1, 2, 5, 6):
        drop(doc, f"{IGD_WLAN}.{n}.X_HW_RFBand")
    wifi = wifi_by_id(params.detail(doc, NOW, 300))
    assert (wifi[f"{IGD_WLAN}.1"]["band"], wifi[f"{IGD_WLAN}.1"]["band_method"]) == ("2.4GHz", "channel")
    # .2 has no channel; X_HW_Standard "11bgnax" still says 2.4 GHz.
    assert (wifi[f"{IGD_WLAN}.2"]["band"], wifi[f"{IGD_WLAN}.2"]["band_method"]) == ("2.4GHz", "standard")
    for n in (1, 2, 5, 6):
        for name in ("Channel", "X_HW_Standard"):
            if name in node_at(doc, f"{IGD_WLAN}.{n}"):
                drop(doc, f"{IGD_WLAN}.{n}.{name}")
    wifi = wifi_by_id(params.detail(doc, NOW, 300))
    assert [(w["band"], w["band_source"], w["band_method"]) for w in wifi.values()] == [
        ("2.4GHz", "guessed", "index_1_5"),
        ("2.4GHz", "guessed", "index_1_5"),
        ("5GHz", "guessed", "index_1_5"),
        ("5GHz", "guessed", "index_1_5"),
    ]


def test_tr098_hybrid_lowerlayers_is_a_reported_band():
    doc = load("tr098_huawei_1_5")
    drop(doc, f"{IGD_WLAN}.1.X_HW_RFBand")
    set_leaf(doc, f"{IGD_WLAN}.1.LowerLayers", "InternetGatewayDevice.LANDevice.1.WiFi.Radio.1", False)
    set_leaf(doc, "InternetGatewayDevice.LANDevice.1.WiFi.Radio.1.OperatingFrequencyBand", "5GHz", False)
    entry = wifi_by_id(params.detail(doc, NOW, 300))[f"{IGD_WLAN}.1"]
    assert (entry["band"], entry["band_source"], entry["band_method"]) == ("5GHz", "reported", "lowerlayers")


def test_tr181_band_fallbacks():
    doc = load("tr181_cudy")
    # One supported band is as good as the operating band.
    set_leaf(doc, f"{WIFI}.Radio.1.OperatingFrequencyBand", "", True)
    assert wifi_by_id(params.detail(doc, NOW, 300))[f"{WIFI}.SSID.2"]["band_source"] == "reported"
    # A dual-band list says nothing; the channel is then a guess.
    set_leaf(doc, f"{WIFI}.Radio.1.SupportedFrequencyBands", "2.4GHz,5GHz", False)
    entry = wifi_by_id(params.detail(doc, NOW, 300))[f"{WIFI}.SSID.2"]
    assert (entry["band"], entry["band_source"], entry["band_method"]) == ("5GHz", "guessed", "channel")


def test_tr181_single_radio_is_a_guess_when_lowerlayers_is_missing():
    doc = load("tr181_cudy")
    drop(doc, f"{WIFI}.Radio.1")
    for n in (1, 2, 3):
        drop(doc, f"{WIFI}.SSID.{n}.LowerLayers")
    wifi = wifi_by_id(params.detail(doc, NOW, 300))
    assert {(w["band"], w["band_source"], w["band_method"]) for w in wifi.values()} == {
        ("2.4GHz", "guessed", "single_radio")
    }


def test_tr181_endpoint_ssid_is_an_uplink_and_never_targeted():
    doc = load("tr181_cudy")
    set_leaf(doc, f"{WIFI}.SSID.4.SSID", "UpstreamISP")
    set_leaf(doc, f"{WIFI}.SSID.4.LowerLayers", f"{WIFI}.Radio.2.", False)
    set_leaf(doc, f"{WIFI}.EndPoint.1.SSIDReference", f"{WIFI}.SSID.4.", False)
    entry = wifi_by_id(params.detail(doc, NOW, 300))[f"{WIFI}.SSID.4"]
    assert entry["role"] == "uplink" and entry["band"] == "2.4GHz"
    plan = params.wifi_write_plan(doc, "all", "x", False)
    assert f"{WIFI}.SSID.4.SSID" not in plan.paths


@pytest.mark.parametrize(
    ("value", "band"),
    [
        ("2.4GHz", "2.4GHz"),
        ("2.4G", "2.4GHz"),
        ("24G", "2.4GHz"),
        ("5GHz", "5GHz"),
        ("5G", "5GHz"),
        ("5.8GHz", "5GHz"),
        ("6GHz", "6GHz"),
        ("6E", "6GHz"),
        ("2.4", "2.4GHz"),
        # A bare digit could be a vendor enum code.
        ("2", None),
        ("5", None),
        ("2.4GHz,5GHz", None),
        ("dual", None),
        (5, None),
    ],
)
def test_parse_band(value, band):
    assert params.parse_band(value) == band


@pytest.mark.parametrize(
    ("value", "band"),
    [(6, "2.4GHz"), ("1-13", "2.4GHz"), ("36,40,44,48", "5GHz"), (149, "5GHz"), (0, None), ("1-11,36-165", None)],
)
def test_band_from_channels(value, band):
    assert params.band_from_channels(value) == band


@pytest.mark.parametrize(
    ("value", "band"),
    [
        ("b/g/n", "2.4GHz"),
        ("11bgnax", "2.4GHz"),
        ("g-only", "2.4GHz"),
        ("a,n,ac,ax", "5GHz"),
        ("11anacax", "5GHz"),
        ("802.11ac", "5GHz"),
        ("n", None),
        ("11be", None),
        ("a,b,g,n", None),
    ],
)
def test_band_from_standard(value, band):
    assert params.band_from_standard(value) == band


# --- security ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "mode"),
    [
        ("None", "open"),
        ("OWE", "open"),
        ("WEP-64", "wep"),
        ("WPA-Personal", "wpa"),
        ("WPA2-Personal", "wpa2"),
        ("WPA-WPA2-Personal", "wpa-wpa2"),
        ("WPA3-Personal", "wpa3"),
        ("WPA3-Personal-Transition", "wpa3-transition"),
        ("WPA3-Personal-Compatibility", "wpa3-transition"),
        ("WPA2-Enterprise", "unknown"),
        ("WPAWPA2", "wpa-wpa2"),
        ("WPA2/WPA3", "wpa3-transition"),
        ("11i", "wpa2"),
        ("mystery", None),
    ],
)
def test_normalise_security_mode(value, mode):
    assert params.normalise_security_mode(value) == mode


@pytest.mark.parametrize(
    ("leaves", "mode"),
    [
        ({"BeaconType": "Basic", "BasicEncryptionModes": "None"}, "open"),
        ({"BeaconType": "Basic", "BasicEncryptionModes": "WEPEncryption"}, "wep"),
        ({"BeaconType": "WPA", "WPAAuthenticationMode": "PSKAuthentication"}, "wpa"),
        ({"BeaconType": "11i", "IEEE11iAuthenticationMode": "PSKAuthentication"}, "wpa2"),
        ({"BeaconType": "11i", "IEEE11iAuthenticationMode": "EAPAuthentication"}, "unknown"),
        ({"BeaconType": "11i", "IEEE11iAuthenticationMode": "SAEAuthentication"}, "wpa3"),
        ({"BeaconType": "WPAand11i", "IEEE11iAuthenticationMode": "PSKandSAEAuthentication"}, "wpa3-transition"),
        ({"BeaconType": "WPAand11i"}, "wpa-wpa2"),
        ({"BeaconType": "None"}, "unknown"),
    ],
)
def test_tr098_security_combinations(leaves, mode):
    doc = load("tr098_tplink_xtp")
    wlan = node_at(doc, f"{IGD_WLAN}.1")
    for name in ("BeaconType", "IEEE11iAuthenticationMode", "WPAAuthenticationMode", "BasicEncryptionModes"):
        wlan.pop(name, None)
    for name, value in leaves.items():
        set_leaf(doc, f"{IGD_WLAN}.1.{name}", value)
    assert wifi_by_id(params.detail(doc, NOW, 300))[f"{IGD_WLAN}.1"]["security"] == mode


# --- info, check-in, WAN, clients ---------------------------------------------------------


def test_info_fields_and_fallbacks():
    info = params.detail(load("tr181_cudy"), NOW, 300)["info"]
    assert {key: info[key] for key in ("model", "serial", "firmware", "hw", "uptime", "data_model")} == {
        "model": "WR3000",
        "serial": "CU24A0001234",
        "firmware": "2.3.5-20240418-165412",
        "hw": "1.0",
        "uptime": 172800,
        "data_model": "tr181",
    }
    assert info["as_of"]["firmware"] == TS
    doc = load("tr098_tplink_xtp")
    drop(doc, "InternetGatewayDevice.DeviceInfo.ModelName")
    drop(doc, "InternetGatewayDevice.DeviceInfo.SerialNumber")
    info = params.detail(doc, NOW, 300)["info"]
    # The serial comes from the Inform's DeviceId; the junk ProductClass is the last resort for the model.
    assert info["serial"] == "2219876543210" and info["model"] == "IGD"


def test_online_uses_the_router_interval_and_falls_back_to_the_configured_one():
    doc = load("tr181_cudy")
    assert params.summarize(doc, NOW, 3600)["online"] is True
    late = LAST_INFORM + timedelta(seconds=2 * 300 + 61)
    checkin = params.detail(doc, late, 3600)["checkin"]
    assert checkin["online"] is False and checkin["interval_source"] == "device"
    assert checkin["expected_by"] == "2026-09-28T09:20:02.311Z"
    node_at(doc, "Device.ManagementServer")["PeriodicInformEnable"]["_value"] = False
    checkin = params.detail(doc, late, 3600)["checkin"]
    assert checkin["online"] is True and checkin["interval_source"] == "configured"
    del doc["_lastInform"]
    assert params.summarize(doc, NOW, 300)["online"] is None
    with pytest.raises(ValidationError):
        params.summarize(doc, NOW, 0)


def test_wan_selection():
    sim = params.detail(load("tr098_sim"), NOW, 300)["wan"]
    # DefaultConnectionService is empty, so the connected Internet-labelled WAN is used.
    assert (sim["ip"], sim["type"], sim["uptime"]) == ("100.64.12.34", "ip", 62703)
    assert sim["selected_by"] == "internet_service"
    huawei = params.detail(load("tr098_huawei_1_5"), NOW, 300)["wan"]
    # The Internet PPPoE link, not the TR-069 management WAN next to it.
    assert (huawei["ip"], huawei["type"], huawei["selected_by"]) == ("41.193.10.20", "ppp", "DefaultConnectionService")
    tplink = params.detail(load("tr098_tplink_xtp"), NOW, 300)["wan"]
    assert (tplink["ip"], tplink["selected_by"]) == ("100.72.5.9", "DefaultConnectionService")
    cudy = params.detail(load("tr181_cudy"), NOW, 300)["wan"]
    # The default route is the second forwarding entry; the live address is the DHCP instance.
    assert (cudy["ip"], cudy["path"], cudy["selected_by"], cudy["connected"], cudy["uptime"]) == (
        "100.64.3.20",
        "Device.IP.Interface.1",
        "default_route",
        True,
        5400,
    )
    assert params.detail(load("tr181_issue1"), NOW, 300)["wan"]["ip"] is None


def test_tr181_wan_over_ppp():
    doc = load("tr181_cudy")
    set_leaf(doc, "Device.IP.Interface.1.LowerLayers", "Device.PPP.Interface.1.", False)
    set_leaf(doc, "Device.PPP.Interface.1.ConnectionStatus", "Connected", False)
    set_leaf(doc, "Device.PPP.Interface.1.LastChange", 900, False)
    wan = params.detail(doc, NOW, 300)["wan"]
    assert (wan["type"], wan["status"], wan["connected"], wan["uptime"]) == ("ppp", "Connected", True, 900)


def test_clients_normalise_macaddress_and_physaddress():
    sim = clients_by_mac(params.detail(load("tr098_sim"), NOW, 300))
    assert list(sim) == ["40:b0:fa:9c:4a:50", "10:68:3f:77:88:20", "c0:14:3d:c0:cf:93", "c0:9f:42:56:33:df"]
    assert (sim["40:b0:fa:9c:4a:50"]["connection"], sim["40:b0:fa:9c:4a:50"]["band"]) == ("wifi", "2.4GHz")
    assert sim["10:68:3f:77:88:20"]["connection"] == "ethernet"
    assert sim["c0:14:3d:c0:cf:93"]["active"] is False
    cudy = clients_by_mac(params.detail(load("tr181_cudy"), NOW, 300))
    phone = cudy["5c:e9:1e:aa:bb:cc"]
    assert (phone["hostname"], phone["band"], phone["signal_dbm"]) == ("pixel-7", "2.4GHz", -48)
    assert phone["connection"] == "wifi"
    assert cudy["00:11:32:ab:cd:ef"]["connection"] == "ethernet"
    # IPAddress is empty, so the IPv4Address table is used.
    assert cudy["7a:11:22:33:44:55"]["ip"] == "192.168.10.40" and cudy["7a:11:22:33:44:55"]["band"] == "5GHz"
    huawei = clients_by_mac(params.detail(load("tr098_huawei_1_5"), NOW, 300))
    assert huawei["a4:5e:60:11:22:33"]["signal_dbm"] == -61
    assert "00:1a:2b:3c:4d:5e" in huawei


def test_clients_come_from_associated_devices_when_there_is_no_hosts_table():
    clients = params.detail(load("tr098_tplink_xtp"), NOW, 300)["clients"]
    assert clients == [
        {
            "mac": "3c:22:fb:01:02:03",
            "ip": "192.168.0.100",
            "hostname": None,
            "active": True,
            "connection": "wifi",
            "band": "2.4GHz",
            "network": f"{IGD_WLAN}.1",
            "signal_dbm": None,
            "as_of": TS,
        }
    ]


def test_summary_needs_only_its_projection():
    for name in FIXTURE_NAMES:
        doc = load(name)
        assert params.summarize(project(doc, params.SUMMARY_PROJECTION), NOW, 300) == params.summarize(doc, NOW, 300)
        assert params.detail(project(doc, params.DETAIL_PROJECTION), NOW, 300) == params.detail(doc, NOW, 300)


def test_summary_card():
    card = params.summarize(load("tr181_cudy"), NOW, 300)
    assert card["acs_id"] == "A0B1C2-WR3000-CU24A0001234"
    assert (card["model"], card["data_model"], card["profile"]) == ("WR3000", "tr181", "cudy-tr181")
    assert card["online"] is True
    assert [(w["band"], w["ssid"], w["as_of"]) for w in card["wifi"]] == [
        ("2.4GHz", "Cudy-7F21", "2026-09-28T08:30:00.000Z"),
        ("5GHz", "Cudy-7F21-5G", "2026-09-28T08:30:00.000Z"),
    ]
    assert params.summarize(load("tr098_sim"), NOW, 300)["tags"] == ["skybre_new"]


# --- refresh scopes --------------------------------------------------------------------------


def test_refresh_scopes_are_valid_task_paths():
    for name in FIXTURE_NAMES:
        doc = load(name)
        model = params.detect_model(doc)
        for scopes in (params.refresh_scopes(model), params.refresh_scopes(model, doc)):
            assert set(scopes) <= set(params.REFRESH_SCOPES)
            for path in scopes.values():
                tasks.refresh_object(path, job="j1", step="refresh", unique_key="skyrouter-refresh")


def test_refresh_scopes_per_model():
    assert params.refresh_scopes("tr181") == {
        "wifi": "Device.WiFi",
        "hosts": "Device.Hosts",
        "wan": "Device.IP",
        "info": "Device.DeviceInfo",
        "all": "Device",
    }
    # Without the document there is no known LANDevice, and task paths take no wildcards.
    assert params.refresh_scopes("tr098")["wifi"] == "InternetGatewayDevice.LANDevice"
    assert params.refresh_scopes("tr098", load("tr098_sim"))["wifi"] == f"{IGD_WLAN}"
    assert "wifi" not in params.refresh_scopes("tr181-issue1")
    assert params.refresh_scopes("unknown") == {}
    dual = load("dual_root")
    assert params.refresh_scopes("mixed", dual)["wifi"] == IGD_WLAN
    node_at(dual, "_deviceId")["_Manufacturer"] = "Acme"
    node_at(dual, "InternetGatewayDevice.DeviceInfo.Manufacturer")["_value"] = "Acme"
    drop(dual, "InternetGatewayDevice.ManagementServer.ConnectionRequestURL")
    set_leaf(dual, "Device.ManagementServer.ConnectionRequestURL", "http://10.10.0.70:7547/", None)
    scopes = params.refresh_scopes("mixed", dual)
    assert (scopes["wifi"], scopes["all"]) == ("Device.WiFi", "Device")
    with pytest.raises(ValidationError):
        params.refresh_scopes("tr098", load("tr181_cudy"))
    with pytest.raises(ValidationError):
        params.refresh_scopes("tr-069")


def test_dual_root_generic_device_manages_the_connection_request_root():
    doc = load("dual_root")
    node_at(doc, "_deviceId")["_Manufacturer"] = "Acme"
    node_at(doc, "InternetGatewayDevice.DeviceInfo.Manufacturer")["_value"] = "Acme"
    detail = params.detail(doc, NOW, 300)
    assert (detail["data_model"], detail["profile"], detail["wifi_root"]) == ("mixed", "generic-tr098", "tr098")
    drop(doc, "InternetGatewayDevice.ManagementServer.ConnectionRequestURL")
    set_leaf(doc, "Device.ManagementServer.ConnectionRequestURL", "http://10.10.0.70:7547/", None)
    detail = params.detail(doc, NOW, 300)
    assert (detail["profile"], detail["wifi_root"]) == ("generic-tr181", "tr181")
    assert [w["id"] for w in detail["wifi"]] == [f"{WIFI}.SSID.1", f"{WIFI}.SSID.2"]
    assert detail["clients"][0]["band"] == "5GHz"


# --- write plans --------------------------------------------------------------------------------


def test_plan_resolves_leaves_per_band_through_the_profile():
    doc = load("tr181_cudy")
    plan = params.wifi_write_plan(doc, "2.4GHz", "NewNet", True)
    assert plan.ok and not plan.needs_refresh and not plan.needs_confirmation
    assert (plan.profile, plan.networks) == ("cudy-tr181", (f"{WIFI}.SSID.1",))
    # WPA3 transition: KeyPassphrase plus the writable SAEPassphrase.
    assert plan.paths == (
        f"{WIFI}.SSID.1.SSID",
        f"{WIFI}.AccessPoint.2.Security.KeyPassphrase",
        f"{WIFI}.AccessPoint.2.Security.SAEPassphrase",
    )
    assert [leaf.placeholder for leaf in plan.leaves] == ["<ssid>", "<passphrase>", "<passphrase>"]
    five = params.wifi_write_plan(doc, "5GHz", None, True)
    assert five.paths == (f"{WIFI}.AccessPoint.1.Security.KeyPassphrase",)
    both = params.wifi_write_plan(doc, "all", "NewNet", False)
    assert both.paths == (f"{WIFI}.SSID.1.SSID", f"{WIFI}.SSID.2.SSID")
    assert params.wifi_write_plan(load("tr098_huawei_1_5"), "5GHz", None, True).paths == (
        f"{IGD_WLAN}.5.PreSharedKey.1.KeyPassphrase",
    )


def test_plan_values_fill_placeholders_and_build_a_valid_task():
    plan = params.wifi_write_plan(load("tr181_cudy"), "5GHz", "NewNet", True)
    values = plan.values(ssid="NewNet", passphrase="correct horse battery")
    assert values == (
        (f"{WIFI}.SSID.2.SSID", "NewNet"),
        (f"{WIFI}.AccessPoint.1.Security.KeyPassphrase", "correct horse battery"),
    )
    task = tasks.set_parameter_values(values, job="j1", step="write", unique_key="skyrouter-wifi")
    assert task.paths == plan.paths
    # The plan itself never held the value.
    assert "correct horse battery" not in repr(plan) and "correct horse battery" not in json.dumps(plan.to_public())
    with pytest.raises(ValidationError, match="passphrase is needed"):
        plan.values(ssid="NewNet")


def test_plan_falls_back_to_the_next_passphrase_leaf_after_a_fault():
    doc = load("tr098_tplink_xtp")
    plan = params.wifi_write_plan(doc, "2.4GHz", None, True)
    assert plan.paths == (f"{IGD_WLAN}.1.X_TP_PreSharedKey",)
    assert plan.fallbacks == (f"{IGD_WLAN}.1.PreSharedKey.1.KeyPassphrase",)
    retry = params.wifi_write_plan(doc, "2.4GHz", None, True, avoid=plan.secret_paths)
    assert retry.paths == (f"{IGD_WLAN}.1.PreSharedKey.1.KeyPassphrase",) and retry.fallbacks == ()
    spent = params.wifi_write_plan(doc, "2.4GHz", None, True, avoid=plan.secret_paths + retry.secret_paths)
    assert not spent.ok and "already been tried" in spent.refusal


def test_plan_skips_a_missing_or_read_only_candidate_for_the_next_one():
    doc = load("tr098_tplink_xtp")
    drop(doc, f"{IGD_WLAN}.1.X_TP_PreSharedKey")
    assert params.wifi_write_plan(doc, "2.4GHz", None, True).paths == (f"{IGD_WLAN}.1.PreSharedKey.1.KeyPassphrase",)
    doc = load("tr098_tplink_xtp")
    node_at(doc, f"{IGD_WLAN}.1.X_TP_PreSharedKey")["_writable"] = False
    assert params.wifi_write_plan(doc, "2.4GHz", None, True).paths == (f"{IGD_WLAN}.1.PreSharedKey.1.KeyPassphrase",)


def test_plan_needs_a_refresh_for_missing_or_unknown_leaves():
    doc = load("tr181_cudy")
    drop(doc, f"{WIFI}.AccessPoint.1.Security.KeyPassphrase")
    plan = params.wifi_write_plan(doc, "5GHz", "x", True)
    assert not plan.ok and plan.needs_refresh
    assert plan.missing == (f"{WIFI}.AccessPoint.1.Security.KeyPassphrase",)
    assert plan.refresh_paths == ("Device.WiFi",)
    doc = load("tr181_cudy")
    del node_at(doc, f"{WIFI}.SSID.2.SSID")["_writable"]
    plan = params.wifi_write_plan(doc, "5GHz", "x", False)
    assert plan.needs_refresh and plan.unknown_writable == (f"{WIFI}.SSID.2.SSID",)
    with pytest.raises(ValidationError, match="cannot be written"):
        plan.values(ssid="x")


def test_plan_unknown_preferred_leaf_waits_for_a_refresh_instead_of_skipping_it():
    doc = load("tr098_tplink_xtp")
    del node_at(doc, f"{IGD_WLAN}.1.X_TP_PreSharedKey")["_writable"]
    plan = params.wifi_write_plan(doc, "2.4GHz", None, True)
    assert plan.needs_refresh and plan.unknown_writable == (f"{IGD_WLAN}.1.X_TP_PreSharedKey",)


def test_plan_read_only_leaf_is_final():
    doc = load("tr098_huawei_1_5")
    node_at(doc, f"{IGD_WLAN}.5.PreSharedKey.1.KeyPassphrase")["_writable"] = False
    plan = params.wifi_write_plan(doc, "5GHz", None, True)
    assert not plan.ok and not plan.needs_refresh
    assert plan.unwritable == (f"{IGD_WLAN}.5.PreSharedKey.1.KeyPassphrase",)
    assert "read-only" in plan.problem()


def test_plan_with_no_wifi_cached_refreshes_the_wifi_subtree():
    doc = load("tr181_cudy")
    del node_at(doc, "Device")["WiFi"]
    plan = params.wifi_write_plan(doc, "all", "x", True)
    assert plan.needs_refresh and plan.missing == ("Device.WiFi",) and plan.refresh_paths == ("Device.WiFi",)
    doc = load("tr098_sim")
    for n in (1, 2):
        drop(doc, f"{IGD_WLAN}.{n}.SSID")
    plan = params.wifi_write_plan(doc, "all", "x", False)
    assert plan.needs_refresh and plan.missing == (f"{IGD_WLAN}.1.SSID", f"{IGD_WLAN}.2.SSID")


def test_plan_guessed_band_needs_confirmation_only_for_a_single_band():
    doc = load("tr098_sim")
    assert params.wifi_write_plan(doc, "5GHz", "x", False).needs_confirmation
    assert not params.wifi_write_plan(doc, "all", "x", False).needs_confirmation
    assert params.wifi_write_plan(doc, "all", "x", False).band_guessed


def test_plan_refusals():
    issue1 = params.wifi_write_plan(load("tr181_issue1"), "all", "x", True)
    assert not issue1.ok and not issue1.needs_refresh and "Issue 1" in issue1.refusal
    unknown = params.wifi_write_plan({"_id": "x"}, "all", "x", True)
    assert not unknown.ok and "not known" in unknown.refusal
    assert "no 6GHz network" in params.wifi_write_plan(load("tr181_cudy"), "6GHz", "x", False).refusal
    # A passphrase on an open network needs a security change first; an SSID does not.
    doc = load("tr098_huawei_1_5")
    node_at(doc, f"{IGD_WLAN}.5.BeaconType")["_value"] = "Basic"
    node_at(doc, f"{IGD_WLAN}.5.BasicEncryptionModes")["_value"] = "None"
    refused = params.wifi_write_plan(doc, "5GHz", None, True)
    assert not refused.ok and "set up WPA2 or WPA3" in refused.refusal and refused.leaves == ()
    assert params.wifi_write_plan(doc, "5GHz", "x", False).ok


def test_plan_needs_the_security_mode_before_a_passphrase():
    doc = load("tr181_cudy")
    drop(doc, f"{WIFI}.AccessPoint.1.Security.ModeEnabled")
    plan = params.wifi_write_plan(doc, "5GHz", None, True)
    assert plan.needs_refresh and plan.missing == (f"{WIFI}.AccessPoint.1.Security.ModeEnabled",)


def test_plan_input_validation():
    doc = load("tr181_cudy")
    with pytest.raises(ValidationError, match="band"):
        params.wifi_write_plan(doc, "2.4", "x", True)
    with pytest.raises(ValidationError, match="nothing to change"):
        params.wifi_write_plan(doc, "all", None, False)
    with pytest.raises(ValidationError):
        params.wifi_write_plan(doc, "all", 5, False)  # type: ignore[arg-type]


def test_plan_to_public_is_json_and_says_what_it_needs():
    public = params.wifi_write_plan(load("tr098_sim"), "2.4GHz", "x", True).to_public()
    json.dumps(public)
    assert public["needs_confirmation"] is True and public["ok"] is True
    assert {leaf["value"] for leaf in public["leaves"]} == {"<ssid>", "<passphrase>"}


# --- secrets ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "secret"),
    [
        ("Device.WiFi.AccessPoint.1.Security.KeyPassphrase", True),
        ("Device.WiFi.AccessPoint.1.Security.PreSharedKey", True),
        ("Device.WiFi.AccessPoint.1.Security.SAEPassphrase", True),
        ("Device.WiFi.AccessPoint.1.Security.RadiusSecret", True),
        ("Device.WiFi.AccessPoint.1.WPS.PIN", True),
        ("InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.X_TP_PreSharedKey", True),
        ("InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.WEPKey.1.WEPKey", True),
        # Anything inside the PreSharedKey table, whatever the leaf is called.
        ("InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.PreSharedKey.1.AssociatedDeviceMACAddress", True),
        ("InternetGatewayDevice.X_TP_UserCfg.UserPwd", True),
        ("InternetGatewayDevice.ManagementServer.ConnectionRequestPassword", True),
        ("Device.PPP.Interface.1.Password", True),
        ("InternetGatewayDevice.ManagementServer.ParameterKey", False),
        ("InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.TotalPSKFailures", False),
        ("Device.WiFi.AccessPoint.1.Security.ModeEnabled", False),
        ("Device.WiFi.SSID.1.SSID", False),
        ("InternetGatewayDevice.ManagementServer.Username", False),
    ],
)
def test_secret_paths(path, secret):
    assert params.is_secret_path(path) is secret


def test_redact_reduces_secret_leaves_and_keeps_the_rest():
    doc = load("tr098_sim")
    before = copy.deepcopy(doc)
    redacted = params.redact(doc)
    assert doc == before
    assert node_at(redacted, f"{IGD_WLAN}.1.KeyPassphrase") == {
        "_object": False,
        "_redacted": True,
        "present": True,
        "writable": True,
    }
    assert node_at(redacted, f"{IGD_WLAN}.1.SSID") == node_at(doc, f"{IGD_WLAN}.1.SSID")
    assert redacted["_id"] == doc["_id"] and redacted["_tags"] == ["skybre_new"]
    # Unknown writability stays unknown rather than becoming false.
    del node_at(doc, f"{IGD_WLAN}.1.KeyPassphrase")["_writable"]
    assert node_at(params.redact(doc), f"{IGD_WLAN}.1.KeyPassphrase")["writable"] is None


def test_redact_known_values_wherever_they_sit():
    doc = load("tr181_cudy")
    set_leaf(doc, "Device.X_VENDOR_Config.Blob", "prefix hunter22-long-pass suffix", False)
    redacted = params.redact(doc, known_values=["hunter22-long-pass", "abc"])
    assert "hunter22-long-pass" not in json.dumps(redacted)
    assert node_at(redacted, "Device.X_VENDOR_Config.Blob")["_redacted"] is True
    # Too short to match safely, so ignored.
    assert node_at(redacted, "Device.WiFi.SSID.1.SSID")["_value"] == "Cudy-7F21"


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_no_secret_value_appears_in_any_output(name):
    doc = load(name)
    assert MARKER in json.dumps(doc)
    outputs: list[Any] = [
        params.summarize(doc, NOW, 300),
        params.detail(doc, NOW, 300),
        params.redact(doc),
        params.refresh_scopes(params.detect_model(doc), doc),
    ]
    for band in params.BAND_CHOICES:
        for ssid, passphrase in (("x", True), (None, True), ("x", False)):
            plan = params.wifi_write_plan(doc, band, ssid, passphrase)
            outputs += [plan.to_public(), repr(plan), plan.problem()]
    blob = json.dumps(outputs, default=str)
    assert MARKER not in blob
    tree = DeviceTree(doc)
    assert all(MARKER not in repr(leaf) for leaf in tree.iter_leaves())


def test_no_secret_value_in_any_output_even_when_every_secret_leaf_is_plaintext():
    # A router that ignores the spec and returns every secret in plaintext (F27 broken).
    for name in FIXTURE_NAMES:
        doc = load(name)
        tree = DeviceTree(doc)
        for leaf in list(tree.iter_leaves()):
            if params.is_secret_path(leaf.path):
                node_at(doc, leaf.path)["_value"] = f"{MARKER}-{leaf.path}"
        blob = json.dumps([params.summarize(doc, NOW, 300), params.detail(doc, NOW, 300), params.redact(doc)])
        assert MARKER not in blob
