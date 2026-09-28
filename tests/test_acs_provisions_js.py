"""SkyRouter's provision scripts, run with node in a stand-in for GenieACS's sandbox.

The stand-in is written for these tests and holds no GenieACS code. It follows the
documented provision API and nothing more. The scripts get only args, declare,
clear, commit, ext, log and a Date whose now() gives period boundaries. Each
script is compiled the way GenieACS compiles it: in strict mode, wrapped in a
function, with a 50 ms timeout. Every call and every attribute read is recorded.
"""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from cudy_manager.acs import bootstrap

NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="node is not installed")

PROVISIONS_DIR = Path(bootstrap.__file__).parent / "provisions"
NAMES = bootstrap.PROVISION_NAMES
SESSION = 1_790_000_000_000
# Stands in for GenieACS's per-device offset, which it derives from the device ID.
PHASE = 1_234_567_891
DEVICE_ID = "202BC1-BM632w-000000"
CR_PASSWORD = "0123456789abcdef0123456789abcdef"
HOUR = 3_600_000
DAY = 86_400_000
SECRET_RE = re.compile(r"(?:KeyPassphrase|PreSharedKey|SAEPassphrase|WEPKey|Password|Secret|PIN|UserPwd)$")

IGD_STORE = {"InternetGatewayDevice.DeviceInfo.SoftwareVersion": ["1.0", "xsd:string"]}
TR181_STORE = {"Device.DeviceInfo.SoftwareVersion": ["1.0", "xsd:string"]}

HARNESS = r"""
"use strict";
const vm = require("vm");
const fs = require("fs");

const config = JSON.parse(process.argv[2]);

function periodStart(interval, variance) {
  const spread = variance === undefined ? interval : variance;
  const offset = spread ? config.phase % spread : 0;
  return Math.floor((config.session + offset) / interval) * interval - offset;
}

// Every stored leaf, and every object above it.
function knownPaths() {
  const paths = new Set();
  for (const key of Object.keys(config.store)) {
    const parts = key.split(".");
    for (let i = 1; i <= parts.length; i++) paths.add(parts.slice(0, i).join("."));
  }
  return [...paths].sort();
}

function matcher(pattern) {
  const want = pattern.split(".");
  return (path) => {
    const have = path.split(".");
    return have.length === want.length && want.every((part, i) => part === "*" || part === have[i]);
  };
}

function runOnce(code) {
  const record = {declares: [], clears: [], exts: [], reads: [], dateNow: [], logs: [], commits: 0};
  const known = knownPaths();
  const copy = (value) => (value === undefined ? null : JSON.parse(JSON.stringify(value)));

  function wrap(pattern, hits) {
    const read = (attr) => record.reads.push([pattern, attr]);
    return {
      get path() { read("path"); return hits[0]; },
      get size() { read("size"); return hits.length ? hits.length : undefined; },
      get value() { read("value"); return hits.length ? config.store[hits[0]] : undefined; },
      [Symbol.iterator]() { read("iterate"); return hits.map((hit) => wrap(hit, [hit]))[Symbol.iterator](); },
    };
  }

  const FakeDate = function () { throw new Error("provisions must not construct Date objects"); };
  FakeDate.now = (interval, variance) => {
    const value = interval === undefined ? config.session : periodStart(interval, variance);
    record.dateNow.push([interval === undefined ? null : interval, value]);
    return value;
  };

  const context = vm.createContext({
    args: copy(config.args),
    declare(path, timestamps, values) {
      if (typeof path !== "string") throw new TypeError("declare() needs a path string");
      record.declares.push({path, timestamps: copy(timestamps), values: copy(values)});
      return wrap(path, known.filter(matcher(path)));
    },
    clear(path, timestamp) { record.clears.push({path, timestamp}); },
    commit() { record.commits += 1; },
    ext(...extArgs) { record.exts.push(extArgs.map(String)); return config.ext; },
    log(message) { record.logs.push(String(message)); },
    Date: FakeDate,
  });
  const started = process.cpuUsage();
  try {
    code.runInContext(context, {timeout: 50});
    record.error = null;
  } catch (error) {
    record.error = String(error && error.message);
  }
  const used = process.cpuUsage(started);
  record.cpuMs = (used.user + used.system) / 1000;
  return record;
}

const source = fs.readFileSync(config.script, "utf8");
const code = new vm.Script('"use strict";(function(){\n' + source + '\n})();', {filename: config.script});
const runs = [];
for (let i = 0; i < config.runs; i++) runs.push(runOnce(code));
const comparable = (run) => JSON.stringify({...run, cpuMs: 0});
const result = runs[runs.length - 1];
result.deterministic = runs.every((run) => comparable(run) === comparable(runs[0]));
result.cpuMs = Math.min(...runs.map((run) => run.cpuMs));
process.stdout.write(JSON.stringify(result));
"""


@pytest.fixture(scope="module")
def harness(tmp_path_factory):
    path = tmp_path_factory.mktemp("provisions") / "harness.js"
    path.write_text(HARNESS, encoding="utf-8")
    return path


def script_path(name):
    return PROVISIONS_DIR / f"{name}.js"


def run(harness, name, args=(), store=None, ext=CR_PASSWORD, runs=3):
    config = {
        "script": str(script_path(name)),
        "args": list(args),
        "store": {"DeviceID.ID": [DEVICE_ID, "xsd:string"], **(store or {})},
        "ext": ext,
        "session": SESSION,
        "phase": PHASE,
        "runs": runs,
    }
    result = subprocess.run(
        [NODE, str(harness), json.dumps(config)], capture_output=True, text=True, timeout=60, check=False
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def period(record, interval):
    values = {value for length, value in record["dateNow"] if length == interval}
    assert len(values) == 1, record["dateNow"]
    return values.pop()


def value_reads(record):
    return [path for path, attr in record["reads"] if attr != "size"]


# --- every script ---------------------------------------------------------------------


class TestEveryScript:
    @pytest.mark.parametrize("name", NAMES)
    def test_node_accepts_the_script_wrapped_as_genieacs_wraps_it(self, name, tmp_path):
        wrapped = tmp_path / f"{name}.js"
        wrapped.write_text(
            '"use strict";(function(){\n' + script_path(name).read_text(encoding="utf-8") + "\n})();", encoding="utf-8"
        )
        result = subprocess.run([NODE, "--check", str(wrapped)], capture_output=True, text=True, check=False)
        assert result.returncode == 0, result.stderr

    def test_the_syntax_check_does_catch_errors(self, tmp_path):
        wrapped = tmp_path / "broken.js"
        wrapped.write_text('"use strict";(function(){\ndeclare("a", {value: 1};\n})();', encoding="utf-8")
        result = subprocess.run([NODE, "--check", str(wrapped)], capture_output=True, text=True, check=False)
        assert result.returncode != 0

    @pytest.mark.parametrize("name", NAMES)
    def test_source_stays_inside_the_sandbox_rules(self, name):
        source = script_path(name).read_text(encoding="utf-8")
        # Sent to the NBI as the request body and stored verbatim, so ASCII avoids
        # any question of encoding.
        assert source.isascii()
        # declare() inside a try/catch is refused by the sandbox, and there is no
        # require, process or network in there.
        for forbidden in (r"\btry\b", r"\brequire\s*\(", r"\bprocess\.", r"\bimport\b", r"\bnew Date\b", r"\blog\("):
            assert not re.search(forbidden, source), forbidden

    @pytest.mark.parametrize(
        ("name", "args", "store"),
        [
            ("skybre-bootstrap", [], IGD_STORE),
            ("skybre-inform", [300], IGD_STORE),
            ("skybre-refresh", [], {**IGD_STORE, **TR181_STORE}),
        ],
    )
    def test_runs_well_inside_the_50ms_budget_and_deterministically(self, harness, name, args, store):
        # GenieACS re-runs a script from the top after every round of RPCs, so the
        # same inputs have to give the same declarations.
        record = run(harness, name, args, store, runs=5)
        assert record["error"] is None
        assert record["deterministic"] is True
        assert record["cpuMs"] < 25

    @pytest.mark.parametrize("name", NAMES)
    def test_never_reads_a_secret(self, harness, name):
        record = run(harness, name, [300] if name == "skybre-inform" else [], {**IGD_STORE, **TR181_STORE})
        assert record["error"] is None
        assert not [path for path in value_reads(record) if SECRET_RE.search(path)]
        assert record["logs"] == []


# --- skybre-bootstrap -----------------------------------------------------------------


class TestBootstrapScript:
    def test_clears_both_roots_as_of_the_session_start(self, harness):
        record = run(harness, "skybre-bootstrap", store=IGD_STORE)
        assert record["error"] is None
        assert record["clears"] == [
            {"path": "InternetGatewayDevice", "timestamp": SESSION},
            {"path": "Device", "timestamp": SESSION},
        ]
        assert record["declares"] == []
        assert record["reads"] == []
        assert record["exts"] == []


# --- skybre-inform --------------------------------------------------------------------


class TestInformScript:
    @pytest.mark.parametrize("interval", [60, 300, 86400])
    def test_declares_the_inform_schedule_and_credentials_on_both_roots(self, harness, interval):
        record = run(harness, "skybre-inform", [interval], IGD_STORE)
        assert record["error"] is None
        daily = period(record, DAY)
        expected = [{"path": "DeviceID.ID", "timestamps": {"value": 1}, "values": None}]
        for root in ("InternetGatewayDevice", "Device"):
            server = f"{root}.ManagementServer."
            expected += [
                {"path": server + "PeriodicInformEnable", "timestamps": {"value": daily}, "values": {"value": True}},
                {
                    "path": server + "PeriodicInformInterval",
                    "timestamps": {"value": daily},
                    "values": {"value": interval},
                },
                {
                    "path": server + "PeriodicInformTime",
                    "timestamps": {"value": daily},
                    "values": {"value": daily % DAY},
                },
                {
                    "path": server + "ConnectionRequestUsername",
                    "timestamps": {"value": daily},
                    "values": {"value": DEVICE_ID},
                },
                # Read once, never refreshed: it is write-only and reads back as "".
                {
                    "path": server + "ConnectionRequestPassword",
                    "timestamps": {"value": 1},
                    "values": {"value": CR_PASSWORD},
                },
            ]
        assert record["declares"] == expected
        assert record["exts"] == [["skyrouter", "crPassword", DEVICE_ID]]
        assert record["reads"] == [["DeviceID.ID", "value"]]
        assert record["clears"] == []
        assert record["commits"] == 0

    def test_the_daily_boundary_is_per_device_and_in_the_past(self, harness):
        daily = period(run(harness, "skybre-inform", [300], IGD_STORE), DAY)
        assert SESSION - DAY < daily <= SESSION
        assert daily % DAY != 0

    def test_owns_only_management_server(self, harness):
        record = run(harness, "skybre-inform", [300], IGD_STORE)
        written = [item["path"] for item in record["declares"] if item["values"] is not None]
        assert written
        assert all(
            re.fullmatch(r"(InternetGatewayDevice|Device)\.ManagementServer\.[A-Za-z]+", path) for path in written
        )

    @pytest.mark.parametrize("args", [[59], [86401], [0], [-300], [], ["300"], [300.5], [None], [True], [[300]]])
    def test_an_unusable_interval_faults_before_anything_is_declared(self, harness, args):
        record = run(harness, "skybre-inform", args, IGD_STORE, runs=1)
        assert record["error"] and "inform interval of 60-86400 seconds" in record["error"]
        assert record["declares"] == []
        assert record["exts"] == []

    def test_its_bounds_match_the_python_side(self):
        source = script_path("skybre-inform").read_text(encoding="utf-8")
        assert f"const MIN_INTERVAL = {bootstrap.MIN_INFORM_INTERVAL};" in source
        assert f"const MAX_INTERVAL = {bootstrap.MAX_INFORM_INTERVAL};" in source

    @pytest.mark.parametrize(
        "ext", [None, "", "undefined", "0123456789ABCDEF0123", "0123456789abcde", "not-a-password-value!", 12345]
    )
    def test_an_unusable_extension_result_faults_without_being_echoed(self, harness, ext):
        record = run(harness, "skybre-inform", [300], IGD_STORE, ext=ext, runs=1)
        assert record["error"] and "no usable connection-request password" in record["error"]
        if isinstance(ext, str) and ext:
            assert ext not in record["error"]
        assert not [item for item in record["declares"] if "ManagementServer" in item["path"]]


# --- skybre-refresh -------------------------------------------------------------------


def refresh(harness, store):
    record = run(harness, "skybre-refresh", store=store)
    assert record["error"] is None
    return record


def declared(record):
    return {item["path"]: item["timestamps"] for item in record["declares"][2:]}


class TestRefreshScript:
    @pytest.mark.parametrize("store", [IGD_STORE, TR181_STORE, {**IGD_STORE, **TR181_STORE}, {}])
    def test_reads_nothing_but_which_roots_exist(self, harness, store):
        record = refresh(harness, store)
        assert record["declares"][:2] == [
            {"path": "InternetGatewayDevice", "timestamps": {"path": 1}, "values": None},
            {"path": "Device", "timestamps": {"path": 1}, "values": None},
        ]
        assert record["reads"] == [["InternetGatewayDevice", "size"], ["Device", "size"]]

    @pytest.mark.parametrize("store", [IGD_STORE, TR181_STORE, {**IGD_STORE, **TR181_STORE}])
    def test_declares_no_desired_values_and_calls_nothing_else(self, harness, store):
        record = refresh(harness, store)
        assert all(item["values"] is None for item in record["declares"])
        assert record["exts"] == []
        assert record["clears"] == []
        assert record["commits"] == 0

    def test_a_device_with_neither_root_gets_only_the_probes(self, harness):
        assert len(refresh(harness, {})["declares"]) == 2

    def test_tr098_gets_only_tr098_paths(self, harness):
        record = refresh(harness, IGD_STORE)
        paths = declared(record)
        hourly, daily = period(record, HOUR), period(record, DAY)
        assert paths and all(path.startswith("InternetGatewayDevice.") for path in paths)
        wlan = "InternetGatewayDevice.LANDevice.*.WLANConfiguration.*."
        stable = {"path": daily, "value": hourly}
        churning = {"path": hourly, "value": hourly}
        secret = {"path": daily, "writable": daily}
        for leaf in ("SSID", "Enable", "Channel", "PossibleChannels", "Standard", "X_HW_RFBand", "X_TP_Band"):
            assert paths[wlan + leaf] == stable
        for leaf in ("BeaconType", "IEEE11iAuthenticationMode", "WPAEncryptionModes", "TotalPSKFailures"):
            assert paths[wlan + leaf] == stable
        for leaf in ("PreSharedKey.1.KeyPassphrase", "KeyPassphrase", "X_TP_PreSharedKey"):
            assert paths[wlan + leaf] == secret
        assert paths[wlan + "AssociatedDevice.*.AssociatedDeviceMACAddress"] == churning
        for leaf in ("MACAddress", "IPAddress", "HostName", "Active", "Layer2Interface"):
            assert paths["InternetGatewayDevice.LANDevice.*.Hosts.Host.*." + leaf] == churning
        assert paths["InternetGatewayDevice.Layer3Forwarding.DefaultConnectionService"] == stable
        for kind in ("WANIPConnection", "WANPPPConnection"):
            for leaf in ("ExternalIPAddress", "ConnectionStatus", "Uptime"):
                assert paths[f"InternetGatewayDevice.WANDevice.*.WANConnectionDevice.*.{kind}.*.{leaf}"] == stable
        for leaf in ("ModelName", "SerialNumber", "SoftwareVersion", "HardwareVersion", "UpTime"):
            assert paths["InternetGatewayDevice.DeviceInfo." + leaf] == stable
        # What params.py falls back on for vendor trees.
        for leaf in ("X_HW_Standard", "LowerLayers"):
            assert paths[wlan + leaf] == stable
        assert paths["InternetGatewayDevice.LANDevice.*.WiFi.Radio.*.OperatingFrequencyBand"] == stable
        assert paths["InternetGatewayDevice.LANDevice.*.Hosts.Host.*.X_HW_RSSI"] == churning
        assert paths[wlan + "AssociatedDevice.*.X_HW_RSSI"] == churning
        for leaf in ("Name", "X_HW_SERVICELIST", "X_ZTE-COM_ServiceList", "X_TP_ServiceType"):
            assert paths[f"InternetGatewayDevice.WANDevice.*.WANConnectionDevice.*.WANIPConnection.*.{leaf}"] == stable

    def test_tr181_gets_only_tr181_paths(self, harness):
        record = refresh(harness, TR181_STORE)
        paths = declared(record)
        hourly, daily = period(record, HOUR), period(record, DAY)
        assert paths and all(path.startswith("Device.") for path in paths)
        stable = {"path": daily, "value": hourly}
        churning = {"path": hourly, "value": hourly}
        secret = {"path": daily, "writable": daily}
        for path in (
            "Device.RootDataModelVersion",
            "Device.WiFi.Radio.*.OperatingFrequencyBand",
            "Device.WiFi.SSID.*.SSID",
            "Device.WiFi.SSID.*.LowerLayers",
            "Device.WiFi.AccessPoint.*.SSIDReference",
            "Device.WiFi.AccessPoint.*.Security.ModeEnabled",
            "Device.IP.Interface.*.IPv4Address.*.IPAddress",
            "Device.PPP.Interface.*.ConnectionStatus",
            "Device.Routing.Router.*.IPv4Forwarding.*.Interface",
            "Device.Routing.Router.*.IPv4Forwarding.*.Enable",
            "Device.NAT.InterfaceSetting.*.Interface",
            "Device.IP.Interface.*.Loopback",
            "Device.PPP.Interface.*.IPCP.LocalIPAddress",
            "Device.WiFi.Radio.*.SupportedStandards",
            "Device.WiFi.EndPoint.*.SSIDReference",
            "Device.DeviceSummary",
            "Device.DeviceInfo.SoftwareVersion",
        ):
            assert paths[path] == stable, path
        # Issue 1 is recognised by the object alone, which has no value to fetch.
        assert paths["Device.LAN"] == {"path": daily}
        for path in (
            "Device.WiFi.AccessPoint.*.Security.KeyPassphrase",
            "Device.WiFi.AccessPoint.*.Security.SAEPassphrase",
        ):
            assert paths[path] == secret
        for path in (
            "Device.Hosts.Host.*.PhysAddress",
            "Device.Hosts.Host.*.Layer1Interface",
            "Device.WiFi.AccessPoint.*.AssociatedDevice.*.SignalStrength",
        ):
            assert paths[path] == churning

    def test_a_dual_root_device_gets_both(self, harness):
        paths = declared(refresh(harness, {**IGD_STORE, **TR181_STORE}))
        assert set(declared(refresh(harness, IGD_STORE))) | set(declared(refresh(harness, TR181_STORE))) == set(paths)

    def test_secrets_are_discovered_but_never_fetched(self, harness):
        record = refresh(harness, {**IGD_STORE, **TR181_STORE})
        secrets = {path: stamps for path, stamps in declared(record).items() if SECRET_RE.search(path)}
        assert len(secrets) == 5
        assert all("value" not in stamps for stamps in secrets.values())
        # And nothing fetched by value looks like a secret.
        fetched = [path for path, stamps in declared(record).items() if "value" in stamps]
        assert not [path for path in fetched if SECRET_RE.search(path)]

    def test_declares_each_path_once(self, harness):
        record = refresh(harness, {**IGD_STORE, **TR181_STORE})
        paths = [item["path"] for item in record["declares"]]
        assert len(paths) == len(set(paths))
