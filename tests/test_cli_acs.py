"""The TR-069 commands (router-manager acs ...) and wifi-password, against the fake NBI.

The CLI builds the same AcsService as the server, from the same environment, so a
change started here lands in the server's job file and vault. Every failure is one
"error:" line and a non-zero exit, and no passphrase is ever printed.
"""

import io
import json
import logging
import os
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from fake_nbi import FakeNbi, build_device, iso

from cudy_manager import cli, web
from cudy_manager.acs import params
from cudy_manager.acs.service import vault_ref
from cudy_manager.adapters import AdapterError, UnsupportedOperation
from cudy_manager.manager import DeviceManager
from cudy_manager.models import ValidationError
from cudy_manager.secrets import SecretStore

REPO = Path(__file__).resolve().parent.parent
PASS = "correct-Horse-Battery-9"
ADMIN = "router-admin-password"

WIFI = "Device.WiFi"
KEY1 = f"{WIFI}.AccessPoint.1.Security.KeyPassphrase"
KEY2 = f"{WIFI}.AccessPoint.2.Security.KeyPassphrase"
IGD = "InternetGatewayDevice"
WLAN1 = f"{IGD}.LANDevice.1.WLANConfiguration.1"


def tr181_leaves(**extra: Any) -> dict[str, Any]:
    """A dual-band TR-181 router that reports its bands, so no write needs confirming."""
    leaves: dict[str, Any] = {
        "Device.ManagementServer.ConnectionRequestURL": {"value": "http://10.10.0.40:7547/", "writable": False},
        "Device.ManagementServer.PeriodicInformInterval": 300,
        "Device.DeviceInfo.Manufacturer": {"value": "Acme", "writable": False},
        f"{WIFI}.Radio.1.OperatingFrequencyBand": "2.4GHz",
        f"{WIFI}.Radio.2.OperatingFrequencyBand": "5GHz",
        f"{WIFI}.SSID.1.SSID": "Home",
        f"{WIFI}.SSID.1.LowerLayers": "Device.WiFi.Radio.1.",
        f"{WIFI}.SSID.2.SSID": "Home-5G",
        f"{WIFI}.SSID.2.LowerLayers": "Device.WiFi.Radio.2.",
    }
    for index in (1, 2):
        ap = f"{WIFI}.AccessPoint.{index}"
        leaves[f"{ap}.SSIDReference"] = f"Device.WiFi.SSID.{index}."
        leaves[f"{ap}.Security.ModeEnabled"] = "WPA2-Personal"
        leaves[f"{ap}.Security.KeyPassphrase"] = ""
    leaves.update(extra)
    return leaves


def tr098_guessed_leaves() -> dict[str, Any]:
    """One TR-098 network whose band SkyRouter can only infer from its channel."""
    return {
        f"{IGD}.ManagementServer.ConnectionRequestURL": {"value": "http://10.10.0.41:7547/", "writable": False},
        f"{IGD}.ManagementServer.PeriodicInformInterval": 300,
        f"{IGD}.DeviceInfo.Manufacturer": {"value": "Acme", "writable": False},
        f"{WLAN1}.SSID": "Shop",
        f"{WLAN1}.Channel": 6,
        f"{WLAN1}.BeaconType": "11i",
        f"{WLAN1}.IEEE11iAuthenticationMode": "PSKAuthentication",
        f"{WLAN1}.KeyPassphrase": "",
        f"{WLAN1}.PreSharedKey.1.KeyPassphrase": "",
    }


@pytest.fixture
def nbi():
    with FakeNbi() as fake:
        yield fake


@pytest.fixture
def data(tmp_path: Path, monkeypatch) -> Path:
    directory = tmp_path / "data"
    monkeypatch.setenv("ROUTER_MANAGER_DATA_DIR", str(directory))
    monkeypatch.setenv("ROUTER_MANAGER_CONFIG", str(tmp_path / "c.yaml"))
    return directory


@pytest.fixture
def acs_env(nbi, data, monkeypatch) -> Path:
    monkeypatch.setenv("ROUTER_MANAGER_ACS_URL", nbi.url)
    return data


def add(nbi: FakeNbi, leaves: dict[str, Any], serial: str = "000001", **kwargs: Any) -> str:
    return nbi.add_device(build_device(serial=serial, leaves=leaves, last_inform=nbi.now(), **kwargs))


@pytest.fixture
def router(nbi) -> str:
    return add(nbi, tr181_leaves())


def typed(monkeypatch, *answers: str) -> None:
    replies = iter(answers)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": next(replies))


def never_prompt(monkeypatch) -> None:
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": pytest.fail("must not prompt"))


def unattended(monkeypatch, value: str = PASS) -> None:
    monkeypatch.setenv("ROUTER_MANAGER_ASSUME_YES", "1")
    monkeypatch.setenv("ROUTER_MANAGER_WIFI_PASSPHRASE", value)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False, raising=False)
    never_prompt(monkeypatch)


class FakeTime:
    """Stands in for cli._clock and cli._sleep, so --wait costs no real time."""

    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def clock(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


@pytest.fixture
def fake_time(monkeypatch) -> FakeTime:
    fake = FakeTime()
    monkeypatch.setattr(cli, "_clock", fake.clock)
    monkeypatch.setattr(cli, "_sleep", fake.sleep)
    return fake


def one_error_line(err: str) -> str:
    """The single error line a failing command printed; asserts there is nothing else."""
    lines = [line for line in err.splitlines() if line.strip()]
    assert "Traceback" not in err
    errors = [line for line in lines if line.startswith("error: ")]
    assert len(errors) == 1, err
    return errors[0]


def posted(nbi: FakeNbi) -> list:
    return [r for r in nbi.requests_for("POST", "/devices/") if "/tasks" in r.path]


def run(argv: list[str], capsys) -> tuple[int, str, str]:
    code = cli.main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


# --- configuration ----------------------------------------------------------------------------


class TestConfiguration:
    @pytest.mark.parametrize(
        "argv",
        [
            ["acs", "status"],
            ["acs", "devices"],
            ["acs", "dump", "202BC1-BM632w-000001"],
            ["acs", "bootstrap"],
            ["acs", "wifi", "202BC1-BM632w-000001", "--band", "all"],
            ["acs", "job", "0123456789abcdef"],
        ],
    )
    def test_every_command_refuses_cleanly_without_an_acs_url(self, data, monkeypatch, capsys, argv):
        never_prompt(monkeypatch)
        code, out, err = run(argv, capsys)
        assert code == 1
        assert "ROUTER_MANAGER_ACS_URL is not set" in one_error_line(err)
        assert out == ""
        # Nothing is created for a feature that is off: no vault, no job file.
        assert not data.exists()

    def test_acs_alone_prints_its_help(self, data, capsys):
        code, out, _ = run(["acs"], capsys)
        assert code == 0
        assert "bootstrap" in out and "wifi" in out
        assert not data.exists()

    def test_the_service_shares_the_servers_data_dir_job_file_and_vault(self, acs_env, nbi, monkeypatch):
        monkeypatch.setenv("ROUTER_MANAGER_ACS_INFORM_INTERVAL", "900")
        monkeypatch.setenv("ROUTER_MANAGER_ACS_SCRUB_SECRETS", "0")
        acs = cli._acs_service()
        settings = web.Settings.from_env()
        assert acs.inform_interval == settings.acs_inform_interval == 900
        assert acs.scrub_secrets is settings.acs_scrub_secrets is False
        assert acs.client.base_url == settings.acs_url
        assert acs.data_dir == settings.data_dir == acs_env
        assert acs.jobs.path == acs_env / "acs_jobs.json"
        assert acs.secrets.directory == acs_env
        assert acs.client.base_url == nbi.url

    @pytest.mark.parametrize(("value", "expected"), [("", 300), ("600", 600), (" 86400 ", 86400), ("60", 60)])
    def test_inform_interval_is_read_from_the_environment(self, acs_env, monkeypatch, value, expected):
        monkeypatch.setenv("ROUTER_MANAGER_ACS_INFORM_INTERVAL", value)
        assert cli._acs_service().inform_interval == expected

    @pytest.mark.parametrize("value", ["59", "86401", "5m", "300.5", "-300"])
    def test_a_bad_inform_interval_is_refused_not_defaulted(self, acs_env, monkeypatch, capsys, value):
        """The bootstrap pushes this interval to every router, so a typo must not become 300."""
        monkeypatch.setenv("ROUTER_MANAGER_ACS_INFORM_INTERVAL", value)
        code, _, err = run(["acs", "status"], capsys)
        assert code == 1
        assert "ROUTER_MANAGER_ACS_INFORM_INTERVAL must be whole seconds from 60 to 86400" in one_error_line(err)

    @pytest.mark.parametrize(
        ("value", "expected"),
        [(None, True), ("", True), ("1", True), ("yes", True), ("0", False), ("false", False), ("OFF", False)],
    )
    def test_scrubbing_is_on_unless_switched_off(self, acs_env, monkeypatch, value, expected):
        if value is not None:
            monkeypatch.setenv("ROUTER_MANAGER_ACS_SCRUB_SECRETS", value)
        assert cli._acs_service().scrub_secrets is expected

    @pytest.mark.parametrize("name", ["ROUTER_MANAGER_ACS_SCRUB_SECRETS", "ROUTER_MANAGER_ACS_ALLOW_REMOTE"])
    def test_a_junk_flag_is_refused_as_the_server_refuses_it(self, acs_env, monkeypatch, capsys, name):
        monkeypatch.setenv(name, "maybe")
        code, out, err = run(["acs", "status"], capsys)
        assert code == 1
        assert name in one_error_line(err)
        assert out == ""
        assert not acs_env.exists()

    def test_a_remote_acs_is_refused_unless_explicitly_allowed(self, data, monkeypatch, capsys):
        # The NBI has no authentication (F3). Nothing here connects: the URL is checked first.
        monkeypatch.setenv("ROUTER_MANAGER_ACS_URL", "http://192.0.2.10:7557")
        code, _, err = run(["acs", "status"], capsys)
        assert code == 1
        assert "loopback" in one_error_line(err)
        monkeypatch.setenv("ROUTER_MANAGER_ACS_ALLOW_REMOTE", "0")
        with pytest.raises(ValueError, match="loopback"):
            cli._acs_service()
        monkeypatch.setenv("ROUTER_MANAGER_ACS_ALLOW_REMOTE", "1")
        assert cli._acs_service().client.base_url == "http://192.0.2.10:7557"

    def test_credentials_in_the_url_are_refused_without_being_echoed(self, data, monkeypatch, capsys):
        monkeypatch.setenv("ROUTER_MANAGER_ACS_URL", "http://ops:hunter2hunter2@127.0.0.1:7557")
        code, out, err = run(["acs", "status"], capsys)
        assert code == 1
        assert "credentials" in one_error_line(err)
        assert "hunter2hunter2" not in out + err

    def test_direct_commands_never_load_the_acs_package(self, tmp_path):
        env = {k: v for k, v in os.environ.items() if not k.startswith("ROUTER_MANAGER_")}
        env.update(
            HOME=str(tmp_path),
            PYTHONPATH=str(REPO),
            ROUTER_MANAGER_DATA_DIR=str(tmp_path / "data"),
            ROUTER_MANAGER_CONFIG=str(tmp_path / "c.yaml"),
        )
        script = (
            "import sys; from cudy_manager import cli; code = cli.main(['list']); "
            "print(code, 'cudy_manager.acs' in sys.modules)"
        )
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            check=True,
        )
        assert result.stdout.splitlines()[-1] == "0 False"

    def test_the_parser_choices_match_the_server(self):
        assert cli.ACS_BANDS == params.BAND_CHOICES
        assert cli.WIFI_RADIOS == web.SSID_RADIOS


# --- status -------------------------------------------------------------------------------------


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def seed_ui_preset(nbi: FakeNbi, name: str) -> None:
    # Roughly what the UI's wizard stores; only the name matters here.
    nbi.presets[name] = {
        "_id": name,
        "weight": 0,
        "channel": name,
        "events": {},
        "precondition": "",
        "configurations": [],
    }


class TestStatus:
    def test_before_the_bootstrap_it_says_what_to_run(self, acs_env, capsys):
        code, out, err = run(["acs", "status"], capsys)
        assert code == 1
        line = one_error_line(err)
        assert "not installed" in line and "'router-manager acs bootstrap'" in line
        health = json.loads(out)
        assert health["reachable"] is True and health["bootstrap"]["installed"] is False

    def test_after_the_bootstrap_it_passes(self, acs_env, nbi, capsys):
        assert run(["acs", "bootstrap"], capsys)[0] == 0
        code, out, err = run(["acs", "status"], capsys)
        assert code == 0, err
        assert json.loads(out)["bootstrap"]["installed"] is True
        assert "reachable" in err and "error" not in err

    def test_seeded_ui_presets_fail_it_even_when_installed(self, acs_env, nbi, capsys):
        assert run(["acs", "bootstrap"], capsys)[0] == 0
        seed_ui_preset(nbi, "inform")
        code, _, err = run(["acs", "status"], capsys)
        assert code == 1
        assert "--remove-seeded" in one_error_line(err)

    def test_a_missing_cr_secret_on_the_genieacs_host_is_reported(self, acs_env, nbi, router, capsys):
        assert run(["acs", "bootstrap"], capsys)[0] == 0
        fault_id = f"{router}:skybre-inform"
        nbi.faults[fault_id] = {
            "_id": fault_id,
            "device": router,
            "channel": "skybre-inform",
            "timestamp": iso(nbi.now()),
            "code": "ext.Error",
            "message": "SKYROUTER_CR_SECRET is unset or shorter than 32 hex characters",
            "detail": {"name": "Error"},
            "retries": 0,
        }
        code, _, err = run(["acs", "status"], capsys)
        assert code == 1
        line = one_error_line(err)
        assert "SKYROUTER_CR_SECRET" in line and "restart genieacs-cwmp" in line

    def test_other_provisioning_faults_are_a_warning(self, acs_env, nbi, router, capsys):
        assert run(["acs", "bootstrap"], capsys)[0] == 0
        fault_id = f"{router}:skybre-refresh"
        nbi.faults[fault_id] = {"_id": fault_id, "device": router, "channel": "skybre-refresh", "code": "script.Error"}
        code, _, err = run(["acs", "status"], capsys)
        assert code == 0
        assert "warning: 1 provisioning fault" in err

    def test_an_unreachable_acs_is_one_error_line(self, data, monkeypatch, capsys):
        monkeypatch.setenv("ROUTER_MANAGER_ACS_URL", f"http://127.0.0.1:{free_port()}")
        code, out, err = run(["acs", "status"], capsys)
        assert code == 1
        assert "is not usable" in one_error_line(err)
        assert json.loads(out)["reachable"] is False

    def test_an_unsupported_genieacs_version_fails(self, acs_env, nbi, capsys):
        nbi.version = "1.3.0-dev"
        code, _, err = run(["acs", "status"], capsys)
        assert code == 1
        assert "1.3.0-dev" in one_error_line(err)


# --- devices and dump -----------------------------------------------------------------------------


class TestDevices:
    def test_lists_every_router_with_the_total(self, acs_env, nbi, capsys):
        first = add(nbi, tr181_leaves(), serial="000001")
        second = add(nbi, tr181_leaves(), serial="000002", tags=("skybre_new",))
        code, out, _ = run(["acs", "devices"], capsys)
        assert code == 0
        listing = json.loads(out)
        assert listing["total"] == 2
        assert {device["acs_id"] for device in listing["devices"]} == {first, second}

        code, out, _ = run(["acs", "devices", "--tag", "skybre_new"], capsys)
        assert [device["acs_id"] for device in json.loads(out)["devices"]] == [second]
        code, out, _ = run(["acs", "devices", "--q", "000001"], capsys)
        assert [device["acs_id"] for device in json.loads(out)["devices"]] == [first]

    @pytest.mark.parametrize(
        "extra", [["--tag", "Not A Tag"], ["--limit", "0"], ["--limit", "201"], ["--q", "a b"], ["--skip", "-1"]]
    )
    def test_bad_filters_are_refused_before_reaching_the_nbi(self, acs_env, nbi, capsys, extra):
        code, out, err = run(["acs", "devices", *extra], capsys)
        assert code == 1
        one_error_line(err)
        assert out == ""
        assert nbi.requests_for("GET", "/devices") == []


class TestDump:
    def test_prints_the_tree_with_every_secret_redacted(self, acs_env, nbi, capsys):
        # GenieACS caches the plaintext it last sent (F15), and a vendor leaf may
        # carry the passphrase under a name that does not look secret.
        router = add(nbi, tr181_leaves(**{KEY1: PASS, "Device.DeviceInfo.X_ACME_Note": f"wifi={PASS}"}))
        code, out, err = run(["acs", "dump", router], capsys)
        assert code == 0, err
        assert PASS not in out + err
        tree = json.loads(out)
        leaf = tree["Device"]["WiFi"]["AccessPoint"]["1"]["Security"]["KeyPassphrase"]
        assert leaf["_redacted"] is True and leaf["present"] is True
        assert tree["Device"]["DeviceInfo"]["X_ACME_Note"]["_redacted"] is True
        assert tree["Device"]["WiFi"]["SSID"]["1"]["SSID"]["_value"] == "Home"

    def test_the_vaults_passphrases_are_redacted_by_value(self, acs_env, nbi, capsys):
        vendor_leaf = "Device.DeviceInfo.X_ACME_Note"
        router = add(nbi, tr181_leaves(**{vendor_leaf: f"wifi={PASS}"}))
        SecretStore(acs_env).put(PASS, vault_ref(router, "2.4GHz", "current"))
        code, out, _ = run(["acs", "dump", router], capsys)
        assert code == 0
        assert PASS not in out
        assert json.loads(out)["Device"]["DeviceInfo"]["X_ACME_Note"]["_redacted"] is True

    def test_an_unknown_router_is_one_error_line(self, acs_env, nbi, capsys):
        code, out, err = run(["acs", "dump", "202BC1-BM632w-999999"], capsys)
        assert code == 1
        assert "GenieACS has no device 202BC1-BM632w-999999" in one_error_line(err)
        assert out == ""

    def test_a_malformed_id_never_reaches_the_nbi(self, acs_env, nbi, capsys):
        code, _, err = run(["acs", "dump", "../../config"], capsys)
        assert code == 1
        one_error_line(err)
        assert nbi.requests == []


# --- bootstrap --------------------------------------------------------------------------------------


class TestBootstrap:
    def test_installs_then_a_second_run_writes_nothing(self, acs_env, nbi, capsys):
        code, out, _ = run(["acs", "bootstrap"], capsys)
        assert code == 0
        lines = out.splitlines()
        assert lines[0] == f"GenieACS {nbi.version}"
        assert "provision skybre-inform: created" in lines
        assert "preset skybre-registered: created" in lines
        assert lines[-1] == "writes: 7"

        code, out, _ = run(["acs", "bootstrap"], capsys)
        assert code == 0
        assert "provision skybre-inform: unchanged" in out.splitlines()
        assert out.splitlines()[-1] == "writes: 0"

    def test_uses_the_configured_inform_interval(self, acs_env, nbi, monkeypatch, capsys):
        monkeypatch.setenv("ROUTER_MANAGER_ACS_INFORM_INTERVAL", "900")
        assert run(["acs", "bootstrap"], capsys)[0] == 0
        assert nbi.presets["skybre-inform"]["configurations"][0]["args"] == [900]

    def test_refuses_while_ui_presets_exist_and_says_how_to_proceed(self, acs_env, nbi, capsys):
        seed_ui_preset(nbi, "default")
        code, out, err = run(["acs", "bootstrap"], capsys)
        assert code == 1
        assert "router-manager acs bootstrap --remove-seeded" in one_error_line(err)
        assert out == ""
        assert nbi.provisions == {} and set(nbi.presets) == {"default"}

        code, out, _ = run(["acs", "bootstrap", "--remove-seeded"], capsys)
        assert code == 0
        assert "removed seeded preset default" in out.splitlines()
        assert "default" not in nbi.presets

    def test_refuses_a_genieacs_that_is_not_1_2(self, acs_env, nbi, capsys):
        nbi.version = "1.3.0-dev"
        code, _, err = run(["acs", "bootstrap"], capsys)
        assert code == 1
        one_error_line(err)
        assert nbi.provisions == {} and nbi.presets == {}


# --- wifi ---------------------------------------------------------------------------------------------


def assert_no_secret(capsys_text: str, data_dir: Path) -> None:
    assert PASS not in capsys_text
    jobs = data_dir / "acs_jobs.json"
    if jobs.exists():
        assert PASS not in jobs.read_text()


class TestWifi:
    def test_typed_twice_starts_a_job_that_the_server_can_follow(self, acs_env, nbi, router, monkeypatch, capsys):
        typed(monkeypatch, PASS, PASS)
        code, out, err = run(["acs", "wifi", router, "--band", "all"], capsys)
        assert code == 0, err
        assert_no_secret(out + err, acs_env)
        job = json.loads(out)
        assert job["kind"] == "wifi" and job["request"]["passphrase"] is True
        assert job["state"] == "contacting_router"
        assert f"router-manager acs job {job['id']} --wait" in err
        # The server's own service sees the same job and the pending passphrase.
        server = cli._acs_service()
        assert server.get_job(job["id"])["state"] == "contacting_router"
        assert server.secrets.get(job["vault_refs"]["pending"]) == PASS

    def test_wait_follows_the_job_to_its_verdict(self, acs_env, nbi, router, monkeypatch, capsys, fake_time):
        nbi.set_cr_outcome(router, 200, session=True)
        unattended(monkeypatch)
        code, out, err = run(["acs", "wifi", router, "--band", "5GHz", "--wait", "60"], capsys)
        assert code == 0, err
        assert_no_secret(out + err, acs_env)
        job = json.loads(out)
        assert job["state"] == "acknowledged" and job["terminal"] is True
        assert "acknowledged: The router accepted the new password" in err
        # What the router itself now holds, not what it would read back.
        assert nbi.cpes[router].leaves[KEY2].value == PASS
        assert nbi.cpes[router].leaves[KEY1].value == ""

    def test_wait_advances_the_job_itself_when_no_server_is_running(
        self, acs_env, nbi, router, monkeypatch, capsys, fake_time
    ):
        unattended(monkeypatch)
        code, out, _ = run(["acs", "wifi", router, "--band", "all"], capsys)
        job_id = json.loads(out)["id"]
        nbi.run_session(router)

        code, out, err = run(["acs", "job", job_id, "--wait", "30"], capsys)
        assert code == 0, err
        assert json.loads(out)["state"] == "acknowledged"
        assert fake_time.sleeps and all(pause <= cli.JOB_POLL_SECONDS for pause in fake_time.sleeps)

    def test_a_router_that_cannot_be_reached_is_still_pending_after_the_wait(
        self, acs_env, nbi, router, monkeypatch, capsys, fake_time
    ):
        nbi.set_cr_outcome(router, 504)
        unattended(monkeypatch)
        code, out, err = run(["acs", "wifi", router, "--band", "all", "--wait", "10"], capsys)
        assert code == 1
        job = json.loads(out)
        assert job["state"] == "waiting_for_checkin"
        line = one_error_line(err)
        assert "has not finished (waiting_for_checkin)" in line
        assert f"router-manager acs job {job['id']} --wait" in line
        assert fake_time.now == 10

    def test_ctrl_c_while_waiting_leaves_the_job_running(self, acs_env, nbi, router, monkeypatch, capsys):
        nbi.set_cr_outcome(router, 504)
        unattended(monkeypatch)

        def interrupt(seconds: float) -> None:
            raise KeyboardInterrupt

        monkeypatch.setattr(cli, "_sleep", interrupt)
        code, out, err = run(["acs", "wifi", router, "--band", "all", "--wait", "60"], capsys)
        assert code == 1
        assert "has not finished" in one_error_line(err)
        assert cli._acs_service().get_job(json.loads(out)["id"])["state"] == "waiting_for_checkin"

    def test_a_rejected_change_exits_nonzero_with_the_routers_fault(
        self, acs_env, nbi, router, monkeypatch, capsys, fake_time
    ):
        nbi.inject_fault(router, KEY1, code="cwmp.9007", message="Invalid parameter value")
        nbi.set_cr_outcome(router, 200, session=True)
        unattended(monkeypatch)
        code, out, err = run(["acs", "wifi", router, "--band", "2.4GHz", "--wait", "120"], capsys)
        assert code == 1
        assert_no_secret(out + err, acs_env)
        assert json.loads(out)["state"] == "rejected"
        assert "rejected" in one_error_line(err)

    def test_ssid_only_asks_for_no_passphrase(self, acs_env, nbi, router, monkeypatch, capsys):
        never_prompt(monkeypatch)
        code, out, err = run(["acs", "wifi", router, "--band", "all", "--ssid", "Cafe", "--keep-passphrase"], capsys)
        assert code == 0, err
        job = json.loads(out)
        assert job["request"] == {"band": "all", "ssid": "Cafe", "passphrase": False, "confirm_guessed_band": False}
        assert "vault_refs" not in job or not job["vault_refs"]

    def test_keep_passphrase_without_an_ssid_changes_nothing(self, acs_env, nbi, router, monkeypatch, capsys):
        never_prompt(monkeypatch)
        code, _, err = run(["acs", "wifi", router, "--band", "all", "--keep-passphrase"], capsys)
        assert code == 1
        assert "--keep-passphrase needs --ssid" in one_error_line(err)
        assert posted(nbi) == []

    @pytest.mark.parametrize("ssid", ["", "x" * 33, "bad\nname"])
    def test_a_bad_ssid_is_refused_before_the_passphrase_is_asked(
        self, acs_env, nbi, router, monkeypatch, capsys, ssid
    ):
        never_prompt(monkeypatch)
        monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)
        code, _, err = run(["acs", "wifi", router, "--band", "all", "--ssid", ssid], capsys)
        assert code == 1
        assert "SSID" in one_error_line(err)
        assert nbi.requests == []

    def test_mismatched_confirmation_changes_nothing(self, acs_env, nbi, router, monkeypatch, capsys):
        typed(monkeypatch, PASS, PASS + "x")
        code, out, err = run(["acs", "wifi", router, "--band", "all"], capsys)
        assert code == 1
        assert "passphrases did not match, nothing was changed" in one_error_line(err)
        assert_no_secret(out + err, acs_env)
        assert posted(nbi) == []
        assert SecretStore(acs_env).references() == []

    @pytest.mark.parametrize("interruption", [EOFError, KeyboardInterrupt])
    def test_an_abandoned_prompt_is_one_error_line(self, acs_env, nbi, router, monkeypatch, capsys, interruption):
        monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)

        def abandon(prompt: str = "") -> str:
            raise interruption

        monkeypatch.setattr(cli.getpass, "getpass", abandon)
        code, _, err = run(["acs", "wifi", router, "--band", "all"], capsys)
        assert code == 1
        assert "no passphrase was entered" in one_error_line(err)
        assert posted(nbi) == []

    def test_non_interactive_without_opt_in_refuses(self, acs_env, nbi, router, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin.isatty", lambda: False, raising=False)
        never_prompt(monkeypatch)
        code, _, err = run(["acs", "wifi", router, "--band", "all"], capsys)
        assert code == 1
        line = one_error_line(err)
        assert "interactive terminal" in line and "ROUTER_MANAGER_WIFI_PASSPHRASE" in line
        assert posted(nbi) == []

    def test_opt_in_never_reuses_the_router_admin_password(self, acs_env, nbi, router, monkeypatch, capsys):
        """ROUTER_MANAGER_DEVICE_PASSWORD is set-password's; it must not become the Wi-Fi passphrase."""
        monkeypatch.setenv("ROUTER_MANAGER_ASSUME_YES", "1")
        monkeypatch.setenv("ROUTER_MANAGER_DEVICE_PASSWORD", ADMIN)
        code, out, err = run(["acs", "wifi", router, "--band", "all"], capsys)
        assert code == 1
        assert "ROUTER_MANAGER_WIFI_PASSPHRASE is empty" in one_error_line(err)
        assert posted(nbi) == []
        assert ADMIN not in out + err

    @pytest.mark.parametrize("value", ["short", "x" * 64, "café-café-café"])
    def test_an_invalid_passphrase_is_refused_without_being_echoed(
        self, acs_env, nbi, router, monkeypatch, capsys, value
    ):
        unattended(monkeypatch, value)
        code, out, err = run(["acs", "wifi", router, "--band", "all"], capsys)
        assert code == 1
        assert "Wi-Fi password" in one_error_line(err)
        assert value not in out + err
        assert posted(nbi) == []

    def test_a_guessed_band_needs_confirming_and_nothing_is_stored_until_then(
        self, acs_env, nbi, monkeypatch, capsys
    ):
        router = add(nbi, tr098_guessed_leaves(), serial="000098")
        unattended(monkeypatch)
        code, out, err = run(["acs", "wifi", router, "--band", "2.4GHz"], capsys)
        assert code == 1
        assert_no_secret(out + err, acs_env)
        assert "--confirm-guessed-band" in one_error_line(err)
        plan = json.loads(out)
        assert plan["band_guessed"] is True
        assert posted(nbi) == []
        assert SecretStore(acs_env).references() == []

        code, out, err = run(["acs", "wifi", router, "--band", "2.4GHz", "--confirm-guessed-band"], capsys)
        assert code == 0, err
        assert json.loads(out)["request"]["confirm_guessed_band"] is True

    def test_an_unknown_router_is_one_error_line_and_stores_nothing(self, acs_env, nbi, monkeypatch, capsys):
        unattended(monkeypatch)
        code, out, err = run(["acs", "wifi", "202BC1-BM632w-999999", "--band", "all"], capsys)
        assert code == 1
        assert "No such device" in one_error_line(err)
        assert_no_secret(out + err, acs_env)
        assert SecretStore(acs_env).references() == []

    def test_an_nbi_crash_is_one_error_line_and_leaks_nothing(self, acs_env, nbi, router, monkeypatch, capsys):
        unattended(monkeypatch)
        nbi.crash_next(count=20)
        code, out, err = run(["acs", "wifi", router, "--band", "all"], capsys)
        assert code == 1
        one_error_line(err)
        assert_no_secret(out + err, acs_env)

    @pytest.mark.parametrize(
        "argv",
        [
            ["acs", "wifi", "202BC1-BM632w-000001", "--band", "all", PASS],
            ["acs", "wifi", "202BC1-BM632w-000001", "--band", "all", "--passphrase", PASS],
            ["acs", "wifi", "202BC1-BM632w-000001", "--band", "2.4G"],
            ["acs", "wifi", "202BC1-BM632w-000001"],
            ["acs", "wifi", "202BC1-BM632w-000001", "--band", "all", "--wait", "-1"],
        ],
    )
    def test_the_passphrase_is_never_an_argument_and_usage_errors_exit_nonzero(self, acs_env, argv):
        with pytest.raises(SystemExit) as exc:
            cli.main(argv)
        assert exc.value.code != 0


class TestJob:
    def test_shows_a_job_without_advancing_it(self, acs_env, nbi, router, monkeypatch, capsys):
        unattended(monkeypatch)
        _, out, _ = run(["acs", "wifi", router, "--band", "all"], capsys)
        job_id = json.loads(out)["id"]
        requests = len(nbi.requests)
        code, out, err = run(["acs", "job", job_id], capsys)
        assert code == 0
        assert json.loads(out)["id"] == job_id
        assert f"wifi job {job_id} contacting_router" in err
        assert len(nbi.requests) == requests

    @pytest.mark.parametrize(("job_id", "message"), [("not-a-job", "16 lowercase hex"), ("0" * 16, "No such job")])
    def test_bad_or_unknown_ids_are_one_error_line(self, acs_env, capsys, job_id, message):
        code, _, err = run(["acs", "job", job_id], capsys)
        assert code == 1
        assert message in one_error_line(err)

    def test_a_damaged_job_file_is_one_error_line(self, acs_env, capsys):
        acs_env.mkdir(parents=True, exist_ok=True)
        (acs_env / "acs_jobs.json").write_text("{not json")
        code, _, err = run(["acs", "job", "0" * 16], capsys)
        assert code == 1
        assert "corrupt" in one_error_line(err)


class TestWarnings:
    def test_log_records_become_single_warning_lines_without_tracebacks(self, capsys):
        log = logging.getLogger("cudy_manager.acs.service")
        with cli._warnings_as_lines():
            try:
                raise RuntimeError("boom")
            except RuntimeError:
                log.exception("could not advance\njob 1")
        err = capsys.readouterr().err
        assert err == "warning: could not advance job 1\n"
        # Removed afterwards, so nothing lingers into the next command.
        assert not any(isinstance(h, cli._WarningLine) for h in logging.getLogger("cudy_manager").handlers)

    def test_the_handler_is_removed_even_when_a_command_fails(self, data, capsys):
        assert run(["acs", "status"], capsys)[0] == 1
        assert not any(isinstance(h, cli._WarningLine) for h in logging.getLogger("cudy_manager").handlers)


# --- wifi-password (direct devices) --------------------------------------------------------------------


@pytest.fixture
def workspace(tmp_path: Path, data, monkeypatch) -> DeviceManager:
    manager = DeviceManager(config_path=tmp_path / "c.yaml", data_dir=data, secret_store=SecretStore(data))
    manager.add_device("r1", "192.0.2.1", "cudy", password=ADMIN)
    monkeypatch.setattr(cli, "_manager", lambda: manager)
    return manager


@pytest.fixture
def calls(workspace, monkeypatch) -> list[tuple[str, str, str | None]]:
    """Records set_wifi_password instead of contacting a router."""
    seen: list[tuple[str, str, str | None]] = []

    def record(identifier: str, password: str, radio: str | None = None) -> bool:
        seen.append((identifier, password, radio))
        return True

    monkeypatch.setattr(workspace, "set_wifi_password", record)
    return seen


class TestWifiPassword:
    def test_typed_twice_changes_every_band(self, calls, monkeypatch, capsys):
        typed(monkeypatch, PASS, PASS)
        code, out, err = run(["wifi-password", "r1"], capsys)
        assert code == 0, err
        assert calls == [("r1", PASS, None)]
        assert json.loads(out) == {"device": "r1", "radio": "all", "status": "changed"}
        assert PASS not in out + err

    @pytest.mark.parametrize("radio", ["2.4G", "5G"])
    def test_one_radio(self, calls, monkeypatch, capsys, radio):
        typed(monkeypatch, PASS, PASS)
        assert run(["wifi-password", "r1", "--radio", radio], capsys)[0] == 0
        assert calls == [("r1", PASS, radio)]

    def test_named_by_host(self, calls, monkeypatch, capsys):
        typed(monkeypatch, PASS, PASS)
        code, out, _ = run(["wifi-password", "192.0.2.1"], capsys)
        assert code == 0
        assert calls == [("r1", PASS, None)]
        assert json.loads(out)["device"] == "r1"

    def test_unattended_uses_its_own_variable_only(self, calls, monkeypatch, capsys):
        monkeypatch.setenv("ROUTER_MANAGER_DEVICE_PASSWORD", ADMIN)
        unattended(monkeypatch)
        assert run(["wifi-password", "r1"], capsys)[0] == 0
        assert calls == [("r1", PASS, None)]

        monkeypatch.delenv("ROUTER_MANAGER_WIFI_PASSPHRASE")
        code, _, err = run(["wifi-password", "r1"], capsys)
        assert code == 1
        assert "ROUTER_MANAGER_WIFI_PASSPHRASE is empty" in one_error_line(err)
        assert len(calls) == 1

    def test_mismatch_changes_nothing(self, calls, monkeypatch, capsys):
        typed(monkeypatch, PASS, "something-else")
        code, _, err = run(["wifi-password", "r1"], capsys)
        assert code == 1
        assert "did not match" in one_error_line(err)
        assert calls == []

    def test_an_unknown_device_fails_before_the_prompt(self, calls, monkeypatch, capsys):
        never_prompt(monkeypatch)
        code, _, err = run(["wifi-password", "ghost"], capsys)
        assert code == 1
        assert "does not exist" in one_error_line(err)

    @pytest.mark.parametrize("value", ["short", "f" * 64])
    def test_an_invalid_passphrase_never_reaches_the_router(self, calls, monkeypatch, capsys, value):
        unattended(monkeypatch, value)
        code, out, err = run(["wifi-password", "r1"], capsys)
        assert code == 1
        assert "Wi-Fi password" in one_error_line(err)
        assert value not in out + err
        assert calls == []

    def test_an_unconfirmed_change_exits_nonzero(self, workspace, monkeypatch, capsys):
        monkeypatch.setattr(workspace, "set_wifi_password", lambda identifier, password, radio=None: False)
        unattended(monkeypatch)
        code, _, err = run(["wifi-password", "r1"], capsys)
        assert code == 1
        assert "did not confirm" in one_error_line(err)

    @pytest.mark.parametrize(
        "error",
        [
            AdapterError(f"router answered 500:\n<input name=key value={PASS}>"),
            UnsupportedOperation("Wi-Fi password changes are not supported by this adapter"),
            ValidationError("the router refused it"),
            OSError("Network is unreachable"),
        ],
    )
    def test_router_errors_are_one_line_with_the_passphrase_scrubbed(self, workspace, monkeypatch, capsys, error):
        def fail(identifier: str, password: str, radio: str | None = None) -> bool:
            raise error

        monkeypatch.setattr(workspace, "set_wifi_password", fail)
        unattended(monkeypatch)
        code, out, err = run(["wifi-password", "r1"], capsys)
        assert code == 1
        line = one_error_line(err)
        assert PASS not in out + err
        assert line.startswith("error: ")

    def test_the_passphrase_is_never_an_argument(self, workspace):
        with pytest.raises(SystemExit) as exc:
            cli.main(["wifi-password", "r1", PASS])
        assert exc.value.code != 0
        with pytest.raises(SystemExit):
            cli.main(["wifi-password", "r1", "--radio", "6G"])


class TestSharedPrompt:
    def test_set_password_keeps_its_wording_and_variable(self, workspace, monkeypatch, capsys):
        monkeypatch.setenv("ROUTER_MANAGER_ASSUME_YES", "1")
        monkeypatch.setenv("ROUTER_MANAGER_WIFI_PASSPHRASE", PASS)
        code, _, err = run(["set-password", "r1", "--no-verify"], capsys)
        assert code == 1
        assert "ROUTER_MANAGER_DEVICE_PASSWORD is empty" in err
        assert workspace.credentials(workspace.get_device("r1")) == ADMIN

    def test_set_password_ctrl_d_is_an_error_line_not_a_traceback(self, workspace, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", io.StringIO(""))
        monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)

        def abandon(prompt: str = "") -> str:
            raise EOFError

        monkeypatch.setattr(cli.getpass, "getpass", abandon)
        code, _, err = run(["set-password", "r1", "--no-verify"], capsys)
        assert code == 1
        assert "no password was entered, nothing was changed" in one_error_line(err)
        assert workspace.credentials(workspace.get_device("r1")) == ADMIN

    def test_scrub_reaches_nested_values(self):
        value = {"a": [f"x{PASS}y", {"b": (PASS,)}], PASS: 1, "n": 5}
        assert cli._scrub(value, [PASS]) == {"a": ["x<redacted>y", {"b": ["<redacted>"]}], "<redacted>": 1, "n": 5}
        assert cli._scrub("unchanged", ["", PASS]) == "unchanged"
