"""The command line for the activity log, router firmware and maintenance plans.

Each command runs as a user would run it: cli.main builds its own DeviceManager
from ROUTER_MANAGER_DATA_DIR, so these tests prove it writes to the server's
activity log, not only that the log works. Routers are fake_router's reconstructed
AP1300 on 127.0.0.1 and the fake NBI.
"""

import io
import json
from pathlib import Path
from typing import Any

import pytest
from fake_nbi import FakeNbi, build_device
from fake_router import FakeRouter, ap1300_autoupgrade_page
from test_acs_firmware import CONTENT, NEW, OUI, PRODUCT, cudy

from cudy_manager import adapters, cli
from cudy_manager.acs import service as service_module
from cudy_manager.acs.service import AcsService
from cudy_manager.activity import ActivityLog
from cudy_manager.maintenance import MaintenanceStore
from cudy_manager.manager import DeviceManager
from cudy_manager.secrets import SecretStore

ACTOR = "cli (ops)"
ROUTER_PASSWORD = "goodpass"  # what fake_router's AP1300 accepts for admin
WIFI_PASS = "correct-Horse-Battery-9"
NEW_ADMIN = "rotated-admin-password"
CURRENT = "2.5.25-20260820-141832"
NEWER = "2.5.26-20261001-101010"


@pytest.fixture
def data(tmp_path: Path, monkeypatch) -> Path:
    directory = tmp_path / "data"
    monkeypatch.setenv("ROUTER_MANAGER_DATA_DIR", str(directory))
    monkeypatch.setenv("ROUTER_MANAGER_CONFIG", str(tmp_path / "c.yaml"))
    for name in (
        "ROUTER_MANAGER_ASSUME_YES",
        "ROUTER_MANAGER_DEVICE_PASSWORD",
        "ROUTER_MANAGER_WIFI_PASSPHRASE",
        "ROUTER_MANAGER_ACS_URL",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(cli.getpass, "getuser", lambda: "ops")
    monkeypatch.setattr(adapters, "_CUDY_CHECK_POLL", 0.01)
    return directory


@pytest.fixture
def router():
    with FakeRouter("ap1300") as fake:
        yield fake


def setup_manager(data: Path) -> DeviceManager:
    """The same inventory the CLI loads, without an activity log so setup is not logged."""
    return DeviceManager(config_path=data.parent / "c.yaml", data_dir=data, secret_store=SecretStore(data))


def add_router(data: Path, router: FakeRouter | None = None, identifier: str = "r1", **values: Any) -> None:
    host, port = ("127.0.0.1", router.port) if router is not None else ("192.0.2.1", 80)
    vendor = values.pop("vendor", "cudy")
    setup_manager(data).add_device(
        identifier, host, vendor, password=ROUTER_PASSWORD, username="admin", http_port=port, **values
    )


def logged(data: Path, **filters: Any) -> list[dict[str, Any]]:
    return ActivityLog(data).list(**filters)


def run(argv: list[str], capsys) -> tuple[int, str, str]:
    code = cli.main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def one_error_line(err: str) -> str:
    assert "Traceback" not in err
    errors = [line for line in err.splitlines() if line.startswith("error: ")]
    assert len(errors) == 1, err
    return errors[0]


class Terminal(io.StringIO):
    """Typed answers on a stdin that says it is a terminal."""

    def isatty(self) -> bool:
        return True


def plan(data: Path, **overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "name": "Weekly check",
        "targets": {"devices": ["r1"]},
        "schedule": {"days": ["tue"], "start": "03:00", "duration_minutes": 60, "timezone": "UTC"},
        "actions": ["firmware_check"],
        "guards": {"min_uptime_seconds": 0},
    }
    body.update(overrides)
    return MaintenanceStore(data).create(body)


# --- who made the change ---------------------------------------------------------------------------


class TestActor:
    def test_the_actor_is_the_login_name(self, data):
        assert cli._actor() == ACTOR

    @pytest.mark.parametrize("error", [OSError("no login name"), KeyError("uid 1234")])
    def test_no_login_name_still_names_the_cli(self, data, monkeypatch, error):
        def fail() -> str:
            raise error

        monkeypatch.setattr(cli.getpass, "getuser", fail)
        assert cli._actor() == "cli (unknown)"

    def test_the_manager_writes_the_servers_log(self, data):
        manager = cli._manager()
        assert isinstance(manager.activity, ActivityLog)
        assert manager.activity.path == data / "activity.jsonl"
        assert manager.data_dir == data and manager.config_path == data.parent / "c.yaml"

    def test_a_reboot_is_logged_as_the_cli_user(self, data, router, capsys):
        add_router(data, router)
        code, out, err = run(["reboot", "r1"], capsys)
        assert code == 0, err
        assert router.state["reboots"] == 1
        [entry] = logged(data)
        assert (entry["who"], entry["kind"], entry["result"], entry["router"]) == (ACTOR, "reboot", "applied", "r1")

    def test_add_and_set_password_are_logged_without_the_passwords(self, data, monkeypatch, capsys):
        monkeypatch.setattr("sys.stdin", io.StringIO("first-admin-password\n"))
        assert run(["add", "r1", "192.0.2.1", "--no-verify"], capsys)[0] == 0
        monkeypatch.setenv("ROUTER_MANAGER_ASSUME_YES", "1")
        monkeypatch.setenv("ROUTER_MANAGER_DEVICE_PASSWORD", NEW_ADMIN)
        assert run(["set-password", "r1", "--no-verify"], capsys)[0] == 0
        credentials, setup = logged(data)
        assert (setup["who"], setup["kind"]) == (ACTOR, "setup")
        assert (credentials["who"], credentials["kind"]) == (ACTOR, "credentials")
        text = (data / "activity.jsonl").read_text()
        assert "first-admin-password" not in text and NEW_ADMIN not in text

    def test_a_wifi_passphrase_change_is_logged_without_it(self, data, router, monkeypatch, capsys):
        add_router(data, router)
        monkeypatch.setenv("ROUTER_MANAGER_ASSUME_YES", "1")
        monkeypatch.setenv("ROUTER_MANAGER_WIFI_PASSPHRASE", WIFI_PASS)
        code, out, err = run(["wifi-password", "r1", "--radio", "5G"], capsys)
        assert code == 0, err
        assert router.state["wifi"]["wlan10"]["key"] == WIFI_PASS
        [entry] = logged(data)
        assert (entry["who"], entry["kind"], entry["result"]) == (ACTOR, "wifi", "applied")
        assert WIFI_PASS not in (data / "activity.jsonl").read_text()

    def test_acs_commands_share_the_log_and_name_the_cli_user(self, data, monkeypatch, capsys):
        with FakeNbi() as nbi:
            monkeypatch.setenv("ROUTER_MANAGER_ACS_URL", nbi.url)
            service = cli._acs_service()
            assert isinstance(service.activity, ActivityLog)
            assert service.activity.path == data / "activity.jsonl"
            leaves = {
                "Device.ManagementServer.ConnectionRequestURL": {"value": "http://10.10.0.40:7547/", "writable": False},
                "Device.WiFi.Radio.1.OperatingFrequencyBand": "2.4GHz",
                "Device.WiFi.SSID.1.SSID": "Home",
                "Device.WiFi.SSID.1.LowerLayers": "Device.WiFi.Radio.1.",
                "Device.WiFi.AccessPoint.1.SSIDReference": "Device.WiFi.SSID.1.",
                "Device.WiFi.AccessPoint.1.Security.ModeEnabled": "WPA2-Personal",
                "Device.WiFi.AccessPoint.1.Security.KeyPassphrase": "",
            }
            acs_id = nbi.add_device(build_device(serial="000001", leaves=leaves, last_inform=nbi.now()))
            argv = ["acs", "wifi", acs_id, "--band", "all", "--ssid", "Shop", "--keep-passphrase"]
            code, out, err = run(argv, capsys)
        assert code == 0, err
        assert json.loads(out)["actor"] == ACTOR


# --- the activity log ------------------------------------------------------------------------------


class TestActivityCommand:
    def _fill(self, data: Path) -> list[dict[str, Any]]:
        log = ActivityLog(data)
        made = [
            log.record(who="alice", router="r1", kind="wifi", what="Wi-Fi name changed", result="applied"),
            log.record(who="bob", router="r2", kind="reboot", what="Reboot started", result="applied"),
            log.record(who="alice", router="acs:80AFCA-AP1300-000001", kind="firmware", what="=cmd", result="queued"),
        ]
        return list(reversed(made))

    def test_json_newest_first_with_filters(self, data, capsys):
        newest = self._fill(data)
        code, out, _ = run(["activity"], capsys)
        assert code == 0 and json.loads(out) == newest
        assert json.loads(run(["activity", "--router", "r1"], capsys)[1]) == [newest[2]]
        assert json.loads(run(["activity", "--kind", "reboot"], capsys)[1]) == [newest[1]]
        assert json.loads(run(["activity", "--who", "alice", "--limit", "1"], capsys)[1]) == [newest[0]]
        assert json.loads(run(["activity", "--before", newest[0]["id"]], capsys)[1]) == newest[1:]

    def test_csv_has_every_entry_unless_limited(self, data, capsys):
        log = ActivityLog(data)
        for index in range(205):
            log.record(who="alice", router="r1", kind="reboot", what=f"Reboot {index}", result="applied")
        assert len(json.loads(run(["activity"], capsys)[1])) == 200
        code, out, _ = run(["activity", "--csv"], capsys)
        rows = [line for line in out.split("\r\n") if line]
        assert code == 0 and rows[0] == "at,who,router,router_name,kind,result,what,details,id"
        assert len(rows) == 206
        limited = [line for line in run(["activity", "--csv", "--limit", "2"], capsys)[1].split("\r\n") if line]
        assert len(limited) == 3 and "Reboot 204" in limited[1]

    def test_a_formula_is_quoted_in_the_csv(self, data, capsys):
        self._fill(data)
        assert ",'=cmd," in run(["activity", "--csv"], capsys)[1]

    @pytest.mark.parametrize("argv", [["--kind", "bogus"], ["--limit", "0"], ["--limit", "ten"]])
    def test_bad_arguments_are_usage_errors(self, data, argv):
        with pytest.raises(SystemExit) as exc:
            cli.main(["activity", *argv])
        assert exc.value.code == 2

    @pytest.mark.parametrize("argv", [["--limit", "5000"], ["--before", "last tuesday"]])
    def test_refused_queries_are_one_error_line(self, data, capsys, argv):
        self._fill(data)
        code, out, err = run(["activity", *argv], capsys)
        assert code == 1 and out == ""
        one_error_line(err)

    def test_it_reads_the_log_even_when_the_device_config_is_broken(self, data, capsys):
        newest = self._fill(data)
        (data.parent / "c.yaml").write_text("devices: {r1: [unclosed\n")
        code, out, _ = run(["activity"], capsys)
        assert code == 0 and json.loads(out) == newest

    def test_no_log_is_an_empty_list_and_creates_nothing(self, data, capsys):
        code, out, _ = run(["activity"], capsys)
        assert code == 0 and json.loads(out) == []
        assert not data.exists()


# --- firmware on a directly managed router ---------------------------------------------------------


class TestFirmwareCommand:
    def test_status(self, data, router, capsys):
        add_router(data, router)
        code, out, err = run(["firmware", "status", "r1"], capsys)
        assert code == 0, err
        assert json.loads(out) == {
            "device": "r1",
            "firmware": {
                "version": CURRENT,
                "hardware": "AP1300 V1.1",
                "auto_update": {"enabled": True, "window_start_hour": 3, "window": "03:00-05:00"},
                "source": "cudy-luci",
            },
        }
        assert logged(data) == []

    def test_a_check_that_finds_newer_firmware_installs_nothing(self, data, router, capsys):
        add_router(data, router)
        notice = f'<div class="alert alert-info">New firmware v{NEWER} found.</div>'
        router.state["check_result_html"] = ap1300_autoupgrade_page(router.state["autoupgrade"], notice)
        code, out, err = run(["firmware", "check", "r1"], capsys)
        assert code == 0, err
        body = json.loads(out)
        assert body["installed"] is False and body["check"]["available"] is True
        assert f"{NEWER} is available" in err and "nothing was installed" in err
        assert router.state["autoupgrade_posts"] == []
        [entry] = logged(data)
        assert (entry["who"], entry["kind"], entry["result"]) == (ACTOR, "firmware", "info")

    def test_an_unrecognised_answer_exits_1(self, data, router, capsys):
        add_router(data, router)
        code, out, err = run(["firmware", "check", "r1"], capsys)
        assert code == 1
        assert json.loads(out)["check"]["available"] is None
        assert "could not tell" in one_error_line(err)

    def test_auto_update_on_with_a_window_then_off(self, data, router, capsys):
        add_router(data, router)
        code, out, err = run(["firmware", "auto-update", "r1", "--on", "--window", "22"], capsys)
        assert code == 0, err
        assert json.loads(out) == {"device": "r1", "auto_update": "on", "window_start_hour": 22}
        assert router.state["autoupgrade"] == {"auto_upgrade": "1", "upgrade_time": "22"}
        assert run(["firmware", "auto-update", "r1", "--off"], capsys)[0] == 0
        assert router.state["autoupgrade"]["auto_upgrade"] == "0"
        assert [(entry["who"], entry["result"]) for entry in logged(data)] == [(ACTOR, "applied")] * 2

    def test_a_window_with_off_is_refused_before_the_router_is_contacted(self, data, router, capsys):
        add_router(data, router)
        code, _, err = run(["firmware", "auto-update", "r1", "--off", "--window", "3"], capsys)
        assert code == 1 and "--window" in one_error_line(err)
        assert router.state["login_posts"] == 0

    @pytest.mark.parametrize(
        "argv",
        [
            ["auto-update", "r1"],
            ["auto-update", "r1", "--on", "--off"],
            ["auto-update", "r1", "--on", "--window", "24"],
            ["auto-update", "r1", "--on", "--window", "noon"],
            ["check"],
        ],
    )
    def test_usage_errors(self, data, argv):
        with pytest.raises(SystemExit) as exc:
            cli.main(["firmware", *argv])
        assert exc.value.code == 2

    def test_a_tplink_is_refused_without_a_login(self, data, monkeypatch, capsys):
        add_router(data, identifier="t1", vendor="tplink")
        monkeypatch.setattr(adapters.TpLinkAdapter, "login", lambda self: pytest.fail("the TP-Link was logged in to"))
        code, _, err = run(["firmware", "auto-update", "t1", "--on"], capsys)
        assert code == 1 and "not supported" in one_error_line(err)

    def test_an_unknown_device(self, data, capsys):
        code, _, err = run(["firmware", "status", "ghost"], capsys)
        assert code == 1 and "does not exist" in one_error_line(err)

    def test_alone_it_prints_its_help(self, data, capsys):
        code, out, _ = run(["firmware"], capsys)
        assert code == 0 and "auto-update" in out


# --- maintenance plans -------------------------------------------------------------------------------


class TestMaintenanceCommand:
    def test_list_and_show(self, data, capsys):
        code, out, _ = run(["maintenance", "list"], capsys)
        assert code == 0 and json.loads(out) == []
        created = plan(data)
        [listed] = json.loads(run(["maintenance", "list"], capsys)[1])
        assert listed["id"] == created["id"] and listed["next_window"]["opens"] and listed["last_run"] is None
        code, out, _ = run(["maintenance", "show", created["id"]], capsys)
        assert code == 0 and json.loads(out) == listed

    @pytest.mark.parametrize(("plan_id", "message"), [("0123456789ab", "no such"), ("nope", "not a maintenance plan")])
    def test_show_and_run_refuse_an_unknown_plan(self, data, capsys, plan_id, message):
        for command in ("show", "run"):
            code, out, err = run(["maintenance", command, plan_id], capsys)
            assert code == 1 and out == ""
            assert message in one_error_line(err)

    def test_a_damaged_plan_file_is_one_error_line(self, data, capsys):
        data.mkdir(parents=True)
        (data / "maintenance.json").write_text("{not json")
        code, _, err = run(["maintenance", "list"], capsys)
        assert code == 1 and "maintenance plans are unreadable" in one_error_line(err)

    def test_run_needs_a_terminal_or_assume_yes(self, data, router, monkeypatch, capsys):
        add_router(data, router)
        created = plan(data)
        monkeypatch.setattr("sys.stdin", io.StringIO(""))
        code, _, err = run(["maintenance", "run", created["id"]], capsys)
        assert code == 1 and "ROUTER_MANAGER_ASSUME_YES=1" in one_error_line(err)
        assert router.state["login_posts"] == 0

    @pytest.mark.parametrize("answer", ["n\n", "\n", ""])
    def test_run_does_nothing_unless_confirmed(self, data, router, monkeypatch, capsys, answer):
        add_router(data, router)
        created = plan(data)
        monkeypatch.setattr("sys.stdin", Terminal(answer))
        code, out, err = run(["maintenance", "run", created["id"]], capsys)
        assert code == 1 and out == ""
        assert 'Run maintenance plan "Weekly check" (firmware_check) on 1 router(s) now? [y/N]' in err
        # A terminal echoes the typed newline; this stdin does not, so only Ctrl-D starts a new line.
        assert "error: not confirmed, nothing was changed" in err and "Traceback" not in err
        assert (answer == "") == ("\nerror: " in err)
        assert router.state["login_posts"] == 0 and logged(data) == []

    def test_a_confirmed_run_checks_the_router_under_the_plans_name(self, data, router, monkeypatch, capsys):
        add_router(data, router)
        created = plan(data)
        monkeypatch.setattr("sys.stdin", Terminal("y\n"))
        code, out, err = run(["maintenance", "run", created["id"]], capsys)
        assert code == 0, err
        body = json.loads(out)
        [result] = body["results"]
        assert body["plan"] == created["id"] and result["status"] == "done" and result["trigger"] == "manual"
        assert "direct:r1: done" in err
        assert router.state["update_checks"]
        [entry] = logged(data)
        assert entry["who"] == f"Maintenance: Weekly check (run by {ACTOR})"
        assert entry["details"]["plan"] == created["id"]

    def test_an_unattended_run_that_fails_exits_1(self, data, router, monkeypatch, capsys):
        add_router(data, router)
        created = plan(data)
        # The router refuses the page's form token, so the check fails on the router's side.
        router.state["stale_page_token"] = True
        monkeypatch.setenv("ROUTER_MANAGER_ASSUME_YES", "1")
        code, out, err = run(["maintenance", "run", created["id"]], capsys)
        assert code == 1
        [result] = json.loads(out)["results"]
        assert result["status"] == "failed"
        assert "direct:r1: failed" in err and "Traceback" not in err

    def test_the_runner_is_the_servers(self, data, monkeypatch):
        manager = cli._manager()
        runner, store = cli._maintenance_runner(manager, with_acs=True)
        assert runner.acs is None, "no ACS without ROUTER_MANAGER_ACS_URL"
        assert runner.activity is manager.activity and runner.store is store
        assert store.path == data / "maintenance.json"
        assert runner.state_path == data / "maintenance_state.json"
        # A device's own scheduled reboots start a plan's cooldown here too.
        assert runner.reboot_history is not None
        with FakeNbi() as nbi:
            monkeypatch.setenv("ROUTER_MANAGER_ACS_URL", nbi.url)
            with_acs, _ = cli._maintenance_runner(manager, with_acs=True)
            assert isinstance(with_acs.acs, AcsService) and with_acs.acs.activity.path == data / "activity.jsonl"
            without, _ = cli._maintenance_runner(manager, with_acs=False)
            assert without.acs is None
            assert nbi.requests == []

    def test_alone_it_prints_its_help(self, data, capsys):
        code, out, _ = run(["maintenance"], capsys)
        assert code == 0 and "run" in out and "list" in out


# --- the TR-069 firmware library -----------------------------------------------------------------------


@pytest.fixture
def nbi(data, monkeypatch):
    with FakeNbi() as fake:
        monkeypatch.setenv("ROUTER_MANAGER_ACS_URL", fake.url)
        yield fake


@pytest.fixture
def image(tmp_path: Path) -> Path:
    path = tmp_path / "AP1300-2.5.26.bin"
    path.write_bytes(CONTENT)
    return path


def add_image(image: Path, capsys, *extra: str) -> tuple[int, str, str]:
    argv = ["acs", "firmware", "add", str(image), "--version", NEW, "--oui", OUI, "--product-class", PRODUCT]
    return run([*argv, *extra], capsys)


class TestAcsFirmwareCommand:
    def test_add_stores_the_file_and_prints_only_its_record(self, nbi, image, capsys):
        code, out, err = add_image(image, capsys, "--model-hint", "Cudy AP1300")
        assert code == 0, err
        record = json.loads(out)
        assert record["name"].startswith("skybre-fw-") and record["filename"] == image.name
        assert (record["version"], record["model_hint"], record["size"]) == (NEW, "Cudy AP1300", len(CONTENT))
        assert nbi.file_data[record["name"]] == CONTENT
        marker = CONTENT[:24].decode()
        assert marker not in out and marker not in err
        [listed] = json.loads(run(["acs", "firmware", "list"], capsys)[1])
        assert listed["name"] == record["name"] and listed["on_acs"] is True

    def test_add_refuses_an_oversized_file_before_reading_it(self, nbi, image, monkeypatch, capsys):
        monkeypatch.setattr(service_module, "MAX_FIRMWARE_BYTES", 16)
        monkeypatch.setattr(
            "builtins.open", lambda *args, **kwargs: pytest.fail("an oversized file was read"), raising=True
        )
        code, _, err = add_image(image, capsys)
        assert code == 1 and "larger than" in one_error_line(err)
        assert nbi.files == {}

    @pytest.mark.parametrize(
        ("extra", "message"),
        [(["--oui", "80AFCA;x"], "OUI"), (["--version", ""], "version")],
    )
    def test_add_refuses_bad_metadata(self, nbi, image, capsys, extra, message):
        code, _, err = add_image(image, capsys, *extra)
        assert code == 1 and message in one_error_line(err)
        assert nbi.files == {}

    def test_add_of_a_missing_file_is_one_error_line(self, nbi, tmp_path, capsys):
        code, _, err = add_image(tmp_path / "nope.bin", capsys)
        assert code == 1
        one_error_line(err)

    def test_remove(self, nbi, image, capsys):
        name = json.loads(add_image(image, capsys)[1])["name"]
        code, out, _ = run(["acs", "firmware", "remove", name], capsys)
        assert code == 0 and json.loads(out) == {"name": name, "removed": True}
        assert nbi.files == {}
        code, _, err = run(["acs", "firmware", "remove", name], capsys)
        assert code == 1 and "No such firmware" in one_error_line(err)

    def test_an_upgrade_asks_first(self, nbi, image, monkeypatch, capsys):
        acs_id = cudy(nbi)
        name = json.loads(add_image(image, capsys)[1])["name"]
        monkeypatch.setattr("sys.stdin", io.StringIO(""))
        code, _, err = run(["acs", "firmware", "upgrade", acs_id, name], capsys)
        assert code == 1 and "ROUTER_MANAGER_ASSUME_YES=1" in one_error_line(err)
        assert [task for task in nbi.tasks if task["name"] == "download"] == []

    def test_a_confirmed_upgrade_is_a_job_by_the_cli_user(self, nbi, image, monkeypatch, capsys):
        acs_id = cudy(nbi)
        name = json.loads(add_image(image, capsys)[1])["name"]
        monkeypatch.setattr("sys.stdin", Terminal("yes\n"))
        code, out, err = run(["acs", "firmware", "upgrade", acs_id, name], capsys)
        assert code == 0, err
        assert f"Install firmware {NEW} ({name}) on {acs_id}? The router restarts. [y/N]" in err
        job = json.loads(out)
        assert job["kind"] == "firmware" and job["actor"] == ACTOR
        assert [task["file"] for task in nbi.tasks if task["name"] == "download"] == [name]

    def test_a_model_mismatch_needs_its_own_flag(self, nbi, image, monkeypatch, capsys):
        acs_id = cudy(nbi, product_class="AP3000")
        name = json.loads(add_image(image, capsys)[1])["name"]
        monkeypatch.setenv("ROUTER_MANAGER_ASSUME_YES", "1")
        code, out, err = run(["acs", "firmware", "upgrade", acs_id, name], capsys)
        assert code == 1
        assert json.loads(out)["mismatch"] == ["product_class"]
        assert "--confirm-model-mismatch" in one_error_line(err)
        assert "--confirm-guessed-band" not in err
        code, _, err = run(["acs", "firmware", "upgrade", acs_id, name, "--confirm-model-mismatch"], capsys)
        assert code == 0, err

    def test_an_unknown_file_is_refused_before_asking(self, nbi, monkeypatch, capsys):
        acs_id = cudy(nbi)
        monkeypatch.setattr("sys.stdin", Terminal("y\n"))
        code, _, err = run(["acs", "firmware", "upgrade", acs_id, "skybre-fw-0123456789abcdef"], capsys)
        assert code == 1 and "not in the firmware library" in one_error_line(err)
        assert "[y/N]" not in err

    def test_alone_it_prints_its_help(self, data, capsys):
        code, out, _ = run(["acs", "firmware"], capsys)
        assert code == 0 and "upgrade" in out
        assert not data.exists()
