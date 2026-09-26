"""Tests for the command line surface, in particular its exit codes.

Scripts rely on the exit status, so an offline device or a failed reboot must not
report success, and routine network failures must not surface as tracebacks.
"""

import json
from pathlib import Path

import pytest

from cudy_manager import cli
from cudy_manager.adapters import AdapterError
from cudy_manager.manager import DeviceManager
from cudy_manager.secrets import SecretStore


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ROUTER_MANAGER_CONFIG", str(tmp_path / "c.yaml"))
    monkeypatch.setenv("ROUTER_MANAGER_DATA_DIR", str(tmp_path / "data"))
    manager = DeviceManager(
        config_path=tmp_path / "c.yaml",
        data_dir=tmp_path / "data",
        secret_store=SecretStore(tmp_path / "data"),
    )
    # cli.main builds its own manager, so point it at this one.
    monkeypatch.setattr(cli, "_manager", lambda: manager)
    return manager


def offline(manager: DeviceManager, identifier: str) -> None:
    def failing(device):
        raise AdapterError("router request failed: timed out")

    manager.adapter_for = failing  # type: ignore[method-assign]


class TestStatusExitCode:
    def test_offline_device_exits_nonzero(self, workspace, capsys):
        workspace.add_device("r1", "192.0.2.1", "cudy", password="pw")
        offline(workspace, "r1")

        code = cli.main(["status", "r1"])

        assert code == 1
        captured = capsys.readouterr()
        assert "offline" in captured.err
        assert json.loads(captured.out)["online"] is False

    def test_online_device_exits_zero(self, workspace, capsys, monkeypatch):
        workspace.add_device("r1", "192.0.2.1", "cudy", password="pw")
        monkeypatch.setattr(workspace, "get_status", lambda identifier: {"online": True, "uptime_seconds": 10})

        assert cli.main(["status", "r1"]) == 0

    def test_unknown_device_exits_nonzero_without_traceback(self, workspace, capsys):
        assert cli.main(["status", "ghost"]) == 1
        assert "does not exist" in capsys.readouterr().err


class TestRebootExitCode:
    def test_network_failure_is_reported_not_raised(self, workspace, capsys, monkeypatch):
        workspace.add_device("r1", "192.0.2.1", "cudy", password="pw")

        def failing(identifier):
            raise AdapterError("router request failed: timed out")

        monkeypatch.setattr(workspace, "reboot_device", failing)

        code = cli.main(["reboot", "r1"])

        assert code == 1
        captured = capsys.readouterr()
        assert "timed out" in captured.err
        assert "Traceback" not in captured.err

    def test_unconfirmed_reboot_exits_nonzero(self, workspace, capsys, monkeypatch):
        workspace.add_device("r1", "192.0.2.1", "cudy", password="pw")
        monkeypatch.setattr(workspace, "reboot_device", lambda identifier: False)

        assert cli.main(["reboot", "r1"]) == 1
        assert "did not confirm" in capsys.readouterr().err

    def test_successful_reboot_exits_zero(self, workspace, monkeypatch):
        workspace.add_device("r1", "192.0.2.1", "cudy", password="pw")
        monkeypatch.setattr(workspace, "reboot_device", lambda identifier: True)

        assert cli.main(["reboot", "r1"]) == 0


class TestAddExitCode:
    def test_rejected_password_exits_nonzero_but_keeps_the_device(self, workspace, capsys, monkeypatch):
        monkeypatch.setattr("getpass.getpass", lambda prompt="": "pw")
        monkeypatch.setattr(DeviceManager, "verify_credentials", lambda self, identifier: {"ok": False, "error": "no"})

        code = cli.main(["add", "r1", "192.0.2.1", "--vendor", "cudy"])

        assert code == 1
        assert workspace.get_device("r1").identifier == "r1"
        assert "diagnose" in capsys.readouterr().err

    def test_accepted_password_exits_zero(self, workspace, capsys, monkeypatch):
        monkeypatch.setattr("getpass.getpass", lambda prompt="": "pw")
        monkeypatch.setattr(DeviceManager, "verify_credentials", lambda self, identifier: {"ok": True})

        assert cli.main(["add", "r1", "192.0.2.1", "--vendor", "cudy"]) == 0

    def test_no_verify_skips_the_check(self, workspace, monkeypatch):
        monkeypatch.setattr("getpass.getpass", lambda prompt="": "pw")

        def explode(self, identifier):
            raise AssertionError("verification should not run")

        monkeypatch.setattr(DeviceManager, "verify_credentials", explode)

        assert cli.main(["add", "r1", "192.0.2.1", "--no-verify"]) == 0


class TestPasswordPromptGuards:
    def test_assume_yes_without_a_password_fails(self, workspace, monkeypatch, capsys):
        workspace.add_device("r1", "192.0.2.1", "cudy", password="pw")
        monkeypatch.setenv("ROUTER_MANAGER_ASSUME_YES", "1")
        monkeypatch.delenv("ROUTER_MANAGER_DEVICE_PASSWORD", raising=False)

        assert cli.main(["set-password", "r1"]) == 1
        assert "ROUTER_MANAGER_DEVICE_PASSWORD" in capsys.readouterr().err

    def test_mismatched_confirmation_changes_nothing(self, workspace, monkeypatch, capsys):
        workspace.add_device("r1", "192.0.2.1", "cudy", password="original")
        answers = iter(["first", "second"])
        monkeypatch.setattr("getpass.getpass", lambda prompt="": next(answers))

        assert cli.main(["set-password", "r1", "--no-verify"]) == 1
        assert workspace.credentials(workspace.get_device("r1")) == "original"

    def test_empty_password_is_rejected(self, workspace, monkeypatch, capsys):
        workspace.add_device("r1", "192.168.1.1", "cudy", password="original")
        monkeypatch.setattr("getpass.getpass", lambda prompt="": "")

        assert cli.main(["set-password", "r1", "--no-verify"]) == 1
        assert workspace.credentials(workspace.get_device("r1")) == "original"


class TestDiscoveryExitCode:
    def test_oversized_subnet_exits_nonzero(self, workspace, capsys):
        assert cli.main(["discover", "--subnet", "0.0.0.0/0"]) == 1
        assert "too large" in capsys.readouterr().err
