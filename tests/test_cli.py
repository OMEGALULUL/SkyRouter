"""Tests for the command line surface, in particular its exit codes.

Scripts rely on the exit status, so an offline device or a failed reboot must not
report success, and routine network failures must not surface as tracebacks.
"""

import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from cudy_manager import cli, web
from cudy_manager.adapters import AdapterError
from cudy_manager.manager import DeviceManager
from cudy_manager.secrets import SecretStore

REPO = Path(__file__).resolve().parent.parent


@pytest.fixture
def paths(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ROUTER_MANAGER_CONFIG", str(tmp_path / "c.yaml"))
    monkeypatch.setenv("ROUTER_MANAGER_DATA_DIR", str(tmp_path / "data"))
    # Exported by a developer's shell, these made set-password store their value
    # instead of reaching the prompt checks below.
    monkeypatch.delenv("ROUTER_MANAGER_ASSUME_YES", raising=False)
    monkeypatch.delenv("ROUTER_MANAGER_DEVICE_PASSWORD", raising=False)
    return tmp_path / "c.yaml", tmp_path / "data"


@pytest.fixture
def workspace(tmp_path: Path, paths, monkeypatch):
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


def typed(monkeypatch, *answers: str) -> None:
    """Answer getpass prompts as if typed at a terminal.

    pytest's stdin is not a TTY, so without this the CLI takes its non-interactive
    path and the prompt logic a test names is never reached.
    """
    replies = iter(answers)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": next(replies))


def piped(monkeypatch, text: str) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO(text))
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": pytest.fail("must read the pipe, not the terminal"))


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
        typed(monkeypatch, "pw")
        monkeypatch.setattr(
            DeviceManager,
            "verify_credentials",
            lambda self, identifier: {"ok": False, "reason": "rejected", "error": "no"},
        )

        code = cli.main(["add", "r1", "192.0.2.1", "--vendor", "cudy"])

        assert code == 1
        assert workspace.get_device("r1").identifier == "r1"
        err = capsys.readouterr().err
        assert "rejected the password" in err
        assert "diagnose" in err

    def test_unreachable_router_is_not_reported_as_a_rejected_password(self, workspace, capsys, monkeypatch):
        # Real classification, so the add path is checked against what
        # verify_credentials actually returns for a router that does not answer.
        typed(monkeypatch, "pw")
        offline(workspace, "r1")

        code = cli.main(["add", "r1", "192.0.2.1", "--vendor", "cudy"])

        assert code == 1
        assert workspace.get_device("r1").identifier == "r1"
        err = capsys.readouterr().err
        assert "could not be checked" in err
        assert "timed out" in err
        assert "rejected" not in err
        assert "set-password" not in err

    def test_ssh_device_is_not_pointed_at_the_http_diagnostic(self, workspace, capsys, monkeypatch):
        typed(monkeypatch, "pw")
        monkeypatch.setattr(
            DeviceManager,
            "verify_credentials",
            lambda self, identifier: {"ok": False, "reason": "unreachable", "error": "not found in known_hosts"},
        )

        assert cli.main(["add", "r1", "192.0.2.1", "--vendor", "cudy", "--transport", "ssh"]) == 1
        err = capsys.readouterr().err
        assert "could not be checked" in err
        assert "diagnose" not in err
        assert "known_hosts" in err

    def test_accepted_password_exits_zero(self, workspace, capsys, monkeypatch):
        typed(monkeypatch, "pw")
        monkeypatch.setattr(DeviceManager, "verify_credentials", lambda self, identifier: {"ok": True})

        assert cli.main(["add", "r1", "192.0.2.1", "--vendor", "cudy"]) == 0

    def test_no_verify_skips_the_check(self, workspace, monkeypatch):
        typed(monkeypatch, "pw")

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
        typed(monkeypatch, "first", "second")

        assert cli.main(["set-password", "r1", "--no-verify"]) == 1
        assert workspace.credentials(workspace.get_device("r1")) == "original"
        assert "did not match" in capsys.readouterr().err

    def test_empty_password_is_rejected(self, workspace, monkeypatch, capsys):
        workspace.add_device("r1", "192.168.1.1", "cudy", password="original")
        typed(monkeypatch, "", "")

        assert cli.main(["set-password", "r1", "--no-verify"]) == 1
        assert workspace.credentials(workspace.get_device("r1")) == "original"
        assert "must not be empty" in capsys.readouterr().err

    def test_exported_unattended_variables_do_not_leak_into_these_tests(self, workspace):
        assert "ROUTER_MANAGER_ASSUME_YES" not in os.environ
        assert "ROUTER_MANAGER_DEVICE_PASSWORD" not in os.environ


class TestAddPasswordInput:
    """README: pipe the password into add when stdin is not a terminal."""

    def test_piped_password_is_read_from_stdin_not_the_terminal(self, workspace, monkeypatch):
        piped(monkeypatch, "piped-secret\n")

        assert cli.main(["add", "r1", "192.0.2.1", "--no-verify"]) == 0
        assert workspace.credentials(workspace.get_device("r1")) == "piped-secret"

    def test_piped_password_without_newline_is_kept_whole(self, workspace, monkeypatch):
        piped(monkeypatch, "printf-secret")

        assert cli.main(["add", "r1", "192.0.2.1", "--no-verify"]) == 0
        assert workspace.credentials(workspace.get_device("r1")) == "printf-secret"

    def test_empty_stdin_is_one_error_line_and_adds_nothing(self, workspace, monkeypatch, capsys):
        piped(monkeypatch, "")

        assert cli.main(["add", "r1", "192.0.2.1", "--no-verify"]) == 1
        assert workspace.get_all_devices() == []
        assert capsys.readouterr().err.startswith("error:")

    @pytest.mark.parametrize("interruption", [EOFError, KeyboardInterrupt])
    def test_abandoned_prompt_is_one_error_line_and_adds_nothing(self, workspace, monkeypatch, capsys, interruption):
        monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)

        def abandon(prompt=""):
            raise interruption

        monkeypatch.setattr(cli.getpass, "getpass", abandon)

        assert cli.main(["add", "r1", "192.0.2.1", "--no-verify"]) == 1
        assert workspace.get_all_devices() == []
        assert "error:" in capsys.readouterr().err


class TestManagerLoadErrors:
    """Errors raised while the manager loads must print one line, not a traceback."""

    def test_malformed_config_is_one_error_line(self, paths, capsys):
        config, _ = paths
        config.write_text("devices: {r1: [unclosed\n")

        assert cli.main(["list"]) == 1
        err = capsys.readouterr().err
        assert err.startswith("error:")
        assert "unreadable" in err

    def test_missing_secret_is_one_error_line(self, paths, capsys):
        config, data = paths
        manager = DeviceManager(config_path=config, data_dir=data, secret_store=SecretStore(data))
        device = manager.add_device("r1", "192.0.2.1", "cudy", password="pw")
        manager.secrets.delete(device.password_ref)

        assert cli.main(["list"]) == 1
        assert "references a missing secret" in capsys.readouterr().err

    def test_unwritable_data_dir_is_one_error_line(self, tmp_path, paths, monkeypatch, capsys):
        blocker = tmp_path / "not-a-dir"
        blocker.write_text("")
        monkeypatch.setenv("ROUTER_MANAGER_DATA_DIR", str(blocker / "data"))

        assert cli.main(["list"]) == 1
        assert capsys.readouterr().err.startswith("error:")

    def test_help_without_a_command_does_not_create_a_vault(self, paths, capsys):
        config, data = paths

        assert cli.main([]) == 0
        assert "usage" in capsys.readouterr().out
        assert not data.exists()
        assert not config.exists()


class TestAppShim:
    def test_importing_the_shim_does_not_open_the_vault(self, tmp_path):
        home = tmp_path / "home"
        cwd = tmp_path / "cwd"
        home.mkdir()
        cwd.mkdir()
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("ROUTER_MANAGER_") and key != "XDG_STATE_HOME"
        }
        env.update(HOME=str(home), PYTHONPATH=str(REPO))

        subprocess.run([sys.executable, "-c", "import cudy_manager.app"], cwd=cwd, env=env, check=True, timeout=60)

        assert list(home.rglob("*")) == []
        assert list(cwd.rglob("*")) == []

    @pytest.mark.parametrize(("value", "expected"), [(None, False), ("0", False), ("1", True)])
    def test_serve_only_trusts_forwarded_headers_when_told_to(self, monkeypatch, value, expected):
        """uvicorn trusted X-Forwarded-For from any loopback peer, bypassing the login limiter."""
        import uvicorn

        seen: dict = {}
        monkeypatch.setattr(uvicorn, "run", lambda *args, **kwargs: seen.update(kwargs))
        if value is None:
            monkeypatch.delenv("ROUTER_MANAGER_TRUST_PROXY", raising=False)
        else:
            monkeypatch.setenv("ROUTER_MANAGER_TRUST_PROXY", value)
        assert cli.main(["serve"]) == 0
        assert seen["proxy_headers"] is expected

    def test_the_shim_still_serves_the_web_app(self, paths, monkeypatch):
        import cudy_manager.app as shim

        sentinel = object()
        monkeypatch.setattr(web, "app", sentinel, raising=False)
        assert shim.app is sentinel


class TestDiscoveryExitCode:
    def test_oversized_subnet_exits_nonzero(self, workspace, capsys):
        assert cli.main(["discover", "--subnet", "0.0.0.0/0"]) == 1
        assert "too large" in capsys.readouterr().err


class TestAddUsernameDefault:
    """A TP-Link added as "root" was refused on every dashboard poll until it locked."""

    @pytest.mark.parametrize(("vendor", "expected"), [("tplink", "admin"), ("cudy", "root"), ("tenda", "root")])
    def test_username_defaults_per_vendor(self, workspace, monkeypatch, vendor, expected):
        typed(monkeypatch, "pw")
        assert cli.main(["add", "r1", "192.0.2.1", "--vendor", vendor, "--no-verify"]) == 0
        assert workspace.get_device("r1").username == expected

    def test_an_explicit_username_wins(self, workspace, monkeypatch):
        typed(monkeypatch, "pw")
        assert cli.main(["add", "r1", "192.0.2.1", "--vendor", "tplink", "--username", "ops", "--no-verify"]) == 0
        assert workspace.get_device("r1").username == "ops"
