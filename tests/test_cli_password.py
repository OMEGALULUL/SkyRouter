import json
from pathlib import Path

import pytest

from cudy_manager import cli
from cudy_manager.manager import DeviceManager
from cudy_manager.secrets import SecretStore

PASSWORD = "typed-twice-secret"


def rejected():
    return {"ok": False, "reason": "rejected", "error": "authentication failed"}


def unreachable():
    return {"ok": False, "reason": "unreachable", "error": "Network is unreachable"}


@pytest.fixture
def env(tmp_path: Path, monkeypatch):
    config = tmp_path / "devices.yaml"
    data = tmp_path / "data"
    monkeypatch.setenv("ROUTER_MANAGER_CONFIG", str(config))
    monkeypatch.setenv("ROUTER_MANAGER_DATA_DIR", str(data))
    monkeypatch.delenv("ROUTER_MANAGER_DEVICE_PASSWORD", raising=False)
    monkeypatch.delenv("ROUTER_MANAGER_ASSUME_YES", raising=False)
    return config, data


def add_device(config: Path, data: Path, password: str = "old") -> None:
    manager = DeviceManager(config_path=config, data_dir=data, secret_store=SecretStore(data))
    manager.add_device("r1", "192.168.1.1", "cudy", password=password)


def stored_password(config: Path, data: Path) -> str:
    manager = DeviceManager(config_path=config, data_dir=data, secret_store=SecretStore(data))
    return manager.credentials(manager.get_device("r1"))


class TestSetPasswordCommand:
    def test_confirmed_password_is_saved(self, env, monkeypatch, capsys):
        config, data = env
        add_device(config, data)
        monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)
        monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": PASSWORD)

        assert cli.main(["set-password", "r1", "--no-verify"]) == 0
        assert stored_password(config, data) == PASSWORD
        assert PASSWORD not in config.read_text()
        assert PASSWORD not in (data / "secrets.json").read_text()

    def test_mismatched_confirmation_changes_nothing(self, env, monkeypatch, capsys):
        config, data = env
        add_device(config, data)
        monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)
        answers = iter([PASSWORD, "something-else"])
        monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": next(answers))

        assert cli.main(["set-password", "r1", "--no-verify"]) == 1
        assert stored_password(config, data) == "old"
        assert "did not match" in capsys.readouterr().err

    def test_empty_confirmation_rejected(self, env, monkeypatch):
        config, data = env
        add_device(config, data)
        monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)
        monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": "")

        assert cli.main(["set-password", "r1", "--no-verify"]) == 1
        assert stored_password(config, data) == "old"

    def test_non_interactive_without_opt_in_refuses(self, env, monkeypatch, capsys):
        config, data = env
        add_device(config, data)
        monkeypatch.setattr("sys.stdin.isatty", lambda: False, raising=False)

        assert cli.main(["set-password", "r1", "--no-verify"]) == 1
        assert stored_password(config, data) == "old"
        assert "interactive terminal" in capsys.readouterr().err

    def test_non_interactive_opt_in_uses_env_password(self, env, monkeypatch):
        config, data = env
        add_device(config, data)
        monkeypatch.setenv("ROUTER_MANAGER_DEVICE_PASSWORD", PASSWORD)
        monkeypatch.setenv("ROUTER_MANAGER_ASSUME_YES", "1")
        monkeypatch.setattr("sys.stdin.isatty", lambda: False, raising=False)
        monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": pytest.fail("must not prompt"))

        assert cli.main(["set-password", "r1", "--no-verify"]) == 0
        assert stored_password(config, data) == PASSWORD

    def test_opt_in_without_password_fails(self, env, monkeypatch, capsys):
        config, data = env
        add_device(config, data)
        monkeypatch.setenv("ROUTER_MANAGER_ASSUME_YES", "1")

        assert cli.main(["set-password", "r1", "--no-verify"]) == 1
        assert "ROUTER_MANAGER_DEVICE_PASSWORD" in capsys.readouterr().err
        assert stored_password(config, data) == "old"

    @pytest.mark.parametrize("value", ["0", "false", "no", ""])
    def test_opt_out_values_still_prompt(self, env, monkeypatch, value):
        # A leftover DEVICE_PASSWORD must not be stored just because ASSUME_YES
        # is exported with a value that reads as "no".
        config, data = env
        add_device(config, data)
        monkeypatch.setenv("ROUTER_MANAGER_ASSUME_YES", value)
        monkeypatch.setenv("ROUTER_MANAGER_DEVICE_PASSWORD", "stale-env-password")
        monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)
        monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": PASSWORD)

        assert cli.main(["set-password", "r1", "--no-verify"]) == 0
        assert stored_password(config, data) == PASSWORD

    def test_device_can_be_named_by_host(self, env, monkeypatch, capsys):
        config, data = env
        add_device(config, data)
        monkeypatch.setenv("ROUTER_MANAGER_DEVICE_PASSWORD", PASSWORD)
        monkeypatch.setenv("ROUTER_MANAGER_ASSUME_YES", "1")

        assert cli.main(["set-password", "192.168.1.1", "--no-verify"]) == 0
        assert json.loads(capsys.readouterr().out)["device"] == "r1"
        assert stored_password(config, data) == PASSWORD

    def test_opt_in_never_reuses_the_web_login_password(self, env, monkeypatch):
        config, data = env
        add_device(config, data)
        monkeypatch.setenv("ROUTER_MANAGER_PASSWORD", "web-login-password")
        monkeypatch.setenv("ROUTER_MANAGER_ASSUME_YES", "1")

        assert cli.main(["set-password", "r1", "--no-verify"]) == 1
        assert stored_password(config, data) == "old"

    def test_password_never_appears_in_command_output(self, env, monkeypatch, capsys):
        config, data = env
        add_device(config, data)
        monkeypatch.setenv("ROUTER_MANAGER_DEVICE_PASSWORD", PASSWORD)
        monkeypatch.setenv("ROUTER_MANAGER_ASSUME_YES", "1")
        monkeypatch.setattr("sys.stdin.isatty", lambda: False, raising=False)

        assert cli.main(["set-password", "r1", "--no-verify"]) == 0
        captured = capsys.readouterr()
        assert PASSWORD not in captured.out
        assert PASSWORD not in captured.err
        json.loads(captured.out)

    def test_verification_success_reported(self, env, monkeypatch, capsys):
        config, data = env
        add_device(config, data)
        monkeypatch.setenv("ROUTER_MANAGER_DEVICE_PASSWORD", PASSWORD)
        monkeypatch.setenv("ROUTER_MANAGER_ASSUME_YES", "1")
        monkeypatch.setattr("sys.stdin.isatty", lambda: False, raising=False)
        monkeypatch.setattr(DeviceManager, "verify_credentials", lambda self, identifier: {"ok": True})

        assert cli.main(["set-password", "r1"]) == 0
        assert "verified" in capsys.readouterr().err
        assert stored_password(config, data) == PASSWORD

    def test_verification_failure_exits_nonzero_but_keeps_password(self, env, monkeypatch, capsys):
        config, data = env
        add_device(config, data)
        monkeypatch.setenv("ROUTER_MANAGER_DEVICE_PASSWORD", PASSWORD)
        monkeypatch.setenv("ROUTER_MANAGER_ASSUME_YES", "1")
        monkeypatch.setattr("sys.stdin.isatty", lambda: False, raising=False)
        monkeypatch.setattr(DeviceManager, "verify_credentials", lambda self, identifier: rejected())

        assert cli.main(["set-password", "r1"]) == 1
        err = capsys.readouterr().err
        assert "rejected it" in err
        assert stored_password(config, data) == PASSWORD

    def test_unreachable_router_is_not_reported_as_rejection(self, env, monkeypatch, capsys):
        config, data = env
        add_device(config, data)
        monkeypatch.setenv("ROUTER_MANAGER_DEVICE_PASSWORD", PASSWORD)
        monkeypatch.setenv("ROUTER_MANAGER_ASSUME_YES", "1")
        monkeypatch.setattr("sys.stdin.isatty", lambda: False, raising=False)
        monkeypatch.setattr(DeviceManager, "verify_credentials", lambda self, identifier: unreachable())

        assert cli.main(["set-password", "r1"]) == 1
        err = capsys.readouterr().err
        assert "could not be checked" in err
        assert "rejected it" not in err
        assert stored_password(config, data) == PASSWORD

    def test_unknown_device_reports_clean_error(self, env, monkeypatch, capsys):
        monkeypatch.setenv("ROUTER_MANAGER_DEVICE_PASSWORD", PASSWORD)
        monkeypatch.setenv("ROUTER_MANAGER_ASSUME_YES", "1")
        monkeypatch.setattr("sys.stdin.isatty", lambda: False, raising=False)

        assert cli.main(["set-password", "ghost", "--no-verify"]) == 1
        assert "does not exist" in capsys.readouterr().err

    def test_password_is_not_accepted_as_a_command_line_argument(self, env):
        with pytest.raises(SystemExit) as exc:
            cli.main(["set-password", "r1", PASSWORD])
        assert exc.value.code != 0
