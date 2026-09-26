import json
from pathlib import Path

import pytest
from fake_router import FakeRouter

from cudy_manager.diagnose import diagnose_cudy
from cudy_manager.manager import DeviceManager, ManagerError
from cudy_manager.secrets import SecretStore


def device_for(port: int) -> "object":
    from cudy_manager.models import Device

    return Device.from_dict("r1", {"vendor": "cudy", "host": "127.0.0.1", "http_port": port, "username": "root"})


class TestDiagnoseCudy:
    def test_correct_password_is_reported_as_accepted(self):
        with FakeRouter("ok") as router:
            report = diagnose_cudy(device_for(router.port), "goodpass")
        assert report["reachable"] is True
        assert "accepted" in report["verdict"]
        assert report["sysauth_cookie"] is True
        login_step = report["steps"][-1]
        assert login_step["status"] == 302
        assert "sysauth" in login_step["cookies_set"]

    def test_wrong_password_is_distinguished_from_a_protocol_problem(self):
        with FakeRouter("ok") as router:
            report = diagnose_cudy(device_for(router.port), "wrongpass")
        assert "credentials rejected" in report["verdict"]
        assert "protocol mismatch" not in report["verdict"]

    def test_missing_salt_is_reported_as_a_protocol_mismatch(self):
        with FakeRouter("no_salt") as router:
            report = diagnose_cudy(device_for(router.port), "anything")
        salt_step = report["steps"][1]
        assert salt_step["salt_present"] is False
        assert "NO SALT" in salt_step["note"]
        assert "not implemented" in report["verdict"]

    def test_wrong_port_is_reported_as_a_path_problem(self):
        with FakeRouter("wrong_path") as router:
            report = diagnose_cudy(device_for(router.port), "goodpass")
        assert "404" in report["steps"][0]["note"]
        assert "no LuCI login page" in report["verdict"]
        assert "credential" not in report["verdict"]

    def test_unreachable_router_is_reported_without_raising(self):
        device = device_for(1)
        report = diagnose_cudy(device, "x")
        assert report["reachable"] is False
        assert "did not answer" in report["verdict"]

    def test_secret_never_appears_in_the_report(self):
        with FakeRouter("ok") as router:
            report = diagnose_cudy(device_for(router.port), "topsecretvalue")
        assert "topsecretvalue" not in json.dumps(report)
        assert "saltsalt" not in json.dumps(report) or "salt_length" in json.dumps(report)

    def test_salt_and_token_are_reported_by_length_only(self):
        with FakeRouter("ok") as router:
            report = diagnose_cudy(device_for(router.port), "goodpass")
        step = report["steps"][1]
        assert step["salt_length"] == len("saltsalt")
        assert step["token_length"] == len("tok-xyz")
        assert step["csrf_present"] is True
        assert step["form_fields"]["_csrf"] == "<8 chars>"

    def test_verdict_is_always_present(self):
        for mode in ("ok", "no_salt", "wrong_path"):
            with FakeRouter(mode) as router:
                report = diagnose_cudy(device_for(router.port), "goodpass")
            assert report["verdict"]
            assert report["steps"]


def make_manager(tmp_path: Path) -> DeviceManager:
    return DeviceManager(
        config_path=tmp_path / "d.yaml",
        data_dir=tmp_path / "data",
        secret_store=SecretStore(tmp_path / "data"),
    )


class TestDiagnoseThroughManager:
    def test_manager_diagnose_uses_the_stored_password(self, tmp_path: Path):
        manager = make_manager(tmp_path)
        with FakeRouter("ok") as router:
            manager.add_device("r1", "127.0.0.1", "cudy", password="goodpass", http_port=router.port)
            report = manager.diagnose("r1")
        assert "accepted" in report["verdict"]

    def test_diagnose_without_a_stored_password_explains_what_to_do(self, tmp_path: Path):
        config = tmp_path / "d.yaml"
        config.write_text("devices:\n  bare:\n    vendor: cudy\n    host: 192.168.1.1\n")
        manager = make_manager(tmp_path)
        report = manager.diagnose("bare")
        assert "set-password" in report["verdict"]

    def test_diagnose_unknown_device_raises(self, tmp_path: Path):
        manager = make_manager(tmp_path)
        with pytest.raises(ManagerError):
            manager.diagnose("ghost")


class TestAddVerifiesPassword:
    def test_add_reports_rejection(self, tmp_path: Path):
        manager = make_manager(tmp_path)
        with FakeRouter("ok") as router:
            manager.add_device("r1", "127.0.0.1", "cudy", password="badpass", http_port=router.port)
            result = manager.verify_credentials("r1")
        assert result["ok"] is False
