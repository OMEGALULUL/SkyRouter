from pathlib import Path

import pytest
from test_manager import build_manager

from cudy_manager.manager import DeviceManager, ManagerError
from cudy_manager.models import ValidationError


class RecordingAdapter:
    calls: list[str] = []

    def __init__(self, device, password):
        self.device = device
        self.password = password
        self.accepted = type(self).accepted

    def status(self):
        if self.password == self.accepted:
            return {"online": True, "uptime_seconds": 100000}
        raise RuntimeError("authentication failed")


def adapter(manager, device):
    return RecordingAdapter(device, manager.credentials(device))


class TestSetPassword:
    def test_rotates_password_and_verifies(self, tmp_path: Path, monkeypatch):
        manager = build_manager(tmp_path)
        manager.add_device("router-1", "192.168.1.1", "cudy", password="old")
        RecordingAdapter.accepted = "new"
        monkeypatch.setattr(manager, "adapter_for", lambda device: adapter(manager, device))

        result = manager.set_password("router-1", "new", verify=True)

        assert result["password_updated"] is True
        assert result["verified"]["ok"] is True
        assert manager.credentials(manager.get_device("router-1")) == "new"
        assert "new" not in (tmp_path / "cudy_devices.yaml").read_text()
        assert "new" not in (tmp_path / "data" / "secrets.json").read_text()

    def test_rejected_password_is_saved_but_reported(self, tmp_path: Path, monkeypatch):
        manager = build_manager(tmp_path)
        manager.add_device("router-1", "192.168.1.1", "cudy", password="good")
        RecordingAdapter.accepted = "good"
        monkeypatch.setattr(manager, "adapter_for", lambda device: adapter(manager, device))

        result = manager.set_password("router-1", "typo", verify=True)

        assert result["verified"]["ok"] is False
        assert "authentication failed" in result["verified"]["error"]
        assert manager.credentials(manager.get_device("router-1")) == "typo"

    def test_verify_can_be_skipped(self, tmp_path: Path, monkeypatch):
        manager = build_manager(tmp_path)
        manager.add_device("router-1", "192.168.1.1", "cudy", password="old")

        def explode(device):
            raise AssertionError("adapter must not be called when verify is off")

        monkeypatch.setattr(manager, "adapter_for", explode)
        result = manager.set_password("router-1", "new", verify=False)

        assert "verified" not in result
        assert manager.credentials(manager.get_device("router-1")) == "new"

    def test_empty_password_rejected(self, tmp_path: Path):
        manager = build_manager(tmp_path)
        manager.add_device("router-1", "192.168.1.1", "cudy", password="old")
        for value in ("", None, 12345):
            with pytest.raises(ValidationError):
                manager.set_password("router-1", value)
        assert manager.credentials(manager.get_device("router-1")) == "old"

    def test_unknown_device_rejected(self, tmp_path: Path):
        manager = build_manager(tmp_path)
        with pytest.raises(ManagerError):
            manager.set_password("nope", "x", verify=False)

    def test_device_without_reference_gains_one(self, tmp_path: Path):
        config = tmp_path / "cudy_devices.yaml"
        config.write_text("devices:\n  bare:\n    vendor: cudy\n    host: 192.168.1.1\n")
        manager = DeviceManager(config_path=config, data_dir=tmp_path / "data")
        assert manager.get_device("bare").password_ref == ""

        manager.set_password("bare", "fresh", verify=False)

        reopened = DeviceManager(config_path=config, data_dir=tmp_path / "data")
        assert reopened.credentials(reopened.get_device("bare")) == "fresh"

    def test_rotation_survives_reload(self, tmp_path: Path):
        manager = build_manager(tmp_path)
        manager.add_device("router-1", "192.168.1.1", "cudy", password="old")
        manager.set_password("router-1", "new", verify=False)

        reopened = DeviceManager(config_path=tmp_path / "cudy_devices.yaml", data_dir=tmp_path / "data")
        assert reopened.credentials(reopened.get_device("router-1")) == "new"

    def test_result_never_contains_the_password(self, tmp_path: Path):
        manager = build_manager(tmp_path)
        manager.add_device("router-1", "192.168.1.1", "cudy", password="old")
        result = manager.set_password("router-1", "brand-new-secret", verify=False)
        assert "brand-new-secret" not in str(result)
        assert "password_ref" not in str(result)


class TestVerifyCredentials:
    def test_reports_adapter_failure(self, tmp_path: Path, monkeypatch):
        manager = build_manager(tmp_path)
        manager.add_device("router-1", "192.168.1.1", "cudy", password="p")
        RecordingAdapter.accepted = "different"
        monkeypatch.setattr(manager, "adapter_for", lambda device: adapter(manager, device))
        assert manager.verify_credentials("router-1")["ok"] is False
