from pathlib import Path

import pytest
import yaml

from cudy_manager.adapters import AdapterError
from cudy_manager.manager import DeviceManager, ManagerError
from cudy_manager.models import ValidationError
from cudy_manager.secrets import SecretStore


def build_manager(tmp_path: Path) -> DeviceManager:
    store = SecretStore(tmp_path / "data")
    return DeviceManager(config_path=tmp_path / "cudy_devices.yaml", data_dir=tmp_path / "data", secret_store=store)


class TestDeviceManager:
    def test_add_device_encrypts_password(self, tmp_path: Path):
        manager = build_manager(tmp_path)
        device = manager.add_device("router-1", "192.168.1.1", "cudy", password="super-secret")
        assert device.password_ref
        assert "super-secret" not in (tmp_path / "cudy_devices.yaml").read_text()
        assert "super-secret" not in (tmp_path / "data" / "secrets.json").read_text()
        assert manager.credentials(device) == "super-secret"

    def test_public_payload_never_contains_secret_material(self, tmp_path: Path):
        manager = build_manager(tmp_path)
        device = manager.add_device("router-1", "192.168.1.1", "cudy", password="super-secret")
        rendered = str(device.to_public())
        assert "super-secret" not in rendered
        assert "password_ref" not in rendered
        assert "password_ref" not in str(manager.dashboard(include_status=False))

    def test_duplicate_identifier_rejected(self, tmp_path: Path):
        manager = build_manager(tmp_path)
        manager.add_device("router-1", "192.168.1.1", "cudy", password="p")
        with pytest.raises(ManagerError):
            manager.add_device("router-1", "192.168.1.2", "cudy", password="p")

    def test_failed_add_does_not_orphan_secret(self, tmp_path: Path):
        manager = build_manager(tmp_path)
        with pytest.raises(ValidationError):
            manager.add_device("bad id", "192.168.1.1", "cudy", password="p")
        assert manager.secrets.references() == []

    def test_failed_add_with_bad_vendor_rolls_back(self, tmp_path: Path):
        manager = build_manager(tmp_path)
        with pytest.raises(ValidationError):
            manager.add_device("router-1", "192.168.1.1", "ubiquiti", password="p")
        assert manager.secrets.references() == []

    def test_remove_device_deletes_secret(self, tmp_path: Path):
        manager = build_manager(tmp_path)
        manager.add_device("router-1", "192.168.1.1", "cudy", password="p")
        reference = manager.devices["router-1"].password_ref
        manager.remove_device("router-1")
        assert not manager.secrets.has(reference)
        assert "router-1" not in (tmp_path / "cudy_devices.yaml").read_text()

    def test_update_password_rotates_secret_in_place(self, tmp_path: Path):
        manager = build_manager(tmp_path)
        device = manager.add_device("router-1", "192.168.1.1", "cudy", password="old")
        reference = device.password_ref
        updated = manager.update_device("router-1", password="new")
        assert manager.credentials(updated) == "new"
        assert manager.secrets.references() == [reference]
        assert "new" not in (tmp_path / "cudy_devices.yaml").read_text()

    def test_reload_from_disk(self, tmp_path: Path):
        manager = build_manager(tmp_path)
        manager.add_device("router-1", "192.168.1.1", "cudy", password="p")
        reopened = DeviceManager(config_path=tmp_path / "cudy_devices.yaml", data_dir=tmp_path / "data")
        assert reopened.get_device("router-1").host == "192.168.1.1"

    def test_plaintext_config_is_rejected(self, tmp_path: Path):
        config = tmp_path / "cudy_devices.yaml"
        config.write_text(
            yaml.safe_dump({"devices": {"r1": {"vendor": "cudy", "host": "1.1.1.1", "luci_password": "admin"}}})
        )
        with pytest.raises(ManagerError):
            DeviceManager(config_path=config, data_dir=tmp_path / "data")

    def test_missing_secret_reference_is_rejected(self, tmp_path: Path):
        config = tmp_path / "cudy_devices.yaml"
        config.write_text(
            yaml.safe_dump({"devices": {"r1": {"vendor": "cudy", "host": "1.1.1.1", "password_ref": "nope"}}})
        )
        with pytest.raises(ManagerError):
            DeviceManager(config_path=config, data_dir=tmp_path / "data")

    def test_lookup_by_host(self, tmp_path: Path):
        manager = build_manager(tmp_path)
        manager.add_device("router-1", "192.168.1.1", "cudy", password="p")
        assert manager.get_device("192.168.1.1").identifier == "router-1"

    def test_status_reports_offline_instead_of_raising(self, tmp_path: Path):
        manager = build_manager(tmp_path)
        manager.add_device("router-1", "127.0.0.1", "cudy", password="p", http_port=1)
        status = manager.get_status("router-1")
        assert status["online"] is False
        assert "error" in status

    def test_credentials_require_secret(self, tmp_path: Path):
        manager = build_manager(tmp_path)
        device = manager.add_device("router-1", "192.168.1.1", "cudy", password="p")
        device.password_ref = ""
        with pytest.raises(AdapterError):
            manager.credentials(device)

    def test_ssid_length_validation(self, tmp_path: Path):
        manager = build_manager(tmp_path)
        manager.add_device("router-1", "192.168.1.1", "cudy", password="p")
        with pytest.raises(ValidationError):
            manager.set_wifi_ssid("router-1", "")
        with pytest.raises(ValidationError):
            manager.set_wifi_ssid("router-1", "x" * 33)

    def test_reboot_policy_round_trip(self, tmp_path: Path):
        manager = build_manager(tmp_path)
        manager.add_device(
            "router-1",
            "192.168.1.1",
            "cudy",
            password="p",
            reboot={"enabled": True, "at": "04:30", "timezone": "Europe/Lisbon"},
        )
        reopened = DeviceManager(config_path=tmp_path / "cudy_devices.yaml", data_dir=tmp_path / "data")
        assert reopened.get_device("router-1").reboot.enabled is True

    def test_dashboard_summary(self, tmp_path: Path):
        manager = build_manager(tmp_path)
        manager.add_device("router-1", "127.0.0.1", "cudy", password="p", http_port=1)
        data = manager.dashboard()
        assert data["summary"] == {"total_devices": 1, "online": 0, "offline": 1}

    def test_legacy_list_config_is_converted(self, tmp_path: Path):
        config = tmp_path / "cudy_devices.yaml"
        config.write_text(
            yaml.safe_dump({"devices": [{"id": "router-1", "vendor": "tenda", "host": "192.168.1.9"}]})
        )
        manager = DeviceManager(config_path=config, data_dir=tmp_path / "data")
        assert manager.get_device("router-1").vendor == "tenda"
