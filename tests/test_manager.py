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


class TestRuntimeStateSurvivesConfigWrites:
    """The config file holds configuration only; cached status must not be lost."""

    def _manager(self, tmp_path: Path) -> DeviceManager:
        return DeviceManager(
            config_path=tmp_path / "c.yaml",
            data_dir=tmp_path / "data",
            secret_store=SecretStore(tmp_path / "data"),
        )

    def _mark(self, manager: DeviceManager, identifier: str, uptime: int) -> None:
        device = manager.devices[identifier]
        device.status = {"online": True, "uptime_seconds": uptime}
        device.last_seen = f"2026-09-26T10:00:{uptime % 60:02d}"

    def test_updating_one_device_keeps_every_device_status(self, tmp_path: Path):
        manager = self._manager(tmp_path)
        manager.add_device("r1", "192.168.1.1", "cudy", password="pw")
        manager.add_device("r2", "192.168.1.2", "cudy", password="pw")
        self._mark(manager, "r1", 1001)
        self._mark(manager, "r2", 1002)

        manager.update_device("r1", model="Cudy-X1")

        assert manager.devices["r1"].status["uptime_seconds"] == 1001
        assert manager.devices["r2"].status["uptime_seconds"] == 1002, "unrelated device lost its status"

    def test_edited_device_keeps_its_own_status(self, tmp_path: Path):
        manager = self._manager(tmp_path)
        manager.add_device("r1", "192.168.1.1", "cudy", password="pw")
        self._mark(manager, "r1", 1001)

        manager.update_device("r1", model="Cudy-X1")

        assert manager.devices["r1"].status["uptime_seconds"] == 1001
        assert manager.devices["r1"].last_seen
        assert manager.devices["r1"].model == "Cudy-X1"

    def test_password_rotation_keeps_status(self, tmp_path: Path):
        manager = self._manager(tmp_path)
        manager.add_device("r1", "192.168.1.1", "cudy", password="pw")
        self._mark(manager, "r1", 1001)

        manager.set_password("r1", "rotated", verify=False)

        assert manager.devices["r1"].status["uptime_seconds"] == 1001
        assert manager.devices["r1"].last_seen

    def test_adding_a_device_keeps_existing_status(self, tmp_path: Path):
        manager = self._manager(tmp_path)
        manager.add_device("r1", "192.168.1.1", "cudy", password="pw")
        self._mark(manager, "r1", 1001)

        manager.add_device("r2", "192.168.1.2", "cudy", password="pw")

        assert manager.devices["r1"].status["uptime_seconds"] == 1001

    def test_status_is_still_dropped_for_a_removed_device(self, tmp_path: Path):
        manager = self._manager(tmp_path)
        manager.add_device("r1", "192.168.1.1", "cudy", password="pw")
        self._mark(manager, "r1", 1001)

        manager.remove_device("r1")
        manager.add_device("r1", "192.168.1.1", "cudy", password="pw")

        assert manager.devices["r1"].status == {}


class TestStatusFanOut:
    """Concurrent dashboard reads must share one sweep.

    Each sweep opens its own bounded thread pool. Without single-flight, a slow
    fleet plus the dashboard's periodic poll starts a second pool and re-queries
    every device, so both thread count and router load grow without bound.
    """

    def test_concurrent_dashboards_share_one_sweep(self, tmp_path: Path):
        import threading
        import time

        manager = build_manager(tmp_path)
        for index in range(30):
            manager.add_device(f"d{index}", f"192.0.2.{index}", "cudy", password="pw")

        counter = {"current": 0, "peak": 0, "calls": 0}
        guard = threading.Lock()

        def tracked(identifier):
            with guard:
                counter["current"] += 1
                counter["calls"] += 1
                counter["peak"] = max(counter["peak"], counter["current"])
            time.sleep(0.3)
            with guard:
                counter["current"] -= 1
            return {"online": False}

        manager.get_status = tracked

        workers = [threading.Thread(target=manager.dashboard, kwargs={"include_status": True}) for _ in range(5)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()

        assert counter["calls"] == 30, f"expected 30 status calls, issued {counter['calls']}"
        assert counter["peak"] <= 8, f"thread pool grew to {counter['peak']} concurrent calls"

    def test_a_later_poll_starts_a_fresh_sweep(self, tmp_path: Path):
        manager = build_manager(tmp_path)
        manager.add_device("d1", "192.0.2.1", "cudy", password="pw")
        calls: list[str] = []

        def tracked(identifier):
            calls.append(identifier)
            return {"online": True}

        manager.get_status = tracked
        manager.dashboard(include_status=True)
        manager.dashboard(include_status=True)

        assert calls == ["d1", "d1"], "a completed sweep must not be cached as a permanent result"

    def test_sweep_survives_a_failing_device(self, tmp_path: Path):
        manager = build_manager(tmp_path)
        manager.add_device("good", "192.0.2.1", "cudy", password="pw")
        manager.add_device("bad", "192.0.2.2", "cudy", password="pw")

        def tracked(identifier):
            if identifier == "bad":
                raise AdapterError("unreachable")
            return {"online": True}

        manager.get_status = tracked
        statuses = manager.get_all_statuses()

        assert statuses["good"] == {"online": True}
        assert statuses["bad"]["online"] is False
        assert "unreachable" in statuses["bad"]["error"]

    def test_no_devices_is_cheap(self, tmp_path: Path):
        manager = build_manager(tmp_path)
        assert manager.get_all_statuses() == {}
