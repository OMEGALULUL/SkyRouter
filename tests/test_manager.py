import fcntl
import http.client
import os
import threading
import time
from pathlib import Path

import pytest
import yaml

import cudy_manager.manager as manager_module
from cudy_manager.activity import ActivityError, ActivityLog
from cudy_manager.adapters import AdapterError, AuthenticationRejected, ProtocolMismatch, UnsupportedOperation
from cudy_manager.manager import DeviceManager, ManagerError
from cudy_manager.models import ValidationError
from cudy_manager.openwrt import OpenWrtAdapter
from cudy_manager.secrets import SecretStore, SecretStoreError


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

    def test_ssid_limit_is_bytes_not_characters(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """17 accented letters are 17 characters but 34 bytes, over the 802.11 limit."""
        manager = build_manager(tmp_path)
        manager.add_device("router-1", "192.168.1.1", "cudy", password="p")
        sent: list[str] = []

        class Adapter:
            def set_ssid(self, ssid, radio=None):
                sent.append(ssid)
                return True

        monkeypatch.setattr(manager, "adapter_for", lambda device: Adapter())
        with pytest.raises(ValidationError, match="32 bytes"):
            manager.set_wifi_ssid("router-1", "\u00e9" * 17)
        assert sent == [], "an oversized SSID reached the router"
        assert manager.set_wifi_ssid("router-1", " " + "\u00e9" * 16 + " ")
        assert sent == ["\u00e9" * 16]

    def test_an_ssid_with_no_utf8_form_is_refused_before_the_router(self, tmp_path: Path, monkeypatch):
        """JSON's \\ud800 escape decodes to a lone surrogate, which UTF-8 cannot encode."""
        manager = build_manager(tmp_path)
        manager.add_device("router-1", "192.168.1.1", "cudy", password="p")
        monkeypatch.setattr(manager, "adapter_for", lambda device: pytest.fail("the router was contacted"))
        with pytest.raises(ValidationError, match="valid Unicode"):
            manager.set_wifi_ssid("router-1", "ab\ud800cd")

    def test_validate_wifi_ssid_is_the_check_set_wifi_ssid_makes(self):
        assert manager_module.validate_wifi_ssid("  Home \n") == "Home"
        assert manager_module.validate_wifi_ssid("\u00e9" * 16) == "\u00e9" * 16
        for bad in ("", "   ", None, 7, "x" * 33, "\u00e9" * 17, "\udfff"):
            with pytest.raises(ValidationError):
                manager_module.validate_wifi_ssid(bad)

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


class TestSilentWipeGuard:
    """A mutation must not persist an empty inventory over a full one.

    The mutation path re-reads the config from disk and writes it back, so an
    emptied file would otherwise take every device and stored password with it.
    """

    def test_adding_a_device_keeps_the_others(self, tmp_path):
        manager = build_manager(tmp_path)
        manager.add_device("a", "192.168.1.1", "cudy", password="x")
        manager.add_device("b", "192.168.1.2", "cudy", password="y")
        manager.add_device("c", "192.168.1.3", "cudy", password="z")
        assert set(manager.devices) == {"a", "b", "c"}

    def test_a_file_truncated_behind_our_back_is_refused(self, tmp_path):
        manager = build_manager(tmp_path)
        manager.add_device("a", "192.168.1.1", "cudy", password="x")
        manager.add_device("b", "192.168.1.2", "cudy", password="y")
        # Something outside the manager empties the file.
        manager.config_path.write_text("devices: {}\n", encoding="utf-8")
        with pytest.raises(ManagerError, match="credentials are still stored"):
            manager.add_device("c", "192.168.1.3", "cudy", password="z")
        # The refusal must leave the file exactly as it was found, so an
        # operator can restore it and no further loss is written on top.
        assert manager.config_path.read_text() == "devices: {}\n"
        assert set(manager.devices) == {"a", "b"}, "in-memory inventory was replaced"

    def test_a_removal_made_by_another_process_is_still_honoured(self, tmp_path):
        """A real remove_device also drops the secret, so it must not be refused."""
        first = build_manager(tmp_path)
        first.add_device("r1", "192.168.1.1", "cudy", password="x")
        first.add_device("r2", "192.168.1.2", "cudy", password="y")
        second = build_manager(tmp_path)
        first.remove_device("r2")
        second.add_device("r3", "192.168.1.3", "cudy", password="z")
        assert set(second.devices) == {"r1", "r3"}

    def test_removing_the_last_device_still_works(self, tmp_path):
        manager = build_manager(tmp_path)
        manager.add_device("only", "192.168.1.1", "cudy", password="x")
        manager.remove_device("only")
        assert manager.devices == {}
        assert "devices: {}" in manager.config_path.read_text()

    def test_removing_one_of_several_keeps_the_rest(self, tmp_path):
        manager = build_manager(tmp_path)
        for name in ("a", "b", "c"):
            manager.add_device(name, f"192.168.1.{len(name)}", "cudy", password="x")
        manager.remove_device("b")
        assert set(manager.devices) == {"a", "c"}


class TestDefaultPaths:
    """``DeviceManager()`` is what the CLI builds, so its defaults must match the web server's.

    They used to differ: the CLI wrote the in-package config, and an exported but
    empty ROUTER_MANAGER_DATA_DIR became Path(""), creating a fresh vault and
    master.key in whatever directory the command was run from.
    """

    @pytest.fixture
    def env(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        home = tmp_path / "home"
        cwd = tmp_path / "cwd"
        home.mkdir()
        cwd.mkdir()
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.chdir(cwd)
        monkeypatch.delenv("ROUTER_MANAGER_CONFIG", raising=False)
        monkeypatch.delenv("ROUTER_MANAGER_DATA_DIR", raising=False)
        # Code that still defaults to the package directory (a red TDD run, a bisect)
        # would otherwise write a config into the source tree, which the real CLI then
        # reads with a password_ref into a vault pytest has already deleted.
        monkeypatch.setattr(manager_module, "__file__", str(tmp_path / "package" / "manager.py"))
        return tmp_path

    def test_default_config_sits_beside_the_vault(self, env: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("ROUTER_MANAGER_DATA_DIR", str(env / "state"))
        manager = DeviceManager()
        assert manager.config_path == env / "state" / "cudy_devices.yaml"
        package_dir = Path(__file__).resolve().parents[1] / "cudy_manager"
        assert package_dir not in manager.config_path.parents

    @pytest.mark.parametrize("value", ["", "   "])
    def test_an_empty_data_dir_writes_nothing_to_the_working_directory(
        self, env: Path, monkeypatch: pytest.MonkeyPatch, value: str
    ):
        monkeypatch.setenv("ROUTER_MANAGER_DATA_DIR", value)
        state = env / "home" / ".local" / "state" / "skybre-router-manager"
        manager = DeviceManager()
        # Checked before the add, so a wrong default fails without writing a device there.
        assert (manager.data_dir, manager.config_path) == (state, state / "cudy_devices.yaml")
        manager.add_device("r1", "192.168.1.1", "cudy", password="x")
        assert list((env / "cwd").iterdir()) == [], "vault or config was created in the working directory"
        assert (state / "master.key").exists()

    def test_an_empty_config_falls_back_beside_the_vault(self, env: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("ROUTER_MANAGER_DATA_DIR", str(env / "state"))
        monkeypatch.setenv("ROUTER_MANAGER_CONFIG", "")
        assert DeviceManager().config_path == env / "state" / "cudy_devices.yaml"

    @pytest.mark.parametrize(
        "variables",
        [{}, {"ROUTER_MANAGER_DATA_DIR": ""}, {"ROUTER_MANAGER_CONFIG": ""}, {"ROUTER_MANAGER_DATA_DIR": "state"}],
    )
    def test_cli_and_web_resolve_the_same_files(
        self, env: Path, monkeypatch: pytest.MonkeyPatch, variables: dict[str, str]
    ):
        from cudy_manager.web import Settings

        for name, value in variables.items():
            monkeypatch.setenv(name, value)
        manager = DeviceManager()
        settings = Settings.from_env()
        assert (manager.config_path, manager.data_dir) == (settings.config_path, settings.data_dir)

    def test_explicit_arguments_still_win(self, env: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("ROUTER_MANAGER_DATA_DIR", str(env / "ignored"))
        monkeypatch.setenv("ROUTER_MANAGER_CONFIG", str(env / "ignored.yaml"))
        manager = DeviceManager(config_path=env / "c.yaml", data_dir=env / "d")
        assert (manager.config_path, manager.data_dir) == (env / "c.yaml", env / "d")


class TestSharedSecretReferences:
    """remove_device keeps a secret another device still uses, so names can be shared.

    Every write used the fixed name ``device-<id>-password``, so re-adding a removed
    id, or rotating a password, could silently replace another device's credential.
    """

    def shared(self, tmp_path: Path) -> DeviceManager:
        manager = build_manager(tmp_path)
        manager.add_device("r1", "192.168.1.1", "cudy", password="mesh-admin")
        manager.add_device("r2", "192.168.1.2", "cudy", password_ref="device-r1-password")
        manager.remove_device("r1")
        assert manager.secrets.has("device-r1-password"), "precondition: r2 still uses it"
        return manager

    def test_re_adding_a_removed_id_leaves_the_survivor_alone(self, tmp_path: Path):
        manager = self.shared(tmp_path)
        manager.add_device("r1", "192.168.1.9", "tenda", password="unrelated")
        assert manager.credentials(manager.get_device("r2")) == "mesh-admin"
        assert manager.credentials(manager.get_device("r1")) == "unrelated"
        assert build_manager(tmp_path).credentials(build_manager(tmp_path).get_device("r2")) == "mesh-admin"

    def test_a_failed_add_does_not_delete_the_survivors_secret(self, tmp_path: Path, monkeypatch):
        manager = self.shared(tmp_path)

        def full_disk():
            raise OSError("no space left on device")

        monkeypatch.setattr(manager, "save_config", full_disk)
        with pytest.raises(OSError):
            manager.add_device("r1", "192.168.1.9", "tenda", password="unrelated")
        monkeypatch.undo()
        reloaded = build_manager(tmp_path)
        assert reloaded.credentials(reloaded.get_device("r2")) == "mesh-admin"

    def test_a_re_add_rejected_after_its_password_was_stored_keeps_the_survivors_secret(self, tmp_path: Path):
        manager = self.shared(tmp_path)
        with pytest.raises(ValidationError):
            manager.add_device("r1", "192.168.1.9", "tenda", password="unrelated", snmp_community="")
        assert manager.secrets.has("device-r1-password")
        reloaded = build_manager(tmp_path)
        assert reloaded.credentials(reloaded.get_device("r2")) == "mesh-admin"

    def test_rotating_a_shared_password_moves_only_that_device(self, tmp_path: Path):
        manager = build_manager(tmp_path)
        manager.add_device("a", "192.168.1.1", "cudy", password="shared")
        reference = manager.get_device("a").password_ref
        manager.add_device("b", "192.168.1.2", "cudy", password_ref=reference)
        manager.set_password("a", "rotated", verify=False)
        assert manager.credentials(manager.get_device("a")) == "rotated"
        assert manager.credentials(manager.get_device("b")) == "shared"

    def test_update_device_points_at_the_new_password(self, tmp_path: Path):
        manager = self.shared(tmp_path)
        manager.update_device("r2", password="r2-own")
        assert manager.credentials(manager.get_device("r2")) == "r2-own"
        assert build_manager(tmp_path).credentials(build_manager(tmp_path).get_device("r2")) == "r2-own"

    def test_update_device_sets_a_password_on_a_device_that_had_none(self, tmp_path: Path):
        manager = build_manager(tmp_path)
        manager.add_device("r1", "192.168.1.1", "cudy")
        manager.update_device("r1", password="first")
        assert manager.credentials(manager.get_device("r1")) == "first"

    def test_an_unshared_password_is_still_rotated_in_place(self, tmp_path: Path):
        manager = build_manager(tmp_path)
        manager.add_device("r1", "192.168.1.1", "cudy", password="old")
        reference = manager.get_device("r1").password_ref
        manager.set_password("r1", "new", verify=False)
        assert manager.get_device("r1").password_ref == reference
        assert manager.secrets.references() == [reference]


class TestConfigThatCannotBeTrusted:
    """Only a missing file means a new, empty inventory.

    Every CLI call and every server start is a fresh process, so the truncation guard
    has nothing in memory to compare against, and the next mutation writes whatever
    was loaded back over the original.
    """

    @pytest.mark.parametrize(
        "text",
        [
            "",
            "   \n",
            "r1:\n  vendor: cudy\n  host: 192.168.1.1\n",
            "device:\n  r1: {vendor: cudy, host: 192.168.1.1}\n",
            "- id: r1\n  vendor: cudy\n  host: 192.168.1.1\n",
            "devi",
            "{}\n",
        ],
    )
    def test_a_file_without_a_devices_mapping_is_refused_and_left_alone(self, tmp_path: Path, text: str):
        config = tmp_path / "cudy_devices.yaml"
        config.write_text(text)
        with pytest.raises(ManagerError):
            build_manager(tmp_path)
        assert config.read_text() == text

    def test_a_config_zeroed_by_a_crash_does_not_lose_the_devices(self, tmp_path: Path):
        manager = build_manager(tmp_path)
        manager.add_device("a", "192.168.1.1", "cudy", password="x")
        manager.add_device("b", "192.168.1.2", "cudy", password="y")
        manager.config_path.write_bytes(b"")
        with pytest.raises(ManagerError):
            build_manager(tmp_path).add_device("c", "192.168.1.3", "cudy", password="z")
        assert manager.config_path.read_bytes() == b""

    @pytest.mark.parametrize(
        "second",
        [
            {"name": "b", "vendor": "cudy", "host": "192.168.1.2"},
            {"id": "a", "vendor": "tenda", "host": "192.168.1.2"},
            "b",
        ],
    )
    def test_a_legacy_list_that_would_drop_entries_is_refused(self, tmp_path: Path, second):
        config = tmp_path / "cudy_devices.yaml"
        config.write_text(yaml.safe_dump({"devices": [{"id": "a", "vendor": "cudy", "host": "192.168.1.1"}, second]}))
        before = config.read_text()
        with pytest.raises(ManagerError):
            build_manager(tmp_path)
        assert config.read_text() == before

    @pytest.mark.parametrize("text", ["devices: {}\n", "devices: []\n"])
    def test_an_explicitly_empty_inventory_still_loads(self, tmp_path: Path, text: str):
        (tmp_path / "cudy_devices.yaml").write_text(text)
        assert build_manager(tmp_path).devices == {}

    def test_a_yaml_syntax_error_is_a_manager_error(self, tmp_path: Path):
        config = tmp_path / "cudy_devices.yaml"
        config.write_text("devices: {r1: [\n")
        with pytest.raises(ManagerError, match="unreadable"):
            build_manager(tmp_path)
        assert config.read_text() == "devices: {r1: [\n"


class TestConfigWrites:
    def test_a_saved_config_is_synced_before_and_after_it_is_published(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """An un-synced replace can leave a zero-length config after a power cut."""
        manager = build_manager(tmp_path)
        events: list[str] = []
        real_fsync, real_replace = os.fsync, os.replace

        def fsync(fd):
            events.append("fsync")
            real_fsync(fd)

        def replace(source, target):
            events.append("replace")
            real_replace(source, target)

        monkeypatch.setattr(os, "fsync", fsync)
        monkeypatch.setattr(os, "replace", replace)
        manager.save_config()
        assert events == ["fsync", "replace", "fsync"]

    def test_interleaved_saves_do_not_share_a_temporary_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        first = build_manager(tmp_path)
        first.add_device("r1", "192.168.1.1", "cudy", password="x")
        second = build_manager(tmp_path)
        real_replace = os.replace

        def replace(source, target):
            monkeypatch.setattr(os, "replace", real_replace)
            second.save_config()
            real_replace(source, target)

        monkeypatch.setattr(os, "replace", replace)
        first.save_config()
        assert set(yaml.safe_load(first.config_path.read_text())["devices"]) == {"r1"}
        assert [path.name for path in tmp_path.iterdir() if path.name.endswith(".tmp")] == []

    def test_creating_a_missing_config_waits_for_a_writer_holding_the_lock(self, tmp_path: Path):
        """Startup used to write ``devices: {}`` unlocked, over an add another process had just saved."""
        config = tmp_path / "cudy_devices.yaml"
        (tmp_path / "data").mkdir()
        lock = os.open(f"{config}.lock", os.O_WRONLY | os.O_CREAT, 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)
        built: dict[str, DeviceManager] = {}
        starter = threading.Thread(target=lambda: built.setdefault("manager", build_manager(tmp_path)))
        try:
            starter.start()
            starter.join(0.3)
            assert not config.exists(), "the missing config was created without taking the lock"
            config.write_text(yaml.safe_dump({"devices": {"r1": {"vendor": "cudy", "host": "192.168.1.1"}}}))
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)
            os.close(lock)
            starter.join(5)
        assert set(built["manager"].devices) == {"r1"}
        assert set(yaml.safe_load(config.read_text())["devices"]) == {"r1"}

    def test_a_failed_save_leaves_no_phantom_device(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        manager = build_manager(tmp_path)
        manager.add_device("keep", "192.168.1.1", "cudy", password="k")

        def full_disk():
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(manager, "save_config", full_disk)
        with pytest.raises(OSError):
            manager.add_device("ghost", "192.168.1.2", "cudy", password="p")
        assert set(manager.devices) == {"keep"}
        with pytest.raises(OSError):
            manager.update_device("keep", model="Unsaved")
        assert manager.get_device("keep").model == ""
        monkeypatch.undo()
        manager.add_device("other", "192.168.1.3", "cudy", password="o")
        assert set(manager.devices) == {"keep", "other"}


class TestSharedReferenceRemovalAcrossProcesses:
    def test_a_removal_of_a_shared_reference_by_another_process_is_honoured(self, tmp_path: Path):
        first = build_manager(tmp_path)
        first.add_device("r1", "192.168.1.1", "cudy", password="x")
        first.add_device("r2", "192.168.1.2", "cudy", password_ref=first.get_device("r1").password_ref)
        second = build_manager(tmp_path)
        first.remove_device("r1")
        second.add_device("r3", "192.168.1.3", "cudy", password="z")
        assert set(second.devices) == {"r2", "r3"}
        assert second.credentials(second.get_device("r2")) == "x"

    def test_the_guard_still_fires_when_devices_sharing_a_reference_are_truncated(self, tmp_path: Path):
        manager = build_manager(tmp_path)
        manager.add_device("r1", "192.168.1.1", "cudy", password="x")
        manager.add_device("r2", "192.168.1.2", "cudy", password_ref=manager.get_device("r1").password_ref)
        manager.config_path.write_text("devices: {}\n")
        with pytest.raises(ManagerError, match="credentials are still stored"):
            manager.add_device("r3", "192.168.1.3", "cudy", password="z")

    def test_secrets_are_deleted_before_the_lock_is_released(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Another manager that still lists the device must never see it gone with its secret present."""
        remover = build_manager(tmp_path)
        remover.add_device("r1", "192.168.1.1", "cudy", password="x")
        remover.add_device("r2", "192.168.1.2", "cudy", password="y")
        other = build_manager(tmp_path)
        errors: list[ManagerError] = []
        workers: list[threading.Thread] = []
        real_delete = remover.secrets.delete

        def other_adds():
            try:
                other.add_device("r3", "192.168.1.3", "cudy", password="z")
            except ManagerError as exc:
                errors.append(exc)

        def delete(reference):
            if not workers:
                workers.append(threading.Thread(target=other_adds))
                workers[0].start()
                workers[0].join(0.5)
            return real_delete(reference)

        monkeypatch.setattr(remover.secrets, "delete", delete)
        remover.remove_device("r1")
        workers[0].join(5)
        assert errors == []
        assert set(other.devices) == {"r2", "r3"}

    def test_a_vault_failure_after_the_save_still_removes_the_device(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        manager = build_manager(tmp_path)
        manager.add_device("r1", "192.168.1.1", "cudy", password="x")
        manager.add_device("r2", "192.168.1.2", "cudy", password="y")

        def read_only(reference):
            raise SecretStoreError("secret vault is read-only")

        monkeypatch.setattr(manager.secrets, "delete", read_only)
        manager.remove_device("r1")
        assert set(manager.devices) == {"r2"}
        assert set(yaml.safe_load(manager.config_path.read_text())["devices"]) == {"r2"}
        monkeypatch.undo()
        assert set(build_manager(tmp_path).devices) == {"r2"}


class TestMutationsSeeTheCurrentFile:
    def test_a_rejected_update_leaves_the_stored_password_alone(self, tmp_path: Path):
        manager = build_manager(tmp_path)
        manager.add_device("r1", "192.168.1.1", "cudy", password="old")
        with pytest.raises(ValidationError):
            manager.update_device("r1", password="new", snmp_community="")
        assert manager.credentials(manager.get_device("r1")) == "old"
        with pytest.raises(ValidationError):
            manager.update_device("r1", password="new", http_port=0)
        assert manager.credentials(manager.get_device("r1")) == "old"

    def test_a_device_added_by_another_process_can_be_edited(self, tmp_path: Path):
        dashboard = build_manager(tmp_path)
        dashboard.add_device("r1", "192.168.1.1", "cudy", password="one")
        build_manager(tmp_path).add_device("r2", "192.168.1.2", "cudy", password="two")
        dashboard.update_device("r2", model="X")
        dashboard.set_password("r2", "rotated", verify=False)
        assert dashboard.get_device("r2").model == "X"
        assert dashboard.credentials(dashboard.get_device("r2")) == "rotated"

    def test_set_password_accepts_the_host_that_get_device_accepts(self, tmp_path: Path):
        manager = build_manager(tmp_path)
        manager.add_device("r1", "192.168.1.1", "cudy", password="old")
        result = manager.set_password("192.168.1.1", "new", verify=False)
        assert result["device"] == "r1"
        assert manager.credentials(manager.get_device("r1")) == "new"

    @pytest.mark.parametrize("key", ["identifier", "self"])
    def test_a_body_key_named_like_a_parameter_is_not_a_crash(self, tmp_path: Path, key: str):
        manager = build_manager(tmp_path)
        manager.add_device("r1", "192.168.1.1", "cudy", password="p", **{key: "x"})
        manager.update_device("r1", **{key: "x", "model": "M"})
        assert set(manager.devices) == {"r1"}
        assert manager.get_device("r1").model == "M"


class TestHostLookup:
    def test_a_host_shared_by_two_devices_is_ambiguous(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        manager = build_manager(tmp_path)
        manager.add_device("a", "198.51.100.7", "cudy", password="p", http_port=8080)
        manager.add_device("b", "198.51.100.7", "cudy", password="p", http_port=8081)
        rebooted: list[str] = []

        class Adapter:
            def __init__(self, device):
                self.device = device

            def reboot(self):
                rebooted.append(self.device.identifier)
                return True

        monkeypatch.setattr(manager, "adapter_for", Adapter)
        with pytest.raises(ManagerError, match="more than one device"):
            manager.reboot_device("198.51.100.7")
        assert rebooted == []
        assert manager.reboot_device("b")
        assert rebooted == ["b"]


class TestStatusSweepCoverage:
    def test_a_disabled_device_is_not_polled(self, tmp_path: Path):
        manager = build_manager(tmp_path)
        manager.add_device("on", "192.0.2.1", "cudy", password="p")
        manager.add_device("off", "192.0.2.2", "tplink", password="p", enabled=False)
        polled: list[str] = []

        def tracked(identifier):
            polled.append(identifier)
            return {"online": True}

        manager.get_status = tracked
        data = manager.dashboard(include_status=True)
        assert polled == ["on"]
        statuses = {item["id"]: item["status"] for item in data["devices"]}
        assert statuses["off"]["online"] is None
        assert statuses["off"]["reason"] == "disabled"
        assert data["summary"] == {"total_devices": 2, "online": 1, "offline": 0}

    def test_a_device_added_during_a_sweep_is_unknown_not_offline(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        manager = build_manager(tmp_path)
        manager.add_device("a", "192.0.2.1", "cudy", password="p")
        started, release = threading.Event(), threading.Event()
        joins: list[object] = []
        real_join = manager_module._StatusSweep.join

        def join(flight):
            # The sweep may finish only once both dashboards are waiting on it.
            joins.append(flight)
            if len(joins) == 2:
                release.set()
            return real_join(flight)

        def slow(identifier):
            started.set()
            release.wait(5)
            return {"online": True}

        monkeypatch.setattr(manager_module._StatusSweep, "join", join)
        manager.get_status = slow
        poll = threading.Thread(target=manager.dashboard, kwargs={"include_status": True})
        poll.start()
        assert started.wait(5)
        manager.add_device("b", "192.0.2.2", "cudy", password="p")
        result = manager.dashboard(include_status=True)
        poll.join(5)
        assert len(joins) == 2 and joins[0] is joins[1], "precondition: both dashboards shared one sweep"
        statuses = {item["id"]: item["status"] for item in result["devices"]}
        assert statuses["a"]["online"] is True
        assert statuses["b"].get("online") is None, "a router that was never contacted was reported offline"
        assert result["summary"]["offline"] == 0

    def test_an_unexpected_exception_does_not_abort_the_sweep(self, tmp_path: Path):
        manager = build_manager(tmp_path)
        manager.add_device("good", "192.0.2.1", "cudy", password="p")
        manager.add_device("bad", "192.0.2.2", "cudy", password="p")

        def tracked(identifier):
            if identifier == "bad":
                raise http.client.BadStatusLine("\x15\x03\x01")
            time.sleep(0.2)
            return {"online": True}

        manager.get_status = tracked
        statuses = manager.get_all_statuses()
        assert statuses["good"] == {"online": True}
        assert statuses["bad"]["online"] is False


class _FakeAdapter:
    """Stands in for a router adapter; ``close`` is what the SSH adapter must receive."""

    def __init__(self, outcome):
        self.outcome = outcome
        self.closed = 0

    def _run(self):
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome

    def status(self):
        return self._run()

    def reboot(self):
        return self._run()

    def close(self):
        self.closed += 1


class TestAdapterLifecycle:
    def factory(self, manager: DeviceManager, monkeypatch: pytest.MonkeyPatch, outcome) -> list[_FakeAdapter]:
        made: list[_FakeAdapter] = []

        def build(device):
            made.append(_FakeAdapter(outcome))
            return made[-1]

        monkeypatch.setattr(manager, "adapter_for", build)
        return made

    def test_every_use_closes_the_adapter(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        manager = build_manager(tmp_path)
        manager.add_device("r1", "192.168.1.1", "cudy", password="p")
        made = self.factory(manager, monkeypatch, {"online": True})
        assert manager.get_status("r1")["online"] is True
        assert manager.verify_credentials("r1")["ok"] is True
        assert manager.reboot_device("r1")
        assert [adapter.closed for adapter in made] == [1, 1, 1]

    @pytest.mark.parametrize("error", [AdapterError("timed out"), http.client.BadStatusLine("x")])
    def test_a_failing_call_still_closes_the_adapter(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: Exception
    ):
        manager = build_manager(tmp_path)
        manager.add_device("r1", "192.168.1.1", "cudy", password="p")
        made = self.factory(manager, monkeypatch, error)
        assert manager.get_status("r1")["online"] is False
        assert manager.verify_credentials("r1")["reason"] == "unreachable"
        with pytest.raises(type(error)):
            manager.reboot_device("r1")
        assert [adapter.closed for adapter in made] == [1, 1, 1]

    def test_a_rejection_closes_the_adapter_and_keeps_the_latch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        manager = build_manager(tmp_path)
        manager.add_device("r1", "192.168.1.1", "tplink", password="wrong")
        made = self.factory(manager, monkeypatch, AuthenticationRejected("bad password"))
        assert manager.get_status("r1")["reason"] == "credentials_rejected"
        assert manager.get_status("r1")["reason"] == "credentials_rejected"
        with pytest.raises(AuthenticationRejected, match="already rejected"):
            manager.reboot_device("r1")
        assert [adapter.closed for adapter in made] == [1], "the latch let a second login through"

    def test_ssh_transport_selects_the_ssh_adapter_for_every_vendor(self, tmp_path: Path):
        manager = build_manager(tmp_path)
        for vendor in ("cudy", "tenda", "tplink"):
            manager.add_device(vendor, "192.168.1.1", vendor, password="p", transport="ssh")
            assert isinstance(manager.adapter_for(manager.get_device(vendor)), OpenWrtAdapter), vendor


class TestVerifyCredentialsReasons:
    @pytest.mark.parametrize(
        ("error", "reason"),
        [
            (AuthenticationRejected("wrong password"), "rejected"),
            (ProtocolMismatch("login page exposed no salt"), "protocol"),
            (UnsupportedOperation("login did not provide a salt"), "protocol"),
            (AdapterError("connection timed out"), "unreachable"),
            (http.client.RemoteDisconnected("closed"), "unreachable"),
        ],
    )
    def test_a_router_that_answered_is_not_called_unreachable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: Exception, reason: str
    ):
        manager = build_manager(tmp_path)
        manager.add_device("r1", "192.168.1.1", "cudy", password="p")
        monkeypatch.setattr(manager, "adapter_for", lambda device: _FakeAdapter(error))
        result = manager.verify_credentials("r1")
        assert (result["ok"], result["reason"]) == (False, reason)


class TestSshHostKeysAreRemembered:
    def test_the_ssh_adapter_gets_a_known_hosts_file_beside_the_vault(self, tmp_path: Path):
        """Without it, accept_unknown_host_key devices failed every connection."""
        manager = build_manager(tmp_path)
        device = manager.add_device(
            "r1", "192.168.1.1", "cudy", password="p", transport="ssh", accept_unknown_host_key=True
        )
        adapter = manager.adapter_for(device)
        assert adapter.known_hosts == manager.data_dir / "ssh_known_hosts"


class TestWifiPassword:
    @pytest.mark.parametrize(
        "password",
        ["short", "x" * 64, "caf\u00e9-password", "tab\there12", 12345678, None],
    )
    def test_invalid_passphrases_never_reach_the_router(self, tmp_path: Path, monkeypatch, password):
        manager = build_manager(tmp_path)
        manager.add_device("r1", "192.168.1.1", "cudy", password="p", transport="ssh")
        monkeypatch.setattr(manager, "adapter_for", lambda device: pytest.fail("router contacted"))
        with pytest.raises(ValidationError):
            manager.set_wifi_password("r1", password)

    def test_a_valid_passphrase_goes_to_the_adapter_with_the_radio(self, tmp_path: Path, monkeypatch):
        manager = build_manager(tmp_path)
        manager.add_device("r1", "192.168.1.1", "cudy", password="p", transport="ssh")
        sent = []

        class Adapter:
            def set_wifi_password(self, password, radio=None):
                sent.append((password, radio))
                return True

        monkeypatch.setattr(manager, "adapter_for", lambda device: Adapter())
        assert manager.set_wifi_password("r1", "correct horse ~!", "5G") is True
        assert sent == [("correct horse ~!", "5G")]

    @pytest.mark.parametrize(("vendor", "transport"), [("tplink", "web"), ("tenda", "web")])
    def test_adapters_without_a_verified_protocol_refuse_and_say_why(self, tmp_path: Path, vendor, transport):
        from cudy_manager.adapters import UnsupportedOperation

        manager = build_manager(tmp_path)
        device = manager.add_device("r1", "192.168.1.1", vendor, password="p", transport=transport)
        with pytest.raises(UnsupportedOperation, match="Wi-Fi password"):
            manager.adapter_for(device).set_wifi_password("goodpassword")


def build_logged_manager(tmp_path: Path) -> tuple[DeviceManager, ActivityLog]:
    activity = ActivityLog(tmp_path / "data")
    manager = DeviceManager(
        config_path=tmp_path / "cudy_devices.yaml",
        data_dir=tmp_path / "data",
        secret_store=SecretStore(tmp_path / "data"),
        activity=activity,
    )
    return manager, activity


class _Router:
    """A router that answers every operation with ``outcome`` and remembers what it was asked."""

    def __init__(self, outcome: object = True, during=None):
        self.outcome = outcome
        self.during = during
        self.calls: list[tuple] = []

    def _answer(self, *call):
        self.calls.append(call)
        if self.during is not None:
            self.during()
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome

    def status(self):
        self._answer("status")
        return {"online": True}

    def reboot(self):
        return self._answer("reboot")

    def set_ssid(self, ssid, radio=None):
        return self._answer("set_ssid", ssid, radio)

    def set_wifi_password(self, password, radio=None):
        return self._answer("set_wifi_password", password, radio)


class TestActivityLogging:
    def raw(self, tmp_path: Path) -> bytes:
        path = tmp_path / "data" / "activity.jsonl"
        return path.read_bytes() if path.exists() else b""

    def only(self, activity: ActivityLog) -> dict:
        (entry,) = activity.list()
        return entry

    def test_without_an_activity_log_nothing_is_recorded(self, tmp_path: Path, monkeypatch):
        manager = build_manager(tmp_path)
        manager.add_device("r1", "192.168.1.1", "cudy", password="p", actor="alice")
        monkeypatch.setattr(manager, "adapter_for", lambda device: _Router())
        assert manager.reboot_device("r1", actor="alice")
        assert not (tmp_path / "data" / "activity.jsonl").exists()

    def test_adding_a_router_names_who_and_where(self, tmp_path: Path):
        manager, activity = build_logged_manager(tmp_path)
        manager.add_device(
            "r1", "192.168.1.1", "cudy", password="router-secret-1", actor="alice", metadata={"name": "Shop"}
        )
        entry = self.only(activity)
        assert (entry["who"], entry["router"], entry["router_name"]) == ("alice", "r1", "Shop")
        assert (entry["kind"], entry["result"]) == ("setup", "applied")
        assert entry["what"] == "Added cudy router at 192.168.1.1:80"
        assert entry["details"] == {"vendor": "cudy", "host": "192.168.1.1", "transport": "web"}
        assert b"router-secret-1" not in self.raw(tmp_path)

    def test_the_default_actor_is_system(self, tmp_path: Path, monkeypatch):
        manager, activity = build_logged_manager(tmp_path)
        manager.add_device("r1", "192.168.1.1", "cudy", password="p")
        monkeypatch.setattr(manager, "adapter_for", lambda device: _Router())
        manager.reboot_device("r1")
        assert [entry["who"] for entry in activity.list()] == ["system", "system"]

    def test_a_router_without_a_name_is_shown_by_its_id(self, tmp_path: Path):
        manager, activity = build_logged_manager(tmp_path)
        manager.add_device("r1", "192.168.1.1", "tplink", password="p")
        assert self.only(activity)["router_name"] == "r1"

    def test_a_refused_add_is_recorded_with_the_reason(self, tmp_path: Path):
        manager, activity = build_logged_manager(tmp_path)
        manager.add_device("r1", "192.168.1.1", "cudy", password="p")
        with pytest.raises(ManagerError):
            manager.add_device("r1", "192.168.1.2", "cudy", password="p", actor="bob")
        with pytest.raises(ValidationError):
            manager.add_device("r2", "192.168.1.3", "ubiquiti", password="p", actor="bob")
        vendor, duplicate, _ = activity.list()
        assert (duplicate["result"], duplicate["router"], duplicate["who"]) == ("refused", "r1", "bob")
        assert duplicate["what"] == "Adding the router refused: device 'r1' already exists"
        assert vendor["what"] == "Adding the router refused: vendor must be cudy, tenda, or tplink"
        assert vendor["router"] == "r2"

    def test_an_edit_names_each_setting_it_changed_with_old_and_new_values(self, tmp_path: Path):
        manager, activity = build_logged_manager(tmp_path)
        manager.add_device("r1", "192.168.1.1", "cudy", password="p")
        manager.update_device(
            "r1",
            actor="bob",
            model="AP1300",
            http_port=8080,
            enabled=False,
            reboot={"enabled": True, "at": "04:30", "timezone": "Europe/Lisbon"},
            metadata={"note": "gate code 4471"},
        )
        entry = activity.list()[0]
        assert (entry["who"], entry["kind"], entry["result"]) == ("bob", "setup", "applied")
        assert entry["what"] == (
            'Settings changed: http_port 80 → 8080, model "" → "AP1300", enabled on → off, '
            "reboot schedule off → daily at 04:30 Europe/Lisbon, metadata"
        )
        assert entry["details"] == {"changed": ["http_port", "model", "enabled", "reboot", "metadata"]}
        assert b"4471" not in self.raw(tmp_path), "free-form metadata was copied into the log"

    def test_an_edit_that_changes_nothing_says_so(self, tmp_path: Path):
        manager, activity = build_logged_manager(tmp_path)
        manager.add_device("r1", "192.168.1.1", "cudy", password="p")
        manager.update_device("r1", model="", http_port="80")
        assert activity.list()[0]["what"] == "Settings saved with no changes"

    def test_a_password_set_through_an_edit_is_a_credentials_entry_without_the_password(self, tmp_path: Path):
        manager, activity = build_logged_manager(tmp_path)
        manager.add_device("r1", "192.168.1.1", "cudy", password="first-router-pass")
        manager.update_device("r1", password="n3w-router-pass", snmp_community="c0mmunity-str", actor="bob")
        entry = activity.list()[0]
        assert (entry["kind"], entry["result"]) == ("credentials", "applied")
        assert entry["what"] == "router login password replaced; SNMP community replaced"
        assert entry["details"] == {"changed": ["password", "snmp_community"]}
        raw = self.raw(tmp_path)
        for secret in (b"first-router-pass", b"n3w-router-pass", b"c0mmunity-str"):
            assert secret not in raw

    def test_editing_a_missing_router_is_refused(self, tmp_path: Path):
        manager, activity = build_logged_manager(tmp_path)
        with pytest.raises(ManagerError):
            manager.update_device("ghost", model="x", actor="bob")
        entry = self.only(activity)
        assert (entry["router"], entry["result"], entry["kind"]) == ("ghost", "refused", "setup")
        assert entry["what"] == "Settings change refused: device 'ghost' does not exist"

    def test_an_edit_is_attributed_by_id_never_by_a_matching_host(self, tmp_path: Path):
        """update and remove take an id; naming another device whose host matches would blame it."""
        manager, activity = build_logged_manager(tmp_path)
        manager.add_device("r1", "10.0.0.1", "cudy", password="p")
        with pytest.raises(ManagerError):
            manager.remove_device("10.0.0.1", actor="bob")
        assert activity.list()[0]["router"] == "10.0.0.1"
        assert set(manager.devices) == {"r1"}

    def test_removal_is_recorded(self, tmp_path: Path):
        manager, activity = build_logged_manager(tmp_path)
        manager.add_device("r1", "192.168.1.1", "tenda", password="p", metadata={"name": "Office"})
        manager.remove_device("r1", actor="carol")
        entry = activity.list()[0]
        assert (entry["who"], entry["router"], entry["router_name"]) == ("carol", "r1", "Office")
        assert (entry["kind"], entry["result"]) == ("setup", "applied")
        assert entry["what"] == "Removed tenda router at 192.168.1.1:80"
        with pytest.raises(ManagerError):
            manager.remove_device("r1", actor="carol")
        assert activity.list()[0]["what"] == "Removing the router refused: device 'r1' does not exist"

    @pytest.mark.parametrize(
        ("verify", "outcome", "what", "verification"),
        [
            (False, True, "Router login password changed (not tested)", "skipped"),
            (True, True, "Router login password changed and accepted by the router", "ok"),
            (
                True,
                AuthenticationRejected("wrong"),
                "Router login password changed, but the router rejected it",
                "rejected",
            ),
            (
                True,
                AdapterError("timed out"),
                "Router login password changed; it could not be tested (unreachable)",
                "unreachable",
            ),
        ],
    )
    def test_a_password_change_records_how_its_test_went(
        self, tmp_path: Path, monkeypatch, verify, outcome, what, verification
    ):
        manager, activity = build_logged_manager(tmp_path)
        manager.add_device("r1", "192.168.1.1", "cudy", password="p")
        monkeypatch.setattr(manager, "adapter_for", lambda device: _Router(outcome))
        manager.set_password("192.168.1.1", "rotated-login-pass", verify=verify, actor="dave")
        entry = activity.list()[0]
        assert (entry["who"], entry["router"], entry["kind"]) == ("dave", "r1", "credentials")
        assert entry["result"] == "applied"
        assert entry["what"] == what
        assert entry["details"] == {"verification": verification}
        assert b"rotated-login-pass" not in self.raw(tmp_path)

    def test_a_reboot_is_recorded_once_it_has_finished(self, tmp_path: Path, monkeypatch):
        manager, activity = build_logged_manager(tmp_path)
        manager.add_device("r1", "192.168.1.1", "cudy", password="p")
        seen_during: list[int] = []
        router = _Router(True, during=lambda: seen_during.append(len(activity.list())))
        monkeypatch.setattr(manager, "adapter_for", lambda device: router)
        assert manager.reboot_device("r1", actor="erin")
        assert seen_during == [1], "the reboot was logged before the router answered"
        entry = activity.list()[0]
        assert (entry["who"], entry["kind"], entry["result"], entry["what"]) == (
            "erin",
            "reboot",
            "applied",
            "Reboot started",
        )

    @pytest.mark.parametrize(
        ("outcome", "result", "what"),
        [
            (False, "failed", "Reboot not confirmed by the router"),
            (AdapterError("timed out"), "failed", "Reboot failed: timed out"),
            (UnsupportedOperation("no reboot here"), "refused", "Reboot refused: no reboot here"),
        ],
    )
    def test_a_reboot_that_did_not_happen_says_why(self, tmp_path: Path, monkeypatch, outcome, result, what):
        manager, activity = build_logged_manager(tmp_path)
        manager.add_device("r1", "192.168.1.1", "cudy", password="p")
        monkeypatch.setattr(manager, "adapter_for", lambda device: _Router(outcome))
        if isinstance(outcome, BaseException):
            with pytest.raises(type(outcome)):
                manager.reboot_device("r1")
        else:
            assert manager.reboot_device("r1") is False
        entry = activity.list()[0]
        assert (entry["result"], entry["what"]) == (result, what)

    def test_a_credential_the_router_refused_is_not_sent_again_and_that_is_a_refusal(
        self, tmp_path: Path, monkeypatch
    ):
        manager, activity = build_logged_manager(tmp_path)
        manager.add_device("r1", "192.168.1.1", "tplink", password="wrong")
        router = _Router(AuthenticationRejected("bad password"))
        monkeypatch.setattr(manager, "adapter_for", lambda device: router)
        with pytest.raises(AuthenticationRejected):
            manager.reboot_device("r1")
        with pytest.raises(AuthenticationRejected, match="already rejected"):
            manager.reboot_device("r1")
        assert router.calls == [("reboot",)]
        latched, tried = activity.list(limit=2)
        assert (tried["result"], tried["what"]) == ("failed", "Reboot failed: bad password")
        assert latched["result"] == "refused"
        assert latched["what"].startswith("Reboot refused: not contacting r1: the router already rejected")

    def test_a_wifi_rename_names_the_old_and_new_network_per_band(self, tmp_path: Path, monkeypatch):
        manager, activity = build_logged_manager(tmp_path)
        manager.add_device("r1", "192.168.1.1", "cudy", password="p")
        monkeypatch.setattr(manager, "adapter_for", lambda device: _Router())
        manager.devices["r1"].status = {"online": True, "ssids": {"2.4G": "OldHome", "5G": "OldHome-5G"}}
        manager.set_wifi_ssid("r1", " NewHome ", actor="carol")
        entry = activity.list()[0]
        assert (entry["who"], entry["kind"], entry["result"]) == ("carol", "wifi", "applied")
        assert entry["what"] == 'Wi-Fi name changed: 2.4G "OldHome" → "NewHome", 5G "OldHome-5G" → "NewHome"'
        assert entry["details"] == {
            "bands": ["2.4G", "5G"],
            "ssid": "NewHome",
            "old": {"2.4G": "OldHome", "5G": "OldHome-5G"},
        }
        manager.set_wifi_ssid("r1", "Five", "5G", actor="carol")
        assert activity.list()[0]["what"] == 'Wi-Fi name changed: 5G "OldHome-5G" → "Five"'

    def test_a_wifi_rename_without_the_old_name_gives_the_new_one(self, tmp_path: Path, monkeypatch):
        manager, activity = build_logged_manager(tmp_path)
        manager.add_device("r1", "192.168.1.1", "cudy", password="p")
        monkeypatch.setattr(manager, "adapter_for", lambda device: _Router())
        manager.set_wifi_ssid("r1", "NewHome")
        assert activity.list()[0]["what"] == 'Wi-Fi name changed to "NewHome" (2.4G, 5G)'
        assert activity.list()[0]["details"]["old"] == {}
        manager.devices["r1"].status = {"online": True, "ssids": {"2.4G": "OldHome"}}
        manager.set_wifi_ssid("r1", "NewHome")
        assert activity.list()[0]["what"] == 'Wi-Fi name changed: 2.4G "OldHome" → "NewHome", 5G → "NewHome"'

    @pytest.mark.parametrize(
        ("vendor", "values", "bands"),
        [
            ("tenda", {"metadata": {"radio": "5G"}}, "5G"),
            ("tenda", {}, "2.4G"),
            ("cudy", {"transport": "ssh", "metadata": {"uci_section": "wireless.lan"}}, "wireless.lan"),
            ("cudy", {"transport": "ssh"}, "all bands"),
        ],
    )
    def test_the_bands_named_are_the_ones_the_router_changes(self, tmp_path: Path, monkeypatch, vendor, values, bands):
        manager, activity = build_logged_manager(tmp_path)
        manager.add_device("r1", "192.168.1.1", vendor, password="p", **values)
        monkeypatch.setattr(manager, "adapter_for", lambda device: _Router())
        manager.set_wifi_password("r1", "correct horse battery")
        assert activity.list()[0]["what"] == f"Wi-Fi password changed ({bands})"

    def test_an_invalid_ssid_is_a_recorded_refusal(self, tmp_path: Path, monkeypatch):
        manager, activity = build_logged_manager(tmp_path)
        manager.add_device("r1", "192.168.1.1", "cudy", password="p", metadata={"name": "Shop"})
        monkeypatch.setattr(manager, "adapter_for", lambda device: pytest.fail("router contacted"))
        with pytest.raises(ValidationError):
            manager.set_wifi_ssid("r1", "x" * 33, actor="carol")
        entry = activity.list()[0]
        assert (entry["router"], entry["router_name"], entry["result"]) == ("r1", "Shop", "refused")
        assert entry["what"].startswith("Wi-Fi name change refused: SSID must be at most 32 bytes")

    def test_a_wifi_password_entry_says_only_which_bands_changed(self, tmp_path: Path, monkeypatch):
        manager, activity = build_logged_manager(tmp_path)
        manager.add_device("r1", "192.168.1.1", "cudy", password="p")
        router = _Router()
        monkeypatch.setattr(manager, "adapter_for", lambda device: router)
        manager.set_wifi_password("r1", "correct horse battery", actor="dave")
        manager.set_wifi_password("r1", "staple horse battery", "2.4G", actor="dave")
        second, first = activity.list(limit=2)
        assert first["what"] == "Wi-Fi password changed (2.4G, 5G)"
        assert first["details"] == {"bands": ["2.4G", "5G"]}
        assert (first["who"], first["kind"], first["result"]) == ("dave", "wifi", "applied")
        assert second["what"] == "Wi-Fi password changed (2.4G)"
        raw = self.raw(tmp_path)
        assert b"horse" not in raw
        assert router.calls[0] == ("set_wifi_password", "correct horse battery", None)

    def test_a_router_error_that_quotes_the_passphrase_is_withheld_from_the_log(self, tmp_path: Path, monkeypatch):
        manager, activity = build_logged_manager(tmp_path)
        manager.add_device("r1", "192.168.1.1", "cudy", password="p")
        passphrase = "correct horse battery"
        monkeypatch.setattr(manager, "adapter_for", lambda device: _Router(AdapterError(f"rejected key {passphrase}")))
        with pytest.raises(AdapterError):
            manager.set_wifi_password("r1", passphrase, actor="dave")
        entry = activity.list()[0]
        assert entry["result"] == "failed"
        assert entry["what"] == (
            "Wi-Fi password change (2.4G, 5G) failed: error details withheld because they quoted the new password"
        )
        assert b"horse" not in self.raw(tmp_path)

    def test_a_refused_short_passphrase_keeps_the_reason(self, tmp_path: Path, monkeypatch):
        """"pass" is part of the validation message itself, which quotes no value."""
        manager, activity = build_logged_manager(tmp_path)
        manager.add_device("r1", "192.168.1.1", "cudy", password="p")
        with pytest.raises(ValidationError):
            manager.set_wifi_password("r1", "pass", actor="dave")
        entry = activity.list()[0]
        assert entry["result"] == "refused"
        assert entry["what"] == "Wi-Fi password change refused: Wi-Fi password must be 8 to 63 characters"

    @pytest.mark.parametrize("actor", ["", "   ", None, 7, {"name": "x"}])
    def test_a_change_needs_a_named_actor_and_nothing_happens_without_one(self, tmp_path: Path, monkeypatch, actor):
        manager, activity = build_logged_manager(tmp_path)
        manager.add_device("r1", "192.168.1.1", "cudy", password="p")
        monkeypatch.setattr(manager, "adapter_for", lambda device: pytest.fail("router contacted"))
        calls = [
            lambda: manager.add_device("r2", "192.168.1.2", "cudy", password="p", actor=actor),
            lambda: manager.update_device("r1", model="X", actor=actor),
            lambda: manager.set_password("r1", "other", verify=False, actor=actor),
            lambda: manager.remove_device("r1", actor=actor),
            lambda: manager.reboot_device("r1", actor=actor),
            lambda: manager.set_wifi_ssid("r1", "Home", actor=actor),
            lambda: manager.set_wifi_password("r1", "correct horse battery", actor=actor),
        ]
        for call in calls:
            with pytest.raises(ValidationError):
                call()
        assert set(manager.devices) == {"r1"}
        assert manager.get_device("r1").model == ""
        assert manager.credentials(manager.get_device("r1")) == "p"
        assert len(activity.list()) == 1

    @pytest.mark.parametrize("error", [OSError("disk full"), ActivityError("refused")])
    def test_a_log_that_cannot_be_written_does_not_fail_a_change_already_made(
        self, tmp_path: Path, monkeypatch, caplog, error
    ):
        manager, activity = build_logged_manager(tmp_path)
        manager.add_device("r1", "192.168.1.1", "cudy", password="p")
        router = _Router()
        monkeypatch.setattr(manager, "adapter_for", lambda device: router)

        def broken(**entry):
            raise error

        monkeypatch.setattr(activity, "record", broken)
        with caplog.at_level("WARNING", logger="cudy_manager.manager"):
            assert manager.reboot_device("r1") is True
        assert router.calls == [("reboot",)]
        assert "could not record activity for r1" in caplog.text

    def test_the_actor_is_stored_as_given(self, tmp_path: Path):
        manager, activity = build_logged_manager(tmp_path)
        manager.add_device("r1", "192.168.1.1", "cudy", password="p", actor="  web:admin@198.51.100.4 ")
        assert self.only(activity)["who"] == "web:admin@198.51.100.4"
