import http.client
import json
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cudy_manager.adapters import AdapterError
from cudy_manager.models import Device
from cudy_manager.scheduler import RebootScheduler, SchedulerError


class FakeManager:
    def __init__(self, devices, status=None, reboot_result=True):
        self.devices = devices
        self.status = status if status is not None else {"online": True, "uptime_seconds": 100000}
        self.reboot_result = reboot_result
        self.reboots: list[str] = []

    def get_all_devices(self):
        return list(self.devices)

    def get_status(self, identifier):
        if isinstance(self.status, dict):
            return self.status
        return self.status[identifier]

    def reboot_device(self, identifier):
        self.reboots.append(identifier)
        return self.reboot_result


def make_device(identifier: str = "router-1", **reboot) -> Device:
    policy = {"enabled": True, "at": "04:00", "timezone": "UTC", **reboot}
    return Device.from_dict(
        identifier, {"vendor": "cudy", "host": "192.168.1.1", "password_ref": "ref", "reboot": policy}
    )


def at(hour: int, minute: int = 0) -> datetime:
    return datetime(2026, 3, 10, hour, minute, tzinfo=UTC)


class TestRebootScheduler:
    def test_reboots_inside_window(self, tmp_path: Path):
        manager = FakeManager([make_device()])
        scheduler = RebootScheduler(manager, tmp_path / "state.json")
        results = scheduler.run_once(at(4, 5))
        assert results[0]["status"] == "initiated"
        assert manager.reboots == ["router-1"]

    def test_outside_window_is_ignored(self, tmp_path: Path):
        manager = FakeManager([make_device()])
        scheduler = RebootScheduler(manager, tmp_path / "state.json")
        assert scheduler.run_once(at(3, 0)) == []
        assert scheduler.run_once(at(4, 30)) == []
        assert manager.reboots == []

    def test_runs_only_once_per_day(self, tmp_path: Path):
        manager = FakeManager([make_device()])
        scheduler = RebootScheduler(manager, tmp_path / "state.json")
        scheduler.run_once(at(4, 1))
        assert scheduler.run_once(at(4, 10)) == []
        assert manager.reboots == ["router-1"]
        scheduler.run_once(at(4, 20))
        assert manager.reboots == ["router-1"]

    def test_next_day_reboots_again(self, tmp_path: Path):
        manager = FakeManager([make_device(cooldown_seconds=0)])
        scheduler = RebootScheduler(manager, tmp_path / "state.json")
        scheduler.run_once(at(4, 1))
        scheduler.run_once(datetime(2026, 3, 11, 4, 1, tzinfo=UTC))
        assert manager.reboots == ["router-1", "router-1"]

    def test_offline_device_is_skipped(self, tmp_path: Path):
        manager = FakeManager([make_device()], status={"online": False})
        scheduler = RebootScheduler(manager, tmp_path / "state.json")
        results = scheduler.run_once(at(4, 1))
        assert results[0]["reason"] == "device is offline"
        assert manager.reboots == []

    def test_minimum_uptime_guard(self, tmp_path: Path):
        manager = FakeManager([make_device(min_uptime_seconds=86400)], status={"online": True, "uptime_seconds": 60})
        scheduler = RebootScheduler(manager, tmp_path / "state.json")
        results = scheduler.run_once(at(4, 1))
        assert results[0]["reason"] == "minimum uptime not reached"
        assert manager.reboots == []

    def test_missing_uptime_fails_closed(self, tmp_path: Path):
        manager = FakeManager([make_device()], status={"online": True})
        scheduler = RebootScheduler(manager, tmp_path / "state.json")
        results = scheduler.run_once(at(4, 1))
        assert "uptime unavailable" in results[0]["reason"]
        assert manager.reboots == []

    def test_cooldown_blocks_repeat(self, tmp_path: Path):
        device = make_device(cooldown_seconds=86400)
        manager = FakeManager([device])
        path = tmp_path / "state.json"
        scheduler = RebootScheduler(manager, path)
        scheduler.run_once(at(4, 1))
        state = json.loads(path.read_text())
        state["router-1"]["last_schedule_date"] = ""
        path.write_text(json.dumps(state))
        results = scheduler.run_once(at(4, 2))
        assert results[0]["reason"] == "cooldown active"

    def test_disabled_policy_is_ignored(self, tmp_path: Path):
        device = make_device(enabled=False)
        manager = FakeManager([device])
        scheduler = RebootScheduler(manager, tmp_path / "state.json")
        assert scheduler.run_once(at(4, 1)) == []

    def test_disabled_device_is_ignored(self, tmp_path: Path):
        device = Device.from_dict(
            "router-1",
            {"vendor": "cudy", "host": "192.168.1.1", "enabled": False, "reboot": {"enabled": True, "at": "04:00"}},
        )
        manager = FakeManager([device])
        scheduler = RebootScheduler(manager, tmp_path / "state.json")
        assert scheduler.run_once(at(4, 1)) == []

    def test_reboot_failure_recorded(self, tmp_path: Path):
        manager = FakeManager([make_device()], reboot_result=False)
        scheduler = RebootScheduler(manager, tmp_path / "state.json")
        results = scheduler.run_once(at(4, 1))
        assert results[0]["status"] == "failed"
        assert scheduler.get_state()["router-1"]["last_schedule_date"] == "2026-03-10"

    def test_adapter_error_is_captured(self, tmp_path: Path):
        class Failing(FakeManager):
            def get_status(self, identifier):
                raise RuntimeError("boom")

        scheduler = RebootScheduler(Failing([make_device()]), tmp_path / "state.json")
        results = scheduler.run_once(at(4, 1))
        assert results[0]["status"] == "failed"
        assert "boom" in results[0]["reason"]

    def test_state_persists_across_restarts(self, tmp_path: Path):
        manager = FakeManager([make_device()])
        RebootScheduler(manager, tmp_path / "state.json").run_once(at(4, 1))
        second = RebootScheduler(manager, tmp_path / "state.json")
        assert second.run_once(at(4, 5)) == []

    def test_state_file_permissions(self, tmp_path: Path):
        import stat

        RebootScheduler(FakeManager([make_device()]), tmp_path / "state.json").run_once(at(4, 1))
        assert stat.S_IMODE((tmp_path / "state.json").stat().st_mode) == 0o600

    def test_invalid_state_file_fails_closed(self, tmp_path: Path):
        path = tmp_path / "state.json"
        path.write_text("[]")
        try:
            RebootScheduler(FakeManager([make_device()]), path)
        except SchedulerError:
            return
        raise AssertionError("invalid state should raise")

    def test_timezone_is_honoured(self, tmp_path: Path):
        device = make_device(at="04:00", timezone="Europe/Lisbon")
        scheduler = RebootScheduler(FakeManager([device]), tmp_path / "winter.json")
        assert scheduler.run_once(datetime(2026, 3, 10, 4, 5, tzinfo=UTC)) != []
        scheduler = RebootScheduler(FakeManager([device]), tmp_path / "summer.json")
        assert scheduler.run_once(datetime(2026, 7, 10, 3, 5, tzinfo=UTC)) != []
        assert scheduler.run_once(datetime(2026, 7, 10, 3, 45, tzinfo=UTC)) == []


class TestBadPolicyIsolation:
    def test_invalid_timezone_does_not_stop_other_devices(self, tmp_path):
        from cudy_manager.manager import DeviceManager
        from cudy_manager.secrets import SecretStore

        store = SecretStore(tmp_path / "data")
        manager = DeviceManager(config_path=tmp_path / "d.yaml", data_dir=tmp_path / "data", secret_store=store)
        manager.add_device("healthy", "192.0.2.1", "cudy", password="p")
        manager.add_device("broken", "192.0.2.2", "cudy", password="p")
        manager.update_device("broken", reboot={"enabled": True, "at": "04:00", "timezone": "Not/AZone"})
        scheduler = RebootScheduler(manager, tmp_path / "state.json")

        results = scheduler.run_once()

        assert [item["device"] for item in results] == ["broken"]
        assert results[0]["status"] == "failed"
        assert "timezone" in results[0]["reason"]

    def test_malformed_at_value_is_isolated(self, tmp_path):
        from cudy_manager.manager import DeviceManager
        from cudy_manager.secrets import SecretStore

        store = SecretStore(tmp_path / "data")
        manager = DeviceManager(config_path=tmp_path / "d.yaml", data_dir=tmp_path / "data", secret_store=store)
        manager.add_device("ok", "192.0.2.1", "cudy", password="p")
        manager.add_device("bad", "192.0.2.2", "cudy", password="p")
        with manager._lock:
            manager.devices["bad"].reboot.enabled = True
            manager.devices["bad"].reboot.at = "not-a-time"
        scheduler = RebootScheduler(manager, tmp_path / "state.json")

        results = scheduler.run_once()

        assert any(item["device"] == "bad" and item["status"] == "failed" for item in results)

    def test_disabled_device_is_not_evaluated(self, tmp_path):
        from cudy_manager.manager import DeviceManager
        from cudy_manager.secrets import SecretStore

        store = SecretStore(tmp_path / "data")
        manager = DeviceManager(config_path=tmp_path / "d.yaml", data_dir=tmp_path / "data", secret_store=store)
        manager.add_device("off", "192.0.2.1", "cudy", password="p")
        manager.update_device("off", enabled=False, reboot={"enabled": True, "at": "04:00", "timezone": "Not/AZone"})
        scheduler = RebootScheduler(manager, tmp_path / "state.json")

        assert scheduler.run_once() == []


class TestAmbiguousRebootOutcome:
    """A reboot request that errors or goes unconfirmed may still have rebooted the router."""

    def test_unconfirmed_reboot_is_not_retried_in_the_window(self, tmp_path: Path):
        manager = FakeManager([make_device(window_minutes=60, min_uptime_seconds=0)], reboot_result=False)
        scheduler = RebootScheduler(manager, tmp_path / "state.json")

        assert scheduler.run_once(at(4, 0))[0]["status"] == "failed"
        for minute in range(2, 60, 2):
            scheduler.run_once(at(4, minute))

        assert manager.reboots == ["router-1"]

    def test_connection_dropped_by_the_reboot_still_counts(self, tmp_path: Path):
        class DropsConnection(FakeManager):
            def reboot_device(self, identifier):
                self.reboots.append(identifier)
                raise AdapterError("router request failed: connection reset by peer")

        manager = DropsConnection([make_device(window_minutes=60, min_uptime_seconds=0)])
        path = tmp_path / "state.json"
        scheduler = RebootScheduler(manager, path)

        assert scheduler.run_once(at(4, 0))[0]["status"] == "failed"
        assert scheduler.run_once(at(4, 5)) == []
        assert RebootScheduler(manager, path).run_once(at(4, 6)) == []
        assert manager.reboots == ["router-1"]

    def test_attempt_counts_towards_the_cooldown(self, tmp_path: Path):
        manager = FakeManager([make_device(cooldown_seconds=172800)], reboot_result=False)
        scheduler = RebootScheduler(manager, tmp_path / "state.json")
        scheduler.run_once(at(4, 1))

        results = scheduler.run_once(at(4, 1) + timedelta(days=1))

        assert results[0]["reason"] == "cooldown active"
        assert manager.reboots == ["router-1"]


class TestStatePersistenceFailure:
    def test_no_reboot_is_sent_when_the_attempt_cannot_be_recorded(self, tmp_path: Path, monkeypatch):
        manager = FakeManager([make_device()])
        path = tmp_path / "state.json"
        scheduler = RebootScheduler(manager, path)

        def disk_full(*_args):
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(scheduler, "_save", disk_full)
        results = scheduler.run_once(at(4, 1))

        assert manager.reboots == []
        assert results[0]["status"] == "failed"
        assert "No space left on device" in results[0]["reason"]
        assert scheduler.get_state() == {}
        assert not path.exists()


class TestUnexpectedErrorIsolation:
    def test_status_error_does_not_stop_later_devices(self, tmp_path: Path):
        class GarbledFirst(FakeManager):
            def get_status(self, identifier):
                if identifier == "bad":
                    raise http.client.BadStatusLine("\x15\x03\x01")
                return super().get_status(identifier)

        manager = GarbledFirst([make_device("bad"), make_device("good")])
        scheduler = RebootScheduler(manager, tmp_path / "state.json")

        results = scheduler.run_once(at(4, 1))

        assert [(item["device"], item["status"]) for item in results] == [("bad", "failed"), ("good", "initiated")]
        assert manager.reboots == ["good"]

    def test_reboot_error_does_not_stop_later_devices(self, tmp_path: Path):
        class SshChannelClosed(Exception):
            pass

        class FailsFirst(FakeManager):
            def reboot_device(self, identifier):
                self.reboots.append(identifier)
                if identifier == "bad":
                    raise SshChannelClosed("channel closed")
                return True

        manager = FailsFirst([make_device("bad"), make_device("good")])
        scheduler = RebootScheduler(manager, tmp_path / "state.json")

        results = scheduler.run_once(at(4, 1))

        assert [(item["device"], item["status"]) for item in results] == [("bad", "failed"), ("good", "initiated")]
        assert "channel closed" in results[0]["reason"]


class TestSharedStateFile:
    """Two dashboards on one data dir share scheduler_state.json and the device list."""

    def test_second_scheduler_sees_the_first_ones_reboot(self, tmp_path: Path):
        path = tmp_path / "state.json"
        first = FakeManager([make_device(min_uptime_seconds=0)])
        second = FakeManager([make_device(min_uptime_seconds=0)])
        a = RebootScheduler(first, path)
        b = RebootScheduler(second, path)

        a.run_once(at(4, 0))
        assert b.run_once(at(4, 1)) == []

        assert first.reboots == ["router-1"]
        assert second.reboots == []

    def test_a_save_keeps_the_other_schedulers_entries(self, tmp_path: Path):
        path = tmp_path / "state.json"
        a = RebootScheduler(FakeManager([make_device("router-1")]), path)
        b = RebootScheduler(FakeManager([make_device("router-2")]), path)

        a.run_once(at(4, 0))
        b.run_once(at(4, 1))

        assert set(json.loads(path.read_text())) == {"router-1", "router-2"}

    def test_overlapping_ticks_reboot_once(self, tmp_path: Path):
        path = tmp_path / "state.json"
        inside = threading.Event()
        release = threading.Event()

        class Slow(FakeManager):
            def get_status(self, identifier):
                inside.set()
                release.wait(5)
                return super().get_status(identifier)

        slow = Slow([make_device()])
        fast = FakeManager([make_device()])
        a = RebootScheduler(slow, path)
        b = RebootScheduler(fast, path)
        first = threading.Thread(target=a.run_once, args=(at(4, 0),))
        second = threading.Thread(target=b.run_once, args=(at(4, 0),))
        first.start()
        assert inside.wait(5)
        second.start()
        second.join(0.3)
        release.set()
        first.join(5)
        second.join(5)

        assert slow.reboots + fast.reboots == ["router-1"]


class TestWindowBoundaries:
    def test_window_crossing_midnight_is_honoured(self, tmp_path: Path):
        manager = FakeManager([make_device(at="23:30", window_minutes=60, cooldown_seconds=0)])
        scheduler = RebootScheduler(manager, tmp_path / "state.json")

        assert scheduler.run_once(datetime(2026, 3, 10, 23, 29, tzinfo=UTC)) == []
        results = scheduler.run_once(datetime(2026, 3, 11, 0, 10, tzinfo=UTC))

        assert results[0]["status"] == "initiated"
        assert scheduler.get_state()["router-1"]["last_schedule_date"] == "2026-03-10"
        assert scheduler.run_once(datetime(2026, 3, 11, 0, 20, tzinfo=UTC)) == []
        assert scheduler.run_once(datetime(2026, 3, 11, 23, 35, tzinfo=UTC))[0]["status"] == "initiated"
        assert manager.reboots == ["router-1", "router-1"]

    def test_midnight_occurrence_is_not_repeated_after_midnight(self, tmp_path: Path):
        manager = FakeManager([make_device(at="23:30", window_minutes=60, cooldown_seconds=0)])
        scheduler = RebootScheduler(manager, tmp_path / "state.json")

        scheduler.run_once(datetime(2026, 3, 10, 23, 40, tzinfo=UTC))

        assert scheduler.run_once(datetime(2026, 3, 11, 0, 5, tzinfo=UTC)) == []
        assert scheduler.run_once(datetime(2026, 3, 11, 0, 30, tzinfo=UTC)) == []
        assert manager.reboots == ["router-1"]

    @staticmethod
    def _sweep(scheduler: RebootScheduler, start: datetime, hours: int) -> list[datetime]:
        fired = []
        step = start
        while step < start + timedelta(hours=hours):
            if scheduler.run_once(step):
                fired.append(step)
            step += timedelta(seconds=30)
        return fired

    def test_time_skipped_by_spring_forward_still_reboots(self, tmp_path: Path):
        device = make_device(at="02:30", timezone="America/New_York", window_minutes=15, min_uptime_seconds=0)
        scheduler = RebootScheduler(FakeManager([device]), tmp_path / "state.json")

        fired = self._sweep(scheduler, datetime(2026, 3, 8, 5, 0, tzinfo=UTC), 6)

        assert fired == [datetime(2026, 3, 8, 7, 30, tzinfo=UTC)]

    def test_repeated_hour_at_fall_back_reboots_once(self, tmp_path: Path):
        device = make_device(
            at="01:30", timezone="America/New_York", window_minutes=90, min_uptime_seconds=0, cooldown_seconds=0
        )
        scheduler = RebootScheduler(FakeManager([device]), tmp_path / "state.json")

        fired = self._sweep(scheduler, datetime(2026, 11, 1, 4, 0, tzinfo=UTC), 6)

        assert fired == [datetime(2026, 11, 1, 5, 30, tzinfo=UTC)]
