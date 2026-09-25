from datetime import UTC, datetime
from pathlib import Path

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


def make_device(**reboot) -> Device:
    policy = {"enabled": True, "at": "04:00", "timezone": "UTC", **reboot}
    return Device.from_dict(
        "router-1", {"vendor": "cudy", "host": "192.168.1.1", "password_ref": "ref", "reboot": policy}
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
        scheduler = RebootScheduler(manager, tmp_path / "state.json")
        scheduler.run_once(at(4, 1))
        scheduler.state["router-1"]["last_schedule_date"] = ""
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
        assert scheduler.get_state() == {}

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
