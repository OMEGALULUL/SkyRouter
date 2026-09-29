"""Maintenance plans: validation, the plan store, window arithmetic and the runner.

Direct routers are faked at the DeviceManager boundary (FakeManager), and TR-069
ones at the AcsService boundary (FakeAcs); the end-to-end tests at the bottom run
a real DeviceManager against fake_router's reconstructed AP1300, and a real
AcsService against the fake NBI. Every activity entry goes through a real
ActivityLog, which refuses a secret-looking detail key, so an entry the runner
built wrongly would show up as a missing one.
"""

import copy
import json
import stat
import threading
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfoNotFoundError

import pytest

from cudy_manager import maintenance
from cudy_manager.acs.client import AcsBusy, AcsNotFound, AcsUnavailable
from cudy_manager.activity import ActivityLog
from cudy_manager.adapters import AdapterError, UnsupportedOperation
from cudy_manager.maintenance import (
    MaintenanceBusy,
    MaintenanceError,
    MaintenancePlan,
    MaintenanceRunner,
    MaintenanceStore,
    PlanNotFound,
    PlanSchedule,
)
from cudy_manager.manager import CredentialLatched, ManagerError
from cudy_manager.models import Device, ValidationError

# Tuesday 10 March 2026, ten minutes into a 03:00 UTC window.
AT = datetime(2026, 3, 10, 3, 10, tzinfo=UTC)
ACS_ID = "80AFCA-AP1300-000001"
ACS_OTHER = "80AFCA-AP1300-000002"
FIRMWARE = "skybre-fw-0123456789abcdef0123456789abcdef"
NEWER = "2.5.26-20261001-101010"


def plan_data(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "name": "Weekly reboot",
        "targets": {"devices": ["r1"]},
        "schedule": {"days": ["tue"], "start": "03:00", "duration_minutes": 60, "timezone": "UTC"},
        "actions": ["reboot"],
    }
    data.update(overrides)
    return data


def make_device(identifier: str = "r1", **values: Any) -> Device:
    return Device.from_dict(identifier, {"vendor": "cudy", "host": "192.0.2.1", "password_ref": "ref", **values})


class FakeManager:
    """DeviceManager as the runner uses it: devices, status, clients, reboot and _call."""

    def __init__(self, *devices: Device) -> None:
        self.devices = {device.identifier: device for device in devices or (make_device(),)}
        self.statuses: dict[str, dict[str, Any]] = {}
        self.default_status: dict[str, Any] = {"online": True, "uptime_seconds": 100_000}
        self.clients: dict[str, Any] = {}
        self.checks: dict[str, dict[str, Any]] = {}
        self.auto: dict[str, Any] = {}
        self.failures: dict[tuple[str, str], BaseException] = {}
        self.calls: list[tuple[str, str, tuple[Any, ...]]] = []
        self.reboots: list[tuple[str, str]] = []
        self.reboot_result = True
        self.activity: ActivityLog | None = None
        self.status_hook = None
        self.call_hook = None

    def _fail(self, identifier: str, operation: str) -> None:
        failure = self.failures.get((identifier, operation))
        if failure is not None:
            raise failure

    def get_device(self, identifier: str) -> Device:
        if identifier not in self.devices:
            raise ManagerError(f"device {identifier!r} does not exist")
        return self.devices[identifier]

    def get_all_devices(self) -> list[Device]:
        return list(self.devices.values())

    def get_status(self, identifier: str) -> dict[str, Any]:
        self.calls.append((identifier, "status", ()))
        if self.status_hook is not None:
            self.status_hook(identifier)
        self._fail(identifier, "status")
        return dict(self.statuses.get(identifier, self.default_status))

    def get_connected_clients(self, identifier: str) -> list[dict[str, Any]]:
        self.calls.append((identifier, "clients", ()))
        self._fail(identifier, "clients")
        return [{"name": f"client-{index}"} for index in range(self.clients.get(identifier, 0))]

    def reboot_device(self, identifier: str, *, actor: str = "system") -> bool:
        self.reboots.append((identifier, actor))
        if self.activity is not None:
            # What DeviceManager does: one entry per reboot, under the caller's actor.
            self.activity.record(who=actor, router=identifier, kind="reboot", what="Reboot started", result="applied")
        self._fail(identifier, "reboot")
        return self.reboot_result

    def _call(self, device: Device, operation: str, *args: Any) -> Any:
        identifier = device.identifier
        self.calls.append((identifier, operation, args))
        if self.call_hook is not None:
            self.call_hook(operation)
        self._fail(identifier, operation)
        if operation == "check_firmware_update":
            return dict(
                self.checks.get(
                    identifier,
                    {"available": False, "current": "2.5.25", "latest": None, "note": "the router found none"},
                )
            )
        if operation == "firmware_info":
            auto = self.auto.get(identifier, {"enabled": True, "window_start_hour": 3, "window": "03:00-05:00"})
            return {"version": "2.5.25", "hardware": "AP1300 V1.1", "auto_update": auto, "source": "cudy-luci"}
        if operation == "set_auto_update":
            return True
        raise AssertionError(f"unexpected adapter call {operation}")

    def ops(self, operation: str) -> list[tuple[str, tuple[Any, ...]]]:
        return [(identifier, args) for identifier, name, args in self.calls if name == operation]


class FakeFirmwareIndex:
    def __init__(self) -> None:
        self.records: dict[str, dict[str, Any]] = {}

    def get(self, name: str) -> dict[str, Any] | None:
        return self.records.get(name)


class FakeAcs:
    """AcsService as the runner uses it."""

    def __init__(self) -> None:
        self.details: dict[str, dict[str, Any]] = {}
        self.fleet: list[dict[str, Any]] = []
        self.firmware = FakeFirmwareIndex()
        self.firmware.records[FIRMWARE] = {"name": FIRMWARE, "version": NEWER, "product_class": "AP1300"}
        self.reboots: list[tuple[str, str]] = []
        self.upgrades: list[tuple[str, str, bool, str]] = []
        # The expiry each reboot or upgrade was queued with; None is the ACS's default.
        self.expiries: list[int | None] = []
        self.upgrade_error: BaseException | None = None
        self.detail_error: BaseException | None = None
        self.terminal = False
        # Job kinds that come back terminal, as if only that request failed to queue.
        self.terminal_kinds: set[str] = set()
        self.jobs = 0

    def add(
        self,
        acs_id: str = ACS_ID,
        *,
        online: bool | None = True,
        booted: datetime | None = AT - timedelta(hours=5),
        product_class: str = "AP1300",
        firmware: str = "2.5.25",
        clients: int = 0,
        clients_as_of: datetime | None = AT - timedelta(minutes=10),
        client_data: bool = True,
        tags: tuple[str, ...] = (),
        wan_ip: str | None = None,
    ) -> str:
        stamp = clients_as_of.isoformat() if clients_as_of else None
        self.details[acs_id] = {
            "acs_id": acs_id,
            "online": online,
            "info": {
                "model": "AP1300",
                "product_class": product_class,
                "firmware": firmware,
                "uptime": None,
                "as_of": {},
            },
            "checkin": {"last_boot": booted.isoformat() if booted else None},
            "wan": {"ip": wan_ip},
            # As params.detail reports them: a count per network, and the hosts table.
            "wifi": [{"band": "2.4GHz", "clients": clients, "as_of": {"clients": stamp}}] if client_data else [],
            "clients": [
                {"mac": f"AA:BB:CC:00:00:{index:02X}", "active": True, "as_of": stamp} for index in range(clients)
            ]
            if client_data
            else [],
            "pending_jobs": [],
        }
        self.fleet.append({"acs_id": acs_id, "tags": list(tags)})
        return acs_id

    def device_detail(self, acs_id: str) -> dict[str, Any]:
        if self.detail_error is not None:
            raise self.detail_error
        if acs_id not in self.details:
            raise AcsNotFound("No such device", status=404)
        return {"device": copy.deepcopy(self.details[acs_id])}

    def list_devices(self, q: str | None = None, tag: str | None = None, skip: int = 0, limit: int = 50):
        return {"devices": copy.deepcopy(self.fleet[skip : skip + limit]), "total": len(self.fleet)}

    def _job(self, acs_id: str, kind: str, actor: str) -> dict[str, Any]:
        self.jobs += 1
        terminal = self.terminal or kind in self.terminal_kinds
        state = "error" if terminal else "contacting_router"
        return {
            "id": f"{self.jobs:016x}",
            "acs_id": acs_id,
            "kind": kind,
            "state": state,
            "actor": actor,
            "terminal": terminal,
            "message": "The ACS could not be reached." if terminal else "Asking the router to check in.",
        }

    def reboot(self, acs_id: str, actor: str = "system", expiry: int | None = None) -> dict[str, Any]:
        self.reboots.append((acs_id, actor))
        self.expiries.append(expiry)
        return self._job(acs_id, "reboot", actor)

    def firmware_upgrade(
        self,
        acs_id: str,
        firmware_name: str,
        confirm_model_mismatch: bool = False,
        actor: str = "system",
        expiry: int | None = None,
    ) -> dict[str, Any]:
        self.upgrades.append((acs_id, firmware_name, confirm_model_mismatch, actor))
        if self.upgrade_error is not None:
            raise self.upgrade_error
        self.expiries.append(expiry)
        return self._job(acs_id, "firmware", actor)


def build(tmp_path: Path, manager: Any = None, acs: Any = None, *, at: datetime = AT, **kwargs: Any):
    store = MaintenanceStore(tmp_path)
    log = ActivityLog(tmp_path)
    clock = kwargs.pop("clock", lambda: at)
    workers = kwargs.pop("max_workers", 1)
    manager = manager if manager is not None else FakeManager()
    runner = MaintenanceRunner(manager, acs, store, log, clock=clock, max_workers=workers, **kwargs)
    return store, log, runner


def entries(log: ActivityLog, **filters: Any) -> list[dict[str, Any]]:
    return list(reversed(log.list(**filters)))


# --- plans ---------------------------------------------------------------------------


class TestPlanValidation:
    def test_a_plan_is_normalised_and_gets_the_default_guards(self):
        plan = MaintenancePlan.from_dict(
            plan_data(
                actions=["reboot", "firmware_check"],
                schedule={"days": ["Thu", "mon", "mon"], "start": "03:00", "timezone": "Africa/Johannesburg"},
            ),
            plan_id="0123456789ab",
        )
        assert plan.actions == ("firmware_check", "reboot")
        assert plan.schedule.days == ("mon", "thu")
        assert plan.schedule.duration_minutes == 60
        assert plan.enabled is True
        assert plan.guards.to_dict() == {"min_uptime_seconds": 3600, "skip_if_clients_over": None, "cooldown_hours": 20}
        again = MaintenancePlan.from_dict(plan.to_dict(), plan_id=plan.id)
        assert again == plan

    def test_a_monthly_plan_for_tr069_firmware(self):
        plan = MaintenancePlan.from_dict(
            plan_data(
                targets={"acs_devices": [ACS_ID]},
                schedule={"monthly_day": 28, "start": "23:30", "duration_minutes": 480, "timezone": "UTC"},
                actions=["firmware_update"],
                firmware={" AP1300 ": FIRMWARE},
                guards={"min_uptime_seconds": 0, "skip_if_clients_over": 5, "cooldown_hours": 0},
            ),
            plan_id="0123456789ab",
        )
        assert plan.firmware == {"AP1300": FIRMWARE}
        assert plan.firmware_for("ap1300") == FIRMWARE
        assert plan.guards.skip_if_clients_over == 5

    @pytest.mark.parametrize(
        "overrides,message",
        [
            ({"colour": "blue"}, "unknown field(s): colour"),
            ({"name": "  "}, "name must not be empty"),
            ({"name": "x" * 61}, "at most 60 characters"),
            ({"name": "evil\x00name"}, "control characters"),
            ({"name": "a‮b"}, "control characters"),
            ({"enabled": "yes"}, "enabled must be true or false"),
            ({"targets": {}}, "at least one router"),
            ({"targets": {"devices": ["bad id"]}}, "targets.devices[0] is not a SkyRouter device id"),
            ({"targets": {"acs_devices": ["no/slash"]}}, "targets.acs_devices[0] is not a GenieACS device ID"),
            ({"targets": {"all": 1}}, "targets.all must be true or false"),
            ({"targets": {"devices": "r1"}}, "targets.devices must be a list"),
            ({"schedule": {"start": "03:00", "timezone": "UTC"}}, "needs days (weekly) or monthly_day"),
            (
                {"schedule": {"days": ["mon"], "monthly_day": 3, "start": "03:00", "timezone": "UTC"}},
                "either days (weekly) or monthly_day (monthly), not both",
            ),
            ({"schedule": {"monthly_day": 29, "start": "03:00", "timezone": "UTC"}}, "from 1 to 28"),
            ({"schedule": {"monthly_day": True, "start": "03:00", "timezone": "UTC"}}, "from 1 to 28"),
            ({"schedule": {"days": ["someday"], "start": "03:00", "timezone": "UTC"}}, "may only hold mon"),
            ({"schedule": {"days": ["mon"], "start": "3:00", "timezone": "UTC"}}, "HH:MM"),
            ({"schedule": {"days": ["mon"], "start": "24:00", "timezone": "UTC"}}, "HH:MM"),
            (
                {"schedule": {"days": ["mon"], "start": "03:00", "duration_minutes": 14, "timezone": "UTC"}},
                "duration_minutes must be from 15 to 480",
            ),
            (
                {"schedule": {"days": ["mon"], "start": "03:00", "duration_minutes": 481, "timezone": "UTC"}},
                "duration_minutes must be from 15 to 480",
            ),
            (
                {"schedule": {"days": ["mon"], "start": "03:00", "duration_minutes": "60", "timezone": "UTC"}},
                "duration_minutes must be a whole number",
            ),
            ({"schedule": {"days": ["mon"], "start": "03:00"}}, "timezone must be a timezone name"),
            ({"schedule": {"days": ["mon"], "start": "03:00", "timezone": "Mars/Olympus"}}, "not a known timezone"),
            ({"schedule": {"days": ["mon"], "start": "03:00", "timezone": "../../etc/passwd"}}, "timezone name"),
            ({"schedule": {"days": ["mon"], "start": "03:00", "timezone": "/etc/localtime"}}, "timezone name"),
            ({"actions": []}, "at least one of firmware_check"),
            ({"actions": ["reboot", "format_disk"]}, "may only include"),
            ({"actions": ["firmware_update"], "targets": {"acs_devices": [ACS_ID]}}, "needs a firmware file"),
            (
                {"actions": ["firmware_update"], "firmware": {"AP1300": FIRMWARE}},
                "only sent to TR-069 routers",
            ),
            ({"firmware": {"AP1300": "vendor.bin"}}, "skybre-fw-"),
            ({"firmware": {"AP1300": FIRMWARE, "ap1300": FIRMWARE}}, "more than once"),
            ({"firmware": {"": FIRMWARE}}, "firmware product class"),
            ({"guards": {"min_uptime_seconds": -1}}, "min_uptime_seconds must be from 0"),
            ({"guards": {"skip_if_clients_over": True}}, "skip_if_clients_over must be a whole number"),
            ({"guards": {"cooldown_hours": 721}}, "cooldown_hours must be from 0 to 720"),
            ({"guards": {"retries": 3}}, "guards has unknown field(s): retries"),
        ],
    )
    def test_invalid_plans_are_refused_with_a_plain_message(self, overrides, message):
        with pytest.raises(ValidationError) as caught:
            MaintenancePlan.from_dict(plan_data(**overrides), plan_id="0123456789ab")
        assert message in str(caught.value)


class TestMaintenanceStore:
    def test_create_get_list_update_delete(self, tmp_path: Path):
        store = MaintenanceStore(tmp_path, clock=lambda: AT)
        created = store.create(plan_data())
        assert len(created["id"]) == 12 and int(created["id"], 16) >= 0
        assert created["created_at"] == created["updated_at"] == AT.isoformat()
        assert store.get(created["id"]) == created
        assert store.list() == [created]

        updated = store.update(created["id"], {"name": "Nightly", "guards": {"cooldown_hours": 2}})
        assert updated["name"] == "Nightly"
        # The field given replaces the stored one whole; the others are kept.
        assert updated["guards"] == {"min_uptime_seconds": 3600, "skip_if_clients_over": None, "cooldown_hours": 2}
        assert updated["schedule"] == created["schedule"]

        assert store.delete(created["id"]) == {"id": created["id"], "name": "Nightly", "deleted": True}
        assert store.list() == []
        with pytest.raises(PlanNotFound):
            store.get(created["id"])

    def test_the_file_is_private_and_replaced_atomically(self, tmp_path: Path):
        store = MaintenanceStore(tmp_path)
        created = store.create(plan_data())
        assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
        saved = json.loads(store.path.read_text())
        assert saved["version"] == 1 and list(saved["plans"]) == [created["id"]]
        assert sorted(path.name for path in tmp_path.iterdir()) == ["maintenance.json", "maintenance.lock"]

    def test_another_store_on_the_same_directory_sees_the_change(self, tmp_path: Path):
        created = MaintenanceStore(tmp_path).create(plan_data())
        other = MaintenanceStore(tmp_path)
        other.update(created["id"], {"enabled": False})
        assert MaintenanceStore(tmp_path).get(created["id"])["enabled"] is False

    def test_concurrent_creates_keep_every_plan(self, tmp_path: Path):
        stores = [MaintenanceStore(tmp_path) for _ in range(8)]
        threads = [
            threading.Thread(target=store.create, args=(plan_data(name=f"Plan {index}"),))
            for index, store in enumerate(stores)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert sorted(plan["name"] for plan in MaintenanceStore(tmp_path).list()) == [f"Plan {i}" for i in range(8)]

    def test_ids_and_timestamps_are_skyrouters(self, tmp_path: Path):
        store = MaintenanceStore(tmp_path)
        with pytest.raises(ValidationError, match="id is set by SkyRouter"):
            store.create({**plan_data(), "id": "0123456789ab"})
        created = store.create(plan_data())
        with pytest.raises(ValidationError, match="cannot be changed"):
            store.update(created["id"], {"id": "ba9876543210"})
        # A dashboard sends back what it read; the timestamps in it are ignored.
        again = store.update(created["id"], {**created, "created_at": "1999-01-01T00:00:00+00:00"})
        assert again["created_at"] == created["created_at"]

    def test_names_are_unique_ignoring_case(self, tmp_path: Path):
        store = MaintenanceStore(tmp_path)
        first = store.create(plan_data(name="Weekly reboot"))
        with pytest.raises(ValidationError, match="already exists"):
            store.create(plan_data(name="WEEKLY REBOOT"))
        second = store.create(plan_data(name="Other"))
        with pytest.raises(ValidationError, match="already exists"):
            store.update(second["id"], {"name": "weekly reboot"})
        assert store.update(first["id"], {"name": "Weekly Reboot"})["name"] == "Weekly Reboot"

    def test_an_invalid_change_leaves_the_plan_as_it_was(self, tmp_path: Path):
        store = MaintenanceStore(tmp_path)
        created = store.create(plan_data())
        with pytest.raises(ValidationError):
            store.update(created["id"], {"actions": ["explode"]})
        assert store.get(created["id"]) == created

    @pytest.mark.parametrize("plan_id", ["", "../../etc", "0123456789AB", "0123456789abc", 7])
    def test_malformed_ids_are_refused(self, tmp_path: Path, plan_id):
        with pytest.raises(ValidationError, match="not a maintenance plan id"):
            MaintenanceStore(tmp_path).get(plan_id)

    @pytest.mark.parametrize("content", ["", "{", "[]", '{"version": 1}', '{"plans": []}'])
    def test_a_damaged_file_is_never_read_as_no_plans(self, tmp_path: Path, content):
        store = MaintenanceStore(tmp_path)
        store.path.write_text(content)
        with pytest.raises(MaintenanceError):
            store.list()
        with pytest.raises(MaintenanceError):
            store.create(plan_data())
        assert store.path.read_text() == content

    def test_an_invalid_stored_plan_names_itself(self, tmp_path: Path):
        store = MaintenanceStore(tmp_path)
        created = store.create(plan_data())
        saved = json.loads(store.path.read_text())
        saved["plans"][created["id"]]["schedule"]["timezone"] = "Not/AZone"
        store.path.write_text(json.dumps(saved))
        with pytest.raises(MaintenanceError, match=created["id"]):
            store.plans()

    def test_a_missing_directory_is_no_plans_and_creates_nothing(self, tmp_path: Path):
        store = MaintenanceStore(tmp_path / "absent")
        assert store.list() == []
        assert not (tmp_path / "absent").exists()


class TestScheduleWindows:
    @staticmethod
    def schedule(**values: Any) -> PlanSchedule:
        return PlanSchedule.from_dict({"days": ["tue"], "start": "03:00", "timezone": "UTC", **values})

    def test_a_weekly_window_opens_and_closes_on_time(self):
        schedule = self.schedule(duration_minutes=60)
        assert schedule.occurrence_at(datetime(2026, 3, 10, 2, 59, tzinfo=UTC)) is None
        assert schedule.occurrence_at(datetime(2026, 3, 10, 3, 0, tzinfo=UTC)) == date(2026, 3, 10)
        assert schedule.occurrence_at(datetime(2026, 3, 10, 3, 59, tzinfo=UTC)) == date(2026, 3, 10)
        assert schedule.occurrence_at(datetime(2026, 3, 10, 4, 0, tzinfo=UTC)) is None
        # Wednesday is not in the plan.
        assert schedule.occurrence_at(datetime(2026, 3, 11, 3, 10, tzinfo=UTC)) is None

    def test_the_window_is_read_in_the_plans_timezone(self):
        schedule = self.schedule(timezone="Africa/Johannesburg")
        assert schedule.occurrence_at(datetime(2026, 3, 10, 1, 10, tzinfo=UTC)) == date(2026, 3, 10)
        assert schedule.occurrence_at(datetime(2026, 3, 10, 3, 10, tzinfo=UTC)) is None

    def test_a_window_crossing_midnight_belongs_to_the_day_it_opened(self):
        schedule = self.schedule(start="23:30", duration_minutes=60)
        assert schedule.occurrence_at(datetime(2026, 3, 11, 0, 20, tzinfo=UTC)) == date(2026, 3, 10)
        assert schedule.occurrence_at(datetime(2026, 3, 11, 0, 30, tzinfo=UTC)) is None
        # Monday night is not Tuesday's window.
        assert schedule.occurrence_at(datetime(2026, 3, 10, 0, 20, tzinfo=UTC)) is None

    def test_a_monthly_window(self):
        schedule = PlanSchedule.from_dict({"monthly_day": 15, "start": "02:00", "timezone": "UTC"})
        assert schedule.occurrence_at(datetime(2026, 4, 15, 2, 30, tzinfo=UTC)) == date(2026, 4, 15)
        assert schedule.occurrence_at(datetime(2026, 4, 16, 2, 30, tzinfo=UTC)) is None

    def test_a_start_skipped_by_spring_forward_opens_just_after_the_jump(self):
        schedule = PlanSchedule.from_dict(
            {"days": ["sun"], "start": "02:30", "duration_minutes": 30, "timezone": "America/New_York"}
        )
        # 8 March 2026: 02:00 EST jumps to 03:00 EDT, so 02:30 never happens.
        opens, closes = schedule.window_for(date(2026, 3, 8))
        assert (opens, closes) == (datetime(2026, 3, 8, 7, 30, tzinfo=UTC), datetime(2026, 3, 8, 8, 0, tzinfo=UTC))
        assert schedule.occurrence_at(datetime(2026, 3, 8, 7, 45, tzinfo=UTC)) == date(2026, 3, 8)

    def test_a_start_repeated_by_fall_back_opens_once_for_its_real_length(self):
        schedule = PlanSchedule.from_dict(
            {"days": ["sun"], "start": "01:30", "duration_minutes": 90, "timezone": "America/New_York"}
        )
        # 1 November 2026: 01:00-02:00 happens twice; the window opens the first time.
        opens, closes = schedule.window_for(date(2026, 11, 1))
        assert opens == datetime(2026, 11, 1, 5, 30, tzinfo=UTC)
        assert closes - opens == timedelta(minutes=90)
        assert schedule.occurrence_at(datetime(2026, 11, 1, 6, 40, tzinfo=UTC)) == date(2026, 11, 1)
        assert schedule.occurrence_at(datetime(2026, 11, 1, 7, 0, tzinfo=UTC)) is None

    def test_the_next_window(self):
        schedule = self.schedule(duration_minutes=60)
        assert schedule.next_window(datetime(2026, 3, 10, 3, 30, tzinfo=UTC)) == (
            datetime(2026, 3, 10, 3, 0, tzinfo=UTC),
            datetime(2026, 3, 10, 4, 0, tzinfo=UTC),
        )
        following = schedule.next_window(datetime(2026, 3, 10, 4, 0, tzinfo=UTC))
        assert following is not None and following[0] == datetime(2026, 3, 17, 3, 0, tzinfo=UTC)


# --- the runner: direct routers ----------------------------------------------------------


class TestRunnerDirect:
    def test_reboots_inside_the_window_once_per_occurrence(self, tmp_path: Path):
        manager = FakeManager()
        store, log, runner = build(tmp_path, manager)
        plan = store.create(plan_data())

        assert runner.run_once(AT - timedelta(minutes=11)) == []
        (result,) = runner.run_once(AT)
        assert result["status"] == "done" and result["target"] == "direct:r1"
        assert result["occurrence"] == f"{plan['id']}:2026-03-10"
        assert result["actions"] == [{"action": "reboot", "status": "done", "detail": "reboot started"}]
        assert runner.run_once(AT + timedelta(minutes=20)) == []
        assert manager.reboots == [("r1", "Maintenance: Weekly reboot")]

        runner.run_once(AT + timedelta(days=7))
        assert len(manager.reboots) == 2

    def test_a_disabled_plan_does_not_run(self, tmp_path: Path):
        manager = FakeManager()
        store, _, runner = build(tmp_path, manager)
        store.create(plan_data(enabled=False))
        assert runner.run_once(AT) == []
        assert manager.calls == [] and manager.reboots == []

    def test_every_outcome_is_logged_under_the_plans_name(self, tmp_path: Path):
        manager = FakeManager(make_device("r1", metadata={"name": "Front office"}))
        manager.checks["r1"] = {"available": True, "current": "2.5.25", "latest": NEWER, "note": "newer firmware"}
        store, log, runner = build(tmp_path, manager)
        plan = store.create(plan_data(actions=["reboot", "firmware_check"]))

        runner.run_once(AT)

        check, reboot = entries(log)
        assert check["who"] == reboot["who"] == "Maintenance: Weekly reboot"
        assert check["router"] == "r1" and check["router_name"] == "Front office"
        assert check["kind"] == "firmware" and check["result"] == "info"
        assert check["what"] == (
            f'Maintenance "Weekly reboot": firmware check: {NEWER} is available (running 2.5.25); nothing was installed'
        )
        assert check["details"]["plan"] == plan["id"] and check["details"]["available"] is True
        assert (reboot["kind"], reboot["result"]) == ("reboot", "applied")
        # The check ran before the reboot, whatever order the plan listed them in.
        assert [name for _, name, _ in manager.calls] == ["status", "check_firmware_update"]

    def test_devicemanager_logs_its_own_reboot_so_it_is_not_logged_twice(self, tmp_path: Path):
        manager = FakeManager()
        store, log, runner = build(tmp_path, manager)
        manager.activity = log
        store.create(plan_data())
        runner.run_once(AT)
        (entry,) = entries(log)
        assert (entry["who"], entry["what"]) == ("Maintenance: Weekly reboot", "Reboot started")

    def test_an_offline_router_is_reported_once_and_acted_on_when_it_returns(self, tmp_path: Path):
        manager = FakeManager()
        manager.statuses["r1"] = {"online": False}
        store, log, runner = build(tmp_path, manager)
        store.create(plan_data())

        (first,) = runner.run_once(AT)
        assert (first["status"], first["reason"]) == ("skipped", "the router is offline")
        assert runner.run_once(AT + timedelta(minutes=1)) == []
        assert runner.run_once(AT + timedelta(minutes=2)) == []
        (entry,) = entries(log)
        assert (entry["kind"], entry["result"]) == ("maintenance", "refused")
        assert entry["what"] == 'Maintenance "Weekly reboot": skipped: the router is offline'

        manager.statuses["r1"] = {"online": True, "uptime_seconds": 100_000}
        assert runner.run_once(AT + timedelta(minutes=3))[0]["status"] == "done"
        assert manager.reboots == [("r1", "Maintenance: Weekly reboot")]

    @pytest.mark.parametrize(
        "status,guards,reason",
        [
            ({"online": None, "reason": "credentials_rejected"}, {}, "the router rejected the stored credentials"),
            ({"online": True, "uptime_seconds": 600}, {}, "minimum uptime not reached: up 10 min, the plan needs 1 h"),
            ({"online": True}, {}, "uptime unavailable"),
            ({"online": True, "uptime_seconds": 100_000, "clients": "7"}, {"skip_if_clients_over": 6}, "7 clients"),
        ],
    )
    def test_guards_hold_the_router_back(self, tmp_path: Path, status, guards, reason):
        manager = FakeManager()
        manager.statuses["r1"] = status
        store, _, runner = build(tmp_path, manager)
        store.create(plan_data(guards=guards))
        (result,) = runner.run_once(AT)
        assert result["status"] == "skipped"
        assert result["reason"].startswith(reason)
        assert manager.reboots == []

    def test_no_minimum_uptime_accepts_a_router_that_reports_none(self, tmp_path: Path):
        manager = FakeManager()
        manager.statuses["r1"] = {"online": True}
        store, _, runner = build(tmp_path, manager)
        store.create(plan_data(guards={"min_uptime_seconds": 0}))
        assert runner.run_once(AT)[0]["status"] == "done"

    def test_the_client_count_is_asked_for_when_the_status_lacks_it(self, tmp_path: Path):
        manager = FakeManager()
        manager.clients["r1"] = 3
        store, _, runner = build(tmp_path, manager)
        store.create(plan_data(guards={"skip_if_clients_over": 2}))
        (result,) = runner.run_once(AT)
        assert result["reason"] == "3 clients connected, more than the 2 the plan allows"

        manager.clients["r1"] = 2
        assert runner.run_once(AT + timedelta(minutes=1))[0]["status"] == "done"

    def test_a_router_that_cannot_count_clients_is_held_back_when_a_limit_is_set(self, tmp_path: Path):
        manager = FakeManager()
        manager.failures[("r1", "clients")] = UnsupportedOperation("connected-client reporting is not supported")
        store, _, runner = build(tmp_path, manager)
        store.create(plan_data(guards={"skip_if_clients_over": 10}))
        (result,) = runner.run_once(AT)
        assert "client limit cannot be checked" in result["reason"]
        assert manager.reboots == []

    def test_two_plans_on_one_router_restart_it_once(self, tmp_path: Path):
        manager = FakeManager()
        store, log, runner = build(tmp_path, manager)
        store.create(plan_data(name="A plan"))
        store.create(plan_data(name="B plan"))

        first, second = runner.run_once(AT)

        assert first["status"] == "done"
        assert second["status"] == "skipped" and second["reason"].startswith("cooldown active")
        assert manager.reboots == [("r1", "Maintenance: A plan")]

    def test_two_plans_visiting_one_router_in_parallel_restart_it_once(self, tmp_path: Path):
        manager = FakeManager()
        # Both visits read the router, and so pass every guard, before either restarts
        # it: only the cooldown check made under the state lock can stop the second.
        barrier = threading.Barrier(2, timeout=5)
        manager.status_hook = lambda identifier: barrier.wait()
        store, _, runner = build(tmp_path, manager, max_workers=4)
        store.create(plan_data(name="A plan"))
        store.create(plan_data(name="B plan"))

        results = runner.run_once(AT)

        assert len(manager.reboots) == 1
        assert sorted(result["status"] for result in results) == ["done", "skipped"]
        (held,) = [result for result in results if result["status"] == "skipped"]
        (outcome,) = held["actions"]
        assert outcome["status"] == "skipped" and outcome["detail"].startswith("cooldown active")

    def test_the_cooldown_holds_the_next_window_until_it_expires(self, tmp_path: Path):
        manager = FakeManager()
        store, _, runner = build(tmp_path, manager)
        schedule = {"days": ["tue", "wed"], "start": "03:00", "duration_minutes": 60, "timezone": "UTC"}
        created = store.create(plan_data(schedule=schedule, guards={"cooldown_hours": 30}))
        runner.run_once(AT)
        (held,) = runner.run_once(AT + timedelta(days=1))
        assert held["reason"] == "cooldown active: SkyRouter last restarted it 24 h ago (cooldown 30 h)"

        store.update(created["id"], {"guards": {"cooldown_hours": 23}})
        assert runner.run_once(AT + timedelta(days=1, minutes=1))[0]["status"] == "done"
        assert len(manager.reboots) == 2

    def test_a_plan_that_restarts_nothing_ignores_the_cooldown(self, tmp_path: Path):
        manager = FakeManager()
        store, _, runner = build(tmp_path, manager)
        # Named so the reboot runs first and would start a cooldown for the check.
        store.create(plan_data(name="A reboot"))
        store.create(plan_data(name="B check", actions=["firmware_check"]))
        results = runner.run_once(AT)
        assert [result["status"] for result in results] == ["done", "done"]
        assert len(manager.ops("check_firmware_update")) == 1

    def test_one_failing_router_does_not_stop_the_others(self, tmp_path: Path):
        manager = FakeManager(make_device("bad"), make_device("good"))

        class ChannelClosed(Exception):
            pass

        manager.failures[("bad", "reboot")] = ChannelClosed("channel closed")
        store, log, runner = build(tmp_path, manager)
        store.create(plan_data(targets={"devices": ["bad", "good"]}))

        bad, good = runner.run_once(AT)

        assert (bad["status"], bad["reason"]) == ("failed", "channel closed")
        assert good["status"] == "done"
        assert [identifier for identifier, _ in manager.reboots] == ["bad", "good"]
        failed = [entry for entry in entries(log) if entry["result"] == "failed"]
        assert [entry["router"] for entry in failed] == ["bad"]

    def test_a_status_read_that_raises_is_reported_once_and_retried(self, tmp_path: Path):
        manager = FakeManager(make_device("bad"), make_device("good"))
        manager.failures[("bad", "status")] = KeyError("garbled")
        store, _, runner = build(tmp_path, manager)
        store.create(plan_data(targets={"devices": ["bad", "good"]}))

        bad, good = runner.run_once(AT)
        assert bad["status"] == "failed" and "nothing was done" in bad["reason"]
        assert good["status"] == "done"
        assert runner.run_once(AT + timedelta(minutes=1)) == []

        del manager.failures[("bad", "status")]
        assert runner.run_once(AT + timedelta(minutes=2))[0]["status"] == "done"

    def test_a_reboot_that_may_have_gone_out_is_not_sent_again(self, tmp_path: Path):
        manager = FakeManager()
        manager.failures[("r1", "reboot")] = AdapterError("router request failed: connection reset by peer")
        store, _, runner = build(tmp_path, manager)
        store.create(plan_data())

        assert runner.run_once(AT)[0]["status"] == "failed"
        for minute in range(1, 40, 5):
            assert runner.run_once(AT + timedelta(minutes=minute)) == []
        # A fresh runner (a restarted dashboard) reads the same record.
        assert build(tmp_path, manager)[2].run_once(AT + timedelta(minutes=45)) == []
        assert len(manager.reboots) == 1

    def test_nothing_is_sent_when_the_visit_cannot_be_recorded(self, tmp_path: Path, monkeypatch):
        manager = FakeManager()
        store, _, runner = build(tmp_path, manager)
        store.create(plan_data())

        def disk_full(*_args):
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(maintenance, "_write_json", disk_full)
        (result,) = runner.run_once(AT)

        assert manager.reboots == []
        assert result["status"] == "failed"
        assert "No space left on device" in result["reason"]

    @pytest.mark.parametrize("via", ["direct", "acs"])
    def test_nothing_is_sent_when_the_restart_cannot_be_recorded_first(self, tmp_path: Path, monkeypatch, via):
        manager, acs = FakeManager(), FakeAcs()
        acs.add()
        store, _, runner = build(tmp_path, manager, acs)
        store.create(acs_plan() if via == "acs" else plan_data())
        real = maintenance._write_json
        writes: list[str] = []

        def second_state_write_fails(path: Path, payload: Any, prefix: str) -> None:
            if prefix == "maintenance-state.":
                writes.append(prefix)
                # The first is the occurrence claim; the second, the restart's cooldown record.
                if len(writes) == 2:
                    raise OSError(28, "No space left on device")
            real(path, payload, prefix)

        monkeypatch.setattr(maintenance, "_write_json", second_state_write_fails)
        (result,) = runner.run_once(AT)

        assert manager.reboots == [] and acs.reboots == []
        (outcome,) = result["actions"]
        assert outcome["status"] == "skipped"
        assert outcome["detail"].startswith("not sent, because the attempt could not be recorded first")
        (occurrence,) = runner.get_state()["occurrences"].values()
        assert result["target"] in occurrence["targets"], "the claim still stands, so the window is not repeated"
        assert result["target"] not in runner.get_state()["targets"]

    def test_a_refused_reboot_does_not_start_the_cooldown(self, tmp_path: Path):
        manager = FakeManager()
        manager.failures[("r1", "reboot")] = CredentialLatched("not contacting r1: the router already rejected it")
        store, _, runner = build(tmp_path, manager)
        store.create(plan_data())

        (result,) = runner.run_once(AT)

        assert result["status"] == "skipped"
        assert "direct:r1" not in runner.get_state()["targets"]

    def test_a_failed_reboot_still_counts_towards_the_cooldown(self, tmp_path: Path):
        manager = FakeManager()
        manager.reboot_result = False
        store, _, runner = build(tmp_path, manager)
        created = store.create(plan_data())
        runner.run_once(AT)
        assert runner.get_state()["targets"]["direct:r1"]["last_disruptive"] == AT.isoformat()
        (again,) = runner.run_now(created["id"], "alice")
        assert again["reason"].startswith("cooldown active")

    def test_firmware_checks_never_claim_an_update_without_evidence(self, tmp_path: Path):
        manager = FakeManager()
        manager.checks["r1"] = {
            "available": None,
            "current": "2.5.25",
            "latest": None,
            "note": "result not recognised: the router's answer named no version",
        }
        store, log, runner = build(tmp_path, manager)
        store.create(plan_data(actions=["firmware_check"]))
        (result,) = runner.run_once(AT)
        (outcome,) = result["actions"]
        assert outcome["status"] == "done" and outcome["available"] is None
        assert outcome["detail"].startswith("could not tell whether newer firmware exists: result not recognised")
        (entry,) = entries(log)
        assert entry["details"]["available"] is None
        assert manager.ops("check_firmware_update") == [("r1", (maintenance.CHECK_TIMEOUT,))]

    def test_auto_update_already_on_is_left_alone(self, tmp_path: Path):
        manager = FakeManager()
        store, log, runner = build(tmp_path, manager)
        store.create(plan_data(actions=["auto_update_on"]))
        runner.run_once(AT)
        assert manager.ops("set_auto_update") == []
        assert entries(log)[0]["what"].endswith("automatic firmware update was already on (window 03:00-05:00)")

    def test_auto_update_is_turned_on_at_the_plans_start_hour_not_the_routers_old_slot(self, tmp_path: Path):
        manager = FakeManager()
        # The slot left selected while automatic update was off is nobody's choice.
        manager.auto["r1"] = {"enabled": False, "window_start_hour": 22, "window": "22:00-00:00"}
        store, log, runner = build(tmp_path, manager)
        store.create(plan_data(actions=["auto_update_on"]))
        runner.run_once(AT)
        assert manager.ops("set_auto_update") == [("r1", (True, 3))]
        (entry,) = entries(log)
        assert entry["result"] == "applied" and "window 03:00-05:00, from the plan's start hour" in entry["what"]
        assert "on the router's own clock" in entry["what"]

    def test_auto_update_already_on_in_another_window_is_left_but_reported(self, tmp_path: Path):
        manager = FakeManager()
        manager.auto["r1"] = {"enabled": True, "window_start_hour": 22, "window": "22:00-00:00"}
        store, log, runner = build(tmp_path, manager)
        store.create(plan_data(actions=["auto_update_on"]))
        (result,) = runner.run_once(AT)
        assert manager.ops("set_auto_update") == []
        (outcome,) = result["actions"]
        assert "already on (window 22:00-00:00)" in outcome["detail"]
        assert "not at the plan's start hour (03:00-05:00)" in outcome["detail"]
        assert "not at the plan's start hour" in entries(log)[0]["what"]

    def test_auto_update_without_a_window_takes_the_plans_start_hour(self, tmp_path: Path):
        manager = FakeManager()
        manager.auto["r1"] = {"enabled": False, "window_start_hour": None, "window": None}
        store, log, runner = build(tmp_path, manager)
        store.create(plan_data(actions=["auto_update_on"]))
        runner.run_once(AT)
        assert manager.ops("set_auto_update") == [("r1", (True, 3))]
        assert "window 03:00-05:00, from the plan's start hour" in entries(log)[0]["what"]

    def test_a_router_without_auto_update_is_skipped_with_a_reason(self, tmp_path: Path):
        manager = FakeManager()
        manager.auto["r1"] = None
        store, log, runner = build(tmp_path, manager)
        store.create(plan_data(actions=["auto_update_on", "reboot"]))
        (result,) = runner.run_once(AT)
        assert [item["status"] for item in result["actions"]] == ["skipped", "done"]
        assert result["status"] == "done"
        assert entries(log)[0]["result"] == "refused"

    def test_unsupported_firmware_operations_are_skipped_not_failed(self, tmp_path: Path):
        manager = FakeManager()
        manager.failures[("r1", "check_firmware_update")] = UnsupportedOperation("not supported by this adapter")
        store, log, runner = build(tmp_path, manager)
        store.create(plan_data(actions=["firmware_check"]))
        (result,) = runner.run_once(AT)
        assert result["status"] == "skipped"
        (entry,) = entries(log)
        assert (entry["kind"], entry["result"]) == ("firmware", "refused")
        assert "Firmware check refused: not supported by this adapter" in entry["what"]

    def test_a_failed_check_before_a_reboot_that_went_out_is_partial(self, tmp_path: Path):
        manager = FakeManager()
        manager.failures[("r1", "check_firmware_update")] = AdapterError("router request failed: timed out")
        store, _, runner = build(tmp_path, manager)
        store.create(plan_data(actions=["firmware_check", "reboot"]))
        (result,) = runner.run_once(AT)
        assert [item["status"] for item in result["actions"]] == ["failed", "done"]
        assert result["status"] == "partial"
        assert result["reason"] == "router request failed: timed out"
        assert len(manager.reboots) == 1

    def test_a_plan_whose_timezone_broke_is_reported_and_the_others_still_run(self, tmp_path: Path, monkeypatch):
        manager = FakeManager()
        store, _, runner = build(tmp_path, manager)
        schedule = {"days": ["tue"], "start": "05:00", "duration_minutes": 60, "timezone": "Africa/Johannesburg"}
        broken = store.create(plan_data(name="Broken", schedule=schedule))
        store.create(plan_data(name="Working"))
        real_zone = PlanSchedule._zone

        def zone(schedule: PlanSchedule):
            # What a tzdata update that dropped the zone would do; it was valid when saved.
            if schedule.timezone == "Africa/Johannesburg":
                raise ZoneInfoNotFoundError("No time zone found with key Africa/Johannesburg")
            return real_zone(schedule)

        monkeypatch.setattr(PlanSchedule, "_zone", zone)
        results = runner.run_once(AT)

        (problem,) = [result for result in results if result["plan"] == broken["id"]]
        assert problem["status"] == "failed"
        assert problem["reason"].startswith("the plan's timezone cannot be used")
        assert manager.reboots == [("r1", "Maintenance: Working")]

    def test_a_firmware_update_is_never_sent_to_a_direct_router(self, tmp_path: Path):
        manager = FakeManager()
        store, log, runner = build(tmp_path, manager, FakeAcs())
        store.create(
            plan_data(targets={"all": True}, actions=["firmware_update", "reboot"], firmware={"AP1300": FIRMWARE})
        )
        (result,) = runner.run_once(AT)
        firmware, reboot = result["actions"]
        assert firmware["status"] == "skipped" and "only sent to TR-069 routers" in firmware["detail"]
        assert reboot["status"] == "done"

    def test_all_means_every_enabled_router_and_a_named_disabled_one_is_reported(self, tmp_path: Path):
        manager = FakeManager(make_device("a"), make_device("b"), make_device("off", enabled=False))
        store, _, runner = build(tmp_path, manager)
        store.create(plan_data(targets={"all": True}))
        assert sorted(result["device"] for result in runner.run_once(AT)) == ["a", "b"]
        assert "off" not in {identifier for identifier, _ in manager.reboots}

        store.create(plan_data(name="Named", targets={"devices": ["off", "gone"]}))
        results = {result["device"]: result["reason"] for result in runner.run_once(AT + timedelta(minutes=1))}
        assert results == {
            "gone": "the router is no longer managed by SkyRouter",
            "off": "the router is disabled in SkyRouter",
        }

    def test_routers_are_visited_in_parallel(self, tmp_path: Path):
        manager = FakeManager(make_device("a"), make_device("b"))
        barrier = threading.Barrier(2, timeout=5)
        manager.status_hook = lambda identifier: barrier.wait()
        store, _, runner = build(tmp_path, manager, max_workers=4)
        store.create(plan_data(targets={"devices": ["a", "b"]}))
        assert [result["status"] for result in runner.run_once(AT)] == ["done", "done"]

    def test_two_dashboards_on_one_data_dir_reboot_once(self, tmp_path: Path):
        inside, release = threading.Event(), threading.Event()
        slow, fast = FakeManager(), FakeManager()

        def hold(_identifier):
            inside.set()
            release.wait(5)

        slow.status_hook = hold
        store, _, first = build(tmp_path, slow)
        second = build(tmp_path, fast)[2]
        store.create(plan_data())
        thread = threading.Thread(target=first.run_once, args=(AT,))
        thread.start()
        assert inside.wait(5)
        second.run_once(AT)
        release.set()
        thread.join(5)
        assert slow.reboots + fast.reboots == [("r1", "Maintenance: Weekly reboot")]

    def test_the_state_file_is_private_and_old_occurrences_are_pruned(self, tmp_path: Path):
        manager = FakeManager()
        store, _, runner = build(tmp_path, manager)
        created = store.create(plan_data(guards={"cooldown_hours": 1}))
        runner.run_once(AT)
        assert stat.S_IMODE(runner.state_path.stat().st_mode) == 0o600
        assert list(runner.get_state()["occurrences"]) == [f"{created['id']}:2026-03-10"]

        runner.run_once(AT + timedelta(days=49))
        assert list(runner.get_state()["occurrences"]) == [f"{created['id']}:2026-04-28"]

    def test_an_unreadable_state_file_stops_the_pass(self, tmp_path: Path):
        manager = FakeManager()
        store, _, runner = build(tmp_path, manager)
        store.create(plan_data())
        runner.state_path.write_text("[]")
        with pytest.raises(MaintenanceError):
            runner.run_once(AT)
        assert manager.reboots == []


class TestRunNow:
    def test_runs_outside_the_window_and_names_who_asked(self, tmp_path: Path):
        manager = FakeManager()
        store, log, runner = build(tmp_path, manager, at=AT + timedelta(hours=5))
        created = store.create(plan_data(enabled=False))
        (result,) = runner.run_now(created["id"], "alice")
        assert result["trigger"] == "manual" and result["status"] == "done"
        assert manager.reboots == [("r1", "Maintenance: Weekly reboot (run by alice)")]
        assert entries(log)[0]["details"]["trigger"] == "manual"

    def test_the_guards_still_apply(self, tmp_path: Path):
        manager = FakeManager()
        manager.statuses["r1"] = {"online": True, "uptime_seconds": 30}
        store, _, runner = build(tmp_path, manager)
        created = store.create(plan_data())
        assert runner.run_now(created["id"], "alice")[0]["reason"].startswith("minimum uptime not reached")
        assert manager.reboots == []

    def test_the_scheduled_window_after_a_manual_run_is_held_by_the_cooldown(self, tmp_path: Path):
        manager = FakeManager()
        store, _, runner = build(tmp_path, manager, at=AT - timedelta(hours=1))
        created = store.create(plan_data())
        runner.run_now(created["id"], "alice")
        (result,) = runner.run_once(AT)
        assert result["reason"].startswith("cooldown active")
        assert len(manager.reboots) == 1

    def test_a_plan_cannot_be_run_twice_at_once(self, tmp_path: Path):
        manager = FakeManager()
        inside, release = threading.Event(), threading.Event()

        def hold(_identifier):
            inside.set()
            release.wait(5)

        manager.status_hook = hold
        store, _, runner = build(tmp_path, manager)
        created = store.create(plan_data())
        thread = threading.Thread(target=runner.run_now, args=(created["id"], "alice"))
        thread.start()
        assert inside.wait(5)
        with pytest.raises(MaintenanceBusy):
            runner.run_now(created["id"], "bob")
        release.set()
        thread.join(5)

    def test_unknown_plans_and_actors_are_refused(self, tmp_path: Path):
        store, _, runner = build(tmp_path)
        created = store.create(plan_data())
        with pytest.raises(PlanNotFound):
            runner.run_now("0123456789ab", "alice")
        with pytest.raises(ValidationError):
            runner.run_now(created["id"], "  ")


class Clock:
    """A clock the fakes move on, as a slow router moves the real one."""

    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **delta: float) -> None:
        self.now += timedelta(**delta)


SHORT_WINDOW = {"days": ["tue"], "start": "03:00", "duration_minutes": 15, "timezone": "UTC"}


class TestAPassOutlastingItsWindowOrItsPlan:
    def test_routers_reached_after_the_window_closed_are_not_restarted(self, tmp_path: Path):
        clock = Clock(datetime(2026, 3, 10, 3, 11, tzinfo=UTC))
        names = [f"r{index}" for index in range(1, 6)]
        manager = FakeManager(*(make_device(name) for name in names))
        # Each status read takes a minute and a half, as a router that times out does.
        manager.status_hook = lambda identifier: clock.advance(seconds=90)
        store, _, runner = build(tmp_path, manager, clock=clock)
        store.create(plan_data(targets={"devices": names}, schedule=SHORT_WINDOW))

        results = runner.run_once()

        # r1 is read by 03:12:30 and r2 by 03:14:00; r3's read ends at 03:15:30, after 03:15.
        assert [identifier for identifier, _ in manager.reboots] == ["r1", "r2"]
        held = [result for result in results if result["status"] == "skipped"]
        assert [result["device"] for result in held] == ["r3", "r4", "r5"]
        assert {result["reason"] for result in held} == {"the plan's window has closed"}
        # r4 and r5 were not even read.
        assert [identifier for identifier, _ in manager.ops("status")] == ["r1", "r2", "r3"]
        # The cooldown runs from when the reboot went out, not from when the pass began.
        assert runner.get_state()["targets"]["direct:r2"]["last_disruptive"] == "2026-03-10T03:14:00+00:00"

    def test_a_reboot_after_a_long_check_is_not_sent_once_the_window_closed(self, tmp_path: Path):
        clock = Clock(datetime(2026, 3, 10, 3, 10, tzinfo=UTC))
        manager = FakeManager()
        manager.call_hook = lambda operation: clock.advance(minutes=6) if operation == "check_firmware_update" else None
        store, _, runner = build(tmp_path, manager, clock=clock)
        store.create(plan_data(actions=["firmware_check", "reboot"], schedule=SHORT_WINDOW))

        (result,) = runner.run_once()

        check, reboot = result["actions"]
        assert check["status"] == "done"
        assert reboot == {"action": "reboot", "status": "skipped", "detail": "not sent: the plan's window has closed"}
        assert manager.reboots == []
        assert "direct:r1" not in runner.get_state()["targets"]

    @pytest.mark.parametrize(
        "change,reason",
        [
            ("disable", "the plan was turned off"),
            ("delete", "the plan was deleted"),
            ("retarget", "the plan no longer names this router"),
            ("reschedule", "the plan's window has closed"),
        ],
    )
    def test_a_plan_changed_during_a_pass_stops_acting_on_its_routers(self, tmp_path: Path, change, reason):
        manager = FakeManager(make_device("r1"), make_device("r2"))
        store, _, runner = build(tmp_path, manager)
        created = store.create(plan_data(targets={"devices": ["r1", "r2"]}))
        edits = {
            "disable": lambda: store.update(created["id"], {"enabled": False}),
            "delete": lambda: store.delete(created["id"]),
            "retarget": lambda: store.update(created["id"], {"targets": {"devices": ["r1"]}}),
            "reschedule": lambda: store.update(created["id"], {"schedule": {**SHORT_WINDOW, "days": ["wed"]}}),
        }
        manager.status_hook = lambda identifier: edits[change]() if identifier == "r2" else None

        results = runner.run_once(AT)

        assert manager.reboots == [("r1", "Maintenance: Weekly reboot")]
        assert {result["device"]: result.get("reason") for result in results}["r2"] == reason

    def test_a_guard_changed_during_a_pass_applies_to_the_routers_after_it(self, tmp_path: Path):
        manager = FakeManager(make_device("r1"), make_device("r2"))
        store, _, runner = build(tmp_path, manager)
        created = store.create(plan_data(targets={"devices": ["r1", "r2"]}))

        def edit(identifier: str) -> None:
            if identifier == "r1":
                store.update(created["id"], {"guards": {"min_uptime_seconds": 200_000}})

        manager.status_hook = edit
        results = {result["device"]: result for result in runner.run_once(AT)}
        # r1 had already passed the guards it was checked against.
        assert manager.reboots == [("r1", "Maintenance: Weekly reboot")]
        assert results["r2"]["reason"].startswith("minimum uptime not reached")


class TestOverview:
    def test_next_window_and_last_run(self, tmp_path: Path):
        manager = FakeManager()
        store, _, runner = build(tmp_path, manager)
        created = store.create(plan_data())
        (view,) = runner.overview(AT - timedelta(hours=1))
        assert view["next_window"] == {"opens": "2026-03-10T03:00:00+00:00", "closes": "2026-03-10T04:00:00+00:00"}
        assert view["window_open"] is False and view["last_run"] is None

        runner.run_once(AT)
        (view,) = runner.overview(AT)
        assert view["window_open"] is True
        assert view["last_run"]["occurrence"] == f"{created['id']}:2026-03-10"
        assert view["last_run"]["targets"] == {"direct:r1": "done"}


# --- the runner: TR-069 routers ----------------------------------------------------------


def acs_plan(**overrides: Any) -> dict[str, Any]:
    return plan_data(targets={"acs_devices": [ACS_ID]}, **overrides)


class TestRunnerAcs:
    def test_a_reboot_is_queued_as_an_acs_job(self, tmp_path: Path):
        acs = FakeAcs()
        acs.add()
        store, log, runner = build(tmp_path, FakeManager(), acs)
        store.create(acs_plan())
        (result,) = runner.run_once(AT)
        # Queued is not done: the job may still fail, and says so in its own log entry.
        assert result["target"] == f"acs:{ACS_ID}" and result["status"] == "queued"
        assert result["actions"][0]["status"] == "queued"
        assert "queued as ACS job 0000000000000001" in result["reason"]
        (occurrence,) = runner.get_state()["occurrences"].values()
        assert occurrence["targets"][f"acs:{ACS_ID}"]["status"] == "queued"
        assert acs.reboots == [(ACS_ID, "Maintenance: Weekly reboot")]
        (entry,) = entries(log)
        assert (entry["router"], entry["kind"], entry["result"]) == (f"acs:{ACS_ID}", "reboot", "queued")
        assert entry["details"]["job"] == "0000000000000001"

    @pytest.mark.parametrize(
        "values,guards,reason",
        [
            ({"online": False}, {}, "the router is not checking in with the ACS"),
            ({"online": None}, {}, "the router is not checking in with the ACS"),
            ({"booted": AT - timedelta(minutes=20)}, {}, "minimum uptime not reached: up 20 min"),
            ({"booted": None}, {}, "uptime unavailable"),
            ({"clients": 4}, {"skip_if_clients_over": 3}, "4 clients connected"),
        ],
    )
    def test_guards(self, tmp_path: Path, values, guards, reason):
        acs = FakeAcs()
        acs.add(**values)
        store, _, runner = build(tmp_path, FakeManager(), acs)
        store.create(acs_plan(guards=guards))
        (result,) = runner.run_once(AT)
        assert result["status"] == "skipped" and result["reason"].startswith(reason)
        assert acs.reboots == []

    @pytest.mark.parametrize(
        "values,reason",
        [
            # No Hosts or AssociatedDevice table cached, or a TR-181 Issue 1 router.
            ({"client_data": False}, "the router has not reported its connected clients over TR-069"),
            ({"clients_as_of": AT - timedelta(hours=3)}, "the connected-client count over TR-069 is 3 h old"),
            ({"clients_as_of": None}, "the connected-client count over TR-069 has no timestamp"),
        ],
    )
    def test_an_unknown_or_stale_client_count_holds_the_router_back(self, tmp_path: Path, values, reason):
        acs = FakeAcs()
        acs.add(clients=1, **values)
        store, _, runner = build(tmp_path, FakeManager(), acs)
        store.create(acs_plan(guards={"skip_if_clients_over": 5}))
        (result,) = runner.run_once(AT)
        assert result["status"] == "skipped" and result["reason"].startswith(reason)
        assert "client limit cannot be checked" in result["reason"]
        assert acs.reboots == []

    def test_a_fresh_client_count_under_the_limit_lets_the_router_through(self, tmp_path: Path):
        acs = FakeAcs()
        acs.add(clients=2)
        acs.details[ACS_ID]["clients"].append({"mac": "AA:BB:CC:00:00:FF", "active": False, "as_of": None})
        store, _, runner = build(tmp_path, FakeManager(), acs)
        store.create(acs_plan(guards={"skip_if_clients_over": 2}))
        assert runner.run_once(AT)[0]["status"] == "queued"
        assert len(acs.reboots) == 1

    def test_a_router_installing_firmware_is_not_restarted(self, tmp_path: Path):
        acs = FakeAcs()
        acs.add()
        # Started from the dashboard; the router is between the download and its restart.
        acs.details[ACS_ID]["pending_jobs"] = [
            {"id": "00000000000000aa", "kind": "firmware", "state": "waiting_for_checkin"}
        ]
        store, _, runner = build(tmp_path, FakeManager(), acs)
        store.create(acs_plan())
        (result,) = runner.run_once(AT)
        assert result["status"] == "skipped"
        assert result["reason"].startswith("a firmware upgrade is under way on this router (ACS job 00000000000000aa)")
        assert acs.reboots == []

    def test_an_upgrade_refused_because_another_is_under_way_also_holds_the_reboot(self, tmp_path: Path):
        acs = FakeAcs()
        acs.add()
        acs.upgrade_error = AcsBusy("another firmware upgrade is under way on this router (job x); wait for it")
        store, _, runner = build(tmp_path, FakeManager(), acs)
        store.create(acs_plan(actions=["firmware_update", "reboot"], firmware={"AP1300": FIRMWARE}))
        (result,) = runner.run_once(AT)
        firmware, reboot = result["actions"]
        assert firmware["status"] == "skipped" and "another firmware upgrade" in firmware["detail"]
        assert reboot["status"] == "skipped" and "could interrupt it" in reboot["detail"]
        assert acs.reboots == []

    def test_a_reboot_after_an_upgrade_that_could_not_be_queued_is_not_held_by_its_own_restart(self, tmp_path: Path):
        acs = FakeAcs()
        acs.add()
        acs.terminal_kinds = {"firmware"}
        store, _, runner = build(tmp_path, FakeManager(), acs)
        store.create(acs_plan(actions=["firmware_update", "reboot"], firmware={"AP1300": FIRMWARE}))
        (result,) = runner.run_once(AT)
        firmware, reboot = result["actions"]
        assert firmware["status"] == "failed" and "could not be queued" in firmware["detail"]
        # The upgrade's restart record is this occurrence's own, so it is no cooldown.
        assert reboot["status"] == "queued"
        assert len(acs.reboots) == 1
        assert result["status"] == "partial"

    def test_tr069_steps_expire_when_the_window_closes(self, tmp_path: Path):
        acs = FakeAcs()
        acs.add(ACS_ID)
        acs.add(ACS_OTHER, firmware=NEWER)
        store, _, runner = build(tmp_path, FakeManager(), acs)
        store.create(
            plan_data(
                targets={"acs_devices": [ACS_ID, ACS_OTHER]},
                actions=["firmware_update", "reboot"],
                firmware={"AP1300": FIRMWARE},
            )
        )
        runner.run_once(AT)
        # 03:10 in a 03:00-04:00 window: 50 minutes left for the upgrade and the reboot.
        assert acs.upgrades == [(ACS_ID, FIRMWARE, False, "Maintenance: Weekly reboot")]
        assert acs.reboots == [(ACS_OTHER, "Maintenance: Weekly reboot")]
        assert acs.expiries == [3000, 3000]

    def test_a_manual_run_leaves_the_expiry_to_the_acs(self, tmp_path: Path):
        acs = FakeAcs()
        acs.add()
        store, _, runner = build(tmp_path, FakeManager(), acs, at=AT + timedelta(hours=5))
        created = store.create(acs_plan())
        runner.run_now(created["id"], "alice")
        assert acs.expiries == [None]

    def test_nothing_is_queued_in_the_windows_last_minute(self, tmp_path: Path):
        acs = FakeAcs()
        acs.add()
        store, _, runner = build(tmp_path, FakeManager(), acs, at=datetime(2026, 3, 10, 3, 59, 30, tzinfo=UTC))
        store.create(acs_plan())
        (result,) = runner.run_once()
        (outcome,) = result["actions"]
        assert outcome["status"] == "skipped" and "closes in under a minute" in outcome["detail"]
        assert acs.reboots == []
        assert f"acs:{ACS_ID}" not in runner.get_state()["targets"]

    def test_a_router_in_both_inventories_is_restarted_once(self, tmp_path: Path):
        acs = FakeAcs()
        # The Cudy's own TR-069 client reports the address SkyRouter manages it at directly.
        acs.add(wan_ip="192.0.2.1")
        manager = FakeManager()
        store, _, runner = build(tmp_path, manager, acs)
        store.create(plan_data(targets={"all": True}))
        results = {result["target"]: result for result in runner.run_once(AT)}
        assert results["direct:r1"]["status"] == "done"
        twin = results[f"acs:{ACS_ID}"]
        assert twin["status"] == "skipped"
        assert twin["reason"].startswith("the same router is managed directly as r1 (192.0.2.1)")
        assert acs.reboots == [] and len(manager.reboots) == 1

    def test_a_twin_the_plan_does_not_name_does_not_hold_the_tr069_router_back(self, tmp_path: Path):
        acs = FakeAcs()
        acs.add(wan_ip="192.0.2.1")
        store, _, runner = build(tmp_path, FakeManager(), acs)
        store.create(acs_plan())
        assert runner.run_once(AT)[0]["status"] == "queued"

    def test_a_cached_uptime_is_aged_when_the_boot_time_is_unknown(self, tmp_path: Path):
        acs = FakeAcs()
        acs.add(booted=None)
        acs.details[ACS_ID]["info"].update(uptime=3000, as_of={"uptime": (AT - timedelta(minutes=10)).isoformat()})
        store, _, runner = build(tmp_path, FakeManager(), acs)
        store.create(acs_plan())
        assert runner.run_once(AT)[0]["status"] == "queued"

    def test_missing_or_unreachable_routers_and_a_disabled_acs(self, tmp_path: Path):
        acs = FakeAcs()
        store, _, runner = build(tmp_path, FakeManager(), acs)
        store.create(acs_plan())
        assert runner.run_once(AT)[0]["reason"] == "the router is no longer in the ACS"
        acs.detail_error = AcsUnavailable("ACS unavailable: connection refused")
        assert runner.run_once(AT)[0]["reason"].startswith("could not read the router from the ACS")
        off = build(tmp_path / "off", FakeManager(), None)
        off[0].create(acs_plan())
        assert off[2].run_once(AT)[0]["reason"] == "TR-069 management is off"

    def test_firmware_is_chosen_by_product_class_and_the_reboot_is_left_to_it(self, tmp_path: Path):
        acs = FakeAcs()
        acs.add(product_class="ap1300")
        store, log, runner = build(tmp_path, FakeManager(), acs)
        store.create(
            acs_plan(actions=["firmware_update", "reboot"], firmware={"AP1300": FIRMWARE}, name="Firmware night")
        )

        (result,) = runner.run_once(AT)

        firmware, reboot = result["actions"]
        assert firmware["status"] == "queued" and firmware["job"] == "0000000000000001"
        assert reboot["status"] == "skipped" and "restarts the router itself" in reboot["detail"]
        # Never past a model mismatch without a person looking at it.
        assert acs.upgrades == [(ACS_ID, FIRMWARE, False, "Maintenance: Firmware night")]
        assert acs.reboots == []
        queued, skipped = entries(log)
        assert (queued["kind"], queued["result"], queued["details"]["firmware"]) == ("firmware", "queued", FIRMWARE)
        assert (skipped["kind"], skipped["result"]) == ("reboot", "info")

    def test_a_router_with_no_chosen_firmware_still_gets_its_reboot(self, tmp_path: Path):
        acs = FakeAcs()
        acs.add(product_class="WR840N")
        store, log, runner = build(tmp_path, FakeManager(), acs)
        store.create(acs_plan(actions=["firmware_update", "reboot"], firmware={"AP1300": FIRMWARE}))
        (result,) = runner.run_once(AT)
        assert [item["status"] for item in result["actions"]] == ["skipped", "queued"]
        assert "no firmware for product class WR840N" in result["actions"][0]["detail"]
        assert acs.upgrades == [] and len(acs.reboots) == 1

    def test_a_router_already_on_the_version_is_not_upgraded(self, tmp_path: Path):
        acs = FakeAcs()
        acs.add(firmware=NEWER)
        store, log, runner = build(tmp_path, FakeManager(), acs)
        store.create(acs_plan(actions=["firmware_update"], firmware={"AP1300": FIRMWARE}))
        (result,) = runner.run_once(AT)
        assert result["actions"][0] == {
            "action": "firmware_update",
            "status": "done",
            "detail": f"the router already runs firmware {NEWER}",
        }
        assert acs.upgrades == []
        # Nothing restarted it, so nothing starts a cooldown.
        assert f"acs:{ACS_ID}" not in runner.get_state()["targets"]

    def test_a_refused_upgrade_is_reported_and_takes_back_its_restart(self, tmp_path: Path):
        from cudy_manager.acs.service import FirmwareMismatch

        acs = FakeAcs()
        acs.add()
        acs.upgrade_error = FirmwareMismatch("firmware was stored for another product class", plan={})
        store, log, runner = build(tmp_path, FakeManager(), acs)
        store.create(acs_plan(actions=["firmware_update"], firmware={"AP1300": FIRMWARE}))
        (result,) = runner.run_once(AT)
        assert result["status"] == "skipped"
        assert f"acs:{ACS_ID}" not in runner.get_state()["targets"]
        (entry,) = entries(log)
        assert entry["result"] == "refused" and "stored for another product class" in entry["what"]

    def test_a_firmware_file_gone_from_the_library_fails(self, tmp_path: Path):
        acs = FakeAcs()
        acs.add()
        acs.firmware.records.clear()
        store, _, runner = build(tmp_path, FakeManager(), acs)
        store.create(acs_plan(actions=["firmware_update"], firmware={"AP1300": FIRMWARE}))
        (result,) = runner.run_once(AT)
        assert result["status"] == "failed" and "no longer in the firmware library" in result["reason"]

    def test_a_job_that_ends_before_it_starts_is_a_failure(self, tmp_path: Path):
        acs = FakeAcs()
        acs.add()
        acs.terminal = True
        store, log, runner = build(tmp_path, FakeManager(), acs)
        store.create(acs_plan())
        (result,) = runner.run_once(AT)
        assert result["status"] == "failed"
        assert entries(log)[0]["result"] == "failed"

    def test_web_page_actions_are_skipped_for_tr069_routers(self, tmp_path: Path):
        acs = FakeAcs()
        acs.add()
        store, _, runner = build(tmp_path, FakeManager(), acs)
        store.create(acs_plan(actions=["firmware_check", "auto_update_on"]))
        (result,) = runner.run_once(AT)
        assert result["status"] == "skipped"
        assert all("TR-069 does not reach" in item["detail"] for item in result["actions"])

    def test_all_includes_adopted_tr069_routers_only(self, tmp_path: Path):
        acs = FakeAcs()
        acs.add(ACS_ID)
        acs.add(ACS_OTHER, tags=("skybre_new",))
        manager = FakeManager()
        store, _, runner = build(tmp_path, manager, acs)
        store.create(plan_data(targets={"all": True}))
        assert sorted(result["target"] for result in runner.run_once(AT)) == [f"acs:{ACS_ID}", "direct:r1"]
        assert acs.reboots == [(ACS_ID, "Maintenance: Weekly reboot")]

    def test_all_pages_through_the_whole_tr069_fleet(self, tmp_path: Path, monkeypatch):
        monkeypatch.setattr(maintenance, "ACS_PAGE", 2)
        acs = FakeAcs()
        ids = [f"80AFCA-AP1300-{index:06d}" for index in range(1, 8)]
        new = {ids[3], ids[6]}
        for acs_id in ids:
            acs.add(acs_id, tags=("skybre_new",) if acs_id in new else ())
        store, _, runner = build(tmp_path, FakeManager(), acs)
        store.create(plan_data(targets={"all": True}))
        visited = sorted(result["device"] for result in runner.run_once(AT) if result["via"] == "acs")
        # Seven routers in pages of two; the unvetted ones on the later pages are still left out.
        assert visited == sorted(acs_id for acs_id in ids if acs_id not in new)

    def test_a_fleet_listing_failure_does_not_stop_the_direct_routers(self, tmp_path: Path):
        acs = FakeAcs()

        def down(**_kwargs):
            raise AcsUnavailable("ACS unavailable: connection refused")

        acs.list_devices = down  # type: ignore[method-assign]
        manager = FakeManager()
        store, _, runner = build(tmp_path, manager, acs)
        store.create(plan_data(targets={"all": True}))
        results = runner.run_once(AT)
        assert [(result["target"], result["status"]) for result in results] == [
            ("acs:*", "failed"),
            ("direct:r1", "done"),
        ]
        assert runner.run_once(AT + timedelta(minutes=1)) == []


# --- end to end ---------------------------------------------------------------------------


class TestEndToEnd:
    def test_a_cudy_plan_against_the_reconstructed_ap1300(self, tmp_path: Path, monkeypatch):
        from fake_router import FakeRouter

        from cudy_manager import adapters
        from cudy_manager.manager import DeviceManager
        from cudy_manager.secrets import SecretStore

        monkeypatch.setattr(adapters, "_CUDY_CHECK_POLL", 0.01)
        log = ActivityLog(tmp_path / "data")
        manager = DeviceManager(
            config_path=tmp_path / "devices.yaml",
            data_dir=tmp_path / "data",
            secret_store=SecretStore(tmp_path / "data"),
            activity=log,
        )
        with FakeRouter("ap1300") as router:
            manager.add_device("ap", "127.0.0.1", "cudy", password="goodpass", http_port=router.port)
            store = MaintenanceStore(tmp_path / "data")
            runner = MaintenanceRunner(manager, None, store, log, max_workers=1, check_timeout=5)
            created = store.create(
                plan_data(
                    name="Cudy night",
                    targets={"devices": ["ap"]},
                    actions=["firmware_check", "auto_update_on", "reboot"],
                    # The fake status page reports no uptime.
                    guards={"min_uptime_seconds": 0},
                )
            )

            (result,) = runner.run_now(created["id"], "alice")

            assert [item["status"] for item in result["actions"]] == ["done", "done", "done"]
            assert len(router.state["update_checks"]) == 1
            assert router.state["autoupgrade_posts"] == []
            assert router.state["reboots"] == 1
        check = result["actions"][0]
        assert check["available"] is None and "result not recognised" in check["detail"]
        maintained = [entry for entry in entries(log) if entry["who"].startswith("Maintenance")]
        assert [(entry["kind"], entry["result"]) for entry in maintained] == [
            ("firmware", "info"),
            ("firmware", "info"),
            ("reboot", "applied"),
        ]
        assert maintained[-1]["who"] == "Maintenance: Cudy night (run by alice)"
        assert "goodpass" not in log.path.read_text()

    def test_tr069_upgrade_and_reboot_against_the_fake_nbi(self, tmp_path: Path):
        from fake_nbi import FakeNbi, build_device, iso

        from cudy_manager.acs.client import AcsClient
        from cudy_manager.acs.service import AcsService
        from cudy_manager.secrets import SecretStore

        with FakeNbi() as nbi:
            log = ActivityLog(tmp_path)
            client = AcsClient(nbi.url, timeout=5)
            svc = AcsService(client, SecretStore(tmp_path), tmp_path, clock=nbi.now, activity=log)
            ids = []
            for serial in ("000001", "000002"):
                doc = build_device(
                    oui="80AFCA",
                    product_class="AP1300",
                    serial=serial,
                    manufacturer="Cudy",
                    leaves={
                        "Device.ManagementServer.ConnectionRequestURL": {
                            "value": "http://10.0.0.1:7547/",
                            "writable": False,
                        },
                        "Device.ManagementServer.PeriodicInformInterval": 300,
                        "Device.DeviceInfo.ModelName": {"value": "AP1300", "writable": False},
                        "Device.DeviceInfo.SoftwareVersion": {"value": "2.5.25", "writable": False},
                    },
                    last_inform=nbi.now(),
                )
                doc["_lastBoot"] = iso(nbi.now() - timedelta(hours=3))
                ids.append(nbi.add_device(doc))
            record = svc.add_firmware(b"IMAGE" * 100, "fw.bin", None, NEWER, "80AFCA", "AP1300")
            store = MaintenanceStore(tmp_path)
            runner = MaintenanceRunner(FakeManager(), svc, store, log, clock=nbi.now, max_workers=1)
            upgrade = store.create(
                plan_data(
                    name="Firmware",
                    targets={"acs_devices": [ids[0]]},
                    actions=["firmware_update", "reboot"],
                    firmware={"AP1300": record["name"]},
                )
            )
            reboot = store.create(plan_data(name="Reboot", targets={"acs_devices": [ids[1]]}))

            (upgraded,) = runner.run_now(upgrade["id"], "alice")
            (rebooted,) = runner.run_now(reboot["id"], "alice")

            assert [item["status"] for item in upgraded["actions"]] == ["queued", "skipped"]
            assert [item["status"] for item in rebooted["actions"]] == ["queued"]
            assert [(task["device"], task["name"]) for task in nbi.tasks] == [(ids[0], "download"), (ids[1], "reboot")]
            (job,) = svc.list_jobs(acs_id=ids[0])
            assert job["actor"] == "Maintenance: Firmware (run by alice)"

    @staticmethod
    def acs_fleet(nbi: Any, tmp_path: Path, *serials: str) -> tuple[Any, ActivityLog, list[str]]:
        from fake_nbi import build_device, iso

        from cudy_manager.acs.client import AcsClient
        from cudy_manager.acs.service import AcsService
        from cudy_manager.secrets import SecretStore

        log = ActivityLog(tmp_path)
        svc = AcsService(AcsClient(nbi.url, timeout=5), SecretStore(tmp_path), tmp_path, clock=nbi.now, activity=log)
        ids = []
        for serial in serials:
            doc = build_device(
                oui="80AFCA",
                product_class="AP1300",
                serial=serial,
                manufacturer="Cudy",
                leaves={
                    "Device.ManagementServer.ConnectionRequestURL": {
                        "value": "http://10.0.0.1:7547/",
                        "writable": False,
                    },
                    "Device.ManagementServer.PeriodicInformInterval": 300,
                    "Device.DeviceInfo.ModelName": {"value": "AP1300", "writable": False},
                    "Device.DeviceInfo.SoftwareVersion": {"value": "2.5.25", "writable": False},
                },
                last_inform=nbi.now(),
            )
            doc["_lastBoot"] = iso(nbi.now() - timedelta(hours=3))
            ids.append(nbi.add_device(doc))
        return svc, log, ids

    def test_a_plan_does_not_restart_a_router_installing_another_upgrade(self, tmp_path: Path):
        from fake_nbi import FakeNbi

        with FakeNbi() as nbi:
            svc, log, (device,) = self.acs_fleet(nbi, tmp_path, "000001")
            first = svc.add_firmware(b"IMAGE" * 100, "a.bin", None, NEWER, "80AFCA", "AP1300")
            second = svc.add_firmware(b"OTHER" * 100, "b.bin", None, "2.5.27-20261101-101010", "80AFCA", "AP1300")
            # Someone started an upgrade from the dashboard; the plan names another file.
            svc.firmware_upgrade(device, first["name"], actor="alice")
            store = MaintenanceStore(tmp_path)
            runner = MaintenanceRunner(FakeManager(), svc, store, log, clock=nbi.now, max_workers=1)
            plan = store.create(
                plan_data(
                    name="Firmware",
                    targets={"acs_devices": [device]},
                    actions=["firmware_update", "reboot"],
                    firmware={"AP1300": second["name"]},
                )
            )

            (result,) = runner.run_now(plan["id"], "bob")

            assert result["status"] == "skipped"
            assert result["reason"].startswith("a firmware upgrade is under way on this router")
            assert [task["name"] for task in nbi.tasks] == ["download"]

    def test_a_client_limit_holds_back_a_router_whose_clients_the_acs_does_not_know(self, tmp_path: Path):
        from fake_nbi import FakeNbi

        with FakeNbi() as nbi:
            # No Hosts or Wi-Fi leaves: GenieACS has nothing cached to count.
            svc, log, (device,) = self.acs_fleet(nbi, tmp_path, "000001")
            assert svc.device_detail(device)["device"]["clients"] == []
            store = MaintenanceStore(tmp_path)
            runner = MaintenanceRunner(FakeManager(), svc, store, log, clock=nbi.now, max_workers=1)
            plan = store.create(
                plan_data(name="Reboot", targets={"acs_devices": [device]}, guards={"skip_if_clients_over": 0})
            )

            (result,) = runner.run_now(plan["id"], "bob")

            assert result["status"] == "skipped" and "client limit cannot be checked" in result["reason"]
            assert nbi.tasks == []

    def test_a_tr069_reboot_queued_in_a_window_expires_as_it_closes(self, tmp_path: Path):
        from fake_nbi import FakeNbi, parse_iso

        with FakeNbi() as nbi:
            svc, log, (device,) = self.acs_fleet(nbi, tmp_path, "000001")
            now = nbi.now().astimezone(UTC)
            opens = now - timedelta(minutes=5)
            store = MaintenanceStore(tmp_path)
            runner = MaintenanceRunner(FakeManager(), svc, store, log, clock=nbi.now, max_workers=1)
            schedule = {
                "days": [maintenance.DAYS[opens.weekday()]],
                "start": opens.strftime("%H:%M"),
                "duration_minutes": 30,
                "timezone": "UTC",
            }
            store.create(plan_data(name="Reboot", targets={"acs_devices": [device]}, schedule=schedule))

            (result,) = runner.run_once()

            assert result["status"] == "queued"
            (task,) = nbi.tasks
            closes = opens.replace(second=0, microsecond=0) + timedelta(minutes=30)
            assert abs((parse_iso(task["expiry"]) - closes).total_seconds()) <= 2
