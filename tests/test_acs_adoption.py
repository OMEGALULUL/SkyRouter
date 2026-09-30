"""Adopting a TR-069 router with its Vexar customer, and the library's activity entries.

The adopt dialog links each new router to a customer. GenieACS has nowhere to keep
one, so AcsService stores it in data_dir/acs_adoptions.json and puts it on every
router summary, which is what the list's Customer column and search show.
"""

import json
import stat
from pathlib import Path
from typing import Any
from urllib.parse import quote

import pytest
from fake_nbi import FakeNbi, build_device
from test_web_acs import make_app, signed_in

from cudy_manager.acs.client import AcsBusy, AcsClient, AcsNotFound, AcsUnavailable
from cudy_manager.acs.jobs import ADOPTIONS_FILE, JobStoreError
from cudy_manager.acs.service import CUSTOMER_MAX, AcsService, validate_customer
from cudy_manager.activity import ActivityLog
from cudy_manager.models import ValidationError
from cudy_manager.secrets import SecretStore
from cudy_manager.web import DASHBOARD_ACTOR

NEW = "skybre_new"
CUSTOMER = "#1080 Customer E"
FIRMWARE = b"\x27\x05\x19\x56" + bytes(range(256)) * 4


class Recorder:
    """Stands in for cudy_manager.activity.ActivityLog."""

    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    def record(self, **entry: Any) -> dict[str, Any]:
        self.entries.append(entry)
        return entry


@pytest.fixture
def nbi():
    with FakeNbi() as fake:
        yield fake


@pytest.fixture
def recorder():
    return Recorder()


@pytest.fixture
def svc(nbi, tmp_path, recorder):
    return AcsService(AcsClient(nbi.url, timeout=5), SecretStore(tmp_path), tmp_path, clock=nbi.now, activity=recorder)


def new_router(nbi: FakeNbi, serial: str = "000001", tags: tuple[str, ...] = (NEW,)) -> str:
    leaves = {
        "Device.ManagementServer.ConnectionRequestURL": {"value": "http://10.10.0.40:7547/", "writable": False},
        "Device.ManagementServer.PeriodicInformInterval": 300,
        "Device.DeviceInfo.Manufacturer": {"value": "Cudy", "writable": False},
        "Device.DeviceInfo.ModelName": {"value": "WR3000", "writable": False},
    }
    return nbi.add_device(build_device(serial=serial, leaves=leaves, tags=tags, last_inform=nbi.now()))


def listed(svc: AcsService) -> dict[str, Any]:
    return {device["acs_id"]: device for device in svc.list_devices()["devices"]}


def stored(tmp_path: Path) -> dict[str, Any]:
    return json.loads((tmp_path / ADOPTIONS_FILE).read_text())["routers"]


# --- the customer ------------------------------------------------------------------------


class TestValidateCustomer:
    def test_it_is_trimmed_and_optional(self):
        assert validate_customer(f"  {CUSTOMER}  ") == CUSTOMER
        assert validate_customer(None) is None

    def test_up_to_120_characters(self):
        assert CUSTOMER_MAX == 120
        assert validate_customer("x" * 120) == "x" * 120
        with pytest.raises(ValidationError, match="at most 120 characters"):
            validate_customer("x" * 121)

    @pytest.mark.parametrize("blank", ["", "   ", "\t"])
    def test_a_blank_customer_is_refused(self, blank):
        with pytest.raises(ValidationError, match="Enter the Vexar customer"):
            validate_customer(blank)

    @pytest.mark.parametrize(
        "text", ["#1080\tCustomer", "#1080\nCustomer", "#1080\x07", "#1080\x85x", "#1080 x", "‮0801#"]
    )
    def test_control_characters_are_refused_not_folded_away(self, text):
        with pytest.raises(ValidationError, match="control characters"):
            validate_customer(text)

    @pytest.mark.parametrize("value", [1080, ["#1080"], {"customer": "#1080"}, True])
    def test_anything_but_text_is_refused(self, value):
        with pytest.raises(ValidationError, match="customer must be text"):
            validate_customer(value)


# --- adopting ----------------------------------------------------------------------------


class TestAdopt:
    def test_the_customer_is_stored_and_shown_on_the_summary_and_the_detail(self, nbi, svc, tmp_path):
        router = new_router(nbi)
        other = new_router(nbi, "000002", tags=())
        result = svc.adopt(router, f"  {CUSTOMER} ", actor="alice")
        assert result == {"acs_id": router, "tags": [], "customer": CUSTOMER}
        assert nbi.devices[router]["_tags"] == []
        devices = listed(svc)
        assert devices[router]["customer"] == CUSTOMER
        assert devices[other]["customer"] is None, "a router nobody adopted has no customer"
        assert svc.device_detail(router)["device"]["customer"] == CUSTOMER
        record = stored(tmp_path)[router]
        assert record["customer"] == CUSTOMER and record["adopted_by"] == "alice" and record["adopted_at"]

    def test_the_file_is_private(self, nbi, svc, tmp_path):
        svc.adopt(new_router(nbi), CUSTOMER)
        assert stat.S_IMODE((tmp_path / ADOPTIONS_FILE).stat().st_mode) == 0o600

    def test_the_adoption_is_logged_as_setup_under_the_routers_sticker_name(self, nbi, svc, recorder):
        router = new_router(nbi, "AB1")
        svc.adopt(router, CUSTOMER, actor="alice")
        assert recorder.entries == [{
            "who": "alice",
            "router": f"acs:{router}",
            "router_name": "WR3000 · AB1",
            "kind": "setup",
            "what": f"Adopted: linked to {CUSTOMER}",
            "result": "applied",
            "details": {"customer": CUSTOMER},
        }]

    def test_adopting_without_a_customer_keeps_the_one_already_linked(self, nbi, svc, recorder, tmp_path):
        router = new_router(nbi)
        svc.adopt(router, CUSTOMER)
        nbi.devices[router]["_tags"] = [NEW]
        assert svc.adopt(router)["customer"] == CUSTOMER
        assert stored(tmp_path)[router]["customer"] == CUSTOMER
        assert recorder.entries[-1]["what"] == "Adopted from the new routers list"
        assert recorder.entries[-1]["details"] is None

    def test_adopting_again_replaces_the_customer(self, nbi, svc):
        router = new_router(nbi)
        svc.adopt(router, CUSTOMER)
        svc.adopt(router, "#1090 Customer F")
        assert listed(svc)[router]["customer"] == "#1090 Customer F"

    @pytest.mark.parametrize("customer", ["", "x" * 121, "a\tb", 1080])
    def test_a_bad_customer_is_refused_before_anything_is_asked_or_stored(self, nbi, svc, recorder, tmp_path, customer):
        router = new_router(nbi)
        before = len(nbi.requests)
        with pytest.raises(ValidationError):
            svc.adopt(router, customer)
        assert len(nbi.requests) == before
        assert not (tmp_path / ADOPTIONS_FILE).exists() and recorder.entries == []

    def test_an_unknown_router_is_not_found_and_nothing_is_stored(self, nbi, svc, recorder, tmp_path):
        new_router(nbi)
        ghost = "202BC1-BM632w-GHOST"
        with pytest.raises(AcsNotFound):
            svc.adopt(ghost, CUSTOMER)
        assert not (tmp_path / ADOPTIONS_FILE).exists() and recorder.entries == []

    def test_a_refused_adoption_puts_the_earlier_customer_back(self, nbi, svc, recorder, monkeypatch):
        router = new_router(nbi)
        svc.adopt(router, CUSTOMER)
        nbi.devices[router]["_tags"] = [NEW]
        logged = len(recorder.entries)

        def refuse(*_: Any) -> None:
            raise AcsBusy("the router is mid-session; try again")

        monkeypatch.setattr(svc.client, "remove_tag", refuse)
        with pytest.raises(AcsBusy):
            svc.adopt(router, "#1090 Customer F")
        assert listed(svc)[router]["customer"] == CUSTOMER
        assert len(recorder.entries) == logged, "nothing was adopted, so nothing is logged"

    def test_a_first_adoption_that_is_refused_leaves_no_customer(self, nbi, svc, tmp_path, monkeypatch):
        router = new_router(nbi)

        def refuse(*_: Any) -> None:
            raise AcsBusy("the router is mid-session; try again")

        monkeypatch.setattr(svc.client, "remove_tag", refuse)
        with pytest.raises(AcsBusy):
            svc.adopt(router, CUSTOMER)
        assert router not in stored(tmp_path)

    def test_a_lost_reply_keeps_the_customer_since_the_tag_may_be_gone(self, nbi, svc, monkeypatch):
        router = new_router(nbi)

        def lost(*_: Any) -> None:
            nbi.devices[router]["_tags"] = []
            raise AcsUnavailable("the reply was lost", outcome_unknown=True)

        monkeypatch.setattr(svc.client, "remove_tag", lost)
        with pytest.raises(AcsUnavailable):
            svc.adopt(router, CUSTOMER)
        assert listed(svc)[router]["customer"] == CUSTOMER

    def test_once_the_tag_is_gone_a_failed_read_back_still_logs_the_adoption(self, nbi, svc, recorder, monkeypatch):
        router = new_router(nbi)

        def unreadable(_: str) -> list[str]:
            raise AcsUnavailable("ACS unavailable (GET /devices): refused")

        monkeypatch.setattr(svc, "_tags", unreadable)
        with pytest.raises(AcsUnavailable):
            svc.adopt(router, CUSTOMER)
        assert nbi.devices[router]["_tags"] == []
        assert listed(svc)[router]["customer"] == CUSTOMER
        assert [entry["what"] for entry in recorder.entries] == [f"Adopted: linked to {CUSTOMER}"]

    def test_a_broken_activity_log_does_not_undo_an_adoption(self, nbi, tmp_path):
        class Broken:
            def record(self, **_: Any) -> None:
                raise RuntimeError("disk full")

        service = AcsService(AcsClient(nbi.url, timeout=5), SecretStore(tmp_path), tmp_path, clock=nbi.now,
                             activity=Broken())
        router = new_router(nbi)
        assert service.adopt(router, CUSTOMER)["customer"] == CUSTOMER
        assert nbi.devices[router]["_tags"] == []


class TestDamagedAdoptionFile:
    @pytest.fixture
    def damaged(self, tmp_path):
        (tmp_path / ADOPTIONS_FILE).write_text("{not json")

    def test_the_fleet_still_lists_without_customers(self, nbi, svc, damaged):
        router = new_router(nbi, tags=())
        assert listed(svc)[router]["customer"] is None
        assert svc.device_detail(router)["device"]["customer"] is None

    def test_health_says_so(self, nbi, svc, damaged):
        [problem] = [text for text in svc.health()["problems"] if "adoption" in text]
        assert "is corrupt" in problem and "adopting is refused" in problem

    def test_adopting_is_refused_and_the_router_stays_new(self, nbi, svc, damaged, tmp_path):
        router = new_router(nbi)
        with pytest.raises(JobStoreError):
            svc.adopt(router, CUSTOMER)
        assert nbi.devices[router]["_tags"] == [NEW]
        assert (tmp_path / ADOPTIONS_FILE).read_text() == "{not json", "the only copy is never replaced"


# --- the firmware library's entries --------------------------------------------------------


def upload(service: AcsService, **extra: Any) -> dict[str, Any]:
    return service.add_firmware(FIRMWARE, "WR3000-2.4.2.bin", "Cudy WR3000", "2.4.2", "80AFCA", "WR3000", **extra)


class TestLibraryActivity:
    def test_adding_and_removing_a_file_are_logged_under_the_library(self, svc, recorder):
        record = upload(svc, actor="alice")
        svc.remove_firmware(record["name"], actor="bob")
        added, removed = recorder.entries
        assert added["who"] == "alice" and removed["who"] == "bob"
        assert added["router"] == removed["router"] == f"library:{record['name']}"
        assert added["router_name"] == "Firmware library" and added["kind"] == removed["kind"] == "firmware"
        assert added["what"] == "Added Cudy WR3000 2.4.2 to the library"
        assert removed["what"] == "Removed Cudy WR3000 2.4.2 from the library"
        assert added["details"] == {"file": record["name"], "version": "2.4.2", "oui": "80AFCA",
                                    "product_class": "WR3000", "size": len(FIRMWARE)}

    def test_the_cli_and_the_scheduler_are_named_system_by_default(self, svc, recorder):
        upload(svc)
        assert recorder.entries[0]["who"] == "system"

    def test_a_refused_upload_logs_nothing(self, svc, recorder):
        with pytest.raises(ValidationError):
            svc.add_firmware(b"", "x.bin", None, "2.4.2", "80AFCA", "WR3000", actor="alice")
        assert recorder.entries == []

    def test_the_real_log_never_holds_the_image(self, nbi, tmp_path):
        log = ActivityLog(tmp_path / "activity")
        service = AcsService(AcsClient(nbi.url, timeout=5), SecretStore(tmp_path), tmp_path, clock=nbi.now,
                             activity=log)
        upload(service, actor="alice")
        [entry] = log.list(kind="firmware")
        assert entry["router_name"] == "Firmware library"
        assert FIRMWARE.hex() not in log.path.read_text()


# --- the routes ----------------------------------------------------------------------------


def web_service(nbi: FakeNbi, tmp_path: Path) -> AcsService:
    """The service on the app's data dir and activity log, as build_acs_service makes it."""
    data = tmp_path / "data"
    return AcsService(AcsClient(nbi.url, timeout=5), SecretStore(data), data, clock=nbi.now,
                      activity=ActivityLog(data))


class TestRoutes:
    def test_adopt_takes_the_customer_and_the_list_and_log_show_it(self, tmp_path, nbi):
        router = new_router(nbi)
        client, headers = signed_in(make_app(tmp_path, nbi, acs_service=web_service(nbi, tmp_path)))
        response = client.post(f"/api/acs/devices/{quote(router, safe='')}/adopt",
                               json={"customer": f" {CUSTOMER} "}, headers=headers)
        assert response.status_code == 200, response.text
        assert response.json() == {"acs_id": router, "tags": [], "customer": CUSTOMER}
        [summary] = client.get("/api/acs/devices").json()["devices"]
        assert summary["customer"] == CUSTOMER
        [entry] = client.get("/api/activity?kind=setup").json()["entries"]
        assert entry["who"] == DASHBOARD_ACTOR and entry["what"] == f"Adopted: linked to {CUSTOMER}"
        assert entry["router"] == f"acs:{router}"

    def test_adopt_still_works_without_a_body(self, tmp_path, nbi):
        router = new_router(nbi)
        client, headers = signed_in(make_app(tmp_path, nbi))
        response = client.post(f"/api/acs/devices/{quote(router, safe='')}/adopt", headers=headers)
        assert response.status_code == 200 and response.json()["customer"] is None

    @pytest.mark.parametrize(
        ("body", "detail"),
        [
            ({"customer": "   "}, "Enter the Vexar customer."),
            ({"customer": "x" * 121}, "customer must be at most 120 characters"),
            ({"customer": "#1080\nCustomer"}, "customer must not contain control characters"),
            ({"customer": 1080}, "customer must be text"),
            ({"customer": CUSTOMER, "name": "x"}, "unexpected field(s): name"),
        ],
    )
    def test_a_bad_body_is_400_and_the_router_stays_new(self, tmp_path, nbi, body, detail):
        router = new_router(nbi)
        client, headers = signed_in(make_app(tmp_path, nbi))
        response = client.post(f"/api/acs/devices/{quote(router, safe='')}/adopt", json=body, headers=headers)
        assert response.status_code == 400, response.text
        assert response.json()["detail"] == detail
        assert nbi.devices[router]["_tags"] == [NEW]
        assert not (tmp_path / "data" / ADOPTIONS_FILE).exists()

    def test_library_changes_are_logged_as_the_signed_in_person(self, tmp_path, nbi):
        client, headers = signed_in(make_app(tmp_path, nbi, acs_service=web_service(nbi, tmp_path)))
        query = "version=2.4.2&oui=80AFCA&product_class=WR3000&filename=WR3000.bin&model_hint=Cudy%20WR3000"
        added = client.post(f"/api/acs/firmware?{query}", content=FIRMWARE,
                            headers={**headers, "Content-Type": "application/octet-stream"})
        assert added.status_code == 201, added.text
        name = added.json()["firmware"]["name"]
        assert client.delete(f"/api/acs/firmware/{name}", headers=headers).status_code == 200
        entries = client.get("/api/activity?kind=firmware").json()["entries"]
        assert [(entry["who"], entry["what"]) for entry in entries] == [
            (DASHBOARD_ACTOR, "Removed Cudy WR3000 2.4.2 from the library"),
            (DASHBOARD_ACTOR, "Added Cudy WR3000 2.4.2 to the library"),
        ]
