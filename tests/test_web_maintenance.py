"""The web routes for the activity log, router firmware and maintenance plans.

Direct routers run against fake_router's reconstructed AP1300 (and a TP-Link or
OpenWrt device that must never be contacted), TR-069 routers against the fake NBI.
Every app gets a real ActivityLog, so an entry built wrongly would be refused and
show up as a missing one.
"""

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote

import pytest
from fake_nbi import FakeNbi
from fake_router import FakeRouter, ap1300_autoupgrade_page
from fastapi.testclient import TestClient
from test_acs_firmware import CONTENT, NEW, OLD, OUI, PRODUCT, cudy

from cudy_manager import adapters, web
from cudy_manager.acs.client import AcsClient
from cudy_manager.acs.service import AcsService
from cudy_manager.activity import ActivityLog
from cudy_manager.maintenance import MaintenanceBusy, MaintenanceRunner
from cudy_manager.manager import DeviceManager
from cudy_manager.openwrt import OpenWrtAdapter
from cudy_manager.scheduler import RebootScheduler
from cudy_manager.secrets import SecretStore
from cudy_manager.web import DASHBOARD_ACTOR, Settings, create_app

PASSWORD = "correct horse battery staple"
ROUTER_PASSWORD = "goodpass"  # what fake_router's AP1300 accepts for admin
WIFI_PASS = "brand-new-wifi-pass-42"
CURRENT = "2.5.25-20260820-141832"
NEWER = "2.5.26-20261001-101010"
PLAN_ID = "0123456789ab"
FIRMWARE_NAME = "skybre-fw-0123456789abcdef0123456789abcdef"
UPLOAD = f"/api/acs/firmware?version={NEW}&oui={OUI}&product_class={PRODUCT}&filename=AP1300-2.5.26.bin"
OCTETS = {"Content-Type": "application/octet-stream"}


def plan_body(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "name": "Weekly check",
        "targets": {"devices": ["r1"]},
        "schedule": {"days": ["tue"], "start": "03:00", "duration_minutes": 60, "timezone": "UTC"},
        "actions": ["firmware_check"],
        "guards": {"min_uptime_seconds": 0},
    }
    body.update(overrides)
    return body


# Every route this file is about, with a body it would accept, so none can miss the
# session and CSRF checks. test_every_route_is_listed_here keeps it in step with the app.
READS = [
    "/api/activity",
    "/api/activity.csv",
    "/api/devices/r1/firmware",
    "/api/maintenance/plans",
    f"/api/maintenance/plans/{PLAN_ID}",
    "/api/maintenance/runs",
]
WRITES: list[tuple[str, str, dict[str, Any] | None]] = [
    ("PUT", "/api/devices/r1/firmware/auto-update", {"enabled": True, "window_start_hour": 3}),
    ("POST", "/api/devices/r1/firmware/check", None),
    ("POST", "/api/maintenance/plans", plan_body()),
    ("PUT", f"/api/maintenance/plans/{PLAN_ID}", {"enabled": False}),
    ("DELETE", f"/api/maintenance/plans/{PLAN_ID}", None),
    ("POST", f"/api/maintenance/plans/{PLAN_ID}/run", {"confirm": True}),
]
TEMPLATES = {
    ("GET", "/api/activity"),
    ("GET", "/api/activity.csv"),
    ("GET", "/api/devices/{identifier}/firmware"),
    ("PUT", "/api/devices/{identifier}/firmware/auto-update"),
    ("POST", "/api/devices/{identifier}/firmware/check"),
    ("GET", "/api/maintenance/plans"),
    ("POST", "/api/maintenance/plans"),
    ("GET", "/api/maintenance/plans/{plan_id}"),
    ("PUT", "/api/maintenance/plans/{plan_id}"),
    ("DELETE", "/api/maintenance/plans/{plan_id}"),
    ("POST", "/api/maintenance/plans/{plan_id}/run"),
    ("GET", "/api/maintenance/runs"),
}


@pytest.fixture
def nbi():
    with FakeNbi() as fake:
        yield fake


@pytest.fixture
def router():
    with FakeRouter("ap1300") as fake:
        yield fake


@pytest.fixture(autouse=True)
def fast_polls(monkeypatch):
    monkeypatch.setattr(adapters, "_CUDY_CHECK_POLL", 0.01)


def make_app(tmp_path: Path, nbi: FakeNbi | None = None, *, acs_service: Any = None, **overrides: Any):
    data = tmp_path / "data"
    store = SecretStore(data)
    log = ActivityLog(data)
    manager = DeviceManager(config_path=tmp_path / "devices.yaml", data_dir=data, secret_store=store, activity=log)
    values: dict[str, Any] = {"scheduler_interval": 3600, **overrides}
    settings = Settings(
        username="admin",
        password=PASSWORD,
        secure_cookie=False,
        config_path=tmp_path / "devices.yaml",
        data_dir=data,
        **values,
    )
    if acs_service is None and nbi is not None:
        acs_service = AcsService(AcsClient(nbi.url, timeout=5), store, data, clock=nbi.now, activity=log)
    return create_app(manager=manager, settings=settings, acs_service=acs_service, activity=log)


def log_in(client: TestClient) -> dict[str, str]:
    response = client.post("/login", json={"username": "admin", "password": PASSWORD})
    assert response.status_code == 200, response.text
    return {"X-CSRF-Token": response.json()["csrf_token"]}


def signed_in(app) -> tuple[TestClient, dict[str, str]]:
    client = TestClient(app)
    return client, log_in(client)


def add_cudy(app, router: FakeRouter | None = None, identifier: str = "r1", **values: Any) -> None:
    """Straight into the manager: logged as "system", never as the dashboard."""
    port = router.port if router is not None else 80
    host = "127.0.0.1" if router is not None else "192.0.2.1"
    app.state.manager.add_device(
        identifier, host, values.pop("vendor", "cudy"), password=ROUTER_PASSWORD, http_port=port, **values
    )


def entries(app, **filters: Any) -> list[dict[str, Any]]:
    return app.state.activity.list(**filters)


def send(client: TestClient, method: str, path: str, body: dict[str, Any] | None = None, **kwargs: Any):
    if body is None:
        return client.request(method, path, **kwargs)
    return client.request(method, path, json=body, **kwargs)


class StubAcs:
    """Answers every AcsService call with ``result`` and records its arguments, keywords included."""

    def __init__(self, result: Any = None):
        self.result = result
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []

    def __getattr__(self, name: str):
        def method(*args: Any, **kwargs: Any) -> Any:
            self.calls.append((name, args, kwargs))
            return self.result

        return method


# --- wiring --------------------------------------------------------------------------------------


class TestWiring:
    def test_every_route_is_listed_here(self, tmp_path: Path):
        app = make_app(tmp_path)
        registered = {
            (method, route.path)
            for route in app.routes
            if getattr(route, "path", "").startswith(("/api/activity", "/api/maintenance"))
            or "/firmware" in getattr(route, "path", "")
            and getattr(route, "path", "").startswith("/api/devices")
            for method in getattr(route, "methods", ())
        }
        assert registered == TEMPLATES
        assert len(READS) + len(WRITES) == len(TEMPLATES)

    def test_every_route_needs_a_session(self, tmp_path: Path, router):
        app = make_app(tmp_path)
        add_cudy(app, router)
        client = TestClient(app)
        for method, path, body in [("GET", path, None) for path in READS] + WRITES:
            response = send(client, method, path, body)
            assert response.status_code == 401, (method, path, response.text)
        assert router.state["login_posts"] == 0

    def test_every_change_needs_the_csrf_token(self, tmp_path: Path, router):
        app = make_app(tmp_path)
        add_cudy(app, router)
        client, _ = signed_in(app)
        for token in (None, "wrong"):
            headers = {"X-CSRF-Token": token} if token else {}
            for method, path, body in WRITES:
                response = send(client, method, path, body, headers=headers)
                assert response.status_code == 403, (method, path, response.text)
        assert router.state["login_posts"] == 0
        assert app.state.maintenance.store.list() == []

    def test_create_app_builds_one_log_for_the_manager_the_acs_and_the_plans(self, tmp_path: Path, nbi):
        data = tmp_path / "data"
        settings = Settings(
            username="admin",
            password=PASSWORD,
            secure_cookie=False,
            scheduler_interval=3600,
            config_path=tmp_path / "devices.yaml",
            data_dir=data,
            acs_url=nbi.url,
        )
        app = create_app(settings=settings)
        log = app.state.activity
        assert isinstance(log, ActivityLog) and log.path == data / "activity.jsonl"
        assert app.state.manager.activity is log
        assert app.state.acs.activity is log
        runner = app.state.maintenance
        assert isinstance(runner, MaintenanceRunner)
        assert runner.activity is log and runner.acs is app.state.acs
        assert runner.state_path == data / "maintenance_state.json"
        # The scheduler hands the runner its reboot history, so each starts the other's cooldown.
        assert isinstance(app.state.scheduler, RebootScheduler)
        assert app.state.scheduler.maintenance is runner
        assert runner.reboot_history == app.state.scheduler.last_reboot

    def test_an_injected_log_is_the_one_the_routes_read(self, tmp_path: Path):
        log = ActivityLog(tmp_path / "elsewhere")
        app = create_app(
            manager=DeviceManager(config_path=tmp_path / "devices.yaml", data_dir=tmp_path / "data"),
            settings=Settings("admin", PASSWORD, False, 3600, tmp_path / "devices.yaml", tmp_path / "data"),
            activity=log,
        )
        assert app.state.activity is log and app.state.maintenance.activity is log
        log.record(who="x", router="r9", kind="setup", what="injected", result="info")
        client, _ = signed_in(app)
        assert [entry["what"] for entry in client.get("/api/activity").json()["entries"]] == ["injected"]


# --- who made the change ---------------------------------------------------------------------------


class TestActor:
    def test_session_actor_names_the_dashboard(self, tmp_path: Path):
        class Stub:
            class state:  # noqa: N801 - stands in for Request.state
                session = {"csrf": "x"}

        assert web.session_actor(Stub()) == DASHBOARD_ACTOR == "Skybre staff"

    def test_session_actor_refuses_a_request_without_a_session(self):
        class Stub:
            class state:  # noqa: N801
                pass

        with pytest.raises(web.HTTPException) as refused:
            web.session_actor(Stub())
        assert refused.value.status_code == 401

    def test_dashboard_changes_are_logged_as_the_session(self, tmp_path: Path):
        app = make_app(tmp_path)
        client, headers = signed_in(app)
        added = client.post(
            "/api/devices", json={"id": "r1", "host": "192.0.2.1", "vendor": "cudy", "password": "p"}, headers=headers
        )
        assert added.status_code == 200, added.text
        assert client.put("/api/devices/r1", json={"model": "AP1300"}, headers=headers).status_code == 200
        assert client.delete("/api/devices/r1", headers=headers).status_code == 200
        logged = entries(app)
        assert [entry["what"].split(" ")[0] for entry in logged] == ["Removed", "Settings", "Added"]
        assert {entry["who"] for entry in logged} == {DASHBOARD_ACTOR}

    @pytest.mark.parametrize("actor", ["mallory", "", None])
    def test_a_client_cannot_choose_the_actor(self, tmp_path: Path, actor):
        app = make_app(tmp_path)
        add_cudy(app)
        before = entries(app)
        client, headers = signed_in(app)
        response = client.put("/api/devices/r1", json={"model": "X", "actor": actor}, headers=headers)
        assert response.status_code == 400, response.text
        assert "actor" in response.json()["detail"]
        assert app.state.manager.get_device("r1").model == ""
        assert entries(app) == before

    def test_router_actions_pass_the_session_actor(self, tmp_path: Path, monkeypatch):
        app = make_app(tmp_path)
        add_cudy(app)
        seen: list[tuple[str, dict[str, Any]]] = []

        def recorder(name: str, result: Any):
            def fake(*args: Any, **kwargs: Any) -> Any:
                seen.append((name, kwargs))
                return result

            return fake

        manager = app.state.manager
        for name, result in (
            ("reboot_device", True),
            ("set_wifi_ssid", True),
            ("set_wifi_password", True),
            ("set_password", {"device": "r1", "password_updated": True}),
        ):
            monkeypatch.setattr(manager, name, recorder(name, result))
        client, headers = signed_in(app)
        assert client.post("/api/devices/r1/reboot", json={"confirm": True}, headers=headers).status_code == 200
        assert client.post("/api/devices/r1/ssid", json={"ssid": "Home"}, headers=headers).status_code == 200
        response = client.post(
            "/api/devices/r1/wifi-password", json={"password": WIFI_PASS, "confirm": True}, headers=headers
        )
        assert response.status_code == 200, response.text
        response = client.post("/api/devices/r1/password", json={"password": "new-admin-pass"}, headers=headers)
        assert response.status_code == 200, response.text
        assert [(name, kwargs.get("actor")) for name, kwargs in seen] == [
            ("reboot_device", DASHBOARD_ACTOR),
            ("set_wifi_ssid", DASHBOARD_ACTOR),
            ("set_wifi_password", DASHBOARD_ACTOR),
            ("set_password", DASHBOARD_ACTOR),
        ]

    def test_acs_changes_pass_the_session_actor(self, tmp_path: Path):
        stub = StubAcs(result={"id": "0123456789abcdef", "state": "queued"})
        app = make_app(tmp_path, acs_service=stub)
        client, headers = signed_in(app)
        device = quote("80AFCA-AP1300-000001", safe="")
        rebooted = client.post(f"/api/acs/devices/{device}/reboot", json={"confirm": True}, headers=headers)
        assert rebooted.status_code == 202, rebooted.text
        wifi = client.post(f"/api/acs/devices/{device}/wifi", json={"band": "all", "ssid": "Home"}, headers=headers)
        assert wifi.status_code == 202, wifi.text
        assert client.delete("/api/acs/jobs/0123456789abcdef", headers=headers).status_code == 200
        upgrade = client.post(
            f"/api/acs/devices/{device}/firmware", json={"firmware": FIRMWARE_NAME, "confirm": True}, headers=headers
        )
        assert upgrade.status_code == 202, upgrade.text
        actors = {name: kwargs.get("actor") for name, _, kwargs in stub.calls}
        assert actors == {
            "reboot": DASHBOARD_ACTOR,
            "set_wifi": DASHBOARD_ACTOR,
            "cancel_job": DASHBOARD_ACTOR,
            "firmware_upgrade": DASHBOARD_ACTOR,
        }

    def test_a_wifi_password_change_reaches_the_log_without_the_password(self, tmp_path: Path, router, caplog):
        caplog.set_level(logging.DEBUG)
        app = make_app(tmp_path)
        add_cudy(app, router)
        client, headers = signed_in(app)
        response = client.post(
            "/api/devices/r1/wifi-password", json={"password": WIFI_PASS, "confirm": True}, headers=headers
        )
        assert response.status_code == 200, response.text
        assert router.state["wifi"]["wlan00"]["key"] == WIFI_PASS
        [entry] = entries(app, kind="wifi")
        assert entry["who"] == DASHBOARD_ACTOR and entry["result"] == "applied"
        listed = client.get("/api/activity").text
        exported = client.get("/api/activity.csv").text
        for text in (listed, exported, app.state.activity.path.read_text(), caplog.text):
            assert WIFI_PASS not in text and ROUTER_PASSWORD not in text


# --- the activity log ------------------------------------------------------------------------------


class TestActivityRoutes:
    def _fill(self, app) -> list[dict[str, Any]]:
        log = app.state.activity
        made = [
            log.record(who="alice", router="r1", kind="wifi", what="Wi-Fi name changed", result="applied"),
            log.record(who="bob", router="r2", kind="reboot", what="Reboot started", result="applied"),
            log.record(who="alice", router="acs:80AFCA-AP1300-000001", kind="firmware", what="=cmd", result="queued"),
            log.record(who="bob", router="r1", kind="reboot", what="Reboot started", result="failed"),
        ]
        return list(reversed(made))

    def test_the_list_is_newest_first_and_filters(self, tmp_path: Path):
        app = make_app(tmp_path)
        newest = self._fill(app)
        client, _ = signed_in(app)
        body = client.get("/api/activity").json()
        assert body["entries"] == newest and body["next_before"] is None
        assert client.get("/api/activity?router=r1").json()["entries"] == [newest[0], newest[3]]
        assert client.get("/api/activity?who=alice").json()["entries"] == [newest[1], newest[3]]
        assert client.get("/api/activity?kind=reboot").json()["entries"] == [newest[0], newest[2]]
        tr069 = client.get(f"/api/activity?router={quote('acs:80AFCA-AP1300-000001')}").json()["entries"]
        assert tr069 == [newest[1]]
        # Empty filters mean no filter, as a form with blank fields sends them.
        assert client.get("/api/activity?router=&who=&kind=&before=").json()["entries"] == newest

    def test_pages_follow_next_before(self, tmp_path: Path):
        app = make_app(tmp_path)
        newest = self._fill(app)
        client, _ = signed_in(app)
        first = client.get("/api/activity?limit=3").json()
        assert first["entries"] == newest[:3] and first["next_before"] == newest[2]["id"]
        second = client.get(f"/api/activity?limit=3&before={first['next_before']}").json()
        assert second["entries"] == newest[3:] and second["next_before"] is None

    @pytest.mark.parametrize(
        "query",
        [
            "kind=nonsense",
            "limit=0",
            "limit=1001",
            "limit=ten",
            "limit=-1",
            "before=yesterday",
            f"router={'r' * 201}",
        ],
    )
    def test_bad_filters_are_400(self, tmp_path: Path, query):
        client, _ = signed_in(make_app(tmp_path))
        response = client.get(f"/api/activity?{query}")
        assert response.status_code == 400, response.text
        assert client.get(f"/api/activity.csv?{query}").status_code == (
            200 if query.startswith("limit=1001") else 400
        )

    def test_a_missing_log_is_empty_and_creates_nothing(self, tmp_path: Path):
        app = make_app(tmp_path)
        client, _ = signed_in(app)
        assert client.get("/api/activity").json() == {"entries": [], "next_before": None}
        assert not app.state.activity.path.exists()

    def test_the_csv_is_an_attachment_with_every_entry_and_no_formulas(self, tmp_path: Path):
        app = make_app(tmp_path)
        newest = self._fill(app)
        client, _ = signed_in(app)
        response = client.get("/api/activity.csv")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/csv")
        disposition = response.headers["content-disposition"]
        assert disposition.startswith("attachment;") and 'filename="skyrouter-activity-' in disposition
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        lines = response.text.split("\r\n")
        assert lines[0] == "at,who,router,router_name,kind,result,what,details,id"
        assert len([line for line in lines[1:] if line]) == len(newest)
        # A cell a spreadsheet would run as a formula is quoted.
        assert ",'=cmd," in response.text
        limited = client.get("/api/activity.csv?limit=1&kind=reboot").text.split("\r\n")
        assert len([line for line in limited[1:] if line]) == 1 and newest[0]["id"] in limited[1]


# --- firmware on a directly managed router ---------------------------------------------------------


class TestDirectFirmware:
    def test_status_reads_the_auto_update_page(self, tmp_path: Path, router):
        app = make_app(tmp_path)
        add_cudy(app, router)
        client, _ = signed_in(app)
        response = client.get("/api/devices/r1/firmware")
        assert response.status_code == 200, response.text
        assert response.json() == {
            "device": "r1",
            "firmware": {
                "version": CURRENT,
                "hardware": "AP1300 V1.1",
                "auto_update": {"enabled": True, "window_start_hour": 3, "window": "03:00-05:00"},
                "source": "cudy-luci",
            },
        }
        # Reading changes nothing, so it is not logged.
        assert entries(app, kind="firmware") == []

    @pytest.mark.parametrize(
        ("method", "path"),
        [
            ("GET", "/api/devices/ghost/firmware"),
            ("PUT", "/api/devices/ghost/firmware/auto-update"),
            ("POST", "/api/devices/ghost/firmware/check"),
        ],
    )
    def test_an_unknown_device_is_404(self, tmp_path: Path, method, path):
        client, headers = signed_in(make_app(tmp_path))
        body = {"enabled": True} if method == "PUT" else None
        assert send(client, method, path, body, headers=headers).status_code == 404

    def test_auto_update_is_switched_and_logged(self, tmp_path: Path, router):
        app = make_app(tmp_path)
        add_cudy(app, router)
        client, headers = signed_in(app)
        response = client.put(
            "/api/devices/r1/firmware/auto-update", json={"enabled": True, "window_start_hour": 22}, headers=headers
        )
        assert response.status_code == 200, response.text
        assert response.json() == {
            "device": "r1",
            "status": "changed",
            "enabled": True,
            "window_start_hour": 22,
            "window": "22:00-00:00",
        }
        assert router.state["autoupgrade"] == {"auto_upgrade": "1", "upgrade_time": "22"}
        off = client.put("/api/devices/r1/firmware/auto-update", json={"enabled": False}, headers=headers)
        assert off.status_code == 200 and off.json()["window"] is None
        assert router.state["autoupgrade"]["auto_upgrade"] == "0"
        logged = entries(app, kind="firmware")
        assert [(entry["who"], entry["result"], entry["what"]) for entry in logged] == [
            (DASHBOARD_ACTOR, "applied", "Automatic firmware update turned off"),
            (DASHBOARD_ACTOR, "applied", "Automatic firmware update turned on (window 22:00-00:00)"),
        ]
        assert logged[1]["details"] == {"enabled": True, "window_start_hour": 22}

    @pytest.mark.parametrize(
        "body",
        [
            {},
            {"enabled": "true"},
            {"enabled": 1},
            {"enabled": True, "window_start_hour": 24},
            {"enabled": True, "window_start_hour": -1},
            {"enabled": True, "window_start_hour": "3"},
            {"enabled": True, "window_start_hour": True},
            {"enabled": True, "window_start_hour": 3.0},
            {"enabled": False, "window_start_hour": 3},
            {"enabled": True, "firmware": "x.bin"},
        ],
    )
    def test_bad_auto_update_bodies_are_400_before_the_router_is_contacted(self, tmp_path: Path, router, body):
        app = make_app(tmp_path)
        add_cudy(app, router)
        client, headers = signed_in(app)
        response = client.put("/api/devices/r1/firmware/auto-update", json=body, headers=headers)
        assert response.status_code == 400, response.text
        assert router.state["login_posts"] == 0
        assert entries(app, kind="firmware") == []

    def test_a_router_that_does_not_keep_the_change_is_502_and_logged_as_failed(self, tmp_path: Path, router):
        app = make_app(tmp_path)
        add_cudy(app, router)
        router.state["ignore_autoupgrade_writes"] = True
        client, headers = signed_in(app)
        response = client.put("/api/devices/r1/firmware/auto-update", json={"enabled": False}, headers=headers)
        assert response.status_code == 502, response.text
        assert "did not keep" in response.json()["detail"]
        [entry] = entries(app, kind="firmware")
        assert entry["result"] == "failed" and entry["who"] == DASHBOARD_ACTOR

    def test_tplink_firmware_writes_are_501_without_a_login(self, tmp_path: Path, monkeypatch):
        app = make_app(tmp_path)
        add_cudy(app, vendor="tplink", identifier="t1")
        monkeypatch.setattr(adapters.TpLinkAdapter, "login", lambda self: pytest.fail("the TP-Link was logged in to"))
        client, headers = signed_in(app)
        for method, path, body in (
            ("PUT", "/api/devices/t1/firmware/auto-update", {"enabled": True}),
            ("POST", "/api/devices/t1/firmware/check", None),
        ):
            response = send(client, method, path, body, headers=headers)
            assert response.status_code == 501, response.text
            assert "not supported" in response.json()["detail"]
        assert [entry["result"] for entry in entries(app, kind="firmware")] == ["refused", "refused"]

    def test_a_check_says_it_installed_nothing_and_is_logged_as_information(self, tmp_path: Path, router):
        app = make_app(tmp_path)
        add_cudy(app, router)
        notice = f'<div class="alert alert-info">New firmware v{NEWER} found.</div>'
        router.state["check_result_html"] = ap1300_autoupgrade_page(router.state["autoupgrade"], notice)
        client, headers = signed_in(app)
        response = client.post("/api/devices/r1/firmware/check", headers=headers)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["check"]["available"] is True and body["check"]["latest"] == NEWER
        assert body["installed"] is False and "nothing was installed" in body["message"]
        assert router.state["autoupgrade_posts"] == [], "a check changes no setting"
        [entry] = entries(app, kind="firmware")
        assert entry["result"] == "info" and entry["who"] == DASHBOARD_ACTOR
        assert entry["details"]["available"] is True and entry["details"]["latest"] == NEWER
        assert "nothing was installed" in entry["what"]

    def test_an_unrecognised_result_is_reported_as_unknown(self, tmp_path: Path, router):
        app = make_app(tmp_path)
        add_cudy(app, router)
        client, headers = signed_in(app)
        body = client.post("/api/devices/r1/firmware/check", json={}, headers=headers).json()
        assert body["check"]["available"] is None
        assert body["check"]["note"].startswith("result not recognised")
        [entry] = entries(app, kind="firmware")
        assert "could not tell" in entry["what"] and entry["details"]["available"] is None

    def test_a_check_takes_no_fields(self, tmp_path: Path, router):
        app = make_app(tmp_path)
        add_cudy(app, router)
        client, headers = signed_in(app)
        response = client.post("/api/devices/r1/firmware/check", json={"install": True}, headers=headers)
        assert response.status_code == 400
        assert router.state["login_posts"] == 0

    def test_a_check_runs_off_the_event_loop(self, tmp_path: Path, router):
        router.state["check_sequence"] = ["checking"] * 150 + ["checkdone"]
        app = make_app(tmp_path)
        add_cudy(app, router)
        adapters_poll = adapters._CUDY_CHECK_POLL
        assert adapters_poll == 0.01
        done: list[int] = []
        # One client, and so one event loop, for both requests. A client used without
        # "with" starts a loop of its own for every request, so a check that blocked
        # its loop could never hold up the other request.
        with TestClient(app) as client:
            headers = log_in(client)
            worker = threading.Thread(
                target=lambda: done.append(client.post("/api/devices/r1/firmware/check", headers=headers).status_code)
            )
            worker.start()
            deadline = time.monotonic() + 5
            while router.state["check_polls"] < 5 and time.monotonic() < deadline:
                time.sleep(0.01)
            started = time.monotonic()
            assert client.get("/healthz").status_code == 200
            assert time.monotonic() - started < 0.5
            assert worker.is_alive(), "the check finished before the other request was answered"
            worker.join(10)
        assert done == [200]

    def test_long_router_operations_leave_the_shared_worker_threads_free(self, tmp_path: Path, monkeypatch):
        app = make_app(tmp_path)
        add_cudy(app)
        release = threading.Event()
        threads: list[str] = []

        def check(device: str, *, actor: str) -> dict[str, Any]:
            threads.append(threading.current_thread().name)
            release.wait(10)
            return {"available": False, "current": CURRENT, "latest": None, "note": "none"}

        monkeypatch.setattr(app.state.manager, "check_firmware_update", check)
        # More checks than the event loop's default executor has threads.
        clicks = min(32, (os.cpu_count() or 1) + 4) + 2
        with TestClient(app) as client:
            headers = log_in(client)
            path = "/api/devices/r1/firmware/check"
            workers = [
                threading.Thread(target=client.post, args=(path,), kwargs={"headers": headers}) for _ in range(clicks)
            ]
            for worker in workers:
                worker.start()
            deadline = time.monotonic() + 5
            while len(threads) < web.FIRMWARE_CHECK_WORKERS and time.monotonic() < deadline:
                time.sleep(0.01)
            started = time.monotonic()
            # Every other route, the scheduler tick and the ACS poll run on the default executor.
            response = client.get("/api/maintenance/runs")
            elapsed = time.monotonic() - started
            release.set()
            for worker in workers:
                worker.join(10)
        assert response.status_code == 200 and elapsed < 2
        assert len(threads) == clicks
        assert all(name.startswith("firmware-check") for name in threads), threads

    def test_a_manual_plan_run_has_its_own_worker_threads(self, tmp_path: Path, monkeypatch):
        app = make_app(tmp_path)
        threads: list[str] = []

        def run_now(plan_id: str, actor: str) -> list[dict[str, Any]]:
            threads.append(threading.current_thread().name)
            return []

        monkeypatch.setattr(app.state.maintenance, "run_now", run_now)
        client, headers = signed_in(app)
        response = client.post(f"/api/maintenance/plans/{PLAN_ID}/run", json={"confirm": True}, headers=headers)
        assert response.status_code == 200, response.text
        assert len(threads) == 1 and threads[0].startswith("maintenance-run"), threads

    def test_openwrt_reports_its_release_and_refuses_the_rest_without_connecting(self, tmp_path: Path, monkeypatch):
        replies = {
            "cat /etc/openwrt_release": (
                0,
                "DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE='23.05.3'\nDISTRIB_REVISION='r23809-234f1a2efa'\n",
                "",
            ),
            "ubus call system board": (0, json.dumps({"model": "Cudy WR3000 v1", "board_name": "cudy,wr3000"}), ""),
        }
        commands: list[str] = []

        def execute(self, command: str, stdin_data: str | None = None):
            commands.append(command)
            return replies.get(command, (1, "", "not found"))

        monkeypatch.setattr(OpenWrtAdapter, "execute", execute)
        app = make_app(tmp_path)
        add_cudy(app, identifier="s1", transport="ssh")
        client, headers = signed_in(app)
        response = client.get("/api/devices/s1/firmware")
        assert response.status_code == 200, response.text
        assert response.json()["firmware"] == {
            "version": "23.05.3 r23809-234f1a2efa",
            "hardware": "Cudy WR3000 v1",
            "auto_update": None,
            "source": "openwrt-ssh",
        }
        commands.clear()
        for method, path, body in (
            ("PUT", "/api/devices/s1/firmware/auto-update", {"enabled": True}),
            ("POST", "/api/devices/s1/firmware/check", None),
        ):
            refused = send(client, method, path, body, headers=headers)
            assert refused.status_code == 501 and "OpenWrt" in refused.json()["detail"]
        assert commands == []

    def test_openwrt_falls_back_to_the_sysinfo_model(self, tmp_path: Path, monkeypatch):
        replies = {
            "cat /etc/openwrt_release": (0, 'DISTRIB_RELEASE="19.07.10"\n', ""),
            "ubus call system board": (1, "", "Command failed: Not found"),
            "cat /tmp/sysinfo/model": (0, "TP-Link Archer C7 v2\n", ""),
        }
        monkeypatch.setattr(OpenWrtAdapter, "execute", lambda self, command, stdin_data=None: replies[command])
        app = make_app(tmp_path)
        add_cudy(app, identifier="s1", transport="ssh")
        client, _ = signed_in(app)
        firmware = client.get("/api/devices/s1/firmware").json()["firmware"]
        assert (firmware["version"], firmware["hardware"]) == ("19.07.10", "TP-Link Archer C7 v2")

    def test_a_router_without_openwrt_release_is_a_gateway_error(self, tmp_path: Path, monkeypatch):
        monkeypatch.setattr(OpenWrtAdapter, "execute", lambda self, command, stdin_data=None: (1, "", ""))
        app = make_app(tmp_path)
        add_cudy(app, identifier="s1", transport="ssh")
        client, _ = signed_in(app)
        response = client.get("/api/devices/s1/firmware")
        assert response.status_code == 502 and "openwrt_release" in response.json()["detail"]


class TestManagerFirmwareWrappers:
    """What the routes and the CLI call; their own checks run before the manager's."""

    @pytest.mark.parametrize(
        ("enabled", "hour", "message"),
        [
            ("yes", None, "enabled"),
            (True, 24, "window_start_hour"),
            (True, True, "window_start_hour"),
            (False, 3, "while turning automatic update on"),
        ],
    )
    def test_bad_settings_are_refused_and_logged_before_the_router_is_contacted(
        self, tmp_path: Path, router, enabled, hour, message
    ):
        app = make_app(tmp_path)
        add_cudy(app, router)
        with pytest.raises(web.ValidationError, match=message):
            app.state.manager.set_auto_update("r1", enabled, hour, actor="tester")
        assert router.state["login_posts"] == 0
        [entry] = entries(app, kind="firmware")
        assert (entry["who"], entry["result"]) == ("tester", "refused")

    @pytest.mark.parametrize("timeout", [0, -1, 301, True, "45"])
    def test_a_bad_check_timeout_is_refused(self, tmp_path: Path, router, timeout):
        app = make_app(tmp_path)
        add_cudy(app, router)
        with pytest.raises(web.ValidationError, match="timeout"):
            app.state.manager.check_firmware_update("r1", timeout, actor="tester")
        assert router.state["login_posts"] == 0

    def test_the_default_check_timeout_is_below_the_router_lock_timeout(self, tmp_path: Path):
        from cudy_manager.manager import FIRMWARE_CHECK_TIMEOUT

        manager = make_app(tmp_path).state.manager
        assert manager.router_lock_timeout > FIRMWARE_CHECK_TIMEOUT

    def test_the_check_is_given_the_default_timeout(self, tmp_path: Path, monkeypatch):
        from cudy_manager.manager import FIRMWARE_CHECK_TIMEOUT

        app = make_app(tmp_path)
        add_cudy(app)
        seen: list[tuple[Any, ...]] = []

        def call(device, operation, *args):
            seen.append((operation, *args))
            return {"available": False, "current": CURRENT, "latest": None, "note": "none"}

        monkeypatch.setattr(app.state.manager, "_call", call)
        app.state.manager.check_firmware_update("r1", actor="tester")
        assert seen == [("check_firmware_update", FIRMWARE_CHECK_TIMEOUT)]
        [entry] = entries(app, kind="firmware")
        assert entry["what"] == f"Firmware check: no newer firmware than {CURRENT}"

    @pytest.mark.parametrize("actor", ["", "   ", None, 7])
    def test_a_missing_actor_is_refused_before_anything(self, tmp_path: Path, router, actor):
        app = make_app(tmp_path)
        add_cudy(app, router)
        with pytest.raises(web.ValidationError):
            app.state.manager.set_auto_update("r1", True, 3, actor=actor)
        with pytest.raises(web.ValidationError):
            app.state.manager.check_firmware_update("r1", actor=actor)
        assert router.state["login_posts"] == 0 and entries(app, kind="firmware") == []


# --- the TR-069 firmware library ---------------------------------------------------------------------


class TestAcsFirmware:
    def test_an_upload_is_stored_and_listed_without_its_content(self, tmp_path: Path, nbi):
        app = make_app(tmp_path, nbi)
        client, headers = signed_in(app)
        response = client.post(UPLOAD, content=CONTENT, headers={**headers, **OCTETS})
        assert response.status_code == 201, response.text
        record = response.json()["firmware"]
        assert record["name"].startswith("skybre-fw-") and record["filename"] == "AP1300-2.5.26.bin"
        assert (record["version"], record["oui"], record["product_class"]) == (NEW, OUI, PRODUCT)
        assert record["size"] == len(CONTENT) and record["on_acs"] is True
        assert nbi.file_data[record["name"]] == CONTENT
        listing = client.get("/api/acs/firmware")
        assert listing.status_code == 200
        [listed] = listing.json()["firmware"]
        assert listed["name"] == record["name"] and listed["on_acs"] is True
        marker = CONTENT[:24].decode()
        assert marker not in response.text and marker not in listing.text

    def test_metadata_can_come_in_headers(self, tmp_path: Path, nbi):
        client, headers = signed_in(make_app(tmp_path, nbi))
        metadata = {
            "X-Firmware-Version": NEW,
            "X-Firmware-OUI": OUI,
            "X-Firmware-Product-Class": PRODUCT,
            "X-Firmware-Model-Hint": "Cudy AP1300",
        }
        response = client.post("/api/acs/firmware", content=CONTENT, headers={**headers, **metadata})
        assert response.status_code == 201, response.text
        assert response.json()["firmware"]["model_hint"] == "Cudy AP1300"

    @pytest.mark.parametrize(
        ("path", "extra", "status"),
        [
            (f"/api/acs/firmware?oui={OUI}&product_class={PRODUCT}", {}, 400),
            (f"/api/acs/firmware?version=bad%0Aversion&oui={OUI}&product_class={PRODUCT}", {}, 400),
            (f"{UPLOAD}&productclass={PRODUCT}", {}, 400),
            (UPLOAD, {"X-Firmware-Version": "9.9.9"}, 400),
            (UPLOAD, {"Content-Type": "multipart/form-data; boundary=x"}, 415),
            (UPLOAD, {"Content-Type": "application/json"}, 415),
            (UPLOAD, {"Content-Type": "application/x-www-form-urlencoded"}, 415),
        ],
    )
    def test_refused_uploads_store_nothing(self, tmp_path: Path, nbi, path, extra, status):
        app = make_app(tmp_path, nbi)
        client, headers = signed_in(app)
        response = client.post(path, content=CONTENT, headers={**headers, **extra})
        assert response.status_code == status, response.text
        assert nbi.files == {} and app.state.acs.firmware.all() == {}

    def test_an_empty_upload_is_400(self, tmp_path: Path, nbi):
        client, headers = signed_in(make_app(tmp_path, nbi))
        response = client.post(UPLOAD, content=b"", headers={**headers, **OCTETS})
        assert response.status_code == 400 and "empty" in response.json()["detail"]
        assert nbi.files == {}

    def test_the_upload_has_its_own_limit_and_other_routes_keep_theirs(self, tmp_path: Path, nbi, monkeypatch):
        app = make_app(tmp_path, nbi)
        client, headers = signed_in(app)
        # Past the 64 KiB JSON limit, well inside the firmware one.
        image = b"\x7fELF" + bytes(200 * 1024)
        accepted = client.post(UPLOAD, content=image, headers={**headers, **OCTETS})
        assert accepted.status_code == 201, accepted.text
        big_json = {"firmware": FIRMWARE_NAME, "confirm": True, "pad": "x" * (100 * 1024)}
        device = quote("80AFCA-AP1300-000001", safe="")
        refused = client.post(f"/api/acs/devices/{device}/firmware", json=big_json, headers=headers)
        assert refused.status_code == 413
        monkeypatch.setattr(web, "MAX_FIRMWARE_UPLOAD", 1024)
        too_big = client.post(UPLOAD, content=bytes(2048), headers={**headers, **OCTETS})
        assert too_big.status_code == 413 and "larger than" in too_big.json()["detail"]

        def chunks():
            for _ in range(4):
                yield bytes(512)

        chunked = client.post(UPLOAD, content=chunks(), headers={**headers, **OCTETS})
        assert chunked.status_code == 413
        assert len(nbi.files) == 1

    def test_the_full_limit_is_64_mib(self):
        assert web.MAX_FIRMWARE_UPLOAD == 64 * 1024 * 1024
        assert web.MAX_BODY_BYTES == 64 * 1024

    def test_a_file_is_removed_and_an_unknown_one_is_404(self, tmp_path: Path, nbi):
        client, headers = signed_in(make_app(tmp_path, nbi))
        name = client.post(UPLOAD, content=CONTENT, headers={**headers, **OCTETS}).json()["firmware"]["name"]
        response = client.delete(f"/api/acs/firmware/{name}", headers=headers)
        assert response.status_code == 200 and response.json() == {"name": name, "removed": True}
        assert nbi.files == {}
        assert client.delete(f"/api/acs/firmware/{name}", headers=headers).status_code == 404
        assert client.delete("/api/acs/firmware/not-ours.bin", headers=headers).status_code == 400

    def test_an_upgrade_is_a_job_under_the_session_actor(self, tmp_path: Path, nbi):
        acs_id = cudy(nbi)
        app = make_app(tmp_path, nbi)
        client, headers = signed_in(app)
        name = client.post(UPLOAD, content=CONTENT, headers={**headers, **OCTETS}).json()["firmware"]["name"]
        response = client.post(
            f"/api/acs/devices/{quote(acs_id, safe='')}/firmware",
            json={"firmware": name, "confirm": True},
            headers=headers,
        )
        assert response.status_code == 202, response.text
        job = response.json()["job"]
        assert job["kind"] == "firmware" and job["actor"] == DASHBOARD_ACTOR
        assert job["request"]["from_version"] == OLD and job["request"]["version"] == NEW
        assert [task["file"] for task in nbi.tasks if task["name"] == "download"] == [name]
        assert "in_use_by" in client.get("/api/acs/firmware").json()["firmware"][0]
        busy = client.delete(f"/api/acs/firmware/{name}", headers=headers)
        assert busy.status_code == 409 and job["id"] in busy.json()["detail"]

    def test_a_model_mismatch_needs_confirming(self, tmp_path: Path, nbi):
        acs_id = cudy(nbi, product_class="AP3000")
        app = make_app(tmp_path, nbi)
        client, headers = signed_in(app)
        name = client.post(UPLOAD, content=CONTENT, headers={**headers, **OCTETS}).json()["firmware"]["name"]
        path = f"/api/acs/devices/{quote(acs_id, safe='')}/firmware"
        refused = client.post(path, json={"firmware": name, "confirm": True}, headers=headers)
        assert refused.status_code == 409, refused.text
        assert refused.json()["plan"]["mismatch"] == ["product_class"]
        assert [task for task in nbi.tasks if task["name"] == "download"] == []
        confirmed = client.post(
            path, json={"firmware": name, "confirm": True, "confirm_model_mismatch": True}, headers=headers
        )
        assert confirmed.status_code == 202, confirmed.text

    @pytest.mark.parametrize(
        "body",
        [
            {"firmware": FIRMWARE_NAME},
            {"firmware": FIRMWARE_NAME, "confirm": "yes"},
            {"confirm": True},
            {"firmware": ["x"], "confirm": True},
            {"firmware": FIRMWARE_NAME, "confirm": True, "confirm_model_mismatch": "true"},
            {"firmware": FIRMWARE_NAME, "confirm": True, "fileType": "1 Firmware Upgrade Image"},
            {"firmware": "http://example.invalid/x.bin", "confirm": True},
        ],
    )
    def test_bad_upgrade_bodies_are_400_before_the_acs_is_asked(self, tmp_path: Path, nbi, body):
        acs_id = cudy(nbi)
        client, headers = signed_in(make_app(tmp_path, nbi))
        before = len(nbi.requests)
        response = client.post(f"/api/acs/devices/{quote(acs_id, safe='')}/firmware", json=body, headers=headers)
        assert response.status_code == 400, response.text
        assert len(nbi.requests) == before

    def test_an_unknown_library_file_is_404(self, tmp_path: Path, nbi):
        acs_id = cudy(nbi)
        client, headers = signed_in(make_app(tmp_path, nbi))
        response = client.post(
            f"/api/acs/devices/{quote(acs_id, safe='')}/firmware",
            json={"firmware": FIRMWARE_NAME, "confirm": True},
            headers=headers,
        )
        assert response.status_code == 404


# --- maintenance plans -------------------------------------------------------------------------------


class TestMaintenancePlans:
    def test_a_plan_is_created_listed_changed_and_deleted(self, tmp_path: Path, caplog):
        caplog.set_level(logging.INFO, logger="cudy_manager.web")
        app = make_app(tmp_path)
        client, headers = signed_in(app)
        created = client.post("/api/maintenance/plans", json=plan_body(), headers=headers)
        assert created.status_code == 201, created.text
        plan = created.json()["plan"]
        plan_id = plan["id"]
        assert plan["enabled"] is True and plan["guards"]["cooldown_hours"] == 20
        [listed] = client.get("/api/maintenance/plans").json()["plans"]
        assert listed["id"] == plan_id and listed["next_window"]["opens"] and listed["last_run"] is None
        one = client.get(f"/api/maintenance/plans/{plan_id}").json()["plan"]
        assert one == listed
        changed = client.put(f"/api/maintenance/plans/{plan_id}", json={"enabled": False}, headers=headers)
        assert changed.status_code == 200 and changed.json()["plan"]["enabled"] is False
        assert changed.json()["plan"]["actions"] == ["firmware_check"]
        deleted = client.delete(f"/api/maintenance/plans/{plan_id}", headers=headers)
        assert deleted.json() == {"id": plan_id, "name": "Weekly check", "deleted": True}
        assert client.get(f"/api/maintenance/plans/{plan_id}").status_code == 404
        assert f"maintenance plan {plan_id} (Weekly check) created by {DASHBOARD_ACTOR}" in caplog.text
        assert f"deleted by {DASHBOARD_ACTOR}" in caplog.text

    @pytest.mark.parametrize(
        "body",
        [
            plan_body(actions=["factory_reset"]),
            plan_body(schedule={"start": "03:00", "timezone": "UTC"}),
            plan_body(schedule={"days": ["tue"], "start": "03:00", "timezone": "Mars/Olympus"}),
            plan_body(targets={}),
            plan_body(id=PLAN_ID),
            plan_body(actor="mallory"),
            plan_body(name=""),
        ],
    )
    def test_invalid_plans_are_400_and_store_nothing(self, tmp_path: Path, body):
        app = make_app(tmp_path)
        client, headers = signed_in(app)
        response = client.post("/api/maintenance/plans", json=body, headers=headers)
        assert response.status_code == 400, response.text
        assert app.state.maintenance.store.list() == []

    @pytest.mark.parametrize(
        ("method", "body"),
        [("GET", None), ("PUT", {"enabled": False}), ("DELETE", None), ("POST", {"confirm": True})],
    )
    def test_an_unknown_plan_is_404_and_a_malformed_id_400(self, tmp_path: Path, method, body):
        client, headers = signed_in(make_app(tmp_path))
        suffix = "/run" if method == "POST" else ""
        unknown = send(client, method, f"/api/maintenance/plans/{PLAN_ID}{suffix}", body, headers=headers)
        assert unknown.status_code == 404, unknown.text
        malformed = send(client, method, f"/api/maintenance/plans/NOT-AN-ID{suffix}", body, headers=headers)
        assert malformed.status_code == 400, malformed.text

    def test_a_damaged_plan_file_is_a_500_that_names_it(self, tmp_path: Path, caplog):
        app = make_app(tmp_path)
        app.state.maintenance.store.path.parent.mkdir(parents=True, exist_ok=True)
        app.state.maintenance.store.path.write_text("{not json")
        client, headers = signed_in(app)
        for response in (
            client.get("/api/maintenance/plans"),
            client.post("/api/maintenance/plans", json=plan_body(), headers=headers),
        ):
            assert response.status_code == 500, response.text
            assert "maintenance.json" in response.json()["detail"]
        assert "maintenance plans are unreadable" in caplog.text
        assert app.state.maintenance.store.path.read_text() == "{not json"

    @pytest.mark.parametrize("body", [{}, {"confirm": False}, {"confirm": "true"}, {"confirm": True, "actor": "x"}])
    def test_a_run_needs_confirm_true_and_takes_nothing_else(self, tmp_path: Path, monkeypatch, body):
        app = make_app(tmp_path)
        monkeypatch.setattr(app.state.maintenance, "run_now", lambda *args: pytest.fail("the plan ran"))
        client, headers = signed_in(app)
        response = client.post(f"/api/maintenance/plans/{PLAN_ID}/run", json=body, headers=headers)
        assert response.status_code == 400, response.text

    def test_a_run_is_by_the_session_and_a_second_one_at_once_is_409(self, tmp_path: Path, monkeypatch):
        app = make_app(tmp_path)
        calls: list[tuple[Any, ...]] = []

        def run_now(*args: Any) -> list[dict[str, Any]]:
            calls.append(args)
            if len(calls) > 1:
                raise MaintenanceBusy('maintenance plan "Weekly check" is already running')
            return [{"target": "direct:r1", "status": "done", "actions": []}]

        monkeypatch.setattr(app.state.maintenance, "run_now", run_now)
        client, headers = signed_in(app)
        path = f"/api/maintenance/plans/{PLAN_ID}/run"
        first = client.post(path, json={"confirm": True}, headers=headers)
        assert first.status_code == 200 and first.json()["results"][0]["status"] == "done"
        second = client.post(path, json={"confirm": True}, headers=headers)
        assert second.status_code == 409 and "already running" in second.json()["detail"]
        assert calls == [(PLAN_ID, DASHBOARD_ACTOR)] * 2

    def test_a_run_checks_a_real_router_and_is_logged_under_the_plan(self, tmp_path: Path, router):
        app = make_app(tmp_path)
        add_cudy(app, router)
        client, headers = signed_in(app)
        plan_id = client.post("/api/maintenance/plans", json=plan_body(), headers=headers).json()["plan"]["id"]
        response = client.post(f"/api/maintenance/plans/{plan_id}/run", json={"confirm": True}, headers=headers)
        assert response.status_code == 200, response.text
        [result] = response.json()["results"]
        assert result["target"] == "direct:r1" and result["trigger"] == "manual" and result["status"] == "done"
        assert [action["action"] for action in result["actions"]] == ["firmware_check"]
        assert router.state["update_checks"] and router.state["autoupgrade_posts"] == []
        [entry] = entries(app, kind="firmware")
        assert entry["who"] == f"Maintenance: Weekly check (run by {DASHBOARD_ACTOR})"
        assert entry["router"] == "r1" and entry["details"]["plan"] == plan_id
        [run] = client.get("/api/maintenance/runs").json()["runs"]
        assert run["plan"] == plan_id and run["trigger"] == "manual"
        assert run["targets"]["direct:r1"]["status"] == "done"
        overview = client.get(f"/api/maintenance/plans/{plan_id}").json()["plan"]
        assert overview["last_run"]["targets"] == {"direct:r1": "done"}

    def test_runs_are_newest_first_and_filter_by_plan(self, tmp_path: Path):
        app = make_app(tmp_path)
        state = {
            "version": 1,
            "occurrences": {
                "aaaaaaaaaaaa:2026-03-03": {
                    "plan": "aaaaaaaaaaaa",
                    "plan_name": "A",
                    "trigger": "schedule",
                    "created": "2026-03-03T03:00:00+00:00",
                    "targets": {"direct:r1": {"status": "done"}},
                    "held": {},
                },
                "bbbbbbbbbbbb:2026-03-04": {
                    "plan": "bbbbbbbbbbbb",
                    "plan_name": "B",
                    "trigger": "schedule",
                    "created": "2026-03-04T03:00:00+00:00",
                    "targets": {},
                    "held": {"acs:X-Y-Z": "the router is not checking in with the ACS"},
                },
            },
            "targets": {},
        }
        app.state.maintenance.state_path.parent.mkdir(parents=True, exist_ok=True)
        app.state.maintenance.state_path.write_text(json.dumps(state))
        client, _ = signed_in(app)
        runs = client.get("/api/maintenance/runs").json()["runs"]
        assert [run["plan_name"] for run in runs] == ["B", "A"]
        assert runs[0]["held"] == {"acs:X-Y-Z": "the router is not checking in with the ACS"}
        assert [run["plan"] for run in client.get("/api/maintenance/runs?plan=aaaaaaaaaaaa").json()["runs"]] == [
            "aaaaaaaaaaaa"
        ]
        assert len(client.get("/api/maintenance/runs?limit=1").json()["runs"]) == 1
        for query in ("limit=0", "limit=501", "limit=x"):
            assert client.get(f"/api/maintenance/runs?{query}").status_code == 400

    def test_a_damaged_state_file_is_a_500(self, tmp_path: Path):
        app = make_app(tmp_path)
        app.state.maintenance.state_path.parent.mkdir(parents=True, exist_ok=True)
        app.state.maintenance.state_path.write_text("[]")
        client, _ = signed_in(app)
        response = client.get("/api/maintenance/runs")
        assert response.status_code == 500 and "maintenance state" in response.json()["detail"]


# --- the scheduler loop ------------------------------------------------------------------------------


class TestSchedulerLoop:
    def test_the_loop_runs_maintenance_and_logs_its_outcomes(self, tmp_path: Path, monkeypatch, caplog):
        caplog.set_level(logging.INFO, logger="cudy_manager.web")
        failed = {
            "source": "maintenance",
            "plan": PLAN_ID,
            "plan_name": "Weekly check",
            "device": "r1",
            "status": "failed",
            "reason": "the router did not confirm the reboot",
            "actions": [],
        }
        passes: list[Any] = []
        monkeypatch.setattr(MaintenanceRunner, "run_once", lambda self, now=None: passes.append(now) or [failed])
        app = make_app(tmp_path, scheduler_interval=0.02)
        with TestClient(app):
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and "maintenance plan Weekly check" not in caplog.text:
                time.sleep(0.02)
        assert passes, "the scheduler loop never ran the maintenance plans"
        assert "maintenance plan Weekly check on r1 failed: the router did not confirm the reboot" in caplog.text
        assert "scheduled reboot of r1" not in caplog.text

    @pytest.mark.parametrize(
        ("result", "line"),
        [
            (
                {"source": "maintenance", "status": "failed", "reason": "maintenance plans are unreadable: x"},
                "maintenance plans could not run: maintenance plans are unreadable: x",
            ),
            (
                {"source": "maintenance", "plan_name": "A", "device": "*", "status": "failed", "reason": "no ACS"},
                "maintenance plan A on its TR-069 routers failed: no ACS",
            ),
            (
                {"source": "maintenance", "plan_name": "A", "device": None, "status": "failed", "reason": "bad zone"},
                "maintenance plan A on its routers failed: bad zone",
            ),
            (
                {"source": "maintenance", "plan_name": "A", "device": "r1", "status": "partial", "reason": "x"},
                "maintenance plan A on r1 partly failed: x",
            ),
            (
                {"source": "maintenance", "plan_name": "A", "device": "r1", "status": "skipped", "reason": "offline"},
                "maintenance plan A skipped r1: offline",
            ),
            (
                {"source": "maintenance", "plan_name": "A", "device": "r1", "status": "done"},
                "maintenance plan A on r1 done",
            ),
            (
                {"source": "maintenance", "plan_name": "A", "device": "acs:X", "status": "queued", "reason": "job 1"},
                "maintenance plan A on acs:X queued: job 1",
            ),
            (
                {"source": "reboot", "device": "r1", "status": "failed", "reason": "x"},
                "scheduled reboot of r1 failed: x",
            ),
            ({"source": "reboot", "device": "r1", "status": "initiated"}, "scheduled reboot of r1 initiated"),
        ],
    )
    def test_each_outcome_gets_its_own_line(self, caplog, result, line):
        caplog.set_level(logging.INFO, logger="cudy_manager.web")
        web._log_scheduled(result)
        assert caplog.messages == [line]

    def test_the_loop_survives_a_failing_tick(self, tmp_path: Path, monkeypatch, caplog):
        ticks: list[int] = []

        def tick(self, now=None, *, wait=False):
            ticks.append(1)
            if len(ticks) == 1:
                raise RuntimeError("state file vanished")
            return []

        monkeypatch.setattr(RebootScheduler, "tick", tick)
        app = make_app(tmp_path, scheduler_interval=0.02)
        with TestClient(app):
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and len(ticks) < 3:
                time.sleep(0.02)
        assert len(ticks) >= 3, "the loop stopped after an error"
        assert "state file vanished" in caplog.text

    def test_shutdown_waits_for_a_maintenance_pass(self, tmp_path: Path, monkeypatch):
        waited: list[float | None] = []
        monkeypatch.setattr(
            RebootScheduler, "join_maintenance", lambda self, timeout=None: waited.append(timeout) or True
        )
        with TestClient(make_app(tmp_path)):
            pass
        assert waited == [web.MAINTENANCE_SHUTDOWN_WAIT]
