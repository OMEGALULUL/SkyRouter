"""The TR-069 web routes (brief §3.8), their dashboard (§3.9), and the direct Wi-Fi password route.

Most tests drive a real AcsService against the fake NBI, so a route is checked
end to end down to the requests GenieACS would see. Error mapping and the poll
loop use a stub service, because those are about web.py alone.
"""

import json
import logging
import os
import socket
import subprocess
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import quote

import pytest
from fake_nbi import FakeNbi, build_device, make_device_id
from fastapi.testclient import TestClient
from test_web import DASHBOARD_HARNESS, NODE, _dashboard_markup, needs_node

from cudy_manager import web
from cudy_manager.acs.bootstrap import BootstrapRefused
from cudy_manager.acs.client import AcsBusy, AcsClient, AcsError, AcsNotFound, AcsRejected, AcsUnavailable
from cudy_manager.acs.jobs import JobStoreError
from cudy_manager.acs.service import AcsConfirmationRequired, AcsService
from cudy_manager.adapters import AdapterError, UnsupportedOperation
from cudy_manager.manager import DeviceManager
from cudy_manager.models import ValidationError
from cudy_manager.secrets import SecretStore
from cudy_manager.web import Settings, create_app

PASSWORD = "correct horse battery staple"
PASS = "zq-Wifi-Passphrase-7731"
WIFI = "Device.WiFi"
IGD = "InternetGatewayDevice"

DEVICE = make_device_id("202BC1", "BM632w", "000001")
ENC = quote(DEVICE, safe="")
JOB = "0123456789abcdef"
FAULT = quote(f"{DEVICE}:skybre-inform", safe="")
WIFI_ROUTE = f"/api/acs/devices/{ENC}/wifi"

# Every /api/acs route, with a body it would accept. test_every_acs_route_is_listed_here
# keeps this in step with the app, so a new route cannot miss the auth, CSRF and 503 checks.
READS: list[tuple[str, str]] = [
    ("GET", "/api/acs"),
    ("GET", "/api/acs/devices"),
    ("GET", f"/api/acs/devices/{ENC}"),
    ("GET", "/api/acs/jobs"),
    ("GET", f"/api/acs/jobs/{JOB}"),
]
WRITES: list[tuple[str, str, dict[str, Any] | None]] = [
    ("POST", f"/api/acs/devices/{ENC}/refresh", {"scope": "wifi"}),
    ("POST", f"/api/acs/devices/{ENC}/wifi", {"band": "all", "passphrase": PASS}),
    ("POST", f"/api/acs/devices/{ENC}/reboot", {"confirm": True}),
    ("POST", f"/api/acs/devices/{ENC}/tags/shop", None),
    ("DELETE", f"/api/acs/devices/{ENC}/tags/shop", None),
    ("POST", f"/api/acs/devices/{ENC}/adopt", None),
    ("DELETE", f"/api/acs/jobs/{JOB}", None),
    ("POST", f"/api/acs/faults/{FAULT}/retry", None),
    ("DELETE", f"/api/acs/faults/{FAULT}", None),
    ("POST", "/api/acs/bootstrap", {"confirm": True}),
]
TEMPLATES = {
    ("GET", "/api/acs"),
    ("GET", "/api/acs/devices"),
    ("GET", "/api/acs/devices/{acs_id}"),
    ("GET", "/api/acs/jobs"),
    ("GET", "/api/acs/jobs/{job_id}"),
    ("POST", "/api/acs/devices/{acs_id}/refresh"),
    ("POST", "/api/acs/devices/{acs_id}/wifi"),
    ("POST", "/api/acs/devices/{acs_id}/reboot"),
    ("POST", "/api/acs/devices/{acs_id}/tags/{tag}"),
    ("DELETE", "/api/acs/devices/{acs_id}/tags/{tag}"),
    ("POST", "/api/acs/devices/{acs_id}/adopt"),
    ("DELETE", "/api/acs/jobs/{job_id}"),
    ("POST", "/api/acs/faults/{fault_id}/retry"),
    ("DELETE", "/api/acs/faults/{fault_id}"),
    ("POST", "/api/acs/bootstrap"),
}


@pytest.fixture
def nbi():
    with FakeNbi() as fake:
        yield fake


def make_app(tmp_path: Path, nbi: FakeNbi | None = None, *, acs_service: Any = None, **overrides: Any):
    data = tmp_path / "data"
    store = SecretStore(data)
    manager = DeviceManager(config_path=tmp_path / "devices.yaml", data_dir=data, secret_store=store)
    settings = Settings(
        username="admin",
        password=PASSWORD,
        secure_cookie=False,
        scheduler_interval=3600,
        config_path=tmp_path / "devices.yaml",
        data_dir=data,
        **overrides,
    )
    if acs_service is None and nbi is not None:
        acs_service = AcsService(AcsClient(nbi.url, timeout=5), store, data, clock=nbi.now)
    return create_app(manager=manager, settings=settings, acs_service=acs_service)


def signed_in(app) -> tuple[TestClient, dict[str, str]]:
    client = TestClient(app)
    response = client.post("/login", json={"username": "admin", "password": PASSWORD})
    assert response.status_code == 200, response.text
    return client, {"X-CSRF-Token": response.json()["csrf_token"]}


def tr181_router(nbi: FakeNbi, serial: str = "000001", tags: tuple[str, ...] = (), **extra: Any) -> str:
    leaves: dict[str, Any] = {
        "Device.ManagementServer.ConnectionRequestURL": {"value": "http://10.10.0.40:7547/", "writable": False},
        "Device.ManagementServer.PeriodicInformInterval": 300,
        "Device.DeviceInfo.Manufacturer": {"value": "Acme", "writable": False},
        "Device.DeviceInfo.ModelName": {"value": "AX3000", "writable": False},
        f"{WIFI}.Radio.1.OperatingFrequencyBand": "2.4GHz",
        f"{WIFI}.SSID.1.SSID": "Home",
        f"{WIFI}.SSID.1.LowerLayers": "Device.WiFi.Radio.1.",
        f"{WIFI}.AccessPoint.1.SSIDReference": "Device.WiFi.SSID.1.",
        f"{WIFI}.AccessPoint.1.Security.ModeEnabled": "WPA2-Personal",
        f"{WIFI}.AccessPoint.1.Security.KeyPassphrase": "",
        **extra,
    }
    return nbi.add_device(build_device(serial=serial, leaves=leaves, tags=tags, last_inform=nbi.now()))


def tr098_router(nbi: FakeNbi) -> str:
    """One network whose band SkyRouter can only infer from its channel."""
    wlan = f"{IGD}.LANDevice.1.WLANConfiguration.1"
    leaves = {
        f"{IGD}.ManagementServer.ConnectionRequestURL": {"value": "http://10.10.0.41:7547/", "writable": False},
        f"{IGD}.ManagementServer.PeriodicInformInterval": 300,
        f"{IGD}.DeviceInfo.Manufacturer": {"value": "Acme", "writable": False},
        f"{wlan}.SSID": "Shop",
        f"{wlan}.Channel": 6,
        f"{wlan}.BeaconType": "11i",
        f"{wlan}.IEEE11iAuthenticationMode": "PSKAuthentication",
        f"{wlan}.KeyPassphrase": "",
        f"{wlan}.PreSharedKey.1.KeyPassphrase": "",
    }
    return nbi.add_device(build_device(serial="000098", leaves=leaves, last_inform=nbi.now()))


def send(client: TestClient, method: str, path: str, body: dict[str, Any] | None = None, **kwargs: Any):
    if body is None:
        return client.request(method, path, **kwargs)
    return client.request(method, path, json=body, **kwargs)


@contextmanager
def served(app):
    """Run the app under uvicorn on a free loopback port; yields call(method, path) -> (status, json)."""
    import http.client

    import uvicorn

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, lifespan="off", log_level="warning"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 5
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.01)
    assert server.started, "uvicorn did not start"
    state: dict[str, str] = {}

    def call(method: str, path: str, body: dict[str, Any] | None = None) -> tuple[int, Any]:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        headers = {"Content-Type": "application/json"}
        if state:
            headers.update({"Cookie": state["cookie"], "X-CSRF-Token": state["csrf"]})
        connection.request(method, path, body=json.dumps(body) if body is not None else None, headers=headers)
        response = connection.getresponse()
        payload = json.loads(response.read() or b"null")
        cookie = response.getheader("set-cookie")
        connection.close()
        if cookie and not state:
            state.update(cookie=cookie.split(";", 1)[0], csrf=payload["csrf_token"])
        return response.status, payload

    try:
        status, _ = call("POST", "/login", {"username": "admin", "password": PASSWORD})
        assert status == 200
        yield call
    finally:
        server.should_exit = True
        thread.join(5)
        sock.close()


# --- settings ----------------------------------------------------------------------------------


class TestSettings:
    def test_the_feature_is_off_without_an_acs_url(self, tmp_path: Path):
        settings = Settings.from_env()
        assert settings.acs_url is None
        app = make_app(tmp_path)
        assert app.state.acs is None

    def test_the_acs_variables_are_read_when_the_url_is_set(self, monkeypatch):
        monkeypatch.setenv("ROUTER_MANAGER_ACS_URL", "http://127.0.0.1:7557/")
        monkeypatch.setenv("ROUTER_MANAGER_ACS_INFORM_INTERVAL", "600")
        monkeypatch.setenv("ROUTER_MANAGER_ACS_SCRUB_SECRETS", "0")
        settings = Settings.from_env()
        assert settings.acs_url == "http://127.0.0.1:7557"
        assert settings.acs_allow_remote is False
        assert settings.acs_inform_interval == 600
        assert settings.acs_scrub_secrets is False

    def test_the_defaults_are_the_briefs(self, monkeypatch):
        monkeypatch.setenv("ROUTER_MANAGER_ACS_URL", "http://localhost:7557")
        settings = Settings.from_env()
        assert (settings.acs_inform_interval, settings.acs_scrub_secrets) == (300, True)

    def test_a_remote_nbi_is_refused_unless_explicitly_allowed(self, monkeypatch):
        monkeypatch.setenv("ROUTER_MANAGER_ACS_URL", "http://10.10.0.2:7557")
        with pytest.raises(ValueError, match="ROUTER_MANAGER_ACS_ALLOW_REMOTE=1"):
            Settings.from_env()
        monkeypatch.setenv("ROUTER_MANAGER_ACS_ALLOW_REMOTE", "1")
        settings = Settings.from_env()
        assert settings.acs_url == "http://10.10.0.2:7557" and settings.acs_allow_remote is True

    @pytest.mark.parametrize(
        ("name", "value", "expected"),
        [
            ("ROUTER_MANAGER_ACS_URL", "ftp://127.0.0.1:7557", "http or https"),
            ("ROUTER_MANAGER_ACS_URL", "http://127.0.0.1:7557/nbi", "path"),
            ("ROUTER_MANAGER_ACS_INFORM_INTERVAL", "30", "60 to 86400"),
            ("ROUTER_MANAGER_ACS_INFORM_INTERVAL", "five minutes", "60 to 86400"),
            ("ROUTER_MANAGER_ACS_SCRUB_SECRETS", "maybe", "ROUTER_MANAGER_ACS_SCRUB_SECRETS"),
            ("ROUTER_MANAGER_ACS_ALLOW_REMOTE", "perhaps", "ROUTER_MANAGER_ACS_ALLOW_REMOTE"),
        ],
    )
    def test_a_bad_acs_value_stops_startup(self, monkeypatch, name, value, expected):
        monkeypatch.setenv("ROUTER_MANAGER_ACS_URL", "http://127.0.0.1:7557")
        monkeypatch.setenv(name, value)
        with pytest.raises(ValueError, match=expected):
            Settings.from_env()

    def test_credentials_in_the_url_are_refused_without_being_repeated(self, monkeypatch):
        monkeypatch.setenv("ROUTER_MANAGER_ACS_URL", "http://nbi:hunter2-secret@127.0.0.1:7557")
        with pytest.raises(ValueError) as refused:
            Settings.from_env()
        assert "credentials" in str(refused.value)
        assert "hunter2-secret" not in str(refused.value)

    def test_acs_variables_are_ignored_while_the_feature_is_off(self, monkeypatch):
        monkeypatch.setenv("ROUTER_MANAGER_ACS_INFORM_INTERVAL", "junk")
        monkeypatch.setenv("ROUTER_MANAGER_ACS_ALLOW_REMOTE", "junk")
        assert Settings.from_env().acs_url is None

    def test_create_app_builds_the_service_from_settings(self, tmp_path: Path, nbi):
        app = make_app(tmp_path, acs_url=nbi.url, acs_inform_interval=900, acs_scrub_secrets=False)
        service = app.state.acs
        assert isinstance(service, AcsService)
        assert service.client.base_url == nbi.url
        assert service.secrets is app.state.manager.secrets, "ACS passphrases belong in the same vault"
        assert service.jobs.path == tmp_path / "data" / "acs_jobs.json"
        assert (service.inform_interval, service.scrub_secrets) == (900, False)
        # Building it contacts nothing.
        assert nbi.requests == []

    def test_the_cli_can_build_the_same_service(self, tmp_path: Path, nbi):
        data = tmp_path / "data"
        manager = DeviceManager(config_path=tmp_path / "devices.yaml", data_dir=data)
        base = {"username": "a", "password": "p", "secure_cookie": False, "scheduler_interval": 30}
        off = Settings(**base, config_path=tmp_path / "devices.yaml", data_dir=data)
        assert web.build_acs_service(off, manager) is None
        on = Settings(**base, config_path=tmp_path / "devices.yaml", data_dir=data, acs_url=nbi.url)
        service = web.build_acs_service(on, manager)
        assert isinstance(service, AcsService) and service.secrets is manager.secrets

    def test_create_app_refuses_a_remote_url_given_directly(self, tmp_path: Path):
        with pytest.raises(ValidationError, match="loopback"):
            make_app(tmp_path, acs_url="http://192.0.2.10:7557")


# --- session, CSRF and the switched-off feature ------------------------------------------------


class TestAccessControl:
    def test_every_acs_route_is_listed_here(self, tmp_path: Path, nbi):
        app = make_app(tmp_path, nbi)
        registered = {
            (method, route.path)
            for route in app.routes
            if getattr(route, "path", "").startswith("/api/acs")
            for method in getattr(route, "methods", ())
        }
        assert registered == TEMPLATES
        listed = {(m, p) for m, p in READS} | {(m, p) for m, p, _ in WRITES}
        assert len(listed) == len(TEMPLATES)

    def test_every_route_needs_a_session(self, tmp_path: Path, nbi):
        client = TestClient(make_app(tmp_path, nbi))
        for method, path, body in [(m, p, None) for m, p in READS] + WRITES:
            response = send(client, method, path, body)
            assert response.status_code == 401, (method, path, response.text)
        assert nbi.requests == []

    def test_every_change_needs_the_csrf_token(self, tmp_path: Path, nbi):
        tr181_router(nbi)
        client, _ = signed_in(make_app(tmp_path, nbi))
        for token in (None, "wrong"):
            headers = {"X-CSRF-Token": token} if token else {}
            for method, path, body in WRITES:
                response = send(client, method, path, body, headers=headers)
                assert response.status_code == 403, (method, path, response.text)
                assert response.json() == {"detail": "CSRF validation failed"}
        assert nbi.requests == [], "a request without a valid token reached the ACS"

    def test_everything_is_503_while_the_feature_is_off(self, tmp_path: Path):
        client, headers = signed_in(make_app(tmp_path))
        for method, path, body in [(m, p, None) for m, p in READS] + WRITES:
            response = send(client, method, path, body, headers=headers)
            assert response.status_code == 503, (method, path, response.text)
            assert response.json()["configured"] is False
            assert "ROUTER_MANAGER_ACS_URL" in response.json()["detail"]
            # The same security headers as every other response.
            assert "Content-Security-Policy" in response.headers

    def test_direct_devices_work_exactly_as_before_while_it_is_off(self, tmp_path: Path):
        client, headers = signed_in(make_app(tmp_path))
        assert client.get("/api/devices").status_code == 200
        added = client.post(
            "/api/devices", json={"id": "r1", "host": "192.0.2.1", "vendor": "cudy", "password": "p"}, headers=headers
        )
        assert added.status_code == 200, added.text


# --- reads -------------------------------------------------------------------------------------


class TestReads:
    def test_health(self, tmp_path: Path, nbi):
        client, _ = signed_in(make_app(tmp_path, nbi))
        health = client.get("/api/acs").json()
        assert health["configured"] is True and health["reachable"] is True
        assert health["version"] == nbi.version
        assert health["bootstrap"]["installed"] is False and health["bootstrap"]["drift"]

    def test_the_device_list_and_one_device(self, tmp_path: Path, nbi):
        router = tr181_router(nbi, tags=("shop",))
        client, _ = signed_in(make_app(tmp_path, nbi))
        listing = client.get("/api/acs/devices").json()
        assert listing["total"] == 1
        [summary] = listing["devices"]
        assert summary["acs_id"] == router and summary["model"] == "AX3000" and summary["tags"] == ["shop"]
        assert [(item["band"], item["ssid"]) for item in summary["wifi"]] == [("2.4GHz", "Home")]
        detail = client.get(f"/api/acs/devices/{quote(router, safe='')}").json()["device"]
        assert detail["acs_id"] == router and detail["pending_jobs"] == [] and detail["faults"] == []
        assert detail["wifi"][0]["passphrase"] == {"present": True, "writable": True}

    def test_search_tag_and_paging_reach_the_nbi(self, tmp_path: Path, nbi):
        tr181_router(nbi, "000001", tags=("shop",))
        tr181_router(nbi, "000002")
        client, _ = signed_in(make_app(tmp_path, nbi))
        assert client.get("/api/acs/devices?tag=shop").json()["total"] == 1
        page = client.get("/api/acs/devices?q=000002").json()
        assert [item["serial"] for item in page["devices"]] == ["000002"]
        second = client.get("/api/acs/devices?skip=1&limit=1").json()
        assert second["total"] == 2 and len(second["devices"]) == 1

    @pytest.mark.parametrize(
        "query",
        ["skip=-1", "skip=x", "limit=0", "limit=201", "limit=abc", "limit=1.5", "q=a/b", "q=a%20b", "tag=Not.A.Tag"],
    )
    def test_bad_search_parameters_are_400_before_any_request(self, tmp_path: Path, nbi, query):
        client, _ = signed_in(make_app(tmp_path, nbi))
        response = client.get(f"/api/acs/devices?{query}")
        assert response.status_code == 400, response.text
        assert nbi.requests == []

    def test_an_escaped_device_id_survives_the_round_trip(self, tmp_path: Path, nbi):
        # GenieACS escapes "-" in a serial as "%2D" (F5). The dashboard sends
        # encodeURIComponent(id), uvicorn decodes the path once, and the client
        # encodes it again for the NBI, which decodes it once more (brief §3.8).
        # TestClient decodes paths twice, so only a real server shows this.
        router = tr181_router(nbi, serial="AB-1")
        assert router == "202BC1-BM632w-AB%2D1"
        encoded = quote(router, safe="")
        assert encoded == "202BC1-BM632w-AB%252D1"
        with served(make_app(tmp_path, nbi)) as call:
            status, detail = call("GET", f"/api/acs/devices/{encoded}")
            assert status == 200, detail
            assert detail["device"]["acs_id"] == router
            status, tagged = call("POST", f"/api/acs/devices/{encoded}/tags/shop")
            assert status == 200, tagged
            assert tagged == {"acs_id": router, "tags": ["shop"]}
            assert nbi.devices[router]["_tags"] == ["shop"]
            # Sent raw, "%2D" decodes to "-" and names a different, malformed ID,
            # which is refused before GenieACS sees it.
            before = len(nbi.requests)
            status, refused = call("GET", f"/api/acs/devices/{router}")
            assert status == 400, refused
            assert len(nbi.requests) == before

    def test_an_unknown_device_is_404(self, tmp_path: Path, nbi):
        client, _ = signed_in(make_app(tmp_path, nbi))
        response = client.get(f"/api/acs/devices/{quote(make_device_id('202BC1', 'BM632w', '999999'), safe='')}")
        assert response.status_code == 404, response.text

    @pytest.mark.parametrize(
        ("method", "path"),
        [
            ("GET", "/api/acs/devices/not%20an%20id"),
            ("GET", "/api/acs/devices/A-B-C-D"),
            ("GET", "/api/acs/jobs/NOT-HEX"),
            ("GET", "/api/acs/jobs?acs_id=bad%20id"),
            ("GET", "/api/acs/jobs?active=perhaps"),
            ("DELETE", "/api/acs/jobs/0123"),
            ("POST", "/api/acs/faults/no-colon/retry"),
            ("DELETE", f"/api/acs/faults/{quote(DEVICE + ':task_xyz', safe='')}"),
            ("POST", f"/api/acs/devices/{ENC}/tags/Shop.Front"),
            ("POST", f"/api/acs/devices/{ENC}/tags/{'x' * 33}"),
            ("DELETE", f"/api/acs/devices/{ENC}/tags/UPPER"),
        ],
    )
    def test_ids_and_tags_are_validated_before_any_request(self, tmp_path: Path, nbi, method, path):
        client, headers = signed_in(make_app(tmp_path, nbi))
        response = client.request(method, path, headers=headers)
        assert response.status_code == 400, response.text
        assert nbi.requests == []

    def test_tags_and_adoption(self, tmp_path: Path, nbi):
        router = tr181_router(nbi, tags=("skybre_new",))
        client, headers = signed_in(make_app(tmp_path, nbi))
        path = f"/api/acs/devices/{quote(router, safe='')}"
        assert client.get("/api/acs/devices?tag=skybre_new").json()["total"] == 1
        assert client.post(f"{path}/tags/shop_42", headers=headers).json()["tags"] == ["skybre_new", "shop_42"]
        adopted = client.post(f"{path}/adopt", headers=headers)
        assert adopted.status_code == 200 and adopted.json() == {"acs_id": router, "tags": ["shop_42"]}
        assert client.get("/api/acs/devices?tag=skybre_new").json()["total"] == 0
        removed = client.delete(f"{path}/tags/shop_42", headers=headers)
        assert removed.json() == {"acs_id": router, "tags": []}

    def test_a_route_without_a_body_refuses_one(self, tmp_path: Path, nbi):
        router = tr181_router(nbi, tags=("skybre_new",))
        client, headers = signed_in(make_app(tmp_path, nbi))
        response = client.post(
            f"/api/acs/devices/{quote(router, safe='')}/adopt", json={"passphrase": PASS}, headers=headers
        )
        assert response.status_code == 400 and PASS not in response.text
        assert nbi.devices[router]["_tags"] == ["skybre_new"]

    def test_an_unreachable_acs_is_502(self, tmp_path: Path):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        client, _ = signed_in(make_app(tmp_path, acs_url=f"http://127.0.0.1:{port}"))
        response = client.get("/api/acs/devices")
        assert response.status_code == 502, response.text
        assert response.json()["detail"].startswith("ACS unavailable")
        # Health still answers, and says why.
        health = client.get("/api/acs")
        assert health.status_code == 200 and health.json()["reachable"] is False


# --- actions -----------------------------------------------------------------------------------


class TestActions:
    def test_refresh_is_a_job(self, tmp_path: Path, nbi):
        router = tr181_router(nbi)
        client, headers = signed_in(make_app(tmp_path, nbi))
        path = f"/api/acs/devices/{quote(router, safe='')}/refresh"
        response = client.post(path, json={"scope": "wifi"}, headers=headers)
        assert response.status_code == 202, response.text
        job = response.json()["job"]
        assert job["kind"] == "refresh" and job["request"]["scope"] == "wifi" and job["done"] is False
        assert [task["name"] for task in nbi.device_tasks(router)] == ["refreshObject"]

    @pytest.mark.parametrize("body", [{}, {"scope": "everything"}, {"scope": ["wifi"]}, {"scope": "wifi", "x": 1}])
    def test_refresh_body_is_validated(self, tmp_path: Path, nbi, body):
        router = tr181_router(nbi)
        client, headers = signed_in(make_app(tmp_path, nbi))
        response = client.post(f"/api/acs/devices/{quote(router, safe='')}/refresh", json=body, headers=headers)
        assert response.status_code == 400, response.text
        assert nbi.device_tasks(router) == []

    def test_a_scope_the_router_does_not_have_is_400(self, tmp_path: Path, nbi):
        router = nbi.add_device(
            build_device(
                serial="000181",
                leaves={
                    "Device.ManagementServer.PeriodicInformInterval": 300,
                    "Device.DeviceInfo.Manufacturer": {"value": "Acme", "writable": False},
                    "Device.LAN.IPAddress": "192.168.1.1",
                },
                last_inform=nbi.now(),
            )
        )
        client, headers = signed_in(make_app(tmp_path, nbi))
        response = client.post(
            f"/api/acs/devices/{quote(router, safe='')}/refresh", json={"scope": "wifi"}, headers=headers
        )
        assert response.status_code == 400, response.text
        assert "no wifi scope" in response.json()["detail"]

    @pytest.mark.parametrize("body", [{}, {"confirm": False}, {"confirm": "true"}, {"confirm": 1}])
    def test_reboot_needs_confirm_true(self, tmp_path: Path, nbi, body):
        router = tr181_router(nbi)
        client, headers = signed_in(make_app(tmp_path, nbi))
        response = client.post(f"/api/acs/devices/{quote(router, safe='')}/reboot", json=body, headers=headers)
        assert response.status_code == 400, response.text
        assert nbi.device_tasks(router) == []

    def test_reboot_is_a_job_that_can_be_followed_and_cancelled(self, tmp_path: Path, nbi):
        router = tr181_router(nbi)
        nbi.set_cr_outcome(router, 504)
        client, headers = signed_in(make_app(tmp_path, nbi))
        started = client.post(
            f"/api/acs/devices/{quote(router, safe='')}/reboot", json={"confirm": True}, headers=headers
        )
        assert started.status_code == 202, started.text
        job = started.json()["job"]
        assert job["kind"] == "reboot" and job["state"] == "waiting_for_checkin"
        assert client.get(f"/api/acs/jobs/{job['id']}").json()["job"]["id"] == job["id"]
        active = client.get("/api/acs/jobs?active=true").json()["jobs"]
        assert [item["id"] for item in active] == [job["id"]]
        assert client.get(f"/api/acs/jobs?acs_id={quote(router, safe='')}").json()["jobs"][0]["id"] == job["id"]
        cancelled = client.delete(f"/api/acs/jobs/{job['id']}", headers=headers)
        assert cancelled.status_code == 200 and cancelled.json()["job"]["state"] == "cancelled"
        assert nbi.device_tasks(router) == []
        assert client.get("/api/acs/jobs?active=1").json()["jobs"] == []

    def test_an_unknown_job_is_404(self, tmp_path: Path, nbi):
        client, headers = signed_in(make_app(tmp_path, nbi))
        assert client.get(f"/api/acs/jobs/{JOB}").status_code == 404
        assert client.delete(f"/api/acs/jobs/{JOB}", headers=headers).status_code == 404

    def test_cancel_while_the_router_is_mid_session_is_409_then_works(self, tmp_path: Path, nbi):
        router = tr181_router(nbi)
        nbi.set_cr_outcome(router, 504)
        client, headers = signed_in(make_app(tmp_path, nbi))
        job = client.post(
            f"/api/acs/devices/{quote(router, safe='')}/wifi", json={"band": "all", "ssid": "Home-2"}, headers=headers
        ).json()["job"]
        nbi.set_busy(router, times=1)
        busy = client.delete(f"/api/acs/jobs/{job['id']}", headers=headers)
        assert busy.status_code == 409, busy.text
        assert "mid-session" in busy.json()["detail"]
        assert client.delete(f"/api/acs/jobs/{job['id']}", headers=headers).json()["job"]["state"] == "cancelled"

    def test_faults_can_be_retried_and_cleared(self, tmp_path: Path, nbi):
        router = tr181_router(nbi)
        client, headers = signed_in(make_app(tmp_path, nbi))
        for channel in ("skybre-refresh", "skybre-inform"):
            fault_id = f"{router}:{channel}"
            nbi.faults[fault_id] = {"_id": fault_id, "device": router, "channel": channel, "code": "script.Error"}
        retried = client.post(f"/api/acs/faults/{quote(router + ':skybre-refresh', safe='')}/retry", headers=headers)
        assert retried.status_code == 200, retried.text
        assert retried.json()["action"] == "cleared" and retried.json()["connection_request"]["ok"] is True
        cleared = client.delete(f"/api/acs/faults/{quote(router + ':skybre-inform', safe='')}", headers=headers)
        assert cleared.json() == {"fault_id": f"{router}:skybre-inform", "cleared": True}
        assert nbi.faults == {}

    def test_the_bootstrap_needs_confirm_and_asks_before_removing_seeded_presets(self, tmp_path: Path, nbi):
        nbi.presets["default"] = {"_id": "default", "weight": 0, "configurations": [{"type": "age", "name": "x"}]}
        client, headers = signed_in(make_app(tmp_path, nbi))
        assert client.post("/api/acs/bootstrap", json={}, headers=headers).status_code == 400
        bad = client.post("/api/acs/bootstrap", json={"confirm": True, "remove_seeded": "yes"}, headers=headers)
        assert bad.status_code == 400
        refused = client.post("/api/acs/bootstrap", json={"confirm": True}, headers=headers)
        assert refused.status_code == 409, refused.text
        assert refused.json()["seeded"] == ["default"]
        assert not nbi.provisions, "a refused bootstrap wrote something"
        report = client.post("/api/acs/bootstrap", json={"confirm": True, "remove_seeded": True}, headers=headers)
        assert report.status_code == 200, report.text
        assert report.json()["removed_seeded"] == ["default"]
        assert client.get("/api/acs").json()["bootstrap"]["installed"] is True


# --- the Wi-Fi route and its passphrase ------------------------------------------------------------


class TestWifi:
    def test_a_change_is_a_job_and_the_passphrase_never_comes_back(self, tmp_path: Path, nbi, caplog):
        caplog.set_level(logging.DEBUG)
        router = tr181_router(nbi)
        nbi.set_cr_outcome(router, 200, session=True)
        app = make_app(tmp_path, nbi)
        client, headers = signed_in(app)
        response = client.post(
            f"/api/acs/devices/{quote(router, safe='')}/wifi",
            json={"band": "2.4GHz", "ssid": "Home-2", "passphrase": PASS},
            headers=headers,
        )
        assert response.status_code == 202, response.text
        job = response.json()["job"]
        assert job["kind"] == "wifi" and job["request"] == {
            "band": "2.4GHz",
            "ssid": "Home-2",
            "passphrase": True,
            "confirm_guessed_band": False,
        }
        # It did reach the router, through GenieACS's write task.
        assert nbi.cpes[router].leaves[f"{WIFI}.AccessPoint.1.Security.KeyPassphrase"].value == PASS
        app.state.acs.poll_jobs()
        seen = [
            response.text,
            client.get(f"/api/acs/jobs/{job['id']}").text,
            client.get("/api/acs/jobs").text,
            client.get(f"/api/acs/devices/{quote(router, safe='')}").text,
            client.get("/api/acs/devices").text,
            client.get("/api/acs").text,
            app.state.acs.jobs.path.read_text(),
            caplog.text,
        ]
        for text in seen:
            assert PASS not in text
        assert client.get(f"/api/acs/jobs/{job['id']}").json()["job"]["state"] in ("acknowledged", "verified")

    @pytest.mark.parametrize(
        "body",
        [
            {"passphrase": PASS},
            {"band": "7GHz", "passphrase": PASS},
            {"band": ["all"], "passphrase": PASS},
            {"band": "all"},
            {"band": "all", "ssid": None, "passphrase": None},
            {"band": "all", "ssid": 5},
            {"band": "all", "passphrase": 12345678},
            {"band": "all", "ssid": "x", "confirm_guessed_band": "yes"},
            {"band": "all", "password": PASS},
            {"band": "all", "passphrase": PASS, "wifi_password": PASS},
            {"band": "all", "passphrase": "short"},
            {"band": "all", "passphrase": PASS + "é"},
            {"band": "all", "ssid": "x" * 33},
            {"band": "all", "ssid": ""},
        ],
    )
    def test_bad_bodies_are_400_and_quote_no_passphrase(self, tmp_path: Path, nbi, caplog, body):
        caplog.set_level(logging.DEBUG)
        router = tr181_router(nbi)
        client, headers = signed_in(make_app(tmp_path, nbi))
        response = client.post(f"/api/acs/devices/{quote(router, safe='')}/wifi", json=body, headers=headers)
        assert response.status_code == 400, response.text
        assert PASS not in response.text and PASS not in caplog.text
        assert nbi.device_tasks(router) == []

    @pytest.mark.parametrize(
        ("path", "body"),
        [
            ("refresh", {"scope": "wifi", "passphrase": PASS}),
            ("reboot", {"confirm": True, "passphrase": PASS}),
        ],
    )
    def test_the_passphrase_is_accepted_on_the_wifi_route_only(self, tmp_path: Path, nbi, path, body):
        router = tr181_router(nbi)
        client, headers = signed_in(make_app(tmp_path, nbi))
        response = client.post(f"/api/acs/devices/{quote(router, safe='')}/{path}", json=body, headers=headers)
        assert response.status_code == 400
        assert response.json()["detail"] == "unexpected field(s): passphrase"
        assert nbi.device_tasks(router) == []

    def test_a_guessed_band_needs_confirmation_and_says_why(self, tmp_path: Path, nbi):
        router = tr098_router(nbi)
        client, headers = signed_in(make_app(tmp_path, nbi))
        path = f"/api/acs/devices/{quote(router, safe='')}/wifi"
        asked = client.post(path, json={"band": "2.4GHz", "passphrase": PASS}, headers=headers)
        assert asked.status_code == 409, asked.text
        assert "inferred" in asked.json()["detail"]
        plan = asked.json()["plan"]
        assert plan["band_guessed"] is True and plan["band"] == "2.4GHz"
        assert PASS not in asked.text
        assert nbi.device_tasks(router) == [] and client.get("/api/acs/jobs").json()["jobs"] == []
        confirmed = client.post(
            path, json={"band": "2.4GHz", "passphrase": PASS, "confirm_guessed_band": True}, headers=headers
        )
        assert confirmed.status_code == 202, confirmed.text
        assert PASS not in confirmed.text

    def test_writing_every_band_needs_no_confirmation(self, tmp_path: Path, nbi):
        router = tr098_router(nbi)
        client, headers = signed_in(make_app(tmp_path, nbi))
        response = client.post(
            f"/api/acs/devices/{quote(router, safe='')}/wifi", json={"band": "all", "ssid": "Shop-2"}, headers=headers
        )
        assert response.status_code == 202, response.text


# --- error mapping and the secret guard, with a stub service -------------------------------------


class StubAcs:
    """Answers every AcsService call with ``result``, or raises ``error``."""

    def __init__(self, result: Any = None, error: BaseException | None = None):
        self.result = result
        self.error = error
        self.calls: list[tuple[str, tuple[Any, ...]]] = []

    def __getattr__(self, name: str):
        def method(*args: Any, **kwargs: Any) -> Any:
            self.calls.append((name, args))
            if self.error is not None:
                raise self.error
            return self.result

        return method


class TestErrorMapping:
    @pytest.mark.parametrize(
        ("error", "status", "extra"),
        [
            (AcsNotFound("No such device", status=404), 404, {}),
            (AcsBusy("the router is mid-session; try again"), 409, {}),
            (AcsUnavailable("ACS unavailable (GET /devices): refused"), 502, {"outcome_unknown": False}),
            (AcsUnavailable("the reply was lost", outcome_unknown=True), 502, {"outcome_unknown": True}),
            (AcsRejected("ACS rejected the request as invalid"), 502, {}),
            (AcsError("GenieACS 1.3.0-dev is not supported"), 502, {}),
            (ValidationError("the Wi-Fi change cannot be made: no such network"), 400, {}),
            (AcsConfirmationRequired("confirm the band", {"band": "5GHz", "band_guessed": True}), 409, {}),
            (BootstrapRefused("seeded presets exist", seeded=["default"]), 409, {"seeded": ["default"]}),
        ],
    )
    def test_service_errors_map_to_statuses(self, tmp_path: Path, error, status, extra):
        client, headers = signed_in(make_app(tmp_path, acs_service=StubAcs(error=error)))
        response = client.post(f"/api/acs/devices/{ENC}/wifi", json={"band": "all", "ssid": "x"}, headers=headers)
        assert response.status_code == status, response.text
        body = response.json()
        for key, value in extra.items():
            assert body[key] == value
        if isinstance(error, AcsConfirmationRequired):
            assert body["plan"] == {"band": "5GHz", "band_guessed": True}
        if isinstance(error, AcsUnavailable):
            assert body["detail"].startswith("ACS unavailable")
        assert "Content-Security-Policy" in response.headers

    def test_a_damaged_job_file_is_a_500_that_names_it(self, tmp_path: Path, caplog):
        stub = StubAcs(error=JobStoreError("ACS job file /x/acs_jobs.json is corrupt"))
        client, _ = signed_in(make_app(tmp_path, acs_service=stub))
        response = client.get(f"/api/acs/jobs/{JOB}")
        assert response.status_code == 500
        assert "acs_jobs.json is corrupt" in response.json()["detail"]

    def test_routes_hand_the_service_what_it_expects(self, tmp_path: Path):
        stub = StubAcs(result={"id": JOB})
        client, headers = signed_in(make_app(tmp_path, acs_service=stub))
        client.get("/api/acs/devices?q=AX&tag=shop&skip=5&limit=10")
        client.get("/api/acs/devices")
        client.post(f"/api/acs/devices/{ENC}/wifi", json={"band": "5GHz", "passphrase": PASS}, headers=headers)
        client.post("/api/acs/bootstrap", json={"confirm": True}, headers=headers)
        client.get("/api/acs/jobs?active=true")
        assert stub.calls == [
            ("list_devices", ("AX", "shop", 5, 10)),
            ("list_devices", (None, None, 0, 50)),
            ("set_wifi", (DEVICE, "5GHz", None, PASS, False)),
            ("bootstrap", (False,)),
            ("list_jobs", (None, True)),
        ]

    def test_an_error_that_quotes_the_passphrase_is_withheld(self, tmp_path: Path, caplog):
        caplog.set_level(logging.DEBUG)
        stub = StubAcs(error=AdapterError(f"the ACS said no to {PASS}"))
        client, headers = signed_in(make_app(tmp_path, acs_service=stub))
        response = client.post(WIFI_ROUTE, json={"band": "all", "passphrase": PASS}, headers=headers)
        assert response.status_code == 502
        assert "withheld" in response.json()["detail"]
        assert PASS not in response.text and PASS not in caplog.text

    def test_a_plan_that_quotes_the_passphrase_is_withheld(self, tmp_path: Path):
        stub = StubAcs(error=AcsConfirmationRequired("confirm", {"leaves": [PASS]}))
        client, headers = signed_in(make_app(tmp_path, acs_service=stub))
        response = client.post(WIFI_ROUTE, json={"band": "5GHz", "passphrase": PASS}, headers=headers)
        assert response.status_code == 409 and PASS not in response.text

    def test_a_job_that_quotes_the_passphrase_is_cut_down(self, tmp_path: Path, caplog):
        caplog.set_level(logging.DEBUG)
        job = {"id": JOB, "acs_id": DEVICE, "kind": "wifi", "state": "queued", "terminal": False, "done": False}
        stub = StubAcs(result={**job, "message": f"sending {PASS}"})
        client, headers = signed_in(make_app(tmp_path, acs_service=stub))
        response = client.post(WIFI_ROUTE, json={"band": "all", "passphrase": PASS}, headers=headers)
        assert response.status_code == 202
        assert PASS not in response.text and PASS not in caplog.text
        assert {key: response.json()["job"][key] for key in job} == job


# --- the poll loop -----------------------------------------------------------------------------


class PollingStub:
    def __init__(self, failures: list[BaseException], active: bool):
        self.failures = list(failures)
        self.active = active
        self.polls: list[float] = []
        self.done = threading.Event()

    def poll_jobs(self) -> None:
        self.polls.append(time.monotonic())
        if len(self.polls) >= 5:
            self.done.set()
        if self.failures:
            raise self.failures.pop(0)

    def has_active_jobs(self) -> bool:
        return self.active

    def refresh(self, acs_id: str, scope: str) -> dict[str, Any]:
        return {"id": JOB}


class TestPollLoop:
    def test_the_loop_survives_errors_and_logs_them(self, tmp_path: Path, monkeypatch, caplog):
        caplog.set_level(logging.INFO, logger="cudy_manager.web")
        monkeypatch.setattr(web, "ACS_POLL_ACTIVE", 0.01)
        monkeypatch.setattr(web, "ACS_POLL_IDLE", 0.01)
        stub = PollingStub([RuntimeError("boom"), JobStoreError("ACS job file is corrupt")], active=True)
        with TestClient(make_app(tmp_path, acs_service=stub)) as client:
            assert client.get("/healthz").status_code == 200
            assert stub.done.wait(5), "the poll loop stopped after an error"
        assert "ACS job poll failed" in caplog.text and "boom" in caplog.text
        assert "ACS jobs cannot advance: ACS job file is corrupt" in caplog.text

    @pytest.mark.parametrize("active", [True, False])
    def test_the_interval_follows_whether_jobs_are_active(self, tmp_path: Path, monkeypatch, active):
        monkeypatch.setattr(web, "ACS_POLL_ACTIVE", 0.02)
        monkeypatch.setattr(web, "ACS_POLL_IDLE", 30.0)
        stub = PollingStub([], active=active)
        with TestClient(make_app(tmp_path, acs_service=stub)):
            finished = stub.done.wait(1.5)
        assert finished is active, stub.polls
        # The first poll runs at startup either way.
        assert stub.polls

    def test_the_real_loop_moves_a_job_along(self, tmp_path: Path, nbi, monkeypatch):
        # Idle for longer than the test runs: starting the job has to wake the loop.
        monkeypatch.setattr(web, "ACS_POLL_ACTIVE", 0.05)
        monkeypatch.setattr(web, "ACS_POLL_IDLE", 60.0)
        router = tr181_router(nbi)
        nbi.set_cr_outcome(router, 504)
        app = make_app(tmp_path, nbi)
        with TestClient(app) as client:
            response = client.post("/login", json={"username": "admin", "password": PASSWORD})
            headers = {"X-CSRF-Token": response.json()["csrf_token"]}
            job = client.post(
                f"/api/acs/devices/{quote(router, safe='')}/reboot", json={"confirm": True}, headers=headers
            ).json()["job"]
            nbi.run_session(router, cr=False)
            deadline = time.monotonic() + 5
            state = job["state"]
            while time.monotonic() < deadline and state == "waiting_for_checkin":
                time.sleep(0.05)
                state = client.get(f"/api/acs/jobs/{job['id']}").json()["job"]["state"]
        assert state != "waiting_for_checkin", "the lifespan poll loop never advanced the job"

    def test_starting_a_job_wakes_an_idle_loop(self, tmp_path: Path, monkeypatch):
        monkeypatch.setattr(web, "ACS_POLL_IDLE", 60.0)
        stub = PollingStub([], active=False)
        with TestClient(make_app(tmp_path, acs_service=stub)) as client:
            response = client.post("/login", json={"username": "admin", "password": PASSWORD})
            headers = {"X-CSRF-Token": response.json()["csrf_token"]}
            deadline = time.monotonic() + 5
            while not stub.polls and time.monotonic() < deadline:
                time.sleep(0.01)
            first = len(stub.polls)
            started = client.post(f"/api/acs/devices/{ENC}/refresh", json={"scope": "wifi"}, headers=headers)
            assert started.status_code == 202, started.text
            while len(stub.polls) == first and time.monotonic() < deadline:
                time.sleep(0.01)
        assert len(stub.polls) > first, "the loop slept out its idle interval after a job started"

    def test_no_loop_runs_while_the_feature_is_off(self, tmp_path: Path, monkeypatch):
        app = make_app(tmp_path)
        with TestClient(app) as client:
            assert client.get("/healthz").status_code == 200
        assert app.state.acs is None

    def test_the_server_starts_from_its_environment_as_before_without_the_url(self, tmp_path: Path, monkeypatch):
        # The path `router-manager serve` takes, rather than hand-built Settings: no
        # ROUTER_MANAGER_ACS_* variable at all, as on every install from before GenieACS.
        data = tmp_path / "state"
        monkeypatch.setenv("ROUTER_MANAGER_PASSWORD", PASSWORD)
        monkeypatch.setenv("ROUTER_MANAGER_DATA_DIR", str(data))
        monkeypatch.setenv("ROUTER_MANAGER_SCHEDULER_INTERVAL", "3600")
        assert not [name for name in os.environ if name.startswith("ROUTER_MANAGER_ACS_")]
        app = create_app()
        assert app.state.acs is None and app.state.settings.acs_url is None
        with TestClient(app) as client:
            assert app.state.acs_wake is None, "the ACS poll loop started"
            response = client.post("/login", json={"username": "admin", "password": PASSWORD})
            assert response.status_code == 200, response.text
            headers = {"X-CSRF-Token": response.json()["csrf_token"]}
            added = client.post(
                "/api/devices",
                json={"id": "r1", "host": "192.0.2.1", "vendor": "cudy", "password": "p"},
                headers=headers,
            )
            assert added.status_code == 200, added.text
            assert [device["id"] for device in client.get("/api/devices").json()["devices"]] == ["r1"]
            off = client.get("/api/acs")
            assert off.status_code == 503 and off.json()["configured"] is False
        # Nothing of the ACS feature is left behind in the state directory.
        assert not (data / "acs_jobs.json").exists()
        assert not [path.name for path in data.iterdir() if "acs" in path.name]


# --- the direct Wi-Fi password route ------------------------------------------------------------


class TestDirectWifiPassword:
    NEW = "brand-new-wifi-pass-42"

    def _app(self, tmp_path: Path, vendor: str = "cudy", transport: str | None = None):
        app = make_app(tmp_path)
        client, headers = signed_in(app)
        body: dict[str, Any] = {"id": "r1", "host": "192.0.2.1", "vendor": vendor, "password": "admin-pass"}
        if transport:
            body["transport"] = transport
        response = client.post("/api/devices", json=body, headers=headers)
        assert response.status_code == 200, response.text
        return app, client, headers

    def _record(self, app, monkeypatch, result: Any = True):
        calls: list[tuple[Any, ...]] = []

        def fake(*args: Any) -> Any:
            calls.append(args)
            if isinstance(result, BaseException):
                raise result
            return result

        monkeypatch.setattr(app.state.manager, "set_wifi_password", fake)
        return calls

    def test_it_needs_a_session_and_the_csrf_token(self, tmp_path: Path, monkeypatch):
        app, client, _ = self._app(tmp_path)
        calls = self._record(app, monkeypatch)
        body = {"password": self.NEW, "confirm": True}
        assert client.post("/api/devices/r1/wifi-password", json=body).status_code == 403
        wrong = client.post("/api/devices/r1/wifi-password", json=body, headers={"X-CSRF-Token": "nope"})
        assert wrong.status_code == 403
        assert TestClient(app).post("/api/devices/r1/wifi-password", json=body).status_code == 401
        assert calls == []

    def test_it_reaches_the_manager_and_never_echoes_the_password(self, tmp_path: Path, monkeypatch, caplog):
        caplog.set_level(logging.DEBUG)
        app, client, headers = self._app(tmp_path)
        calls = self._record(app, monkeypatch)
        for radio in (None, "2.4G", "5G"):
            body: dict[str, Any] = {"password": self.NEW, "confirm": True}
            if radio:
                body["radio"] = radio
            response = client.post("/api/devices/r1/wifi-password", json=body, headers=headers)
            assert response.status_code == 200, response.text
            assert response.json() == {"device": "r1", "status": "changed", "radio": radio}
            assert self.NEW not in response.text
        assert calls == [("r1", self.NEW, None), ("r1", self.NEW, "2.4G"), ("r1", self.NEW, "5G")]
        assert self.NEW not in caplog.text

    @pytest.mark.parametrize(
        "body",
        [
            {"password": NEW},
            {"password": NEW, "confirm": False},
            {"password": NEW, "confirm": "true"},
            {"confirm": True},
            {"password": "", "confirm": True},
            {"password": 12345678, "confirm": True},
            {"password": NEW, "confirm": True, "radio": "6G"},
            {"password": NEW, "confirm": True, "radio": ["5G"]},
            {"password": NEW, "confirm": True, "radio": ""},
            {"password": NEW, "confirm": True, "ssid": "x"},
        ],
    )
    def test_bad_bodies_are_400_before_the_router_is_contacted(self, tmp_path: Path, monkeypatch, body):
        app, client, headers = self._app(tmp_path)
        calls = self._record(app, monkeypatch)
        response = client.post("/api/devices/r1/wifi-password", json=body, headers=headers)
        assert response.status_code == 400, response.text
        assert self.NEW not in response.text
        assert calls == []

    @pytest.mark.parametrize("password", ["short", "x" * 64, "café-password", "tab\there-password"])
    def test_the_managers_passphrase_rules_are_400(self, tmp_path: Path, password):
        _, client, headers = self._app(tmp_path)
        response = client.post(
            "/api/devices/r1/wifi-password", json={"password": password, "confirm": True}, headers=headers
        )
        assert response.status_code == 400, response.text
        assert "Wi-Fi password" in response.json()["detail"]
        assert password not in response.text

    def test_an_unknown_device_is_404(self, tmp_path: Path):
        _, client, headers = self._app(tmp_path)
        response = client.post(
            "/api/devices/nope/wifi-password", json={"password": self.NEW, "confirm": True}, headers=headers
        )
        assert response.status_code == 404

    def test_a_router_that_cannot_do_it_is_501_not_a_gateway_error(self, tmp_path: Path):
        # The Tenda adapter refuses before contacting anything.
        _, client, headers = self._app(tmp_path, vendor="tenda")
        response = client.post(
            "/api/devices/r1/wifi-password", json={"password": self.NEW, "confirm": True}, headers=headers
        )
        assert response.status_code == 501, response.text
        assert "not supported" in response.json()["detail"]

    def test_an_unsupported_operation_from_the_manager_is_501(self, tmp_path: Path, monkeypatch):
        app, client, headers = self._app(tmp_path)
        self._record(app, monkeypatch, UnsupportedOperation("Smart Connect joins both bands into one network"))
        response = client.post(
            "/api/devices/r1/wifi-password",
            json={"password": self.NEW, "confirm": True, "radio": "5G"},
            headers=headers,
        )
        assert response.status_code == 501 and "Smart Connect" in response.json()["detail"]

    def test_an_unconfirmed_change_is_502(self, tmp_path: Path, monkeypatch):
        app, client, headers = self._app(tmp_path)
        self._record(app, monkeypatch, False)
        response = client.post(
            "/api/devices/r1/wifi-password", json={"password": self.NEW, "confirm": True}, headers=headers
        )
        assert response.status_code == 502 and "did not confirm" in response.json()["detail"]

    def test_a_router_error_that_quotes_the_password_is_withheld(self, tmp_path: Path, monkeypatch, caplog):
        caplog.set_level(logging.DEBUG)
        app, client, headers = self._app(tmp_path)
        self._record(app, monkeypatch, AdapterError(f"uci: invalid key {self.NEW}"))
        response = client.post(
            "/api/devices/r1/wifi-password", json={"password": self.NEW, "confirm": True}, headers=headers
        )
        assert response.status_code == 502
        assert "withheld" in response.json()["detail"]
        assert self.NEW not in response.text and self.NEW not in caplog.text

    def test_an_unexpected_crash_that_quotes_the_password_is_withheld_too(self, tmp_path: Path, monkeypatch, caplog):
        caplog.set_level(logging.DEBUG)
        app, client, headers = self._app(tmp_path)
        self._record(app, monkeypatch, RuntimeError(f"surprise {self.NEW}"))
        response = client.post(
            "/api/devices/r1/wifi-password", json={"password": self.NEW, "confirm": True}, headers=headers
        )
        assert response.status_code == 500
        assert self.NEW not in response.text and self.NEW not in caplog.text


# --- the dashboard -----------------------------------------------------------------------------


def run_page(tmp_path: Path, scenario: str, setup: str = "") -> dict:
    """test_web.run_dashboard, pinned to UTC so check-in times read the same everywhere."""
    tree, script = _dashboard_markup()
    harness = tmp_path / "dashboard_harness.js"
    harness.write_text(DASHBOARD_HARNESS, encoding="utf-8")
    payload = json.dumps({"tree": tree, "script": script, "setup": setup, "scenario": scenario})
    assert NODE is not None
    completed = subprocess.run(
        [NODE, str(harness)],
        input=payload,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env={**os.environ, "TZ": "UTC"},
    )
    assert completed.returncode == 0, completed.stderr
    outcome = json.loads(completed.stdout)
    assert outcome["errors"] == [], outcome["errors"]
    return outcome


# A configured ACS with one router on two bands, the 5 GHz one only inferred.
ACS_SETUP = r"""
const minutesAgo = m => new Date(Date.now() - m * 60000).toISOString();
const todayAt = (h, m) => { const d = new Date(); d.setUTCHours(h, m, 0, 0); return d.toISOString(); };
const router = {
  acs_id: '202BC1-BM632w-AB%2D1', manufacturer: 'Acme', model: 'AX3000', serial: 'AB-1', firmware: '1.2.3',
  data_model: 'tr181', profile: 'generic-tr181', online: true, last_inform: minutesAgo(3),
  expected_by: minutesAgo(-2), inform_interval: 300, tags: ['shop'],
  wifi: [
    {band: '2.4GHz', band_source: 'reported', ssid: 'Home', enabled: true, as_of: minutesAgo(10)},
    {band: '5GHz', band_source: 'guessed', ssid: 'Home-5G', enabled: true, as_of: minutesAgo(10)},
  ],
};
harness.acs = {
  health: {configured: true, reachable: true, version: '1.2.16+20260329', error: null,
           bootstrap: {installed: true, drift: [], seeded_presets: []}, channel_faults: [], problems: [],
           jobs: {active: 0}},
  devices: [router], inbox: [], jobs: [],
};
const makeJob = (state, extra = {}) => Object.assign({
  id: 'a1b2c3d4e5f60718', acs_id: router.acs_id, kind: 'wifi', state, message: '', expected_by: null,
  cr_attempts: [], last_error: null,
  terminal: !['queued', 'contacting_router', 'waiting_for_checkin'].includes(state),
  done: !['queued', 'contacting_router', 'waiting_for_checkin'].includes(state),
}, extra);
harness.acsReply = () => undefined;
harness.handler = (path, options, record) => {
  const custom = harness.acsReply(path, options, record);
  if (custom) return custom;
  if (path === '/api/acs') return {status: 200, body: harness.acs.health};
  if (path.startsWith('/api/acs/devices?tag=skybre_new')) {
    return {status: 200, body: {devices: harness.acs.inbox, total: harness.acs.inbox.length}};
  }
  if (path.startsWith('/api/acs/devices?')) {
    return {status: 200, body: {devices: harness.acs.devices, total: harness.acs.devices.length}};
  }
  if (path.startsWith('/api/acs/jobs?')) return {status: 200, body: {jobs: harness.acs.jobs}};
};
"""


def sent(outcome: dict, suffix: str, method: str = "POST") -> list[Any]:
    return [item["body"] for item in outcome["requests"] if item["method"] == method and item["path"].endswith(suffix)]


@needs_node
class TestDashboardAcs:
    def test_the_managed_tab_stays_hidden_while_the_acs_is_off(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            harness.handler = path => (path === '/api/acs'
              ? {status: 503, body: {detail: 'off', configured: false}} : undefined);
            await initAcs();
            return {
              tabs: document.getElementById('tabs').hidden,
              direct: document.getElementById('direct-view').hidden,
              acs: document.getElementById('acs-view').hidden,
              notice: document.getElementById('notice').textContent,
            };
            """,
        )
        assert outcome["result"] == {"tabs": True, "direct": False, "acs": True, "notice": ""}
        assert not [item for item in outcome["requests"] if item["path"].startswith("/api/acs/")]

    def test_the_managed_tab_shows_the_fleet(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            await harness.flush();
            const view = document.getElementById('acs-view');
            const cardNode = document.getElementById('acs-devices').querySelector('article');
            return {
              tabs: document.getElementById('tabs').hidden, acs: view.hidden,
              direct: document.getElementById('direct-view').hidden,
              selected: document.getElementById('tab-acs').getAttribute('aria-selected'),
              addHidden: document.getElementById('add-button').hidden,
              text: cardNode.textContent, buttons: harness.buttons(cardNode),
              health: document.getElementById('acs-health').textContent,
              page: document.getElementById('acs-page').textContent,
              inboxHidden: document.getElementById('acs-inbox').hidden,
            };
            """,
            setup=ACS_SETUP,
        )
        result = outcome["result"]
        assert (result["tabs"], result["acs"], result["direct"], result["selected"]) == (False, False, True, "true")
        assert result["addHidden"] is True, "Add device is for direct routers only"
        for expected in ("AX3000", "Acme", "serial AB-1", "online", "1.2.3", "3 min ago", "TR-181", "Wi-Fi 2.4 GHz",
                         "Home", "Wi-Fi 5 GHz", "Home-5G", "as of 10 min ago", "band inferred", "shop"):
            assert expected in result["text"], expected
        assert result["buttons"] == ["Refresh", "Change Wi-Fi", "Reboot", "Tags"]
        assert "GenieACS 1.2.16+20260329 is connected" in result["health"]
        assert result["page"] == "1–1 of 1"
        assert result["inboxHidden"] is True

    def test_actions_are_disabled_with_a_reason_where_they_cannot_work(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            const out = {};
            for (const model of ['tr181-issue1', 'unknown', 'tr098']) {
              const node = acsCard(Object.assign({}, router, {data_model: model}));
              const wifi = harness.button(node, 'Change Wi-Fi');
              const refresh = harness.button(node, 'Refresh');
              out[model] = [wifi.disabled, Boolean(wifi.title), refresh.disabled];
            }
            return out;
            """,
            setup=ACS_SETUP,
        )
        assert outcome["result"] == {
            "tr181-issue1": [True, True, False],
            "unknown": [True, True, True],
            "tr098": [False, False, False],
        }

    def test_change_wifi_sends_one_request_and_forgets_the_password(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            await harness.flush();
            harness.acsReply = (path, options) => (path.endsWith('/wifi') && options.method === 'POST'
              ? {status: 202, body: {job: makeJob('queued')}} : undefined);
            const cardNode = document.getElementById('acs-devices').querySelector('article');
            harness.button(cardNode, 'Change Wi-Fi').click();
            const dialog = document.getElementById('acs-wifi-dialog');
            const form = document.getElementById('acs-wifi-form');
            const bands = form.elements.band.options.map(option => [option.value, option.textContent]);
            const warning = dialog.querySelector('.warning').textContent;
            form.elements.band.value = '2.4GHz';
            form.elements.ssid.value = ' New-Home ';
            form.elements.passphrase.value = 'zq-Wifi-Passphrase-7731';
            form.elements.repeat.value = 'zq-Wifi-Passphrase-7731';
            await harness.submit(form);
            await harness.flush();
            return {
              bands, warning, open: dialog.open, left: form.elements.passphrase.value + form.elements.repeat.value,
              toast: document.getElementById('toasts').textContent,
              notice: document.getElementById('notice').textContent,
            };
            """,
            setup=ACS_SETUP,
        )
        result = outcome["result"]
        assert result["bands"] == [
            ["all", "All bands"],
            ["2.4GHz", "2.4 GHz — Home"],
            ["5GHz", "5 GHz — Home-5G (band inferred)"],
        ]
        assert "will be disconnected" in result["warning"]
        assert sent(outcome, "/wifi") == [{"band": "2.4GHz", "ssid": "New-Home", "passphrase": PASS}]
        [post] = [item for item in outcome["requests"] if item["path"].endswith("/wifi")]
        assert post["path"] == "/api/acs/devices/202BC1-BM632w-AB%252D1/wifi"
        assert result["open"] is False and result["left"] == ""
        assert "Wi-Fi change · AX3000 · AB-1" in result["toast"]
        assert "Queued — sending it to the router now." in result["toast"]
        assert PASS not in result["toast"] + result["notice"]

    @pytest.mark.parametrize(
        ("ssid", "passphrase", "repeat", "expected"),
        [
            ("", "", "", "Enter a new network name, a new Wi-Fi password, or both"),
            ("", "zq-Wifi-Passphrase-7731", "zq-Wifi-Passphrase-7732", "do not match"),
            ("", "short", "short", "8 to 63 characters"),
            ("", "café-passphrase", "café-passphrase", "8 to 63 characters"),
        ],
    )
    def test_change_wifi_checks_the_form_before_sending(self, tmp_path: Path, ssid, passphrase, repeat, expected):
        outcome = run_page(
            tmp_path,
            f"""
            await harness.flush();
            showAcsWifi(router);
            const form = document.getElementById('acs-wifi-form');
            form.elements.ssid.value = {json.dumps(ssid)};
            form.elements.passphrase.value = {json.dumps(passphrase)};
            form.elements.repeat.value = {json.dumps(repeat)};
            await harness.submit(form);
            return [document.getElementById('notice').textContent, document.getElementById('acs-wifi-dialog').open];
            """,
            setup=ACS_SETUP,
        )
        notice, still_open = outcome["result"]
        assert expected in notice and still_open is True
        assert sent(outcome, "/wifi") == []
        if passphrase:
            assert passphrase not in notice

    @pytest.mark.parametrize("answer", [True, False])
    def test_an_inferred_band_is_confirmed_before_it_is_written(self, tmp_path: Path, answer):
        outcome = run_page(
            tmp_path,
            f"""
            await harness.flush();
            harness.answers.confirm.push({json.dumps(answer)});
            harness.acsReply = (path, options, record) => {{
              if (!path.endsWith('/wifi')) return undefined;
              if (!record.body.confirm_guessed_band) {{
                return {{status: 409, body: {{detail: 'SkyRouter inferred 5GHz.', plan: {{band_guessed: true}}}}}};
              }}
              return {{status: 202, body: {{job: makeJob('queued')}}}};
            }};
            showAcsWifi(router);
            const form = document.getElementById('acs-wifi-form');
            form.elements.band.value = '5GHz';
            form.elements.ssid.value = 'Upstairs';
            await harness.submit(form);
            await harness.flush();
            return [document.getElementById('notice').textContent, document.getElementById('acs-wifi-dialog').open];
            """,
            setup=ACS_SETUP,
        )
        bodies = sent(outcome, "/wifi")
        if answer:
            assert bodies == [
                {"band": "5GHz", "ssid": "Upstairs"},
                {"band": "5GHz", "ssid": "Upstairs", "confirm_guessed_band": True},
            ]
            assert outcome["result"][1] is False
        else:
            assert bodies == [{"band": "5GHz", "ssid": "Upstairs"}]
            assert outcome["result"] == ["Nothing was changed", True]

    def test_a_job_toast_explains_each_state_and_polls_on_the_briefs_schedule(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            await harness.flush();
            let reply = makeJob('waiting_for_checkin', {
              expected_by: todayAt(10, 5), cr_attempts: [{at: todayAt(10, 0), ok: false, result: 'Device is offline'}],
            });
            harness.acsReply = path => (path.startsWith('/api/acs/jobs/')
              ? {status: 200, body: {job: reply}} : undefined);
            trackJob(reply, router);
            const toasts = document.getElementById('toasts');
            const waiting = toasts.textContent;
            const buttons = harness.buttons(toasts);
            const polls = () => harness.requests.filter(r => r.path === '/api/acs/jobs/a1b2c3d4e5f60718').length;
            await harness.advance(180000);
            const fast = polls();
            await harness.advance(60000);
            const slow = polls() - fast;
            reply = makeJob('acknowledged', {
              message: 'The router accepted the new password. It cannot be read back to double-check.',
            });
            await harness.advance(15000);
            const done = toasts.textContent;
            const doneButtons = harness.buttons(toasts);
            const after = polls();
            await harness.advance(60000);
            const stopped = polls() === after;
            return {waiting, buttons, fast, slow, done, doneButtons, stopped, left: toasts.textContent};
            """,
            setup=ACS_SETUP,
        )
        result = outcome["result"]
        assert "Queued — the router will pick this up at its next check-in, expected around 10:05." in result["waiting"]
        assert "Not reachable right now: Device is offline" in result["waiting"]
        assert result["buttons"] == ["Cancel"]
        assert result["fast"] == 90, "every 2 s for the first three minutes"
        assert result["slow"] == 4, "then every 15 s"
        assert "The router accepted the new password. It cannot be read back to double-check." in result["done"]
        assert result["doneButtons"] == ["Dismiss"]
        assert result["stopped"] is True, "polling went on after done"
        assert result["left"] == "", "a successful toast should clear itself"

    def test_an_accepted_change_still_being_read_back_can_be_dismissed_and_refreshes_the_card(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            await harness.flush();
            const lists = () => harness.requests.filter(r => r.path.startsWith('/api/acs/devices?skip')).length;
            const before = lists();
            const watching = makeJob('acknowledged', {done: false, watch: 'scrub', message: 'The router accepted it.'});
            harness.acsReply = path => (path.startsWith('/api/acs/jobs/')
              ? {status: 200, body: {job: watching}} : undefined);
            trackJob(watching, router);
            await harness.flush();
            const buttons = harness.buttons(document.getElementById('toasts'));
            const reloaded = lists() - before;
            const polls = () => harness.requests.filter(r => r.path.startsWith('/api/acs/jobs/')).length;
            await harness.advance(4000);
            const polled = polls();
            harness.button(document.getElementById('toasts'), 'Dismiss').click();
            await harness.advance(60000);
            return {buttons, reloaded, polled, after: polls(), left: document.getElementById('toasts').textContent};
            """,
            setup=ACS_SETUP,
        )
        result = outcome["result"]
        assert result["buttons"] == ["Dismiss"]
        assert result["reloaded"] == 1, "the card should show the accepted change straight away"
        assert result["polled"] == 2, "a job still being read back is still followed"
        assert result["after"] == result["polled"] and result["left"] == ""

    @pytest.mark.parametrize(
        ("state", "extra", "expected"),
        [
            ("queued", {}, "Queued — sending it to the router now."),
            ("contacting_router", {}, "The router answered — waiting for it to check in and take the change."),
            ("waiting_for_checkin", {}, "Queued — the router will pick this up at its next check-in."),
            ("rejected", {"message": "The router refused the change: cwmp.9007 Invalid value"}, "cwmp.9007"),
            ("expired", {}, "did not check in in time"),
            ("cancelled", {}, "Cancelled."),
        ],
    )
    def test_job_state_text(self, tmp_path: Path, state, extra, expected):
        scenario = f"return jobText(makeJob({json.dumps(state)}, {json.dumps(extra)}));"
        outcome = run_page(tmp_path, scenario, setup=ACS_SETUP)
        assert expected in outcome["result"]

    def test_cancelling_a_job_asks_first_and_shows_a_busy_router(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            await harness.flush();
            harness.acsReply = (path, options) => (options.method === 'DELETE'
              ? {status: 409, body: {detail: 'the router is mid-session; try again'}} : undefined);
            trackJob(makeJob('waiting_for_checkin'), router);
            harness.answers.confirm.push(false);
            harness.button(document.getElementById('toasts'), 'Cancel').click();
            await harness.flush();
            const declined = harness.requests.filter(r => r.method === 'DELETE').length;
            harness.button(document.getElementById('toasts'), 'Cancel').click();
            await harness.flush();
            return [declined, document.getElementById('notice').textContent];
            """,
            setup=ACS_SETUP,
        )
        assert outcome["result"] == [0, "the router is mid-session; try again"]
        assert [item["path"] for item in outcome["requests"] if item["method"] == "DELETE"] == [
            "/api/acs/jobs/a1b2c3d4e5f60718"
        ]

    def test_jobs_in_progress_are_picked_up_after_a_reload(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            await harness.flush();
            return document.getElementById('toasts').textContent;
            """,
            setup=ACS_SETUP + "harness.acs.jobs = [makeJob('contacting_router', {kind: 'reboot'})];",
        )
        # Named as on its card, although the job itself only carries the ACS ID.
        assert "Reboot · AX3000 · AB-1" in outcome["result"]
        assert any(item["path"] == "/api/acs/jobs?active=true" for item in outcome["requests"])

    def test_reboot_refresh_tags_and_adopt(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            await harness.flush();
            harness.acsReply = (path, options) => {
              if (/\\/(reboot|refresh)$/.test(path)) {
                return {status: 202, body: {job: makeJob('queued', {kind: 'reboot'})}};
              }
              if (path.includes('/tags/')) {
                const tag = decodeURIComponent(path.split('/tags/')[1]);
                return {status: 200, body: {tags: options.method === 'POST' ? ['shop', tag] : []}};
              }
            };
            const cardNode = document.getElementById('acs-devices').querySelector('article');
            harness.answers.confirm.push(false);
            harness.button(cardNode, 'Reboot').click();
            await harness.flush();
            harness.button(cardNode, 'Reboot').click();
            await harness.flush();
            harness.button(cardNode, 'Refresh').click();
            const refreshForm = document.getElementById('acs-refresh-form');
            const scopes = refreshForm.elements.scope.options.map(option => option.value);
            const preselected = refreshForm.elements.scope.value;
            await harness.submit(refreshForm);
            await harness.flush();
            harness.button(cardNode, 'Tags').click();
            const tagsForm = document.getElementById('acs-tags-form');
            tagsForm.elements.tag.value = 'Not A Tag';
            await harness.submit(tagsForm);
            const refused = document.getElementById('notice').textContent;
            tagsForm.elements.tag.value = ' Shop_42 ';
            await harness.submit(tagsForm);
            await harness.flush();
            const chips = document.getElementById('acs-tags-list').textContent;
            harness.button(document.getElementById('acs-tags-list'), '×').click();
            await harness.flush();
            return {scopes, preselected, refused, chips, after: document.getElementById('acs-tags-list').textContent};
            """,
            setup=ACS_SETUP,
        )
        result = outcome["result"]
        assert sent(outcome, "/reboot") == [{"confirm": True}], "a declined reboot was sent"
        assert result["scopes"] == ["wifi", "hosts", "wan", "info", "all"] and result["preselected"] == "wifi"
        assert sent(outcome, "/refresh") == [{"scope": "wifi"}]
        assert "lowercase" in result["refused"]
        assert [item["path"] for item in outcome["requests"] if "/tags/" in item["path"]] == [
            "/api/acs/devices/202BC1-BM632w-AB%252D1/tags/shop_42",
            "/api/acs/devices/202BC1-BM632w-AB%252D1/tags/shop",
        ]
        assert "shop_42" in result["chips"] and result["after"] == "No tags yet"

    def test_the_new_devices_inbox_adopts(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            await harness.flush();
            const inbox = document.getElementById('acs-inbox');
            const shown = [inbox.hidden, inbox.textContent];
            harness.acs.inbox = [];
            harness.button(inbox, 'Adopt').click();
            await harness.flush();
            return {shown, after: inbox.hidden, notice: document.getElementById('notice').textContent};
            """,
            setup=ACS_SETUP + "harness.acs.inbox = [Object.assign({}, router, {tags: ['skybre_new']})];",
        )
        result = outcome["result"]
        assert result["shown"][0] is False and "AX3000 · AB-1" in result["shown"][1]
        assert sent(outcome, "/adopt") == [None]
        assert result["after"] is True and result["notice"] == "AX3000 · AB-1 adopted"

    def test_installing_the_provisioning_asks_before_removing_seeded_presets(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            await harness.flush();
            harness.acsReply = (path, options, record) => {
              if (path !== '/api/acs/bootstrap') return undefined;
              if (!record.body.remove_seeded) {
                return {status: 409, body: {detail: 'GenieACS has seeded presets', seeded: ['default']}};
              }
              return {status: 200, body: {writes: 7}};
            };
            harness.answers.confirm.push(true, true);
            harness.button(document.getElementById('acs-health'), 'Install provisioning').click();
            await harness.flush();
            return document.getElementById('notice').textContent;
            """,
            setup=ACS_SETUP + "harness.acs.health.bootstrap = {installed: false, drift: [{}, {}], seeded_presets: []};",
        )
        assert sent(outcome, "/api/acs/bootstrap") == [
            {"confirm": True, "remove_seeded": False},
            {"confirm": True, "remove_seeded": True},
        ]
        assert outcome["result"] == "Provisioning installed (7 change(s) written)"

    def test_health_problems_and_faults_are_shown(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            await harness.flush();
            harness.acsReply = path => (path.endsWith('/retry')
              ? {status: 200, body: {connection_request: {ok: false, reason: 'Device is offline'}}} : undefined);
            const health = document.getElementById('acs-health');
            const text = health.textContent;
            harness.button(health, 'Retry').click();
            await harness.flush();
            return [text, document.getElementById('notice').textContent];
            """,
            setup=ACS_SETUP
            + """
            harness.acs.health.problems = ['SKYROUTER_CR_SECRET is unset on the GenieACS host'];
            harness.acs.health.channel_faults = [{id: router.acs_id + ':skybre-inform', device: router.acs_id,
              channel: 'skybre-inform', code: 'ext.Error', message: 'secret unset'}];
            """,
        )
        text, notice = outcome["result"]
        assert "SKYROUTER_CR_SECRET is unset" in text and "skybre-inform on 202BC1-BM632w-AB%2D1: ext.Error" in text
        assert [item["path"] for item in outcome["requests"] if item["path"].endswith("/retry")] == [
            "/api/acs/faults/202BC1-BM632w-AB%252D1%3Askybre-inform/retry"
        ]
        assert "next check-in (Device is offline)" in notice

    def test_an_unreachable_acs_says_so(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            "await harness.flush(); return document.getElementById('acs-health').textContent;",
            setup=ACS_SETUP
            + "Object.assign(harness.acs.health, {reachable: false, version: null, error: 'ACS unavailable'});",
        )
        assert "SkyRouter cannot reach GenieACS: ACS unavailable" in outcome["result"]

    def test_search_and_paging(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            await harness.flush();
            harness.acsReply = path => (path.startsWith('/api/acs/devices?skip')
              ? {status: 200, body: {devices: [router], total: 30}} : undefined);
            const form = document.getElementById('acs-search');
            form.elements.q.value = ' AB-1 ';
            form.elements.tag.value = 'Shop';
            await harness.submit(form);
            document.getElementById('acs-next').click();
            await harness.flush();
            return document.getElementById('acs-page').textContent;
            """,
            setup=ACS_SETUP,
        )
        listed = [item["path"] for item in outcome["requests"] if item["path"].startswith("/api/acs/devices?skip")]
        assert listed[-2:] == [
            "/api/acs/devices?skip=0&limit=24&q=AB-1&tag=shop",
            "/api/acs/devices?skip=24&limit=24&q=AB-1&tag=shop",
        ]
        assert outcome["result"] == "25–25 of 30"

    def test_switching_tabs_and_leaving_direct_routers_alone_meanwhile(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            await harness.flush();
            const direct = () => harness.requests.filter(r => r.path.startsWith('/api/devices?')).length;
            const before = direct();
            await harness.advance(60000);
            const whileManaged = direct() - before;
            await chooseTab('direct');
            return {whileManaged, after: direct() - before, acs: document.getElementById('acs-view').hidden,
                    add: document.getElementById('add-button').hidden};
            """,
            setup=ACS_SETUP,
        )
        assert outcome["result"] == {"whileManaged": 0, "after": 1, "acs": True, "add": False}


@needs_node
class TestDashboardDirectWifiPassword:
    def test_the_buttons_are_renamed_and_offered_where_they_can_work(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            const out = {};
            const pairs = [['cudy', 'web'], ['cudy', 'ssh'], ['tplink', 'ssh'], ['tenda', 'web'], ['tplink', 'web']];
            for (const [vendor, transport] of pairs) {
              const node = card({id: 'r1', vendor, host: 'h', transport, status: {}});
              const wifi = harness.button(node, 'Wi-Fi password');
              out[vendor + '/' + transport] = [wifi.disabled, wifi.title || ''];
              out.labels = harness.buttons(node);
            }
            return out;
            """,
        )
        result = outcome["result"]
        assert "Admin login" in result["labels"] and "Password" not in result["labels"]
        for supported in ("cudy/web", "cudy/ssh", "tplink/ssh"):
            assert result[supported] == [False, ""], supported
        for refused in ("tenda/web", "tplink/web"):
            disabled, title = result[refused]
            assert disabled is True and "SSH" in title, refused

    def test_the_dialog_sends_the_password_once_with_confirm(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            f"""
            const node = card({{id: 'r1', vendor: 'cudy', host: 'h', transport: 'ssh', status: {{}}, metadata: {{}}}});
            harness.button(node, 'Wi-Fi password').click();
            const dialog = document.getElementById('wifi-password-dialog');
            const form = document.getElementById('wifi-password-form');
            const radios = form.elements.radio.options.map(option => [option.value, option.textContent]);
            const warning = dialog.querySelector('.warning').textContent;
            form.elements.password.value = {json.dumps(PASS)};
            form.elements.repeat.value = {json.dumps(PASS)};
            await harness.submit(form);
            await harness.flush();
            return {{radios, warning, open: dialog.open, left: form.elements.password.value,
                    notice: document.getElementById('notice').textContent}};
            """,
        )
        result = outcome["result"]
        assert result["radios"] == [["", "All bands"], ["2.4G", "2.4 GHz only"], ["5G", "5 GHz only"]]
        assert "will be disconnected" in result["warning"]
        assert sent(outcome, "/wifi-password") == [{"password": PASS, "confirm": True}]
        assert result["open"] is False and result["left"] == ""
        assert "Wi-Fi password changed on r1" in result["notice"] and PASS not in result["notice"]

    def test_an_ssh_router_with_a_configured_section_names_it_and_a_band_can_be_chosen(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            f"""
            const metadata = {{uci_section: 'wireless.guest'}};
            showWifiPassword({{id: 'r2', vendor: 'cudy', transport: 'ssh', metadata}});
            const form = document.getElementById('wifi-password-form');
            const first = form.elements.radio.options[0].textContent;
            form.elements.radio.value = '5G';
            form.elements.password.value = {json.dumps(PASS)};
            form.elements.repeat.value = {json.dumps(PASS)};
            await harness.submit(form);
            return first;
            """,
        )
        assert outcome["result"] == "The configured network (wireless.guest)"
        assert sent(outcome, "/wifi-password") == [{"password": PASS, "radio": "5G", "confirm": True}]

    @pytest.mark.parametrize(
        ("password", "repeat", "expected"),
        [("", "", "Enter the new Wi-Fi password"), (PASS, PASS + "x", "do not match"), ("short", "short", "8 to 63")],
    )
    def test_the_dialog_checks_before_sending(self, tmp_path: Path, password, repeat, expected):
        outcome = run_page(
            tmp_path,
            f"""
            showWifiPassword({{id: 'r1', vendor: 'cudy', transport: 'ssh'}});
            const form = document.getElementById('wifi-password-form');
            form.elements.password.value = {json.dumps(password)};
            form.elements.repeat.value = {json.dumps(repeat)};
            await harness.submit(form);
            const dialog = document.getElementById('wifi-password-dialog');
            return [document.getElementById('notice').textContent, dialog.open];
            """,
        )
        notice, still_open = outcome["result"]
        assert expected in notice and still_open is True
        assert sent(outcome, "/wifi-password") == []

    def test_a_refusal_is_shown_and_the_dialog_stays_open(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            f"""
            harness.handler = path => (path.endsWith('/wifi-password')
              ? {{status: 501, body: {{detail: 'Smart Connect joins both bands into one network'}}}} : undefined);
            showWifiPassword({{id: 'r1', vendor: 'cudy', transport: 'web'}});
            const form = document.getElementById('wifi-password-form');
            form.elements.radio.value = '5G';
            form.elements.password.value = {json.dumps(PASS)};
            form.elements.repeat.value = {json.dumps(PASS)};
            await harness.submit(form);
            await harness.flush();
            const dialog = document.getElementById('wifi-password-dialog');
            const openAfter = dialog.open;
            dialog.close();
            return [document.getElementById('notice').textContent, openAfter, form.elements.password.value];
            """,
        )
        assert outcome["result"] == ["Smart Connect joins both bands into one network", True, ""]


class TestDashboardMarkup:
    def test_new_controls_are_wired_from_script_under_the_strict_policy(self, tmp_path: Path):
        import re

        client, _ = signed_in(make_app(tmp_path))
        body = client.get("/").text
        assert not re.search(r"""\son[a-z]+\s*=\s*["']""", body), "inline event handler would be blocked"
        assert "innerHTML" not in body and "insertAdjacentHTML" not in body and "eval(" not in body
        for control in (
            "tab-acs",
            "tab-direct",
            "acs-search",
            "acs-prev",
            "acs-next",
            "acs-wifi-cancel",
            "acs-refresh-cancel",
            "acs-tags-close",
            "wifi-password-cancel",
        ):
            assert f'id="{control}"' in body
            assert f"'{control}'" in body
        policy = client.get("/").headers["Content-Security-Policy"]
        assert "connect-src 'self'" in policy and "unsafe-inline" not in policy.split("script-src")[1].split(";")[0]
        # Still one script, carrying the nonce.
        assert body.count("<script") == 1
