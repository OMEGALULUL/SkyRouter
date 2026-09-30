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
FIRMWARE_NAME = "skybre-fw-0123456789abcdef0123456789abcdef"
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
    ("GET", "/api/acs/firmware"),
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
    ("POST", "/api/acs/firmware?version=2.5.26&oui=80AFCA&product_class=AP1300", None),
    ("DELETE", f"/api/acs/firmware/{FIRMWARE_NAME}", None),
    ("POST", f"/api/acs/devices/{ENC}/firmware", {"firmware": FIRMWARE_NAME, "confirm": True}),
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
    ("GET", "/api/acs/firmware"),
    ("POST", "/api/acs/firmware"),
    ("DELETE", "/api/acs/firmware/{name}"),
    ("POST", "/api/acs/devices/{acs_id}/firmware"),
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
        monkeypatch.setenv("ROUTER_MANAGER_ACS_CWMP_URL", "junk")
        settings = Settings.from_env()
        assert settings.acs_url is None and settings.acs_cwmp_url is None

    def test_the_address_routers_check_in_to_is_read_and_shown_with_the_health(self, tmp_path: Path, monkeypatch, nbi):
        monkeypatch.setenv("ROUTER_MANAGER_ACS_URL", "http://127.0.0.1:7557")
        assert Settings.from_env().acs_cwmp_url is None
        monkeypatch.setenv("ROUTER_MANAGER_ACS_CWMP_URL", "  https://acs.example.net:7547/  ")
        assert Settings.from_env().acs_cwmp_url == "https://acs.example.net:7547/"
        client, _ = signed_in(make_app(tmp_path, nbi, acs_cwmp_url="http://10.10.0.2:7547/"))
        assert client.get("/api/acs").json()["cwmp_url"] == "http://10.10.0.2:7547/"
        client, _ = signed_in(make_app(tmp_path / "unset", nbi))
        assert client.get("/api/acs").json()["cwmp_url"] is None

    @pytest.mark.parametrize(
        "value",
        [
            "ftp://10.10.0.2:7547/",
            "10.10.0.2:7547",
            "http://",
            "http://10.10.0.2:7547/?x=1",
            "http://10.10.0.2:7547/#top",
            "http://10.10.0.2:0/",
            "http://10.10.0.2:99999/",
            "http://[::1/",
            "http://10.10.0.2 :7547/",
            "http://10.10.0.2:7547/" + "a" * 250,
        ],
    )
    def test_a_bad_address_for_the_routers_stops_startup(self, monkeypatch, value):
        monkeypatch.setenv("ROUTER_MANAGER_ACS_URL", "http://127.0.0.1:7557")
        monkeypatch.setenv("ROUTER_MANAGER_ACS_CWMP_URL", value)
        with pytest.raises(ValueError, match="ROUTER_MANAGER_ACS_CWMP_URL must be the plain http"):
            Settings.from_env()

    def test_credentials_in_the_routers_address_are_refused_without_being_repeated(self, monkeypatch):
        monkeypatch.setenv("ROUTER_MANAGER_ACS_URL", "http://127.0.0.1:7557")
        monkeypatch.setenv("ROUTER_MANAGER_ACS_CWMP_URL", "http://cpe:hunter2-secret@10.10.0.2:7547/")
        with pytest.raises(ValueError) as refused:
            Settings.from_env()
        assert "credentials" in str(refused.value) and "hunter2-secret" not in str(refused.value)

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
        assert adopted.status_code == 200
        assert adopted.json() == {"acs_id": router, "tags": ["shop_42"], "customer": None}
        assert client.get("/api/acs/devices?tag=skybre_new").json()["total"] == 0
        removed = client.delete(f"{path}/tags/shop_42", headers=headers)
        assert removed.json() == {"acs_id": router, "tags": []}

    def test_adopt_refuses_any_field_but_the_customer(self, tmp_path: Path, nbi):
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

        def fake(*args: Any, **_: Any) -> Any:
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
#
# These drive the approved design: one router list with a side panel, dialogs and toasts.
# Managed (TR-069) routers sit in that list beside the direct ones, so where the old page
# had a Managed tab of cards these open the router's side panel instead.


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


# A configured ACS with one router on two bands, the 5 GHz one only inferred. The list
# names a managed router after its sticker, model and serial: NAME.
ACS_SETUP = r"""
const minutesAgo = m => new Date(Date.now() - m * 60000).toISOString();
const todayAt = (h, m) => { const d = new Date(); d.setUTCHours(h, m, 0, 0); return d.toISOString(); };
const NAME = 'AX3000 · AB-1';
const router = {
  acs_id: '202BC1-BM632w-AB%2D1', manufacturer: 'Acme', model: 'AX3000', serial: 'AB-1', firmware: '1.2.3',
  data_model: 'tr181', profile: 'generic-tr181', online: true, last_inform: minutesAgo(3),
  expected_by: minutesAgo(-2), inform_interval: 300, tags: ['shop'],
  wifi: [
    {band: '2.4GHz', band_source: 'reported', ssid: 'Home', enabled: true, as_of: minutesAgo(10)},
    {band: '5GHz', band_source: 'guessed', ssid: 'Home-5G', enabled: true, as_of: minutesAgo(10)},
  ],
};
harness.db.acs = {configured: true, reachable: true, version: '1.2.16+20260329', error: null,
                  bootstrap: {installed: true, drift: [], seeded_presets: []}, channel_faults: [], problems: [],
                  jobs: {active: 0}};
harness.db.acsDevices = [router];
const makeJob = (state, extra = {}) => Object.assign({
  id: 'a1b2c3d4e5f60718', acs_id: router.acs_id, kind: 'wifi', state, message: '', expected_by: null,
  cr_attempts: [], last_error: null,
  terminal: !['queued', 'contacting_router', 'waiting_for_checkin'].includes(state),
  done: !['queued', 'contacting_router', 'waiting_for_checkin'].includes(state),
}, extra);
const managedRouter0 = () => routerByKey('acs:' + router.acs_id);
"""
NAME = "AX3000 · AB-1"
# The ID as it appears in a request path: encodeURIComponent turns its % into %25.
ACS_PATH = "/api/acs/devices/202BC1-BM632w-AB%252D1"
DIRECT_ROUTER = (
    "harness.db.devices = [{id: 'r1', vendor: 'cudy', host: 'h', transport: '%s', status: {online: true},"
    " metadata: %s}];"
)


def sent(outcome: dict, suffix: str, method: str = "POST") -> list[Any]:
    return [item["body"] for item in outcome["requests"] if item["method"] == method and item["path"].endswith(suffix)]


def csrf_of(outcome: dict, suffix: str) -> list[Any]:
    return [item["headers"].get("X-CSRF-Token") for item in outcome["requests"] if item["path"].endswith(suffix)]


@needs_node
class TestDashboardAcs:
    def test_the_tr069_parts_stay_hidden_while_the_acs_is_off(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            return {
              kindSeg: byId('kind-seg').hidden, routers: byId('view-routers').hidden,
              acsOnly: document.querySelectorAll('.acs-only').every((node) => node.hidden),
              pill: byId('new-pill').hidden, state: byId('acs-state').hidden, pager: byId('acs-pager').hidden,
              notes: [byId('routers-notes').hidden, byId('routers-notes').textContent],
              chips: byId('status-chips').children.map((chip) => chip.dataset.status),
            };
            """,
            setup="harness.handler = (req) => (req.path === '/api/acs'"
            " ? {status: 503, body: {detail: 'off', configured: false}} : undefined);",
        )
        assert outcome["result"] == {
            "kindSeg": True, "routers": False, "acsOnly": True, "pill": True, "state": True, "pager": True,
            "notes": [True, ""], "chips": ["all", "online", "offline", "attention"],
        }
        assert not [item for item in outcome["requests"] if item["path"].startswith("/api/acs/")]

    def test_a_managed_router_shows_its_details_beside_the_list(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            const rows = harness.rows();
            await harness.open(NAME);
            const shown = (root) => root.querySelectorAll('button')
              .filter((b) => !b.hidden && !b.closest('[hidden]')).map((b) => b.textContent.trim());
            const actions = shown(document.querySelector('.drawer-actions'));
            await harness.press(byId('d-more'));
            const menu = shown(byId('d-menu'));
            const text = [byId('d-name'), byId('d-sub'), byId('d-badges'), byId('p-overview')]
              .map((node) => node.textContent).join(' | ');
            return {
              rows, actions, menu, text,
              kind: [byId('kind-seg').hidden, byId('kind-seg').querySelector('[aria-pressed=true]').dataset.kind],
              state: [byId('acs-state').hidden, byId('acs-state').textContent],
              pager: [byId('acs-pager').hidden, byId('acs-page').textContent],
              pill: byId('new-pill').hidden,
            };
            """,
            setup=ACS_SETUP,
        )
        result = outcome["result"]
        assert result["rows"][0][:3] == [f"{NAME}  Acme", "—", "Online"]
        # The design lists every router at once: All is chosen, and Managed narrows it down.
        assert result["kind"] == [False, "all"]
        for expected in ("AX3000", "Acme", "AB-1", "Online", "1.2.3", "3 min ago", "TR-181", "2.4 GHz", "Home",
                         "5 GHz", "Home-5G", "as of 10 min ago", "band inferred", "shop", "Managed · TR-069"):
            assert expected in result["text"], expected
        assert result["actions"] == ["Change Wi-Fi", "Refresh", "Reboot", "More"]
        assert result["menu"] == ["Tags"], "the admin login and Remove are for direct routers only"
        assert result["state"] == [False, "GenieACS 1.2.16+20260329 is connected"]
        # Everything fits on one page, so there is nothing to page through.
        assert result["pager"] == [True, "1–1 of 1 managed router"]
        assert result["pill"] is True

    def test_actions_are_disabled_with_a_reason_where_they_cannot_work(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            const out = {};
            for (const model of ['tr181-issue1', 'unknown', 'tr098']) {
              harness.db.acsDevices = [Object.assign({}, router, {data_model: model})];
              await loadRouters();
              await harness.open(NAME);
              const state = (id) => [byId(id).disabled, Boolean(byId(id).title)];
              out[model] = [...state('d-wifi'), ...state('d-refresh'), ...state('d-reboot')];
              if (!byId('d-refresh').disabled) {
                await harness.press(byId('d-refresh'));
                const scope = byId('refresh-scope');
                out[model].push(scope.options.map((option) => option.value), scope.value);
                byId('refresh-dialog').close();
              }
            }
            return out;
            """,
            setup=ACS_SETUP,
        )
        assert outcome["result"] == {
            # The first TR-181 edition has no Wi-Fi tree, but can still report the rest.
            "tr181-issue1": [True, True, False, False, False, False, ["info", "all"], "info"],
            "unknown": [True, True, True, True, False, False],
            "tr098": [False, False, False, False, False, False, ["wifi", "hosts", "wan", "info", "all"], "wifi"],
        }
        assert sent(outcome, "/refresh") == []

    def test_change_wifi_sends_one_request_and_forgets_the_password(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            f"""
            harness.handler = (req) => (req.path.endsWith('/wifi') && req.method === 'POST'
              ? {{status: 202, body: {{job: makeJob('queued')}}}} : undefined);
            await harness.open(NAME);
            await harness.press(byId('d-wifi'));
            const seg = byId('band-seg');
            const bands = seg.children.map((b) => [b.dataset.band, b.textContent, b.disabled, b.title]);
            await harness.press(seg.querySelector('[data-band="5"]'));
            const five = [byId('band-hint').hidden, byId('band-hint').textContent, byId('ssid-hint').textContent];
            await harness.press(seg.querySelector('[data-band="2.4"]'));
            const two = [byId('band-hint').hidden, byId('ssid-hint').textContent];
            const warning = byId('wifi-dialog').querySelector('.warnbox').textContent;
            const note = byId('wifi-note').textContent;
            byId('w-ssid').value = ' New-Home ';
            byId('w-pw1').value = {json.dumps(PASS)};
            byId('w-pw2').value = {json.dumps(PASS)};
            await harness.press(byId('wifi-send'));
            return {{bands, five, two, warning, note, open: byId('wifi-dialog').open,
                     left: byId('w-pw1').value + byId('w-pw2').value, toasts: harness.toasts(),
                     status: harness.row(NAME).children[2].textContent, page: document.body.textContent}};
            """,
            setup=ACS_SETUP,
        )
        result = outcome["result"]
        assert result["bands"] == [
            ["both", "Both bands", False, ""],
            ["2.4", "2.4 GHz", False, 'Now "Home"'],
            ["5", "5 GHz", False, 'Now "Home-5G" (band inferred)'],
        ]
        assert result["five"] == [
            False,
            'SkyRouter inferred from its channel that "Home-5G" is the 5 GHz network, so it asks before writing to it.',
            '(empty keeps "Home-5G")',
        ]
        assert result["two"] == [True, '(empty keeps "Home")']
        assert "disconnects and must reconnect" in result["warning"]
        assert result["note"] == "If the router cannot be reached right now, the change waits for its next check-in."
        assert sent(outcome, "/wifi") == [{"band": "2.4GHz", "ssid": "New-Home", "passphrase": PASS}]
        [post] = [item for item in outcome["requests"] if item["path"].endswith("/wifi")]
        assert post["path"] == f"{ACS_PATH}/wifi" and post["headers"]["X-CSRF-Token"] == "t1"
        assert result["open"] is False and result["left"] == ""
        assert result["toasts"] == [{"kind": "queued", "title": "Queued", "text": f"Sending it to {NAME} now."}]
        assert result["status"] == "Change waiting"
        assert PASS not in result["page"]

    @pytest.mark.parametrize(
        ("ssid", "passphrase", "repeat", "expected"),
        [
            ("", "", "", "Enter a new Wi-Fi name, a new password, or both."),
            ("", "zq-Wifi-Passphrase-7731", "zq-Wifi-Passphrase-7732", "do not match"),
            ("", "short", "short", "8 to 63 characters"),
            ("", "café-passphrase", "café-passphrase", "no accents or emoji"),
        ],
    )
    def test_change_wifi_checks_the_form_before_sending(self, tmp_path: Path, ssid, passphrase, repeat, expected):
        outcome = run_page(
            tmp_path,
            f"""
            await harness.open(NAME);
            await harness.press(byId('d-wifi'));
            byId('w-ssid').value = {json.dumps(ssid)};
            byId('w-pw1').value = {json.dumps(passphrase)};
            byId('w-pw2').value = {json.dumps(repeat)};
            await harness.press(byId('wifi-send'));
            return [byId('wifi-error').textContent, byId('wifi-dialog').open];
            """,
            setup=ACS_SETUP,
        )
        error, still_open = outcome["result"]
        assert expected in error and still_open is True
        assert sent(outcome, "/wifi") == []
        if passphrase:
            assert passphrase not in error

    @pytest.mark.parametrize("answer", ["ok", "cancel"])
    def test_an_inferred_band_is_confirmed_before_it_is_written(self, tmp_path: Path, answer):
        outcome = run_page(
            tmp_path,
            f"""
            harness.handler = (req) => {{
              if (!req.path.endsWith('/wifi')) return undefined;
              if (!req.body.confirm_guessed_band) {{
                return {{status: 409, body: {{detail: 'SkyRouter inferred 5GHz.', plan: {{band_guessed: true}}}}}};
              }}
              return {{status: 202, body: {{job: makeJob('queued')}}}};
            }};
            await harness.open(NAME);
            await harness.press(byId('d-wifi'));
            await harness.press(byId('band-seg').querySelector('[data-band="5"]'));
            byId('w-ssid').value = 'Upstairs';
            const sending = byId('wifi-send').click();
            await harness.flush();
            const asked = [byId('confirm-dialog').open, byId('confirm-text').textContent];
            await harness.press(byId('confirm-{answer}'));
            await sending;
            await harness.flush();
            return [asked, byId('wifi-error').textContent, byId('wifi-dialog').open];
            """,
            setup=ACS_SETUP,
        )
        asked, error, still_open = outcome["result"]
        assert asked == [True, "SkyRouter inferred 5GHz."]
        bodies = sent(outcome, "/wifi")
        if answer == "ok":
            assert bodies == [
                {"band": "5GHz", "ssid": "Upstairs"},
                {"band": "5GHz", "ssid": "Upstairs", "confirm_guessed_band": True},
            ]
            assert still_open is False
        else:
            assert bodies == [{"band": "5GHz", "ssid": "Upstairs"}]
            assert [error, still_open] == ["Nothing was changed.", True]

    def test_a_job_toast_explains_each_state_and_polls_on_the_briefs_schedule(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            let reply = makeJob('waiting_for_checkin', {
              expected_by: todayAt(10, 5), cr_attempts: [{at: todayAt(10, 0), ok: false, result: 'Device is offline'}],
            });
            harness.handler = (req) => (req.path.startsWith('/api/acs/jobs/')
              ? {status: 200, body: {job: reply}} : undefined);
            trackJob(reply, managedRouter0());
            const toasts = byId('toasts');
            const waiting = [harness.toasts()[0], toasts.textContent];
            const buttons = harness.buttons(toasts);
            const status = harness.row(NAME).children[2].textContent;
            const polls = () => harness.requests.filter(r => r.path === '/api/acs/jobs/a1b2c3d4e5f60718').length;
            await harness.advance(180000);
            const fast = polls();
            await harness.advance(60000);
            const slow = polls() - fast;
            reply = makeJob('acknowledged', {
              message: 'The router accepted the new password. It cannot be read back to double-check.',
            });
            await harness.advance(15000);
            const done = harness.toasts()[0];
            const doneButtons = harness.buttons(toasts);
            const after = polls();
            await harness.advance(60000);
            const stopped = polls() === after;
            return {waiting, buttons, status, fast, slow, done, doneButtons, stopped, left: toasts.textContent,
                    now: harness.row(NAME).children[2].textContent};
            """,
            setup=ACS_SETUP,
        )
        result = outcome["result"]
        toast, text = result["waiting"]
        assert toast == {"kind": "queued", "title": "Queued",
                         "text": f"{NAME} picks this up at its next check-in, around 10:05."}
        assert "Not reachable right now: Device is offline." in text
        assert result["buttons"] == ["×", "Cancel change"]
        assert result["status"] == "Change waiting"
        assert result["fast"] == 90, "every 2 s for the first three minutes"
        assert result["slow"] == 4, "then every 15 s"
        assert result["done"] == {
            "kind": "applied", "title": "Applied",
            "text": f"{NAME}: The router accepted the new password. It cannot be read back to double-check.",
        }
        assert result["doneButtons"] == ["×"]
        assert result["stopped"] is True, "polling went on after done"
        assert result["left"] == "", "a successful toast should clear itself"
        assert result["now"] == "Online"

    def test_an_accepted_change_still_being_read_back_can_be_dismissed_and_refreshes_the_list(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            const lists = () => harness.requests.filter(r => r.path.startsWith('/api/acs/devices?skip')).length;
            const before = lists();
            const watching = makeJob('acknowledged', {done: false, watch: 'scrub', message: 'The router accepted it.'});
            harness.handler = (req) => (req.path.startsWith('/api/acs/jobs/')
              ? {status: 200, body: {job: watching}} : undefined);
            trackJob(watching, managedRouter0());
            await harness.flush();
            const buttons = harness.buttons(byId('toasts'));
            const reloaded = lists() - before;
            const polls = () => harness.requests.filter(r => r.path.startsWith('/api/acs/jobs/')).length;
            await harness.advance(4000);
            const polled = polls();
            await harness.press(harness.button(byId('toasts'), '×'));
            await harness.advance(60000);
            return {buttons, reloaded, polled, after: polls(), left: byId('toasts').textContent};
            """,
            setup=ACS_SETUP,
        )
        result = outcome["result"]
        assert result["buttons"] == ["×"]
        assert result["reloaded"] == 1, "the list should show the accepted change straight away"
        assert result["polled"] == 2, "a job still being read back is still followed"
        assert result["after"] == result["polled"] and result["left"] == ""

    def test_an_answer_that_arrives_after_dismissing_is_dropped(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            const watching = makeJob('acknowledged', {done: false, watch: 'scrub', message: 'The router accepted it.'});
            const gate = harness.deferred();
            harness.handler = (req) => (req.path.startsWith('/api/acs/jobs/') ? gate.promise : undefined);
            trackJob(watching, managedRouter0());
            await harness.advance(2000);
            await harness.press(harness.button(byId('toasts'), '×'));
            gate.resolve({status: 200, body: {job: watching}});
            await harness.advance(60000);
            const polls = harness.requests.filter(r => r.path.startsWith('/api/acs/jobs/')).length;
            return [harness.toasts().length, polls];
            """,
            setup=ACS_SETUP,
        )
        assert outcome["result"] == [0, 1], "a dismissed change came back"

    def test_a_pending_toast_closed_early_still_reports_the_outcome(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            let reply = makeJob('waiting_for_checkin');
            harness.handler = (req) => (req.path.startsWith('/api/acs/jobs/')
              ? {status: 200, body: {job: reply}} : undefined);
            trackJob(reply, managedRouter0());
            await harness.press(harness.button(byId('toasts'), '×'));
            await harness.advance(10000);
            const hidden = [harness.toasts().length, harness.row(NAME).children[2].textContent];
            reply = makeJob('rejected', {message: 'The router refused the change: cwmp.9007 Invalid value'});
            await harness.advance(2000);
            return [hidden, harness.toasts()];
            """,
            setup=ACS_SETUP,
        )
        hidden, shown = outcome["result"]
        assert hidden == [0, "Change waiting"], "closing the toast does not forget the change"
        assert shown == [{"kind": "refused", "title": "Refused",
                          "text": f"{NAME}: The router refused the change: cwmp.9007 Invalid value"}]

    @pytest.mark.parametrize(
        ("state", "extra", "expected", "kind"),
        [
            ("queued", {}, f"Sending it to {NAME} now.", ["queued", "Queued"]),
            ("contacting_router", {}, f"{NAME} answered; waiting for it to check in and take the change.",
             ["queued", "Queued"]),
            ("waiting_for_checkin", {}, f"{NAME} picks this up at its next check-in.", ["queued", "Queued"]),
            ("rejected", {"message": "The router refused the change: cwmp.9007 Invalid value"}, "cwmp.9007",
             ["refused", "Refused"]),
            ("expired", {}, "did not check in in time", ["info", "Not applied"]),
            ("cancelled", {}, f"Cancelled: nothing was changed on {NAME}.", ["info", "Not applied"]),
        ],
    )
    def test_job_state_text(self, tmp_path: Path, state, extra, expected, kind):
        scenario = f"return jobView({{job: makeJob({json.dumps(state)}, {json.dumps(extra)}), router: null}});"
        outcome = run_page(tmp_path, scenario, setup=ACS_SETUP)
        assert outcome["result"][:2] == kind
        assert expected in outcome["result"][2]

    def test_cancelling_a_job_asks_first_and_shows_a_busy_router(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            harness.handler = (req) => (req.method === 'DELETE'
              ? {status: 409, body: {detail: 'the router is mid-session; try again'}} : undefined);
            trackJob(makeJob('waiting_for_checkin'));
            const cancel = () => harness.button(byId('toasts'), 'Cancel change');
            await harness.press(cancel());
            const asked = byId('confirm-title').textContent;
            await harness.press(byId('confirm-cancel'));
            const declined = harness.requests.filter(r => r.method === 'DELETE').length;
            await harness.press(cancel());
            await harness.press(byId('confirm-ok'));
            return [asked, declined, harness.toasts()];
            """,
            setup=ACS_SETUP,
        )
        asked, declined, toasts = outcome["result"]
        assert asked == "Cancel this change?" and declined == 0
        assert [item["path"] for item in outcome["requests"] if item["method"] == "DELETE"] == [
            "/api/acs/jobs/a1b2c3d4e5f60718"
        ]
        # The refusal says why, and the change it could not cancel is still followed.
        assert toasts[0] == {"kind": "refused", "title": "Not cancelled",
                             "text": "the router is mid-session; try again"}
        assert [toast["title"] for toast in toasts[1:]] == ["Queued"]

    def test_jobs_in_progress_are_picked_up_after_a_reload(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            "return {toasts: harness.toasts(), status: harness.row(NAME).children[2].textContent};",
            setup=ACS_SETUP + "harness.db.jobs = [makeJob('contacting_router', {kind: 'reboot'})];",
        )
        # Named as in the list, although the job itself only carries the ACS ID.
        assert outcome["result"] == {
            "toasts": [{"kind": "queued", "title": "Reboot queued",
                        "text": f"{NAME} answered; waiting for it to check in and restart."}],
            "status": "Change waiting",
        }
        paths = [item["path"] for item in outcome["requests"]]
        assert "/api/acs/jobs?active=true" in paths
        assert paths.index("/api/acs/jobs?active=true") > paths.index("/api/acs/devices?skip=0&limit=200")

    def test_reboot_refresh_and_tags(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            harness.handler = (req) => {
              if (/\\/(reboot|refresh)$/.test(req.path)) {
                return {status: 202, body: {job: makeJob('queued', {kind: 'reboot'})}};
              }
              if (req.path.includes('/tags/')) {
                const tag = decodeURIComponent(req.path.split('/tags/')[1]);
                return {status: 200, body: {tags: req.method === 'POST' ? ['shop', tag] : []}};
              }
            };
            await harness.open(NAME);
            await harness.press(byId('d-reboot'));
            await harness.press(byId('reboot-cancel'));
            await harness.press(byId('d-reboot'));
            await harness.press(byId('reboot-ok'));
            await harness.press(byId('d-refresh'));
            const scopes = byId('refresh-scope').options.map((option) => [option.value, option.textContent]);
            const preselected = byId('refresh-scope').value;
            await harness.press(byId('refresh-send'));
            await harness.press(byId('d-more'));
            await harness.press(byId('d-tags'));
            const listed = byId('tags-list').textContent;
            byId('tag-input').value = 'Not A Tag';
            await harness.press(byId('tags-add'));
            const refused = byId('tags-error').textContent;
            byId('tag-input').value = ' Shop_42 ';
            await harness.press(byId('tags-add'));
            const chips = byId('tags-list').textContent;
            const badges = byId('d-badges').textContent;
            const typed = byId('tag-input').value;
            await harness.press(harness.button(byId('tags-list'), '×'));
            return {scopes, preselected, listed, refused, chips, badges, typed, open: byId('tags-dialog').open,
                    after: byId('tags-list').textContent, refreshOpen: byId('refresh-dialog').open};
            """,
            setup=ACS_SETUP,
        )
        result = outcome["result"]
        assert sent(outcome, "/reboot") == [{"confirm": True}], "a declined reboot was sent"
        assert result["scopes"] == [
            ["wifi", "Wi-Fi settings"], ["hosts", "Connected devices"], ["wan", "Internet connection"],
            ["info", "Router information"], ["all", "Everything (slow on some routers)"],
        ]
        assert result["preselected"] == "wifi" and result["refreshOpen"] is False
        assert sent(outcome, "/refresh") == [{"scope": "wifi"}]
        assert result["listed"] == "shop×"
        assert "lowercase" in result["refused"]
        tags = [(item["method"], item["path"]) for item in outcome["requests"] if "/tags/" in item["path"]]
        assert tags == [("POST", f"{ACS_PATH}/tags/shop_42"), ("DELETE", f"{ACS_PATH}/tags/shop")]
        assert set(csrf_of(outcome, "/shop_42") + csrf_of(outcome, "/tags/shop")) == {"t1"}
        assert "shop_42" in result["chips"] and "shop_42" in result["badges"] and result["typed"] == ""
        assert result["after"] == "No tags yet" and result["open"] is True

    def test_the_new_routers_inbox_adopts(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            const pill = byId('new-pill');
            const shown = [pill.hidden, pill.textContent];
            await harness.press(pill);
            const list = byId('new-list');
            const label = list.querySelector('label span').textContent;
            list.querySelector('input').value = ' #1080 Customer E ';
            harness.db.acsNew = [];
            await harness.press(harness.button(list, 'Adopt'));
            return {shown, label, after: pill.hidden, left: list.textContent, toast: harness.toasts()[0],
                    rows: harness.rows().map((row) => row[0])};
            """,
            setup=ACS_SETUP + """
            harness.db.acsNew = [Object.assign({}, router, {acs_id: '202BC1-BM632w-NEW1', serial: 'NEW1',
                                                            tags: ['skybre_new']})];
            """,
        )
        result = outcome["result"]
        assert result["shown"] == [False, "1 new router to adopt"]
        assert result["label"] == "AX3000 · serial NEW1"
        assert result["rows"] == [f"{NAME}  Acme"], "a router waiting to be adopted is not in the list"
        # The approved design links an adopted router to its Vexar customer.
        assert sent(outcome, "/adopt") == [{"customer": "#1080 Customer E"}]
        assert result["after"] is True and result["left"] == "No new routers waiting."
        assert result["toast"] == {"kind": "applied", "title": "Adopted",
                                   "text": "AX3000 · serial NEW1 is linked to #1080 Customer E."}

    def test_installing_the_provisioning_asks_before_removing_seeded_presets(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            harness.handler = (req) => {
              if (req.path !== '/api/acs/bootstrap') return undefined;
              if (!req.body.remove_seeded) {
                return {status: 409, body: {detail: 'GenieACS has seeded presets.', seeded: ['default']}};
              }
              return {status: 200, body: {writes: 7}};
            };
            const notes = byId('routers-notes');
            const warned = notes.textContent;
            await harness.press(harness.button(notes, 'Install provisioning'));
            const first = byId('confirm-title').textContent;
            await harness.press(byId('confirm-ok'));
            const second = [byId('confirm-title').textContent, byId('confirm-text').textContent];
            harness.db.acs.bootstrap = {installed: true, drift: [], seeded_presets: []};
            await harness.press(byId('confirm-ok'));
            return {warned, first, second, toast: harness.toasts()[0], after: notes.textContent};
            """,
            setup=ACS_SETUP + "harness.db.acs.bootstrap = {installed: false, drift: [{}, {}], seeded_presets: []};",
        )
        result = outcome["result"]
        assert "SkyRouter's provisioning is not installed in GenieACS (2 parts missing or changed)" in result["warned"]
        assert result["first"] == "Install SkyRouter's provisioning?"
        assert result["second"] == ["Remove GenieACS's default presets?",
                                    "GenieACS has seeded presets. Remove default and install?"]
        assert sent(outcome, "/api/acs/bootstrap") == [
            {"confirm": True, "remove_seeded": False},
            {"confirm": True, "remove_seeded": True},
        ]
        assert result["toast"] == {"kind": "applied", "title": "Provisioning installed",
                                   "text": "7 changes written to GenieACS."}
        assert "not installed" not in result["after"], "the banner is read again afterwards"

    def test_declining_to_remove_the_seeded_presets_installs_nothing(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            harness.handler = (req) => (req.path === '/api/acs/bootstrap'
              ? {status: 409, body: {detail: 'GenieACS has seeded presets.', seeded: ['default']}} : undefined);
            await harness.press(harness.button(byId('routers-notes'), 'Install provisioning'));
            await harness.press(byId('confirm-ok'));
            await harness.press(byId('confirm-cancel'));
            return byId('confirm-dialog').open;
            """,
            setup=ACS_SETUP + "harness.db.acs.bootstrap = {installed: false, drift: [], seeded_presets: []};",
        )
        assert outcome["result"] is False
        assert sent(outcome, "/api/acs/bootstrap") == [{"confirm": True, "remove_seeded": False}]

    def test_health_problems_and_faults_are_shown(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            harness.handler = (req) => (req.path.endsWith('/retry')
              ? {status: 200, body: {connection_request: {ok: false, reason: 'Device is offline'}}} : undefined);
            const notes = byId('routers-notes');
            const text = notes.textContent;
            await harness.press(harness.button(notes, 'Retry'));
            const retried = harness.toasts()[0];
            await harness.press(harness.button(notes, 'Clear'));
            const asked = byId('confirm-title').textContent;
            await harness.press(byId('confirm-ok'));
            return {text, retried, asked, cleared: harness.toasts()[0]};
            """,
            setup=ACS_SETUP
            + """
            harness.db.acs.problems = ['SKYROUTER_CR_SECRET is unset on the GenieACS host'];
            harness.db.acs.channel_faults = [{id: router.acs_id + ':skybre-inform', device: router.acs_id,
              channel: 'skybre-inform', code: 'ext.Error', message: 'secret unset'}];
            """,
        )
        result = outcome["result"]
        assert "SKYROUTER_CR_SECRET is unset" in result["text"]
        assert f"Provisioning step skybre-inform failed on {NAME}: ext.Error secret unset" in result["text"]
        fault = "/api/acs/faults/202BC1-BM632w-AB%252D1%3Askybre-inform"
        assert [item["path"] for item in outcome["requests"] if item["method"] == "POST"] == [f"{fault}/retry"]
        assert "next check-in (Device is offline)" in result["retried"]["text"]
        assert result["asked"] == "Clear this fault?"
        assert [item["path"] for item in outcome["requests"] if item["method"] == "DELETE"] == [fault]
        assert result["cleared"]["title"] == "Fault cleared"

    def test_an_unreachable_acs_says_so(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            "return [byId('routers-notes').textContent, byId('acs-state').hidden];",
            setup=ACS_SETUP
            + "Object.assign(harness.db.acs, {reachable: false, version: null, error: 'ACS unavailable'});",
        )
        text, state_hidden = outcome["result"]
        assert "SkyRouter cannot reach GenieACS: ACS unavailable" in text and state_hidden is True

    def test_an_acs_that_goes_away_while_the_page_is_open_says_so(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            const before = byId('acs-state').textContent;
            harness.handler = (req) => (req.path === '/api/acs'
              ? {status: 502, body: {detail: 'ACS unavailable'}} : undefined);
            await harness.advance(30000);
            return [before, byId('routers-notes').textContent, byId('acs-state').hidden];
            """,
            setup=ACS_SETUP,
        )
        before, text, state_hidden = outcome["result"]
        assert before.startswith("GenieACS 1.2.16")
        assert "SkyRouter cannot reach GenieACS: ACS unavailable" in text and state_hidden is True

    def test_search_and_paging(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            harness.handler = (req) => (req.path.startsWith('/api/acs/devices?skip')
              ? {status: 200, body: {devices: [router], total: 230}} : undefined);
            await loadRouters();
            const pager = () => [byId('acs-pager').hidden, byId('acs-page').textContent,
                                 byId('acs-prev').disabled, byId('acs-next').disabled];
            const first = pager();
            byId('acs-q').value = ' AB-1 ';
            byId('acs-tag').value = 'Shop';
            await harness.press(byId('acs-find'));
            await harness.press(byId('acs-next'));
            const next = pager();
            const reads = harness.requests.length;
            byId('acs-q').value = 'two words';
            await harness.press(byId('acs-find'));
            const refused = [byId('acs-search-error').textContent, harness.requests.length - reads];
            await harness.type(byId('search'), 'shop');
            const byTag = harness.rows().map((row) => row[0]);
            await harness.type(byId('search'), 'acme');
            return {first, next, refused, byTag, byMaker: harness.rows().map((row) => row[0])};
            """,
            setup=ACS_SETUP,
        )
        result = outcome["result"]
        listed = [item["path"] for item in outcome["requests"] if item["path"].startswith("/api/acs/devices?skip")]
        assert listed[-2:] == [
            "/api/acs/devices?skip=0&limit=200&q=AB-1&tag=shop",
            "/api/acs/devices?skip=200&limit=200&q=AB-1&tag=shop",
        ]
        assert result["first"] == [False, "1–1 of 230 managed routers", True, False]
        assert result["next"][:3] == [False, "201–201 of 230 managed routers", False]
        assert "letters, digits" in result["refused"][0] and result["refused"][1] == 0
        # The list's own search also finds a router by its tags and its maker.
        assert result["byTag"] == [f"{NAME}  Acme"] and result["byMaker"] == [f"{NAME}  Acme"]

    def test_direct_routers_are_left_alone_while_only_managed_ones_are_shown(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            const direct = () => harness.requests.filter(r => r.path.startsWith('/api/devices?')).length;
            const managed = () => harness.requests.filter(r => r.path.startsWith('/api/acs/devices?skip')).length;
            await harness.press(byId('kind-seg').querySelector('[data-kind=managed]'));
            const before = [direct(), managed()];
            await harness.advance(60000);
            const whileManaged = [direct() - before[0], managed() - before[1]];
            const rows = harness.rows().map((row) => row[0]);
            await harness.press(byId('kind-seg').querySelector('[data-kind=direct]'));
            const switched = direct() - before[0];
            await harness.advance(30000);
            return {whileManaged, rows, switched, after: direct() - before[0],
                    shown: harness.rows().map((row) => row[0])};
            """,
            setup=ACS_SETUP + DIRECT_ROUTER % ("web", "{name: 'Shop'}"),
        )
        assert outcome["result"] == {
            "whileManaged": [0, 2], "rows": [f"{NAME}  Acme"], "switched": 1, "after": 2, "shown": ["Shop  Cudy"],
        }


@needs_node
class TestDashboardDirectWifiPassword:
    def test_the_password_is_offered_only_where_it_can_work(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            """
            const out = {};
            const pairs = [['cudy', 'web'], ['cudy', 'ssh'], ['tplink', 'ssh'], ['tenda', 'web'], ['tplink', 'web']];
            for (const [vendor, transport] of pairs) {
              harness.db.devices = [{id: 'r1', vendor, host: 'h', transport, status: {online: true}, metadata: {}}];
              await loadRouters();
              await harness.open('r1');
              const key = vendor + '/' + transport;
              if (byId('d-wifi').disabled) { out[key] = ['dialog', true, byId('d-wifi').title]; continue; }
              await harness.press(byId('d-wifi'));
              const note = byId('wifi-note');
              out[key] = ['password', byId('w-pw1').disabled, note.hidden ? '' : note.textContent];
              byId('wifi-dialog').close();
            }
            await harness.press(byId('d-more'));
            out.labels = byId('d-menu').querySelectorAll('button').filter((b) => !b.hidden).map((b) => b.textContent);
            return out;
            """,
        )
        result = outcome["result"]
        assert result["labels"] == ["Router admin password", "Remove from SkyRouter"]
        for supported in ("cudy/web", "cudy/ssh", "tplink/ssh"):
            assert result[supported] == ["password", False, ""], supported
        for refused in ("tenda/web", "tplink/web"):
            _, disabled, why = result[refused]
            assert disabled is True and "SSH" in why, refused
        assert result["tenda/web"][0] == "password", "a Tenda can still be renamed"
        assert result["tplink/web"][0] == "dialog", "the older TP-Link page can change neither"

    def test_the_dialog_sends_the_password_once_with_confirm(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            f"""
            await harness.open('r1');
            await harness.press(byId('d-wifi'));
            const bands = byId('band-seg').children
              .map((b) => [b.dataset.band, b.textContent, b.getAttribute('aria-checked')]);
            const warning = byId('wifi-dialog').querySelector('.warnbox').textContent;
            byId('w-pw1').value = {json.dumps(PASS)};
            byId('w-pw2').value = {json.dumps(PASS)};
            await harness.press(byId('wifi-send'));
            return {{bands, warning, open: byId('wifi-dialog').open, left: byId('w-pw1').value,
                     toast: harness.toasts()[0], page: document.body.textContent}};
            """,
            setup=DIRECT_ROUTER % ("ssh", "{}"),
        )
        result = outcome["result"]
        assert result["bands"] == [["both", "Both bands", "true"], ["2.4", "2.4 GHz", "false"], ["5", "5 GHz", "false"]]
        assert "disconnects and must reconnect" in result["warning"]
        assert sent(outcome, "/wifi-password") == [{"password": PASS, "confirm": True}]
        assert csrf_of(outcome, "/wifi-password") == ["t1"] and sent(outcome, "/ssid") == []
        assert result["open"] is False and result["left"] == ""
        assert result["toast"] == {"kind": "applied", "title": "Applied", "text": "r1 accepted the change."}
        assert PASS not in result["page"]

    def test_an_ssh_router_with_a_configured_section_names_it_and_a_band_can_be_chosen(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            f"""
            await harness.open('r1');
            await harness.press(byId('d-wifi'));
            const first = [byId('band-seg').children[0].textContent, byId('band-hint').textContent];
            await harness.press(byId('band-seg').querySelector('[data-band="5"]'));
            const hint = byId('band-hint').hidden;
            byId('w-pw1').value = {json.dumps(PASS)};
            byId('w-pw2').value = {json.dumps(PASS)};
            await harness.press(byId('wifi-send'));
            return {{first, hint}};
            """,
            setup=DIRECT_ROUTER % ("ssh", "{uci_section: 'wireless.guest'}"),
        )
        assert outcome["result"] == {"first": ["Its configured network", "Its configured network is wireless.guest."],
                                     "hint": True}
        assert sent(outcome, "/wifi-password") == [{"password": PASS, "radio": "5G", "confirm": True}]

    @pytest.mark.parametrize(
        ("password", "repeat", "expected"),
        [("", "", "Enter a new Wi-Fi name, a new password, or both."), (PASS, PASS + "x", "do not match"),
         ("short", "short", "8 to 63")],
    )
    def test_the_dialog_checks_before_sending(self, tmp_path: Path, password, repeat, expected):
        outcome = run_page(
            tmp_path,
            f"""
            await harness.open('r1');
            await harness.press(byId('d-wifi'));
            byId('w-pw1').value = {json.dumps(password)};
            byId('w-pw2').value = {json.dumps(repeat)};
            await harness.press(byId('wifi-send'));
            return [byId('wifi-error').textContent, byId('wifi-dialog').open];
            """,
            setup=DIRECT_ROUTER % ("ssh", "{}"),
        )
        error, still_open = outcome["result"]
        assert expected in error and still_open is True
        assert sent(outcome, "/wifi-password") == []
        if password:
            assert password not in error

    def test_a_refusal_is_shown_and_the_dialog_stays_open(self, tmp_path: Path):
        outcome = run_page(
            tmp_path,
            f"""
            harness.handler = (req) => (req.path.endsWith('/wifi-password')
              ? {{status: 501, body: {{detail: 'Smart Connect joins both bands into one network'}}}} : undefined);
            await harness.open('r1');
            await harness.press(byId('d-wifi'));
            await harness.press(byId('band-seg').querySelector('[data-band="5"]'));
            byId('w-pw1').value = {json.dumps(PASS)};
            byId('w-pw2').value = {json.dumps(PASS)};
            await harness.press(byId('wifi-send'));
            const openAfter = byId('wifi-dialog').open;
            const error = byId('wifi-error').textContent;
            byId('wifi-dialog').close();
            return [error, openAfter, byId('w-pw1').value, byId('w-pw2').value];
            """,
            setup=DIRECT_ROUTER % ("web", "{}"),
        )
        assert outcome["result"] == ["Smart Connect joins both bands into one network", True, "", ""]
        assert sent(outcome, "/wifi-password") == [{"password": PASS, "radio": "5G", "confirm": True}]


class TestDashboardMarkup:
    def test_new_controls_are_wired_from_script_under_the_strict_policy(self, tmp_path: Path):
        import re

        client, _ = signed_in(make_app(tmp_path))
        body = client.get("/").text
        assert not re.search(r"""\son[a-z]+\s*=\s*["']""", body), "inline event handler would be blocked"
        assert "innerHTML" not in body and "insertAdjacentHTML" not in body and "eval(" not in body
        for control in (
            "kind-seg",
            "search",
            "new-pill",
            "acs-search",
            "acs-prev",
            "acs-next",
            "d-tags",
            "wifi-cancel",
            "refresh-cancel",
            "refresh-form",
            "tags-close",
            "tags-form",
        ):
            assert f'id="{control}"' in body
            assert f"'{control}'" in body
        policy = client.get("/").headers["Content-Security-Policy"]
        assert "connect-src 'self'" in policy and "unsafe-inline" not in policy.split("script-src")[1].split(";")[0]
        # Still one script, carrying the nonce.
        assert body.count("<script") == 1
