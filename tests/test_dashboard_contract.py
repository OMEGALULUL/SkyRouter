"""The dashboard's requests, replayed against the real server.

test_dashboard_ui.py checks what the page sends against an in-memory stand-in for
the API. This file closes the loop: it drives every part of the page that talks to
the server, collects each request exactly as the page made it, and sends it to the
real app under uvicorn, where the actual routes, body checks, AcsService (on the
fake NBI) and maintenance and setup stores answer. A path, method, field name or
value shape the server does not take fails here.

Direct routers are never contacted: the manager's router calls are replaced, the
hosts are in TEST-NET-1, and any connection off loopback fails the test.
"""

import http.client
import json
import re
import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import pytest
import uvicorn
from fake_nbi import FakeNbi, build_device
from test_dashboard_ui import NODE, needs_node, run_page

from cudy_manager.acs.client import AcsClient
from cudy_manager.acs.service import AcsService
from cudy_manager.activity import ActivityLog
from cudy_manager.manager import DeviceManager
from cudy_manager.secrets import SecretStore
from cudy_manager.web import Settings, create_app

PASSKEY = "contract-test-passkey-5521"
WIFI = "Device.WiFi"
IGD = "InternetGatewayDevice"
# Placeholders the page is given, swapped for the real server's own ids on replay.
JOB = "0123456789abcdef"
PLAN_ID = "a1b2c3d4e5f6"
RECORD_ID = "b1b2b3b4b5b6"
LIBRARY_NAME = "skybre-fw-0123456789abcdef0123456789abcdef"
# An older file, which the page removes: the newer one is being installed by then.
OLDER_NAME = "skybre-fw-fedcba9876543210fedcba9876543210"
ENTRY_ID = "e1"
FAULT = "80AFCA-WR3000-AB%2D1:skybre-inform"
IMAGE = b"\x27\x05\x19\x56" + bytes(range(256)) * 8

# Every (method, route) the page uses. The replay must reach each one, so a flow the
# scenarios stop exercising is noticed, and nothing else.
EXPECTED_ROUTES = {
    ("GET", "/api/csrf"),
    ("GET", "/api/me"),
    ("POST", "/logout"),
    ("GET", "/api/devices"),
    ("DELETE", "/api/devices/{identifier}"),
    ("GET", "/api/devices/{identifier}/status"),
    ("GET", "/api/devices/{identifier}/clients"),
    ("POST", "/api/devices/{identifier}/reboot"),
    ("POST", "/api/devices/{identifier}/ssid"),
    ("POST", "/api/devices/{identifier}/wifi-password"),
    ("POST", "/api/devices/{identifier}/password"),
    ("GET", "/api/devices/{identifier}/firmware"),
    ("PUT", "/api/devices/{identifier}/firmware/auto-update"),
    ("POST", "/api/devices/{identifier}/firmware/check"),
    ("GET", "/api/activity"),
    ("GET", "/api/activity.csv"),
    ("GET", "/api/acs"),
    ("GET", "/api/acs/devices"),
    ("GET", "/api/acs/devices/{acs_id}"),
    ("POST", "/api/acs/devices/{acs_id}/wifi"),
    ("POST", "/api/acs/devices/{acs_id}/reboot"),
    ("POST", "/api/acs/devices/{acs_id}/refresh"),
    ("POST", "/api/acs/devices/{acs_id}/tags/{tag}"),
    ("DELETE", "/api/acs/devices/{acs_id}/tags/{tag}"),
    ("POST", "/api/acs/devices/{acs_id}/adopt"),
    ("POST", "/api/acs/devices/{acs_id}/firmware"),
    ("GET", "/api/acs/jobs"),
    ("GET", "/api/acs/jobs/{job_id}"),
    ("DELETE", "/api/acs/jobs/{job_id}"),
    ("POST", "/api/acs/faults/{fault_id}/retry"),
    ("DELETE", "/api/acs/faults/{fault_id}"),
    ("POST", "/api/acs/bootstrap"),
    ("GET", "/api/acs/firmware"),
    ("POST", "/api/acs/firmware"),
    ("DELETE", "/api/acs/firmware/{name}"),
    ("GET", "/api/maintenance/plans"),
    ("POST", "/api/maintenance/plans"),
    ("PUT", "/api/maintenance/plans/{plan_id}"),
    ("DELETE", "/api/maintenance/plans/{plan_id}"),
    ("POST", "/api/maintenance/plans/{plan_id}/run"),
    ("GET", "/api/setup/records"),
    ("POST", "/api/setup/records"),
    ("POST", "/api/setup/records/{record_id}/reveal"),
}
# The only answers other than 2xx a replay may get, and why. A retried fault is
# GenieACS's own record, which the fake NBI does not have.
ALLOWED_REFUSALS = {
    ("POST", "/api/acs/faults/{fault_id}/retry"): (404, "fault"),
    ("DELETE", "/api/acs/faults/{fault_id}"): (404, "fault"),
}

# The page's view of the fleet: what the real server holds, as the API reports it.
PAGE_DATA = rf"""
const minutesAgo = (m) => new Date(Date.now() - m * 60000).toISOString();
harness.db.devices = [
  {{id: 'hk', vendor: 'cudy', host: '192.0.2.10', username: 'admin', model: 'Cudy AP1300', transport: 'web',
   enabled: true, metadata: {{name: 'Hennenman kantoor'}}, last_seen: minutesAgo(0),
   status: {{online: true, firmware: '2.5.25', uptime_seconds: 300, checked_at: minutesAgo(0)}}}},
  {{id: 't3', vendor: 'tplink', host: '192.0.2.11', username: 'admin', model: 'TL-WR840N', transport: 'web',
   enabled: true, metadata: {{name: 'Tower 3 office'}}, last_seen: minutesAgo(60),
   status: {{online: null, reason: 'credentials_rejected', error: 'the router refused the login'}}}},
];
harness.db.acs = {{configured: true, reachable: true, version: '1.2.16', error: null, cwmp_url: null,
  bootstrap: {{installed: false, drift: ['skybre-inform'], seeded_presets: []}}, problems: [], jobs: {{active: 0}},
  channel_faults: [{{id: '{FAULT}', device: '80AFCA-WR3000-AB%2D1', channel: 'skybre-inform', code: 'ext',
                     message: 'failed'}}]}};
harness.db.acsDevices = [
  {{acs_id: '80AFCA-WR3000-AB%2D1', manufacturer: 'Cudy', model: 'WR3000', serial: 'AB-1', firmware: '2.3.8',
   data_model: 'tr181', online: true, last_inform: minutesAgo(2), inform_interval: 300, tags: [],
   wifi: [{{band: '2.4GHz', band_source: 'reported', ssid: 'Home', enabled: true}}]}},
  {{acs_id: '80AFCA-WR1300-CD1', manufacturer: 'Cudy', model: 'WR1300', serial: 'CD1', firmware: '2.2.4',
   data_model: 'tr098', online: false, last_inform: minutesAgo(200), inform_interval: 300, tags: [],
   wifi: [{{band: '2.4GHz', band_source: 'reported', ssid: 'Shop', enabled: true}}]}},
];
harness.db.acsNew = [{{acs_id: '80AFCA-WR3000-NEW1', model: 'WR3000', serial: 'NEW1', tags: ['skybre_new'],
                       online: true, wifi: []}}];
harness.db.library = [{{name: '{LIBRARY_NAME}', filename: 'wr3000.bin', model_hint: 'Cudy WR3000', version: '2.4.2',
  oui: '80AFCA', product_class: 'WR3000', size: 2052, uploaded_at: minutesAgo(60), on_acs: true, in_use_by: []}},
  {{name: '{OLDER_NAME}', filename: 'wr3000-old.bin', model_hint: 'Cudy WR3000', version: '2.4.1',
  oui: '80AFCA', product_class: 'WR3000', size: 2052, uploaded_at: minutesAgo(90), on_acs: true, in_use_by: []}}];
harness.db.plans = [{{id: '{PLAN_ID}', name: 'Weekly Sunday reboot', enabled: true,
  targets: {{all: true, devices: [], acs_devices: [], groups: []}},
  schedule: {{days: ['sun'], monthly_day: null, start: '02:00', duration_minutes: 120,
             timezone: 'Africa/Johannesburg'}},
  actions: ['firmware_check', 'reboot'], firmware: {{}},
  guards: {{min_uptime_seconds: 3600, skip_if_clients_over: null, cooldown_hours: 20}},
  next_window: null, window_open: false, last_run: null}}];
harness.db.records = [{{id: '{RECORD_ID}', customer: '#1057 Customer B', model: 'Cudy M3000 mesh', ip: '10.20.0.57',
  method: 'managed', ssid_24: 'CustomerB', created_at: minutesAgo(30), checklist: {{remote_management: true}},
  checklist_complete: false, password_saved: true}}];
const job = (kind, state) => ({{id: '{JOB}', acs_id: '80AFCA-WR3000-AB%2D1', kind, state, message: '',
  expected_by: null, cr_attempts: [], last_error: null, terminal: state !== 'queued', done: state !== 'queued'}});
const firmware = {{version: '2.5.25', hardware: 'AP1300 V1.1',
                   auto_update: {{enabled: true, window_start_hour: 3, window: '03:00-05:00'}}}};
harness.handler = (req) => {{
  const [path] = req.path.split('?');
  if (/\/api\/acs\/devices\/[^/]+\/(wifi|reboot|refresh|firmware)$/.test(path) && req.method === 'POST') {{
    return {{status: 202, body: {{job: job(path.split('/').pop(), 'queued')}}}};
  }}
  if (path === '/api/acs/jobs/{JOB}') {{
    return {{status: 200, body: {{job: job('wifi', req.method === 'DELETE' ? 'cancelled' : 'queued')}}}};
  }}
  if (path === '/api/devices/hk/firmware') return {{status: 200, body: {{device: 'hk', firmware}}}};
  if (path === '/api/devices/hk/firmware/check') return {{status: 200, body: {{check: {{available: false}}}}}};
  if (path.includes('/tags/')) return {{status: 200, body: {{tags: req.method === 'POST' ? ['shop_42'] : []}}}};
  if (path.endsWith('/reveal')) return {{status: 200, body: {{wifi_password: 'sunflower-garden-7'}}}};
  if (path.endsWith('/run')) return {{status: 200, body: {{results: [{{status: 'done'}}]}}}};
  return undefined;
}};
"""
PW = json.dumps("correct-horse-9")

DIRECT = f"""
await harness.open('Hennenman kantoor');
await harness.press(byId('t-devices'));
await harness.press(byId('t-history'));
await harness.press(byId('t-overview'));
await harness.press(harness.button(byId('p-overview'), 'Check for updates'));
await harness.press(byId('d-wifi'));
await harness.press(byId('band-seg').querySelector('[data-band="2.4"]'));
byId('w-ssid').value = 'Office';
byId('w-pw1').value = {PW}; byId('w-pw2').value = {PW};
await harness.press(byId('wifi-send'));
await harness.press(byId('d-wifi'));
byId('w-ssid').value = 'Office-all';
await harness.press(byId('wifi-send'));
await harness.press(byId('d-reboot'));
await harness.press(byId('reboot-ok'));
await harness.press(byId('d-refresh'));
await harness.press(byId('d-more'));
await harness.press(byId('d-admin'));
byId('pw-new').value = 'new-admin-1'; byId('pw-confirm').value = 'new-admin-1';
await harness.press(byId('pw-save'));
await harness.open('Tower 3 office');
await harness.press(byId('d-more'));
await harness.press(byId('d-remove'));
await harness.press(byId('confirm-ok'));
"""

MANAGED = f"""
await harness.open('WR3000 · AB-1');
await harness.press(byId('d-wifi'));
byId('w-ssid').value = 'Home-new';
byId('w-pw1').value = {PW}; byId('w-pw2').value = {PW};
await harness.press(byId('wifi-send'));
await harness.advance(2000);
await harness.press(harness.button(byId('toasts'), 'Cancel change'));
await harness.press(byId('confirm-ok'));
await harness.press(byId('d-refresh'));
await harness.press(byId('refresh-send'));
await harness.press(byId('d-more'));
await harness.press(byId('d-tags'));
byId('tag-input').value = 'shop_42';
await harness.press(byId('tags-add'));
await harness.press(byId('tags-list').querySelector('button'));
byId('tags-dialog').close();
await harness.open('WR1300 · CD1');
await harness.press(byId('d-reboot'));
await harness.press(byId('reboot-ok'));
await harness.press(byId('new-pill'));
byId('new-list').querySelector('input').value = '#1080 Customer E';
await harness.press(harness.button(byId('new-list'), 'Adopt'));
byId('new-dialog').close();
const notes = byId('routers-notes');
await harness.press(harness.button(notes, 'Retry'));
await harness.press(harness.button(notes, 'Clear'));
await harness.press(byId('confirm-ok'));
await harness.press(harness.button(notes, 'Install provisioning'));
await harness.press(byId('confirm-ok'));
"""

ACTIVITY = """
harness.db.activity = [{id: 'e1', at: new Date().toISOString(), who: 'Skybre staff', router: 'hk',
  router_name: 'hk', kind: 'wifi', what: 'Wi-Fi name changed', result: 'applied', details: {}}];
harness.db.nextBefore = 'e1';
await harness.go('#activity');
await harness.press(byId('activity-more'));
await harness.choose(byId('f-type'), 'wifi');
await harness.choose(byId('f-router'), 'hk');
await harness.choose(byId('f-who'), 'Skybre staff');
return byId('export').getAttribute('href');
"""

SETUP = """
await harness.go('#setup');
const fill = () => {
  byId('s-customer').value = '#1080 Customer E';
  byId('s-ip').value = '10.20.0.15';
  byId('s-ssid24').value = 'CustomerE';
  byId('s-ssid5').value = 'CustomerE-5G';
  byId('s-wifipass').value = 'sunflower-garden-7';
  byId('s-notes').value = 'lounge';
};
fill();
byId('s-name').value = 'Customer 1080 home';
for (const id of ['c-remote', 'c-acs', 'c-default', 'c-firmware']) await harness.press(byId(id));
await harness.press(byId('setup-save'));
// The saved form clears its checklist a tick later.
await harness.advance(0);
fill();
byId('s-name').value = 'Customer 1080 office';
await harness.press(byId('s-method').querySelector('[data-method=direct]'));
await harness.choose(byId('s-model'), 'Tenda');
byId('s-admin-pass').value = 'router-admin-1';
await harness.press(byId('c-remote'));
await harness.press(byId('setup-save'));
await harness.press(harness.button(byId('records'), 'Show password'));
"""

MAINTENANCE = """
await harness.go('#maintenance');
for (const target of ['all', 'managed', 'direct', 'cudy']) {
  await harness.press(byId('new-plan'));
  byId('p-name').value = `Plan ${target}`;
  await harness.press(byId('p-target').querySelector(`[data-target=${target}]`));
  await harness.press(harness.button(byId('p-days'), 'Wed'));
  byId('g-clients').value = '5';
  await harness.press(byId('a-auto'));
  if (target === 'managed') await harness.press(byId('a-install'));
  await harness.press(byId('plan-save'));
}
const card = () => byId('plans').querySelector('.plan');
await harness.press(harness.button(card(), 'Edit'));
byId('p-name').value = 'Sunday reboot';
await harness.press(byId('plan-save'));
await harness.press(card().querySelector('input[type=checkbox]'));
await harness.press(harness.button(card(), 'Run now'));
await harness.press(byId('confirm-ok'));
await harness.press(harness.button(card(), 'Edit'));
await harness.press(byId('plan-delete'));
await harness.press(byId('confirm-ok'));
await harness.press(byId('mt-firmware'));
const row = (key) => byId('fw-rows').children.find((tr) => tr.dataset.key === key);
await harness.press(harness.button(row('direct:hk'), 'Change window'));
byId('auto-window').value = '1';
await harness.press(byId('auto-save'));
await harness.press(harness.button(row('direct:hk'), 'Change window'));
await harness.press(byId('auto-on'));
await harness.press(byId('auto-save'));
await harness.press(harness.button(row('direct:hk'), 'Check now'));
await harness.press(harness.button(row('acs:80AFCA-WR3000-AB%2D1'), 'Install 2.4.2'));
await harness.press(byId('confirm-ok'));
byId('fw-file').files = [{name: 'wr3000 v2.4.3.bin', size: 2052}];
byId('fw-version').value = '2.4.3';
await harness.choose(byId('fw-model'), '80AFCA|WR3000');
await harness.press(byId('fw-upload'));
await harness.press(byId('fw-library').children[1].querySelector('button'));
await harness.press(byId('confirm-ok'));
"""

SIGN_OUT = """
await harness.press(byId('signout'));
"""


# --- the real server ---------------------------------------------------------------------


@pytest.fixture(autouse=True)
def loopback_only(monkeypatch):
    """Fail on any connection off this machine: no router may be contacted from here."""
    real = socket.socket.connect

    def connect(self, address):
        host = address[0] if isinstance(address, tuple) else address
        if host not in ("127.0.0.1", "::1", "localhost"):
            raise AssertionError(f"the contract test tried to reach {address!r}")
        return real(self, address)

    monkeypatch.setattr(socket.socket, "connect", connect)


def tr181(serial: str, product_class: str, tags: tuple[str, ...] = ()) -> dict[str, Any]:
    leaves = {
        "Device.ManagementServer.ConnectionRequestURL": {"value": "http://10.10.0.40:7547/", "writable": False},
        "Device.ManagementServer.PeriodicInformInterval": 300,
        "Device.DeviceInfo.Manufacturer": {"value": "Cudy", "writable": False},
        "Device.DeviceInfo.ModelName": {"value": product_class, "writable": False},
        "Device.DeviceInfo.SoftwareVersion": {"value": "2.3.8", "writable": False},
        f"{WIFI}.Radio.1.OperatingFrequencyBand": "2.4GHz",
        f"{WIFI}.SSID.1.SSID": "Home",
        f"{WIFI}.SSID.1.LowerLayers": "Device.WiFi.Radio.1.",
        f"{WIFI}.AccessPoint.1.SSIDReference": "Device.WiFi.SSID.1.",
        f"{WIFI}.AccessPoint.1.Security.ModeEnabled": "WPA2-Personal",
        f"{WIFI}.AccessPoint.1.Security.KeyPassphrase": "",
    }
    return build_device(oui="80AFCA", product_class=product_class, serial=serial, manufacturer="Cudy",
                        leaves=leaves, tags=tags)


def tr098(serial: str, product_class: str) -> dict[str, Any]:
    wlan = f"{IGD}.LANDevice.1.WLANConfiguration.1"
    leaves = {
        f"{IGD}.ManagementServer.ConnectionRequestURL": {"value": "http://10.10.0.41:7547/", "writable": False},
        f"{IGD}.ManagementServer.PeriodicInformInterval": 300,
        f"{IGD}.DeviceInfo.Manufacturer": {"value": "Cudy", "writable": False},
        f"{wlan}.SSID": "Shop",
        f"{wlan}.Channel": 6,
        f"{wlan}.BeaconType": "11i",
        f"{wlan}.IEEE11iAuthenticationMode": "PSKAuthentication",
        f"{wlan}.KeyPassphrase": "",
        f"{wlan}.PreSharedKey.1.KeyPassphrase": "",
    }
    return build_device(oui="80AFCA", product_class=product_class, serial=serial, manufacturer="Cudy", leaves=leaves)


def no_router_calls(manager: DeviceManager) -> None:
    """Answer every call that would reach a direct router, after web.py has checked the request."""
    canned = {
        "get_all_statuses": {},
        "get_status": {"online": True},
        "reboot_device": True,
        "get_connected_clients": [],
        "set_wifi_ssid": True,
        "set_wifi_password": True,
        "set_auto_update": True,
        "firmware_info": {"version": "2.5.25", "hardware": "AP1300 V1.1", "auto_update": None},
        "check_firmware_update": {"available": False, "current": "2.5.25", "latest": None},
    }
    for name, value in canned.items():
        setattr(manager, name, lambda *_, _value=value, **__: _value)
    manager.set_password = lambda identifier, *_, **__: {"device": identifier, "verified": None}  # type: ignore[method-assign]


class Server:
    """The app under uvicorn on a free loopback port, signed in with the passkey.

    A real server rather than TestClient, which decodes a path twice: an ACS ID
    holds a literal "%", so only a real server shows what the page's paths name.
    """

    def __init__(self, port: int):
        self.port = port
        self.cookie = ""
        self.csrf = ""

    def send(self, method: str, path: str, body: bytes | None = None, kind: str | None = None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        headers = {"Accept": "application/json"}
        if kind:
            headers["Content-Type"] = kind
        if self.cookie:
            headers.update({"Cookie": self.cookie, "X-CSRF-Token": self.csrf})
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read()
        cookie = response.getheader("set-cookie")
        media = response.getheader("content-type") or ""
        connection.close()
        payload = json.loads(raw or b"null") if media.startswith("application/json") else raw.decode()
        return response.status, payload, cookie, media

    def sign_in(self) -> None:
        status, payload, cookie, _ = self.send(
            "POST", "/login", json.dumps({"passkey": PASSKEY}).encode(), "application/json"
        )
        assert status == 200 and cookie, payload
        self.cookie, self.csrf = cookie.split(";", 1)[0], payload["csrf_token"]


@contextmanager
def served(tmp_path: Path, nbi: FakeNbi) -> Iterator[tuple[Server, Any]]:
    data = tmp_path / "data"
    store = SecretStore(data)
    activity = ActivityLog(data)
    manager = DeviceManager(config_path=tmp_path / "devices.yaml", data_dir=data, secret_store=store,
                            activity=activity)
    manager.add_device("hk", "192.0.2.10", "cudy", password="router-pass-1", username="admin", model="Cudy AP1300")
    manager.add_device("t3", "192.0.2.11", "tplink", password="router-pass-2", username="admin", model="TL-WR840N")
    no_router_calls(manager)
    settings = Settings(username="admin", password=PASSKEY, secure_cookie=False, scheduler_interval=3600,
                        config_path=tmp_path / "devices.yaml", data_dir=data)
    service = AcsService(AcsClient(nbi.url, timeout=5), store, data, clock=nbi.now, activity=activity)
    app = create_app(manager=manager, settings=settings, acs_service=service, activity=activity)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    server = uvicorn.Server(uvicorn.Config(app, lifespan="off", log_level="warning"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 5
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.01)
    assert server.started, "uvicorn did not start"
    try:
        client = Server(sock.getsockname()[1])
        client.sign_in()
        yield client, app
    finally:
        server.should_exit = True
        thread.join(5)
        sock.close()


def route_of(app, method: str, path: str) -> str | None:
    """The template of the app's route that serves this request, as uvicorn decodes its path."""
    from starlette.routing import Match

    scope = {"type": "http", "method": method, "path": unquote(path.split("?", 1)[0]), "root_path": ""}
    for route in app.routes:
        match, _ = route.matches(scope)
        if match == Match.FULL:
            return route.path
    return None


def swap(value: Any, ids: dict[str, str]) -> Any:
    """The page's placeholder ids in a path or body, replaced by the real server's."""
    if isinstance(value, str):
        for placeholder, real in ids.items():
            value = value.replace(placeholder, real)
        return value
    if isinstance(value, list):
        return [swap(item, ids) for item in value]
    if isinstance(value, dict):
        return {key: swap(item, ids) for key, item in value.items()}
    return value


# --- the replay ------------------------------------------------------------------------------


@needs_node
def test_every_request_the_page_makes_is_one_the_server_takes(tmp_path: Path):
    assert NODE is not None
    requests: list[dict[str, Any]] = []
    for number, scenario in enumerate((DIRECT, MANAGED, ACTIVITY, SETUP, MAINTENANCE, SIGN_OUT)):
        (tmp_path / f"page{number}").mkdir()
        outcome = run_page(tmp_path / f"page{number}", scenario, setup=PAGE_DATA)
        requests.extend(outcome["requests"])
        if scenario is ACTIVITY:
            # The export is a link, not a fetch, but it is a request all the same.
            requests.append({"method": "GET", "path": outcome["result"], "headers": {}, "body": None})

    with FakeNbi() as nbi:
        nbi.add_device(tr181("AB-1", "WR3000"))
        nbi.add_device(tr098("CD1", "WR1300"))
        nbi.add_device(tr181("NEW1", "WR3000", tags=("skybre_new",)))
        with served(tmp_path, nbi) as (server, app):
            ids = {}
            # What the page was shown as already there, made for real.
            record = server.send("POST", "/api/setup/records", json.dumps({
                "customer": "#1057 Customer B", "model": "Cudy M3000 mesh", "ip": "10.20.0.57",
                "method": "managed", "ssid_24": "CustomerB", "wifi_password": "garden-sunflower-8",
                "checklist": {"remote_management": True},
            }).encode(), "application/json")
            assert record[0] == 201, record[1]
            ids[RECORD_ID] = record[1]["record"]["id"]
            plan = server.send("POST", "/api/maintenance/plans", json.dumps({
                "name": "Weekly Sunday reboot", "targets": {"all": True}, "actions": ["firmware_check", "reboot"],
                "schedule": {"days": ["sun"], "start": "02:00", "duration_minutes": 120,
                             "timezone": "Africa/Johannesburg"},
            }).encode(), "application/json")
            assert plan[0] == 201, plan[1]
            ids[PLAN_ID] = plan[1]["plan"]["id"]
            query = "version=2.4.2&oui=80AFCA&product_class=WR3000&filename=wr3000.bin&model_hint=Cudy%20WR3000"
            library = server.send("POST", f"/api/acs/firmware?{query}", IMAGE, "application/octet-stream")
            assert library[0] == 201, library[1]
            ids[LIBRARY_NAME] = library[1]["firmware"]["name"]
            older = server.send("POST", f"/api/acs/firmware?{query.replace('2.4.2', '2.4.1')}", IMAGE[::-1],
                                "application/octet-stream")
            assert older[0] == 201, older[1]
            ids[OLDER_NAME] = older[1]["firmware"]["name"]

            reached, problems = set(), []
            for request in requests:
                method, path = request["method"], swap(request["path"], ids)
                if "before=" + ENTRY_ID in path:
                    # The page pages on with the id the server gave it; this is the newest real one.
                    newest = server.send("GET", "/api/activity?limit=1")[1]["entries"][0]["id"]
                    path = path.replace("before=" + ENTRY_ID, "before=" + newest)
                template = route_of(app, method, path)
                if template is None:
                    problems.append(f"{method} {path}: no such route")
                    continue
                reached.add((method, template))
                body, kind = None, request["headers"].get("Content-Type")
                if kind == "application/octet-stream":
                    body = IMAGE
                elif request["body"] is not None:
                    body = json.dumps(swap(request["body"], ids)).encode()
                status, payload, _, _ = server.send(method, path, body, kind)
                if isinstance(payload, dict) and isinstance(payload.get("job"), dict):
                    ids[JOB] = payload["job"]["id"]
                allowed = ALLOWED_REFUSALS.get((method, template))
                if 200 <= status < 300:
                    continue
                detail = payload.get("detail") if isinstance(payload, dict) else payload
                if allowed and status == allowed[0] and allowed[1] in str(detail).lower():
                    continue
                problems.append(f"{method} {path} {json.dumps(request['body'])}: {status} {detail}")

    assert problems == []
    assert reached == EXPECTED_ROUTES, (sorted(EXPECTED_ROUTES - reached), sorted(reached - EXPECTED_ROUTES))
    # Each way of filling the two biggest forms was sent, not only one of them.
    bodies = {path: [r["body"] for r in requests if r["method"] == "POST" and r["path"] == path]
              for path in ("/api/setup/records", "/api/maintenance/plans")}
    assert sorted(body["method"] for body in bodies["/api/setup/records"]) == ["direct", "managed"]
    assert [body["targets"] for body in bodies["/api/maintenance/plans"]] == [
        {"all": True}, {"groups": ["managed"]}, {"groups": ["direct"]}, {"groups": ["cudy"]},
    ]


def test_every_route_the_page_names_in_its_source_is_listed_here():
    # A new fetch in the page must be added to the replay above, or it goes untested.
    page = (Path(__file__).resolve().parents[1] / "cudy_manager" / "dashboard.html").read_text()
    named = set(re.findall(r"['`](/(?:api|logout)[a-z/.-]*)", page))
    prefixes = {template.split("{", 1)[0].rstrip("/") for _, template in EXPECTED_ROUTES}
    unlisted = sorted(path for path in named if path.rstrip("/") not in prefixes and not any(
        path.startswith(prefix + "/") for prefix in prefixes if prefix))
    assert unlisted == []
