"""Setup records: the Setup page's "Program a new router".

Every store and app here uses a real SecretStore, DeviceManager and ActivityLog,
so a record that leaked a secret, or an entry the activity log refuses, shows up
as such. No router is contacted: adding a direct router only writes the config.
"""

import json
import logging
import stat
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from cudy_manager import setup_records
from cudy_manager.activity import ActivityLog
from cudy_manager.manager import DeviceManager, ManagerError
from cudy_manager.models import ValidationError
from cudy_manager.secrets import SecretStore
from cudy_manager.setup_records import (
    DIRECT_UNSUPPORTED,
    MODELS,
    REMOTE_MANAGEMENT_REQUIRED,
    RecordNotFound,
    SavedPasswordMissing,
    SetupRecords,
    SetupRecordsError,
    validate_setup,
    vendor_of,
)
from cudy_manager.web import Settings, create_app

PASSKEY = "correct horse battery staple"
WIFI = "sunflower-garden-7"
ADMIN = "Adm1n-only-in-the-vault"
AT = datetime(2026, 9, 27, 16, 40, tzinfo=UTC)
ALL_TICKED = {
    "remote_management": True,
    "acs_configured": True,
    "default_password_changed": True,
    "firmware_updated": True,
}
# Every key a listed record has; anything else would be a field nobody reviewed.
PUBLIC_KEYS = {
    "id",
    "customer",
    "name",
    "model",
    "vendor",
    "ip",
    "method",
    "admin_username",
    "ssid_24",
    "ssid_5",
    "notes",
    "checklist",
    "device_id",
    "created_at",
    "created_by",
    "password_saved",
    "admin_password_saved",
    "device_present",
    "checklist_complete",
}


def managed(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "customer": "#1057 · Customer B",
        "model": "Cudy M3000 mesh",
        "ip": "10.20.0.57",
        "method": "managed",
        "ssid_24": "CustomerB-Home",
        "wifi_password": WIFI,
        "checklist": dict(ALL_TICKED),
    }
    body.update(overrides)
    return body


def direct(**overrides: Any) -> dict[str, Any]:
    body = managed(
        customer="#1080",
        name="Customer 1080 home",
        model="Cudy WR3000",
        ip="192.0.2.80",
        method="direct",
        admin_username="admin",
        admin_password=ADMIN,
        checklist={"remote_management": True, "default_password_changed": True, "firmware_updated": True},
    )
    body.update(overrides)
    return body


class Clock:
    def __init__(self) -> None:
        self.now = AT

    def __call__(self) -> datetime:
        self.now += timedelta(seconds=1)
        return self.now


def no_router_contact(manager: DeviceManager, monkeypatch) -> None:
    def refuse(device):
        raise AssertionError(f"setup contacted {device.identifier}")

    monkeypatch.setattr(manager, "adapter_for", refuse)


@pytest.fixture
def parts(tmp_path: Path, monkeypatch):
    data = tmp_path / "data"
    vault = SecretStore(data)
    log = ActivityLog(data)
    manager = DeviceManager(config_path=tmp_path / "devices.yaml", data_dir=data, secret_store=vault, activity=log)
    no_router_contact(manager, monkeypatch)
    store = SetupRecords(data, vault, manager, log, clock=Clock())
    return store, vault, manager, log


def secret_refs(vault: SecretStore) -> list[str]:
    return [reference for reference in vault.references() if reference.startswith("setup-")]


def assert_no_secret(*texts: str) -> None:
    for text in texts:
        assert WIFI not in text and ADMIN not in text, text[:300]


# --- validation -------------------------------------------------------------------------------------


class TestValidation:
    def test_the_models_are_the_designs_list(self):
        assert MODELS == (
            "Cudy WR3000",
            "Cudy WR1300",
            "Cudy M3000 mesh",
            "Cudy AP1300 access point",
            "TP-Link Archer C64",
            "TP-Link TL-WR840N",
            "Tenda",
            "Other",
        )
        assert [vendor_of(model) for model in MODELS] == ["cudy"] * 4 + ["tplink"] * 2 + ["tenda", None]

    def test_a_managed_record_is_normalised(self):
        request = validate_setup(
            managed(customer="  #1057   Customer B ", ssid_5="", name=None, notes="lounge\r\n  second   line \n")
        )
        assert request.customer == "#1057 Customer B"
        assert request.name == "#1057 Customer B router"
        assert request.ssid_5 == request.ssid_24 == "CustomerB-Home"
        assert request.notes == "lounge\nsecond line"
        assert request.vendor == "cudy" and request.admin_password is None
        assert request.checklist == ALL_TICKED

    def test_the_passwords_stay_out_of_repr(self):
        text = repr(validate_setup(direct()))
        assert WIFI not in text and ADMIN not in text
        assert "Customer 1080 home" in text

    @pytest.mark.parametrize("ip", ["10.20.0.15", "router-1080.skybre.lan", " 10.0.0.1 "])
    def test_an_ipv4_address_or_hostname_is_accepted(self, ip):
        assert validate_setup(managed(ip=ip)).ip == ip.strip()

    @pytest.mark.parametrize(
        "overrides,message",
        [
            ({"customer": " "}, "Enter the Vexar customer."),
            ({"customer": None}, "Enter the Vexar customer."),
            ({"customer": 1057}, "customer must be text"),
            ({"customer": "x" * 81}, "customer must be at most 80 characters"),
            ({"customer": "a\x00b"}, "customer must not contain control characters"),
            ({"customer": "a\u202eb"}, "customer must not contain control characters"),
            ({"customer": "a\ud800"}, "customer must be valid Unicode text"),
            ({"name": "x" * 101}, "name must be at most 100 characters"),
            ({"model": "Cudy X9"}, "Choose the router model from the list: Cudy WR3000, "),
            ({"model": None}, "Choose the router model from the list"),
            ({"ip": ""}, "Enter the router IP address, e.g. 10.20.0.15."),
            ({"ip": "http://10.0.0.1"}, "without http://, a path or a port"),
            ({"ip": "10.0.0.1:8080"}, "without http://, a path or a port"),
            ({"ip": "10.0.0.1/24"}, "without http://, a path or a port"),
            ({"ip": "10.0.0 .1"}, "without http://, a path or a port"),
            ({"ip": "10.0.0.1\x00"}, "without http://, a path or a port"),
            ({"ip": "10.20.0.256"}, "That is not an IPv4 address"),
            ({"ip": "10.20.0"}, "That is not an IPv4 address"),
            ({"method": None}, 'method must be "managed"'),
            ({"method": "ssh"}, 'method must be "managed"'),
            ({"ssid_24": ""}, "Enter the Wi-Fi name."),
            ({"ssid_24": "é" * 17}, "2.4 GHz Wi-Fi name: SSID must be at most 32 bytes"),
            ({"ssid_5": "x" * 33}, "5 GHz Wi-Fi name: SSID must be at most 32 bytes"),
            ({"wifi_password": ""}, "Enter the Wi-Fi password."),
            ({"wifi_password": None}, "Enter the Wi-Fi password."),
            ({"wifi_password": "short"}, "Wi-Fi password must be 8 to 63 characters"),
            ({"wifi_password": "x" * 64}, "Wi-Fi password must be 8 to 63 characters"),
            ({"wifi_password": "pässword1"}, "printable ASCII"),
            ({"wifi_password": 12345678}, "Wi-Fi password must be a string"),
            ({"admin_password": 5}, "admin_password must be text"),
            ({"admin_password": "x" * 129}, "at most 128 characters"),
            ({"notes": "x" * 501}, "notes must be at most 500 characters"),
            ({"notes": "bell\x07"}, "notes must not contain control characters"),
            ({"notes": f"password is {WIFI}"}, "The Wi-Fi password must not appear in the notes"),
            ({"ssid_24": WIFI}, "The Wi-Fi password must not appear in the Wi-Fi name"),
            ({"customer": f"#1 {WIFI}"}, "The Wi-Fi password must not appear in the customer"),
            ({"checklist": None}, REMOTE_MANAGEMENT_REQUIRED),
            ({"checklist": {**ALL_TICKED, "remote_management": False}}, REMOTE_MANAGEMENT_REQUIRED),
            ({"checklist": {**ALL_TICKED, "remote_management": "yes"}}, "checklist.remote_management must be true"),
            ({"checklist": {**ALL_TICKED, "colour": True}}, "checklist has unknown field(s): colour"),
            ({"checklist": ["remote_management"]}, "checklist must be an object"),
            ({"password": "x"}, "unexpected field(s): password"),
            ({"wifi_password_ref": "device-r1-password"}, "unexpected field(s): wifi_password_ref"),
        ],
    )
    def test_problems_are_refused_with_a_plain_message(self, overrides, message):
        with pytest.raises(ValidationError) as caught:
            validate_setup(managed(**overrides))
        assert message in str(caught.value)
        assert WIFI not in str(caught.value)

    def test_the_remote_management_message_is_the_designs(self):
        assert REMOTE_MANAGEMENT_REQUIRED == (
            'Tick "Remote web management is on" first. '
            "Without it Skybre cannot reach this router after installation."
        )

    def test_a_direct_router_needs_its_admin_password_and_a_make_skybre_can_sign_in_to(self):
        with pytest.raises(ValidationError, match="Enter the router admin password so Skybre can sign in to it."):
            validate_setup(direct(admin_password=""))
        with pytest.raises(ValidationError) as caught:
            validate_setup(direct(model="Other"))
        assert str(caught.value) == DIRECT_UNSUPPORTED
        assert validate_setup(direct(model="Tenda")).vendor == "tenda"
        # A router that checks in by itself may be any make, with or without an admin password.
        assert validate_setup(managed(model="Other")).vendor is None

    def test_a_body_that_is_not_an_object_is_refused(self):
        with pytest.raises(ValidationError, match="must be an object"):
            validate_setup(["customer"])


# --- the store ---------------------------------------------------------------------------------------


class TestStore:
    def test_the_passwords_are_kept_only_in_the_vault(self, parts):
        store, vault, _, _ = parts
        created = store.create(managed(admin_password=ADMIN), "alice")
        record = created["record"]
        assert created["device"] is None
        assert set(record) == PUBLIC_KEYS
        assert record["password_saved"] is True and record["admin_password_saved"] is False
        assert vault.get(f"setup-{record['id']}-wifi") == WIFI
        # A router that checks in by itself is never signed in to, so nothing would ever use its admin password.
        assert not vault.has(f"setup-{record['id']}-admin")
        assert ADMIN not in [vault.get(reference) for reference in vault.references()]
        text = store.path.read_text()
        assert_no_secret(text, json.dumps(created), json.dumps(store.list()))
        assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
        stored = json.loads(text)["records"][record["id"]]
        assert stored["wifi_password_ref"] == f"setup-{record['id']}-wifi"

    def test_a_listing_says_whether_a_password_is_saved_rather_than_showing_it(self, parts):
        store, vault, _, _ = parts
        record = store.create(managed(), "alice")["record"]
        (listed,) = store.list()
        assert set(listed) == PUBLIC_KEYS
        assert listed["password_saved"] is True and listed["admin_password_saved"] is False
        vault.delete(f"setup-{record['id']}-wifi")
        assert store.list()[0]["password_saved"] is False

    def test_programming_is_logged_without_a_secret(self, parts):
        store, _, _, log = parts
        record = store.create(managed(ssid_5="CustomerB-5G", admin_password=ADMIN), "alice")["record"]
        (entry,) = log.list()
        assert (entry["who"], entry["router"], entry["kind"], entry["result"]) == (
            "alice",
            f"setup:{record['id']}",
            "setup",
            "applied",
        )
        assert entry["what"] == (
            'Programmed: linked to #1057 · Customer B, IP 10.20.0.57, Wi-Fi "CustomerB-Home" (2.4 GHz), '
            '"CustomerB-5G" (5 GHz)'
        )
        assert entry["router_name"] == "#1057 · Customer B router"
        assert entry["details"]["checks"] == list(ALL_TICKED)
        assert_no_secret(json.dumps(entry), log.export_csv())

    def test_one_network_name_is_named_once(self, parts):
        store, _, _, log = parts
        store.create(managed(), "alice")
        what = log.list()[0]["what"]
        assert what == 'Programmed: linked to #1057 · Customer B, IP 10.20.0.57, Wi-Fi "CustomerB-Home"'

    def test_a_direct_router_joins_the_router_list_without_being_contacted(self, parts):
        store, _, manager, log = parts
        created = store.create(direct(), "alice")
        device = manager.get_device("customer-1080-home")
        assert (device.host, device.vendor, device.username, device.model) == (
            "192.0.2.80",
            "cudy",
            "admin",
            "Cudy WR3000",
        )
        assert device.metadata == {
            "name": "Customer 1080 home",
            "customer": "#1080",
            "setup_record": created["record"]["id"],
        }
        assert manager.credentials(device) == ADMIN
        assert created["device"]["id"] == created["record"]["device_id"] == "customer-1080-home"
        assert created["record"]["device_present"] is True
        # The manager's own entry for the router, then the record's, both under its id.
        added, programmed = reversed(log.list())
        assert added["what"] == "Added cudy router at 192.0.2.80:80" and added["who"] == "alice"
        assert programmed["router"] == "customer-1080-home" and programmed["what"].startswith("Programmed:")
        assert_no_secret(json.dumps(log.list()), json.dumps(created), (manager.config_path).read_text())

    def test_removing_a_router_set_up_here_leaves_no_copy_of_its_admin_password(self, parts):
        # The router list's own copy is the one it signs in with; a second one here outlived the router.
        store, vault, manager, _ = parts
        record = store.create(direct(), "alice")["record"]
        assert record["admin_password_saved"] is False
        assert [vault.get(reference) for reference in vault.references()].count(ADMIN) == 1
        manager.remove_device(record["device_id"], actor="bob")
        assert ADMIN not in [vault.get(reference) for reference in vault.references()]
        assert store.reveal(record["id"], "bob") == WIFI, "the record keeps its Wi-Fi password"

    def test_a_tplink_without_a_username_gets_its_own_default(self, parts):
        store, _, manager, _ = parts
        record = store.create(direct(model="TP-Link TL-WR840N", admin_username=None), "alice")["record"]
        assert manager.get_device(record["device_id"]).username == "admin"
        assert record["admin_username"] == "admin"

    def test_device_ids_come_from_the_name_and_never_collide(self, parts):
        store, _, manager, _ = parts
        first = store.create(direct(), "alice")["record"]
        second = store.create(direct(ip="192.0.2.81"), "alice")["record"]
        third = store.create(direct(name="Café Ümlaut / shop", ip="192.0.2.82"), "alice")["record"]
        assert [first["device_id"], second["device_id"], third["device_id"]] == [
            "customer-1080-home",
            "customer-1080-home-2",
            "cafe-umlaut-shop",
        ]
        assert len(manager.get_all_devices()) == 3

    def test_records_are_listed_newest_first_even_when_the_clock_steps_back(self, parts):
        store, vault, manager, log = parts
        moments = iter([AT, AT - timedelta(hours=1), AT - timedelta(hours=1)])
        store = SetupRecords(store.data_dir, vault, manager, log, clock=lambda: next(moments))
        for customer in ("#1", "#2", "#3"):
            store.create(managed(customer=customer), "alice")
        assert [record["customer"] for record in store.list()] == ["#3", "#2", "#1"]

    def test_the_checklist_counts_only_what_applies_to_the_method(self, parts):
        store, _, _, _ = parts
        partial = {**ALL_TICKED, "acs_configured": False}
        assert store.create(managed(checklist=partial), "a")["record"]["checklist_complete"] is False
        assert store.create(direct(checklist=partial), "a")["record"]["checklist_complete"] is True
        assert store.create(managed(), "a")["record"]["checklist_complete"] is True

    def test_a_removed_router_shows_on_its_record(self, parts):
        store, _, manager, _ = parts
        record = store.create(direct(), "alice")["record"]
        manager.remove_device(record["device_id"], actor="bob")
        (listed,) = store.list()
        assert listed["device_id"] == "customer-1080-home" and listed["device_present"] is False

    def test_a_reveal_is_logged_before_the_password_is_handed_over(self, parts):
        store, _, _, log = parts
        record = store.create(managed(), "alice")["record"]
        assert store.reveal(record["id"], "bob") == WIFI
        entry = log.list()[0]
        assert (entry["who"], entry["kind"], entry["what"], entry["result"]) == (
            "bob",
            "access",
            "Viewed the saved Wi-Fi password",
            "info",
        )
        assert entry["router"] == f"setup:{record['id']}" and entry["details"] == {"record": record["id"]}
        assert_no_secret(json.dumps(log.list()))

    def test_a_reveal_that_cannot_be_logged_shows_nothing(self, parts, monkeypatch):
        store, vault, manager, log = parts
        record = store.create(managed(), "alice")["record"]

        def full(**_entry):
            raise OSError("No space left on device")

        monkeypatch.setattr(log, "record", full)
        with pytest.raises(SetupRecordsError, match="so the password was not shown"):
            store.reveal(record["id"], "bob")
        unlogged = SetupRecords(store.data_dir, vault, manager, None)
        with pytest.raises(SetupRecordsError, match="no activity log"):
            unlogged.reveal(record["id"], "bob")

    def test_a_hand_edited_record_cannot_reveal_another_secret(self, parts):
        store, vault, manager, log = parts
        record = store.create(direct(), "alice")["record"]
        router_ref = manager.get_device(record["device_id"]).password_ref
        saved = json.loads(store.path.read_text())
        saved["records"][record["id"]]["wifi_password_ref"] = router_ref
        store.path.write_text(json.dumps(saved))
        logged = len(log.list())
        with pytest.raises(SetupRecordsError, match="does not name its own saved Wi-Fi password") as caught:
            store.reveal(record["id"], "bob")
        assert ADMIN not in str(caught.value)
        # Nothing was shown, so nothing is logged as viewed.
        assert len(log.list()) == logged
        assert vault.get(router_ref) == ADMIN

    def test_a_password_gone_from_the_vault_is_a_missing_record_password(self, parts):
        store, vault, _, _ = parts
        record = store.create(managed(), "alice")["record"]
        vault.delete(f"setup-{record['id']}-wifi")
        with pytest.raises(SavedPasswordMissing):
            store.reveal(record["id"], "bob")

    @pytest.mark.parametrize("method", ["reveal", "delete"])
    def test_unknown_and_malformed_ids(self, parts, method):
        store, _, _, _ = parts
        with pytest.raises(RecordNotFound):
            getattr(store, method)("0123456789ab", "bob")
        for bad in ("../../secrets", "0123456789AB", "", "0123456789abc"):
            with pytest.raises(ValidationError, match="not a setup record id"):
                getattr(store, method)(bad, "bob")

    def test_an_actor_is_required(self, parts):
        store, _, _, _ = parts
        with pytest.raises(ValidationError):
            store.create(managed(), " ")
        assert not store.path.exists()

    def test_deleting_a_record_removes_its_passwords_but_not_its_router(self, parts):
        store, vault, manager, log = parts
        record = store.create(direct(), "alice")["record"]
        assert store.delete(record["id"], "bob") == {
            "id": record["id"],
            "deleted": True,
            "device_id": "customer-1080-home",
        }
        assert store.list() == [] and secret_refs(vault) == []
        device = manager.get_device("customer-1080-home")
        assert manager.credentials(device) == ADMIN
        entry = log.list()[0]
        assert entry["who"] == "bob" and entry["kind"] == "setup"
        assert entry["what"] == "Setup record removed: #1080, IP 192.0.2.80; the router itself was left as it is"
        with pytest.raises(RecordNotFound):
            store.delete(record["id"], "bob")

    def test_a_hand_edited_record_cannot_delete_a_routers_password(self, parts):
        store, vault, manager, _ = parts
        record = store.create(direct(), "alice")["record"]
        router_ref = manager.get_device(record["device_id"]).password_ref
        saved = json.loads(store.path.read_text())
        saved["records"][record["id"]]["wifi_password_ref"] = router_ref
        store.path.write_text(json.dumps(saved))
        store.delete(record["id"], "bob")
        assert vault.has(router_ref)

    def test_a_record_that_cannot_be_saved_leaves_no_router_and_no_password(self, parts, monkeypatch):
        store, vault, manager, log = parts

        def disk_full(*_args, **_kwargs):
            raise OSError("No space left on device")

        monkeypatch.setattr(setup_records, "_write_json", disk_full)
        with pytest.raises(SetupRecordsError, match="could not be saved"):
            store.create(direct(), "alice")
        assert secret_refs(vault) == [] and manager.get_all_devices() == []
        assert store.list() == []
        # The router was added and taken back, and both are in the log; nothing was programmed.
        assert [entry["what"].split(" ")[0] for entry in log.list()] == ["Removed", "Added"]

    def test_a_router_that_cannot_be_added_leaves_no_record_and_no_password(self, parts, monkeypatch):
        store, vault, manager, _ = parts

        def refuse(*_args, **_kwargs):
            raise ManagerError("device config is unreadable")

        monkeypatch.setattr(manager, "add_device", refuse)
        with pytest.raises(ManagerError):
            store.create(direct(), "alice")
        assert secret_refs(vault) == [] and store.list() == []

    @pytest.mark.parametrize("content", ["", "{", "[]", '{"records": []}', '{"records": {"x": 1}}'])
    def test_a_damaged_file_is_never_read_as_no_records(self, parts, content):
        store, vault, _, _ = parts
        store.data_dir.mkdir(parents=True, exist_ok=True)
        store.path.write_text(content)
        with pytest.raises(SetupRecordsError):
            store.list()
        with pytest.raises(SetupRecordsError):
            store.create(managed(), "alice")
        assert store.path.read_text() == content
        assert secret_refs(vault) == []

    def test_the_record_limit(self, parts, monkeypatch):
        store, vault, _, _ = parts
        monkeypatch.setattr(setup_records, "MAX_RECORDS", 1)
        store.create(managed(), "alice")
        with pytest.raises(ValidationError, match="at most 1 setup records"):
            store.create(managed(customer="#2"), "alice")
        assert len(secret_refs(vault)) == 1

    def test_concurrent_creates_keep_every_record(self, parts):
        store, vault, _, _ = parts
        errors: list[BaseException] = []

        def create(index: int) -> None:
            try:
                store.create(managed(customer=f"#{index}"), "alice")
            except BaseException as exc:  # noqa: BLE001 - reported below
                errors.append(exc)

        threads = [threading.Thread(target=create, args=(index,)) for index in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert errors == []
        assert sorted(record["customer"] for record in store.list()) == sorted(f"#{index}" for index in range(8))
        assert len(secret_refs(vault)) == 8


# --- the routes ---------------------------------------------------------------------------------------


RECORD_ID = "0123456789ab"
TEMPLATES = {
    ("GET", "/api/setup/records"),
    ("POST", "/api/setup/records"),
    ("POST", "/api/setup/records/{record_id}/reveal"),
    ("DELETE", "/api/setup/records/{record_id}"),
}
WRITES: list[tuple[str, str, dict[str, Any] | None]] = [
    ("POST", "/api/setup/records", managed()),
    ("POST", f"/api/setup/records/{RECORD_ID}/reveal", {"confirm": True}),
    ("DELETE", f"/api/setup/records/{RECORD_ID}", None),
]


def make_app(tmp_path: Path, monkeypatch=None):
    data = tmp_path / "data"
    vault = SecretStore(data)
    log = ActivityLog(data)
    manager = DeviceManager(config_path=tmp_path / "devices.yaml", data_dir=data, secret_store=vault, activity=log)
    if monkeypatch is not None:
        no_router_contact(manager, monkeypatch)
    settings = Settings("admin", PASSKEY, False, 3600, tmp_path / "devices.yaml", data)
    return create_app(manager=manager, settings=settings, activity=log)


def signed_in(app) -> tuple[TestClient, dict[str, str]]:
    client = TestClient(app)
    response = client.post("/login", json={"passkey": PASSKEY})
    assert response.status_code == 200, response.text
    return client, {"X-CSRF-Token": response.json()["csrf_token"]}


def send(client: TestClient, method: str, path: str, body: dict[str, Any] | None = None, **kwargs: Any):
    return client.request(method, path, **({"json": body} if body is not None else {}), **kwargs)


class TestRoutes:
    def test_every_setup_route_is_listed_here(self, tmp_path: Path):
        app = make_app(tmp_path)
        registered = {
            (method, route.path)
            for route in app.routes
            if getattr(route, "path", "").startswith("/api/setup")
            for method in getattr(route, "methods", ())
        }
        assert registered == TEMPLATES

    def test_every_route_needs_a_session(self, tmp_path: Path):
        app = make_app(tmp_path)
        client = TestClient(app)
        for method, path, body in [("GET", "/api/setup/records", None), *WRITES]:
            assert send(client, method, path, body).status_code == 401, (method, path)
        assert not app.state.setup_records.path.exists()

    def test_every_change_needs_the_csrf_token(self, tmp_path: Path):
        app = make_app(tmp_path)
        client, headers = signed_in(app)
        record = send(client, "POST", "/api/setup/records", managed(), headers=headers).json()["record"]
        before = app.state.setup_records.path.read_text()
        entries = app.state.activity.list()
        for token in (None, "wrong"):
            sent = {"X-CSRF-Token": token} if token else {}
            for method, path, body in WRITES:
                path = path.replace(RECORD_ID, record["id"])
                response = send(client, method, path, body, headers=sent)
                assert response.status_code == 403, (method, path, response.text)
                assert WIFI not in response.text
        assert app.state.setup_records.path.read_text() == before
        assert app.state.activity.list() == entries

    def test_create_list_reveal_and_delete(self, tmp_path: Path, monkeypatch):
        app = make_app(tmp_path, monkeypatch)
        client, headers = signed_in(app)
        created = client.post("/api/setup/records", json=direct(), headers=headers)
        assert created.status_code == 201, created.text
        record = created.json()["record"]
        assert created.json()["device"]["id"] == record["device_id"] == "customer-1080-home"
        assert record["created_by"] == "Skybre staff"
        listed = client.get("/api/setup/records").json()
        assert listed["models"] == list(MODELS)
        assert [item["id"] for item in listed["records"]] == [record["id"]]
        assert [device["id"] for device in client.get("/api/devices").json()["devices"]] == ["customer-1080-home"]

        revealed = client.post(f"/api/setup/records/{record['id']}/reveal", json={"confirm": True}, headers=headers)
        assert revealed.status_code == 200 and revealed.json() == {"wifi_password": WIFI}

        deleted = client.delete(f"/api/setup/records/{record['id']}", headers=headers)
        assert deleted.json() == {"id": record["id"], "deleted": True, "device_id": "customer-1080-home"}
        assert client.get("/api/setup/records").json()["records"] == []
        assert client.delete(f"/api/setup/records/{record['id']}", headers=headers).status_code == 404
        # The router stays in the list.
        assert [device["id"] for device in client.get("/api/devices").json()["devices"]] == ["customer-1080-home"]

    def test_no_secret_leaves_skyrouter_except_through_the_reveal(self, tmp_path: Path, monkeypatch, caplog):
        caplog.set_level(logging.DEBUG)
        app = make_app(tmp_path, monkeypatch)
        client, headers = signed_in(app)
        texts = []
        for body in (managed(admin_password=ADMIN), direct()):
            response = client.post("/api/setup/records", json=body, headers=headers)
            assert response.status_code == 201, response.text
            texts.append(response.text)
        records = client.get("/api/setup/records").json()["records"]
        for record in records:
            refused = client.post(f"/api/setup/records/{record['id']}/reveal", json={}, headers=headers)
            texts.append(refused.text)
        texts.append(client.post("/api/setup/records", json=managed(checklist={}), headers=headers).text)
        texts.append(client.post("/api/setup/records", json=direct(notes=WIFI), headers=headers).text)
        revealed = client.post(f"/api/setup/records/{records[0]['id']}/reveal", json={"confirm": True}, headers=headers)
        assert revealed.json() == {"wifi_password": WIFI}
        for record in records:
            texts.append(client.delete(f"/api/setup/records/{record['id']}", headers=headers).text)
        texts += [
            client.get("/api/setup/records").text,
            client.get("/api/devices").text,
            client.get("/api/activity").text,
            client.get("/api/activity.csv").text,
            app.state.manager.config_path.read_text(),
            app.state.setup_records.path.read_text(),
            caplog.text,
        ]
        assert_no_secret(*texts)
        kinds = [entry["kind"] for entry in client.get("/api/activity").json()["entries"]]
        assert kinds.count("access") == 1

    @pytest.mark.parametrize(
        "body,message",
        [
            (managed(checklist={**ALL_TICKED, "remote_management": False}), REMOTE_MANAGEMENT_REQUIRED),
            (managed(customer=""), "Enter the Vexar customer."),
            (managed(ip="10.20.0.999"), "That is not an IPv4 address"),
            (managed(wifi_password="short"), "Wi-Fi password must be 8 to 63 characters"),
            (direct(admin_password=None), "Enter the router admin password so Skybre can sign in to it."),
            (direct(model="Other"), DIRECT_UNSUPPORTED),
            (managed(password=PASSKEY), "unexpected field(s): password"),
            (managed(actor="mallory"), "unexpected field(s): actor"),
        ],
    )
    def test_refusals_are_400s_that_say_what_to_fix(self, tmp_path: Path, body, message):
        app = make_app(tmp_path)
        client, headers = signed_in(app)
        response = client.post("/api/setup/records", json=body, headers=headers)
        assert response.status_code == 400, response.text
        assert message in response.json()["detail"]
        assert not app.state.setup_records.path.exists()
        assert app.state.activity.list() == []

    def test_a_reveal_must_be_confirmed_and_name_a_record(self, tmp_path: Path):
        app = make_app(tmp_path)
        client, headers = signed_in(app)
        record = client.post("/api/setup/records", json=managed(), headers=headers).json()["record"]
        path = f"/api/setup/records/{record['id']}/reveal"
        for body in ({}, {"confirm": "yes"}, {"confirm": False}):
            response = client.post(path, json=body, headers=headers)
            assert response.status_code == 400
            assert "recorded in the activity log" in response.json()["detail"]
        assert client.post(path, json={"confirm": True, "why": "x"}, headers=headers).status_code == 400
        missing = client.post(f"/api/setup/records/{RECORD_ID}/reveal", json={"confirm": True}, headers=headers)
        assert missing.status_code == 404
        assert client.post("/api/setup/records/nope/reveal", json={"confirm": True}, headers=headers).status_code == 400
        assert [entry["kind"] for entry in app.state.activity.list()] == ["setup"]

    def test_a_reveal_is_logged_under_the_session(self, tmp_path: Path):
        app = make_app(tmp_path)
        client, headers = signed_in(app)
        record = client.post("/api/setup/records", json=managed(), headers=headers).json()["record"]
        client.post(f"/api/setup/records/{record['id']}/reveal", json={"confirm": True}, headers=headers)
        entry = app.state.activity.list(kind="access")[0]
        assert entry["who"] == "Skybre staff" and entry["what"] == "Viewed the saved Wi-Fi password"

    def test_a_reveal_that_cannot_be_logged_is_a_500_without_the_password(self, tmp_path: Path, monkeypatch):
        app = make_app(tmp_path)
        client, headers = signed_in(app)
        record = client.post("/api/setup/records", json=managed(), headers=headers).json()["record"]

        def full(**_entry):
            raise OSError("No space left on device")

        monkeypatch.setattr(app.state.activity, "record", full)
        response = client.post(f"/api/setup/records/{record['id']}/reveal", json={"confirm": True}, headers=headers)
        assert response.status_code == 500
        assert "so the password was not shown" in response.json()["detail"]
        assert WIFI not in response.text

    def test_an_error_that_quotes_a_password_is_withheld(self, tmp_path: Path, monkeypatch):
        app = make_app(tmp_path)
        client, headers = signed_in(app)

        def quoting(*_args, **kwargs):
            raise ManagerError(f"could not store {kwargs.get('password')}")

        monkeypatch.setattr(app.state.manager, "add_device", quoting)
        response = client.post("/api/setup/records", json=direct(), headers=headers)
        assert response.status_code == 400
        assert "withheld" in response.json()["detail"] and ADMIN not in response.text

    def test_a_damaged_record_file_is_a_500_that_says_where_to_look(self, tmp_path: Path, caplog):
        app = make_app(tmp_path)
        client, headers = signed_in(app)
        app.state.setup_records.path.write_text("[]")
        response = client.get("/api/setup/records")
        assert response.status_code == 500
        assert "refusing to treat it as empty; see the SkyRouter log" in response.json()["detail"]
        assert "setup records:" in caplog.text

    def test_a_slow_save_does_not_block_other_requests(self, tmp_path: Path):
        app = make_app(tmp_path)
        store = app.state.setup_records
        original = store.create

        def slow_create(*args, **kwargs):
            time.sleep(1.0)
            return original(*args, **kwargs)

        store.create = slow_create
        with TestClient(app) as client:
            response = client.post("/login", json={"passkey": PASSKEY})
            headers = {"X-CSRF-Token": response.json()["csrf_token"]}
            elapsed: dict[str, float] = {}

            def save() -> None:
                started = time.time()
                client.post("/api/setup/records", json=managed(), headers=headers)
                elapsed["save"] = time.time() - started

            worker = threading.Thread(target=save)
            worker.start()
            time.sleep(0.3)
            started = time.time()
            assert client.get("/api/me").status_code == 200
            elapsed["other"] = time.time() - started
            worker.join()
        assert elapsed["save"] >= 1.0
        assert elapsed["other"] < 0.5, f"the event loop was blocked for {elapsed['other']:.2f}s"
