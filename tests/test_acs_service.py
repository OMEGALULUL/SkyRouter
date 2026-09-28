"""The ACS job store and AcsService's reads, tags, faults and bootstrap (brief §3.6, §3.8, §4).

The Wi-Fi, reboot and refresh job paths are in test_acs_wifi.py.
"""

import json
import os
import socket
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fake_nbi import FakeNbi, build_device, iso, make_device_id

from cudy_manager.acs import bootstrap, jobs
from cudy_manager.acs.bootstrap import BootstrapRefused
from cudy_manager.acs.client import AcsClient, AcsNotFound
from cudy_manager.acs.jobs import (
    ACKNOWLEDGED,
    CANCELLED,
    CONTACTING_ROUTER,
    ERROR,
    LEASE_TTL,
    MAX_HISTORY,
    QUEUED,
    RETENTION,
    VERIFIED,
    WAITING_FOR_CHECKIN,
    JobStore,
    JobStoreError,
    new_job,
    new_job_id,
    note,
    public_view,
    transition,
    validate_job_id,
)
from cudy_manager.acs.service import AcsService, vault_ref
from cudy_manager.models import ValidationError
from cudy_manager.secrets import SecretStore

START = datetime(2026, 9, 28, 9, 0, tzinfo=UTC)
WIFI = "Device.WiFi"
KEY1 = f"{WIFI}.AccessPoint.1.Security.KeyPassphrase"
MARKER = "zz-secret-stored-by-genieacs"


class Clock:
    def __init__(self, start: datetime = START):
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **delta: float) -> None:
        self.now += timedelta(**delta)


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def store(tmp_path, clock):
    return JobStore(tmp_path, clock)


def make(job_id: str | None = None, acs_id: str = "202BC1-BM632w-000001", kind: str = jobs.KIND_WIFI, now=START):
    return new_job(job_id or new_job_id(), acs_id, kind, now, request={"band": "2.4GHz"})


def saved(store: JobStore, job: dict[str, Any]) -> None:
    token = store.create(job)
    assert store.release(job["id"], token, job)


# --- the job store ----------------------------------------------------------------------------


def test_the_job_file_is_private_and_written_whole(store, tmp_path):
    job = make()
    saved(store, job)
    for path in (tmp_path / "acs_jobs.json", tmp_path / "acs_jobs.json.lock"):
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    data = json.loads((tmp_path / "acs_jobs.json").read_text())
    assert data["version"] == jobs.FORMAT_VERSION and list(data["jobs"]) == [job["id"]]
    # The atomic rename leaves no temporary file behind.
    assert sorted(p.name for p in tmp_path.iterdir()) == ["acs_jobs.json", "acs_jobs.json.lock"]


def test_an_update_that_changes_nothing_does_not_rewrite_the_file(store):
    job = make()
    saved(store, job)
    # Every save is a fresh file renamed into place, so a new inode means a rewrite.
    inode = os.stat(store.path).st_ino
    assert store.release(job["id"], "not-the-token") is False
    assert store.prune() == 0
    assert os.stat(store.path).st_ino == inode
    assert store.claim(job["id"]) is not None
    assert os.stat(store.path).st_ino != inode


@pytest.mark.parametrize("content", ["{not json", json.dumps([1, 2]), json.dumps({"jobs": {"a": 1}})])
def test_a_damaged_job_file_is_refused_and_never_replaced(store, content):
    store.path.write_text(content)
    with pytest.raises(JobStoreError):
        store.all()
    with pytest.raises(JobStoreError):
        store.create(make())
    # It may be the only record of a pending vault entry.
    assert store.path.read_text() == content


def test_a_missing_job_file_is_an_empty_store(store):
    assert store.all() == {} and store.get("0" * 16) is None


def test_job_ids_are_sixteen_hex_characters():
    assert validate_job_id(new_job_id()) and len(new_job_id()) == 16
    for bad in ("", "0" * 15, "G" * 16, "0" * 16 + "\n", None, 7):
        with pytest.raises(ValidationError):
            validate_job_id(bad)


def test_new_jobs_start_queued_and_hold_no_secret():
    job = make()
    assert job["state"] == QUEUED and job["steps"] == [] and job["cr_attempts"] == [] and job["vault_refs"] == {}
    assert job["history"][0]["state"] == QUEUED
    with pytest.raises(ValueError):
        new_job(new_job_id(), "x-y", "factory_reset", START, request={})


@pytest.mark.parametrize(
    ("start", "target", "allowed"),
    [
        (QUEUED, CONTACTING_ROUTER, True),
        (QUEUED, WAITING_FOR_CHECKIN, True),
        (QUEUED, ERROR, True),
        (CONTACTING_ROUTER, CONTACTING_ROUTER, True),
        (WAITING_FOR_CHECKIN, CONTACTING_ROUTER, True),
        (WAITING_FOR_CHECKIN, "expired", True),
        (CONTACTING_ROUTER, QUEUED, False),
        (ACKNOWLEDGED, VERIFIED, True),
        (ACKNOWLEDGED, CANCELLED, False),
        (ACKNOWLEDGED, WAITING_FOR_CHECKIN, False),
        (VERIFIED, ACKNOWLEDGED, False),
        (CANCELLED, QUEUED, False),
        ("rejected", "not_applied", False),
        (QUEUED, "bogus", False),
    ],
)
def test_transitions_follow_the_state_machine(start, target, allowed):
    job = make()
    job["state"] = start
    if allowed:
        transition(job, target, "moved", START)
        assert job["state"] == target and job["message"] == "moved"
        assert job["history"][-1] == {"at": iso(START), "state": target, "note": "moved"}
    else:
        with pytest.raises(JobStoreError):
            transition(job, target, "moved", START)
        assert job["state"] == start


def test_history_is_capped():
    job = make()
    for index in range(MAX_HISTORY + 20):
        note(job, f"note {index}", START)
    assert len(job["history"]) == MAX_HISTORY
    assert job["history"][-1]["note"] == f"note {MAX_HISTORY + 19}"


def test_the_public_view_drops_the_lease_and_says_when_nothing_more_will_change(store):
    job = make()
    store.create(job)
    raw = store.get(job["id"])
    assert raw is not None and "lease" in raw
    view = public_view(raw)
    assert "lease" not in view and view["terminal"] is False and view["done"] is False
    job["state"], job["watch"] = ACKNOWLEDGED, jobs.WATCH_SCRUB
    assert public_view(job)["terminal"] is True and public_view(job)["done"] is False
    job["watch"] = None
    assert public_view(job)["done"] is True


def test_a_leased_job_is_left_to_its_holder_until_the_lease_runs_out(store, clock):
    job = make()
    token = store.create(job)
    assert store.claim(job["id"]) is None
    clock.advance(seconds=LEASE_TTL.total_seconds() - 1)
    assert store.claim(job["id"]) is None
    clock.advance(seconds=2)
    taken = store.claim(job["id"])
    assert taken is not None
    view, new_token = taken
    assert "lease" not in view
    # The first holder lost its lease, so its late save is dropped, not merged.
    stale = dict(job, state=ERROR)
    assert store.release(job["id"], token, stale) is False
    with pytest.raises(JobStoreError):
        store.checkpoint(job["id"], token, stale)
    assert store.get(job["id"])["state"] == QUEUED
    assert store.release(job["id"], new_token, view) is True
    assert "lease" not in store.get(job["id"])


def test_claim_waits_briefly_for_a_lease_to_be_released(store):
    job = make()
    token = store.create(job)
    assert store.claim(job["id"], wait=0.1) is None
    store.release(job["id"], token)
    assert store.claim(job["id"], wait=0.1) is not None
    assert store.claim("0" * 16) is None


def test_creating_a_job_twice_is_refused(store):
    job = make()
    store.create(job)
    with pytest.raises(JobStoreError):
        store.create(job)


def test_terminal_jobs_are_pruned_after_seven_days(store, clock):
    old_done = make(now=START)
    old_done["state"] = CANCELLED
    old_watching = make(now=START)
    old_watching["state"], old_watching["watch"] = ACKNOWLEDGED, jobs.WATCH_BOOT
    old_active = make(now=START)
    old_active["state"] = WAITING_FOR_CHECKIN
    for job in (old_done, old_watching, old_active):
        saved(store, job)
    clock.advance(days=6)
    recent_done = make(now=clock.now)
    recent_done["state"] = VERIFIED
    saved(store, recent_done)

    clock.advance(days=1, seconds=1)
    assert store.prune() == 1
    assert set(store.all()) == {old_watching["id"], old_active["id"], recent_done["id"]}
    clock.advance(seconds=RETENTION.total_seconds())
    assert store.prune() == 1
    assert set(store.all()) == {old_watching["id"], old_active["id"]}


# --- the service: set-up and job reads -----------------------------------------------------------


@pytest.fixture
def nbi():
    with FakeNbi() as fake:
        yield fake


@pytest.fixture
def svc(nbi, tmp_path):
    return AcsService(AcsClient(nbi.url, timeout=5), SecretStore(tmp_path), tmp_path, clock=nbi.now)


def tr181_router(nbi: FakeNbi, serial: str = "000001", tags=(), minutes_ago: float = 0) -> str:
    leaves = {
        "Device.ManagementServer.ConnectionRequestURL": {"value": "http://10.10.0.40:7547/", "writable": False},
        "Device.ManagementServer.PeriodicInformInterval": 300,
        "Device.DeviceInfo.Manufacturer": {"value": "Acme", "writable": False},
        "Device.DeviceInfo.ModelName": {"value": "AX3000", "writable": False},
        f"{WIFI}.Radio.1.OperatingFrequencyBand": "2.4GHz",
        f"{WIFI}.SSID.1.SSID": f"Home-{serial}",
        f"{WIFI}.SSID.1.LowerLayers": "Device.WiFi.Radio.1.",
        f"{WIFI}.AccessPoint.1.SSIDReference": "Device.WiFi.SSID.1.",
        f"{WIFI}.AccessPoint.1.Security.ModeEnabled": "WPA2-Personal",
        # GenieACS keeps what it last wrote in plaintext (F15); SkyRouter must never show it.
        KEY1: MARKER,
    }
    doc = build_device(serial=serial, leaves=leaves, tags=tags, last_inform=nbi.now() - timedelta(minutes=minutes_ago))
    return nbi.add_device(doc)


def test_the_inform_interval_is_checked_when_the_service_is_built(nbi, tmp_path):
    for bad in (10, 86401, "300"):
        with pytest.raises(ValidationError):
            AcsService(AcsClient(nbi.url), SecretStore(tmp_path), tmp_path, inform_interval=bad)
    assert AcsService(AcsClient(nbi.url), SecretStore(tmp_path), tmp_path, inform_interval=60).inform_interval == 60


def test_jobs_are_read_back_newest_first(nbi, svc):
    first, second = tr181_router(nbi, "000001"), tr181_router(nbi, "000002")
    nbi.set_cr_outcome(first, 504)
    nbi.set_cr_outcome(second, 504)
    older = svc.reboot(first)
    nbi.advance(1)
    newer = svc.refresh(second, "wifi")
    assert [job["id"] for job in svc.list_jobs()] == [newer["id"], older["id"]]
    assert [job["id"] for job in svc.list_jobs(acs_id=first)] == [older["id"]]
    assert svc.get_job(older["id"])["kind"] == "reboot"
    assert svc.has_active_jobs() is True
    svc.cancel_job(older["id"])
    svc.cancel_job(newer["id"])
    assert svc.list_jobs(active_only=True) == [] and svc.has_active_jobs() is False


def test_get_job_validates_and_reports_missing_jobs(svc):
    with pytest.raises(ValidationError):
        svc.get_job("../acs_jobs")
    with pytest.raises(AcsNotFound):
        svc.get_job("0123456789abcdef")


def test_polling_prunes_old_finished_jobs(nbi, svc):
    router = tr181_router(nbi)
    nbi.set_cr_outcome(router, 504)
    job = svc.reboot(router)
    svc.cancel_job(job["id"])
    nbi.advance(RETENTION.total_seconds() + 60)
    svc._last_prune = float("-inf")
    svc.poll_jobs()
    assert svc.list_jobs() == []


def test_known_secrets_are_only_this_routers(nbi, svc):
    router = tr181_router(nbi)
    other = make_device_id("202BC1", "BM632w", "999999")
    svc.secrets.put("router-passphrase", vault_ref(router, "2.4GHz", "current"))
    svc.secrets.put("other-passphrase", vault_ref(other, "2.4GHz", "current"))
    svc.secrets.put("unrelated", "device-admin-password")
    assert svc.known_secrets(router) == ["router-passphrase"]


# --- health ---------------------------------------------------------------------------------


def test_health_reports_the_version_bootstrap_and_provisioning_faults(nbi, svc):
    router = tr181_router(nbi)
    fault_id = f"{router}:skybre-inform"
    nbi.faults[fault_id] = {
        "_id": fault_id,
        "device": router,
        "channel": "skybre-inform",
        "timestamp": iso(nbi.now()),
        "code": "ext.Error",
        "message": "SKYROUTER_CR_SECRET is unset or shorter than 32 hex characters",
        "detail": {"name": "Error"},
        "retries": 2,
        "provisions": json.dumps([["skybre-inform", 300]]),
    }
    health = svc.health()
    assert health["configured"] is True and health["reachable"] is True
    assert health["version"] == nbi.version and health["error"] is None
    assert health["bootstrap"]["installed"] is False
    assert {item["name"] for item in health["bootstrap"]["drift"]} >= set(bootstrap.PROVISION_NAMES)
    [fault] = health["channel_faults"]
    assert fault["id"] == fault_id and fault["code"] == "ext.Error" and fault["retries"] == 2
    assert "restart genieacs-cwmp" in fault["hint"]
    assert fault["hint"] in health["problems"]
    assert "provisions" not in fault
    assert health["jobs"] == {"active": 0}


def test_health_after_the_bootstrap_shows_it_installed(nbi, svc):
    report = svc.bootstrap()
    assert set(report["provisions"]) == set(bootstrap.PROVISION_NAMES)
    assert svc.bootstrap_status()["installed"] is True
    assert svc.health()["bootstrap"] == {"installed": True, "drift": [], "seeded_presets": []}
    # A second run writes nothing (§4 step 5).
    assert svc.bootstrap()["writes"] == 0


def test_the_bootstrap_refuses_while_seeded_presets_exist(nbi, svc):
    nbi.presets["default"] = {"_id": "default", "weight": 0, "configurations": [{"type": "age", "name": "x", "age": 1}]}
    with pytest.raises(BootstrapRefused) as refused:
        svc.bootstrap()
    assert refused.value.seeded == ["default"]
    assert svc.bootstrap(remove_seeded=True)["removed_seeded"] == ["default"]
    assert "default" not in nbi.presets


def test_health_when_the_acs_is_unreachable(tmp_path):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    service = AcsService(AcsClient(f"http://127.0.0.1:{port}", timeout=2), SecretStore(tmp_path), tmp_path)
    health = service.health()
    assert health["reachable"] is False and health["version"] is None
    assert "ACS unavailable" in health["error"]
    assert health["bootstrap"] is None and health["channel_faults"] == []


def test_health_refuses_an_unsupported_genieacs(nbi, svc):
    nbi.version = "1.3.0-dev+20260901"
    health = svc.health()
    assert health["reachable"] is True and health["version"] is None
    assert "not supported" in health["error"]


def test_health_reports_a_damaged_job_file_without_failing(nbi, svc):
    svc.jobs.path.write_text("{")
    health = svc.health()
    assert health["jobs"] == {"active": None}
    assert any("corrupt" in problem for problem in health["problems"])


# --- the device list and one device ----------------------------------------------------------------


def test_the_device_list_is_summarised_newest_check_in_first_and_paged(nbi, svc):
    old = tr181_router(nbi, "000001", minutes_ago=60)
    new = tr181_router(nbi, "000002", minutes_ago=1)
    middle = tr181_router(nbi, "000003", tags=["skybre_new"], minutes_ago=10)
    page = svc.list_devices(limit=2)
    assert page["total"] == 3
    assert [device["acs_id"] for device in page["devices"]] == [new, middle]
    assert [device["acs_id"] for device in svc.list_devices(skip=2)["devices"]] == [old]
    summary = page["devices"][0]
    assert summary["manufacturer"] == "Acme" and summary["online"] is True
    assert summary["wifi"][0]["ssid"] == "Home-000002"
    assert MARKER not in json.dumps(page)

    assert [device["acs_id"] for device in svc.list_devices(q="000003")["devices"]] == [middle]
    assert [device["acs_id"] for device in svc.list_devices(tag="skybre_new")["devices"]] == [middle]
    assert svc.list_devices(q="  ")["total"] == 3


@pytest.mark.parametrize(
    "kwargs", [{"q": "a b"}, {"q": {"$gt": ""}}, {"tag": "Bad Tag"}, {"limit": 0}, {"limit": 201}, {"skip": -1}]
)
def test_device_list_input_is_validated_before_any_request(nbi, svc, kwargs):
    before = len(nbi.requests)
    with pytest.raises(ValidationError):
        svc.list_devices(**kwargs)
    assert len(nbi.requests) == before


def test_one_odd_document_does_not_hide_the_fleet(nbi, svc, monkeypatch):
    from cudy_manager.acs import service as service_module

    good, bad = tr181_router(nbi, "000001"), tr181_router(nbi, "000002")
    real = service_module.params.summarize

    def summarize(doc, now, interval):
        if doc["_id"] == bad:
            raise TypeError("unexpected shape")
        return real(doc, now, interval)

    monkeypatch.setattr(service_module.params, "summarize", summarize)
    devices = {device["acs_id"]: device for device in svc.list_devices()["devices"]}
    assert devices[good]["model"] == "AX3000"
    assert devices[bad] == {"acs_id": bad, "error": "SkyRouter could not read this router's document"}


def test_device_detail_includes_pending_jobs_and_faults_and_no_secret(nbi, svc):
    router = tr181_router(nbi)
    fault_id = faulted_task(nbi, svc, router)
    nbi.set_cr_outcome(router, 504)
    job = svc.reboot(router)

    device = svc.device_detail(router)["device"]
    assert device["acs_id"] == router and device["data_model"] == "tr181"
    assert [pending["id"] for pending in device["pending_jobs"]] == [job["id"]]
    assert [(fault["id"], fault["code"]) for fault in device["faults"]] == [(fault_id, "cwmp.9002")]
    assert device["wifi"][0]["passphrase"]["present"] is True
    assert MARKER not in json.dumps(device)
    # Reads never reach the router (§3.6): no connection request beyond the reboot's own.
    assert nbi.cr_requests == [router]


def test_device_detail_of_an_unknown_or_malformed_id(nbi, svc):
    with pytest.raises(AcsNotFound):
        svc.device_detail(make_device_id("202BC1", "BM632w", "ghost"))
    before = len(nbi.requests)
    with pytest.raises(ValidationError):
        svc.device_detail("202BC1-BM632w-000001/../x")
    assert len(nbi.requests) == before


# --- tags ----------------------------------------------------------------------------------------


def test_tags_are_added_and_removed(nbi, svc):
    router = tr181_router(nbi, tags=["skybre_new"])
    assert svc.add_tag(router, "shop-7") == {"acs_id": router, "tags": ["skybre_new", "shop-7"]}
    assert svc.remove_tag(router, "shop-7") == {"acs_id": router, "tags": ["skybre_new"]}
    # Adopting takes a router out of the "New devices" inbox (§3.9).
    assert svc.adopt(router)["tags"] == []


@pytest.mark.parametrize("tag", ["Shop", "a" * 33, "shop.7", "", "shop 7", None])
def test_tags_are_validated_before_any_request(nbi, svc, tag):
    router = tr181_router(nbi)
    before = len(nbi.requests)
    for action in (svc.add_tag, svc.remove_tag):
        with pytest.raises(ValidationError):
            action(router, tag)
    assert len(nbi.requests) == before


def test_tagging_an_unknown_router_is_not_found(svc):
    with pytest.raises(AcsNotFound):
        svc.add_tag(make_device_id("202BC1", "BM632w", "ghost"), "shop")


# --- faults ----------------------------------------------------------------------------------------


def faulted_task(nbi: FakeNbi, svc: AcsService, router: str) -> str:
    from cudy_manager.acs import tasks

    nbi.inject_task_fault(router, "refreshObject", code="cwmp.9002", message="Internal error")
    task = svc.client.queue_task(
        router, tasks.refresh_object("Device.DeviceInfo", job="manual", step="refresh", unique_key="skyrouter-manual")
    )
    nbi.run_session(router, cr=False)
    return f"{router}:task_{task['_id']}"


def test_retrying_a_task_fault_clears_it_and_asks_the_router_to_check_in(nbi, svc):
    router = tr181_router(nbi)
    fault_id = faulted_task(nbi, svc, router)
    result = svc.retry_fault(fault_id)
    assert result == {"fault_id": fault_id, "action": "retried", "connection_request": {"ok": True, "reason": ""}}
    assert fault_id not in nbi.faults and len(nbi.device_tasks(router)) == 1
    assert nbi.cr_requests == [router]


def test_retrying_a_provisioning_fault_clears_it_so_it_runs_again(nbi, svc):
    router = tr181_router(nbi)
    nbi.set_cr_outcome(router, 504)
    fault_id = f"{router}:skybre-refresh"
    nbi.faults[fault_id] = {"_id": fault_id, "device": router, "channel": "skybre-refresh", "code": "script.Error"}
    result = svc.retry_fault(fault_id)
    assert result["action"] == "cleared" and fault_id not in nbi.faults
    assert result["connection_request"] == {"ok": False, "reason": "Device is offline"}


def test_clearing_a_task_fault_deletes_the_task_too(nbi, svc):
    router = tr181_router(nbi)
    fault_id = faulted_task(nbi, svc, router)
    assert svc.clear_fault(fault_id) == {"fault_id": fault_id, "cleared": True}
    assert nbi.faults == {} and nbi.device_tasks(router) == []


@pytest.mark.parametrize("fault_id", ["no-colon", "202BC1-BM632w-000001:task_xyz", ":skybre-inform", "a:b"])
def test_fault_ids_are_validated_before_any_request(nbi, svc, fault_id):
    for action in (svc.retry_fault, svc.clear_fault):
        with pytest.raises(ValidationError):
            action(fault_id)
    assert nbi.requests == []


def test_retrying_a_fault_whose_task_is_gone_is_not_found(nbi, svc):
    router = tr181_router(nbi)
    with pytest.raises(AcsNotFound):
        svc.retry_fault(f"{router}:task_{'a' * 24}")
    assert nbi.crashes == 0


def test_the_job_file_lives_in_the_given_data_dir(nbi, tmp_path):
    data = tmp_path / "state"
    service = AcsService(AcsClient(nbi.url), SecretStore(data), data, clock=nbi.now)
    router = tr181_router(nbi)
    nbi.set_cr_outcome(router, 504)
    job = service.reboot(router)
    assert service.jobs.path == Path(data) / "acs_jobs.json"
    assert list(json.loads(service.jobs.path.read_text())["jobs"]) == [job["id"]]
