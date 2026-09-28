"""ACS jobs end to end against the fake NBI: Wi-Fi changes (brief §3.7), reboots and refreshes.

The fake keeps GenieACS's cached document and the router's own values apart, and
run_session() plays a check-in, so each job path below is driven the way a real
router would drive it: by when (and whether) it opens a session.
"""

import hashlib
import json
import logging
import os
import stat
from datetime import timedelta
from typing import Any

import pytest
from fake_nbi import FakeNbi, build_device, iso, make_device_id, parse_iso

from cudy_manager.acs import jobs as job_store
from cudy_manager.acs import tasks
from cudy_manager.acs.client import AcsBusy, AcsClient, AcsNotFound
from cudy_manager.acs.jobs import LEASE_TTL, new_job, new_job_id
from cudy_manager.acs.service import (
    CR_SPACING,
    EXPIRY_GRACE,
    AcsConfirmationRequired,
    AcsService,
    vault_ref,
)
from cudy_manager.models import ValidationError
from cudy_manager.secrets import SecretStore

PASS = "correct-Horse-Battery-9"
NEW_PASS = "Tr0ub4dor&3-staple"

WIFI = "Device.WiFi"
SSID1 = f"{WIFI}.SSID.1.SSID"
SSID2 = f"{WIFI}.SSID.2.SSID"
KEY1 = f"{WIFI}.AccessPoint.1.Security.KeyPassphrase"
KEY2 = f"{WIFI}.AccessPoint.2.Security.KeyPassphrase"

IGD = "InternetGatewayDevice"
WLAN1 = f"{IGD}.LANDevice.1.WLANConfiguration.1"
PSK1 = f"{WLAN1}.PreSharedKey.1.KeyPassphrase"
KEYPHRASE1 = f"{WLAN1}.KeyPassphrase"


def tr181_leaves(**security: str) -> dict[str, Any]:
    """A dual-band TR-181 router whose bands are reported through LowerLayers."""
    leaves: dict[str, Any] = {
        "Device.ManagementServer.ConnectionRequestURL": {"value": "http://10.10.0.40:7547/", "writable": False},
        "Device.ManagementServer.PeriodicInformInterval": 300,
        "Device.DeviceInfo.Manufacturer": {"value": "Acme", "writable": False},
        f"{WIFI}.Radio.1.OperatingFrequencyBand": "2.4GHz",
        f"{WIFI}.Radio.2.OperatingFrequencyBand": "5GHz",
        SSID1: "Home",
        f"{WIFI}.SSID.1.LowerLayers": "Device.WiFi.Radio.1.",
        SSID2: "Home-5G",
        f"{WIFI}.SSID.2.LowerLayers": "Device.WiFi.Radio.2.",
    }
    for index in (1, 2):
        ap = f"{WIFI}.AccessPoint.{index}"
        leaves[f"{ap}.SSIDReference"] = f"Device.WiFi.SSID.{index}."
        leaves[f"{ap}.Security.ModeEnabled"] = security.get(f"mode{index}", "WPA2-Personal")
        leaves[f"{ap}.Security.KeyPassphrase"] = ""
    return leaves


def tr098_leaves() -> dict[str, Any]:
    """One TR-098 network on the generic profile: PreSharedKey.1.KeyPassphrase first, then KeyPassphrase."""
    return {
        f"{IGD}.ManagementServer.ConnectionRequestURL": {"value": "http://10.10.0.41:7547/", "writable": False},
        f"{IGD}.ManagementServer.PeriodicInformInterval": 300,
        f"{IGD}.DeviceInfo.Manufacturer": {"value": "Acme", "writable": False},
        f"{WLAN1}.SSID": "Shop",
        # A channel only lets SkyRouter infer the band, so single-band writes need confirming.
        f"{WLAN1}.Channel": 6,
        f"{WLAN1}.BeaconType": "11i",
        f"{WLAN1}.IEEE11iAuthenticationMode": "PSKAuthentication",
        KEYPHRASE1: "",
        PSK1: "",
    }


@pytest.fixture
def nbi():
    with FakeNbi() as fake:
        yield fake


@pytest.fixture
def make_service(nbi, tmp_path):
    def make(data_dir=None, **kwargs: Any) -> AcsService:
        directory = data_dir or tmp_path
        return AcsService(AcsClient(nbi.url, timeout=5), SecretStore(directory), directory, clock=nbi.now, **kwargs)

    return make


@pytest.fixture
def svc(make_service):
    return make_service()


def add(nbi: FakeNbi, leaves: dict[str, Any], serial: str = "000001", **kwargs: Any) -> str:
    return nbi.add_device(build_device(serial=serial, leaves=leaves, last_inform=nbi.now()), **kwargs)


@pytest.fixture
def router(nbi):
    return add(nbi, tr181_leaves())


def poll(service: AcsService, job: dict[str, Any], times: int = 1) -> dict[str, Any]:
    for _ in range(times):
        service.poll_jobs()
    return service.get_job(job["id"])


def posted_tasks(nbi: FakeNbi) -> list[dict[str, Any]]:
    return [json.loads(r.body) for r in nbi.requests_for("POST", "/devices/") if r.path.endswith("/tasks") and r.body]


def cr_posts(nbi: FakeNbi) -> list[Any]:
    return [r for r in nbi.requests_for("POST", "/devices/") if "connection_request" in r.query]


def job_file(service: AcsService) -> str:
    return service.jobs.path.read_text()


def assert_never_exposed(service: AcsService, caplog: pytest.LogCaptureFixture, *values: str) -> None:
    """Nothing SkyRouter stores or shows carries the passphrase: not the job file, a view, or a log line."""
    blobs = {
        "job file": job_file(service),
        "job views": json.dumps(service.list_jobs()),
        "log": caplog.text,
    }
    for value in values:
        for where, blob in blobs.items():
            assert value not in blob, f"passphrase leaked into the {where}"


# --- validation ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        {"band": "7GHz", "ssid": "Home"},
        {"band": "2.4GHz", "ssid": "   "},
        {"band": "2.4GHz", "ssid": "é" * 17},  # 34 UTF-8 bytes
        {"band": "2.4GHz", "ssid": "Home\nNet"},
        {"band": "2.4GHz", "passphrase": "short"},
        {"band": "2.4GHz", "passphrase": "pässwörd-with-umlauts"},
        {"band": "2.4GHz", "passphrase": "ab" * 32},  # a 64-hex PSK is refused in phase 1
        {"band": "2.4GHz"},
        {"band": "2.4GHz", "ssid": "Home", "confirm_guessed_band": "yes"},
    ],
)
def test_invalid_wifi_input_is_refused_before_anything_is_sent(nbi, svc, router, kwargs):
    with pytest.raises(ValidationError):
        svc.set_wifi(router, **kwargs)
    assert not nbi.requests_for("POST") and not nbi.tasks
    assert svc.list_jobs() == []
    assert svc.secrets.references() == []


def test_a_malformed_device_id_is_refused_locally(nbi, svc):
    with pytest.raises(ValidationError):
        svc.set_wifi("../devices", "2.4GHz", ssid="Home")
    assert nbi.requests == []


def test_a_passphrase_on_an_open_network_is_refused(nbi, svc):
    device = add(nbi, tr181_leaves(mode1="None"))
    with pytest.raises(ValidationError, match="no passphrase to change"):
        svc.set_wifi(device, "2.4GHz", passphrase=PASS)
    assert not nbi.tasks and svc.list_jobs() == [] and svc.secrets.references() == []


def test_a_guessed_band_needs_confirmation_but_all_bands_never_does(nbi, svc):
    device = add(nbi, tr098_leaves())
    with pytest.raises(AcsConfirmationRequired) as refused:
        svc.set_wifi(device, "2.4GHz", ssid="Shop-2")
    assert refused.value.plan["band_guessed"] is True
    assert refused.value.plan["leaves"][0]["value"] == "<ssid>"
    assert not nbi.tasks

    confirmed = svc.set_wifi(device, "2.4GHz", ssid="Shop-2", confirm_guessed_band=True)
    everywhere = svc.set_wifi(device, "all", ssid="Shop-3")
    assert confirmed["state"] == "contacting_router"
    assert svc.get_job(confirmed["id"])["state"] == "cancelled"  # superseded by the "all" change
    assert svc.get_job(everywhere["id"])["state"] == "contacting_router"


# --- acknowledged -------------------------------------------------------------------------


def test_a_change_is_acknowledged_when_every_leaf_carries_the_new_value(nbi, svc, router, caplog):
    caplog.set_level(logging.DEBUG)
    nbi.set_cr_outcome(router, 200, session=True)

    job = svc.set_wifi(router, "2.4GHz", ssid="Home-New", passphrase=PASS)
    assert job["state"] == "contacting_router"
    assert [step["name"] for step in job["steps"]] == ["getParameterValues", "setParameterValues"]

    # Task A reads the secret and the SSID first, so B cannot be skipped as unchanged (F15);
    # task B is one SetParameterValues covering both, so the router applies them together.
    read, write = posted_tasks(nbi)
    assert read["name"] == "getParameterValues" and set(read["parameterNames"]) == {SSID1, KEY1}
    assert write["name"] == "setParameterValues"
    assert sorted(path for path, _ in write["parameterValues"]) == sorted([SSID1, KEY1])
    assert write["uniqueKey"] == "skyrouter-wifi-24ghz" and write["expiry"] == tasks.WIFI_EXPIRY
    assert write["skyrouterJob"] == job["id"]
    # The connection request carries no body (§3.7 step 6).
    assert [r.body for r in cr_posts(nbi)] == [b""]

    done = poll(svc, job)
    assert done["state"] == "acknowledged"
    assert "cannot be read back" in done["message"]
    assert done["result"]["leaves"] == [
        {"path": SSID1, "kind": "ssid", "outcome": "acknowledged"},
        {"path": KEY1, "kind": "passphrase", "outcome": "acknowledged"},
    ]
    assert nbi.cpes[router].leaves[SSID1].value == "Home-New"
    assert nbi.cpes[router].leaves[KEY1].value == PASS

    # The pending entry became the band's current one.
    current = vault_ref(router, "2.4GHz", "current")
    assert done["vault_refs"] == {"current": [current]}
    assert svc.secrets.references() == [current]
    assert svc.secrets.get(current) == PASS
    assert_never_exposed(svc, caplog, PASS)


def test_the_acknowledgement_uses_task_b_timestamp(nbi, svc, router):
    nbi.set_cr_outcome(router, 200, session=True)
    job = svc.set_wifi(router, "5GHz", ssid="Home-5G-New")
    write = next(step for step in job["steps"] if step["step"] == "write")
    queued = next(r for r in nbi.sessions[-1]["tasks"] if r["name"] == "setParameterValues")
    assert write["task_id"] == queued["_id"]
    stamp = nbi.cached(router, SSID2)["_timestamp"]
    assert stamp >= write["submitted_ts"]
    assert poll(svc, job)["state"] == "acknowledged"


def test_vault_references_hash_the_device_id(router):
    digest = hashlib.sha256(router.encode()).hexdigest()[:20]
    assert vault_ref(router, "5GHz", "pending") == f"acs-wifi-{digest}-5GHz-pending"
    # GenieACS IDs carry "%", which the vault does not allow.
    assert "%" not in vault_ref(make_device_id("A0:B1", "X Y", "1/2"), "all", "current")


def test_a_change_to_all_bands_promotes_one_current_entry_per_band(nbi, svc, router):
    nbi.set_cr_outcome(router, 200, session=True)
    job = svc.set_wifi(router, "all", passphrase=PASS)
    assert svc.secrets.get(vault_ref(router, "all", "pending")) == PASS
    write = posted_tasks(nbi)[1]
    assert sorted(path for path, _ in write["parameterValues"]) == [KEY1, KEY2]

    done = poll(svc, job)
    assert done["state"] == "acknowledged"
    current = [vault_ref(router, "2.4GHz", "current"), vault_ref(router, "5GHz", "current")]
    assert done["vault_refs"] == {"current": current}
    assert svc.secrets.references() == sorted(current)
    assert all(svc.secrets.get(ref) == PASS for ref in current)


# --- not applied ----------------------------------------------------------------------------


def test_not_applied_when_the_router_no_longer_has_the_passphrase_leaf(nbi, svc):
    # GenieACS still caches the leaf, the router lacks it: the write is skipped silently (F15).
    device = add(nbi, tr181_leaves(), cpe_leaves={KEY1: None})
    nbi.set_cr_outcome(device, 200, session=True)
    job = svc.set_wifi(device, "2.4GHz", ssid="Home-2", passphrase=PASS)

    # One poll of grace: GenieACS clears tasks and saves the device separately.
    assert poll(svc, job)["state"] == "contacting_router"
    done = poll(svc, job)
    assert done["state"] == "not_applied"
    assert done["result"]["skipped"] == [{"path": KEY1, "kind": "passphrase", "reason": "not on the router"}]
    assert KEY1 in done["message"]
    assert svc.secrets.references() == []


def test_not_applied_when_the_router_reports_the_leaf_read_only(nbi, svc):
    device = add(nbi, tr181_leaves(), cpe_leaves={SSID1: {"value": "Home", "writable": False}})
    nbi.set_cr_outcome(device, 200, session=True)
    job = svc.set_wifi(device, "2.4GHz", ssid="Home-2")
    done = poll(svc, job, times=2)
    assert done["state"] == "not_applied"
    assert done["result"]["skipped"] == [{"path": SSID1, "kind": "ssid", "reason": "not written"}]
    assert nbi.cpes[device].leaves[SSID1].value == "Home"


def test_not_applied_when_the_cached_value_is_older_than_task_b(nbi, svc, router):
    nbi.set_cr_outcome(router, 504)
    job = svc.set_wifi(router, "2.4GHz", ssid="Home-2")
    # GenieACS dropped both tasks without a write, and its cache already held the
    # desired value from before B was queued: the stale timestamp gives it away.
    with nbi.lock:
        nbi.tasks.clear()
        leaf = nbi.devices[router]["Device"]["WiFi"]["SSID"]["1"]["SSID"]
        leaf["_value"] = "Home-2"
        leaf["_timestamp"] = iso(nbi.now() - timedelta(hours=1))
    done = poll(svc, job, times=2)
    assert done["state"] == "not_applied"
    assert done["result"]["skipped"] == [{"path": SSID1, "kind": "ssid", "reason": "no newer value"}]


# --- rejected -------------------------------------------------------------------------------


def test_a_refused_write_is_rejected_and_its_fault_cleared(nbi, svc, router, caplog):
    caplog.set_level(logging.DEBUG)
    nbi.inject_fault(router, SSID1, code="cwmp.9007", message="Invalid parameter value")
    nbi.set_cr_outcome(router, 200, session=True)
    job = svc.set_wifi(router, "2.4GHz", ssid="Home-2", passphrase=PASS)
    assert nbi.faults  # the router refused B

    done = poll(svc, job)
    assert done["state"] == "rejected"
    assert "cwmp.9007" in done["message"] and "Invalid parameter value" in done["message"]
    assert done["fault"]["parameters"] == [{"path": SSID1, "code": "9007", "message": "Invalid parameter value"}]
    # Deleting the fault deleted the task, so GenieACS stops retrying it (F16).
    assert nbi.faults == {} and nbi.device_tasks(router) == []
    # An SSID fault is not about the passphrase leaf, so nothing is re-planned.
    assert len([t for t in posted_tasks(nbi) if t["name"] == "setParameterValues"]) == 1
    assert svc.secrets.references() == []
    assert_never_exposed(svc, caplog, PASS)


def test_a_refused_passphrase_leaf_is_replanned_once_onto_the_next_leaf(nbi, svc):
    device = add(nbi, tr098_leaves())
    nbi.inject_fault(device, PSK1, code="cwmp.9007")
    nbi.set_cr_outcome(device, 200, session=True)
    job = svc.set_wifi(device, "all", passphrase=PASS)

    replanned = poll(svc, job)
    assert replanned["state"] == "contacting_router"
    assert replanned["plan"]["replans"] == 1 and replanned["plan"]["avoid"] == [PSK1]
    assert replanned["plan"]["first_fault"]["parameters"][0]["path"] == PSK1
    assert any("trying" in entry["note"] and KEYPHRASE1 in entry["note"] for entry in replanned["history"])

    done = poll(svc, job)
    assert done["state"] == "acknowledged"
    assert [leaf["path"] for leaf in done["plan"]["leaves"]] == [KEYPHRASE1]
    assert nbi.cpes[device].leaves[KEYPHRASE1].value == PASS
    writes = [t for t in posted_tasks(nbi) if t["name"] == "setParameterValues"]
    # Never KeyPassphrase and PreSharedKey in one write.
    assert [[path for path, _ in w["parameterValues"]] for w in writes] == [[PSK1], [KEYPHRASE1]]
    assert nbi.faults == {}


def test_only_one_replan_then_the_change_is_rejected(nbi, svc):
    device = add(nbi, tr098_leaves())
    nbi.inject_fault(device, PSK1, code="cwmp.9007")
    nbi.inject_fault(device, KEYPHRASE1, code="cwmp.9008", message="Attempt to set a non-writable parameter")
    nbi.set_cr_outcome(device, 200, session=True)
    job = svc.set_wifi(device, "all", passphrase=PASS)
    done = poll(svc, job, times=2)
    assert done["state"] == "rejected"
    assert "cwmp.9008" in done["message"]
    assert len([t for t in posted_tasks(nbi) if t["name"] == "setParameterValues"]) == 2
    assert nbi.faults == {} and nbi.device_tasks(device) == []


def test_rejected_when_the_profile_has_no_other_passphrase_leaf(nbi, svc, router):
    nbi.inject_fault(router, KEY1, code="cwmp.9007")
    nbi.set_cr_outcome(router, 200, session=True)
    job = svc.set_wifi(router, "2.4GHz", passphrase=PASS)
    done = poll(svc, job)
    assert done["state"] == "rejected" and done["plan"]["replans"] == 0


def test_a_faulted_read_is_cleared_and_never_blocks_the_write(nbi, svc, router):
    nbi.set_cr_outcome(router, 504)
    job = svc.set_wifi(router, "2.4GHz", ssid="Home-2")
    read = next(step for step in job["steps"] if step["step"] == "read")
    fault_id = f"{router}:task_{read['task_id']}"
    with nbi.lock:
        nbi.faults[fault_id] = {
            "_id": fault_id,
            "device": router,
            "channel": f"task_{read['task_id']}",
            "timestamp": iso(nbi.now()),
            "code": "cwmp.9002",
            "message": "Internal error",
            "detail": {},
            "retries": 0,
        }
    waiting = poll(svc, job)
    assert fault_id not in nbi.faults
    assert waiting["state"] == "waiting_for_checkin"
    assert next(step for step in waiting["steps"] if step["step"] == "read")["outcome"] == "faulted"
    nbi.run_session(router, cr=False)
    assert poll(svc, job)["state"] == "acknowledged"


# --- waiting for check-in and connection requests -----------------------------------------------


def test_waiting_for_checkin_then_applied_at_the_next_periodic_inform(nbi, svc, router):
    nbi.set_cr_outcome(router, 504, "Device is offline")
    job = svc.set_wifi(router, "2.4GHz", ssid="Home-2", passphrase=PASS)
    assert job["state"] == "waiting_for_checkin"
    last_inform = parse_iso(nbi.devices[router]["_lastInform"])
    assert last_inform is not None
    expected = iso(last_inform + timedelta(seconds=300))
    assert job["expected_by"] == expected
    assert job["message"] == (
        "Queued. The router is not reachable right now (Device is offline), so this will apply at its next "
        f"check-in, expected around {expected}."
    )
    assert job["cr_attempts"][0]["ok"] is False and job["cr_attempts"][0]["result"] == "Device is offline"

    assert poll(svc, job)["state"] == "waiting_for_checkin"
    nbi.run_session(router, cr=False)
    assert poll(svc, job)["state"] == "acknowledged"


def test_a_session_that_skipped_the_task_earns_at_most_two_more_connection_requests(nbi, svc, router):
    nbi.set_cr_outcome(router, 200)  # answered, but no session follows
    job = svc.set_wifi(router, "2.4GHz", ssid="Home-2")
    assert job["state"] == "contacting_router" and len(cr_posts(nbi)) == 1

    def inform_without_the_task() -> None:
        with nbi.lock:
            nbi.devices[router]["_lastInform"] = iso(nbi.now())

    # GenieACS stamps have millisecond precision; keep each inform clearly after the request.
    nbi.advance(1)
    inform_without_the_task()
    # Too soon after the last request: the poller waits out the 20 s spacing.
    assert len(poll(svc, job)["cr_attempts"]) == 1
    nbi.advance(CR_SPACING.total_seconds() + 1)
    assert len(poll(svc, job)["cr_attempts"]) == 2
    nbi.advance(1)
    inform_without_the_task()
    nbi.advance(CR_SPACING.total_seconds() + 1)
    assert len(poll(svc, job)["cr_attempts"]) == 3
    nbi.advance(1)
    inform_without_the_task()
    nbi.advance(CR_SPACING.total_seconds() + 1)
    final = poll(svc, job)
    assert len(final["cr_attempts"]) == 3 and len(cr_posts(nbi)) == 3
    # The task is still queued and still applies at the router's next session.
    nbi.run_session(router, cr=False)
    assert poll(svc, job)["state"] == "acknowledged"


def test_no_connection_request_is_resent_while_no_session_has_run(nbi, svc, router):
    nbi.set_cr_outcome(router, 200)
    job = svc.set_wifi(router, "2.4GHz", ssid="Home-2")
    nbi.advance(CR_SPACING.total_seconds() * 3)
    assert len(poll(svc, job)["cr_attempts"]) == 1


def test_a_router_that_answers_but_never_checks_in_is_shown_as_waiting(nbi, svc, router):
    nbi.set_cr_outcome(router, 200)
    job = svc.set_wifi(router, "2.4GHz", ssid="Home-2")
    nbi.advance(121)
    waiting = poll(svc, job)
    assert waiting["state"] == "waiting_for_checkin"
    assert "answered but has not checked in" in waiting["message"]


# --- expired -------------------------------------------------------------------------------


def test_expired_when_the_router_never_checks_in(nbi, svc, router):
    nbi.set_cr_outcome(router, 504)
    job = svc.set_wifi(router, "2.4GHz", ssid="Home-2", passphrase=PASS)
    nbi.advance(tasks.WIFI_EXPIRY - 60)
    assert poll(svc, job)["state"] == "waiting_for_checkin"
    nbi.advance(60 + EXPIRY_GRACE.total_seconds() + 1)
    done = poll(svc, job)
    assert done["state"] == "expired"
    assert nbi.device_tasks(router) == []
    assert svc.secrets.references() == []


def test_expired_when_genieacs_drops_the_task_at_a_late_session(nbi, svc, router):
    nbi.set_cr_outcome(router, 504)
    job = svc.set_wifi(router, "2.4GHz", ssid="Home-2")
    nbi.advance(tasks.WIFI_EXPIRY + 1)
    report = nbi.run_session(router, cr=False)
    assert {entry["outcome"] for entry in report["tasks"]} == {"expired"}
    done = poll(svc, job)
    assert done["state"] == "expired"
    assert nbi.cpes[router].leaves[SSID1].value == "Home"


# --- superseded --------------------------------------------------------------------------------


def test_a_newer_change_to_the_same_band_supersedes_the_older_one(nbi, svc, router):
    nbi.set_cr_outcome(router, 504)
    first = svc.set_wifi(router, "2.4GHz", ssid="Home-A", passphrase=PASS)
    second = svc.set_wifi(router, "2.4GHz", ssid="Home-B", passphrase=NEW_PASS)

    old = svc.get_job(first["id"])
    assert old["state"] == "cancelled" and old["superseded_by"] == second["id"]
    # Only the newer change is left at the ACS, under the band's uniqueKey.
    assert {task["skyrouterJob"] for task in nbi.device_tasks(router)} == {second["id"]}
    assert [t["uniqueKey"] for t in nbi.device_tasks(router)] == ["skyrouter-wifi-24ghz-read", "skyrouter-wifi-24ghz"]
    assert svc.secrets.get(vault_ref(router, "2.4GHz", "pending")) == NEW_PASS

    nbi.run_session(router, cr=False)
    assert poll(svc, second)["state"] == "acknowledged"
    assert svc.get_job(first["id"])["state"] == "cancelled"
    assert nbi.cpes[router].leaves[KEY1].value == NEW_PASS


def test_a_change_to_another_band_leaves_the_first_one_alone(nbi, svc, router):
    nbi.set_cr_outcome(router, 504)
    first = svc.set_wifi(router, "2.4GHz", ssid="Home-A")
    second = svc.set_wifi(router, "5GHz", ssid="Home-5G-B")
    assert svc.get_job(first["id"])["state"] == "waiting_for_checkin"
    nbi.run_session(router, cr=False)
    assert poll(svc, first)["state"] == "acknowledged"
    assert svc.get_job(second["id"])["state"] == "acknowledged"


def test_a_change_to_all_bands_supersedes_a_single_band_one(nbi, svc, router):
    nbi.set_cr_outcome(router, 504)
    first = svc.set_wifi(router, "5GHz", ssid="Home-5G-A")
    second = svc.set_wifi(router, "all", ssid="Everywhere")
    assert svc.get_job(first["id"])["superseded_by"] == second["id"]


def test_a_task_replaced_through_its_unique_key_elsewhere_cancels_the_job(nbi, svc, make_service, router, tmp_path):
    nbi.set_cr_outcome(router, 504)
    first = svc.set_wifi(router, "2.4GHz", ssid="Home-A")
    # Another SkyRouter with its own job file queues the same band: GenieACS replaces
    # the first change's tasks through their shared uniqueKey (F14).
    other = make_service(data_dir=tmp_path / "other")
    second = other.set_wifi(router, "2.4GHz", ssid="Home-B")
    done = poll(svc, first)
    assert done["state"] == "cancelled"
    assert done["superseded_by"] == second["id"]


def test_a_newer_change_stops_an_older_read_back_that_would_compare_the_wrong_passphrase(nbi, svc, router):
    nbi.set_cr_outcome(router, 200, session=True)
    first = svc.set_wifi(router, "2.4GHz", passphrase=PASS)
    assert poll(svc, first)["watch"] == "scrub"
    nbi.set_cr_outcome(router, 504)
    svc.set_wifi(router, "2.4GHz", passphrase=NEW_PASS)
    old = svc.get_job(first["id"])
    assert old["state"] == "acknowledged" and old["watch"] is None
    assert "replaces this one's read-back" in old["history"][-1]["note"]


# --- cancelling -------------------------------------------------------------------------------


def test_cancel_deletes_the_tasks_and_the_pending_passphrase(nbi, svc, router):
    nbi.set_cr_outcome(router, 504)
    job = svc.set_wifi(router, "2.4GHz", ssid="Home-2", passphrase=PASS)
    cancelled = svc.cancel_job(job["id"])
    assert cancelled["state"] == "cancelled" and cancelled["done"] is True
    assert nbi.device_tasks(router) == []
    assert svc.secrets.references() == []
    nbi.run_session(router, cr=False)
    assert poll(svc, job)["state"] == "cancelled"
    assert nbi.cpes[router].leaves[SSID1].value == "Home"


def test_cancel_while_the_router_is_mid_session_is_busy_then_succeeds(nbi, svc, router):
    nbi.set_cr_outcome(router, 504)
    job = svc.set_wifi(router, "2.4GHz", ssid="Home-2")
    nbi.set_busy(router, times=1)
    with pytest.raises(AcsBusy):
        svc.cancel_job(job["id"])
    assert svc.get_job(job["id"])["state"] == "waiting_for_checkin"
    assert svc.cancel_job(job["id"])["state"] == "cancelled"
    assert nbi.device_tasks(router) == []


def test_cancel_after_the_router_took_the_change_keeps_the_real_outcome(nbi, svc, router):
    nbi.set_cr_outcome(router, 504)
    job = svc.set_wifi(router, "2.4GHz", ssid="Home-2")
    nbi.run_session(router, cr=False)
    assert svc.cancel_job(job["id"])["state"] == "acknowledged"


def test_cancelling_a_finished_job_changes_nothing(nbi, svc, router):
    nbi.set_cr_outcome(router, 200, session=True)
    job = svc.set_wifi(router, "2.4GHz", ssid="Home-2")
    done = poll(svc, job)
    assert svc.cancel_job(job["id"])["state"] == done["state"] == "acknowledged"


def test_cancel_needs_a_real_job_id(svc):
    with pytest.raises(ValidationError):
        svc.cancel_job("../../etc")
    with pytest.raises(AcsNotFound):
        svc.cancel_job("0" * 16)


# --- the read-back (task C) ----------------------------------------------------------------------


def test_the_read_back_clears_genieacs_plaintext_copy(nbi, svc, router):
    nbi.set_cr_outcome(router, 200, session=True)
    job = svc.set_wifi(router, "2.4GHz", ssid="Home-2", passphrase=PASS)
    acknowledged = poll(svc, job)
    assert acknowledged["watch"] == "scrub" and acknowledged["done"] is False
    # GenieACS caches the plaintext it sent (F15) until task C reads the leaf again.
    assert nbi.cached(router, KEY1)["_value"] == PASS
    scrub = posted_tasks(nbi)[-1]
    assert scrub["name"] == "getParameterValues" and scrub["skyrouterStep"] == "scrub"
    assert len(cr_posts(nbi)) == 1  # C waits for the next inform

    nbi.run_session(router, cr=False)
    done = poll(svc, job)
    assert nbi.cached(router, KEY1)["_value"] == ""
    assert done["state"] == "acknowledged" and done["watch"] is None and done["done"] is True
    assert done["result"]["scrubbed"] is True
    assert done["result"]["leaves"] == [
        {"path": SSID1, "kind": "ssid", "outcome": "verified"},
        {"path": KEY1, "kind": "passphrase", "outcome": "acknowledged"},
    ]
    assert done["message"].endswith("The new SSID reads back correctly.")


def test_an_ssid_change_is_verified_by_the_read_back(nbi, svc, router):
    nbi.set_cr_outcome(router, 200, session=True)
    job = svc.set_wifi(router, "5GHz", ssid="Home-5G-2")
    poll(svc, job)
    nbi.run_session(router, cr=False)
    done = poll(svc, job)
    assert done["state"] == "verified"
    assert "scrubbed" not in done["result"]


def test_a_router_that_reads_its_passphrase_back_is_verified_and_flagged(nbi, svc, caplog):
    caplog.set_level(logging.DEBUG)
    device = add(nbi, tr181_leaves(), readback="plaintext")
    nbi.set_cr_outcome(device, 200, session=True)
    job = svc.set_wifi(device, "2.4GHz", passphrase=PASS)
    poll(svc, job)
    nbi.run_session(device, cr=False)
    done = poll(svc, job)
    assert done["state"] == "verified"
    assert done["result"]["readback"] == "plaintext"
    # The key still sits in GenieACS's database, and the job says so.
    assert done["result"]["scrubbed"] is False
    assert "exposes its Wi-Fi password" in done["message"]
    assert "readback=plaintext" in caplog.text
    assert_never_exposed(svc, caplog, PASS)


def test_a_masked_read_back_stays_acknowledged(nbi, svc):
    device = add(nbi, tr181_leaves(), readback="masked")
    nbi.set_cr_outcome(device, 200, session=True)
    job = svc.set_wifi(device, "2.4GHz", passphrase=PASS)
    poll(svc, job)
    nbi.run_session(device, cr=False)
    done = poll(svc, job)
    assert done["state"] == "acknowledged" and done["result"]["scrubbed"] is True


def test_with_scrubbing_off_no_read_back_is_queued(nbi, make_service, router):
    service = make_service(scrub_secrets=False)
    nbi.set_cr_outcome(router, 200, session=True)
    job = service.set_wifi(router, "2.4GHz", passphrase=PASS)
    done = poll(service, job)
    assert done["state"] == "acknowledged" and done["watch"] is None
    assert [t["name"] for t in posted_tasks(nbi)] == ["getParameterValues", "setParameterValues"]


def test_a_read_back_that_never_runs_stops_watching_at_its_expiry(nbi, svc, router):
    nbi.set_cr_outcome(router, 200, session=True)
    job = svc.set_wifi(router, "2.4GHz", ssid="Home-2")
    poll(svc, job)
    nbi.advance(tasks.WIFI_EXPIRY + EXPIRY_GRACE.total_seconds() + 1)
    done = poll(svc, job)
    assert done["state"] == "acknowledged" and done["watch"] is None
    assert nbi.device_tasks(router) == []


# --- the pre-flight --------------------------------------------------------------------------


def test_a_leaf_of_unknown_writability_is_refreshed_before_anything_is_written(nbi, svc, router):
    with nbi.lock:
        del nbi.devices[router]["Device"]["WiFi"]["SSID"]["1"]["SSID"]["_writable"]
    nbi.set_cr_outcome(router, 200, session=True)
    job = svc.set_wifi(router, "2.4GHz", ssid="Home-2")
    assert [(t["name"], t.get("objectName")) for t in posted_tasks(nbi)] == [("refreshObject", "Device.WiFi")]

    written = poll(svc, job)
    assert written["plan"]["refreshed"] is True
    assert [t["name"] for t in posted_tasks(nbi)][1:] == ["getParameterValues", "setParameterValues"]
    assert poll(svc, written)["state"] == "acknowledged"


def test_a_leaf_still_missing_after_the_refresh_ends_in_error_without_writing(nbi, svc):
    leaves = tr181_leaves()
    del leaves[KEY1]
    device = add(nbi, leaves)
    nbi.set_cr_outcome(device, 200, session=True)
    job = svc.set_wifi(device, "2.4GHz", passphrase=PASS)
    assert job["phase"] == "refresh"
    done = poll(svc, job)
    assert done["state"] == "error" and done["message"].startswith("Nothing was written")
    assert "setParameterValues" not in [t["name"] for t in posted_tasks(nbi)]
    assert svc.secrets.references() == []


# --- restarts ---------------------------------------------------------------------------------


def test_a_new_service_resumes_jobs_from_the_job_file(nbi, svc, make_service, router):
    nbi.set_cr_outcome(router, 504)
    job = svc.set_wifi(router, "2.4GHz", ssid="Home-2", passphrase=PASS)
    assert stat.S_IMODE(os.stat(svc.jobs.path).st_mode) == 0o600

    restarted = make_service()
    nbi.run_session(router, cr=False)
    assert poll(restarted, job)["state"] == "acknowledged"
    assert restarted.secrets.get(vault_ref(router, "2.4GHz", "current")) == PASS


def test_a_write_whose_reply_was_lost_is_found_by_its_job_field(nbi, svc, router, monkeypatch):
    queue = svc.client.queue_task

    def lose_the_write_reply(device_id, task):
        if task.step == "write":
            # The POST lands and the worker dies, then both lookups die too: the
            # client cannot tell whether B was queued.
            nbi.crash_next(3, after=True)
        return queue(device_id, task)

    monkeypatch.setattr(svc.client, "queue_task", lose_the_write_reply)
    nbi.set_cr_outcome(router, 200)
    job = svc.set_wifi(router, "2.4GHz", ssid="Home-2")
    assert job["state"] == "queued" and [step["step"] for step in job["steps"]] == ["read"]
    assert cr_posts(nbi) == []
    monkeypatch.undo()

    # The next poll finds B by skyrouterJob and sends the connection request it never sent.
    found = poll(svc, job)
    assert found["state"] == "contacting_router"
    assert [step["step"] for step in found["steps"]] == ["read", "write"]
    assert any("reply was lost" in entry["note"] for entry in found["history"])
    assert len(cr_posts(nbi)) == 1
    nbi.run_session(router)
    assert poll(svc, job)["state"] == "acknowledged"


def test_a_job_abandoned_before_its_first_task_ends_in_error_and_keeps_the_passphrase(nbi, svc, router):
    job = new_job(new_job_id(), router, job_store.KIND_WIFI, nbi.now(), request={"band": "2.4GHz"})
    job["vault_refs"] = {"pending": vault_ref(router, "2.4GHz", "pending")}
    svc.jobs.create(job)  # leased, as by a process that died right after
    svc.secrets.put(PASS, job["vault_refs"]["pending"])
    stray = tasks.get_parameter_values([SSID1], job=job["id"], step="read", unique_key="skyrouter-wifi-24ghz-read")
    svc.client.queue_task(router, stray)

    assert poll(svc, job)["state"] == "queued"  # the lease still stands
    nbi.advance(LEASE_TTL.total_seconds() + 1)
    done = poll(svc, job)
    assert done["state"] == "error" and "stopped while queueing" in done["message"]
    assert nbi.device_tasks(router) == []
    # Whether the router got it is unknown, so the passphrase stays in the vault.
    assert svc.secrets.get(vault_ref(router, "2.4GHz", "pending")) == PASS


def test_a_lease_held_elsewhere_is_left_alone_until_it_runs_out(nbi, svc, make_service, router):
    nbi.set_cr_outcome(router, 504)
    job = svc.set_wifi(router, "2.4GHz", ssid="Home-2")
    assert svc.jobs.claim(job["id"]) is not None  # another process is advancing it
    nbi.run_session(router, cr=False)
    other = make_service()
    assert poll(other, job)["state"] == "waiting_for_checkin"
    nbi.advance(LEASE_TTL.total_seconds() + 1)
    assert poll(other, job)["state"] == "acknowledged"


# --- the poller's resilience ---------------------------------------------------------------------


def test_a_poll_while_the_acs_is_down_waits_and_says_why(nbi, svc, router):
    nbi.set_cr_outcome(router, 504)
    job = svc.set_wifi(router, "2.4GHz", ssid="Home-2")
    nbi.crash_next(2)  # the first read and its one retry
    waiting = poll(svc, job)
    assert waiting["state"] == "waiting_for_checkin" and waiting["last_error"]
    nbi.run_session(router, cr=False)
    done = poll(svc, job)
    assert done["state"] == "acknowledged" and done["last_error"] is None


def test_a_router_removed_from_the_acs_ends_its_jobs(nbi, svc, router):
    nbi.set_cr_outcome(router, 504)
    job = svc.set_wifi(router, "2.4GHz", ssid="Home-2", passphrase=PASS)
    with nbi.lock:
        del nbi.devices[router]
    done = poll(svc, job)
    assert done["state"] == "error" and "no longer in the ACS" in done["message"]
    assert svc.secrets.references() == []


# --- reboot ---------------------------------------------------------------------------------


def test_a_reboot_is_verified_once_last_boot_moves_past_the_task(nbi, svc, router):
    nbi.set_cr_outcome(router, 200, session=True)
    job = svc.reboot(router)
    task = posted_tasks(nbi)[0]
    assert task["name"] == "reboot" and task["uniqueKey"] == "skyrouter-reboot"
    assert nbi.cpes[router].reboots == 1
    done = poll(svc, job)
    assert done["state"] == "verified"
    assert nbi.devices[router]["_lastBoot"] in done["message"]


def test_a_reboot_waits_for_the_next_checkin(nbi, svc, router):
    nbi.set_cr_outcome(router, 504)
    job = svc.reboot(router)
    assert job["state"] == "waiting_for_checkin" and "will run at its next check-in" in job["message"]
    nbi.run_session(router, cr=False)
    assert poll(svc, job)["state"] == "verified"


def test_a_reboot_the_router_accepted_is_acknowledged_until_it_reports_booting(nbi, svc, router):
    nbi.set_cr_outcome(router, 200)
    job = svc.reboot(router)
    with nbi.lock:
        nbi.tasks.clear()  # the RPC went through; the router has not come back yet
    accepted = poll(svc, job)
    assert accepted["state"] == "acknowledged" and accepted["watch"] == "boot"
    nbi.advance(1)
    with nbi.lock:
        nbi.devices[router]["_lastBoot"] = iso(nbi.now())
    done = poll(svc, job)
    assert done["state"] == "verified" and done["watch"] is None


def test_a_reboot_that_never_reports_back_stops_being_watched(nbi, svc, router):
    nbi.set_cr_outcome(router, 200)
    job = svc.reboot(router)
    with nbi.lock:
        nbi.tasks.clear()
    poll(svc, job)
    nbi.advance(16 * 60)
    done = poll(svc, job)
    assert done["state"] == "acknowledged" and done["watch"] is None
    assert "has not reported booting" in done["message"]


def test_a_reboot_the_router_refuses_is_rejected(nbi, svc, router):
    nbi.inject_task_fault(router, "reboot", code="cwmp.9000", message="Method not supported")
    nbi.set_cr_outcome(router, 200, session=True)
    job = svc.reboot(router)
    done = poll(svc, job)
    assert done["state"] == "rejected" and "cwmp.9000" in done["message"]
    assert nbi.faults == {} and nbi.device_tasks(router) == []


def test_a_second_reboot_request_returns_the_pending_one(nbi, svc, router):
    nbi.set_cr_outcome(router, 504)
    first = svc.reboot(router)
    assert svc.reboot(router)["id"] == first["id"]
    assert len(posted_tasks(nbi)) == 1


def test_a_reboot_can_be_cancelled_before_it_runs(nbi, svc, router):
    nbi.set_cr_outcome(router, 504)
    job = svc.reboot(router)
    assert svc.cancel_job(job["id"])["state"] == "cancelled"
    nbi.run_session(router, cr=False)
    assert nbi.cpes[router].reboots == 0


# --- refresh ---------------------------------------------------------------------------------


def test_a_refresh_is_verified_when_fresh_data_arrives(nbi, svc, router):
    nbi.set_cr_outcome(router, 200, session=True)
    job = svc.refresh(router, "wifi")
    task = posted_tasks(nbi)[0]
    assert task == {
        "name": "refreshObject",
        "objectName": "Device.WiFi",
        "expiry": tasks.DEFAULT_EXPIRY,
        "uniqueKey": "skyrouter-refresh-wifi",
        "skyrouterJob": job["id"],
        "skyrouterStep": "refresh",
    }
    done = poll(svc, job)
    assert done["state"] == "verified" and done["request"] == {"scope": "wifi", "object": "Device.WiFi"}


def test_a_refresh_that_brings_nothing_newer_is_acknowledged(nbi, svc, router):
    nbi.set_cr_outcome(router, 504)
    job = svc.refresh(router, "hosts")
    with nbi.lock:
        nbi.tasks.clear()
    assert poll(svc, job)["state"] == "waiting_for_checkin"
    done = poll(svc, job)
    assert done["state"] == "acknowledged" and "nothing newer" in done["message"]


def test_a_refresh_scope_must_exist_on_the_router(nbi, svc, router):
    with pytest.raises(ValidationError):
        svc.refresh(router, "everything")
    issue1 = nbi.add_device(
        build_device(
            serial="issue1",
            leaves={
                "Device.DeviceInfo.Manufacturer": "Acme",
                "Device.LAN.IPAddress": "192.168.1.1",
            },
        )
    )
    with pytest.raises(ValidationError, match="no wifi scope"):
        svc.refresh(issue1, "wifi")
    assert not nbi.tasks


def test_a_second_refresh_of_one_scope_returns_the_running_job(nbi, svc, router):
    nbi.set_cr_outcome(router, 504)
    first = svc.refresh(router, "wifi")
    assert svc.refresh(router, "wifi")["id"] == first["id"]
    assert svc.refresh(router, "wan")["id"] != first["id"]


def test_a_refresh_the_router_refuses_is_rejected(nbi, svc, router):
    nbi.inject_task_fault(router, "refreshObject", code="cwmp.9002", message="Internal error")
    nbi.set_cr_outcome(router, 200, session=True)
    job = svc.refresh(router, "info")
    done = poll(svc, job)
    assert done["state"] == "rejected" and "cwmp.9002" in done["message"]
    assert nbi.faults == {}


def test_actions_on_an_unknown_router_are_not_found(nbi, svc):
    ghost = make_device_id("202BC1", "BM632w", "ghost")
    for action in (lambda: svc.reboot(ghost), lambda: svc.refresh(ghost, "wifi")):
        with pytest.raises(AcsNotFound):
            action()
    with pytest.raises(AcsNotFound):
        svc.set_wifi(ghost, "2.4GHz", ssid="Home")
    assert svc.list_jobs() == []
