"""TR-069 firmware upgrades through GenieACS, end to end against the fake NBI.

The fake models the part of a Download that matters here: the task going away only
means the router accepted the RPC, and the transfer's outcome comes later, in the
boot session that follows (or a TransferComplete fault on the task's channel).
"""

import base64
import hashlib
import json
import os
import re
import stat
from datetime import timedelta
from typing import Any

import pytest
from fake_nbi import FakeNbi, build_device, parse_iso

from cudy_manager.acs import client as client_module
from cudy_manager.acs import params, tasks
from cudy_manager.acs import service as service_module
from cudy_manager.acs.client import AcsBusy, AcsClient, AcsError, AcsNotFound, AcsUnavailable
from cudy_manager.acs.jobs import (
    CANCELLED,
    CONTACTING_ROUTER,
    ERROR,
    EXPIRED,
    KIND_FIRMWARE,
    NOT_APPLIED,
    REJECTED,
    VERIFIED,
    WAITING_FOR_CHECKIN,
    JobStoreError,
)
from cudy_manager.acs.service import (
    EXPIRY_GRACE,
    FIRMWARE_INSTALL_WAIT,
    AcsConfirmationRequired,
    AcsService,
    FirmwareMismatch,
)
from cudy_manager.activity import ActivityLog
from cudy_manager.models import ValidationError
from cudy_manager.secrets import SecretStore

OUI = "80AFCA"
PRODUCT = "AP1300"
OLD = "2.5.25-20260820-141832"
NEW = "2.5.26-20261001-120000"
# Stands in for the image: it must never turn up in a job, the library index or a log.
CONTENT = b"FIRMWARE-CONTENT-MARKER-" * 64

WIFI = "Device.WiFi"
KEY1 = f"{WIFI}.AccessPoint.1.Security.KeyPassphrase"
NEW_PASS = "Tr0ub4dor&3-staple"


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


def cudy(
    nbi: FakeNbi,
    serial: str = "000001",
    *,
    oui: str = OUI,
    product_class: str = PRODUCT,
    version: str | None = OLD,
    minutes_ago: float = 0,
    extra: dict[str, Any] | None = None,
) -> str:
    leaves: dict[str, Any] = {
        "Device.ManagementServer.ConnectionRequestURL": {"value": "http://10.10.0.40:7547/", "writable": False},
        "Device.ManagementServer.PeriodicInformInterval": 300,
        "Device.DeviceInfo.Manufacturer": {"value": "Cudy", "writable": False},
        "Device.DeviceInfo.ModelName": {"value": "AP1300", "writable": False},
        "Device.DeviceInfo.HardwareVersion": {"value": "AP1300 V1.1", "writable": False},
        **(extra or {}),
    }
    if version is not None:
        leaves["Device.DeviceInfo.SoftwareVersion"] = {"value": version, "writable": False}
    doc = build_device(
        oui=oui,
        product_class=product_class,
        serial=serial,
        manufacturer="Cudy",
        leaves=leaves,
        last_inform=nbi.now() - timedelta(minutes=minutes_ago),
    )
    return nbi.add_device(doc)


@pytest.fixture
def router(nbi):
    return cudy(nbi)


def upload(svc: AcsService, **overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "data": CONTENT,
        "filename": "AP1300-2.5.26.bin",
        "model_hint": "Cudy AP1300",
        "version": NEW,
        "oui": OUI,
        "product_class": PRODUCT,
    }
    values.update(overrides)
    return svc.add_firmware(**values)


def poll(svc: AcsService, job: dict[str, Any], times: int = 1) -> dict[str, Any]:
    for _ in range(times):
        svc.poll_jobs()
    return svc.get_job(job["id"])


def download_tasks(nbi: FakeNbi) -> list[dict[str, Any]]:
    return [task for task in nbi.tasks if task["name"] == "download"]


def accepted(nbi: FakeNbi, svc: AcsService, router: str, **kwargs: Any) -> dict[str, Any]:
    """An upgrade whose Download the router has taken, but not yet reported on."""
    job = svc.firmware_upgrade(router, upload(svc, **kwargs)["name"], actor="alice")
    nbi.run_session(router)
    job = poll(svc, job)
    assert job["state"] == WAITING_FOR_CHECKIN, job["message"]
    return job


# --- the download task ------------------------------------------------------------------


class TestDownloadTask:
    def test_a_download_names_one_skyrouter_file_and_nothing_else(self):
        task = tasks.download("skybre-fw-0123456789abcdef", job="j", step="download")
        assert task.to_json() == {
            "name": "download",
            "file": "skybre-fw-0123456789abcdef",
            "expiry": 86400,
            "uniqueKey": "skyrouter-firmware",
            "skyrouterJob": "j",
            "skyrouterStep": "download",
        }
        assert task.paths == ()
        assert "skybre-fw-0123456789abcdef" in repr(task)

    @pytest.mark.parametrize(
        "name",
        [
            pytest.param("", id="empty"),
            pytest.param("skybre-fw-", id="no-token"),
            pytest.param("skybre-fw-abc1234", id="token-too-short"),
            pytest.param("skybre-fw-" + "a" * 81, id="token-too-long"),
            pytest.param("skybre-fw-ABCDEF123456", id="upper-case"),
            pytest.param("skybre-fw-abcdef12.bin", id="dot"),
            pytest.param("skybre-fw-../../etc/passwd", id="traversal"),
            pytest.param("vendor-image-abcdef123456", id="not-skyrouters"),
            pytest.param("skybre-fw-abcdef12345\n", id="newline"),
            pytest.param(None, id="none"),
            pytest.param(7, id="number"),
        ],
    )
    def test_file_names_outside_skyrouters_own_naming_are_refused(self, name):
        with pytest.raises(ValidationError):
            tasks.download(name, job="j", step="download")
        with pytest.raises(ValidationError):
            tasks.validate_firmware_name(name)

    @pytest.mark.parametrize(
        "extra",
        [
            pytest.param({"fileType": "1 Firmware Upgrade Image"}, id="file-type"),
            pytest.param({"fileName": "other.bin"}, id="file-name"),
            pytest.param({"targetFileName": "x"}, id="target-file-name"),
            pytest.param({"url": "http://evil.example/fw.bin"}, id="url"),
        ],
    )
    def test_free_form_download_fields_never_pass_validation(self, extra):
        base = {
            "name": "download",
            "file": "skybre-fw-0123456789abcdef",
            "expiry": 86400,
            "uniqueKey": "skyrouter-firmware",
            "skyrouterJob": "j",
            "skyrouterStep": "download",
        }
        tasks.validate_task(base)
        with pytest.raises(ValidationError, match="unsupported fields"):
            tasks.validate_task({**base, **extra})
        without_file = {key: value for key, value in base.items() if key != "file"}
        with pytest.raises(ValidationError, match="missing fields: file"):
            tasks.validate_task(without_file)
        # GenieACS's own fileType + fileName form is never an alternative to a file ID.
        with pytest.raises(ValidationError, match="unsupported fields"):
            tasks.validate_task({**without_file, "fileType": "1 Firmware Upgrade Image", "fileName": "x"})

    def test_a_file_on_any_other_task_is_refused(self):
        with pytest.raises(ValidationError, match="does not take file"):
            tasks.Task("reboot", "j", "s", "skyrouter-reboot", file="skybre-fw-0123456789abcdef")


# --- the client -----------------------------------------------------------------------------


class TestClientFiles:
    NAME = "skybre-fw-0123456789abcdef"

    @pytest.fixture
    def client(self, nbi):
        return AcsClient(nbi.url, timeout=5)

    def test_put_file_stores_the_content_with_its_metadata_as_headers(self, nbi, client):
        client.put_file(self.NAME, b"image", "1 Firmware Upgrade Image", OUI, PRODUCT, NEW)
        assert nbi.file_data[self.NAME] == b"image"
        assert nbi.files[self.NAME]["metadata"] == {
            "fileType": "1 Firmware Upgrade Image",
            "oui": OUI,
            "productClass": PRODUCT,
            "version": NEW,
        }
        [put] = nbi.requests_for("PUT")
        assert put.path == f"/files/{self.NAME}" and put.status == 201
        headers = {key.lower(): value for key, value in put.headers.items()}
        assert headers["content-type"] == "application/octet-stream"

    @pytest.mark.parametrize(
        "kwargs",
        [
            pytest.param({"name": "fw.bin"}, id="foreign-name"),
            pytest.param({"data": b""}, id="empty"),
            pytest.param({"data": "text"}, id="not-bytes"),
            pytest.param({"file_type": "6 Unknown"}, id="file-type"),
            pytest.param({"oui": ""}, id="empty-oui"),
            pytest.param({"product_class": "AP1300\r\nX-Evil: 1"}, id="header-injection"),
            pytest.param({"version": " 2.5.26"}, id="leading-space"),
            pytest.param({"version": "v" * 65}, id="version-too-long"),
            pytest.param({"version": "2.5.26\u00e9"}, id="not-ascii"),
        ],
    )
    def test_bad_files_are_refused_before_any_request(self, nbi, client, kwargs):
        values = {
            "name": self.NAME,
            "data": b"image",
            "file_type": "1 Firmware Upgrade Image",
            "oui": OUI,
            "product_class": PRODUCT,
            "version": NEW,
            **kwargs,
        }
        with pytest.raises(ValidationError):
            client.put_file(**values)
        assert nbi.requests == []

    def test_a_file_over_the_limit_is_refused(self, nbi, client, monkeypatch):
        monkeypatch.setattr(client_module, "MAX_FILE_BYTES", 4)
        with pytest.raises(ValidationError, match="at most"):
            client.put_file(self.NAME, b"12345", "1 Firmware Upgrade Image", OUI, PRODUCT, NEW)
        assert nbi.requests == []

    def test_anything_but_201_is_an_error(self, nbi, client):
        client.version()
        nbi.reply_next(200)
        with pytest.raises(AcsError, match="unexpected ACS reply"):
            client.put_file(self.NAME, b"image", "1 Firmware Upgrade Image", OUI, PRODUCT, NEW)

    def test_an_upload_gets_longer_than_an_ordinary_request(self, nbi, client, monkeypatch):
        seen: list[float | None] = []
        send = client._session.request

        def spy(method, path, *args, **kwargs):
            seen.append(kwargs.get("timeout"))
            return send(method, path, *args, **kwargs)

        client.version()
        monkeypatch.setattr(client._session, "request", spy)
        client.put_file(self.NAME, b"image", "1 Firmware Upgrade Image", OUI, PRODUCT, NEW)
        assert seen == [client_module.FILE_UPLOAD_TIMEOUT] and client.timeout < client_module.FILE_UPLOAD_TIMEOUT

    def test_a_lost_reply_leaves_the_outcome_unknown(self, nbi, client):
        client.version()
        nbi.crash_next(after=True)
        with pytest.raises(AcsUnavailable) as caught:
            client.put_file(self.NAME, b"image", "1 Firmware Upgrade Image", OUI, PRODUCT, NEW)
        assert caught.value.outcome_unknown
        # Never retried: one PUT only.
        assert len(nbi.requests_for("PUT")) == 1

    def test_delete_file_and_a_missing_file(self, nbi, client):
        client.put_file(self.NAME, b"image", "1 Firmware Upgrade Image", OUI, PRODUCT, NEW)
        client.delete_file(self.NAME)
        assert self.NAME not in nbi.files and self.NAME not in nbi.file_data
        with pytest.raises(AcsNotFound):
            client.delete_file(self.NAME)
        with pytest.raises(ValidationError):
            client.delete_file("../presets/x")

    def test_list_files_reads_metadata_only(self, nbi, client):
        client.put_file(self.NAME, b"image", "1 Firmware Upgrade Image", OUI, PRODUCT, NEW)
        [record] = client.list_files()
        assert record == {
            "name": self.NAME,
            "size": 5,
            "uploaded_at": nbi.files[self.NAME]["uploadDate"],
            "file_type": "1 Firmware Upgrade Image",
            "oui": OUI,
            "product_class": PRODUCT,
            "version": NEW,
        }
        [listing] = [r for r in nbi.requests_for("GET", "/files")]
        assert listing.query["projection"] == "_id,length,uploadDate,metadata"
        assert client.get_file(self.NAME) == record
        assert client.get_file("skybre-fw-ffffffffffffffff") is None

    def test_file_queries_only_take_skyrouter_names(self, client):
        with pytest.raises(ValidationError):
            client.find("files", {"_id": "*"})
        with pytest.raises(ValidationError):
            client.find("files", {"metadata.version": NEW})
        with pytest.raises(ValidationError):
            client.get_file("other.bin")

    def test_a_queued_download_is_listed_with_its_file(self, nbi, client, router):
        client.queue_task(router, tasks.download(self.NAME, job="j", step="download"))
        [listed] = client.tasks(device_id=router)
        assert listed["name"] == "download" and listed["file"] == self.NAME


# --- params ----------------------------------------------------------------------------------


def test_the_identity_comes_from_the_device_id_first(nbi):
    device = cudy(nbi, oui="80afca", extra={"Device.DeviceInfo.ManufacturerOUI": {"value": "FFFFFF"}})
    doc = nbi.devices[device]
    identity = params.firmware_identity(doc, nbi.now(), 300)
    assert identity["oui"] == "80afca" and identity["product_class"] == PRODUCT
    assert identity["software_version"] == OLD and identity["hardware_version"] == "AP1300 V1.1"
    assert identity["model"] == "AP1300" and identity["online"] is True
    # Only the DeviceInfo copy left: it is the fallback.
    del doc["_deviceId"]["_OUI"]
    assert params.firmware_identity(doc, nbi.now(), 300)["oui"] == "FFFFFF"


# --- the library --------------------------------------------------------------------------------


class TestLibrary:
    def test_a_file_is_stored_under_a_random_name_with_its_checksum(self, nbi, svc):
        record = upload(svc, filename="C:\\firmware\\AP1300-2.5.26.bin")
        assert re.fullmatch(r"skybre-fw-[0-9a-f]{32}", record["name"])
        assert record["sha256"] == hashlib.sha256(CONTENT).hexdigest() and record["size"] == len(CONTENT)
        assert record["filename"] == "AP1300-2.5.26.bin" and record["model_hint"] == "Cudy AP1300"
        assert record["version"] == NEW and record["oui"] == OUI and record["product_class"] == PRODUCT
        assert parse_iso(record["uploaded_at"]) is not None
        assert record["on_acs"] is True and record["in_use_by"] == []
        assert nbi.file_data[record["name"]] == CONTENT
        assert nbi.files[record["name"]]["metadata"]["fileType"] == "1 Firmware Upgrade Image"
        assert upload(svc)["name"] != record["name"]

    def test_the_index_is_private_and_never_holds_the_content(self, nbi, svc):
        upload(svc)
        index = svc.firmware.path
        assert stat.S_IMODE(os.stat(index).st_mode) == 0o600
        text = index.read_text()
        assert CONTENT.decode()[:24] not in text and base64.b64encode(CONTENT).decode()[:40] not in text

    @pytest.mark.parametrize(
        "overrides",
        [
            pytest.param({"data": b""}, id="empty"),
            pytest.param({"data": "not bytes"}, id="not-bytes"),
            pytest.param({"version": ""}, id="no-version"),
            pytest.param({"version": "2.5.26\nX"}, id="version-newline"),
            pytest.param({"version": "2.5\r\n26"}, id="version-crlf"),
            pytest.param({"oui": ""}, id="no-oui"),
            pytest.param({"product_class": "AP1300\nX: y"}, id="product-class-newline"),
            pytest.param({"model_hint": 7}, id="model-hint"),
            pytest.param({"filename": b"fw.bin"}, id="filename-bytes"),
        ],
    )
    def test_bad_uploads_are_refused_before_anything_is_sent(self, nbi, svc, overrides):
        with pytest.raises(ValidationError):
            upload(svc, **overrides)
        assert nbi.requests == [] and svc.firmware.all() == {}

    def test_an_upload_over_64_mib_is_refused(self, nbi, svc, monkeypatch):
        assert service_module.MAX_FIRMWARE_BYTES == 64 * 1024 * 1024
        monkeypatch.setattr(service_module, "MAX_FIRMWARE_BYTES", len(CONTENT) - 1)
        with pytest.raises(ValidationError, match="larger than"):
            upload(svc)
        assert nbi.requests == []

    def test_the_display_fields_are_optional(self, svc):
        record = upload(svc, filename=None, model_hint="  ")
        assert record["filename"] is None and record["model_hint"] is None

    @pytest.mark.parametrize(
        "content",
        [pytest.param("{not json", id="corrupt"), pytest.param('{"files": []}', id="wrong-shape")],
    )
    def test_a_damaged_index_is_refused_and_never_replaced(self, nbi, svc, content):
        svc.firmware.path.write_text(content)
        with pytest.raises(JobStoreError):
            svc.list_firmware()
        with pytest.raises(JobStoreError):
            upload(svc)
        assert svc.firmware.path.read_text() == content
        # The file it had already stored is taken back off the ACS.
        assert nbi.files == {}

    def test_surrounding_whitespace_is_trimmed(self, svc):
        record = upload(svc, version=f"  {NEW} ", oui=f" {OUI}", product_class=f"{PRODUCT} ")
        assert (record["version"], record["oui"], record["product_class"]) == (NEW, OUI, PRODUCT)

    def test_a_lost_upload_reply_removes_whatever_was_stored(self, nbi, svc):
        svc.client.version()
        nbi.crash_next(after=True)
        with pytest.raises(AcsUnavailable):
            upload(svc)
        assert nbi.files == {} and svc.firmware.all() == {}
        assert len(nbi.requests_for("DELETE", "/files/")) == 1

    def test_an_index_that_cannot_be_written_removes_the_stored_file(self, nbi, svc, monkeypatch):
        def broken(record):
            raise JobStoreError("disk full")

        monkeypatch.setattr(svc.firmware, "add", broken)
        with pytest.raises(JobStoreError):
            upload(svc)
        assert nbi.files == {}

    def test_the_library_lists_newest_first_and_says_what_is_on_the_acs(self, nbi, svc, router):
        first = upload(svc)
        nbi.advance(5)
        second = upload(svc, version="2.5.27")
        del nbi.files[first["name"]]
        listed = svc.list_firmware()
        assert [item["name"] for item in listed] == [second["name"], first["name"]]
        assert [item["on_acs"] for item in listed] == [True, False]
        job = svc.firmware_upgrade(router, second["name"])
        assert svc.list_firmware()[0]["in_use_by"] == [job["id"]]

    def test_the_library_is_still_listed_while_the_acs_is_down(self, svc, monkeypatch):
        upload(svc)

        def down():
            raise AcsUnavailable("ACS unavailable")

        monkeypatch.setattr(svc.client, "list_files", down)
        [item] = svc.list_firmware()
        assert item["on_acs"] is None

    def test_removing_a_file_deletes_it_from_the_acs_and_the_library(self, nbi, svc):
        record = upload(svc)
        assert svc.remove_firmware(record["name"]) == {"name": record["name"], "removed": True}
        assert nbi.files == {} and svc.list_firmware() == []
        with pytest.raises(AcsNotFound):
            svc.remove_firmware(record["name"])
        with pytest.raises(ValidationError):
            svc.remove_firmware("../etc")

    def test_a_file_already_gone_from_the_acs_still_leaves_the_library(self, nbi, svc):
        record = upload(svc)
        del nbi.files[record["name"]]
        svc.remove_firmware(record["name"])
        assert svc.firmware.all() == {}

    def test_a_file_an_upgrade_is_using_cannot_be_removed(self, nbi, svc, router):
        record = upload(svc)
        job = svc.firmware_upgrade(router, record["name"])
        with pytest.raises(AcsBusy, match=job["id"]):
            svc.remove_firmware(record["name"])
        assert record["name"] in nbi.files and svc.firmware.get(record["name"]) is not None


# --- pre-flight -------------------------------------------------------------------------------


def test_an_upgrade_queues_one_download_and_a_connection_request(nbi, svc, router):
    record = upload(svc)
    job = svc.firmware_upgrade(router, record["name"], actor="alice")
    assert job["kind"] == KIND_FIRMWARE and job["state"] == CONTACTING_ROUTER and job["actor"] == "alice"
    assert job["request"]["version"] == NEW and job["request"]["from_version"] == OLD
    assert job["request"]["sha256"] == record["sha256"]
    [task] = download_tasks(nbi)
    assert task["file"] == record["name"] and task["uniqueKey"] == "skyrouter-firmware"
    assert "fileType" not in task and "fileName" not in task
    assert parse_iso(task["expiry"]) - parse_iso(task["timestamp"]) == timedelta(seconds=86400)
    assert nbi.cr_requests == [router]


def test_an_upgrade_and_a_reboot_can_be_given_a_shorter_expiry(nbi, svc, router):
    # A maintenance plan's window: a router that misses it must not take the task later.
    record = upload(svc)
    svc.firmware_upgrade(router, record["name"], actor="alice", expiry=900)
    svc.reboot(cudy(nbi, "000002"), actor="alice", expiry=600)
    download, reboot = nbi.tasks
    assert parse_iso(download["expiry"]) - parse_iso(download["timestamp"]) == timedelta(seconds=900)
    assert parse_iso(reboot["expiry"]) - parse_iso(reboot["timestamp"]) == timedelta(seconds=600)


@pytest.mark.parametrize("expiry", [0, 59, 7 * 86400 + 1, True, 60.5, "600"])
def test_an_expiry_out_of_range_is_refused_before_anything_is_queued(nbi, svc, router, expiry):
    record = upload(svc)
    with pytest.raises(ValidationError, match="expiry"):
        svc.firmware_upgrade(router, record["name"], expiry=expiry)
    with pytest.raises(ValidationError, match="expiry"):
        svc.reboot(router, expiry=expiry)
    assert nbi.tasks == [] and svc.list_jobs() == []


def test_the_job_record_never_holds_the_file(nbi, svc, router):
    job = accepted(nbi, svc, router)
    nbi.run_session(router)
    poll(svc, job)
    blob = svc.jobs.path.read_text() + json.dumps(svc.list_jobs())
    assert CONTENT.decode()[:24] not in blob and base64.b64encode(CONTENT).decode()[:40] not in blob


def test_a_model_mismatch_is_refused_unless_confirmed(nbi, svc):
    other = cudy(nbi, "000002", product_class="WR840N")
    record = upload(svc)
    with pytest.raises(FirmwareMismatch) as caught:
        svc.firmware_upgrade(other, record["name"])
    # It is a confirmation request, so the dashboard answers it like the Wi-Fi one (409).
    assert isinstance(caught.value, AcsConfirmationRequired)
    assert caught.value.plan["mismatch"] == ["product_class"]
    assert caught.value.plan["device"]["product_class"] == "WR840N"
    assert caught.value.plan["firmware"]["product_class"] == PRODUCT
    assert "WR840N" in str(caught.value) and "confirm" in str(caught.value)
    assert download_tasks(nbi) == [] and svc.list_jobs() == []

    job = svc.firmware_upgrade(other, record["name"], confirm_model_mismatch=True)
    assert job["request"]["model_mismatch"] == ["product_class"] and job["request"]["confirm_model_mismatch"]
    assert len(download_tasks(nbi)) == 1


def test_a_different_oui_is_a_mismatch_but_its_case_is_not(nbi, svc):
    lower = cudy(nbi, "000002", oui=OUI.lower())
    other = cudy(nbi, "000003", oui="001122")
    record = upload(svc)
    svc.firmware_upgrade(lower, record["name"])
    with pytest.raises(FirmwareMismatch) as caught:
        svc.firmware_upgrade(other, record["name"])
    assert caught.value.plan["mismatch"] == ["oui"]


def test_the_version_the_router_already_runs_is_refused(nbi, svc, router):
    record = upload(svc, version=OLD)
    with pytest.raises(ValidationError, match="already runs"):
        svc.firmware_upgrade(router, record["name"])
    assert download_tasks(nbi) == [] and svc.list_jobs() == []


def test_a_router_that_stopped_checking_in_is_refused(nbi, svc):
    stale = cudy(nbi, "000002", minutes_ago=60)
    with pytest.raises(ValidationError, match="not checked in"):
        svc.firmware_upgrade(stale, upload(svc)["name"])
    assert download_tasks(nbi) == []


def test_a_router_whose_version_is_unknown_is_refused(nbi, svc):
    unknown = cudy(nbi, "000002", version=None)
    with pytest.raises(ValidationError, match="refresh its info"):
        svc.firmware_upgrade(unknown, upload(svc)["name"])
    assert download_tasks(nbi) == []


def test_a_file_missing_from_the_acs_or_changed_there_is_refused(nbi, svc, router):
    record = upload(svc)
    nbi.files[record["name"]]["length"] += 1
    with pytest.raises(ValidationError, match="not the file SkyRouter stored"):
        svc.firmware_upgrade(router, record["name"])
    del nbi.files[record["name"]]
    with pytest.raises(ValidationError, match="no longer on the ACS"):
        svc.firmware_upgrade(router, record["name"])
    assert download_tasks(nbi) == []


def test_unknown_and_malformed_requests(nbi, svc, router):
    with pytest.raises(AcsNotFound):
        svc.firmware_upgrade(router, "skybre-fw-0123456789abcdef")
    before = len(nbi.requests)
    for kwargs in (
        {"acs_id": router, "firmware_name": "firmware.bin"},
        {"acs_id": "not a device", "firmware_name": "skybre-fw-0123456789abcdef"},
        {"acs_id": router, "firmware_name": "skybre-fw-0123456789abcdef", "confirm_model_mismatch": "yes"},
        {"acs_id": router, "firmware_name": "skybre-fw-0123456789abcdef", "actor": ""},
    ):
        with pytest.raises(ValidationError):
            svc.firmware_upgrade(**kwargs)
    assert len(nbi.requests) == before
    record = upload(svc)
    ghost = cudy(nbi, "000009")
    del nbi.devices[ghost]
    with pytest.raises(AcsNotFound):
        svc.firmware_upgrade(ghost, record["name"])


def test_a_file_removed_during_the_pre_flight_is_not_sent(nbi, svc, router, monkeypatch):
    record = upload(svc)
    check = svc._running_firmware
    calls = []

    def racing(acs_id, name):
        calls.append(name)
        if len(calls) == 2:
            # remove_firmware ran between the pre-flight and the job being created.
            svc.firmware.remove(name)
        return check(acs_id, name)

    monkeypatch.setattr(svc, "_running_firmware", racing)
    with pytest.raises(AcsNotFound):
        svc.firmware_upgrade(router, record["name"])
    assert download_tasks(nbi) == [] and svc.list_jobs() == []


def test_a_second_click_returns_the_first_job_and_another_file_waits(nbi, svc, router):
    record = upload(svc)
    first = svc.firmware_upgrade(router, record["name"])
    assert svc.firmware_upgrade(router, record["name"])["id"] == first["id"]
    other = upload(svc, version="2.5.27")
    with pytest.raises(AcsBusy, match=first["id"]):
        svc.firmware_upgrade(router, other["name"])
    assert len(download_tasks(nbi)) == 1


# --- job paths ------------------------------------------------------------------------------------


def test_verified_once_the_router_boots_into_the_new_version(nbi, svc, router, recorder):
    job = accepted(nbi, svc, router)
    # The Download being accepted proves nothing yet.
    assert "accepted the download" in job["message"] and not job["done"]
    assert recorder.entries == []
    report = nbi.run_session(router, cr=False)
    assert "1 BOOT" in report["events"] and nbi.software_version(router) == NEW
    job = poll(svc, job)
    assert job["state"] == VERIFIED and NEW in job["message"] and job["done"]
    assert job["result"]["running"] == NEW
    [entry] = recorder.entries
    assert entry["who"] == "alice" and entry["router"] == f"acs:{router}"
    assert entry["kind"] == "firmware" and entry["result"] == "applied"
    assert entry["details"]["version"] == NEW and entry["details"]["from_version"] == OLD
    poll(svc, job, times=2)
    assert len(recorder.entries) == 1


def test_verified_in_the_same_session_when_the_router_installs_at_once(nbi, svc, router):
    nbi.set_download(router, "same_session")
    job = svc.firmware_upgrade(router, upload(svc)["name"])
    nbi.run_session(router)
    assert poll(svc, job)["state"] == VERIFIED


def test_the_new_version_without_a_boot_after_the_task_is_not_proof(nbi, svc, router):
    nbi.set_download(router, "ignore")
    job = accepted(nbi, svc, router)
    doc = nbi.devices[router]
    doc["Device"]["DeviceInfo"]["SoftwareVersion"]["_value"] = NEW
    doc["_lastBoot"] = "2026-01-01T00:00:00.000Z"
    assert poll(svc, job)["state"] == WAITING_FOR_CHECKIN
    doc["_lastBoot"] = nbi.now().isoformat().replace("+00:00", "Z")
    assert poll(svc, job)["state"] == VERIFIED


def test_a_transfer_fault_in_a_later_session_rejects_it(nbi, svc, router, recorder):
    nbi.set_download(router, fault=("cwmp.9010", "Download failure"))
    job = accepted(nbi, svc, router)
    nbi.run_session(router, cr=False)
    job = poll(svc, job)
    assert job["state"] == REJECTED
    assert job["fault"]["code"] == "cwmp.9010" and "Download failure" in job["message"]
    # Cleared, so GenieACS does not offer the Download again.
    assert nbi.faults == {} and nbi.tasks == []
    [entry] = recorder.entries
    assert entry["result"] == "refused" and entry["details"]["fault_code"] == "cwmp.9010"


def test_a_refused_download_rpc_rejects_it_and_stops_the_retries(nbi, svc, router):
    nbi.inject_task_fault(router, "download", "cwmp.9000", "Method not supported")
    job = svc.firmware_upgrade(router, upload(svc)["name"])
    nbi.run_session(router)
    job = poll(svc, job)
    assert job["state"] == REJECTED and job["fault"]["code"] == "cwmp.9000"
    assert nbi.tasks == [] and nbi.faults == {}


def test_a_router_that_never_checks_in_expires(nbi, svc, router, recorder):
    nbi.set_cr_outcome(router, 504)
    job = svc.firmware_upgrade(router, upload(svc)["name"])
    assert job["state"] == WAITING_FOR_CHECKIN and "start at its next check-in" in job["message"]
    nbi.advance(86400 - 60)
    assert poll(svc, job)["state"] == WAITING_FOR_CHECKIN
    nbi.advance(60 + EXPIRY_GRACE.total_seconds())
    job = poll(svc, job)
    assert job["state"] == EXPIRED and nbi.tasks == []
    assert recorder.entries[0]["result"] == "failed"


def test_a_task_genieacs_dropped_as_expired_is_not_taken_for_accepted(nbi, svc, router):
    nbi.set_cr_outcome(router, 504)
    job = svc.firmware_upgrade(router, upload(svc)["name"])
    nbi.advance(86400 + 1)
    report = nbi.run_session(router, cr=False)
    assert [task["outcome"] for task in report["tasks"]] == ["expired"]
    job = poll(svc, job)
    assert job["state"] == EXPIRED and "expired" in job["message"]


def test_a_router_that_takes_the_download_and_never_comes_back_expires(nbi, svc, router):
    nbi.set_download(router, "ignore")
    job = accepted(nbi, svc, router)
    nbi.advance(FIRMWARE_INSTALL_WAIT.total_seconds() - 30)
    assert poll(svc, job)["state"] == WAITING_FOR_CHECKIN
    nbi.advance(31)
    job = poll(svc, job)
    assert job["state"] == EXPIRED and "has not checked in since" in job["message"]


def test_a_router_that_checks_in_without_installing_expires_saying_so(nbi, svc, router):
    nbi.set_download(router, "ignore")
    job = accepted(nbi, svc, router)
    nbi.advance(60)
    nbi.run_session(router, cr=False)
    nbi.advance(FIRMWARE_INSTALL_WAIT.total_seconds())
    job = poll(svc, job)
    assert job["state"] == EXPIRED and "has checked in since" in job["message"] and OLD in job["message"]


def test_a_boot_back_into_the_old_version_is_not_applied(nbi, svc, router):
    nbi.set_download(router, version=OLD)
    job = accepted(nbi, svc, router)
    nbi.run_session(router, cr=False)
    # One more look first: the transfer's fault may still be on its way.
    assert poll(svc, job)["state"] == WAITING_FOR_CHECKIN
    job = poll(svc, job)
    assert job["state"] == NOT_APPLIED and f"still runs firmware {OLD}" in job["message"]


def test_a_boot_into_another_version_is_not_applied_and_says_which(nbi, svc, router):
    nbi.set_download(router, version="2.5.26")
    job = accepted(nbi, svc, router)
    nbi.run_session(router, cr=False)
    job = poll(svc, job, times=2)
    assert job["state"] == NOT_APPLIED and "reports firmware 2.5.26, not" in job["message"]


def test_cancelling_before_the_router_takes_it_deletes_the_task(nbi, svc, router, recorder):
    nbi.set_cr_outcome(router, 504)
    job = svc.firmware_upgrade(router, upload(svc)["name"], actor="alice")
    job = svc.cancel_job(job["id"], actor="bob")
    assert job["state"] == CANCELLED and job["message"].startswith("Cancelled before")
    assert nbi.tasks == []
    [entry] = recorder.entries
    assert entry["who"] == "alice" and entry["result"] == "info" and entry["details"]["cancelled_by"] == "bob"


def test_cancelling_after_the_router_took_it_only_stops_watching(nbi, svc, router):
    job = accepted(nbi, svc, router)
    job = svc.cancel_job(job["id"])
    assert job["state"] == CANCELLED and "may still install it" in job["message"]


def test_a_failed_start_is_logged_as_failed(nbi, svc, router, recorder, monkeypatch):
    record = upload(svc)

    def refuse(device_id, task):
        raise AcsError("unexpected ACS reply to POST /devices/x/tasks: 500 Internal Server Error", status=500)

    monkeypatch.setattr(svc.client, "queue_task", refuse)
    job = svc.firmware_upgrade(router, record["name"])
    assert job["state"] == ERROR and "could not be queued" in job["message"]
    [entry] = recorder.entries
    assert entry["result"] == "failed" and entry["kind"] == "firmware"


# --- the activity log ------------------------------------------------------------------------------


def wifi_router(nbi: FakeNbi) -> str:
    leaves = {
        "Device.ManagementServer.ConnectionRequestURL": {"value": "http://10.10.0.40:7547/", "writable": False},
        "Device.ManagementServer.PeriodicInformInterval": 300,
        "Device.DeviceInfo.Manufacturer": {"value": "Acme", "writable": False},
        f"{WIFI}.Radio.1.OperatingFrequencyBand": "2.4GHz",
        f"{WIFI}.SSID.1.SSID": "Home",
        f"{WIFI}.SSID.1.LowerLayers": "Device.WiFi.Radio.1.",
        f"{WIFI}.AccessPoint.1.SSIDReference": "Device.WiFi.SSID.1.",
        f"{WIFI}.AccessPoint.1.Security.ModeEnabled": "WPA2-Personal",
        KEY1: "",
    }
    return nbi.add_device(build_device(serial="000077", leaves=leaves, last_inform=nbi.now()))


@pytest.fixture
def logged(nbi, tmp_path):
    log = ActivityLog(tmp_path / "activity")
    service = AcsService(AcsClient(nbi.url, timeout=5), SecretStore(tmp_path), tmp_path, clock=nbi.now, activity=log)
    return service, log


def test_the_real_activity_log_takes_firmware_and_wifi_outcomes_without_secrets(nbi, logged):
    service, log = logged
    router = cudy(nbi)
    job = accepted(nbi, service, router)
    nbi.run_session(router, cr=False)
    assert poll(service, job)["state"] == VERIFIED

    device = wifi_router(nbi)
    wifi = service.set_wifi(device, "2.4GHz", ssid="Office", passphrase=NEW_PASS, actor="carol")
    nbi.run_session(device)
    poll(service, wifi, times=2)

    entries = log.list(limit=10)
    by_kind = {entry["kind"]: entry for entry in entries}
    assert set(by_kind) == {"firmware", "wifi"} and len(entries) == 2
    assert by_kind["firmware"]["who"] == "alice" and by_kind["firmware"]["result"] == "applied"
    assert by_kind["wifi"]["who"] == "carol" and by_kind["wifi"]["result"] == "applied"
    assert by_kind["wifi"]["details"]["changed"] == ["ssid", "passphrase"]
    assert by_kind["wifi"]["details"]["ssid"] == "Office"
    assert NEW_PASS not in log.path.read_text()


def test_a_router_fault_that_quotes_the_new_password_stays_out_of_the_activity_log(nbi, logged):
    service, log = logged
    device = wifi_router(nbi)
    # A router that echoes the value it refused, in its FaultString and per parameter.
    nbi.inject_fault(device, KEY1, "cwmp.9007", f"Invalid value '{NEW_PASS}' for KeyPassphrase")
    wifi = service.set_wifi(device, "2.4GHz", passphrase=NEW_PASS, actor="carol")
    for _ in range(4):
        nbi.run_session(device)
        job = poll(service, wifi, times=2)
        if job["terminal"]:
            break
    assert job["state"] == REJECTED

    [entry] = log.list(kind="wifi")
    assert entry["result"] == "refused" and entry["who"] == "carol"
    assert "9007" in entry["what"] and KEY1 in entry["what"]
    assert "the router's own wording is left out" in entry["what"]
    assert entry["details"]["fault_code"] and "fault_message" not in entry["details"]
    assert NEW_PASS not in log.path.read_text()
    assert NEW_PASS not in log.export_csv()


def test_an_ssid_only_change_keeps_the_routers_fault_text(nbi, logged):
    service, log = logged
    device = wifi_router(nbi)
    nbi.inject_fault(device, f"{WIFI}.SSID.1.SSID", "cwmp.9007", "SSID too long for this radio")
    wifi = service.set_wifi(device, "2.4GHz", ssid="Office", actor="carol")
    for _ in range(4):
        nbi.run_session(device)
        job = poll(service, wifi, times=2)
        if job["terminal"]:
            break
    assert job["state"] == REJECTED
    [entry] = log.list(kind="wifi")
    assert "SSID too long for this radio" in entry["what"]
    assert entry["details"]["fault_message"]


def test_a_reboot_is_logged_once_and_a_refresh_not_at_all(nbi, svc, router, recorder):
    job = svc.reboot(router, actor="dave")
    nbi.run_session(router)
    assert poll(svc, job, times=2)["state"] == VERIFIED
    refresh = svc.refresh(router, "info")
    nbi.run_session(router)
    poll(svc, refresh)
    [entry] = recorder.entries
    assert entry["kind"] == "reboot" and entry["who"] == "dave" and entry["result"] == "applied"


def test_a_broken_activity_log_never_stops_a_job(nbi, tmp_path, router, caplog):
    class Broken:
        def record(self, **entry):
            raise RuntimeError("disk full")

    service = AcsService(
        AcsClient(nbi.url, timeout=5), SecretStore(tmp_path), tmp_path, clock=nbi.now, activity=Broken()
    )
    job = service.reboot(router)
    nbi.run_session(router)
    assert poll(service, job)["state"] == VERIFIED
    assert "activity log" in caplog.text


def test_actors_are_checked(nbi, svc, router):
    device = wifi_router(nbi)
    for bad in ("", "   ", None, 7):
        with pytest.raises(ValidationError, match="actor"):
            svc.reboot(router, actor=bad)
        with pytest.raises(ValidationError, match="actor"):
            svc.set_wifi(device, "2.4GHz", ssid="Office", actor=bad)
    assert svc.list_jobs() == []
    nbi.set_cr_outcome(router, 504)
    job = svc.reboot(router, actor="  erin\n")
    assert job["actor"] == "erin"
    with pytest.raises(ValidationError, match="actor"):
        svc.cancel_job(job["id"], actor="")
    assert svc.get_job(job["id"])["state"] == WAITING_FOR_CHECKIN


def test_the_dashboard_cannot_reboot_a_router_that_is_installing_firmware(nbi, svc, router):
    """Only maintenance plans held back mid-install; a manual reboot could interrupt the write."""
    upgrade = accepted(nbi, svc, router)
    with pytest.raises(AcsBusy, match=f"firmware upgrade is in progress on this router \\(job {upgrade['id']}\\)"):
        svc.reboot(router, actor="alice")
    assert not [task for task in nbi.tasks if task.get("device") == router and task.get("name") == "reboot"]


def test_a_reboot_is_allowed_again_once_the_upgrade_is_over(nbi, svc, router):
    upgrade = accepted(nbi, svc, router)
    svc.cancel_job(upgrade["id"])
    job = svc.reboot(router, actor="alice")
    assert job["kind"] == "reboot"
