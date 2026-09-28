import json
import logging
from datetime import UTC, datetime, timedelta, timezone

import pytest
from fake_nbi import FakeNbi, build_device, make_device_id

from cudy_manager.acs import tasks
from cudy_manager.acs.client import (
    AcsBusy,
    AcsClient,
    AcsError,
    AcsNotFound,
    AcsRejected,
    AcsUnavailable,
    CrResult,
    Page,
    device_search_query,
    is_supported_version,
    validate_device_id,
    validate_fault_id,
)
from cudy_manager.adapters import AdapterError
from cudy_manager.http_client import HttpError, HttpSession
from cudy_manager.models import ValidationError

WLAN = "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1"
SSID = f"{WLAN}.SSID"
PSK = f"{WLAN}.PreSharedKey.1.KeyPassphrase"
PASSPHRASE = "hunter22-Correct-Horse"


@pytest.fixture
def nbi():
    with FakeNbi() as fake:
        yield fake


@pytest.fixture
def client(nbi):
    return AcsClient(nbi.url, timeout=5)


@pytest.fixture
def device(nbi):
    return nbi.add_device(
        build_device(serial="SR552NA084-0003269", leaves={SSID: "Skybre", PSK: "", f"{WLAN}.Enable": True})
    )


def wifi_task(job="job1", step="B", passphrase=PASSPHRASE, unique_key="skyrouter-wifi"):
    return tasks.set_parameter_values(
        {SSID: "Skybre-5", PSK: passphrase}, job=job, step=step, unique_key=unique_key, expiry=tasks.WIFI_EXPIRY
    )


def calls(nbi, method=None, prefix=""):
    """Requests other than the version probe the client makes before its first write."""
    return [r for r in nbi.requests_for(method, prefix) if r.path != "/"]


class TestErrorTypes:
    @pytest.mark.parametrize("error", [AcsUnavailable, AcsNotFound, AcsBusy, AcsRejected])
    def test_every_error_is_an_adapter_error(self, error):
        # web.py already maps AdapterError to 502, so nothing new escapes as a 500.
        assert issubclass(error, AcsError)
        assert issubclass(error, AdapterError)


class TestBaseUrl:
    @pytest.mark.parametrize(
        "url",
        ["http://127.0.0.1:7557", "http://localhost:7557/", "http://[::1]:7557", "https://127.0.0.2:7557"],
    )
    def test_loopback_urls_are_accepted(self, url):
        assert AcsClient(url).base_url == url.rstrip("/")

    @pytest.mark.parametrize(
        "url",
        [
            "http://10.10.0.2:7557",
            "http://acs.example.com:7557",
            "http://[::ffff:10.0.0.1]:7557",
            "ftp://127.0.0.1:7557",
            "http://user:pw@127.0.0.1:7557",
            "http://127.0.0.1:7557/nbi",
            "http://127.0.0.1:7557/?x=1",
            "http://127.0.0.1:notaport",
            "http://:7557",
            "",
        ],
    )
    def test_other_urls_are_refused(self, url):
        with pytest.raises(ValidationError):
            AcsClient(url)

    def test_remote_host_needs_explicit_permission(self):
        assert AcsClient("http://10.10.0.2:7557", allow_remote=True).base_url == "http://10.10.0.2:7557"

    def test_credentials_are_refused_even_when_remote_is_allowed(self):
        with pytest.raises(ValidationError):
            AcsClient("http://admin:admin@10.10.0.2:7557", allow_remote=True)


class TestVersion:
    def test_version_comes_from_the_header_on_get_root(self, nbi, client):
        assert client.version() == "1.2.16+20260329"
        assert [(r.method, r.path) for r in nbi.requests] == [("GET", "/")]

    @pytest.mark.parametrize(
        ("version", "supported"),
        [
            ("1.2.16", True),
            ("1.2.16+20260329", True),
            ("1.2.10", True),
            ("1.2.17-beta.1", True),
            ("1.2.9", False),
            ("1.3.0-dev", False),
            ("1.3.0", False),
            ("2.0.0", False),
            ("1.2", False),
            ("", False),
        ],
    )
    def test_supported_versions(self, version, supported):
        assert is_supported_version(version) is supported

    def test_1_3_is_refused(self, nbi, client):
        nbi.version = "1.3.0-dev"
        with pytest.raises(AcsError, match="1.3.0-dev"):
            client.version()

    def test_no_write_reaches_an_unsupported_nbi(self, nbi, client, device):
        nbi.version = "1.3.0-dev"
        with pytest.raises(AcsError):
            client.add_tag(device, "skybre_new")
        with pytest.raises(AcsError):
            client.queue_task(device, wifi_task())
        assert calls(nbi) == []

    def test_an_upgrade_is_noticed_on_the_next_reply(self, nbi, client):
        client.version()
        nbi.version = "1.3.0"
        with pytest.raises(AcsError, match="not supported"):
            client.find("devices", {})

    def test_a_reply_without_the_header_is_not_from_genieacs(self, nbi, client):
        nbi.version = None
        with pytest.raises(AcsError, match="did not come from GenieACS"):
            client.version()

    def test_check_db_uses_head_presets(self, nbi, client):
        client.check_db()
        assert [(r.method, r.path) for r in nbi.requests] == [("HEAD", "/presets")]

    def test_check_db_retries_once_then_reports_unavailable(self, nbi, client):
        nbi.crash_next(2)
        with pytest.raises(AcsUnavailable):
            client.check_db()
        assert len(nbi.requests) == 2

    def test_refused_connection_is_unavailable(self):
        with FakeNbi() as fake:
            url = fake.url
        with pytest.raises(AcsUnavailable):
            AcsClient(url, timeout=2).version()


class TestEncoding:
    def test_device_id_percent_is_sent_as_percent_25(self, nbi, client, device):
        assert "%2D" in device
        client.add_tag(device, "skybre_new")
        (tag_request,) = calls(nbi, "POST")
        assert tag_request.path == f"/devices/{device.replace('%', '%25')}/tags/skybre_new"
        assert nbi.devices[device]["_tags"] == ["skybre_new"]

    def test_fake_decodes_once_so_a_raw_id_misses(self, nbi, device):
        # The failure the encoding rule exists for (F5): "%2D" arrives as "-".
        session = HttpSession(nbi.url)
        response = session.request("POST", f"/devices/{device}/tags/x", data=b"")
        assert (response.status, response.body) == (404, b"No such device")
        response = session.request("DELETE", f"/devices/{device}")
        assert response.status == 200
        assert device in nbi.devices

    def test_query_parameters_are_form_encoded(self, nbi, client, device):
        client.find("devices", device_search_query("NA084"), projection=["_id"])
        (request,) = nbi.requests
        target = request.target.split("?", 1)[1]
        assert '"' not in target and "{" not in target and ":" not in target
        assert json.loads(request.query["query"]) == device_search_query("NA084")

    def test_aware_datetimes_are_sent_as_utc(self, nbi, client, device):
        cutoff = datetime(2026, 9, 28, 11, 0, tzinfo=timezone(timedelta(hours=2)))
        client.find("devices", {"_lastInform": {"$lt": cutoff}})
        assert json.loads(nbi.requests[0].query["query"]) == {"_lastInform": {"$lt": "2026-09-28T09:00:00.000Z"}}

    @pytest.mark.parametrize("text", ["", "a b", "/x/", "a*b", "ü", "x" * 63, None])
    def test_search_text_is_restricted(self, text):
        with pytest.raises(ValidationError):
            device_search_query(text)

    def test_device_id_validation_matches_what_genieacs_generates(self):
        assert validate_device_id(make_device_id("00259E", "HG8245", "48575443A1B2C3D4"))
        assert validate_device_id(make_device_id("E8F724", "", "SR 552/NA"))
        assert validate_device_id(make_device_id("40ED00", "EC220-G5", "2226.07"))
        for bad in ["202BC1", "202BC1-BM632w-SR552-01-X", "202BC1-%2d", "202BC1-a%", "202BC1-a b", "a-" + "b" * 300]:
            with pytest.raises(ValidationError):
                validate_device_id(bad)

    def test_fault_id_validation(self, device):
        assert validate_fault_id(f"{device}:task_{'a' * 24}")
        assert validate_fault_id(f"{device}:skybre-inform")
        for bad in [f"{device}:task_xyz", f"{device}:", "nodevice:default", device]:
            with pytest.raises(ValidationError):
                validate_fault_id(bad)


class TestFind:
    @pytest.fixture
    def fleet(self, nbi):
        base = datetime(2026, 9, 28, 9, 0, tzinfo=UTC)
        return [
            nbi.add_device(build_device(serial=f"SN{n}", last_inform=base + timedelta(minutes=n), tags=tags))
            for n, tags in [(1, ["skybre_new"]), (2, []), (3, ["skybre_new"])]
        ]

    def test_paging_uses_the_total_header(self, client, fleet):
        first = client.find("devices", {}, projection=["_id"], sort={"_lastInform": 1}, limit=2)
        assert first == Page(items=[{"_id": fleet[0]}, {"_id": fleet[1]}], total=3)
        rest = client.find("devices", {}, projection=["_id"], sort={"_lastInform": 1}, skip=2, limit=2)
        assert rest == Page(items=[{"_id": fleet[2]}], total=3)

    def test_sort_descending(self, client, fleet):
        page = client.find("devices", {}, projection=["_id"], sort={"_lastInform": -1})
        assert [item["_id"] for item in page.items] == list(reversed(fleet))

    def test_tag_and_search_filters(self, client, fleet):
        tagged = client.find("devices", {"_tags": "skybre_new"}, projection=["_id"])
        assert [item["_id"] for item in tagged.items] == [fleet[0], fleet[2]]
        found = client.find("devices", device_search_query("N2"), projection=["_id"])
        assert found.items == [{"_id": fleet[1]}]

    def test_time_range(self, client, fleet):
        page = client.find("devices", {"_lastInform": {"$gt": "2026-09-28T09:01:30Z"}}, projection=["_id"])
        assert [item["_id"] for item in page.items] == fleet[1:]

    def test_projection_sends_an_ancestor_alone(self, nbi, client, fleet):
        client.find("devices", {}, projection=["_id", "InternetGatewayDevice.DeviceInfo._value", "_id"])
        client.find(
            "devices",
            {},
            projection=["InternetGatewayDevice.DeviceInfo", "InternetGatewayDevice.DeviceInfo.SoftwareVersion._value"],
        )
        assert [r.query["projection"] for r in nbi.requests] == [
            "_id,InternetGatewayDevice.DeviceInfo._value",
            "InternetGatewayDevice.DeviceInfo",
        ]

    def test_limit_is_always_sent(self, nbi, client, fleet):
        client.find("devices", {})
        assert nbi.requests[0].query["limit"] == "50"
        assert nbi.requests[0].query["skip"] == "0"

    @pytest.mark.parametrize(
        ("collection", "query", "options"),
        [
            pytest.param("users", {}, {}, id="users-collection"),
            pytest.param("config", {}, {}, id="config-collection"),
            pytest.param("cache", {}, {}, id="cache-collection"),
            pytest.param("devices", [], {}, id="query-not-object"),
            pytest.param("devices", {"$where": "1"}, {}, id="where"),
            pytest.param("devices", {"$nor": [{"_tags": "a"}]}, {}, id="nor"),
            pytest.param("devices", {"InternetGatewayDevice.DeviceInfo.SerialNumber": "x"}, {}, id="param-path"),
            pytest.param("devices", {"_id": {"$regex": "x"}}, {}, id="regex-operator"),
            pytest.param("devices", {"_id": {"$ne": "x"}}, {}, id="ne-operator"),
            pytest.param("devices", {"_tags": {"$ne": "x", "$in": ["y"]}}, {}, id="ne-mixed"),
            pytest.param("devices", {"_tags": {}}, {}, id="empty-condition"),
            pytest.param("devices", {"_id": "/.*/"}, {}, id="regex-shaped-string"),
            pytest.param("devices", {"_deviceId._SerialNumber": "a*b"}, {}, id="interior-wildcard"),
            pytest.param("devices", {"_deviceId._SerialNumber": 5}, {}, id="non-string-value"),
            pytest.param("devices", {"_tags": "Bad.Tag"}, {}, id="bad-tag"),
            pytest.param("devices", {"$or": {"_id": "x"}}, {}, id="or-not-list"),
            pytest.param("devices", {"$or": []}, {}, id="or-empty"),
            pytest.param("devices", {"$or": [{}]}, {}, id="or-empty-branch"),
            pytest.param("devices", {"$or": [{"$and": [{"_tags": "a"}]}]}, {}, id="nested-logical"),
            pytest.param("devices", {"_tags": {"$in": []}}, {}, id="in-empty"),
            pytest.param("devices", {"_tags": {"$in": "abc"}}, {}, id="in-string"),
            pytest.param("devices", {"_lastInform": {"$lt": "yesterday"}}, {}, id="bad-time"),
            pytest.param("devices", {"_lastInform": {"$lt": datetime(2026, 1, 1)}}, {}, id="naive-time"),
            pytest.param("tasks", {"_id": "not-hex"}, {}, id="task-id"),
            pytest.param("tasks", {"_id": {"$in": ["zz"]}}, {}, id="task-id-in"),
            pytest.param("tasks", {"name": "factoryReset"}, {}, id="task-name"),
            pytest.param("faults", {"_id": "dev:task_xyz"}, {}, id="fault-id"),
            pytest.param("devices", {}, {"limit": 0}, id="limit-zero"),
            pytest.param("devices", {}, {"limit": 201}, id="limit-high"),
            pytest.param("devices", {}, {"limit": "10"}, id="limit-string"),
            pytest.param("devices", {}, {"limit": True}, id="limit-bool"),
            pytest.param("devices", {}, {"skip": -1}, id="skip-negative"),
            pytest.param("devices", {}, {"skip": 1.5}, id="skip-float"),
            pytest.param("devices", {}, {"projection": []}, id="projection-empty"),
            pytest.param("devices", {}, {"projection": "_id"}, id="projection-string"),
            pytest.param("devices", {}, {"projection": ["a..b"]}, id="projection-path"),
            pytest.param("devices", {}, {"projection": ["_id", ""]}, id="projection-blank"),
            pytest.param("devices", {}, {"sort": {"_lastInform": 2}}, id="sort-direction"),
            pytest.param("devices", {}, {"sort": {"_lastInform": True}}, id="sort-bool"),
            pytest.param("devices", {}, {"sort": {"InternetGatewayDevice.X": 1}}, id="sort-field"),
            pytest.param("devices", {}, {"sort": {}}, id="sort-empty"),
            pytest.param("tasks", {}, {"projection": ["parameterValues"]}, id="task-values"),
            pytest.param("tasks", {}, {"projection": ["_id", "parameterValues.0"]}, id="task-values-nested"),
            pytest.param("faults", {}, {"projection": ["provisions"]}, id="fault-provisions"),
        ],
    )
    def test_invalid_input_never_reaches_the_nbi(self, nbi, client, collection, query, options):
        with pytest.raises(ValidationError):
            client.find(collection, query, **options)
        assert nbi.requests == []

    def test_get_is_retried_once_after_a_crash(self, nbi, client, fleet):
        nbi.crash_next(1)
        assert client.find("devices", {}, projection=["_id"]).total == 3
        assert [r.outcome for r in nbi.requests] == ["crashed", "answered"]

    def test_get_gives_up_after_the_retry(self, nbi, client, fleet):
        nbi.crash_next(2)
        with pytest.raises(AcsUnavailable):
            client.find("devices", {})
        assert len(nbi.requests) == 2

    def test_truncated_json_is_retried(self, nbi, client, fleet):
        nbi.truncate_next(1)
        assert len(client.find("devices", {}, projection=["_id"]).items) == 3
        assert [r.outcome for r in nbi.requests] == ["truncated", "answered"]

    def test_truncated_twice_is_unavailable(self, nbi, client, fleet):
        nbi.truncate_next(2)
        with pytest.raises(AcsUnavailable, match="cut short"):
            client.find("devices", {})

    def test_a_400_is_rejected_and_not_retried(self, nbi, client):
        nbi.reply_next(400, b"SyntaxError: Unexpected token")
        with pytest.raises(AcsRejected, match="SyntaxError"):
            client.find("devices", {})
        assert len(nbi.requests) == 1

    def test_get_device(self, nbi, client, device):
        doc = client.get_device(device, [SSID])
        assert doc["_id"] == device
        assert doc["InternetGatewayDevice"]["LANDevice"]["1"]["WLANConfiguration"]["1"]["SSID"]["_value"] == "Skybre"
        assert "_deviceId" not in doc
        assert client.get_device(make_device_id("202BC1", "BM632w", "other"), ["_id"]) is None

    def test_get_device_needs_a_valid_id_and_projection(self, nbi, client, device):
        with pytest.raises(ValidationError):
            client.get_device("202BC1-BM632w-SR552-01-X", ["_id"])
        with pytest.raises(ValidationError):
            client.get_device(device, None)
        with pytest.raises(ValidationError):
            client.get_device(device, [])
        assert nbi.requests == []


class TestQueueTask:
    def test_queued_task_comes_back_without_its_values(self, nbi, client, device):
        stored = client.queue_task(device, wifi_task())
        assert set(stored) >= {"_id", "timestamp", "expiry", "device"}
        assert stored["skyrouterJob"] == "job1"
        assert stored["skyrouterStep"] == "B"
        assert stored["uniqueKey"] == "skyrouter-wifi"
        assert "parameterValues" not in stored
        assert PASSPHRASE not in json.dumps(stored)

    def test_request_body_carries_expiry_unique_key_and_job(self, nbi, client, device):
        client.queue_task(device, wifi_task())
        (post,) = calls(nbi, "POST")
        body = json.loads(post.body)
        assert body == {
            "name": "setParameterValues",
            "parameterValues": [[SSID, "Skybre-5"], [PSK, PASSPHRASE]],
            "expiry": 21600,
            "uniqueKey": "skyrouter-wifi",
            "skyrouterJob": "job1",
            "skyrouterStep": "B",
        }
        assert post.headers["Content-Type"] == "application/json"

    def test_unique_key_replaces_the_earlier_task(self, nbi, client, device):
        client.queue_task(device, wifi_task(job="old"))
        client.queue_task(device, wifi_task(job="new"))
        assert [task["skyrouterJob"] for task in nbi.device_tasks(device)] == ["new"]

    def test_unknown_device(self, client):
        with pytest.raises(AcsNotFound, match="No such device"):
            client.queue_task(make_device_id("202BC1", "BM632w", "missing"), wifi_task())

    def test_only_validated_tasks_are_sent(self, nbi, client, device):
        with pytest.raises(ValidationError):
            client.queue_task(device, {"name": "reboot"})
        with pytest.raises(ValidationError):
            client.queue_task("not an id", tasks.reboot(job="j", step="s"))
        assert nbi.requests == []

    def test_post_is_never_retried_and_the_lookup_shows_it_was_not_queued(self, nbi, client, device):
        client.version()
        nbi.crash_next(1)
        with pytest.raises(AcsUnavailable, match="not queued") as caught:
            client.queue_task(device, wifi_task())
        assert caught.value.outcome_unknown is False
        assert len(calls(nbi, "POST")) == 1
        (lookup,) = calls(nbi, "GET", "/tasks")
        assert json.loads(lookup.query["query"]) == {"device": device, "skyrouterJob": "job1"}
        assert nbi.tasks == []

    def test_lost_reply_is_reconciled_through_the_job_fields(self, nbi, client, device):
        client.version()
        nbi.crash_next(1, after=True)
        stored = client.queue_task(device, wifi_task())
        assert len(calls(nbi, "POST")) == 1
        assert [task["_id"] for task in nbi.tasks] == [stored["_id"]]
        assert "parameterValues" not in stored

    def test_reconciliation_ignores_other_steps_of_the_same_job(self, nbi, client, device):
        client.queue_task(device, tasks.get_parameter_values([PSK], job="job1", step="A", unique_key="skyrouter-read"))
        nbi.crash_next(1)
        with pytest.raises(AcsUnavailable, match="not queued"):
            client.queue_task(device, wifi_task(step="B"))

    def test_outcome_unknown_when_the_lookup_fails_too(self, nbi, client, device):
        client.version()
        nbi.crash_next(3)
        with pytest.raises(AcsUnavailable, match="unknown") as caught:
            client.queue_task(device, wifi_task())
        assert caught.value.outcome_unknown is True
        assert len(calls(nbi, "POST")) == 1

    def test_truncated_accept_is_reconciled(self, nbi, client, device):
        client.version()
        nbi.reply_next(202, b'{"_id": "6aba', reason="Accepted")
        with pytest.raises(AcsUnavailable, match="not queued"):
            client.queue_task(device, wifi_task())
        assert len(calls(nbi, "POST")) == 1

    def test_202_with_another_reason_is_an_error(self, nbi, client, device):
        client.version()
        nbi.reply_next(202, b"{}", reason="Task queued but not processed")
        with pytest.raises(AcsError, match="Task queued but not processed"):
            client.queue_task(device, wifi_task())

    def test_rejection_never_repeats_the_passphrase(self, nbi, client, device, caplog):
        client.version()
        # Node's JSON.parse errors quote the input, so a 400 body can echo the request.
        nbi.reply_next(400, f'SyntaxError: Unexpected token in "{PASSPHRASE}"'.encode())
        with caplog.at_level(logging.DEBUG), pytest.raises(AcsRejected) as caught:
            client.queue_task(device, wifi_task())
        assert PASSPHRASE not in str(caught.value)
        assert PASSPHRASE not in caplog.text
        assert "rejected" in caplog.text


class TestConnectionRequest:
    def test_success(self, nbi, client, device):
        assert client.connection_request(device) == CrResult(ok=True, reason="")
        (post,) = calls(nbi, "POST")
        assert post.body == b""
        assert "connection_request" in post.query
        assert nbi.cr_requests == [device]

    @pytest.mark.parametrize(
        "reason",
        ["Device is offline", "Invalid connection request URL", "Connection request error: connect EHOSTUNREACH"],
    )
    def test_failure_reason_comes_from_the_reply(self, nbi, client, device, reason):
        nbi.set_cr_outcome(device, 504, reason)
        assert client.connection_request(device) == CrResult(ok=False, reason=reason)

    def test_unknown_device(self, client):
        with pytest.raises(AcsNotFound):
            client.connection_request(make_device_id("202BC1", "BM632w", "missing"))

    def test_gets_longer_than_the_default_timeout(self, monkeypatch, client, device):
        # The NBI waits on the router, twice with Digest, before it can answer.
        seen = []
        original = client._session.request

        def spy(method, path, **kwargs):
            seen.append((method, kwargs.get("timeout")))
            return original(method, path, **kwargs)

        monkeypatch.setattr(client._session, "request", spy)
        client.connection_request(device)
        client.find("devices", {})
        assert seen == [("GET", None), ("POST", 30.0), ("GET", None)]

    def test_never_retried(self, nbi, client, device):
        client.version()
        nbi.crash_next(1)
        with pytest.raises(AcsUnavailable):
            client.connection_request(device)
        assert len(calls(nbi, "POST")) == 1

    def test_a_scripted_session_runs_the_queued_task(self, nbi, client, device):
        client.queue_task(device, wifi_task())
        nbi.set_cr_outcome(device, 200, session=True)
        assert client.connection_request(device).ok
        assert client.tasks(device_id=device) == []
        assert nbi.cached(device, SSID)["_value"] == "Skybre-5"


class TestTasksAndFaults:
    def test_tasks_filters(self, nbi, client, device):
        first = client.queue_task(device, wifi_task(job="job1"))
        second = client.queue_task(device, tasks.reboot(job="job2", step="R"))
        assert [t["_id"] for t in client.tasks(job="job1")] == [first["_id"]]
        assert [t["_id"] for t in client.tasks(device_id=device)] == [first["_id"], second["_id"]]
        assert [t["_id"] for t in client.tasks(ids=[second["_id"]])] == [second["_id"]]

    def test_written_values_never_come_back(self, nbi, client, device):
        client.queue_task(device, wifi_task())
        assert PASSPHRASE in json.dumps(nbi.tasks)
        listed = client.tasks(device_id=device)
        assert listed and PASSPHRASE not in json.dumps(listed)
        assert "parameterValues" not in client.find("tasks", {"device": device}).items[0]

    def test_empty_id_list_needs_no_request(self, nbi, client):
        assert client.tasks(ids=[]) == []
        assert client.faults(ids=[]) == []
        assert client.faults(channels=[]) == []
        assert nbi.requests == []

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"ids": ["xyz"]},
            {"ids": "a" * 24},
            {"ids": ["A" * 24]},
            {"ids": ["a" * 24] * 201},
            {"device_id": "bad id"},
            {"job": "a b"},
        ],
    )
    def test_invalid_task_filters(self, nbi, client, kwargs):
        with pytest.raises(ValidationError):
            client.tasks(**kwargs)
        assert nbi.requests == []

    def test_lists_are_paged_to_the_end(self, nbi, client, device):
        for n in range(250):
            nbi.tasks.append({"_id": f"{n:024x}", "name": "reboot", "device": device, "timestamp": "x"})
        assert len(client.tasks(device_id=device)) == 250
        assert len(calls(nbi, "GET", "/tasks")) == 2

    def test_a_list_too_long_to_trust_is_an_error(self, nbi, client, device):
        for n in range(1001):
            nbi.tasks.append({"_id": f"{n:024x}", "name": "reboot", "device": device, "timestamp": "x"})
        with pytest.raises(AcsError, match="1001"):
            client.tasks(device_id=device)

    def test_faults_leave_out_the_provisions_copy(self, nbi, client, device):
        nbi.inject_fault(device, PSK, "cwmp.9007", "Invalid parameter value")
        stored = client.queue_task(device, wifi_task())
        nbi.run_session(device)
        fault_id = f"{device}:task_{stored['_id']}"
        assert PASSPHRASE in nbi.faults[fault_id]["provisions"]
        (fault,) = client.faults(device_id=device)
        assert fault["_id"] == fault_id
        assert fault["code"] == "cwmp.9007"
        assert fault["channel"] == f"task_{stored['_id']}"
        assert "provisions" not in fault
        assert PASSPHRASE not in json.dumps(fault)
        assert client.faults(ids=[fault_id]) == [fault]
        assert client.faults(channels=[f"task_{stored['_id']}"]) == [fault]
        assert client.faults(channels=["skybre-inform"]) == []

    @pytest.mark.parametrize(
        "kwargs", [{"ids": ["nodevice"]}, {"channels": ["task_zz"]}, {"channels": "default"}, {"device_id": "x"}]
    )
    def test_invalid_fault_filters(self, nbi, client, kwargs):
        with pytest.raises(ValidationError):
            client.faults(**kwargs)
        assert nbi.requests == []

    def test_delete_task(self, nbi, client, device):
        stored = client.queue_task(device, wifi_task())
        client.delete_task(stored["_id"])
        assert nbi.tasks == []
        with pytest.raises(AcsNotFound, match="Task not found"):
            client.delete_task(stored["_id"])

    def test_delete_task_while_in_session(self, nbi, client, device):
        stored = client.queue_task(device, wifi_task())
        nbi.set_busy(device, times=1)
        with pytest.raises(AcsBusy):
            client.delete_task(stored["_id"])
        client.delete_task(stored["_id"])
        assert nbi.tasks == []

    @pytest.mark.parametrize("task_id", ["xyz", "A" * 24, "a" * 23, "a" * 25, None])
    def test_non_hex_task_ids_never_reach_the_nbi(self, nbi, client, task_id):
        for call in (client.delete_task, client.retry_fault_task):
            with pytest.raises(ValidationError):
                call(task_id)
        assert nbi.requests == []

    def test_delete_fault_also_cancels_the_task(self, nbi, client, device):
        nbi.inject_fault(device, PSK)
        stored = client.queue_task(device, wifi_task())
        nbi.run_session(device)
        client.delete_fault(f"{device}:task_{stored['_id']}")
        assert nbi.faults == {} and nbi.tasks == []
        (delete,) = calls(nbi, "DELETE")
        assert delete.path == f"/faults/{device.replace('%', '%25')}%3Atask_{stored['_id']}"

    def test_delete_fault_while_in_session(self, nbi, client, device):
        nbi.set_busy(device)
        with pytest.raises(AcsBusy):
            client.delete_fault(f"{device}:skybre-inform")

    def test_retry_keeps_the_task_and_clears_the_fault(self, nbi, client, device):
        nbi.inject_fault(device, PSK)
        stored = client.queue_task(device, wifi_task())
        nbi.run_session(device)
        client.retry_fault_task(stored["_id"])
        assert nbi.faults == {}
        assert [task["_id"] for task in nbi.tasks] == [stored["_id"]]

    def test_retry_of_a_missing_task_is_refused_locally(self, nbi, client):
        # POST /tasks/<missing>/retry kills a 1.2.x worker (F13).
        with pytest.raises(AcsNotFound):
            client.retry_fault_task("a" * 24)
        assert calls(nbi, "POST") == []
        assert nbi.crashes == 0

    def test_retry_while_in_session(self, nbi, client, device):
        stored = client.queue_task(device, wifi_task())
        nbi.set_busy(device)
        with pytest.raises(AcsBusy):
            client.retry_fault_task(stored["_id"])


class TestTags:
    def test_add_and_remove(self, nbi, client, device):
        client.add_tag(device, "skybre_new")
        client.add_tag(device, "tower-07")
        client.remove_tag(device, "skybre_new")
        assert nbi.devices[device]["_tags"] == ["tower-07"]

    def test_unknown_device(self, client):
        with pytest.raises(AcsNotFound):
            client.add_tag(make_device_id("202BC1", "BM632w", "missing"), "x")

    @pytest.mark.parametrize("tag", ["Bad", "a.b", "a~b", "a b", "", "x" * 49, None])
    def test_invalid_tags_never_reach_the_nbi(self, nbi, client, device, tag):
        for call in (client.add_tag, client.remove_tag):
            with pytest.raises(ValidationError):
                call(device, tag)
        assert nbi.requests == []


class TestPresetsAndProvisions:
    PRESET = {
        "weight": 10,
        "channel": "skybre-inform",
        "events": {},
        "precondition": "",
        "configurations": [{"type": "provision", "name": "skybre-inform", "args": [300]}],
    }

    def test_preset_round_trip(self, nbi, client):
        client.put_preset("skybre-inform", self.PRESET)
        assert nbi.presets["skybre-inform"] == {**self.PRESET, "_id": "skybre-inform"}
        assert client.get_preset("skybre-inform") == self.PRESET
        assert nbi.cache_invalidations == 1
        client.delete_preset("skybre-inform")
        assert client.get_preset("skybre-inform") is None

    @pytest.mark.parametrize(
        "preset",
        [
            pytest.param(["not", "an", "object"], id="list"),
            pytest.param({"weight": 0}, id="no-configurations"),
            pytest.param({"configurations": []}, id="empty-configurations"),
            pytest.param({"configurations": [{"type": "script"}]}, id="unknown-type"),
            pytest.param({"configurations": ["provision"]}, id="entry-not-object"),
            pytest.param({"configurations": [{"type": "provision", "name": "x", "args": "300"}]}, id="args-string"),
            pytest.param({"weight": "10", "configurations": [{"type": "add_tag", "tag": "x"}]}, id="weight-string"),
            pytest.param({"events": {"1 BOOT": 1}, "configurations": [{"type": "add_tag"}]}, id="event-not-bool"),
            pytest.param({"_id": "x", "configurations": [{"type": "add_tag"}]}, id="own-id"),
            pytest.param({"weight": float("nan"), "configurations": [{"type": "add_tag"}]}, id="nan"),
        ],
    )
    def test_malformed_presets_never_reach_the_nbi(self, nbi, client, preset):
        with pytest.raises(ValidationError):
            client.put_preset("skybre-x", preset)
        assert nbi.requests == []

    def test_provision_round_trip(self, nbi, client):
        script = 'declare("InternetGatewayDevice.DeviceInfo.*", {value: Date.now(3600000)});\n'
        client.put_provision("skybre-refresh", script)
        (put,) = calls(nbi, "PUT")
        assert put.body == script.encode()
        assert client.get_provision("skybre-refresh") == script
        assert client.get_provision("skybre-missing") is None

    def test_provision_syntax_error_is_rejected_with_the_message(self, nbi, client):
        nbi.check_script = lambda script: "SyntaxError: Unexpected end of input"
        with pytest.raises(AcsRejected, match="Unexpected end of input"):
            client.put_provision("skybre-refresh", "declare(")

    @pytest.mark.parametrize("name", ["Bad", "a.b", "a~b", "", "x" * 49])
    def test_invalid_names_never_reach_the_nbi(self, nbi, client, name):
        with pytest.raises(ValidationError):
            client.put_provision(name, "log('x');")
        with pytest.raises(ValidationError):
            client.put_preset(name, self.PRESET)
        with pytest.raises(ValidationError):
            client.get_preset(name)
        with pytest.raises(ValidationError):
            client.delete_preset(name)
        assert nbi.requests == []

    def test_empty_script_is_refused(self, nbi, client):
        with pytest.raises(ValidationError):
            client.put_provision("skybre-x", "  ")
        assert nbi.requests == []


class TestTaskConstructors:
    def test_every_task_carries_expiry_unique_key_and_job_fields(self):
        built = [
            tasks.get_parameter_values([PSK, SSID], job="j", step="A", unique_key="skyrouter-read"),
            tasks.set_parameter_values([(SSID, "x")], job="j", step="B", unique_key="skyrouter-wifi"),
            tasks.refresh_object(WLAN, job="j", step="R", unique_key="skyrouter-refresh"),
            tasks.reboot(job="j", step="X"),
        ]
        for task in built:
            body = task.to_json()
            assert body["expiry"] == tasks.DEFAULT_EXPIRY
            assert body["uniqueKey"].startswith("skyrouter-")
            assert (body["skyrouterJob"], body["skyrouterStep"]) == ("j", task.step)
            tasks.validate_task(body)
        assert built[0].to_json()["parameterNames"] == [PSK, SSID]
        assert built[1].to_json()["parameterValues"] == [[SSID, "x"]]
        assert built[2].to_json()["objectName"] == WLAN
        assert built[3].to_json() == {
            "name": "reboot",
            "expiry": 3600,
            "uniqueKey": "skyrouter-reboot",
            "skyrouterJob": "j",
            "skyrouterStep": "X",
        }

    def test_values_stay_out_of_repr(self):
        task = wifi_task()
        assert PASSPHRASE not in repr(task)
        assert PASSPHRASE not in str(task)
        assert task.paths == (SSID, PSK)

    def test_vendor_paths_are_allowed(self):
        tasks.set_parameter_values(
            {"Device.PPP.Interface.1.X_ZTE-COM_ServiceList": "INTERNET", f"{WLAN}.X_TP_PreSharedKey": "abcdefgh"},
            job="j",
            step="B",
            unique_key="skyrouter-wifi",
        )

    @pytest.mark.parametrize(
        "build",
        [
            pytest.param(
                lambda: tasks.get_parameter_values([], job="j", step="s", unique_key="skyrouter-r"), id="none"
            ),
            pytest.param(
                lambda: tasks.get_parameter_values(PSK, job="j", step="s", unique_key="skyrouter-r"), id="str"
            ),
            pytest.param(lambda: tasks.get_parameter_values([f"{WLAN}."], job="j", step="s", unique_key="skyrouter-r")),
            pytest.param(lambda: tasks.get_parameter_values(["a..b"], job="j", step="s", unique_key="skyrouter-r")),
            pytest.param(lambda: tasks.get_parameter_values(["a b"], job="j", step="s", unique_key="skyrouter-r")),
            pytest.param(lambda: tasks.get_parameter_values([None], job="j", step="s", unique_key="skyrouter-r")),
            pytest.param(lambda: tasks.get_parameter_values(["Wlan.ü"], job="j", step="s", unique_key="skyrouter-r")),
            pytest.param(lambda: tasks.get_parameter_values(["a"] * 65, job="j", step="s", unique_key="skyrouter-r")),
            pytest.param(
                lambda: tasks.set_parameter_values({}, job="j", step="s", unique_key="skyrouter-w"), id="empty"
            ),
            pytest.param(lambda: tasks.refresh_object("", job="j", step="s", unique_key="skyrouter-r"), id="root"),
            pytest.param(lambda: tasks.refresh_object("Device.WiFi.", job="j", step="s", unique_key="skyrouter-r")),
            pytest.param(lambda: tasks.reboot(job="j", step="s", expiry=0), id="expiry-0"),
            pytest.param(lambda: tasks.reboot(job="j", step="s", expiry=59), id="expiry-59"),
            pytest.param(lambda: tasks.reboot(job="j", step="s", expiry=10**7), id="expiry-high"),
            pytest.param(lambda: tasks.reboot(job="j", step="s", expiry=True), id="expiry-bool"),
            pytest.param(lambda: tasks.reboot(job="j", step="s", expiry=60.0), id="expiry-float"),
            pytest.param(lambda: tasks.reboot(job="j", step="s", unique_key="wifi"), id="key-prefix"),
            pytest.param(lambda: tasks.reboot(job="j", step="s", unique_key="skyrouter-"), id="key-empty"),
            pytest.param(lambda: tasks.reboot(job="j", step="s", unique_key="skyrouter-UP"), id="key-case"),
            pytest.param(lambda: tasks.reboot(job="", step="s"), id="job-empty"),
            pytest.param(lambda: tasks.reboot(job="a b", step="s"), id="job-space"),
            pytest.param(lambda: tasks.reboot(job="j" * 65, step="s"), id="job-long"),
            pytest.param(lambda: tasks.reboot(job="j", step="s" * 33), id="step-long"),
            pytest.param(lambda: tasks.Task("factoryReset", "j", "s", "skyrouter-x"), id="factory-reset"),
            pytest.param(lambda: tasks.Task("download", "j", "s", "skyrouter-x"), id="download"),
            pytest.param(lambda: tasks.Task("reboot", "j", "s", "skyrouter-x", object_name="Device"), id="stray"),
            pytest.param(lambda: tasks.Task("reboot", "j", "s", "skyrouter-x", parameter_values="ab"), id="values-str"),
        ],
    )
    def test_invalid_tasks_cannot_be_built(self, build):
        with pytest.raises(ValidationError):
            build()

    @pytest.mark.parametrize(
        "value",
        [
            pytest.param(None, id="none"),
            pytest.param(1.5, id="float"),
            pytest.param(float("nan"), id="nan"),
            pytest.param(2**60, id="unsafe-int"),
            pytest.param("a\nb", id="newline"),
            pytest.param("a\x00b", id="nul"),
            pytest.param("\ud800", id="surrogate"),
            pytest.param("x" * 1025, id="too-long"),
            pytest.param(["list"], id="list"),
        ],
    )
    def test_invalid_write_values(self, value):
        with pytest.raises(ValidationError):
            tasks.set_parameter_values({PSK: value}, job="j", step="s", unique_key="skyrouter-wifi")

    def test_write_limits(self):
        many = [(f"Device.X.{n}", "v") for n in range(33)]
        with pytest.raises(ValidationError, match="32"):
            tasks.set_parameter_values(many, job="j", step="s", unique_key="skyrouter-wifi")
        with pytest.raises(ValidationError, match="more than once"):
            tasks.set_parameter_values([(SSID, "a"), (SSID, "b")], job="j", step="s", unique_key="skyrouter-wifi")
        tasks.set_parameter_values(many[:32], job="j", step="s", unique_key="skyrouter-wifi")
        tasks.set_parameter_values({SSID: True, PSK: 2**53 - 1}, job="j", step="s", unique_key="skyrouter-wifi")

    def test_validation_messages_never_include_the_value(self):
        with pytest.raises(ValidationError) as caught:
            tasks.set_parameter_values({PSK: PASSPHRASE + "\n"}, job="j", step="s", unique_key="skyrouter-wifi")
        assert PASSPHRASE not in str(caught.value)
        assert PSK in str(caught.value)

    @pytest.mark.parametrize(
        "task",
        [
            pytest.param("reboot", id="not-object"),
            pytest.param({"name": "provisions", "provisions": [["x"]]}, id="provisions"),
            pytest.param({"name": "addObject"}, id="add-object"),
            pytest.param(
                {"name": "reboot", "expiry": 60, "uniqueKey": "skyrouter-r", "skyrouterJob": "j"}, id="no-step"
            ),
        ]
        + [
            pytest.param(
                {
                    "name": "reboot",
                    "expiry": 60,
                    "uniqueKey": "skyrouter-r",
                    "skyrouterJob": "j",
                    "skyrouterStep": "s",
                    field: value,
                },
                id=field,
            )
            for field, value in [("_id", "a" * 24), ("device", "x"), ("timestamp", "2026-01-01T00:00:00Z")]
        ],
    )
    def test_raw_task_documents_are_checked(self, task):
        with pytest.raises(ValidationError):
            tasks.validate_task(task)

    def test_raw_write_may_carry_a_type(self):
        base = {"name": "setParameterValues", "expiry": 60, "uniqueKey": "skyrouter-w"}
        base |= {"skyrouterJob": "j", "skyrouterStep": "s"}
        tasks.validate_task({**base, "parameterValues": [[SSID, "x", "xsd:string"]]})
        with pytest.raises(ValidationError):
            tasks.validate_task({**base, "parameterValues": [[SSID, "x", 7]]})
        with pytest.raises(ValidationError):
            tasks.validate_task({**base, "parameterValues": [[SSID]]})


class TestFakeNbi:
    """The simulator's behaviour, which the job and web tests rely on matching GenieACS."""

    @pytest.fixture
    def gpv(self, client, device):
        def queue(*paths, step="A"):
            return client.queue_task(
                device,
                tasks.get_parameter_values(list(paths), job="j", step=step, unique_key=f"skyrouter-{step.lower()}"),
            )

        return queue

    def test_read_blanks_a_secret_leaf(self, nbi, client, device, gpv):
        nbi.cpes[device].leaves[PSK].value = "old-secret"
        gpv(PSK, SSID)
        nbi.run_session(device)
        assert nbi.cached(device, PSK)["_value"] == ""
        assert nbi.cached(device, SSID)["_value"] == "Skybre"

    @pytest.mark.parametrize(("readback", "expected"), [("plaintext", "old-secret"), ("masked", "********")])
    def test_non_conforming_readback(self, nbi, client, readback, expected):
        device = nbi.add_device(build_device(leaves={PSK: ""}), readback=readback, cpe_leaves={PSK: "old-secret"})
        client.queue_task(device, tasks.get_parameter_values([PSK], job="j", step="A", unique_key="skyrouter-a"))
        nbi.run_session(device)
        assert nbi.cached(device, PSK)["_value"] == expected

    def test_write_is_stamped_after_the_session_and_cached_in_plaintext(self, nbi, client, device):
        stored = client.queue_task(device, wifi_task())
        report = nbi.run_session(device)
        assert report["tasks"] == [{"_id": stored["_id"], "name": "setParameterValues", "outcome": "done"}]
        assert report["written"] == [SSID, PSK]
        leaf = nbi.cached(device, PSK)
        assert leaf["_value"] == PASSPHRASE
        assert leaf["_timestamp"] > report["timestamp"] >= stored["timestamp"]
        assert nbi.cpes[device].leaves[PSK].value == PASSPHRASE
        assert nbi.devices[device]["_lastInform"] == report["timestamp"]

    def test_unchanged_cached_value_is_not_sent(self, nbi, client, device):
        client.queue_task(device, wifi_task())
        nbi.run_session(device)
        # The router now holds something else, but GenieACS still caches our value.
        nbi.cpes[device].leaves[PSK].value = "changed-on-router"
        client.queue_task(device, wifi_task(job="again"))
        assert nbi.run_session(device)["written"] == []
        assert nbi.cpes[device].leaves[PSK].value == "changed-on-router"

    def test_leaf_not_writable_in_the_cache_is_skipped(self, nbi, client):
        device = nbi.add_device(build_device(leaves={SSID: {"value": "a", "writable": False}}))
        client.queue_task(device, tasks.set_parameter_values({SSID: "b"}, job="j", step="B", unique_key="skyrouter-w"))
        report = nbi.run_session(device)
        assert report["written"] == [] and report["tasks"][0]["outcome"] == "done"

    def test_leaf_missing_from_the_cache_is_skipped(self, nbi, client, device):
        missing = f"{WLAN}.KeyPassphrase"
        client.queue_task(
            device, tasks.set_parameter_values({missing: "x"}, job="j", step="B", unique_key="skyrouter-w")
        )
        report = nbi.run_session(device)
        assert report["written"] == [] and nbi.tasks == [] and nbi.faults == {}

    def test_leaf_gone_from_the_router_is_forgotten_without_a_fault(self, nbi, client):
        device = nbi.add_device(build_device(leaves={SSID: "a", PSK: ""}), cpe_leaves={PSK: None})
        client.queue_task(device, wifi_task())
        report = nbi.run_session(device)
        assert report["written"] == [SSID]
        assert nbi.cached(device, PSK) is None
        assert nbi.tasks == [] and nbi.faults == {}

    def test_injected_fault_keeps_the_task_and_retries_after_the_delay(self, nbi, client, device):
        nbi.inject_fault(device, PSK, "cwmp.9007")
        stored = client.queue_task(device, wifi_task())
        assert nbi.run_session(device)["tasks"][0]["outcome"] == "faulted"
        fault = nbi.faults[f"{device}:task_{stored['_id']}"]
        assert fault["retries"] == 0
        assert fault["detail"]["setParameterValuesFault"][0]["parameterName"] == PSK
        assert nbi.cpes[device].leaves[SSID].value == "Skybre"
        assert nbi.run_session(device)["tasks"][0]["outcome"] == "waiting_retry"
        nbi.advance(301)
        assert nbi.run_session(device)["tasks"][0]["outcome"] == "faulted"
        assert fault["retries"] == 0 and nbi.faults[f"{device}:task_{stored['_id']}"]["retries"] == 1
        del nbi.cpes[device].leaf_faults[PSK]
        client.retry_fault_task(stored["_id"])
        assert nbi.run_session(device)["tasks"][0]["outcome"] == "done"
        assert nbi.tasks == [] and nbi.faults == {}

    def test_reboot_moves_last_boot(self, nbi, client, device):
        stored = client.queue_task(device, tasks.reboot(job="j", step="R"))
        nbi.run_session(device)
        assert nbi.devices[device]["_lastBoot"] > stored["timestamp"]
        assert nbi.cpes[device].reboots == 1

    def test_unsupported_reboot_faults(self, nbi, client, device):
        nbi.inject_task_fault(device, "reboot", "cwmp.9000", "Method not supported")
        client.queue_task(device, tasks.reboot(job="j", step="R"))
        nbi.run_session(device)
        (fault,) = nbi.faults.values()
        assert fault["code"] == "cwmp.9000"

    def test_expired_task_is_dropped(self, nbi, client, device):
        client.queue_task(device, tasks.reboot(job="j", step="R", expiry=60))
        nbi.advance(61)
        assert nbi.run_session(device, cr=False)["tasks"][0]["outcome"] == "expired"
        assert nbi.tasks == []
        assert nbi.cpes[device].reboots == 0

    def test_refresh_discovers_router_only_leaves(self, nbi, client):
        device = nbi.add_device(build_device(leaves={SSID: "a"}), cpe_leaves={PSK: {"value": "s", "writable": True}})
        client.queue_task(device, tasks.refresh_object(WLAN, job="j", step="R", unique_key="skyrouter-r"))
        nbi.run_session(device)
        assert nbi.cached(device, PSK) | {"_timestamp": None} == {
            "_object": False,
            "_value": "",
            "_type": "xsd:string",
            "_writable": True,
            "_timestamp": None,
        }

    @pytest.mark.parametrize(
        ("method", "path", "body"),
        [
            pytest.param(
                "POST", "/devices/{id}/tasks", b'{"name":"setParameterValues","parameterValues":[["x",null]]}'
            ),
            pytest.param("POST", "/devices/{id}/tasks", b'{"name":"upload"}', id="unknown-task"),
            pytest.param("DELETE", "/tasks/xyz", None, id="non-hex-delete"),
            pytest.param("POST", "/tasks/" + "a" * 24 + "/retry", b"", id="retry-missing"),
            pytest.param("GET", "/devices?limit=abc", None, id="nan-limit"),
            pytest.param("GET", "/devices?projection=", None, id="empty-projection"),
            pytest.param("GET", "/tasks?query=%7B%22_id%22%3A%22x%22%7D", None, id="non-hex-query"),
            pytest.param("PUT", "/presets/x", b'"not an object"', id="preset-not-object"),
        ],
    )
    def test_input_genieacs_throws_on_gets_no_reply(self, nbi, device, method, path, body):
        session = HttpSession(nbi.url, timeout=5)
        with pytest.raises(HttpError):
            session.request(method, path.replace("{id}", device.replace("%", "%25")), data=body)
        assert nbi.crashes == 1
        assert nbi.tasks == []
