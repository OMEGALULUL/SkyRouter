import hashlib
import json
from types import SimpleNamespace
from urllib.parse import parse_qs

import pytest

from cudy_manager import adapters
from cudy_manager.adapters import (
    AdapterError,
    AuthenticationRejected,
    CudyAdapter,
    ProtocolMismatch,
    TendaAdapter,
    UnsupportedOperation,
)
from cudy_manager.http_client import HttpError, HttpResponse
from cudy_manager.models import Device


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []
        self.cookie_jar = []

    def request(self, method, path, data=None, headers=None, follow_redirects=False):
        self.requests.append({"method": method, "path": path, "data": data, "headers": headers or {}})
        if path == "/cgi-bin/luci/admin/get_token":
            # These scripts model firmware without the per-login token step; the
            # AP1300 flow that has it is covered against fake_router's "ap1300" mode.
            return response("not found", status=404)
        if not self.responses:
            raise AssertionError(f"unexpected request: {method} {path}")
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def response(body: str, status: int = 200, content_type: str = "text/html") -> HttpResponse:
    return HttpResponse(
        status=status,
        headers={"Content-Type": content_type},
        body=body.encode(),
        url="http://192.168.1.1/",
    )


def form_response(fields, status=200):
    inputs = "".join(f'<input type="hidden" name="{k}" value="{v}">' for k, v in fields.items())
    return response(f"<html><head><title>LuCI</title></head><body><form>{inputs}</form></body></html>", status)


def json_response(payload, status=200):
    return response(json.dumps(payload), status, "application/json")


def cudy_device(**overrides) -> Device:
    data = {"vendor": "cudy", "host": "192.168.1.1", "username": "root"}
    data.update(overrides)
    return Device.from_dict("cudy-1", data)


def tenda_device(**overrides) -> Device:
    data = {"vendor": "tenda", "host": "192.168.1.2", "username": "admin"}
    data.update(overrides)
    return Device.from_dict("tenda-1", data)


class TestCudyPasswordDerivation:
    def test_matches_luci_reference_algorithm(self):
        first = hashlib.sha256(("hunter2" + "NaCl").encode()).hexdigest()
        assert adapters.derive_cudy_password("hunter2", "NaCl", "") == first

    def test_token_is_applied_to_hash_digest(self):
        password, salt, token = "hunter2", "NaCl", "abc"
        first = hashlib.sha256((password + salt).encode()).hexdigest()
        derived = adapters.derive_cudy_password(password, salt, token)
        assert derived == hashlib.sha256((first + token).encode()).hexdigest()

    def test_hash_is_not_the_plaintext(self):
        assert "hunter2" not in adapters.derive_cudy_password("hunter2", "s", "")


class TestCudyAdapter:
    def test_login_posts_salted_hash(self, monkeypatch):
        session = FakeSession(
            [
                form_response({"_csrf": "csrf-value", "token": "token-value", "salt": "salty"}),
                response("", status=302),
            ]
        )
        monkeypatch.setattr(adapters, "HttpSession", lambda *a, **k: session)
        adapter = CudyAdapter(cudy_device(), "hunter2")
        assert adapter.login() is True
        posted = session.requests[-1]
        assert posted["method"] == "POST"
        assert posted["path"] == "/cgi-bin/luci/"
        form = {key: values[0] for key, values in parse_qs(posted["data"].decode()).items()}
        expected = hashlib.sha256(
            (hashlib.sha256(("hunter2" + "salty").encode()).hexdigest() + "token-value").encode()
        ).hexdigest()
        assert form["luci_password"] == expected
        assert form["luci_username"] == "root"
        assert "hunter2" not in posted["data"].decode()

    def test_login_requires_salt_unless_legacy_allowed(self, monkeypatch):
        session = FakeSession([form_response({"_csrf": "c"})])
        monkeypatch.setattr(adapters, "HttpSession", lambda *a, **k: session)
        with pytest.raises(UnsupportedOperation):
            CudyAdapter(cudy_device(), "hunter2").login()

    def test_legacy_login_allows_missing_salt(self, monkeypatch):
        session = FakeSession([form_response({"_csrf": "c"}), response("ok", status=200)])
        monkeypatch.setattr(adapters, "HttpSession", lambda *a, **k: session)
        assert CudyAdapter(cudy_device(allow_legacy_login=True), "hunter2").login() is True

    def test_failed_login_raises(self, monkeypatch):
        session = FakeSession(
            [form_response({"_csrf": "c", "salt": "s"}), response("wrong password", status=403)]
        )
        monkeypatch.setattr(adapters, "HttpSession", lambda *a, **k: session)
        with pytest.raises(AdapterError):
            CudyAdapter(cudy_device(), "hunter2").login()

    def test_status_reports_online_and_source(self, monkeypatch):
        session = FakeSession(
            [
                form_response({"_csrf": "c", "salt": "s", "token": "t"}),
                response("", status=302),
                response("<html><body>firmware 1.2.3</body></html>"),
            ]
        )
        monkeypatch.setattr(adapters, "HttpSession", lambda *a, **k: session)
        status = CudyAdapter(cudy_device(), "p").status()
        assert status["online"] is True
        assert status["source"] == "cudy-luci"

    def test_http_failure_becomes_adapter_error(self, monkeypatch):
        session = FakeSession([HttpError("connection refused")])
        monkeypatch.setattr(adapters, "HttpSession", lambda *a, **k: session)
        with pytest.raises(AdapterError):
            CudyAdapter(cudy_device(), "p").login()


class TestCudyForbiddenLogin:
    """Stock LuCI answers a failed login with 403, the login form and X-LuCI-Login-Required."""

    def test_a_403_that_returns_the_login_form_is_a_rejection(self, monkeypatch):
        session = FakeSession(
            [
                form_response({"_csrf": "c", "salt": "s"}),
                response('<form><input name="luci_username"><input name="password"></form>', status=403),
            ]
        )
        monkeypatch.setattr(adapters, "HttpSession", lambda *a, **k: session)
        with pytest.raises(AuthenticationRejected):
            CudyAdapter(cudy_device(), "hunter2").login()

    def test_the_login_required_header_is_a_rejection(self, monkeypatch):
        refused = HttpResponse(
            status=403, headers={"X-Luci-Login-Required": "yes"}, body=b"<html></html>", url="http://192.168.1.1/"
        )
        session = FakeSession([form_response({"_csrf": "c", "salt": "s"}), refused])
        monkeypatch.setattr(adapters, "HttpSession", lambda *a, **k: session)
        with pytest.raises(AuthenticationRejected):
            CudyAdapter(cudy_device(), "hunter2").login()

    @pytest.mark.parametrize("status", [403, 404, 500])
    def test_other_error_pages_are_not_called_a_rejection(self, monkeypatch, status):
        session = FakeSession([form_response({"_csrf": "c", "salt": "s"}), response("<html>nope</html>", status)])
        monkeypatch.setattr(adapters, "HttpSession", lambda *a, **k: session)
        with pytest.raises(AdapterError) as caught:
            CudyAdapter(cudy_device(), "hunter2").login()
        assert not isinstance(caught.value, AuthenticationRejected)

    def test_verify_reports_a_403_rejection_as_rejected(self, tmp_path):
        from fake_router import FakeRouter
        from test_manager import build_manager

        with FakeRouter("forbidden_on_failure") as router:
            manager = build_manager(tmp_path)
            manager.add_device("c1", "127.0.0.1", "cudy", password="wrong", http_port=router.port)
            result = manager.verify_credentials("c1")
        assert result["ok"] is False
        assert result["reason"] == "rejected"


class TestCudyLoginMatchesRealFirmware:
    """Behaviour read from a real Cudy AP1300's login page and its sysauth.js.

    The adapter was written from community notes and failed against the hardware
    three ways: it gave up on the 403 the login page is served with, hashed with the
    page's stale token instead of the one sysauth.js fetches, and sent the device
    record's "root" where the form fixes the username to "admin".
    """

    def test_logs_in_like_the_routers_own_script(self):
        from fake_router import FakeRouter

        with FakeRouter("ap1300") as router:
            adapter = CudyAdapter(Device.from_dict("c1", {"vendor": "cudy", "host": "127.0.0.1",
                                                           "http_port": router.port, "username": "root"}), "goodpass")
            assert adapter.login() is True
            assert router.state["tokens_issued"] == 1
            assert router.state["login_posts"] == 1

    def test_a_wrong_password_on_the_real_flow_is_a_rejection(self):
        from fake_router import FakeRouter

        with FakeRouter("ap1300") as router:
            device = Device.from_dict("c1", {"vendor": "cudy", "host": "127.0.0.1", "http_port": router.port})
            with pytest.raises(AuthenticationRejected):
                CudyAdapter(device, "wrong").login()
            # One retry with a fresh token, because a stolen token looks identical.
            assert router.state["login_posts"] == 2

    def test_a_factory_fresh_router_is_never_submitted_to(self):
        """Its page is a create-password form: submitting it would set the admin password."""
        from fake_router import FakeRouter

        with FakeRouter("first_boot") as router:
            device = Device.from_dict("c1", {"vendor": "cudy", "host": "127.0.0.1", "http_port": router.port})
            with pytest.raises(UnsupportedOperation, match="no admin password yet"):
                CudyAdapter(device, "goodpass").login()
            assert router.state["login_posts"] == 0

    def test_the_login_page_is_read_the_way_sysauth_js_reads_it(self):
        from fake_router import AP1300_LOGIN_PAGE, FIRST_BOOT_PAGE

        page = adapters.parse_cudy_login_page(AP1300_LOGIN_PAGE.decode())
        assert (page.username, page.salt, page.is_login, page.first_boot) == ("admin", "apsalt", True, False)
        assert adapters.parse_cudy_login_page(FIRST_BOOT_PAGE.decode()).first_boot is True
        form = adapters.cudy_login_form(page, "pw", "root", "tok")
        assert form["luci_username"] == "admin"
        assert form["luci_language"] == "auto"


class TestTendaAdapter:
    def test_login_uses_base64_password(self, monkeypatch):
        session = FakeSession([json_response({"sysLogin": {"Login": True}})])
        monkeypatch.setattr(adapters, "HttpSession", lambda *a, **k: session)
        adapter = TendaAdapter(tenda_device(), "admin")
        assert adapter.login() is True
        payload = json.loads(session.requests[-1]["data"].decode())
        assert payload["sysLogin"]["password"] == "YWRtaW4="
        assert payload["sysLogin"]["logoff"] is False
        assert session.requests[-1]["path"] == "/goform/modules?login"

    def test_login_failure_raises(self, monkeypatch):
        session = FakeSession([json_response({"sysLogin": {"Login": False}})])
        monkeypatch.setattr(adapters, "HttpSession", lambda *a, **k: session)
        with pytest.raises(AdapterError):
            TendaAdapter(tenda_device(), "admin").login()

    def test_numeric_zero_errcode_is_accepted(self, monkeypatch):
        session = FakeSession([json_response({"sysReboot": {}, "errCode": 0})])
        monkeypatch.setattr(adapters, "HttpSession", lambda *a, **k: session)
        adapter = TendaAdapter(tenda_device(), "admin")
        adapter.cookie = "b=1"
        assert adapter.request({"sysReboot": {}})["errCode"] == 0

    def test_module_error_raises(self, monkeypatch):
        session = FakeSession([json_response({"errCode": "noauth"})])
        monkeypatch.setattr(adapters, "HttpSession", lambda *a, **k: session)
        adapter = TendaAdapter(tenda_device(), "admin")
        adapter.cookie = "b=1"
        with pytest.raises(AdapterError):
            adapter.request({"sysReboot": {}}, retry=False)

    def test_status_normalizes_uptime(self, monkeypatch):
        session = FakeSession(
            [
                json_response(
                    {
                        "sysStatus": {"deviceName": "AP", "softwareVersion": "3.0", "runningTime": "2 03:04:05"},
                        "lanStatus": {"lanIp": "192.168.1.2"},
                        "wifiClientNum": {"clientNum": "7"},
                    }
                )
            ]
        )
        monkeypatch.setattr(adapters, "HttpSession", lambda *a, **k: session)
        adapter = TendaAdapter(tenda_device(), "admin")
        adapter.cookie = "b=1"
        status = adapter.status()
        assert status["online"] is True
        assert status["uptime_seconds"] == 2 * 86400 + 3 * 3600 + 4 * 60 + 5
        assert status["clients"] == "7"

    def test_set_ssid_validates_radio(self, monkeypatch):
        monkeypatch.setattr(adapters, "HttpSession", lambda *a, **k: FakeSession([]))
        adapter = TendaAdapter(tenda_device(), "admin")
        with pytest.raises(AdapterError):
            adapter.set_ssid("ssid", radio="6G")

    def test_set_ssid_posts_wifi_payload(self, monkeypatch):
        session = FakeSession([json_response({})])
        monkeypatch.setattr(adapters, "HttpSession", lambda *a, **k: session)
        adapter = TendaAdapter(tenda_device(), "admin")
        adapter.cookie = "b=1"
        assert adapter.set_ssid("Skybre", radio="5G") is True
        payload = json.loads(session.requests[-1]["data"].decode())
        assert payload["wifiBasicSetIndoor"]["ssid"] == "Skybre"
        assert payload["wifiBasicSetIndoor"]["radio"] == "5G"

    def test_clients_tolerate_one_missing_radio_module(self, monkeypatch):
        session = FakeSession(
            [json_response({"errCode": "1"}), json_response({"wifiClientList": [{"mac": "AA:BB:CC:DD:EE:01"}]})]
        )
        monkeypatch.setattr(adapters, "HttpSession", lambda *a, **k: session)
        adapter = TendaAdapter(tenda_device(), "admin")
        adapter.cookie = "b=1"
        assert adapter.clients() == [{"radio": "5G", "mac": "AA:BB:CC:DD:EE:01"}]


class TestTendaClientFailures:
    """A router that cannot be asked must not read as a router with nobody on it."""

    def test_a_rejected_password_is_raised_after_one_attempt(self, monkeypatch):
        rejected = json_response({"sysLogin": {"Login": False}})
        session = FakeSession([rejected, rejected])
        monkeypatch.setattr(adapters, "HttpSession", lambda *a, **k: session)
        with pytest.raises(AuthenticationRejected):
            TendaAdapter(tenda_device(), "wrong").clients()
        assert len(session.requests) == 1

    def test_an_unreachable_router_is_raised_after_one_attempt(self, monkeypatch):
        session = FakeSession([HttpError("timed out"), HttpError("timed out")])
        monkeypatch.setattr(adapters, "HttpSession", lambda *a, **k: session)
        adapter = TendaAdapter(tenda_device(), "admin")
        adapter.cookie = "b=1"
        with pytest.raises(AdapterError, match="timed out"):
            adapter.clients()
        assert len(session.requests) == 1

    def test_a_session_dropped_again_after_relogin_is_not_a_missing_radio(self, monkeypatch):
        session = FakeSession(
            [
                json_response({"errCode": "logout"}),
                json_response({"sysLogin": {"Login": True}}),
                json_response({"errCode": "logout"}),
            ]
        )
        session.cookie_jar = [SimpleNamespace(name="password", value="fresh")]
        monkeypatch.setattr(adapters, "HttpSession", lambda *a, **k: session)
        adapter = TendaAdapter(tenda_device(), "admin")
        adapter.cookie = "b=1"
        with pytest.raises(AdapterError, match="session"):
            adapter.clients()
        assert len(session.requests) == 3

    def test_every_radio_refusing_the_module_is_an_error(self, monkeypatch):
        session = FakeSession([json_response({"errCode": "1"}), json_response({"errCode": "1"})])
        monkeypatch.setattr(adapters, "HttpSession", lambda *a, **k: session)
        adapter = TendaAdapter(tenda_device(), "admin")
        adapter.cookie = "b=1"
        with pytest.raises(AdapterError, match="module error"):
            adapter.clients()

    def test_an_idle_router_still_reports_no_clients(self, monkeypatch):
        session = FakeSession([json_response({"wifiClientList": []}), json_response({"wifiClientList": []})])
        monkeypatch.setattr(adapters, "HttpSession", lambda *a, **k: session)
        adapter = TendaAdapter(tenda_device(), "admin")
        adapter.cookie = "b=1"
        assert adapter.clients() == []


class TestTendaUnexpectedReplies:
    @pytest.mark.parametrize("body", ["[]", '"ok"', "null", "3"])
    def test_a_login_reply_that_is_not_an_object_is_a_protocol_mismatch(self, monkeypatch, body):
        session = FakeSession([response(body, content_type="application/json")])
        monkeypatch.setattr(adapters, "HttpSession", lambda *a, **k: session)
        with pytest.raises(ProtocolMismatch):
            TendaAdapter(tenda_device(), "admin").login()

    def test_a_null_login_module_is_a_rejection_not_a_crash(self, monkeypatch):
        session = FakeSession([json_response({"sysLogin": None})])
        monkeypatch.setattr(adapters, "HttpSession", lambda *a, **k: session)
        with pytest.raises(AuthenticationRejected):
            TendaAdapter(tenda_device(), "admin").login()

    @pytest.mark.parametrize("body", ["[]", '"ok"', "null"])
    def test_a_module_reply_that_is_not_an_object_is_a_protocol_mismatch(self, monkeypatch, body):
        session = FakeSession([response(body, content_type="application/json")])
        monkeypatch.setattr(adapters, "HttpSession", lambda *a, **k: session)
        adapter = TendaAdapter(tenda_device(), "admin")
        adapter.cookie = "b=1"
        with pytest.raises(ProtocolMismatch):
            adapter.status()

    def test_status_modules_of_the_wrong_type_are_a_protocol_mismatch(self, monkeypatch):
        session = FakeSession([json_response({"sysStatus": [], "lanStatus": "x", "wifiClientNum": None})])
        monkeypatch.setattr(adapters, "HttpSession", lambda *a, **k: session)
        adapter = TendaAdapter(tenda_device(), "admin")
        adapter.cookie = "b=1"
        with pytest.raises(ProtocolMismatch):
            adapter.status()

    def test_side_modules_of_the_wrong_type_are_ignored(self, monkeypatch):
        session = FakeSession(
            [json_response({"sysStatus": {"deviceName": "AP"}, "lanStatus": "x", "wifiClientNum": []})]
        )
        monkeypatch.setattr(adapters, "HttpSession", lambda *a, **k: session)
        adapter = TendaAdapter(tenda_device(), "admin")
        adapter.cookie = "b=1"
        status = adapter.status()
        assert status["hostname"] == "AP"
        assert status["ip"] == ""
        assert status["clients"] == ""

    def test_an_empty_status_reply_is_not_reported_as_online(self, monkeypatch):
        session = FakeSession([response("")])
        monkeypatch.setattr(adapters, "HttpSession", lambda *a, **k: session)
        adapter = TendaAdapter(tenda_device(), "admin")
        adapter.cookie = "b=1"
        with pytest.raises(ProtocolMismatch):
            adapter.status()

    @pytest.mark.parametrize("operation", ["status", "reboot", "set_ssid"])
    def test_a_redirected_module_request_is_not_success(self, monkeypatch, operation):
        """HttpSession does not follow redirects, so a 3xx carries no module reply at all."""
        redirect = HttpResponse(status=302, headers={"Location": "/login.html"}, body=b"", url="http://192.168.1.2/")
        session = FakeSession([redirect])
        monkeypatch.setattr(adapters, "HttpSession", lambda *a, **k: session)
        adapter = TendaAdapter(tenda_device(), "admin")
        adapter.cookie = "b=1"
        args = ("NewName",) if operation == "set_ssid" else ()
        with pytest.raises(AdapterError, match="302"):
            getattr(adapter, operation)(*args)
        assert len(session.requests) == 1


class TestUptimeParsing:
    @pytest.mark.parametrize(
        "value,expected",
        [
            ("1 02:03:04", 86400 + 2 * 3600 + 3 * 60 + 4),
            ("02:03:04", 2 * 3600 + 3 * 60 + 4),
            ("3 days", 3 * 86400),
            ("", None),
            (None, None),
            ("garbage", None),
        ],
    )
    def test_uptime_seconds(self, value, expected):
        assert adapters._uptime_seconds(value) == expected


class TestUptimeParsingExtended:
    def test_bare_integer_is_seconds(self):
        from cudy_manager.adapters import _uptime_seconds

        assert _uptime_seconds("3650") == 3650

    def test_sysinfo_style_days_and_clock(self):
        from cudy_manager.adapters import _uptime_seconds

        assert _uptime_seconds("5 06:00:00") == 5 * 86400 + 6 * 3600

    def test_day_and_clock_combined(self):
        from cudy_manager.adapters import _uptime_seconds

        assert _uptime_seconds("1 day 2:03:04") == 86400 + 2 * 3600 + 3 * 60 + 4

    def test_empty_and_junk_return_none(self):
        from cudy_manager.adapters import _uptime_seconds

        assert _uptime_seconds("") is None
        assert _uptime_seconds(None) is None
        assert _uptime_seconds("unknown") is None


class TestCudyStatusUptime:
    def _status(self, page: str) -> dict:
        from unittest.mock import patch

        from cudy_manager.adapters import CudyAdapter
        from cudy_manager.http_client import HttpResponse
        from cudy_manager.models import Device

        device = Device.from_dict("c1", {"vendor": "cudy", "host": "192.168.1.1"})
        adapter = CudyAdapter(device, "pw")
        adapter.authenticated = True
        response = HttpResponse(
            status=200,
            headers={"Content-Type": "text/html"},
            body=page.encode(),
            url="http://192.168.1.1/status",
        )
        with patch.object(adapter, "_session_get", return_value=response):
            return adapter.status()

    def test_day_and_clock_are_both_counted(self):
        status = self._status("<html><body>Uptime: 1 day 2:03:04</body></html>")
        assert status["uptime_seconds"] == 86400 + 2 * 3600 + 3 * 60 + 4

    def test_activity_time_label_is_understood(self):
        status = self._status("<html><body>Activity Time 00:45:12</body></html>")
        assert status["uptime_seconds"] == 45 * 60 + 12

    def test_activity_time_is_not_lost_entirely(self):
        # A None here makes the scheduler skip automatic reboots forever.
        status = self._status("<html><body>Activity Time 00:45:12</body></html>")
        assert status["uptime_seconds"] is not None

    def test_seconds_only_uptime(self):
        status = self._status("<html><body>Uptime: 900</body></html>")
        assert status["uptime_seconds"] == 900

    def test_page_without_uptime_reports_none(self):
        status = self._status("<html><body>no timing here</body></html>")
        assert "uptime_seconds" not in status

    @pytest.mark.parametrize(
        "page,expected",
        [
            ("<tr><td>Firmware Version</td><td>2.1.5-20230512</td></tr>", "2.1.5-20230512"),
            ("<tr><th>Software Version</th><td>1.16.2</td></tr>", "1.16.2"),
            ("<p>Firmware Version: 2.3.1</p>", "2.3.1"),
            ("<p>Firmware Version: V1.16.2 Build 5</p>", "V1.16.2"),
            ("<html><body>firmware 1.2.3</body></html>", "1.2.3"),
        ],
    )
    def test_firmware_is_the_value_not_the_end_of_its_label(self, page, expected):
        assert self._status(page)["firmware"] == expected

    def test_a_firmware_menu_link_is_not_a_version(self):
        assert self._status('<a href="/upgrade">Firmware Upgrade</a>')["firmware"] == ""


class TestOneConversationPerRouter:
    """A Cudy invalidates its login token when the next login asks for one.

    Found on a real AP1300: the dashboard's 30-second poll and a Clients click logged
    in at the same moment, one of them got the login form back, and the rejection
    latch then stopped all polling until the password was re-entered.
    """

    def run_together(self, manager, calls):
        import threading

        results: dict = {}

        def run(name, call):
            try:
                results[name] = call()
            except Exception as exc:  # noqa: BLE001 - the assertion below reports it
                results[name] = exc

        threads = [threading.Thread(target=run, args=item) for item in calls.items()]
        [thread.start() for thread in threads]
        [thread.join() for thread in threads]
        return results

    def test_concurrent_operations_on_one_cudy_both_succeed(self, tmp_path):
        from fake_router import FakeRouter
        from test_manager import build_manager

        with FakeRouter("ap1300") as router:
            router.state["login_delay"] = 0.3
            manager = build_manager(tmp_path)
            manager.add_device("c1", "127.0.0.1", "cudy", password="goodpass", http_port=router.port)
            results = self.run_together(
                manager,
                {"a": lambda: manager.verify_credentials("c1"), "b": lambda: manager.verify_credentials("c1")},
            )
        assert results["a"]["ok"] and results["b"]["ok"], results
        assert manager.rejected_credential(manager.get_device("c1")) is None

    def test_a_router_held_too_long_is_busy_not_rejected(self, tmp_path):
        import fcntl
        import hashlib
        import os

        from test_manager import build_manager

        manager = build_manager(tmp_path)
        device = manager.add_device("c1", "192.0.2.1", "cudy", password="p")
        manager.router_lock_timeout = 0.2
        key = hashlib.sha256(f"{device.host}:{device.http_port}:{device.ssh_port}".encode()).hexdigest()[:16]
        (manager.data_dir / "locks").mkdir(parents=True, exist_ok=True)
        holder = os.open(manager.data_dir / "locks" / f"router-{key}.lock", os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(holder, fcntl.LOCK_EX)
        try:
            with pytest.raises(AdapterError, match="busy") as caught:
                manager.reboot_device("c1")
            assert not isinstance(caught.value, AuthenticationRejected)
            assert manager.get_status("c1").get("reason") != "credentials_rejected"
        finally:
            os.close(holder)


class TestCudyTokenStolenByAnotherLogin:
    def test_a_login_elsewhere_during_ours_is_retried_once_and_succeeds(self, monkeypatch):
        """The operator signing in to the AP's own web UI mid-poll must not read as a wrong password."""
        from fake_router import FakeRouter

        monkeypatch.setattr(adapters, "_CUDY_RETRY_PAUSE", 0)
        with FakeRouter("ap1300") as router:
            router.state["steal_next_token"] = True
            device = Device.from_dict("c1", {"vendor": "cudy", "host": "127.0.0.1", "http_port": router.port})
            assert CudyAdapter(device, "goodpass").login() is True
            assert router.state["login_posts"] == 2


# The status widget of a real Cudy AP1300 (firmware 2.5.25), values changed. Each
# cell carries a desktop and a mobile copy, and an empty "cbip-table-N" div follows
# the label: its digit is what the old parser read as the uptime.
AP1300_STATUS_PAGE = """
<table><tbody>
<tr data-sid="0"><td><div id="cbi-table-0-content">
  <p class="form-control-static hidden-xs ">Firmware Version</p></div>
  <div id="cbip-table-0-content"></div></td>
<td><div id="cbi-table-0-data"><p class="form-control-static hidden-xs ">2.5.25 DE</p></div>
  <div id="cbip-table-0-data"></div></td><td></td></tr>
<tr data-sid="2"><td><div id="cbi-table-2-content">
  <p class="form-control-static hidden-xs ">Uptime</p>
  <p class="visible-xs ">Uptime</p></div>
  <div id="cbip-table-2-content"></div></td>
<td><div id="cbi-table-2-data">
  <p class="form-control-static hidden-xs ">1 Day 20:55:55</p>
  <p class="visible-xs ">1 Day 20:55:55</p></div>
  <div id="cbip-table-2-data"></div></td><td></td></tr>
</tbody></table>
"""


class TestCudyStatusFromRealFirmware:
    def test_uptime_and_firmware_come_from_the_value_cells(self, monkeypatch):
        session = FakeSession(
            [
                form_response({"_csrf": "c", "salt": "s", "token": "t"}),
                response("", status=302),
                response(AP1300_STATUS_PAGE),
            ]
        )
        monkeypatch.setattr(adapters, "HttpSession", lambda *a, **k: session)
        status = CudyAdapter(cudy_device(), "p").status()
        assert status["uptime_seconds"] == 86400 + 20 * 3600 + 55 * 60 + 55
        assert status["uptime_text"] == "1 Day 20:55:55"
        assert status["firmware"] == "2.5.25"

    def test_an_inline_uptime_on_older_pages_still_parses(self, monkeypatch):
        session = FakeSession(
            [
                form_response({"_csrf": "c", "salt": "s", "token": "t"}),
                response("", status=302),
                response("<html><body><p>Uptime: 3d 04:05:06</p></body></html>"),
            ]
        )
        monkeypatch.setattr(adapters, "HttpSession", lambda *a, **k: session)
        assert CudyAdapter(cudy_device(), "p").status()["uptime_seconds"] == 3 * 86400 + 4 * 3600 + 5 * 60 + 6


class TestCudyRebootFromRealFirmware:
    """The AP1300's own reboot page GETs reboot/apply from a script as it loads.

    The adapter used to POST reboot/call (older LuCI), which the real AP answered
    without restarting: the operator had to reboot it from the Cudy app instead.
    """

    def test_reboot_requests_apply_once_after_logging_in(self):
        from fake_router import FakeRouter

        with FakeRouter("ap1300") as router:
            device = Device.from_dict("c1", {"vendor": "cudy", "host": "127.0.0.1", "http_port": router.port})
            assert CudyAdapter(device, "goodpass").reboot() is True
            assert router.state["reboots"] == 1
            assert not router.state.get("posted_reboot_call")

    def test_older_firmware_without_apply_still_gets_reboot_call(self, monkeypatch):
        session = FakeSession(
            [
                form_response({"_csrf": "c", "salt": "s", "token": "t"}),
                response("", status=302),
                response("not found", status=404),
                response("", status=200),
            ]
        )
        monkeypatch.setattr(adapters, "HttpSession", lambda *a, **k: session)
        assert CudyAdapter(cudy_device(), "p").reboot() is True
        assert [r["path"] for r in session.requests[-2:]] == [
            "/cgi-bin/luci/admin/system/reboot/apply",
            "/cgi-bin/luci/admin/system/reboot/call",
        ]

    def test_a_refused_reboot_is_an_error_not_a_success(self, monkeypatch):
        session = FakeSession(
            [
                form_response({"_csrf": "c", "salt": "s", "token": "t"}),
                response("", status=302),
                response("not found", status=404),
                response("server error", status=500),
            ]
        )
        monkeypatch.setattr(adapters, "HttpSession", lambda *a, **k: session)
        with pytest.raises(AdapterError, match="did not accept the reboot"):
            CudyAdapter(cudy_device(), "p").reboot()


class TestCudyWifiChangesFromRealFirmware:
    """Wi-Fi name and password changes through the AP1300's own per-network form.

    The fake serves sanitised copies of the real forms, so these tests pin what the
    router's Save & Apply button sends: every field back unchanged except the one
    being changed, fields the page's dependency rules hide left out.
    """

    def adapter(self, router):
        device = Device.from_dict("c1", {"vendor": "cudy", "host": "127.0.0.1", "http_port": router.port})
        return CudyAdapter(device, "goodpass")

    def original_fields(self, iface):
        from fake_router import FIXTURES

        return adapters._cbi_fields((FIXTURES / f"ap1300_edit_{iface}.html").read_text())

    def test_renaming_one_band_sends_everything_else_back_untouched(self):
        from fake_router import FakeRouter

        with FakeRouter("ap1300") as router:
            assert self.adapter(router).set_ssid("New-Name", "2.4G") is True
            assert router.state["wifi"]["wlan00"]["ssid"] == "New-Name"
            assert router.state["wifi"]["wlan10"]["ssid"] == "Example-5G"
            (iface, posted), = router.state["wifi_posts"]
        assert iface == "wlan00"
        sent = dict(posted)
        assert sent.pop("cbid.wireless.wlan00.ssid") == "New-Name"
        assert sent.pop("cbi.apply") == ""
        assert sent.pop("timeclock").isdigit()
        expected = {
            name: value
            for name, value in self.original_fields("wlan00")
            if name not in {"cbid.wireless.wlan00.ssid", "timeclock"}
        }
        # Hidden by the page's own rules while encryption is psk-mixed.
        for hidden in ("radius_server", "radius_port", "radius_secret", "nas_id", "ddrate", "uurate"):
            expected.pop(f"cbid.wireless.wlan00.{hidden}")
        assert sent == expected
        assert sent["cbid.wireless.wlan00.key"] == "old-password-1", "the password must go back unchanged"

    def test_a_password_change_covers_both_bands_and_is_read_back(self):
        from fake_router import FakeRouter

        with FakeRouter("ap1300") as router:
            assert self.adapter(router).set_wifi_password("brand-new-pass") is True
            assert [iface for iface, _ in router.state["wifi_posts"]] == ["wlan00", "wlan10"]
            assert router.state["wifi"]["wlan00"]["key"] == "brand-new-pass"
            assert router.state["wifi"]["wlan10"]["key"] == "brand-new-pass"

    @pytest.mark.parametrize("encryption", ["none", "wpa2", "wpa-mixed"])
    def test_a_network_without_a_passphrase_is_never_written(self, encryption):
        """Setting a key on an open or enterprise network would change nothing, or break RADIUS logins."""
        from fake_router import FakeRouter

        with FakeRouter("ap1300") as router:
            router.state["wifi"]["wlan00"]["encryption"] = encryption
            with pytest.raises(AdapterError, match="no Wi-Fi password to change"):
                self.adapter(router).set_wifi_password("brand-new-pass")
            assert router.state["wifi_posts"] == []

    def test_a_router_that_does_not_keep_the_change_is_an_error(self):
        from fake_router import FakeRouter

        with FakeRouter("ap1300") as router:
            router.state["ignore_wifi_writes"] = True
            with pytest.raises(AdapterError, match="did not keep the change") as caught:
                self.adapter(router).set_wifi_password("brand-new-pass", "5G")
        assert "brand-new-pass" not in str(caught.value)

    def test_a_failure_on_the_second_band_says_the_bands_now_differ(self, monkeypatch):
        from fake_router import FakeRouter

        with FakeRouter("ap1300") as router:
            adapter = self.adapter(router)
            original = adapter._wifi_form
            calls = {"n": 0}

            def flaky(iface):
                # Reads: both forms, then the 2.4G read-back; the 5G write after it is ignored.
                calls["n"] += 1
                if calls["n"] == 3:
                    router.state["ignore_wifi_writes"] = True
                return original(iface)

            monkeypatch.setattr(adapter, "_wifi_form", flaky)
            with pytest.raises(AdapterError, match="changed on 2.4G, but not on 5G"):
                adapter.set_ssid("New-Name")

    def test_the_manager_routes_a_cudy_web_ssid_change_through_the_router_lock(self, tmp_path):
        from fake_router import FakeRouter
        from test_manager import build_manager

        with FakeRouter("ap1300") as router:
            manager = build_manager(tmp_path)
            manager.add_device("c1", "127.0.0.1", "cudy", password="goodpass", http_port=router.port)
            assert manager.set_wifi_ssid("c1", "Shop-WiFi", "5G") is True
            assert manager.set_wifi_password("c1", "shop-password-1") is True
            assert router.state["wifi"]["wlan10"]["ssid"] == "Shop-WiFi"
            assert router.state["wifi"]["wlan00"]["key"] == "shop-password-1"
