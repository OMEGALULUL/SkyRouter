import json
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import pytest
from fake_router import FakeRouter, FakeTpLink

from cudy_manager.adapters import AdapterError, CudyAdapter
from cudy_manager.diagnose import _snippet, diagnose_cudy, diagnose_device, diagnose_tenda
from cudy_manager.manager import DeviceManager, ManagerError
from cudy_manager.models import Device
from cudy_manager.secrets import SecretStore


def device_for(port: int, vendor: str = "cudy", username: str = "root", **extra: Any) -> Device:
    return Device.from_dict(
        "r1", {"vendor": vendor, "host": "127.0.0.1", "http_port": port, "username": username, **extra}
    )


Reply = tuple[int, bytes, dict[str, str]]


class ScriptedRouter:
    """Answers each "METHOD path" from a table, for replies the shared fakes do not model."""

    def __init__(self, routes: dict[str, Reply | Callable[[bytes], Reply]]):
        self.requests: list[tuple[str, str, bytes]] = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                return

            def _answer(self):
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length) if length else b""
                owner.requests.append((self.command, self.path, body))
                reply = routes.get(f"{self.command} {self.path}", (404, b"<html>not found</html>", {}))
                status, payload, headers = reply(body) if callable(reply) else reply
                self.send_response(status)
                self.send_header("Content-Type", headers.pop("Content-Type", "text/html; charset=utf-8"))
                self.send_header("Content-Length", str(len(payload)))
                for name, value in headers.items():
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(payload)

            do_GET = _answer
            do_POST = _answer

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()


SALTED_LOGIN_PAGE = (
    b'<html><title>Login</title><form><input name="_csrf" value="csrf-abc">'
    b'<input name="token" value="tok-xyz"><input name="salt" value="saltsalt">'
    b'<input name="luci_username"><input name="password"></form></html>'
)
UNSALTED_LOGIN_PAGE = (
    b'<html><title>Login</title><form><input name="_csrf" value="csrf-abc">'
    b'<input name="luci_username"><input name="password"></form></html>'
)
DASHBOARD_PAGE = b"<html><title>Router</title><h1>Dashboard</h1></html>"


def luci(login_reply: Reply | Callable[[bytes], Reply], page: bytes = SALTED_LOGIN_PAGE) -> ScriptedRouter:
    return ScriptedRouter(
        {
            "GET /": (200, page, {}),
            "GET /cgi-bin/luci/": (200, page, {}),
            "POST /cgi-bin/luci/": login_reply,
        }
    )


def adapter_logs_in(device: Device, password: str) -> bool:
    try:
        return CudyAdapter(device, password).login()
    except AdapterError:
        return False


class TestDiagnoseCudy:
    def test_correct_password_is_reported_as_accepted(self):
        with FakeRouter("ok") as router:
            report = diagnose_cudy(device_for(router.port), "goodpass")
        assert report["reachable"] is True
        assert "accepted" in report["verdict"]
        assert report["sysauth_cookie"] is True
        login_step = report["steps"][-1]
        assert login_step["status"] == 302
        assert "sysauth" in login_step["cookies_set"]

    def test_wrong_password_is_distinguished_from_a_protocol_problem(self):
        with FakeRouter("ok") as router:
            report = diagnose_cudy(device_for(router.port), "wrongpass")
        assert "credentials rejected" in report["verdict"]
        assert "protocol mismatch" not in report["verdict"]

    def test_missing_salt_is_reported_as_a_protocol_mismatch(self):
        with FakeRouter("no_salt") as router:
            report = diagnose_cudy(device_for(router.port), "anything")
        salt_step = report["steps"][1]
        assert salt_step["salt_present"] is False
        assert "NO SALT" in salt_step["note"]
        assert "not implemented" in report["verdict"]

    def test_wrong_port_is_reported_as_a_path_problem(self):
        with FakeRouter("wrong_path") as router:
            report = diagnose_cudy(device_for(router.port), "goodpass")
        assert "404" in report["steps"][0]["note"]
        assert "no LuCI login page" in report["verdict"]
        assert "credential" not in report["verdict"]

    def test_unreachable_router_is_reported_without_raising(self):
        device = device_for(1)
        report = diagnose_cudy(device, "x")
        assert report["reachable"] is False
        assert "did not answer" in report["verdict"]

    def test_secret_never_appears_in_the_report(self):
        with FakeRouter("ok") as router:
            report = diagnose_cudy(device_for(router.port), "topsecretvalue")
        assert "topsecretvalue" not in json.dumps(report)
        assert "saltsalt" not in json.dumps(report)

    def test_salt_and_token_are_reported_by_length_only(self):
        with FakeRouter("ok") as router:
            report = diagnose_cudy(device_for(router.port), "goodpass")
        step = report["steps"][1]
        assert step["salt_length"] == len("saltsalt")
        assert step["token_length"] == len("tok-xyz")
        assert step["csrf_present"] is True
        assert step["form_fields"]["_csrf"] == "<8 chars>"

    def test_verdict_is_always_present(self):
        for mode in ("ok", "no_salt", "wrong_path"):
            with FakeRouter(mode) as router:
                report = diagnose_cudy(device_for(router.port), "goodpass")
            assert report["verdict"]
            assert report["steps"]


def make_manager(tmp_path: Path) -> DeviceManager:
    return DeviceManager(
        config_path=tmp_path / "d.yaml",
        data_dir=tmp_path / "data",
        secret_store=SecretStore(tmp_path / "data"),
    )


class TestDiagnoseThroughManager:
    def test_manager_diagnose_uses_the_stored_password(self, tmp_path: Path):
        manager = make_manager(tmp_path)
        with FakeRouter("ok") as router:
            manager.add_device("r1", "127.0.0.1", "cudy", password="goodpass", http_port=router.port)
            report = manager.diagnose("r1")
        assert "accepted" in report["verdict"]

    def test_diagnose_without_a_stored_password_explains_what_to_do(self, tmp_path: Path):
        config = tmp_path / "d.yaml"
        config.write_text("devices:\n  bare:\n    vendor: cudy\n    host: 192.168.1.1\n")
        manager = make_manager(tmp_path)
        report = manager.diagnose("bare")
        assert "set-password" in report["verdict"]

    def test_diagnose_unknown_device_raises(self, tmp_path: Path):
        manager = make_manager(tmp_path)
        with pytest.raises(ManagerError):
            manager.diagnose("ghost")


class TestAddVerifiesPassword:
    def test_add_reports_rejection(self, tmp_path: Path):
        manager = make_manager(tmp_path)
        with FakeRouter("ok") as router:
            manager.add_device("r1", "127.0.0.1", "cudy", password="badpass", http_port=router.port)
            result = manager.verify_credentials("r1")
        assert result["ok"] is False


class TestCudyVerdictMatchesTheAdapter:
    """diagnose must reach the same conclusion the status command would."""

    def test_legacy_login_is_replayed_when_the_device_allows_it(self):
        def login(body: bytes) -> Reply:
            form = {key: value[0] for key, value in parse_qs(body.decode()).items()}
            if form.get("luci_password") == "plainpass":
                return 302, b"", {"Set-Cookie": "sysauth=SESSIONVALUE; Path=/"}
            return 200, UNSALTED_LOGIN_PAGE, {}

        with luci(login, page=UNSALTED_LOGIN_PAGE) as router:
            device = device_for(router.port, allow_legacy_login=True)
            report = diagnose_cudy(device, "plainpass")
            assert adapter_logs_in(device, "plainpass") is True
        assert "not implemented" not in report["verdict"]
        assert "accepted" in report["verdict"]
        assert "plainpass" not in json.dumps(report)

    def test_missing_salt_is_still_refused_without_legacy_login(self):
        with luci((302, b"", {}), page=UNSALTED_LOGIN_PAGE) as router:
            report = diagnose_cudy(device_for(router.port), "plainpass")
            posted = [request for request in router.requests if request[0] == "POST"]
        assert "not implemented" in report["verdict"]
        assert posted == []

    def test_a_dashboard_without_a_sysauth_cookie_counts_as_accepted_like_the_adapter(self):
        with luci((200, DASHBOARD_PAGE, {})) as router:
            device = device_for(router.port)
            report = diagnose_cudy(device, "goodpass")
            assert adapter_logs_in(device, "goodpass") is True
        assert "accepted" in report["verdict"]
        assert "protocol mismatch" not in report["verdict"]
        assert "protocol mismatch" not in report["steps"][-1]["note"]

    def test_a_login_form_with_a_sysauth_cookie_is_not_reported_as_accepted(self):
        reply = (200, UNSALTED_LOGIN_PAGE, {"Set-Cookie": "sysauth=SESSIONVALUE; Path=/"})
        with luci(reply) as router:
            device = device_for(router.port)
            report = diagnose_cudy(device, "goodpass")
            assert adapter_logs_in(device, "goodpass") is False
        assert "credentials rejected" in report["verdict"]

    def test_a_temporary_redirect_is_not_reported_as_accepted(self):
        with luci((307, b"", {"Location": "/cgi-bin/luci/"})) as router:
            device = device_for(router.port)
            report = diagnose_cudy(device, "goodpass")
            assert adapter_logs_in(device, "goodpass") is False
        assert "accepted" not in report["verdict"]

    def test_a_forbidden_login_form_is_reported_as_rejected(self):
        with FakeRouter("forbidden_on_failure") as router:
            report = diagnose_cudy(device_for(router.port), "wrongpass")
        assert "credentials rejected" in report["verdict"]


class TestCudySessionIsNotPrinted:
    def test_session_token_in_the_location_header_is_redacted(self):
        reply = (
            302,
            b"",
            {"Location": "/cgi-bin/luci/;stok=0123456789abcdef/admin?session=feedface#frag", "Set-Cookie": "sysauth=x"},
        )
        with luci(reply) as router:
            report = diagnose_cudy(device_for(router.port), "goodpass")
        dumped = json.dumps(report)
        assert "0123456789abcdef" not in dumped
        assert "feedface" not in dumped
        assert report["steps"][-1]["location"].startswith("/cgi-bin/luci/;")
        assert "accepted" in report["verdict"]

    def test_session_cookie_value_echoed_in_the_body_is_redacted(self):
        reply = (200, b"<html><h1>Dashboard</h1><a href='/x?sid=COOKIEVALUE42'>x</a></html>", {})
        reply[2]["Set-Cookie"] = "sysauth=COOKIEVALUE42; Path=/"
        with luci(reply) as router:
            report = diagnose_cudy(device_for(router.port), "goodpass")
        assert "COOKIEVALUE42" not in json.dumps(report)
        assert report["steps"][-1]["cookies_set"] == ["sysauth"]

    def test_a_short_non_session_cookie_does_not_blank_the_snippet(self):
        """Masking lang=en turned every "en" in the report into <redacted>."""
        reply = (200, b"<html><h1>Dashboard</h1><p>Wireless settings</p></html>", {})
        reply[2]["Set-Cookie"] = "lang=en; Path=/"
        with luci(reply) as router:
            report = diagnose_cudy(device_for(router.port), "goodpass")
        assert "Wireless settings" in report["steps"][-1]["body_snippet"]


    def test_session_token_in_a_link_in_the_body_is_redacted(self):
        reply = (200, b'<html><h1>Dashboard</h1><a href="/cgi-bin/luci/;stok=deadbeef99/admin">x</a></html>', {})
        with luci(reply) as router:
            report = diagnose_cudy(device_for(router.port), "goodpass")
        assert "deadbeef99" not in json.dumps(report)


class TestSnippetRedaction:
    def test_secret_with_repeated_whitespace_is_redacted(self):
        text = _snippet("error: wrong password my  secret pw", "my  secret pw")
        assert "secret" not in text
        assert "<redacted>" in text

    def test_secret_with_a_tab_or_newline_is_redacted(self):
        assert "hunter" not in _snippet("echo: a\tb\nhunter2", "a\tb\nhunter2")

    def test_whitespace_reflowed_echo_is_redacted(self):
        assert "hunter" not in _snippet("echo: a b\n\nhunter2", "a  b hunter2")

    def test_json_escaped_echo_is_redacted(self):
        secret = 'a"b\\c'
        body = json.dumps({"errMsg": f"bad password {secret}"})
        text = _snippet(body, secret)
        assert "<redacted>" in text
        assert 'a\\"b' not in text

    def test_html_escaped_echo_is_redacted(self):
        text = _snippet("<p>bad password a&lt;b&amp;c</p>", "a<b&c")
        assert "a&lt;b" not in text
        assert "<redacted>" in text

    def test_unicode_escaped_echo_is_redacted(self):
        text = _snippet('{"errMsg": "p\\u00e4ss"}', "päss")
        assert "u00e4" not in text


def tenda(login: bytes, status: bytes = b'{"sysStatus": {"runningTime": "100"}}') -> ScriptedRouter:
    json_type = {"Content-Type": "application/json"}
    return ScriptedRouter(
        {
            "GET /config/macro_config.js": (200, b'var CONFIG_PRODUCT_MODEL = "AC6";', {}),
            "POST /goform/modules?login": (200, login, dict(json_type)),
            "POST /goform/modules?status": (200, status, dict(json_type)),
        }
    )


def tenda_device(port: int) -> Device:
    return device_for(port, vendor="tenda", username="admin")


def login_step(report: dict[str, Any]) -> dict[str, Any]:
    return next(step for step in report["steps"] if step["step"] == "POST /goform/modules?login")


class TestDiagnoseTenda:
    def test_accepted_login_and_status(self):
        with tenda(b'{"sysLogin": {"Login": true}}') as router:
            report = diagnose_tenda(tenda_device(router.port), "pw")
        assert report["verdict"] == "login and status both answered"
        assert report["steps"][-1]["uptime_raw"] == "100"

    @pytest.mark.parametrize("body", [b"1", b"[]", b'"text"', b"null"])
    def test_login_json_that_is_not_an_object_is_reported_not_raised(self, body: bytes):
        with tenda(body) as router:
            report = diagnose_tenda(tenda_device(router.port), "pw")
        assert "different API" in report["verdict"]
        assert login_step(report)["response_keys"] == []

    @pytest.mark.parametrize("body", [b'{"sysLogin": "ok"}', b'{"sysLogin": [1]}', b'{"sysLogin": 1}'])
    def test_login_block_that_is_not_an_object_is_reported_not_raised(self, body: bytes):
        with tenda(body) as router:
            report = diagnose_tenda(tenda_device(router.port), "pw")
        assert report["verdict"] == "login was not accepted"
        assert login_step(report)["login_flag"] is None

    @pytest.mark.parametrize("status", [b"[]", b"5", b'{"sysStatus": "x"}', b'{"sysStatus": [1]}'])
    def test_status_json_of_the_wrong_shape_is_reported_not_raised(self, status: bytes):
        with tenda(b'{"sysLogin": {"Login": true}}', status) as router:
            report = diagnose_tenda(tenda_device(router.port), "pw")
        assert report["steps"][-1]["step"] == "POST /goform/modules (status)"
        assert report["verdict"]

    @pytest.mark.parametrize("status", [b"[]", b"not json"])
    def test_status_failure_is_not_reported_as_both_answered(self, status: bytes):
        with tenda(b'{"sysLogin": {"Login": true}}', status) as router:
            report = diagnose_tenda(tenda_device(router.port), "pw")
        assert "both answered" not in report["verdict"]
        assert "login accepted" in report["verdict"]

    def test_decoded_password_echoed_in_json_is_redacted(self):
        secret = 'pa"ss\\word'
        body = json.dumps({"sysLogin": {"Login": False, "errMsg": f"wrong password {secret}"}}).encode()
        with tenda(body) as router:
            report = diagnose_tenda(tenda_device(router.port), secret)
        snippet = login_step(report)["body_snippet"]
        assert "<redacted>" in snippet
        assert "ss\\\\word" not in snippet
        assert 'pa\\"ss' not in snippet


def tplink_device(port: int) -> Device:
    return device_for(port, vendor="tplink", username="admin")


class TestDiagnoseTpLink:
    def test_tplink_is_not_diagnosed_as_a_luci_router(self):
        with FakeTpLink(password="admin") as router:
            report = diagnose_device(tplink_device(router.port), "admin")
        assert report["vendor"] == "tplink"
        assert "LuCI" not in report["verdict"]
        assert "port" not in report["verdict"]

    def test_diagnose_never_presents_the_credential(self):
        with FakeTpLink(password="right") as router:
            report = diagnose_device(tplink_device(router.port), "NotTheSecret9")
            attempts = router.attempts
        assert attempts == 0
        assert "NotTheSecret9" not in json.dumps(report)

    def test_failed_login_counter_is_reported(self):
        with FakeTpLink() as router:
            router.handler.state["attempts"] = 3
            report = diagnose_device(tplink_device(router.port), "admin")
            attempts = router.attempts
        step = report["steps"][0]
        assert step["auth_times"] == 3
        assert step["model"] == "TL-WR840N"
        assert "3 failed" in report["verdict"]
        assert "7 left" in report["verdict"]
        assert attempts == 3

    def test_lockout_is_reported_as_a_lockout(self):
        with FakeTpLink() as router:
            router.handler.state["attempts"] = 10
            report = diagnose_device(tplink_device(router.port), "admin")
        assert "locked" in report["verdict"]

    def test_clean_counter_says_the_address_is_right(self):
        with FakeTpLink() as router:
            report = diagnose_device(tplink_device(router.port), "admin")
        assert report["reachable"] is True
        assert report["steps"][0]["auth_times"] == 0
        assert "no failed logins" in report["verdict"]

    def test_a_page_without_the_counter_is_not_the_tplink_ui(self):
        with FakeRouter("ok") as router:
            report = diagnose_device(tplink_device(router.port), "admin")
        assert report["vendor"] == "tplink"
        assert "LuCI" not in report["verdict"]
        assert "authTimes" in report["verdict"]

    def test_wrong_port_is_reported(self):
        with FakeRouter("wrong_path") as router:
            report = diagnose_device(tplink_device(router.port), "admin")
        assert "404" in report["verdict"]

    def test_unreachable_is_reported_without_raising(self):
        report = diagnose_device(tplink_device(1), "admin")
        assert report["reachable"] is False
        assert "did not answer" in report["verdict"]

    def test_manager_routes_tplink_to_the_tplink_diagnostic(self, tmp_path: Path):
        manager = make_manager(tmp_path)
        with FakeTpLink() as router:
            manager.add_device("t1", "127.0.0.1", "tplink", password="admin", http_port=router.port)
            report = manager.diagnose("t1")
            attempts = router.attempts
        assert report["vendor"] == "tplink"
        assert attempts == 0


class TestDiagnoseMatchesRealCudyFirmware:
    def test_the_real_ap1300_flow_is_reported_as_accepted(self):
        from fake_router import FakeRouter

        with FakeRouter("ap1300") as router:
            report = diagnose_cudy(device_for(router.port), "goodpass")
        assert "accepted" in report["verdict"], report["verdict"]
        assert any(step.get("token_fetched") for step in report["steps"])
        assert "f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8" not in json.dumps(report)

    def test_a_first_boot_page_is_diagnosed_without_logging_in(self):
        from fake_router import FakeRouter

        with FakeRouter("first_boot") as router:
            report = diagnose_cudy(device_for(router.port), "goodpass")
            assert router.state["login_posts"] == 0
        assert "first-time setup" in report["verdict"]
