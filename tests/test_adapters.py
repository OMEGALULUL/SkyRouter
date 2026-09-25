import hashlib
import json
from urllib.parse import parse_qs

import pytest

from cudy_manager import adapters
from cudy_manager.adapters import (
    AdapterError,
    CudyAdapter,
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

    def test_ssid_change_unsupported_over_web(self, monkeypatch):
        monkeypatch.setattr(adapters, "HttpSession", lambda *a, **k: FakeSession([]))
        with pytest.raises(UnsupportedOperation):
            CudyAdapter(cudy_device(), "p").set_ssid("new-ssid")

    def test_http_failure_becomes_adapter_error(self, monkeypatch):
        session = FakeSession([HttpError("connection refused")])
        monkeypatch.setattr(adapters, "HttpSession", lambda *a, **k: session)
        with pytest.raises(AdapterError):
            CudyAdapter(cudy_device(), "p").login()


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

    def test_clients_tolerate_missing_radio_module(self, monkeypatch):
        session = FakeSession([AdapterError("no 2.4G"), AdapterError("no 5G")])
        monkeypatch.setattr(adapters, "HttpSession", lambda *a, **k: session)
        adapter = TendaAdapter(tenda_device(), "admin")
        adapter.cookie = "b=1"
        assert adapter.clients() == []


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
