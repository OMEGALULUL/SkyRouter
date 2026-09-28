"""Tests for the old-style TP-Link adapter.

The WR840N counts every failed login and locks its web UI for two hours after
ten, so most of these tests are about the adapter being careful: one attempt per
session, never a silent retry, and an honest error when the router is locked.

The page shapes here come from the structure confirmed against the real device.
They are the part most likely to need adjusting against live hardware, so the
adapter reports a protocol mismatch with a snippet of what it actually received
instead of returning an empty but successful result.
"""

import contextlib
from pathlib import Path

import pytest
from fake_router import FakeTpLink
from test_manager import build_manager

from cudy_manager import adapters
from cudy_manager.adapters import (
    AdapterError,
    AuthenticationRejected,
    ProtocolMismatch,
    TpLinkAdapter,
    _tplink_clients,
)
from cudy_manager.http_client import HttpResponse
from cudy_manager.models import Device


def device_for(port: int, username: str = "admin") -> Device:
    return Device.from_dict(
        "r1",
        {"vendor": "tplink", "host": "127.0.0.1", "http_port": port, "username": username},
    )


class TestTpLinkAuth:
    def test_correct_password_authenticates(self):
        with FakeTpLink(password="admin") as router:
            adapter = TpLinkAdapter(device_for(router.port), "admin")
            assert adapter.login() is True
            assert router.attempts == 0

    def test_wrong_password_is_rejected_as_authentication(self):
        with FakeTpLink(password="admin") as router:
            adapter = TpLinkAdapter(device_for(router.port), "wrong")
            try:
                adapter.login()
            except AuthenticationRejected as exc:
                assert "rejected" in str(exc)
            else:
                raise AssertionError("wrong password was accepted") from None

    def test_a_rejection_costs_exactly_one_attempt(self):
        """The router allows ten tries, so the adapter must not burn them."""
        with FakeTpLink(password="admin") as router:
            adapter = TpLinkAdapter(device_for(router.port), "wrong")
            for _ in range(5):
                with contextlib.suppress(AuthenticationRejected):
                    adapter.login()
            assert router.attempts == 5

    def test_login_is_attempted_once_per_adapter(self):
        with FakeTpLink(password="admin") as router:
            adapter = TpLinkAdapter(device_for(router.port), "admin")
            adapter.login()
            for _ in range(10):
                adapter.login()
            assert router.attempts == 0

    def test_lockout_is_reported_once_the_real_threshold_is_reached(self):
        """The firmware locks at ten, so drive it to ten exactly."""
        with FakeTpLink(password="admin", max_attempts=10) as router:
            adapter = TpLinkAdapter(device_for(router.port), "wrong")
            last = None
            for _ in range(10):
                try:
                    adapter.login()
                except AuthenticationRejected as exc:
                    last = exc
            assert last is not None
            assert "locked" in str(last)
            assert "2 hours" in str(last)

    def test_a_wrong_password_before_lockout_says_so(self):
        with FakeTpLink(password="admin", max_attempts=10) as router:
            adapter = TpLinkAdapter(device_for(router.port), "wrong")
            try:
                adapter.login()
            except AuthenticationRejected as exc:
                assert "1 of 10" in str(exc)
                assert "locked" not in str(exc)

    def test_a_refused_session_is_not_treated_as_success(self):
        with FakeTpLink(password="admin") as router:
            adapter = TpLinkAdapter(device_for(router.port), "admin")
            adapter.login()
            # Simulate the router dropping the session.
            adapter.authenticated = False
            adapter.auth_cookie = "Basic bogus"
            try:
                adapter.status()
            except AuthenticationRejected:
                pass
            except AdapterError as exc:
                raise AssertionError(f"expected an auth rejection, got {exc}") from exc


class _ScriptedSession:
    """Answers each path with a fixed status and body, and records what was asked."""

    def __init__(self, pages: dict[str, tuple[int, str]]):
        self.pages = pages
        self.requests: list[tuple[str, str, str]] = []

    def request(self, method, path, data=None, headers=None, follow_redirects=False):
        self.requests.append((method, path, (headers or {}).get("Cookie", "")))
        status, body = self.pages.get(path, (404, "<html>not found</html>"))
        return HttpResponse(status=status, headers={}, body=body.encode(), url="http://127.0.0.1/")

    @property
    def credentialed(self) -> int:
        return sum(1 for _method, _path, cookie in self.requests if cookie)


def scripted(monkeypatch, pages: dict[str, tuple[int, str]]) -> _ScriptedSession:
    session = _ScriptedSession({"/": (200, "<script>var authTimes=0;</script>"), **pages})
    monkeypatch.setattr(adapters, "HttpSession", lambda *a, **k: session)
    return session


class TestTpLinkUnexpectedStatus:
    """Only a 2xx confirms the credential; every other answer must not count as logged in."""

    def test_a_401_is_a_rejection(self, monkeypatch):
        session = scripted(monkeypatch, {"/userRpm/StatusRpm.htm": (401, "<html>401</html>")})
        adapter = TpLinkAdapter(device_for(80), "wrong")
        with pytest.raises(AuthenticationRejected):
            adapter.login()
        assert adapter.authenticated is False
        assert session.credentialed == 1

    @pytest.mark.parametrize(
        "status,expected",
        [(404, ProtocolMismatch), (500, AdapterError), (302, AdapterError)],
    )
    def test_other_answers_are_errors_not_a_login(self, monkeypatch, status, expected):
        scripted(monkeypatch, {"/userRpm/StatusRpm.htm": (status, "<html>error</html>")})
        adapter = TpLinkAdapter(device_for(80), "admin")
        with pytest.raises(expected, match=str(status)) as caught:
            adapter.login()
        assert not isinstance(caught.value, AuthenticationRejected)
        assert adapter.authenticated is False

    def test_a_failed_client_table_is_not_an_empty_one(self, monkeypatch):
        from fake_router import TP_LINK_STATUS_PAGE

        scripted(
            monkeypatch,
            {
                "/userRpm/StatusRpm.htm": (200, TP_LINK_STATUS_PAGE.decode()),
                "/userRpm/DhcpTableRpm.htm": (500, "<html>error</html>"),
            },
        )
        with pytest.raises(AdapterError, match="500"):
            TpLinkAdapter(device_for(80), "admin").clients()

    def test_a_login_page_in_place_of_the_client_table_is_a_rejection(self, monkeypatch):
        from fake_router import TP_LINK_STATUS_PAGE

        scripted(
            monkeypatch,
            {
                "/userRpm/StatusRpm.htm": (200, TP_LINK_STATUS_PAGE.decode()),
                "/userRpm/DhcpTableRpm.htm": (200, "<script>var authTimes=3;</script>"),
            },
        )
        with pytest.raises(AuthenticationRejected):
            TpLinkAdapter(device_for(80), "admin").clients()

    def test_verify_reports_a_401_as_rejected_and_stops_trying(self, monkeypatch, tmp_path: Path):
        session = scripted(monkeypatch, {"/userRpm/StatusRpm.htm": (401, "<html>401</html>")})
        manager = build_manager(tmp_path)
        manager.add_device("r1", "127.0.0.1", "tplink", password="wrong")
        assert manager.verify_credentials("r1")["reason"] == "rejected"
        assert manager.get_status("r1")["reason"] == "credentials_rejected"
        assert session.credentialed == 1


class TestTpLinkLockout:
    def test_a_locked_router_is_reported_as_locked_even_with_the_right_password(self):
        from cudy_manager.adapters import RouterLockedOut

        with FakeTpLink(password="admin", max_attempts=10) as router:
            for _ in range(10):
                with contextlib.suppress(AuthenticationRejected):
                    TpLinkAdapter(device_for(router.port), "wrong").login()
            with pytest.raises(RouterLockedOut, match="locked"):
                TpLinkAdapter(device_for(router.port), "admin").login()

    def test_a_wrong_password_before_the_threshold_is_not_a_lockout(self):
        from cudy_manager.adapters import RouterLockedOut

        with FakeTpLink(password="admin", max_attempts=10) as router:
            with pytest.raises(AuthenticationRejected) as caught:
                TpLinkAdapter(device_for(router.port), "wrong").login()
            assert not isinstance(caught.value, RouterLockedOut)


class TestTpLinkStatus:
    def test_status_reports_model_firmware_and_uptime(self):
        with FakeTpLink(password="admin") as router:
            adapter = TpLinkAdapter(device_for(router.port), "admin")
            status = adapter.status()
            assert status["online"] is True
            assert status["model"] == "TL-WR840N"
            assert "3.14.3" in status["firmware"]
            assert status["uptime_seconds"] == 12345 * 3600 + 6 * 60 + 7

    def test_unrecognisable_page_raises_rather_than_reporting_health(self):
        with FakeTpLink(password="admin") as router:
            adapter = TpLinkAdapter(device_for(router.port), "admin")
            adapter.login()
            adapter._session_get = lambda path: _Stub("nothing useful here")
            try:
                adapter.status()
            except ProtocolMismatch as exc:
                assert "did not contain" in str(exc)
            else:
                raise AssertionError("an unparsable page was reported as a healthy router")

    def test_uptime_without_days_is_understood(self):
        from cudy_manager.adapters import _uptime_seconds

        assert _uptime_seconds("05:06:07") == 5 * 3600 + 6 * 60 + 7
        assert _uptime_seconds("2 days 03:04:05") == 2 * 86400 + 3 * 3600 + 4 * 60 + 5


class _Stub:
    def __init__(self, text: str):
        self.text = text
        self.status = 200


class TestTpLinkClients:
    def test_clients_are_parsed_from_the_host_table(self):
        with FakeTpLink(password="admin") as router:
            adapter = TpLinkAdapter(device_for(router.port), "admin")
            clients = adapter.clients()
            by_mac = {item["mac"]: item for item in clients}
            assert set(by_mac) == {"AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02", "AA:BB:CC:DD:EE:03"}
            assert by_mac["AA:BB:CC:DD:EE:01"]["ip"] == "192.168.0.101"
            assert by_mac["AA:BB:CC:DD:EE:01"]["name"] == "laptop"
            assert by_mac["AA:BB:CC:DD:EE:02"]["name"] == "phone"

    def test_dashed_macs_are_normalised(self):
        macs = {item["mac"] for item in _tplink_clients('var t=new TClient("AA-BB-CC-DD-EE-09","10.0.0.5","x");')}
        assert macs == {"AA:BB:CC:DD:EE:09"}

    def test_all_zero_mac_is_ignored(self):
        assert _tplink_clients('new TClient("00:00:00:00:00:00","0.0.0.0","")') == []

    def test_duplicate_macs_are_collapsed(self):
        page = 'new TClient("AA:BB:CC:DD:EE:01","1.1.1.1","a")' 'new TClient("AA:BB:CC:DD:EE:01","1.1.1.1","a")'
        assert len(_tplink_clients(page)) == 1

    def test_a_client_with_no_hostname_falls_back_to_its_mac(self):
        items = _tplink_clients('new TClient("AA:BB:CC:DD:EE:07","10.0.0.7","")')
        assert items[0]["name"] == "AA:BB:CC:DD:EE:07"

    def test_broadcast_addresses_are_not_taken_as_the_client_ip(self):
        items = _tplink_clients('new TClient("AA:BB:CC:DD:EE:08","255.255.255.0","host")')
        assert items[0]["ip"] != "255.255.255.0"


class TestTpLinkReboot:
    def test_reboot_posts_the_form_and_reports_success(self):
        with FakeTpLink(password="admin") as router:
            adapter = TpLinkAdapter(device_for(router.port), "admin")
            assert adapter.reboot() is True
            assert router.reboots == 1


class TestTpLinkPlumbing:
    def test_vendor_is_accepted_by_the_model(self, tmp_path: Path):
        manager = build_manager(tmp_path)
        device = manager.add_device("r1", "192.168.0.1", "tplink", password="admin")
        assert device.vendor == "tplink"

    def test_manager_builds_the_tplink_adapter(self, tmp_path: Path):
        manager = build_manager(tmp_path)
        manager.add_device("r1", "192.168.0.1", "tplink", password="admin")
        assert isinstance(manager.adapter_for(manager.get_device("r1")), TpLinkAdapter)

    def test_tplink_reaches_the_rest_of_the_stack(self, tmp_path: Path):
        """A full status read through the manager, against the fake."""
        with FakeTpLink(password="admin") as router:
            manager = build_manager(tmp_path)
            device = manager.add_device(
                "r1", "127.0.0.1", "tplink", password="admin", http_port=router.port, username="admin"
            )
            assert device.vendor == "tplink"
            status = manager.get_status("r1")
            assert status["online"] is True
            assert manager.get_connected_clients("r1")

    def test_verify_reports_rejection_not_unreachable(self, tmp_path: Path):
        with FakeTpLink(password="admin") as router:
            manager = build_manager(tmp_path)
            manager.add_device("r1", "127.0.0.1", "tplink", password="wrong", http_port=router.port)
            result = manager.verify_credentials("r1")
            assert result["ok"] is False
            assert result["reason"] == "rejected"


class TestRejectedCredentialIsNotResent:
    """The dashboard polls every 30 seconds and the WR840N locks after ten failures.

    Before this latch, a wrong username or password cost one of the router's ten
    attempts per poll, locking its web UI for two hours within about five minutes.
    """

    def add(self, manager, router, password: str = "wrong", username: str = "admin"):
        return manager.add_device(
            "r1", "127.0.0.1", "tplink", password=password, http_port=router.port, username=username
        )

    def test_repeated_polling_costs_one_attempt(self, tmp_path: Path):
        with FakeTpLink(password="admin") as router:
            manager = build_manager(tmp_path)
            self.add(manager, router)
            for _ in range(12):
                status = manager.get_status("r1")
            assert router.attempts == 1
            assert status["online"] is None
            assert status["reason"] == "credentials_rejected"
            for _ in range(5):
                manager.get_all_statuses()
            assert router.attempts == 1

    def test_actions_are_refused_without_contacting_the_router(self, tmp_path: Path):
        import pytest

        with FakeTpLink(password="admin") as router:
            manager = build_manager(tmp_path)
            self.add(manager, router)
            manager.get_status("r1")
            for action in (
                lambda: manager.reboot_device("r1"),
                lambda: manager.get_connected_clients("r1"),
                lambda: manager.set_wifi_ssid("r1", "home"),
            ):
                with pytest.raises(AuthenticationRejected, match="already rejected"):
                    action()
            assert router.attempts == 1
            assert router.reboots == 0

    def test_correcting_the_password_releases_it(self, tmp_path: Path):
        with FakeTpLink(password="admin") as router:
            manager = build_manager(tmp_path)
            self.add(manager, router)
            manager.get_status("r1")
            manager.set_password("r1", "admin", verify=False)
            assert manager.get_status("r1")["online"] is True
            assert router.attempts == 1

    def test_correcting_the_username_releases_it(self, tmp_path: Path):
        with FakeTpLink(password="admin") as router:
            manager = build_manager(tmp_path)
            self.add(manager, router, password="admin", username="root")
            manager.get_status("r1")
            manager.update_device("r1", username="admin")
            assert manager.get_status("r1")["online"] is True
            assert router.attempts == 1

    def test_a_password_rotated_by_another_process_releases_it(self, tmp_path: Path):
        """The CLI's set-password runs in its own process; the server must notice."""
        with FakeTpLink(password="admin") as router:
            server = build_manager(tmp_path)
            self.add(server, router)
            server.get_status("r1")
            build_manager(tmp_path).set_password("r1", "admin", verify=False)
            server._load_config()
            assert server.get_status("r1")["online"] is True

    def test_an_explicit_verify_still_tries_once(self, tmp_path: Path):
        """Re-testing is an operator decision, so it may spend exactly one attempt."""
        with FakeTpLink(password="admin") as router:
            manager = build_manager(tmp_path)
            self.add(manager, router)
            manager.get_status("r1")
            assert manager.verify_credentials("r1")["reason"] == "rejected"
            assert router.attempts == 2
            manager.get_status("r1")
            assert router.attempts == 2

    def test_the_scheduler_skips_without_trying(self, tmp_path: Path):
        from datetime import UTC, datetime

        from cudy_manager.scheduler import RebootScheduler

        with FakeTpLink(password="admin") as router:
            manager = build_manager(tmp_path)
            self.add(manager, router)
            manager.update_device("r1", reboot={"enabled": True, "at": "04:00", "timezone": "UTC"})
            manager.get_status("r1")
            scheduler = RebootScheduler(manager, tmp_path / "state.json")
            for minute in range(1, 6):
                results = scheduler.run_once(datetime(2026, 3, 10, 4, minute, tzinfo=UTC))
                assert results[0]["reason"] == "router rejected the stored credentials"
            assert router.attempts == 1
            assert router.reboots == 0


class TestLatchEdgesFoundInReview:
    def add(self, manager, router, password: str = "wrong"):
        return manager.add_device(
            "r1", "127.0.0.1", "tplink", password=password, http_port=router.port, username="admin"
        )

    def test_an_edit_that_leaves_the_credential_alone_keeps_the_latch(self, tmp_path: Path):
        with FakeTpLink(password="admin") as router:
            manager = build_manager(tmp_path)
            self.add(manager, router)
            manager.get_status("r1")
            manager.update_device("r1", model="TL-WR840N")
            manager.get_status("r1")
            assert router.attempts == 1

    def test_a_locked_router_is_reported_as_locked_not_as_a_wrong_password(self, tmp_path: Path):
        """While locked, the router refuses the right password too."""
        with FakeTpLink(password="admin") as router:
            manager = build_manager(tmp_path)
            self.add(manager, router)
            for _ in range(10):
                manager.verify_credentials("r1")
            assert router.attempts == 10
            manager.set_password("r1", "admin", verify=False)
            checked = manager.verify_credentials("r1")
            assert checked["reason"] == "locked", checked
            manager.get_status("r1")
            assert manager.rejected_credential(manager.get_device("r1")) is not None
