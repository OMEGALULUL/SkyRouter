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

from fake_router import FakeTpLink
from test_manager import build_manager

from cudy_manager.adapters import (
    AdapterError,
    AuthenticationRejected,
    ProtocolMismatch,
    TpLinkAdapter,
    _tplink_clients,
)
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
