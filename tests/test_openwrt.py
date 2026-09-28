import os
import socket
import stat
import threading
import time
from pathlib import Path

import paramiko
import pytest

from cudy_manager import openwrt
from cudy_manager.adapters import AdapterError, AuthenticationRejected, UnsupportedOperation
from cudy_manager.manager import DeviceManager
from cudy_manager.models import Device
from cudy_manager.openwrt import OpenWrtAdapter
from cudy_manager.secrets import SecretStore

SSH_DEVICE = {"vendor": "cudy", "host": "192.168.1.1", "transport": "ssh"}
DEVICE = Device.from_dict("s1", SSH_DEVICE)

ROUTER_PASSWORD = "root-secret"
HANG = "hang"
DROP = "drop"


class _Session(paramiko.ServerInterface):
    def __init__(self, router: "FakeSshRouter", sock: socket.socket):
        self.router = router
        self.sock = sock

    def get_allowed_auths(self, username):
        return self.router.allowed_auths

    def check_auth_password(self, username, password):
        self.router.logins.append((username, password))
        if self.router.auth_delay:
            time.sleep(self.router.auth_delay)
        if self.router.hang_up_on_login:
            self.sock.shutdown(socket.SHUT_RDWR)
            return paramiko.AUTH_FAILED
        if "password" in self.router.allowed_auths.split(",") and (username, password) == ("root", ROUTER_PASSWORD):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == "session" and not self.router.refuse_sessions:
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel, command):
        text = command.decode()
        self.router.commands.append(text)
        threading.Thread(target=self.router.answer, args=(channel, text), daemon=True).start()
        return True


class FakeSshRouter:
    """A dropbear stand-in on an ephemeral 127.0.0.1 port, driven by a reply table."""

    def __init__(self):
        self.host_key = paramiko.ECDSAKey.generate()
        self.allowed_auths = "password"
        self.auth_delay = 0.0
        self.hang_up_on_login = False
        self.refuse_sessions = False
        self.replies: dict[str, object] = {}
        self.logins: list[tuple[str, str]] = []
        self.commands: list[str] = []
        self._transports: list[paramiko.Transport] = []
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(8)
        self.port = self._listener.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                sock, _ = self._listener.accept()
            except OSError:
                return
            transport = paramiko.Transport(sock)
            transport.add_server_key(self.host_key)
            self._transports.append(transport)
            try:
                transport.start_server(server=_Session(self, sock))
            except (paramiko.SSHException, EOFError, OSError):
                continue

    def answer(self, channel: paramiko.Channel, command: str) -> None:
        reply = self.replies.get(command, (127, "", f"sh: {command}: not found"))
        if reply == HANG:
            return
        # The client closes stdin only once the exec request was accepted; answering
        # sooner can overtake that acceptance and look like a refused command.
        deadline = time.monotonic() + 5
        while not channel.eof_received and time.monotonic() < deadline:
            time.sleep(0.005)
        if reply == DROP:
            channel.close()
            return
        assert isinstance(reply, tuple)
        code, out, err = reply
        if out:
            channel.sendall(out.encode())
        if err:
            channel.sendall_stderr(err.encode())
        channel.send_exit_status(code)
        channel.close()

    def known_hosts_line(self) -> str:
        return f"[127.0.0.1]:{self.port} {self.host_key.get_name()} {self.host_key.get_base64()}\n"

    def close(self) -> None:
        self._listener.close()
        for transport in self._transports:
            transport.close()


@pytest.fixture
def router(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    # paramiko reads ~/.ssh/known_hosts; the operator's own file stays out of the tests.
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    fake = FakeSshRouter()
    yield fake
    fake.close()


def _device(router: FakeSshRouter, **values) -> Device:
    data = {
        "vendor": "cudy",
        "host": "127.0.0.1",
        "transport": "ssh",
        "ssh_port": router.port,
        "username": "root",
        **values,
    }
    return Device.from_dict("s1", data)


def _trust_router(router: FakeSshRouter) -> None:
    ssh_dir = Path(os.environ["HOME"]) / ".ssh"
    ssh_dir.mkdir(parents=True, exist_ok=True)
    (ssh_dir / "known_hosts").write_text(router.known_hosts_line())


def _known_adapter(router: FakeSshRouter, password: str = ROUTER_PASSWORD, **values) -> OpenWrtAdapter:
    """An adapter for a router whose key is already in ~/.ssh/known_hosts."""
    _trust_router(router)
    return OpenWrtAdapter(_device(router, **values), password)


def _live_client_transports() -> list[paramiko.Transport]:
    return [
        thread
        for thread in threading.enumerate()
        if isinstance(thread, paramiko.Transport) and not thread.server_mode and thread.is_active()
    ]


STATUS_REPLIES = {
    "cat /proc/uptime": (0, "3600.25 7000.00\n", ""),
    "cat /etc/openwrt_release 2>/dev/null || cat /etc/os-release": (0, "DISTRIB_ID='OpenWrt'\n", ""),
    "cat /proc/loadavg": (0, "0.01 0.02 0.03 1/50 123\n", ""),
    "free -m": (0, "Mem: 123\n", ""),
}


class TestMalformedOutput:
    def test_unparsable_uptime_raises_adapter_error(self, monkeypatch):
        adapter = OpenWrtAdapter(DEVICE, "pw")
        monkeypatch.setattr(adapter, "execute", lambda command: (0, "", "") if "uptime" in command else (0, "", ""))

        with pytest.raises(AdapterError) as info:
            adapter.status()
        assert "uptime" in str(info.value)

    def test_unparsable_uptime_is_not_a_bare_value_error(self, monkeypatch):
        adapter = OpenWrtAdapter(DEVICE, "pw")
        monkeypatch.setattr(
            adapter,
            "execute",
            lambda command: (0, "not-a-number", "") if "uptime" in command else (0, "", ""),
        )

        try:
            adapter.status()
        except AdapterError:
            pass
        except ValueError as exc:  # pragma: no cover - the bug being guarded
            pytest.fail(f"leaked ValueError: {exc}")


class TestSshLogin:
    def test_a_session_reads_status(self, router: FakeSshRouter):
        router.replies = dict(STATUS_REPLIES)
        adapter = _known_adapter(router)
        try:
            status = adapter.status()
        finally:
            adapter.close()
        assert status["online"] is True
        assert status["uptime_seconds"] == 3600

    def test_a_wrong_password_is_rejected_not_unreachable(self, router: FakeSshRouter):
        adapter = _known_adapter(router, password="wrong")
        with pytest.raises(AuthenticationRejected):
            adapter.status()
        assert router.logins == [("root", "wrong")], "a refused login must not be retried"

    def test_password_logins_disabled_is_a_rejection_that_says_so(self, router: FakeSshRouter):
        router.allowed_auths = "publickey"
        adapter = _known_adapter(router)
        with pytest.raises(AuthenticationRejected, match="password"):
            adapter.status()

    def test_a_login_that_times_out_is_not_called_a_rejection(
        self, router: FakeSshRouter, monkeypatch: pytest.MonkeyPatch
    ):
        # paramiko raises AuthenticationException for this too; calling it a rejection
        # would latch a password the router never answered for.
        monkeypatch.setattr(openwrt, "_CONNECT_TIMEOUT", 0.5)
        router.auth_delay = 2.0
        adapter = _known_adapter(router)
        with pytest.raises(AdapterError) as info:
            adapter.status()
        assert not isinstance(info.value, AuthenticationRejected)

    def test_a_hang_up_during_login_is_not_called_a_rejection(self, router: FakeSshRouter):
        router.hang_up_on_login = True
        adapter = _known_adapter(router)
        with pytest.raises(AdapterError) as info:
            adapter.status()
        assert not isinstance(info.value, AuthenticationRejected)

    def test_a_failed_login_closes_the_half_open_session(self, router: FakeSshRouter):
        before = set(_live_client_transports())
        adapter = _known_adapter(router, password="wrong")
        with pytest.raises(AdapterError):
            adapter.status()
        assert set(_live_client_transports()) - before == set()

    def test_verify_credentials_reports_a_wrong_ssh_password_as_rejected(self, router: FakeSshRouter, tmp_path: Path):
        _trust_router(router)
        data = tmp_path / "data"
        manager = DeviceManager(
            config_path=tmp_path / "cudy_devices.yaml", data_dir=data, secret_store=SecretStore(data)
        )
        manager.add_device(
            "s1", "127.0.0.1", "cudy", password="wrong", transport="ssh", ssh_port=router.port, username="root"
        )
        assert manager.verify_credentials("s1")["reason"] == "rejected"


class TestSshCommands:
    def test_a_refused_session_channel_is_an_adapter_error(self, router: FakeSshRouter):
        router.refuse_sessions = True
        before = set(_live_client_transports())
        adapter = _known_adapter(router)
        with pytest.raises(AdapterError):
            adapter.status()
        assert adapter.connected is False
        assert set(_live_client_transports()) - before == set()

    def test_a_command_that_never_answers_is_an_adapter_error(
        self, router: FakeSshRouter, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setattr(openwrt, "_COMMAND_TIMEOUT", 0.3)
        router.replies = {"reboot": HANG}
        adapter = _known_adapter(router)
        with pytest.raises(AdapterError, match="may"):
            adapter.reboot()
        assert adapter.connected is False

    def test_a_session_dropped_mid_change_says_the_outcome_is_unknown(self, router: FakeSshRouter):
        router.replies = {
            "uci set wireless.default_radio0.ssid=New && uci commit wireless && wifi reload": DROP,
        }
        adapter = _known_adapter(router, metadata={"uci_section": "wireless.default_radio0"})
        with pytest.raises(AdapterError, match="may"):
            adapter.set_ssid("New")

    def test_close_ends_the_session_and_can_be_repeated(self, router: FakeSshRouter):
        router.replies = dict(STATUS_REPLIES)
        before = set(_live_client_transports())
        adapter = _known_adapter(router)
        adapter.status()
        assert set(_live_client_transports()) - before, "the fixture should have opened a session"
        adapter.close()
        adapter.close()
        assert set(_live_client_transports()) - before == set()
        assert adapter.connected is False


class TestHostKeys:
    def test_a_first_key_is_remembered_and_a_different_one_is_refused(self, router: FakeSshRouter, tmp_path: Path):
        known_hosts = tmp_path / "data" / "ssh_known_hosts"
        router.replies = dict(STATUS_REPLIES)
        first = OpenWrtAdapter(_device(router, accept_unknown_host_key=True), ROUTER_PASSWORD, known_hosts=known_hosts)
        try:
            first.status()
        finally:
            first.close()
        assert router.known_hosts_line().split()[2] in known_hosts.read_text()
        assert stat.S_IMODE(known_hosts.stat().st_mode) == 0o600

        router.host_key = paramiko.ECDSAKey.generate()
        router.logins.clear()
        impostor = OpenWrtAdapter(
            _device(router, accept_unknown_host_key=True), ROUTER_PASSWORD, known_hosts=known_hosts
        )
        with pytest.raises(AdapterError, match="host key") as info:
            impostor.status()
        assert not isinstance(info.value, AuthenticationRejected)
        assert router.logins == [], "the password went to a router with a different key"

    def test_auto_add_without_a_file_to_remember_keys_in_does_not_connect(self, router: FakeSshRouter):
        adapter = OpenWrtAdapter(_device(router, accept_unknown_host_key=True), ROUTER_PASSWORD)
        with pytest.raises(AdapterError, match="known_hosts"):
            adapter.status()
        assert router.logins == []

    def test_a_remembered_key_is_trusted_without_auto_add(self, router: FakeSshRouter, tmp_path: Path):
        known_hosts = tmp_path / "ssh_known_hosts"
        known_hosts.write_text(router.known_hosts_line())
        router.replies = dict(STATUS_REPLIES)
        adapter = OpenWrtAdapter(_device(router), ROUTER_PASSWORD, known_hosts=known_hosts)
        try:
            assert adapter.status()["online"] is True
        finally:
            adapter.close()

    def test_recording_a_key_keeps_entries_written_since_the_file_was_read(self, tmp_path: Path):
        known_hosts = tmp_path / "ssh_known_hosts"
        other = paramiko.ECDSAKey.generate()
        known_hosts.write_text(f"[10.0.0.2]:22 {other.get_name()} {other.get_base64()}\n")
        key = paramiko.ECDSAKey.generate()

        openwrt._record_new_host_keys(known_hosts).missing_host_key(None, "[10.0.0.1]:22", key)

        saved = paramiko.HostKeys(str(known_hosts))
        assert saved.lookup("[10.0.0.1]:22")[key.get_name()] == key
        assert saved.lookup("[10.0.0.2]:22")[other.get_name()] == other

    def test_a_key_another_adapter_recorded_meanwhile_is_enforced(self, tmp_path: Path):
        known_hosts = tmp_path / "ssh_known_hosts"
        recorded = paramiko.ECDSAKey.generate()
        known_hosts.write_text(f"[10.0.0.1]:22 {recorded.get_name()} {recorded.get_base64()}\n")

        with pytest.raises(paramiko.BadHostKeyException):
            openwrt._record_new_host_keys(known_hosts).missing_host_key(
                None, "[10.0.0.1]:22", paramiko.ECDSAKey.generate()
            )


REAL_DUMP = """Station aa:bb:cc:dd:ee:01 (on wlan0)
\tinactive time:\t100 ms
\trx bytes:\t123456
\ttx bytes:\t654321
\tsignal:\t\t-45 dBm
\tsignal avg:\t-48 dBm
\ttx bitrate:\t144.4 MBit/s
Station 11:22:33:44:55:66 (on wlan0)
\tinactive time:\t2500 ms
\trx bytes:\t999
\treceived bytes:\t1234
\ttransmitted bytes:\t5678
"""

IW_DEV = """phy#1
\tInterface phy1-ap0
\t\tifindex 12
\t\twdev 0x100000002
\t\taddr 02:00:00:00:01:01
\t\tssid Home-5G
\t\ttype AP
\t\tchannel 36 (5180 MHz), width: 80 MHz, center1: 5210 MHz
phy#0
\tUnnamed/non-netdev interface
\t\twdev 0x3
\t\ttype P2P-device
\tInterface phy0-sta0
\t\tifindex 11
\t\ttype managed
\tInterface phy0-ap0
\t\tifindex 10
\t\twdev 0x1
\t\taddr 02:00:00:00:00:01
\t\tssid Home
\t\ttype AP
\t\tchannel 1 (2412 MHz), width: 20 MHz, center1: 2412 MHz
"""


class TestStationParsing:
    def _parse(self, text: str):
        from cudy_manager.openwrt import _parse_stations

        return _parse_stations(text)

    def test_mac_does_not_include_the_interface(self):
        first = self._parse(REAL_DUMP)[0]
        assert first["mac"] == "aa:bb:cc:dd:ee:01"

    def test_interface_is_separated(self):
        assert self._parse(REAL_DUMP)[0]["interface"] == "wlan0"

    def test_multiword_keys_are_kept_whole(self):
        first = self._parse(REAL_DUMP)[0]
        assert first["rx bytes"] == "123456"
        assert first["tx bytes"] == "654321"
        assert first["inactive time"] == "100 ms"
        assert first["signal avg"] == "-48 dBm"

    def test_rx_and_tx_bytes_do_not_collide(self):
        first = self._parse(REAL_DUMP)[0]
        assert first["rx bytes"] != first["tx bytes"]

    def test_values_containing_colons_survive(self):
        parsed = self._parse("Station aa:bb:cc:dd:ee:ff (on eth0)\n\tconnected time:\t00:01:02\n")
        assert parsed[0]["connected time"] == "00:01:02"

    def test_both_stations_are_returned(self):
        clients = self._parse(REAL_DUMP)
        assert [item["mac"] for item in clients] == ["aa:bb:cc:dd:ee:01", "11:22:33:44:55:66"]

    def test_junk_before_the_first_station_is_ignored(self):
        assert self._parse("command failed: no such device\n") == []

    def test_empty_output(self):
        assert self._parse("") == []

    def test_station_without_fields(self):
        parsed = self._parse("Station aa:bb:cc:dd:ee:ff (on eth0)\n")
        assert parsed == [{"mac": "aa:bb:cc:dd:ee:ff", "interface": "eth0"}]

    def test_adapter_clients_uses_the_parser(self, monkeypatch):
        adapter = OpenWrtAdapter(DEVICE, "pw")
        monkeypatch.setattr(
            adapter,
            "execute",
            lambda command: (0, "\tInterface wlan0\n\t\ttype AP\n" if command == "iw dev" else REAL_DUMP, ""),
        )
        assert adapter.clients()[0]["mac"] == "aa:bb:cc:dd:ee:01"


class TestClients:
    def test_every_access_point_interface_is_queried(self, router: FakeSshRouter):
        router.replies = {
            "iw dev": (0, IW_DEV, ""),
            "iw dev phy0-ap0 station dump": (0, "Station aa:bb:cc:dd:ee:01 (on phy0-ap0)\n\tsignal:\t-40 dBm\n", ""),
            "iw dev phy1-ap0 station dump": (0, "Station aa:bb:cc:dd:ee:02 (on phy1-ap0)\n\tsignal:\t-60 dBm\n", ""),
        }
        adapter = _known_adapter(router)
        try:
            clients = adapter.clients()
        finally:
            adapter.close()
        assert sorted((item["mac"], item["interface"]) for item in clients) == [
            ("aa:bb:cc:dd:ee:01", "phy0-ap0"),
            ("aa:bb:cc:dd:ee:02", "phy1-ap0"),
        ]
        # A station interface's "station" is the upstream AP, not a client.
        assert "iw dev phy0-sta0 station dump" not in router.commands

    def test_no_access_point_means_no_clients(self, monkeypatch):
        adapter = OpenWrtAdapter(DEVICE, "pw")
        commands: list[str] = []

        def execute(command):
            commands.append(command)
            return 0, "phy#0\n\tInterface phy0-sta0\n\t\ttype managed\n", ""

        monkeypatch.setattr(adapter, "execute", execute)
        assert adapter.clients() == []
        assert commands == ["iw dev"]

    def test_a_failed_interface_listing_is_an_adapter_error(self, monkeypatch):
        adapter = OpenWrtAdapter(DEVICE, "pw")
        monkeypatch.setattr(adapter, "execute", lambda command: (127, "", "sh: iw: not found"))
        with pytest.raises(AdapterError, match="iw: not found"):
            adapter.clients()


class TestSetSsid:
    def _adapter(self, monkeypatch, section: str = "wireless.default_radio0"):
        adapter = OpenWrtAdapter(Device.from_dict("s1", {**SSH_DEVICE, "metadata": {"uci_section": section}}), "pw")
        commands: list[str] = []

        def execute(command):
            commands.append(command)
            return 0, "", ""

        monkeypatch.setattr(adapter, "execute", execute)
        return adapter, commands

    def test_without_a_band_the_configured_section_is_renamed(self, monkeypatch):
        adapter, commands = self._adapter(monkeypatch)
        assert adapter.set_ssid("New") is True
        assert commands == ["uci set wireless.default_radio0.ssid=New && uci commit wireless && wifi reload"]

    @pytest.mark.parametrize("radio", ["2.4G", "5G"])
    def test_a_band_choice_is_refused_instead_of_renaming_the_configured_section(self, monkeypatch, radio):
        adapter, commands = self._adapter(monkeypatch)
        with pytest.raises(UnsupportedOperation, match="uci_section"):
            adapter.set_ssid("New", radio)
        assert commands == []

    def test_a_section_outside_the_wireless_config_is_refused(self, monkeypatch):
        # Only "wireless" is committed and reloaded, so a change anywhere else would be
        # reported as done while staying uncommitted.
        adapter, commands = self._adapter(monkeypatch, section="network.lan")
        with pytest.raises(AdapterError, match="wireless"):
            adapter.set_ssid("New")
        assert commands == []
