import pytest

from cudy_manager.adapters import AdapterError
from cudy_manager.models import Device
from cudy_manager.openwrt import OpenWrtAdapter

SSH_DEVICE = {"vendor": "cudy", "host": "192.168.1.1", "transport": "ssh"}
DEVICE = Device.from_dict("s1", SSH_DEVICE)


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


REAL_DUMP = """Station aa:bb:cc:dd:ee:01 (on br-lan)
\tinactive time:\t100 ms
\trx bytes:\t123456
\ttx bytes:\t654321
\tsignal:\t\t-45 dBm
\tsignal avg:\t-48 dBm
\ttx bitrate:\t144.4 MBit/s
Station 11:22:33:44:55:66 (on br-lan)
\tinactive time:\t2500 ms
\trx bytes:\t999
\treceived bytes:\t1234
\ttransmitted bytes:\t5678
"""


class TestStationParsing:
    def _parse(self, text: str):
        from cudy_manager.openwrt import _parse_stations

        return _parse_stations(text)

    def test_mac_does_not_include_the_interface(self):
        first = self._parse(REAL_DUMP)[0]
        assert first["mac"] == "aa:bb:cc:dd:ee:01"

    def test_interface_is_separated(self):
        assert self._parse(REAL_DUMP)[0]["interface"] == "br-lan"

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
        monkeypatch.setattr(adapter, "execute", lambda command: (0, REAL_DUMP, ""))
        assert adapter.clients()[0]["mac"] == "aa:bb:cc:dd:ee:01"
