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
