

class TestIPv6Subnets:
    def test_ipv6_hosts_sort_without_crashing(self):
        from cudy_manager.discovery import DiscoveredDevice, _address_key

        items = [
            DiscoveredDevice(host="fd00::3", vendor="cudy"),
            DiscoveredDevice(host="fd00::1", vendor="cudy"),
            DiscoveredDevice(host="fd00::2", vendor="cudy"),
        ]
        items.sort(key=lambda item: _address_key(item.host))
        assert [item.host for item in items] == ["fd00::1", "fd00::2", "fd00::3"]

    def test_ipv4_still_sorts_numerically_not_lexically(self):
        from cudy_manager.discovery import _address_key

        hosts = ["192.168.1.100", "192.168.1.9", "192.168.1.20"]
        assert sorted(hosts, key=_address_key) == ["192.168.1.9", "192.168.1.20", "192.168.1.100"]

    def test_unparsable_host_falls_back_to_text(self):
        from cudy_manager.discovery import _address_key

        assert sorted(["not-an-ip", "192.168.1.1"], key=_address_key) == ["192.168.1.1", "not-an-ip"]

    def test_small_ipv6_subnet_is_accepted(self):
        from cudy_manager.discovery import CudyDiscovery

        assert CudyDiscovery.validate_subnet("fd00::/120") == "fd00::/120"
