import pytest

from cudy_manager.discovery import CudyDiscovery


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


class TestHttpsProbing:
    def test_port_443_uses_https(self):
        from cudy_manager.discovery import CudyDiscovery

        assert CudyDiscovery._url("192.168.1.1", 443, "/x").startswith("https://")

    @pytest.mark.parametrize("port", [80, 8080, 3000])
    def test_other_ports_stay_on_http(self, port):
        from cudy_manager.discovery import CudyDiscovery

        assert CudyDiscovery._url("192.168.1.1", port, "/x").startswith("http://")

    def test_ipv6_https_url_is_bracketed(self):
        from cudy_manager.discovery import CudyDiscovery

        assert CudyDiscovery._url("fd00::1", 443, "/x") == "https://[fd00::1]:443/x"

    def test_self_signed_https_router_is_discovered(self, tmp_path, monkeypatch):
        """A router with a self-signed cert must still be found, which is the norm."""
        import ssl
        import subprocess
        import threading
        from http.server import BaseHTTPRequestHandler, HTTPServer

        key = tmp_path / "k.pem"
        cert = tmp_path / "c.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", str(key), "-out", str(cert),
             "-days", "1", "-nodes", "-subj", "/CN=router"],
            capture_output=True,
            check=True,
        )
        body = b'var CONFIG_PRODUCT_MODEL = "Tenda-AC10";\nvar CONFIG_FIRMWARE_VERION = "V5.11";'

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/config/macro_config.js":
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            discovery = CudyDiscovery("127.0.0.1/32", timeout=3.0)
            discovery.ports = (port,)
            # bind the test port into the HTTPS branch, as port 443 would be
            discovery._url = staticmethod(lambda host, p, path: f"https://{host}:{p}{path}")

            found = discovery.discover()
        finally:
            server.shutdown()

        assert [item.model for item in found] == ["Tenda-AC10"]
        assert found[0].vendor == "tenda"
