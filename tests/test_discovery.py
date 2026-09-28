import socket
import threading
import time
from contextlib import contextmanager

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


@contextmanager
def _raw_http_server(respond):
    """Answer every connection with respond(path) verbatim, as a misbehaving LAN host would."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)
    listener.settimeout(0.1)
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except OSError:
                continue
            with conn:
                conn.settimeout(2)
                request = b""
                try:
                    while b"\r\n\r\n" not in request:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        request += chunk
                    parts = request.split(b" ", 2)
                    conn.sendall(respond(parts[1].decode() if len(parts) > 1 else ""))
                except OSError:
                    pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1]
    finally:
        stop.set()
        thread.join()
        listener.close()


def _http(status: str, body: bytes, extra: str = "") -> bytes:
    return f"HTTP/1.1 {status}\r\nContent-Length: {len(body)}\r\n{extra}Connection: close\r\n\r\n".encode() + body


def _scan(port: int):
    discovery = CudyDiscovery("127.0.0.1/32", timeout=2.0)
    discovery.ports = (port,)
    return discovery.discover()


LUCI_LOGIN = (
    b'<html><head><title>Cudy</title><link rel="stylesheet" href="/luci-static/bootstrap/cascade.css"></head>'
    b'<body><form method="post" action="/cgi-bin/luci/"><input name="luci_username">'
    b'<input name="luci_password" type="password"></form></body></html>'
)


class TestMisbehavingHosts:
    @pytest.mark.parametrize(
        "reply",
        [
            pytest.param(b"SSH-2.0-OpenSSH_9.6\r\n", id="ssh-banner"),
            pytest.param(b"\x15\x03\x01\x00\x02\x02\x46", id="tls-alert"),
            pytest.param(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nzz\r\n",
                id="malformed-chunked",
            ),
        ],
    )
    def test_non_http_reply_is_skipped_not_raised(self, reply):
        with _raw_http_server(lambda path: reply) as port:
            assert _scan(port) == []

    def test_malformed_error_body_does_not_hide_the_hosts_other_probes(self):
        def respond(path):
            if path == "/config/macro_config.js":
                return b"HTTP/1.1 404 Not Found\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nzz\r\n"
            return _http("200 OK", LUCI_LOGIN)

        with _raw_http_server(respond) as port:
            found = _scan(port)

        assert [(item.vendor, item.port) for item in found] == [("cudy", port)]

    def test_one_host_failing_unexpectedly_does_not_discard_the_scan(self, monkeypatch):
        from cudy_manager.discovery import DiscoveredDevice

        discovery = CudyDiscovery("127.0.0.0/30")

        def probe(host):
            if host == "127.0.0.1":
                raise RuntimeError("unexpected parser failure")
            return DiscoveredDevice(host=host, vendor="cudy")

        monkeypatch.setattr(discovery, "_probe", probe)

        assert [item.host for item in discovery.discover()] == ["127.0.0.2"]


class TestLuciMarkers:
    def test_404_page_echoing_the_probe_path_is_not_a_router(self):
        def respond(path):
            page = (
                '<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<title>Error</title>\n'
                f"</head>\n<body>\n<pre>Cannot GET {path}</pre>\n</body>\n</html>\n"
            )
            return _http("404 Not Found", page.encode(), "Content-Type: text/html; charset=utf-8\r\n")

        with _raw_http_server(respond) as port:
            assert _scan(port) == []

    def test_login_page_is_found_even_though_its_form_echoes_the_path(self):
        with _raw_http_server(lambda path: _http("200 OK", LUCI_LOGIN)) as port:
            found = _scan(port)

        assert [item.vendor for item in found] == ["cudy"]
        assert "luci" in found[0].markers

    def test_forbidden_login_page_is_still_found(self):
        # LuCI answers an unauthenticated /cgi-bin/luci/ with 403 and its login form.
        reply = _http("403 Forbidden", LUCI_LOGIN, "X-LuCI-Login-Required: yes\r\n")
        with _raw_http_server(lambda path: reply) as port:
            assert [item.vendor for item in _scan(port)] == ["cudy"]


class TestTitleParsing:
    # Sized so the old backtracking pattern needed several seconds for each.
    @pytest.mark.parametrize(("opening", "count"), [("<title>", 10000), ("<title", 37000)])
    def test_unclosed_titles_parse_in_linear_time(self, opening, count):
        body = "luci" + opening * count
        started = time.monotonic()

        assert CudyDiscovery._model_from_text(body) == "Cudy Router"
        assert time.monotonic() - started < 1.0

    def test_title_with_attributes_and_whitespace_is_extracted(self):
        body = '<html><head><title id="t">\n  Cudy   WR3000\n</title></head></html>'

        assert CudyDiscovery._model_from_text(body) == "Cudy WR3000"
