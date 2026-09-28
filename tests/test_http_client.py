import socket
import threading
import time

import pytest

from cudy_manager.http_client import HttpError, HttpResponse, HttpSession


def response(body: str, content_type: str = "text/html; charset=utf-8", raw: bytes | None = None) -> HttpResponse:
    return HttpResponse(
        status=200,
        headers={"Content-Type": content_type},
        body=raw if raw is not None else body.encode(),
        url="http://192.168.1.1/",
    )


class TestCharsetHandling:
    def test_html_charset_is_not_used_as_codec(self):
        parsed = response("<html><body>hi</body></html>", "text/html; charset=utf-8")
        assert parsed.text == "<html><body>hi</body></html>"

    def test_plain_text_content_type(self):
        assert response("plain", "text/plain").text == "plain"

    def test_declared_charset_is_honoured(self):
        parsed = response("olá", "text/html; charset=latin-1", raw="olá".encode("latin-1"))
        assert parsed.text == "olá"

    def test_quoted_charset(self):
        assert response("ok", 'text/html; charset="utf-8"').text == "ok"

    def test_invalid_charset_falls_back(self):
        assert response("ok", "text/html; charset=not-a-codec").text == "ok"

    def test_json_decoding(self):
        assert response('{"a": 1}', "application/json").json() == {"a": 1}

    def test_invalid_json_raises(self):
        with pytest.raises(HttpError):
            response("not json", "application/json").json()


class TestUrlValidation:
    def test_relative_paths_are_joined_to_base(self):
        session = HttpSession("http://192.168.1.1:8080")
        assert session.url("/cgi-bin/luci/") == "http://192.168.1.1:8080/cgi-bin/luci/"
        assert session.url("cgi-bin/luci/") == "http://192.168.1.1:8080/cgi-bin/luci/"

    def test_absolute_http_urls_pass_through(self):
        session = HttpSession("http://192.168.1.1:8080")
        assert session.url("http://other/") == "http://other/"

    def test_file_scheme_is_rejected(self):
        session = HttpSession("http://192.168.1.1:8080")
        with pytest.raises(HttpError):
            session.request("GET", "file:///etc/passwd")

    def test_ftp_scheme_is_rejected(self):
        session = HttpSession("http://192.168.1.1:8080")
        with pytest.raises(HttpError):
            session.request("GET", "ftp://example.com/secret")

    def test_base_url_scheme_is_validated(self):
        session = HttpSession("file:///tmp")
        with pytest.raises(HttpError):
            session.request("GET", "/etc/passwd")


class _CannedServer:
    """Answers every connection on 127.0.0.1 with fixed bytes once the request head arrives.

    The head is read first so the client never sees a reset caused by unread data,
    which would surface as an OSError and hide the error actually under test.
    """

    def __init__(self, reply: bytes):
        self.reply = reply
        self.requests: list[bytes] = []
        self.connected = threading.Event()
        self._stop = threading.Event()
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen()
        self._sock.settimeout(0.1)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            self.connected.set()
            with conn:
                conn.settimeout(5)
                head = b""
                try:
                    while b"\r\n\r\n" not in head:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        head += chunk
                    self.requests.append(head)
                    conn.sendall(self.reply)
                    conn.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

    def close(self):
        self._stop.set()
        self._thread.join(timeout=2)
        self._sock.close()


@pytest.fixture
def canned():
    servers: list[_CannedServer] = []

    def start(reply: bytes) -> _CannedServer:
        server = _CannedServer(reply)
        servers.append(server)
        return server

    yield start
    for server in servers:
        server.close()


class TestMalformedRouterReplies:
    """Anything a router can send back must come out as HttpError, the only error callers handle."""

    @pytest.mark.parametrize(
        "reply",
        [
            pytest.param(b"SSH-2.0-dropbear_2020.81\r\n", id="non-http-service"),
            pytest.param(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort", id="short-body"),
            pytest.param(b"HTTP/1.1 500 Oops\r\nContent-Length: 100\r\n\r\nshort", id="short-error-body"),
            pytest.param(b"HTTP/1.1 200 OK\r\nX-Big: " + b"a" * 70000 + b"\r\n\r\n", id="header-line-too-long"),
            pytest.param(
                b"HTTP/1.1 200 OK\r\n" + b"".join(b"X-%d: y\r\n" % n for n in range(101)) + b"\r\n",
                id="too-many-headers",
            ),
            pytest.param(
                b"HTTP/1.1 302 Found\r\nLocation: http://[bad\r\nContent-Length: 0\r\n\r\n",
                id="unparseable-location",
            ),
        ],
    )
    def test_reply_becomes_http_error(self, canned, reply):
        server = canned(reply)
        session = HttpSession(f"http://127.0.0.1:{server.port}", timeout=5)
        with pytest.raises(HttpError):
            session.request("GET", "/", follow_redirects=True)

    def test_unparseable_second_location_header_becomes_http_error(self, canned):
        # urllib validates the first Location header; the response dict keeps the last one.
        server = canned(b"HTTP/1.1 302 Found\r\nLocation: /ok\r\nLocation: http://[bad\r\nContent-Length: 0\r\n\r\n")
        session = HttpSession(f"http://127.0.0.1:{server.port}", timeout=5)
        with pytest.raises(HttpError):
            session.request("GET", "/", follow_redirects=True)

    @pytest.mark.parametrize(
        "path",
        [
            pytest.param("http://[::1/", id="bad-ipv6-literal"),
            pytest.param("/reboot now", id="space-in-path"),
            pytest.param("http://127.0.0.1:notaport/", id="non-numeric-port"),
        ],
    )
    def test_unusable_url_becomes_http_error(self, canned, path):
        # TP-Link form actions come from the router's own HTML, so the path is not ours to trust.
        server = canned(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        session = HttpSession(f"http://127.0.0.1:{server.port}", timeout=5)
        with pytest.raises(HttpError):
            session.request("GET", path)


class TestProxyEnvironmentIsIgnored:
    @pytest.fixture
    def clean_proxy_env(self, monkeypatch):
        for name in ("http_proxy", "https_proxy", "all_proxy", "no_proxy"):
            monkeypatch.delenv(name, raising=False)
            monkeypatch.delenv(name.upper(), raising=False)
        return monkeypatch

    def test_http_goes_direct_despite_http_proxy(self, canned, clean_proxy_env):
        proxy = canned(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nvia-proxy")
        router = canned(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\ndirect")
        clean_proxy_env.setenv("http_proxy", f"http://127.0.0.1:{proxy.port}")
        session = HttpSession(f"http://127.0.0.1:{router.port}", timeout=5)

        result = session.request("GET", "/", headers={"Cookie": "Authorization=Basic c2VjcmV0"})

        assert result.body == b"direct"
        assert not proxy.connected.is_set()

    def test_https_is_not_tunnelled_through_https_proxy(self, canned, clean_proxy_env):
        proxy = canned(b"HTTP/1.1 200 Connection established\r\n\r\n")
        router = canned(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
        clean_proxy_env.setenv("https_proxy", f"http://127.0.0.1:{proxy.port}")
        session = HttpSession(f"https://127.0.0.1:{router.port}", timeout=1, verify_tls=False)

        with pytest.raises(HttpError):
            session.request("GET", "/")

        assert router.connected.wait(2)
        assert not proxy.connected.is_set()


class TestReasonPhrase:
    """GenieACS tells some outcomes apart only by the reason phrase, so it must survive both paths."""

    def test_success_reason_is_kept(self, canned):
        server = canned(b"HTTP/1.1 202 Accepted\r\nContent-Length: 2\r\n\r\n{}")
        result = HttpSession(f"http://127.0.0.1:{server.port}", timeout=5).request("GET", "/")
        assert (result.status, result.reason) == (202, "Accepted")

    def test_error_reason_is_kept(self, canned):
        server = canned(b"HTTP/1.1 504 Device is offline\r\nContent-Length: 17\r\n\r\nDevice is offline")
        result = HttpSession(f"http://127.0.0.1:{server.port}", timeout=5).request("GET", "/")
        assert (result.status, result.reason, result.body) == (504, "Device is offline", b"Device is offline")

    def test_reason_defaults_to_empty_for_hand_built_responses(self):
        assert response("x").reason == ""


class TestPerRequestTimeout:
    def test_request_timeout_overrides_the_session_default(self):
        # A listening socket nobody accepts on: the connection completes in the
        # kernel's backlog, and no reply ever comes.
        silent = socket.socket()
        silent.bind(("127.0.0.1", 0))
        silent.listen()
        try:
            session = HttpSession(f"http://127.0.0.1:{silent.getsockname()[1]}", timeout=30)
            started = time.monotonic()
            with pytest.raises(HttpError):
                session.request("GET", "/", timeout=0.3)
            assert time.monotonic() - started < 5
        finally:
            silent.close()

    def test_session_timeout_applies_when_none_is_given(self, monkeypatch):
        session = HttpSession("http://127.0.0.1:9", timeout=7)
        seen = []

        def fake_open(request, timeout):
            seen.append(timeout)
            raise OSError("stop here")

        monkeypatch.setattr(session.opener, "open", fake_open)
        for timeout in (None, 2.5):
            with pytest.raises(HttpError):
                session.request("GET", "/", timeout=timeout)
        assert seen == [7, 2.5]
