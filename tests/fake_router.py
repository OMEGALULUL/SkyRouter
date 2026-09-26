"""A stand-in Cudy LuCI server, so diagnose can be exercised without hardware.

Deliberately configurable so the awkward real-world cases can be reproduced: a
firmware with no salt, a wrong password, and a plain success.
"""

import hashlib
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs


def make_handler(mode: str):
    class Handler(BaseHTTPRequestHandler):
        state = {"logged_in": False}

        def log_message(self, *args):
            return

        def _send(self, code, body: bytes, ctype="text/html; charset=utf-8", cookie=None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            if cookie:
                self.send_header("Set-Cookie", cookie)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path in {"/", "/cgi-bin/luci/"}:
                if self.state["logged_in"] and "sysauth" in self.headers.get("Cookie", ""):
                    return self._send(200, b"<html><title>Router</title><h1>Dashboard</h1></html>")
                if mode == "no_salt":
                    return self._send(
                        200,
                        b'<html><title>Login</title><form><input name="_csrf" value="tok1">'
                        b'<input name="luci_username"></form></html>',
                    )
                if mode == "wrong_path":
                    return self._send(404, b"<html>not found</html>")
                return self._send(
                    200,
                    b'<html><title>Login</title><form><input name="_csrf" value="csrf-abc">'
                    b'<input name="token" value="tok-xyz"><input name="salt" value="saltsalt">'
                    b'<input name="luci_username"><input name="password"></form></html>',
                )
            if self.path.startswith("/cgi-bin/luci/admin"):
                return self._send(200, b"<html>admin page</html>")
            return self._send(404, b"<html>not found</html>")

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length).decode()
            if "luci_username" in raw:
                form = {k: v[0] for k, v in parse_qs(raw).items()}
                first = hashlib.sha256(("goodpass" + "saltsalt").encode()).hexdigest()
                expected = hashlib.sha256((first + "tok-xyz").encode()).hexdigest()
                if form.get("luci_password") == expected:
                    self.state["logged_in"] = True
                    return self._send(302, b"", cookie="sysauth=SESSIONVALUE; Path=/")
                return self._send(200, b'<html><form><input name="luci_username"></form><p>wrong password</p></html>')
            return self._send(200, b'{"ok":true}')

    return Handler


class FakeRouter:
    def __init__(self, mode: str = "ok"):
        self.server = HTTPServer(("127.0.0.1", 0), make_handler(mode))
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"
