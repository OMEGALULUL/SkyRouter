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


# --- TP-Link (old 11N web UI) -----------------------------------------------------
#
# Reproduces the two behaviours that matter for the adapter:
#   * auth lives in a cookie called "Authorization", not a header
#   * failed logins increment authTimes, and 10 of them lock the UI
#
# The page bodies mimic the WR840N structure that was confirmed against the real
# device: modelName/modelDesc variables on the login page, uptime and firmware
# strings on the status page, and MAC/IP/host records on the DHCP table page.

TP_LINK_STATUS_PAGE = b"""<html><head><title>System Status</title></head><body>
<script>var modelName="TL-WR840N"; var modelDesc="TP-Link Wireless N Router WR840N";</script>
<table>
<tr><td>Model No.</td><td>TL-WR840N</td></tr>
<tr><td>Firmware Version</td><td>3.14.3 1.0.0 Build 20130628 Rel.40000n</td></tr>
<tr><td>Uptime</td><td>12345:06:07</td></tr>
</table></body></html>"""

TP_LINK_CLIENTS_PAGE = b"""<html><head><title>DHCP Client</title></head><body>
<script>
var t1 = new TClient("AA:BB:CC:DD:EE:01","192.168.0.101","laptop");
var t2 = new TClient("AA:BB:CC:DD:EE:02","192.168.0.102","phone");
var t3 = new TClient("AA-BB-CC-DD-EE-03","192.168.0.103","");
</script></body></html>"""

TP_LINK_REBOOT_PAGE = b"""<html><body>
<form action="/userRpm/SysRebootRpm.htm" method="post">
<input type="hidden" name="reboot" value="Reboot"/>
</form></body></html>"""


def make_tplink_handler(password: str = "admin", max_attempts: int = 10):
    """A stand-in for the old TP-Link web UI.

    ``password`` is the one the fake accepts. A wrong password increments
    ``authTimes`` and, once ``max_attempts`` is reached, serves the lockout page
    instead of the status page.
    """

    class Handler(BaseHTTPRequestHandler):
        state = {"attempts": 0, "reboots": 0}

        def log_message(self, *args):
            return

        def _send(self, code, body: bytes, ctype="text/html; charset=utf-8"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _login_page(self):
            attempts = self.state["attempts"]
            if attempts >= max_attempts:
                note = f"You have exceeded ten attempts. Please try again in {7200}s."
            elif attempts > 0:
                note = "The username or password is incorrect, please try again."
            else:
                note = ""
            return (
                f"<html><body><p>NOTE: {note}</p></body></html>"
                '<script>var authTimes='
                f"{attempts}; var forbidTime=0; var modelName=\"TL-WR840N\";</script>"
                "</html>"
            ).encode()

        def _authed(self) -> bool:
            cookie = self.headers.get("Cookie", "")
            if not cookie.startswith("Authorization=Basic "):
                return False
            import base64

            try:
                raw = base64.b64decode(cookie[len("Authorization=Basic ") :]).decode()
            except (ValueError, UnicodeDecodeError):
                return False
            return raw == f"admin:{password}"

        def do_GET(self):
            if self.path == "/":
                return self._send(200, self._login_page())
            if self.path not in {
                "/userRpm/StatusRpm.htm",
                "/userRpm/DhcpTableRpm.htm",
                "/userRpm/SysRebootRpm.htm",
            }:
                return self._send(404, b"<html>not found</html>")
            if not self._authed():
                # Real firmware refuses protected pages outright, and counts the
                # rejected attempt. This is the only place a try is consumed.
                self.state["attempts"] += 1
                return self._send(403, b"<html>forbidden</html>")
            if self.state["attempts"] >= max_attempts:
                return self._send(200, self._login_page())
            if self.path == "/userRpm/StatusRpm.htm":
                return self._send(200, TP_LINK_STATUS_PAGE)
            if self.path == "/userRpm/DhcpTableRpm.htm":
                return self._send(200, TP_LINK_CLIENTS_PAGE)
            return self._send(200, TP_LINK_REBOOT_PAGE)

        def do_POST(self):
            if self.path != "/userRpm/SysRebootRpm.htm":
                return self._send(404, b"<html>not found</html>")
            if not self._authed():
                self.state["attempts"] += 1
                return self._send(403, b"<html>forbidden</html>")
            self.state["reboots"] += 1
            return self._send(200, b"<html><body>Rebooting</body></html>")

        def count_attempts(self) -> int:
            return self.state["attempts"]

    return Handler


class FakeTpLink:
    def __init__(self, password: str = "admin", max_attempts: int = 10):
        self.handler = make_tplink_handler(password=password, max_attempts=max_attempts)
        self.server = HTTPServer(("127.0.0.1", 0), self.handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()

    @property
    def attempts(self) -> int:
        return self.handler.state["attempts"]

    @property
    def reboots(self) -> int:
        return self.handler.state["reboots"]
