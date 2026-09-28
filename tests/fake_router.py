"""A stand-in Cudy LuCI server, so diagnose can be exercised without hardware.

Deliberately configurable so the awkward real-world cases can be reproduced: a
firmware with no salt, a wrong password, and a plain success. ``forbidden_on_failure``
answers a wrong password the way stock LuCI 18.06+ does: HTTP 403, the login form
and ``X-LuCI-Login-Required: yes``.
"""

import hashlib
import html
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, parse_qsl

# The login page of a real Cudy AP1300 (firmware git-26.232), reduced to what the
# login reads: served with 403, a fixed hidden username, and a per-login token that
# sysauth.js fetches from get_token rather than the one embedded in the page.
AP1300_LOGIN_PAGE = (
    b'<html><title>AP1300</title><form method="post">'
    b'<input type="hidden" name="_csrf" value="csrf-ap">'
    b'<input type="hidden" name="token" value="page-token-stale">'
    b'<input type="hidden" name="salt" value="apsalt">'
    b'<input type="hidden" name="zonename" value=""><input type="hidden" name="timeclock" value="">'
    b'<input type="hidden" name="luci_username" value="admin">'
    b'<input type="password" id="luci_password_login"><input type="hidden" name="luci_password">'
    b"</form></html>"
)
AP1300_FRESH_TOKEN = "f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8"
FIRST_BOOT_PAGE = (
    b'<html><title>AP1300</title><form method="post"><input type="hidden" name="salt" value="apsalt">'
    b'<input type="hidden" name="luci_username" value="admin">'
    b'<input type="password" id="luci_password_create"><input type="hidden" name="luci_password"></form></html>'
)


# The per-network Wi-Fi forms of a real AP1300, captured with every real value (name,
# password, RADIUS fields, token, MACs) replaced by the dummies below.
FIXTURES = Path(__file__).parent / "fixtures" / "cudy"
AP1300_WIFI_PATH = "/cgi-bin/luci/admin/network/wireless/config/multi_ssid_add_edit_ssid/"


def ap1300_wifi_page(iface: str, network: dict) -> bytes:
    text = (FIXTURES / f"ap1300_edit_{iface}.html").read_text()
    for option in ("ssid", "key"):
        value = html.escape(network[option], quote=True)
        text = re.sub(
            rf'(name="cbid\.wireless\.{iface}\.{option}"[^>]*?value=")[^"]*(")',
            lambda match, value=value: match.group(1) + value + match.group(2),
            text,
        )
    text = text.replace(' selected="selected"', "") if network.get("encryption") else text
    if network.get("encryption"):
        text = re.sub(
            rf'(id="cbi-wireless-{iface}-encryption-{re.escape(network["encryption"])}" value="[^"]*")',
            r'\1 selected="selected"',
            text,
        )
        # nas_id lost its selected option to the blanket removal above; the page's default is _apmac_.
        text = text.replace('<option  value="_apmac_">', '<option  value="_apmac_" selected="selected">')
    return text.encode()


def make_handler(mode: str):
    class Handler(BaseHTTPRequestHandler):
        state = {
            "logged_in": False,
            "login_posts": 0,
            "tokens_issued": 0,
            "wifi": {
                "wlan00": {"ssid": "Example-2G", "key": "old-password-1", "encryption": "psk-mixed"},
                "wlan10": {"ssid": "Example-5G", "key": "old-password-1", "encryption": "psk-mixed"},
            },
            "wifi_posts": [],
        }
        lock = threading.Lock()

        def log_message(self, *args):
            return

        def _send(self, code, body: bytes, ctype="text/html; charset=utf-8", cookie=None, headers=None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            if cookie:
                self.send_header("Set-Cookie", cookie)
            for name, value in (headers or {}).items():
                self.send_header(name, value)
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
                if mode == "ap1300":
                    return self._send(403, AP1300_LOGIN_PAGE)
                if mode == "first_boot":
                    return self._send(403, FIRST_BOOT_PAGE)
                return self._send(
                    200,
                    b'<html><title>Login</title><form><input name="_csrf" value="csrf-abc">'
                    b'<input name="token" value="tok-xyz"><input name="salt" value="saltsalt">'
                    b'<input name="luci_username"><input name="password"></form></html>',
                )
            if self.path.startswith(AP1300_WIFI_PATH) and mode == "ap1300":
                iface = self.path[len(AP1300_WIFI_PATH):]
                if iface not in self.state["wifi"]:
                    return self._send(404, b"<html>not found</html>")
                return self._send(200, ap1300_wifi_page(iface, self.state["wifi"][iface]))
            if self.path == "/cgi-bin/luci/admin/system/reboot/apply" and mode == "ap1300":
                if not (self.state["logged_in"] and "sysauth=" in self.headers.get("Cookie", "")):
                    return self._send(403, AP1300_LOGIN_PAGE)
                self.state["reboots"] = self.state.get("reboots", 0) + 1
                return self._send(200, b"")
            if self.path == "/cgi-bin/luci/admin/system/reboot" and mode == "ap1300":
                # The real page reboots only when a browser runs its script.
                script = b"$.get('/cgi-bin/luci/admin/system/reboot/apply')"
                return self._send(200, b"<html><script>" + script + b"</script></html>")
            if self.path.startswith("/cgi-bin/luci/admin"):
                return self._send(200, b"<html>admin page</html>")
            return self._send(404, b"<html>not found</html>")

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length).decode()
            if self.path.startswith(AP1300_WIFI_PATH) and mode == "ap1300":
                iface = self.path[len(AP1300_WIFI_PATH):]
                posted = parse_qsl(raw, keep_blank_values=True)
                self.state["wifi_posts"].append((iface, posted))
                if not self.state.get("ignore_wifi_writes"):
                    values = dict(posted)
                    network = self.state["wifi"][iface]
                    for option in ("ssid", "key", "encryption"):
                        network[option] = values.get(f"cbid.wireless.{iface}.{option}", network[option])
                return self._send(200, ap1300_wifi_page(iface, self.state["wifi"][iface]))
            if self.path == "/cgi-bin/luci/admin/system/reboot/call" and mode == "ap1300":
                # What the adapter used to send: the AP1300 has no such action.
                self.state["posted_reboot_call"] = True
                return self._send(404, b"<html>not found</html>")
            if self.path == "/cgi-bin/luci/admin/get_token" and mode in {"ap1300", "first_boot"}:
                with self.lock:
                    self.state["tokens_issued"] += 1
                    # Like the real AP1300, only the most recently issued token is valid.
                    token = f"{AP1300_FRESH_TOKEN[:-4]}{self.state['tokens_issued']:04d}"
                    self.state["current_token"] = token
                return self._send(200, token.encode(), ctype="text/plain")
            if mode in {"ap1300", "first_boot"} and "luci_username" in raw:
                with self.lock:
                    self.state["login_posts"] += 1
                # Checked after a pause, so a second login that asked for a token in
                # the meantime has already invalidated this one, as on the hardware.
                time.sleep(self.state.get("login_delay", 0.0))
                if self.state.pop("steal_next_token", False):
                    # Someone else (the router's own web UI) logged in mid-way.
                    with self.lock:
                        self.state["tokens_issued"] += 1
                        self.state["current_token"] = f"{AP1300_FRESH_TOKEN[:-4]}{self.state['tokens_issued']:04d}"
                form = {k: v[0] for k, v in parse_qs(raw).items()}
                first = hashlib.sha256(("goodpass" + "apsalt").encode()).hexdigest()
                expected = hashlib.sha256((first + self.state.get("current_token", "")).encode()).hexdigest()
                if form.get("luci_username") == "admin" and form.get("luci_password") == expected:
                    self.state["logged_in"] = True
                    return self._send(302, b"", cookie="sysauth=APSESSION0123456789; Path=/")
                return self._send(403, AP1300_LOGIN_PAGE, headers={"X-LuCI-Login-Required": "yes"})
            if "luci_username" in raw:
                form = {k: v[0] for k, v in parse_qs(raw).items()}
                first = hashlib.sha256(("goodpass" + "saltsalt").encode()).hexdigest()
                expected = hashlib.sha256((first + "tok-xyz").encode()).hexdigest()
                if form.get("luci_password") == expected:
                    self.state["logged_in"] = True
                    return self._send(302, b"", cookie="sysauth=SESSIONVALUE; Path=/")
                if mode == "forbidden_on_failure":
                    return self._send(
                        403,
                        b'<html><form><input name="luci_username"><input name="password"></form></html>',
                        headers={"X-LuCI-Login-Required": "yes"},
                    )
                return self._send(200, b'<html><form><input name="luci_username"></form><p>wrong password</p></html>')
            return self._send(200, b'{"ok":true}')

    return Handler


class FakeRouter:
    def __init__(self, mode: str = "ok"):
        # Threaded, so concurrent logins can interleave the way they do on a router.
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(mode))
        self.server.daemon_threads = True
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

    @property
    def state(self) -> dict:
        return self.server.RequestHandlerClass.state


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
