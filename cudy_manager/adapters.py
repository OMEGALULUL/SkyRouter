import base64
import difflib
import hashlib
import html
import json
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlencode

from .http_client import HttpError, HttpSession
from .models import Device


class AdapterError(RuntimeError):
    pass


class UnsupportedOperation(AdapterError):
    pass


class AuthenticationRejected(AdapterError):
    def __init__(self, message: str, response: Any | None = None):
        super().__init__(message)
        self.response = response


class RouterLockedOut(AuthenticationRejected):
    """The router refuses every login until its lockout expires.

    A subclass so callers that stop re-sending a refused credential keep doing so,
    while those that report the outcome can say the password went untested rather
    than that it is wrong.
    """


class ProtocolMismatch(AdapterError):
    pass


class RouterAdapter(ABC):
    def __init__(self, device: Device, password: str):
        self.device = device
        self.password = password

    @abstractmethod
    def status(self) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def reboot(self) -> bool:
        raise NotImplementedError

    def clients(self) -> list[dict[str, Any]]:
        raise UnsupportedOperation("connected-client reporting is not supported by this adapter")

    def set_ssid(self, ssid: str, radio: str | None = None) -> bool:
        raise UnsupportedOperation("SSID changes are not supported by this adapter")

    def set_wifi_password(self, password: str, radio: str | None = None) -> bool:
        raise UnsupportedOperation("Wi-Fi password changes are not supported by this adapter")

    def mesh_status(self) -> dict[str, Any]:
        raise UnsupportedOperation("mesh status is not supported by this adapter")

    def firmware_info(self) -> dict[str, Any]:
        """``{"version", "hardware", "auto_update", "source"}``.

        ``auto_update`` is None where the router has no automatic update this adapter
        can read, else ``{"enabled", "window_start_hour", "window"}`` (a 2-hour window
        such as "03:00-05:00"; the hour and window are None when none is set).
        """
        raise UnsupportedOperation("firmware information is not supported by this adapter")

    def set_auto_update(self, enabled: bool, window_start_hour: int | None = None) -> bool:
        raise UnsupportedOperation("firmware auto-update settings are not supported by this adapter")

    def check_firmware_update(self, timeout: float = 60) -> dict[str, Any]:
        """``{"available": bool | None, "current", "latest", "note"}``; a check installs nothing."""
        raise UnsupportedOperation("firmware update checks are not supported by this adapter")


class _FormParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.inputs: dict[str, str] = {}
        self.forms: list[dict[str, Any]] = []
        self._form: dict[str, Any] | None = None
        self._cell: list[str] | None = None
        self._row: list[str] | None = None
        self.rows: list[list[str]] = []
        self.title: list[str] = []
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key: value or "" for key, value in attrs}
        if tag == "input" and values.get("name"):
            self.inputs[values["name"]] = values.get("value", "")
        if tag == "form":
            self._form = {
                "action": values.get("action", ""),
                "method": values.get("method", "get").upper(),
                "inputs": {},
            }
        elif self._form is not None and tag == "input" and values.get("name"):
            self._form["inputs"][values["name"]] = values.get("value", "")
        if tag == "tr":
            self._row = []
        elif tag in {"td", "th"} and self._row is not None:
            self._cell = []
        if tag == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None
        if tag in {"td", "th"} and self._cell is not None and self._row is not None:
            self._row.append(" ".join("".join(self._cell).split()))
            self._cell = None
        if tag == "tr" and self._row is not None:
            if any(self._row):
                self.rows.append(self._row)
            self._row = None
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._cell is not None:
            self._cell.append(data)
        if self._in_title:
            self.title.append(data)


def _host_for_url(host: str) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


def _uptime_seconds(value: Any) -> int | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.isdigit():
        return int(text)
    day_clock = re.match(r"^(\d+)\s+(\d+):(\d{2}):(\d{2})$", text)
    if day_clock:
        return (
            int(day_clock.group(1)) * 86400
            + int(day_clock.group(2)) * 3600
            + int(day_clock.group(3)) * 60
            + int(day_clock.group(4))
        )
    days = re.search(r"(\d+)\s*(?:days?|d)\b", text, re.IGNORECASE)
    clock = re.search(r"(\d+):(\d{2}):(\d{2})", text)
    if not days and not clock:
        return None
    total = 0
    if days:
        total += int(days.group(1)) * 86400
    if clock:
        total += int(clock.group(1)) * 3600 + int(clock.group(2)) * 60 + int(clock.group(3))
    return total


def _labelled_value(rows: list[list[str]], *labels: str) -> str:
    """The cell after the first cell naming one of ``labels``.

    Cudy status tables are label/value rows, and each cell holds the same text
    twice (a desktop and a mobile copy), so the doubled text is collapsed.
    """
    for row in rows:
        for index, cell in enumerate(row[:-1]):
            if any(label in cell.lower() for label in labels):
                words = row[index + 1].split()
                half = len(words) // 2
                if words and len(words) % 2 == 0 and words[:half] == words[half:]:
                    words = words[:half]
                return " ".join(words)
    return ""


_DURATION = re.compile(r"\d+\s*(?:days?|d)\s*\d{1,2}:\d{2}:\d{2}|\d{1,2}:\d{2}:\d{2}|\d+", re.IGNORECASE)


def _looks_like_login(text: str) -> bool:
    lowered = text.lower()
    return "luci_username" in lowered or "name=\"password\"" in lowered or "wrong password" in lowered


def _luci_login_required(response: Any) -> bool:
    return any(
        key.lower() == "x-luci-login-required" and str(value).strip().lower() == "yes"
        for key, value in response.headers.items()
    )


_CUDY_CHALLENGE_PATH = "/cgi-bin/luci/admin/get_token"
_CUDY_CHALLENGE = re.compile(r"[A-Za-z0-9]{8,128}")
_CUDY_RETRY_PAUSE = 1.0
_CUDY_WIFI_FORM = "/cgi-bin/luci/admin/network/wireless/config/multi_ssid_add_edit_ssid/{iface}"
_CUDY_WIFI_IFACES = {"2.4G": "wlan00", "5G": "wlan10"}
# Modes whose "key" field is a WPA passphrase; open and WPA-Enterprise networks have none.
_CUDY_PASSPHRASE_MODES = {"psk", "psk2", "psk-mixed", "psk2psk3", "psk3"}


def _cbi_fields(text: str) -> list[tuple[str, str]]:
    form = _CbiForm()
    form.feed(text)
    return form.fields


def _partial(done: list[str], band: str, reason: str) -> str:
    if done:
        return f"changed on {' and '.join(done)}, but not on {band}: {reason}; the bands now differ"
    return f"the router did not accept the change on {band}: {reason}; nothing was changed"


@dataclass
class CudyLoginPage:
    """What a Cudy login page asks for, read the way the router's own sysauth.js reads it."""

    csrf: str
    token: str
    salt: str
    username: str
    is_login: bool
    # Factory-fresh firmware serves a "create password" form instead: submitting it
    # sets the admin password rather than checking it.
    first_boot: bool


def parse_cudy_login_page(text: str) -> CudyLoginPage:
    parser = _FormParser()
    parser.feed(text)
    inputs = parser.inputs
    return CudyLoginPage(
        csrf=inputs.get("_csrf", ""),
        token=inputs.get("token", ""),
        salt=inputs.get("salt", ""),
        # The stock form carries a fixed hidden username ("admin") that the browser
        # always submits, whatever the device record says.
        username=inputs.get("luci_username", ""),
        is_login="luci_username" in inputs or "luci_password" in inputs,
        first_boot='id="luci_password_create"' in text and 'id="luci_password_login"' not in text,
    )


def cudy_login_form(page: CudyLoginPage, password: str, username: str, token: str) -> dict[str, str]:
    return {
        "_csrf": page.csrf,
        "token": token,
        "salt": page.salt,
        "luci_language": "auto",
        "luci_username": page.username or username,
        "luci_password": derive_cudy_password(password, page.salt, token) if page.salt else password,
        "timeclock": str(int(time.time())),
        "zonename": "UTC",
    }


def fetch_cudy_token(http: "HttpSession", referer: str) -> str | None:
    """The per-login token the browser fetches just before submitting.

    Real firmware (AP1300, git-26.232) POSTs here and hashes with the answer, not
    with the token embedded in the page; None means this firmware has no such step.
    """
    try:
        headers = {"Referer": referer, "X-Requested-With": "XMLHttpRequest"}
        reply = http.request("POST", _CUDY_CHALLENGE_PATH, b"", headers)
    except HttpError:
        return None
    token = reply.text.strip()
    return token if reply.status == 200 and _CUDY_CHALLENGE.fullmatch(token) else None


class _CbiForm(HTMLParser):
    """The first POST form on a LuCI CBI page, as a browser would submit it.

    Cudy's Wi-Fi forms are posted back whole, so every field the router's own
    page would send must be sent unchanged: text and hidden inputs by value,
    checkboxes and radios only when checked, a select's selected option.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.action = ""
        self.fields: list[tuple[str, str]] = []
        # Per select: its option values, and the one marked selected (None when none
        # is: the browser then sends the first, which is not a value the router holds).
        self.options: dict[str, list[str]] = {}
        self.selected: dict[str, str | None] = {}
        self._in_form = False
        self._done = False
        self._select: dict[str, Any] | None = None
        self._textarea: list[str] | None = None
        self._textarea_name = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key: value or "" for key, value in attrs}
        if self._done:
            return
        if tag == "form" and not self._in_form and values.get("method", "get").lower() == "post":
            self._in_form = True
            self.action = values.get("action", "")
            return
        if not self._in_form:
            return
        name = values.get("name", "")
        if tag == "input" and name:
            kind = values.get("type", "text").lower()
            if kind in {"submit", "button", "image", "reset", "file"}:
                return
            if kind in {"checkbox", "radio"}:
                if "checked" in values:
                    self.fields.append((name, values.get("value", "on")))
                return
            self.fields.append((name, values.get("value", "")))
        elif tag == "select" and name:
            self._select = {"name": name, "first": None, "chosen": None, "values": []}
        elif tag == "option" and self._select is not None:
            value = values.get("value", "")
            self._select["values"].append(value)
            if self._select["first"] is None:
                self._select["first"] = value
            if "selected" in values:
                self._select["chosen"] = value
        elif tag == "textarea" and name:
            self._textarea, self._textarea_name = [], name

    def handle_data(self, data: str) -> None:
        if self._textarea is not None:
            self._textarea.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "select" and self._select is not None:
            chosen = self._select["chosen"] if self._select["chosen"] is not None else self._select["first"]
            if chosen is not None:
                self.fields.append((self._select["name"], chosen))
            self.options[self._select["name"]] = self._select["values"]
            self.selected[self._select["name"]] = self._select["chosen"]
            self._select = None
        elif tag == "textarea" and self._textarea is not None:
            self.fields.append((self._textarea_name, "".join(self._textarea)))
            self._textarea = None
        elif tag == "form" and self._in_form:
            self._in_form, self._done = False, True


_CBI_DEPENDENCY = re.compile(r'cbi_d_add\(\s*"([^"]+)"\s*,\s*(\{[^}]*\})')


def _cbi_submission(text: str, changes: dict[str, str]) -> tuple[str, list[tuple[str, str]]]:
    """What the page would POST after ``changes``, with its dependency rules applied.

    ``cbi_d_update`` in the browser removes a field whose ``cbi_d_add`` conditions
    are all unmet before the form is sent; the RADIUS fields, for instance, only
    exist while encryption is WPA-Enterprise.
    """
    form = _CbiForm()
    form.feed(text)
    missing = [name for name in changes if name not in {field for field, _ in form.fields}]
    if missing:
        raise ProtocolMismatch(f"Cudy form has no field {missing[0]}; this firmware uses a different page")
    fields = [(name, changes.get(name, value)) for name, value in form.fields]
    rules: dict[str, list[dict[str, str]]] = {}
    for target, raw in _CBI_DEPENDENCY.findall(text):
        try:
            rule = json.loads(raw)
        except ValueError:
            continue
        rules.setdefault(target, []).append({str(key): str(value) for key, value in rule.items()})
    visible = dict(fields)
    kept = []
    for name, value in fields:
        options = rules.get("cbi-" + name.removeprefix("cbid.").replace(".", "-"))
        if options and not any(all(visible.get(key) == want for key, want in rule.items()) for rule in options):
            continue
        kept.append((name, value))
    return form.action, kept


# The Auto Update page of a real AP1300 (2.5.25) and the requests its own script
# makes to check for new firmware.
_CUDY_AUTOUPGRADE_PAGE = "/cgi-bin/luci/admin/system/autoupgrade?nomodal="
_CUDY_UPDATE_CHECK = "/cgi-bin/luci/admin/system/autoupgrade/updatecheck"
_CUDY_CHECK_STATUS = "/cgi-bin/luci/admin/system/autoupgrade/checkstatus/000000000000"
_CUDY_CHECK_RESULT = "/cgi-bin/luci/admin/system/autoupgrade?updatecheck=&nomodal="
_CUDY_CHECK_POLL = 1.0
_CUDY_AUTO_UPGRADE = "cbid.upgrade.1.auto_upgrade"
_CUDY_UPGRADE_TIME = "cbid.upgrade.1.upgrade_time"
# Every label on the page: a value that is another label means the value was empty.
_CUDY_FIRMWARE_LABELS = {
    "auto update", "current time", "update time", "firmware version", "hardware", "firmware file path",
}
# Three dotted numbers, so neither the hardware revision ("V1.1") nor an IP address
# reads as a firmware version.
_FIRMWARE_VERSION = re.compile(r"(?<![\w.])[vV]?(\d+\.\d+\.\d+(?:-\w+)*)(?!\w|\.\d)")
_NEWER_WORDS = re.compile(r"\b(?:new|newer|newest|latest|available)\b", re.IGNORECASE)
_AVAILABLE_AFTER = re.compile(r"\s*(?:is\s+)?(?:now\s+)?available\b", re.IGNORECASE)
_LATEST_WORDS = re.compile(r"\b(?:latest|newest)\b", re.IGNORECASE)
_UP_TO_DATE = re.compile(
    r"\balready\s+(?:running\s+|on\s+)?(?:the\s+)?(?:latest|newest|up[\s-]to[\s-]date)"
    r"|\bup[\s-]to[\s-]date\b"
    r"|\bno\s+(?:new|newer)\s+(?:firmware|version|update)"
    r"|\bno\s+(?:firmware\s+)?updates?\s+(?:is\s+|are\s+)?(?:available|found)",
    re.IGNORECASE,
)


class _PageText(HTMLParser):
    """The text a browser shows, one entry per text node; scripts and styles are left out."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.chunks: list[str] = []
        self._hidden = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style"}:
            self._hidden += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"} and self._hidden:
            self._hidden -= 1

    def handle_data(self, data: str) -> None:
        text = " ".join(data.split())
        if text and not self._hidden:
            self.chunks.append(text)


def _page_text(text: str) -> list[str]:
    parser = _PageText()
    parser.feed(text)
    return parser.chunks


def _static_after(chunks: list[str], label: str) -> str:
    """The static text shown after ``label``, as a CBI page shows a read-only value.

    Labels and values may each be doubled (a desktop and a mobile copy), so repeats
    of the label are skipped; whole-chunk matching keeps a "Firmware" menu link from
    passing for the "Firmware Version" label.
    """
    want = label.lower()
    for index, chunk in enumerate(chunks):
        text = chunk.lower()
        if text.rstrip(": ") == want:
            for following in chunks[index + 1 :]:
                bare = following.lower().rstrip(": ")
                if bare == want:
                    continue
                return "" if bare in _CUDY_FIRMWARE_LABELS else following
            return ""
        if text.startswith(want + ":"):
            return chunk[len(label) + 1 :].strip()
    return ""


def _cudy_firmware_details(text: str) -> tuple[str, str]:
    chunks = _page_text(text)
    version = re.match(r"v?\d[\w.-]*", _static_after(chunks, "firmware version"), re.IGNORECASE)
    return (version.group(0) if version else ""), _static_after(chunks, "hardware")


def _update_window(hour: int) -> str:
    return f"{hour:02d}:00-{(hour + 2) % 24:02d}:00"


def _window_hour(value: str | None) -> int | None:
    if value is None or not value.isdigit() or not 0 <= int(value) <= 23:
        return None
    return int(value)


def _cudy_auto_update(form: "_CbiForm") -> dict[str, Any] | None:
    switch = dict(form.fields).get(_CUDY_AUTO_UPGRADE)
    if switch not in {"0", "1"}:
        return None
    # The window stays in the page while auto-update is off (only hidden), so it is
    # the one the router will use when it is turned back on.
    hour = _window_hour(form.selected.get(_CUDY_UPGRADE_TIME))
    return {
        "enabled": switch == "1",
        "window_start_hour": hour,
        "window": _update_window(hour) if hour is not None else None,
    }


def _version_key(version: str) -> tuple[int, ...]:
    return tuple(int(number) for number in re.findall(r"\d+", version))


def _cudy_update_result(before: str, after: str, current: str) -> dict[str, Any]:
    """What the router's update check says, read only from what it added to the page.

    The result page's markup has not been seen on real hardware. The page before the
    check is the same page without the result, so only the text the check changed
    is read: the page's own labels, help text and current version cannot be taken
    for an answer. A newer version must be named beside a word such as "new" or
    "latest"; anything less, or an answer that contradicts itself, is not a result.
    """
    old, new = _page_text(before), _page_text(after)
    newer: list[str] = []
    said_current = named_current = False
    matcher = difflib.SequenceMatcher(None, old, new, autojunk=False)
    for tag, _, _, start, end in matcher.get_opcodes():
        if tag not in {"insert", "replace"}:
            continue
        # The two chunks before the change are its context: a label the page already
        # had ("Latest Version") may be the one a filled-in value belongs to.
        lead = " ".join(new[max(0, start - 2) : start])
        block = " ".join(new[start:end])
        if _UP_TO_DATE.search(block):
            said_current = True
        text = f"{lead} {block}"
        previous_end = 0
        for match in _FIRMWARE_VERSION.finditer(text):
            context = text[max(previous_end, match.start() - 60) : match.start()]
            previous_end = match.end()
            if match.start() <= len(lead):
                continue
            version = match.group(1)
            if current and _version_key(version) > _version_key(current):
                if _NEWER_WORDS.search(context) or _AVAILABLE_AFTER.match(text, match.end()):
                    newer.append(version)
            elif current and _version_key(version) == _version_key(current) and _LATEST_WORDS.search(context):
                said_current = named_current = True
    result: dict[str, Any] = {"available": None, "current": current, "latest": None}
    if newer and not said_current:
        latest = max(newer, key=_version_key)
        result.update(available=True, latest=latest)
        result["note"] = f"the router reports firmware {latest} is available; nothing was installed"
    elif said_current and not newer:
        result.update(available=False, latest=current if named_current else None)
        result["note"] = "the router reports it already runs the latest firmware"
    elif newer:
        result["note"] = (
            "result not recognised: the router's answer both names a newer version and says the firmware is current"
        )
    else:
        result["note"] = (
            "result not recognised: the router finished its update check, but the result page did not say "
            "whether newer firmware exists"
        )
    return result


def derive_cudy_password(password: str, salt: str, token: str = "") -> str:
    value = hashlib.sha256((password + salt).encode()).hexdigest()
    if token:
        value = hashlib.sha256((value + token).encode()).hexdigest()
    return value


class CudyAdapter(RouterAdapter):
    def __init__(self, device: Device, password: str):
        super().__init__(device, password)
        scheme = "https" if device.https else "http"
        self.base_url = f"{scheme}://{_host_for_url(device.host)}:{device.http_port}"
        self.http = HttpSession(self.base_url, verify_tls=device.verify_tls)
        self.authenticated = False
        self.csrf_token = ""
        self.token = ""
        self.salt = ""
        self.session_id = ""

    def _get(self, path: str):
        try:
            return self.http.request("GET", path, headers={"Referer": f"{self.base_url}/cgi-bin/luci/"})
        except HttpError as exc:
            raise AdapterError(str(exc)) from exc

    def _post(self, path: str, data: dict[str, str] | None = None, json_body: Any = None):
        headers = {"Referer": f"{self.base_url}/cgi-bin/luci/", "X-Requested-With": "XMLHttpRequest"}
        body = None
        if json_body is not None:
            body = json.dumps(json_body).encode()
            headers["Content-Type"] = "application/json"
        elif data is not None:
            body = urlencode(data).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        try:
            return self.http.request("POST", path, body, headers)
        except HttpError as exc:
            raise AdapterError(str(exc)) from exc

    def login(self) -> bool:
        if self.authenticated:
            return True
        try:
            return self._login_once()
        except AuthenticationRejected as exc:
            if not getattr(exc, "cudy_token_may_be_stale", False):
                raise
            # A Cudy keeps one valid login token: anyone logging in meanwhile, even
            # the operator in the router's own web UI, invalidates ours, and the
            # router then answers exactly as it does to a wrong password. One retry
            # with a fresh token tells the two apart; a wrong password is refused again.
            time.sleep(_CUDY_RETRY_PAUSE)
            return self._login_once()

    def _login_once(self) -> bool:
        response = self._get("/cgi-bin/luci/")
        page = parse_cudy_login_page(response.text)
        self.csrf_token = page.csrf
        self.token = page.token
        self.salt = page.salt
        # Stock LuCI serves its login form with 403 to anyone not yet signed in.
        if response.status >= 400 and not (response.status in {401, 403} and page.is_login):
            raise AdapterError(f"Cudy login page returned HTTP {response.status}")
        if page.first_boot:
            raise UnsupportedOperation(
                "this Cudy has no admin password yet (it shows the first-time setup page); set one in its web UI "
                "first, since signing in from here would set it"
            )
        if not self.salt and not self.csrf_token and not self.device.allow_legacy_login:
            raise ProtocolMismatch(
                "Cudy login page exposed no salt and no token, so the expected challenge/response handshake "
                "is not present; this firmware likely uses a different login flow. Check the raw exchange with "
                "'router-manager diagnose'."
            )
        if not self.salt and not self.device.allow_legacy_login:
            raise UnsupportedOperation("Cudy login did not provide a salt; enable legacy_login only on a trusted LAN")
        self.token = fetch_cudy_token(self.http, f"{self.base_url}/cgi-bin/luci/") or page.token
        form = cudy_login_form(page, self.password, self.device.username, self.token)
        result = self._post("/cgi-bin/luci/", form)
        if result.status in {401, 403} and (_looks_like_login(result.text) or _luci_login_required(result)):
            # Stock LuCI answers a wrong password with 403 and the login form. That is
            # the router saying no, and reporting it as a generic HTTP error would send
            # the operator to check the network instead of the password.
            refused = AuthenticationRejected(
                f"Cudy rejected the credentials: HTTP {result.status} with the login form",
                response=result,
            )
            refused.cudy_token_may_be_stale = bool(self.token)  # type: ignore[attr-defined]
            raise refused
        if result.status >= 400:
            raise AdapterError(f"Cudy login POST returned HTTP {result.status}")
        if result.status in {301, 302, 303} or (result.status == 200 and not _looks_like_login(result.text)):
            self.authenticated = True
        else:
            raise AuthenticationRejected(
                "Cudy rejected the credentials: the login form was returned after submitting",
                response=result,
            )
        for cookie in self.http.cookie_jar:
            if cookie.name in {"sysauth", "sysauth_https"}:
                self.session_id = cookie.value or ""
        return True

    def _session_get(self, path: str, missing_ok: bool = False):
        if not self.authenticated:
            self.login()
        response = self._get(path)
        if response.status in {401, 403}:
            self.authenticated = False
            self.login()
            response = self._get(path)
        if response.status == 404 and missing_ok:
            return response
        if response.status >= 400:
            raise AdapterError(f"Cudy request returned HTTP {response.status}")
        return response

    def status(self) -> dict[str, Any]:
        response = self._session_get("/cgi-bin/luci/admin/system/status")
        text = response.text
        parser = _FormParser()
        parser.feed(text)
        firmware = ""
        # The value must start with a digit and may sit in the next cell. A pattern
        # that accepts any word backtracks into the label and returns "ion" from
        # "Firmware Version".
        labelled = _labelled_value(parser.rows, "firmware", "software version")
        match = re.search(r"v?\d[\w.-]*", labelled) or re.search(
            r"(?:firmware|software)(?:\s*version)?\s*:?\s*(?:<[^>]*>\s*){0,4}(v?\d[\w.-]*)",
            text,
            re.IGNORECASE,
        )
        if match:
            firmware = html.unescape(match.group(match.lastindex or 0))
        result: dict[str, Any] = {
            "online": True,
            "firmware": firmware,
            "title": " ".join("".join(parser.title).split()),
            "source": "cudy-luci",
        }
        # Capture the whole duration expression. Matching only the leading number
        # would drop the H:MM:SS part, and would fail outright on pages that label
        # the field "Activity Time", leaving the scheduler unable to read uptime.
        # Read the value cell, not the first digit after the label: on real firmware
        # (AP1300 2.5.25) that digit belongs to the next element's id, which gave an
        # uptime of 2 seconds and would have let the scheduler reboot too early.
        duration = _DURATION.search(_labelled_value(parser.rows, "uptime", "activity time"))
        if duration:
            result["uptime_text"] = duration.group(0)
            result["uptime_seconds"] = _uptime_seconds(duration.group(0))
        else:
            inline = re.search(
                r"(?:uptime|activity time)\s*:?\s*"
                r"(\d+\s*(?:days?|d)?\s*\d{1,2}:\d{2}:\d{2}|\d{1,2}:\d{2}:\d{2}|\d+)",
                html.unescape(re.sub(r"<[^>]+>", " ", text)),
                re.IGNORECASE,
            )
            if inline:
                result["uptime_text"] = inline.group(1)
                result["uptime_seconds"] = _uptime_seconds(inline.group(1))
        return result

    def clients(self) -> list[dict[str, Any]]:
        response = self._session_get("/cgi-bin/luci/admin/network/devices/devlist?detail=1")
        parser = _FormParser()
        parser.feed(response.text)
        clients = []
        for row in parser.rows[1:]:
            if len(row) >= 2:
                clients.append({"name": row[1], "cells": row})
        return clients

    def reboot(self) -> bool:
        # What the router's own reboot page does (AP1300, 2.5.25): its script GETs
        # reboot/apply as soon as the page loads. The POST to reboot/call used before
        # came from older LuCI; this firmware answered it without restarting.
        response = self._session_get("/cgi-bin/luci/admin/system/reboot/apply", missing_ok=True)
        if response.status == 404:
            tokens = {"_csrf": self.csrf_token, "token": self.token}
            response = self._post("/cgi-bin/luci/admin/system/reboot/call", {k: v for k, v in tokens.items() if v})
        if response.status in {200, 202, 204} and not _looks_like_login(response.text):
            return True
        raise AdapterError(f"Cudy did not accept the reboot request (HTTP {response.status})")

    def _wifi_ifaces(self, radio: str | None) -> list[tuple[str, str]]:
        if radio is None:
            return list(_CUDY_WIFI_IFACES.items())
        if radio not in _CUDY_WIFI_IFACES:
            raise AdapterError("Cudy radio must be 2.4G or 5G")
        return [(radio, _CUDY_WIFI_IFACES[radio])]

    def _wifi_form(self, iface: str) -> str:
        return self._session_get(_CUDY_WIFI_FORM.format(iface=iface)).text

    def _write_wifi(self, radio: str | None, option: str, value: str) -> bool:
        """Post the band's own Wi-Fi form back with one option changed, then read it back.

        Taken from a real AP1300 (2.5.25): the page the router's UI uses for one
        network, submitted with its Save & Apply button. Every other field goes back
        exactly as the page gave it, so nothing else on the network changes.
        """
        targets = self._wifi_ifaces(radio)
        pages = {iface: self._wifi_form(iface) for _, iface in targets}
        for band, iface in targets:
            fields = dict(_cbi_fields(pages[iface]))
            if radio is not None and fields.get(f"cbid.wireless.{iface}.smart_connect") == "1":
                raise UnsupportedOperation(
                    "Smart Connect joins both bands into one network; change both bands together"
                )
            if option == "key":
                encryption = fields.get(f"cbid.wireless.{iface}.encryption", "")
                if encryption not in _CUDY_PASSPHRASE_MODES:
                    raise AdapterError(
                        f"the {band} network uses encryption {encryption or 'none'!r}, which has no Wi-Fi password "
                        "to change; set up WPA2 or WPA3 on the router first"
                    )
        done: list[str] = []
        for band, iface in targets:
            name = f"cbid.wireless.{iface}.{option}"
            action, submission = _cbi_submission(pages[iface], {name: value, "timeclock": str(int(time.time()))})
            if not action.startswith("/cgi-bin/luci/"):
                action = _CUDY_WIFI_FORM.format(iface=iface)
            submission.append(("cbi.apply", ""))
            try:
                reply = self.http.request(
                    "POST",
                    action,
                    urlencode(submission).encode(),
                    {
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Referer": f"{self.base_url}/cgi-bin/luci/admin/setup",
                    },
                )
            except HttpError as exc:
                raise AdapterError(_partial(done, band, f"no answer ({exc})")) from exc
            if reply.status >= 400 or _looks_like_login(reply.text):
                raise AdapterError(_partial(done, band, f"HTTP {reply.status}"))
            if dict(_cbi_fields(self._wifi_form(iface))).get(name) != value:
                raise AdapterError(_partial(done, band, "the router did not keep the change"))
            done.append(band)
        return True

    def set_ssid(self, ssid: str, radio: str | None = None) -> bool:
        return self._write_wifi(radio, "ssid", ssid)

    def set_wifi_password(self, password: str, radio: str | None = None) -> bool:
        return self._write_wifi(radio, "key", password)

    def mesh_status(self) -> dict[str, Any]:
        response = self._session_get("/cgi-bin/luci/admin/network/wireless")
        return {"online": response.status < 400, "source": "cudy-luci"}

    def _autoupgrade_page(self) -> str | None:
        response = self._session_get(_CUDY_AUTOUPGRADE_PAGE, missing_ok=True)
        return None if response.status == 404 else response.text

    def _require_autoupgrade_page(self) -> str:
        text = self._autoupgrade_page()
        if text is None:
            raise UnsupportedOperation("this Cudy firmware has no Auto Update page (HTTP 404)")
        return text

    def _running_version(self, text: str | None) -> tuple[str, str]:
        version, hardware = _cudy_firmware_details(text) if text is not None else ("", "")
        if not version:
            # Older pages without the Auto Update page still name it on the status page.
            version = str(self.status().get("firmware", ""))
        return version, hardware

    def firmware_info(self) -> dict[str, Any]:
        text = self._autoupgrade_page()
        version, hardware = self._running_version(text)
        form = _CbiForm()
        form.feed(text or "")
        return {"version": version, "hardware": hardware, "auto_update": _cudy_auto_update(form), "source": "cudy-luci"}

    def set_auto_update(self, enabled: bool, window_start_hour: int | None = None) -> bool:
        """Switch the router's own automatic firmware update, as its Auto Update page's Save & Apply does.

        The window is the page's 2-hour Update Time slot, named by its start hour. The
        page's dependency rule sends it only while auto-update is on, so one cannot be
        set while turning it off. The file field (manual upload) is never sent.
        """
        if not isinstance(enabled, bool):
            raise AdapterError("auto-update must be turned on or off (true or false)")
        if window_start_hour is not None and (
            isinstance(window_start_hour, bool)
            or not isinstance(window_start_hour, int)
            or not 0 <= window_start_hour <= 23
        ):
            raise AdapterError("the update window's start hour must be a whole hour from 0 to 23")
        if not enabled and window_start_hour is not None:
            raise AdapterError("an update window can only be set while turning auto-update on")
        text = self._require_autoupgrade_page()
        form = _CbiForm()
        form.feed(text)
        if _cudy_auto_update(form) is None:
            raise ProtocolMismatch("the Cudy Auto Update page has no Auto Update switch; this firmware differs")
        changes = {_CUDY_AUTO_UPGRADE: "1" if enabled else "0", "timeclock": str(int(time.time()))}
        hour = window_start_hour
        if enabled:
            if hour is None:
                hour = _window_hour(form.selected.get(_CUDY_UPGRADE_TIME))
                if hour is None:
                    # The browser would send the list's first slot (00:00), which nobody chose.
                    raise AdapterError("the router has no update window set; choose a start hour (0-23) to turn it on")
            if str(hour) not in form.options.get(_CUDY_UPGRADE_TIME, []):
                raise ProtocolMismatch(f"the router's Update Time list has no window starting at {hour:02d}:00")
            changes[_CUDY_UPGRADE_TIME] = str(hour)
        action, submission = _cbi_submission(text, changes)
        if not action.startswith("/cgi-bin/luci/"):
            action = _CUDY_AUTOUPGRADE_PAGE
        submission.append(("cbi.apply", ""))
        try:
            reply = self.http.request(
                "POST",
                action,
                urlencode(submission).encode(),
                {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Referer": f"{self.base_url}{_CUDY_AUTOUPGRADE_PAGE}",
                },
            )
        except HttpError as exc:
            raise AdapterError(f"the router did not answer the auto-update change ({exc})") from exc
        if reply.status >= 400 or _looks_like_login(reply.text):
            raise AdapterError(f"the router did not accept the auto-update change (HTTP {reply.status})")
        check = _CbiForm()
        check.feed(self._require_autoupgrade_page())
        now = _cudy_auto_update(check)
        kept = now is not None and now["enabled"] == enabled and (not enabled or now["window_start_hour"] == hour)
        if not kept:
            shown = "no Auto Update switch" if now is None else "auto-update " + ("on" if now["enabled"] else "off")
            if now is not None and now["enabled"]:
                shown += f", window {now['window'] or 'unset'}"
            raise AdapterError(f"the router did not keep the auto-update change; it now shows {shown}")
        return True

    def check_firmware_update(self, timeout: float = 60) -> dict[str, Any]:
        """Have the router look for newer firmware, the way its Auto Update page's script does.

        A check installs nothing. ``available`` is None whenever the router's answer
        cannot be read with certainty (see ``_cudy_update_result``).
        """
        before = self._require_autoupgrade_page()
        current, _ = self._running_version(before)
        token = dict(_cbi_fields(before)).get("token", "")
        if not token:
            raise ProtocolMismatch("the Cudy Auto Update page carried no form token to start an update check with")
        reply = self._post(_CUDY_UPDATE_CHECK, {"token": token})
        if reply.status == 404:
            raise ProtocolMismatch("this Cudy firmware has no update check (HTTP 404)")
        if reply.status >= 400 or _looks_like_login(reply.text):
            raise AdapterError(f"the router did not start its update check (HTTP {reply.status})")
        deadline = time.monotonic() + timeout
        while True:
            answer = self._session_get(_CUDY_CHECK_STATUS).text.strip()
            if answer == "checkdone":
                break
            if answer == "timeout":
                note = "the router's own update check timed out, so it could not say whether newer firmware exists"
                return {"available": None, "current": current, "latest": None, "note": note}
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                note = f"the router had not finished its update check after {timeout:g} s"
                return {"available": None, "current": current, "latest": None, "note": note}
            time.sleep(min(_CUDY_CHECK_POLL, remaining))
        return _cudy_update_result(before, self._session_get(_CUDY_CHECK_RESULT).text, current)


class _TendaModuleError(AdapterError):
    """The router answered, but refused the requested module (errCode)."""


def _json_object(result: Any, what: str) -> dict[str, Any]:
    try:
        data = result.json()
    except HttpError as exc:
        raise AdapterError(f"{what} returned invalid JSON") from exc
    if not isinstance(data, dict):
        raise ProtocolMismatch(f"{what} returned JSON that is not an object: {result.text[:80]!r}")
    return data


def _block(data: dict[str, Any], key: str) -> dict[str, Any]:
    value = data.get(key)
    return value if isinstance(value, dict) else {}


class TendaAdapter(RouterAdapter):
    def __init__(self, device: Device, password: str):
        super().__init__(device, password)
        scheme = "https" if device.https else "http"
        self.base_url = f"{scheme}://{_host_for_url(device.host)}:{device.http_port}"
        self.http = HttpSession(self.base_url, verify_tls=device.verify_tls)
        self.cookie = ""

    def _post(self, path: str, payload: dict[str, Any]):
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Connection": "close",
        }
        try:
            return self.http.request("POST", path, json.dumps(payload).encode(), headers)
        except HttpError as exc:
            raise AdapterError(str(exc)) from exc

    def login(self) -> bool:
        now = time.localtime()
        time_value = ";".join(
            str(value)
            for value in (
                now.tm_year,
                now.tm_mon,
                now.tm_mday,
                now.tm_hour,
                now.tm_min,
                now.tm_sec,
            )
        )
        encoded = base64.b64encode(self.password.encode()).decode()
        result = self._post(
            "/goform/modules?login",
            {"sysLogin": {"password": encoded, "logoff": False, "timeZone": 20, "time": time_value}},
        )
        if result.status >= 400:
            raise AdapterError(f"Tenda login returned HTTP {result.status}")
        data = _json_object(result, "Tenda login")
        login = _block(data, "sysLogin")
        if not login.get("Login"):
            detail = login.get("errMsg") or data.get("errMsg") or ""
            raise AuthenticationRejected(
                f"Tenda rejected the credentials{' (' + str(detail) + ')' if detail else ''}",
                response=result,
            )
        for cookie in self.http.cookie_jar:
            self.cookie = f"{cookie.name}={cookie.value}"
            break
        return True

    def request(self, payload: dict[str, Any], retry: bool = True) -> dict[str, Any]:
        if not self.cookie:
            self.login()
        result = self._post(f"/goform/modules?{int(time.time() * 1000)}", payload)
        if not 200 <= result.status < 300:
            # HttpSession does not follow redirects, so a 3xx (typically to the login
            # page) carries no module reply; accepting it reported reboots and SSID
            # changes the router never made.
            location = result.headers.get("Location", "")
            raise AdapterError(f"Tenda request returned HTTP {result.status}{' to ' + location if location else ''}")
        if not result.body.strip():
            return {}
        data = _json_object(result, "Tenda request")
        if data.get("errCode") == "logout":
            if not retry:
                raise AdapterError("Tenda ended the session again straight after a fresh login")
            self.cookie = ""
            self.login()
            return self.request(payload, retry=False)
        error = data.get("errCode")
        if error not in (None, "", 0, "0", False):
            raise _TendaModuleError(f"Tenda module error {error}")
        return data

    def identity(self) -> dict[str, Any]:
        result = self.http.request("GET", "/config/macro_config.js")
        if result.status >= 400:
            raise AdapterError(f"Tenda identity request returned HTTP {result.status}")
        values = {}
        for key, value in re.findall(r"var\s+(\w+)\s*=\s*\"([^\"]*)\"", result.text):
            values[key] = value
        return {
            "model": values.get("CONFIG_PRODUCT_MODEL", self.device.model),
            "firmware": values.get("CONFIG_FIRMWARE_VERION", ""),
            "firmware_date": values.get("CONFIG_FIRMWARE_DATE", ""),
        }

    def status(self) -> dict[str, Any]:
        data = self.request({"sysStatus": {}, "lanStatus": {}, "wifiClientNum": {}})
        system = data.get("sysStatus")
        if not isinstance(system, dict):
            # An empty or unrelated reply is not a healthy router with blank fields.
            raise ProtocolMismatch(f"Tenda status reply carried no sysStatus module; reply began: {str(data)[:120]!r}")
        lan = _block(data, "lanStatus")
        clients = _block(data, "wifiClientNum")
        return {
            "online": True,
            "hostname": system.get("deviceName", ""),
            "firmware": system.get("softwareVersion", ""),
            "uptime": system.get("runningTime", ""),
            "uptime_text": system.get("runningTime", ""),
            "uptime_seconds": _uptime_seconds(system.get("runningTime")),
            "cpu": system.get("cpu", ""),
            "memory": system.get("ram", ""),
            "ip": lan.get("lanIp", ""),
            "clients": clients.get("clientNum", ""),
            "source": "tenda-goform",
        }

    def clients(self) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        refused: _TendaModuleError | None = None
        answered = False
        for radio in ("2.4G", "5G"):
            try:
                data = self.request({"wifiClientList": {"radio": radio, "ssidIndex": ""}})
            except _TendaModuleError as exc:
                # A single-band model refuses the other radio's module. A rejected
                # login or a router that did not answer is not about the radio, and
                # swallowing it showed a wrong password or an offline router as idle.
                refused = exc
                continue
            answered = True
            values = data.get("wifiClientList") or []
            if isinstance(values, list):
                result.extend({"radio": radio, **item} for item in values if isinstance(item, dict))
        if not answered and refused is not None:
            raise refused
        return result

    def set_ssid(self, ssid: str, radio: str | None = None) -> bool:
        selected = radio or str(self.device.metadata.get("radio", "2.4G"))
        if selected not in {"2.4G", "5G"}:
            raise AdapterError("Tenda radio must be 2.4G or 5G")
        payload = {
            "radio": selected,
            "ssidIndex": str(self.device.metadata.get("ssid_index", "0")),
            "ssid": ssid,
            "ssidEn": True,
            "broadcastSsid": True,
            "maxClientNum": "0",
            "staIsolate": False,
            "wmf": False,
            "ssidIsolate": False,
            "ssidEncode": "utf-8",
        }
        self.request({"wifiBasicSetIndoor": payload})
        return True


    def set_wifi_password(self, password: str, radio: str | None = None) -> bool:
        # The security fields of this module API are not evidenced anywhere; a guessed
        # payload can reset the SSID to open rather than failing.
        raise UnsupportedOperation(
            "Tenda Wi-Fi password changes are not supported yet: the security module has not been captured "
            "from real firmware"
        )
    def reboot(self) -> bool:
        self.request({"sysReboot": {}})
        return True

    def firmware_info(self) -> dict[str, Any]:
        # sysStatus names the software version but not the hardware.
        return {"version": self.status()["firmware"], "hardware": "", "auto_update": None, "source": "tenda-goform"}

    def set_auto_update(self, enabled: bool, window_start_hour: int | None = None) -> bool:
        raise UnsupportedOperation(
            "Tenda firmware auto-update is not supported yet: its upgrade module has not been captured from real "
            "firmware"
        )

    def check_firmware_update(self, timeout: float = 60) -> dict[str, Any]:
        raise UnsupportedOperation(
            "Tenda firmware update checks are not supported yet: its upgrade module has not been captured from "
            "real firmware"
        )


# Old TP-Link firmware (WR840N and siblings) locks the web UI for two hours after
# ten failed logins, so the adapter must never retry. Every failure mode below
# reports the router's own authTimes counter so the operator can tell a wrong
# password apart from a lockout.
_TPLINK_MAX_ATTEMPTS = 10
_TPLINK_LOCKOUT_SECONDS = 7200

# Pages used by the 11N-era web UI. Confirmed present on the WR840N: without valid
# auth each returns 403 rather than 404.
_TPLINK_STATUS_PATH = "/userRpm/StatusRpm.htm"
_TPLINK_CLIENTS_PATH = "/userRpm/DhcpTableRpm.htm"
_TPLINK_REBOOT_PATH = "/userRpm/SysRebootRpm.htm"


def _cell_after(pattern: str, text: str, flags: int = re.IGNORECASE) -> str:
    """Return the contents of the first table cell following a label.

    Reading the value out of its own cell avoids the earlier mistake of taking
    the next word after the label, which on this firmware picks up the word
    "Version" from "Firmware Version" instead of the value beside it.
    """
    match = re.search(pattern, text, flags)
    if not match:
        return ""
    window = text[match.end() : match.end() + 300]
    cell = re.search(r"<t[dh][^>]*>(.*?)</t[dh]>", window, re.IGNORECASE | re.DOTALL)
    if not cell:
        return ""
    value = html.unescape(re.sub(r"<[^>]+>", " ", cell.group(1)))
    return " ".join(value.split())


class TpLinkAdapter(RouterAdapter):
    """TP-Link consumer routers using the older 192.168.1.x web UI.

    Authentication is HTTP Basic, but this firmware does not read an
    ``Authorization`` header. The login page builds the credential in JavaScript
    and stores it in a cookie of the same name::

        auth = "Basic " + base64(user + ":" + password)
        document.cookie = "Authorization=" + auth

    Everything after login is a plain page fetch using that cookie.
    """

    def set_wifi_password(self, password: str, radio: str | None = None) -> bool:
        # Excluded for the same reason as SSID changes: the security page is only
        # community-described, sends the key in a plain-HTTP query string, and a
        # write missing a field can leave the network open.
        raise UnsupportedOperation(
            "TP-Link Wi-Fi password changes are not supported on the 11N web UI until its security form has "
            "been captured from real hardware"
        )

    def __init__(self, device: Device, password: str):
        super().__init__(device, password)
        scheme = "https" if device.https else "http"
        self.base_url = f"{scheme}://{_host_for_url(device.host)}:{device.http_port}"
        self.http = HttpSession(self.base_url, verify_tls=device.verify_tls)
        self.username = device.username or "admin"
        self.authenticated = False
        self.auth_cookie = ""

    def _cookie_header(self) -> str:
        if not self.auth_cookie:
            return ""
        return f"Authorization={self.auth_cookie}"

    def _get(self, path: str):
        headers = {"Referer": f"{self.base_url}/"}
        cookie = self._cookie_header()
        if cookie:
            headers["Cookie"] = cookie
        try:
            return self.http.request("GET", path, headers=headers)
        except HttpError as exc:
            raise AdapterError(str(exc)) from exc

    @staticmethod
    def _auth_times(text: str) -> int:
        match = re.search(r"authTimes\s*=\s*(\d+)", text)
        return int(match.group(1)) if match else 0

    def _rejection(self, text: str) -> AuthenticationRejected:
        """Describe a failed login precisely, including an active lockout."""
        attempts = self._auth_times(text)
        message = "TP-Link login rejected"
        if attempts >= _TPLINK_MAX_ATTEMPTS:
            message = (
                f"TP-Link login rejected and the web UI is now locked after {attempts} failed attempts; "
                f"it stays locked for about {_TPLINK_LOCKOUT_SECONDS // 3600} hours"
            )
            # While locked the router refuses the right password too, so this must not
            # read as a wrong one.
            return RouterLockedOut(message)
        if attempts:
            message = f"TP-Link login rejected ({attempts} of {_TPLINK_MAX_ATTEMPTS} attempts used before lockout)"
        return AuthenticationRejected(message)

    @staticmethod
    def _unexpected(status: int, path: str) -> AdapterError:
        if status == 404:
            return ProtocolMismatch(f"TP-Link {path} returned HTTP 404; not the 11N web UI, or the wrong port")
        return AdapterError(f"TP-Link {path} returned HTTP {status}")

    def _login_state(self) -> str:
        """Read the router's authTimes counter.

        Requested without the credential cookie, so it does not count as another
        login attempt. This is what distinguishes a wrong password from a router
        that is already locked out.
        """
        try:
            response = self.http.request("GET", "/", headers={"Referer": f"{self.base_url}/"})
            return response.text
        except HttpError:
            return ""

    def login(self) -> bool:
        """Authenticate once. Never retried, because the router counts attempts."""
        if self.authenticated:
            return True
        raw = f"{self.username}:{self.password}".encode()
        self.auth_cookie = "Basic " + base64.b64encode(raw).decode()
        # Confirm the cookie works. This is the only request that presents
        # credentials, so a wrong password costs a single one of the router's ten.
        response = self._get(_TPLINK_STATUS_PATH)
        # 401 is refused like 403: counting it as a login would have the manager
        # present the same credential on every poll, and each one may count
        # toward the lockout.
        if response.status in {401, 403} or self._auth_times(response.text) > 0:
            self.authenticated = False
            self.auth_cookie = ""
            raise self._rejection(self._login_state())
        if not 200 <= response.status < 300:
            self.auth_cookie = ""
            raise self._unexpected(response.status, _TPLINK_STATUS_PATH)
        self.authenticated = True
        return True

    def _session_get(self, path: str):
        if not self.authenticated:
            self.login()
        response = self._get(path)
        if response.status in {401, 403} or self._auth_times(response.text) > 0:
            # The session expired, or the cookie was never accepted.
            self.authenticated = False
            raise self._rejection(response.text)
        if not 200 <= response.status < 300:
            # An error page parsed as a host table reads as "no clients".
            raise self._unexpected(response.status, path)
        return response

    def status(self) -> dict[str, Any]:
        response = self._session_get(_TPLINK_STATUS_PATH)
        text = response.text
        result: dict[str, Any] = {"online": True, "source": "tplink-11n"}
        # The page carries the model twice: a JavaScript variable and a table row.
        # The variable is the value itself, so read it directly rather than
        # looking for a neighbouring cell, which would return the row's label.
        declared = re.search(r"modelName\s*=\s*\"([^\"]+)\"", text)
        if declared:
            result["model"] = html.unescape(declared.group(1)).strip()
        else:
            model = _cell_after(r"Model\s*No\.?", text)
            if model:
                result["model"] = model
        firmware = _cell_after(r"(?:firmware|software)[^0-9]{0,20}version", text)
        if firmware:
            result["firmware"] = firmware.split()[0]
        uptime = _cell_after(r"uptime", text)
        if uptime:
            seconds = _uptime_seconds(uptime)
            if seconds is not None:
                result["uptime_text"] = uptime
                result["uptime_seconds"] = seconds
        if "model" not in result and "firmware" not in result and "uptime_seconds" not in result:
            # Nothing recognisable came back. Say so instead of reporting a healthy
            # router with no data, which would hide a broken parser.
            raise ProtocolMismatch(
                "TP-Link status page did not contain model, firmware, or uptime; "
                f"page began: {text[:120]!r}"
            )
        return result

    def clients(self) -> list[dict[str, Any]]:
        response = self._session_get(_TPLINK_CLIENTS_PATH)
        return _tplink_clients(response.text)

    def reboot(self) -> bool:
        response = self._session_get(_TPLINK_REBOOT_PATH)
        parser = _FormParser()
        parser.feed(response.text)
        form = next((item for item in parser.forms if "reboot" in item["action"].lower()), None)
        if form is None and parser.forms:
            form = parser.forms[0]
        if form is None:
            # Some builds post straight back to the same page with no form.
            form = {"action": _TPLINK_REBOOT_PATH, "inputs": {}}
        action = form["action"] or _TPLINK_REBOOT_PATH
        if not action.startswith("/"):
            action = _TPLINK_REBOOT_PATH
        fields = {key: str(value) for key, value in form["inputs"].items()}
        fields.setdefault("reboot", "Reboot")
        headers = {"Referer": f"{self.base_url}{_TPLINK_REBOOT_PATH}"}
        cookie = self._cookie_header()
        if cookie:
            headers["Cookie"] = cookie
        try:
            result = self.http.request("POST", action, urlencode(fields).encode(), headers)
        except HttpError as exc:
            raise AdapterError(str(exc)) from exc
        if result.status == 403:
            self.authenticated = False
            raise self._rejection("TP-Link refused the reboot request")
        return result.status in {200, 202, 204, 301, 302, 303}

    def firmware_info(self) -> dict[str, Any]:
        # Read from the status page, so this costs no login beyond a status poll's.
        status = self.status()
        return {
            "version": status.get("firmware", ""),
            "hardware": status.get("model", ""),
            "auto_update": None,
            "source": "tplink-11n",
        }

    # Both refuse before logging in: a login spent on an unsupported call still
    # counts toward the router's ten.
    def set_auto_update(self, enabled: bool, window_start_hour: int | None = None) -> bool:
        raise UnsupportedOperation(
            "TP-Link firmware settings are not supported on the 11N web UI: firmware writes stay excluded, since "
            "its firmware page has not been captured from real hardware"
        )

    def check_firmware_update(self, timeout: float = 60) -> dict[str, Any]:
        raise UnsupportedOperation(
            "TP-Link firmware update checks are not supported on the 11N web UI: its firmware page has not been "
            "captured from real hardware"
        )


_MAC_PATTERN = re.compile(r"\b([0-9A-F]{2}(?:[:-][0-9A-F]{2}){5})\b", re.IGNORECASE)
_IP_PATTERN = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def _quoted_values(text: str) -> list[str]:
    """Every double- or single-quoted string in order, correctly paired.

    Matching a quote with a lazy ``.*?`` in one regex lets the closing quote of
    one value serve as the opening quote of the next, which silently shifts every
    field by one. Splitting the two quote styles keeps the pairing correct.
    """
    values = [item for item in re.findall(r'"([^"\n]*)"', text)]
    values += [item for item in re.findall(r"'([^'\n]*)'", text)]
    return [item.strip() for item in values]


def _tplink_clients(text: str) -> list[dict[str, Any]]:
    """Pull MAC, IP, and hostname out of the TP-Link host table.

    This firmware has emitted the table in several shapes across model years
    (JavaScript object constructors, plain rows, and definition lists), so match
    on each MAC and read only its own record. The record runs up to the next MAC:
    scanning a fixed window ahead bleeds into the following row and picks up
    fragments of the next entry as if they were this one's hostname.
    """
    matches = list(_MAC_PATTERN.finditer(text))
    clients: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, match in enumerate(matches):
        mac = match.group(1).upper().replace("-", ":")
        if mac in seen or mac == "00:00:00:00:00:00":
            continue
        seen.add(mac)
        # Start one character early so the record includes the quote that opens the
        # MAC. Without it the quoted values in the row are paired off by one and
        # every real field is skipped.
        start = max(0, match.start() - 1)
        end = matches[index + 1].start() - 1 if index + 1 < len(matches) else len(text)
        record = text[start : max(start + 1, end)][:400]
        address = next((item for item in _IP_PATTERN.findall(record) if not item.startswith("255.")), "")
        hostname = ""
        for candidate in _quoted_values(record):
            if not re.search(r"[A-Za-z0-9]", candidate):
                continue
            if candidate.lower() in {"null", "none", "unknown", "true", "false"}:
                continue
            if _IP_PATTERN.fullmatch(candidate) or _MAC_PATTERN.fullmatch(candidate):
                continue
            # A hostname is a single word; a fragment of the next statement is not.
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", candidate):
                continue
            hostname = candidate
            break
        clients.append({"name": hostname or mac, "mac": mac, "ip": address, "cells": [mac, address, hostname]})
    return clients
