import base64
import hashlib
import html
import json
import re
import time
from abc import ABC, abstractmethod
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

    def mesh_status(self) -> dict[str, Any]:
        raise UnsupportedOperation("mesh status is not supported by this adapter")


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


def _looks_like_login(text: str) -> bool:
    lowered = text.lower()
    return "luci_username" in lowered or "name=\"password\"" in lowered or "wrong password" in lowered


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
        response = self._get("/cgi-bin/luci/")
        parser = _FormParser()
        parser.feed(response.text)
        self.csrf_token = parser.inputs.get("_csrf", "")
        self.token = parser.inputs.get("token", "")
        self.salt = parser.inputs.get("salt", "")
        if response.status >= 400:
            raise AdapterError(f"Cudy login page returned HTTP {response.status}")
        if not self.salt and not self.csrf_token and not self.device.allow_legacy_login:
            raise ProtocolMismatch(
                "Cudy login page exposed no salt and no token, so the expected challenge/response handshake "
                "is not present; this firmware likely uses a different login flow. Check the raw exchange with "
                "'router-manager diagnose'."
            )
        if not self.salt and not self.device.allow_legacy_login:
            raise UnsupportedOperation("Cudy login did not provide a salt; enable legacy_login only on a trusted LAN")
        password = self.password
        if self.salt:
            password = derive_cudy_password(self.password, self.salt, self.token)
        form = {
            "_csrf": self.csrf_token,
            "token": self.token,
            "salt": self.salt,
            "luci_language": "autp",
            "luci_username": self.device.username,
            "luci_password": password,
            "timeclock": str(int(time.time())),
            "zonename": "UTC",
        }
        result = self._post("/cgi-bin/luci/", form)
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

    def _session_get(self, path: str):
        if not self.authenticated:
            self.login()
        response = self._get(path)
        if response.status in {401, 403}:
            self.authenticated = False
            self.login()
            response = self._get(path)
        if response.status >= 400:
            raise AdapterError(f"Cudy request returned HTTP {response.status}")
        return response

    def status(self) -> dict[str, Any]:
        response = self._session_get("/cgi-bin/luci/admin/system/status")
        text = response.text
        parser = _FormParser()
        parser.feed(text)
        firmware = ""
        match = re.search(r"(?:firmware|software)[^<]{0,40}([A-Za-z0-9._-]{3,})", text, re.IGNORECASE)
        if match:
            firmware = html.unescape(match.group(1))
        result: dict[str, Any] = {
            "online": True,
            "firmware": firmware,
            "title": " ".join("".join(parser.title).split()),
            "source": "cudy-luci",
        }
        # Capture the whole duration expression. Matching only the leading number
        # would drop the H:MM:SS part, and would fail outright on pages that label
        # the field "Activity Time", leaving the scheduler unable to read uptime.
        uptime = re.search(
            r"(?:uptime|activity time)[^0-9]{0,40}"
            r"(\d+\s*(?:days?)?\s*\d{1,2}:\d{2}:\d{2}|\d{1,2}:\d{2}:\d{2}|\d+)",
            text,
            re.IGNORECASE,
        )
        if uptime:
            result["uptime_text"] = uptime.group(0)
            result["uptime_seconds"] = _uptime_seconds(uptime.group(1))
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

    def _submit_reboot_form(self) -> bool:
        response = self._session_get("/cgi-bin/luci/admin/system/reboot")
        parser = _FormParser()
        parser.feed(response.text)
        form = next((item for item in parser.forms if "reboot" in item["action"].lower()), None)
        if form is None and parser.forms:
            form = parser.forms[0]
        if form is None:
            return False
        action = form["action"] or "/cgi-bin/luci/admin/system/reboot"
        if not action.startswith("/"):
            action = "/cgi-bin/luci/admin/system/reboot"
        fields = {key: str(value) for key, value in form["inputs"].items()}
        fields.setdefault("token", self.token)
        fields["submit"] = "1"
        result = self._post(action, fields)
        return result.status in {200, 202, 204, 301, 302, 303}

    def reboot(self) -> bool:
        if not self.authenticated:
            self.login()
        token_fields = {key: value for key, value in {"_csrf": self.csrf_token, "token": self.token}.items() if value}
        result = self._post("/cgi-bin/luci/admin/system/reboot/call", token_fields)
        if result.status in {200, 202, 204, 301, 302, 303} and not _looks_like_login(result.text):
            return True
        return self._submit_reboot_form()

    def set_ssid(self, ssid: str, radio: str | None = None) -> bool:
        raise UnsupportedOperation("Cudy SSID changes require an SSH transport on this firmware")

    def mesh_status(self) -> dict[str, Any]:
        response = self._session_get("/cgi-bin/luci/admin/network/wireless")
        return {"online": response.status < 400, "source": "cudy-luci"}


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
        try:
            data = result.json()
        except HttpError as exc:
            raise AdapterError("Tenda login returned invalid JSON") from exc
        if not data.get("sysLogin", {}).get("Login"):
            detail = data.get("sysLogin", {}).get("errMsg") or data.get("errMsg") or ""
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
        if result.status >= 400:
            raise AdapterError(f"Tenda request returned HTTP {result.status}")
        if not result.body.strip():
            return {}
        try:
            data = result.json()
        except HttpError as exc:
            raise AdapterError("Tenda returned invalid JSON") from exc
        if data.get("errCode") == "logout" and retry:
            self.cookie = ""
            self.login()
            return self.request(payload, retry=False)
        error = data.get("errCode")
        if error not in (None, "", 0, "0", False):
            raise AdapterError(f"Tenda module error {error}")
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
        system = data.get("sysStatus") or {}
        lan = data.get("lanStatus") or {}
        clients = data.get("wifiClientNum") or {}
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
        for radio in ("2.4G", "5G"):
            try:
                data = self.request({"wifiClientList": {"radio": radio, "ssidIndex": ""}})
            except AdapterError:
                continue
            values = data.get("wifiClientList") or []
            if isinstance(values, list):
                result.extend({"radio": radio, **item} for item in values if isinstance(item, dict))
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

    def reboot(self) -> bool:
        self.request({"sysReboot": {}})
        return True


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
        elif attempts:
            message = f"TP-Link login rejected ({attempts} of {_TPLINK_MAX_ATTEMPTS} attempts used before lockout)"
        return AuthenticationRejected(message)

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
        if response.status == 403 or self._auth_times(response.text) > 0:
            self.authenticated = False
            self.auth_cookie = ""
            raise self._rejection(self._login_state())
        self.authenticated = True
        return True

    def _session_get(self, path: str):
        if not self.authenticated:
            self.login()
        response = self._get(path)
        if response.status == 403:
            # The session expired, or the cookie was never accepted.
            self.authenticated = False
            raise self._rejection("TP-Link session was refused")
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
