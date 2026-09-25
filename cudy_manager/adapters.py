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
        if result.status in {301, 302, 303} or result.status == 200 and not _looks_like_login(result.text):
            self.authenticated = True
        else:
            raise AdapterError("Cudy authentication failed")
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
        uptime = re.search(r"(?:uptime|activity time)[^0-9]{0,40}(\d+)\s*(?:days?|d)?", text, re.IGNORECASE)
        if uptime:
            result["uptime_text"] = uptime.group(0)
            result["uptime_seconds"] = _uptime_seconds(uptime.group(0))
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
        self.base_url = f"http://{_host_for_url(device.host)}:{device.http_port}"
        self.http = HttpSession(self.base_url)
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
            raise AdapterError("Tenda authentication failed")
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
