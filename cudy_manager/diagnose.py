import base64
import json
import re
import time
from typing import Any
from urllib.parse import urlencode

from .adapters import _FormParser, _host_for_url, derive_cudy_password
from .http_client import HttpError, HttpSession
from .models import Device

REDIRECT_STATUSES = {301, 302, 303, 307, 308}
MAX_SNIPPET = 400


def _snippet(text: str, *secrets: str) -> str:
    """Collapse a response body for display, redacting anything sensitive.

    A router is free to echo the submitted password back in an error page, so the
    known secret values are masked before the text ever reaches a terminal, a log,
    or the API.
    """
    collapsed = " ".join(text.split())
    for secret in secrets:
        if secret:
            collapsed = collapsed.replace(secret, "<redacted>")
    if len(collapsed) <= MAX_SNIPPET:
        return collapsed
    return collapsed[:MAX_SNIPPET] + f"... (+{len(collapsed) - MAX_SNIPPET} chars)"


def _form_fields(html: str) -> dict[str, str]:
    parser = _FormParser()
    parser.feed(html)
    return {key: ("<empty>" if not value else f"<{len(value)} chars>") for key, value in parser.inputs.items()}


def _interpret(response, expected: str | None) -> str:
    if response.status in REDIRECT_STATUSES:
        return "redirect, which is what a successful Cudy login returns"
    if response.status == 404:
        return "404 not found, so the port or path is wrong rather than the password"
    if response.status == 401 or response.status == 403:
        return "the router refused the request outright; wrong credentials or a locked account"
    if response.status >= 400:
        return f"server error {response.status}, so this is not a credential problem"
    if expected == "login-page":
        if "luci_username" in response.text:
            return "login form found, so the endpoint and port are correct"
        return "no login form here, so the path or port is probably wrong"
    if "luci_username" in response.text or "password" in response.text.lower():
        return "login form came back after submitting, which means the credentials were rejected"
    return "unexpected page; this is a protocol mismatch rather than a bad password"


def diagnose_cudy(device: Device, password: str) -> dict[str, Any]:
    scheme = "https" if device.https else "http"
    base = f"{scheme}://{_host_for_url(device.host)}:{device.http_port}"
    steps: list[dict[str, Any]] = []
    session = HttpSession(base, verify_tls=device.verify_tls)
    try:
        landing = session.request("GET", "/", follow_redirects=True)
    except HttpError as exc:
        return {
            "vendor": "cudy",
            "base_url": base,
            "reachable": False,
            "steps": [{"step": "GET /", "error": str(exc)}],
            "verdict": "the router did not answer on this address",
        }
    steps.append(
        {
            "step": "GET /",
            "status": landing.status,
            "landed_on": landing.url,
            "server": landing.headers.get("Server", ""),
            "login_form_present": "luci_username" in landing.text,
            "note": _interpret(landing, "login-page"),
        }
    )
    try:
        page = session.request("GET", "/cgi-bin/luci/")
    except HttpError as exc:
        steps.append({"step": "GET /cgi-bin/luci/", "error": str(exc)})
        return {
            "vendor": "cudy",
            "base_url": base,
            "reachable": True,
            "steps": steps,
            "verdict": "login page unreachable",
        }
    parser = _FormParser()
    parser.feed(page.text)
    salt = parser.inputs.get("salt", "")
    token = parser.inputs.get("token", "")
    csrf = parser.inputs.get("_csrf", "")
    steps.append(
        {
            "step": "GET /cgi-bin/luci/",
            "status": page.status,
            "form_fields": _form_fields(page.text),
            "salt_present": bool(salt),
            "salt_length": len(salt),
            "token_present": bool(token),
            "token_length": len(token),
            "csrf_present": bool(csrf),
            "title": " ".join("".join(parser.title).split()),
            "note": (
                "salt and token present, so the challenge/response handshake is expected"
                if salt
                else "NO SALT, so the assumed handshake does not apply to this firmware"
            ),
        }
    )
    if page.status == 404:
        return {
            "vendor": "cudy",
            "base_url": base,
            "reachable": True,
            "steps": steps,
            "verdict": f"no LuCI login page at {base}/cgi-bin/luci/; check the port and that http is the right scheme",
        }
    if page.status >= 400:
        return {
            "vendor": "cudy",
            "base_url": base,
            "reachable": True,
            "steps": steps,
            "verdict": f"login page returned HTTP {page.status}; this is not a credential problem",
        }
    if not salt:
        return {
            "vendor": "cudy",
            "base_url": base,
            "reachable": True,
            "steps": steps,
            "verdict": "login page has no salt; the login flow for this firmware is not implemented",
        }
    form = {
        "_csrf": csrf,
        "token": token,
        "salt": salt,
        "luci_language": "autp",
        "luci_username": device.username,
        "luci_password": derive_cudy_password(password, salt, token),
        "timeclock": "0",
        "zonename": "UTC",
    }
    try:
        result = session.request(
            "POST",
            "/cgi-bin/luci/",
            urlencode(form).encode(),
            {
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": f"{base}/cgi-bin/luci/",
                "X-Requested-With": "XMLHttpRequest",
            },
        )
    except HttpError as exc:
        steps.append({"step": "POST /cgi-bin/luci/ (login)", "error": str(exc)})
        return {
            "vendor": "cudy",
            "base_url": base,
            "reachable": True,
            "steps": steps,
            "verdict": "login POST failed",
        }
    cookies = sorted({cookie.name for cookie in session.cookie_jar})
    derived = form["luci_password"]
    steps.append(
        {
            "step": "POST /cgi-bin/luci/ (login)",
            "status": result.status,
            "location": result.headers.get("Location", ""),
            "cookies_set": cookies,
            "body_snippet": _snippet(result.text, derived, password, salt, token, csrf),
            "note": _interpret(result, None),
        }
    )
    sysauth = any(name in {"sysauth", "sysauth_https"} for name in cookies)
    if result.status in REDIRECT_STATUSES or sysauth:
        verdict = "login accepted; the router issued a session cookie"
    elif "luci_username" in result.text:
        verdict = "credentials rejected; the login form came back"
    else:
        verdict = "no session cookie and no login form; treat this as a protocol mismatch"
    return {
        "vendor": "cudy",
        "base_url": base,
        "reachable": True,
        "sysauth_cookie": sysauth,
        "steps": steps,
        "verdict": verdict,
    }


def diagnose_tenda(device: Device, password: str) -> dict[str, Any]:
    scheme = "https" if device.https else "http"
    base = f"{scheme}://{_host_for_url(device.host)}:{device.http_port}"
    steps: list[dict[str, Any]] = []
    session = HttpSession(base, verify_tls=device.verify_tls)
    try:
        macro = session.request("GET", "/config/macro_config.js")
    except HttpError as exc:
        return {
            "vendor": "tenda",
            "base_url": base,
            "reachable": False,
            "steps": [{"step": "GET /config/macro_config.js", "error": str(exc)}],
            "verdict": "the router did not answer on this address",
        }
    model = re.findall(r'var\s+CONFIG_PRODUCT_MODEL\s*=\s*"([^"]*)"', macro.text)
    steps.append(
        {
            "step": "GET /config/macro_config.js",
            "status": macro.status,
            "model": model[0] if model else "",
            "note": "identity file found" if model else "no model in this file; some firmware omits it",
        }
    )
    now = time.localtime()
    stamp = ";".join(
        str(v) for v in (now.tm_year, now.tm_mon, now.tm_mday, now.tm_hour, now.tm_min, now.tm_sec)
    )
    encoded = base64.b64encode(password.encode()).decode()
    payload = {"sysLogin": {"password": encoded, "logoff": False, "timeZone": 20, "time": stamp}}
    try:
        result = session.request(
            "POST",
            "/goform/modules?login",
            json.dumps(payload).encode(),
            {"Content-Type": "application/json"},
        )
    except HttpError as exc:
        steps.append({"step": "POST /goform/modules?login", "error": str(exc)})
        return {"vendor": "tenda", "base_url": base, "reachable": True, "steps": steps, "verdict": "login POST failed"}
    try:
        data = result.json()
    except HttpError:
        data = {}
    login_block = data.get("sysLogin") or {}
    steps.append(
        {
            "step": "POST /goform/modules?login",
            "status": result.status,
            "response_keys": sorted(data) if isinstance(data, dict) else [],
            "login_flag": login_block.get("Login"),
            "cookies_set": sorted({cookie.name for cookie in session.cookie_jar}),
            "body_snippet": _snippet(result.text, encoded, password),
            "note": "login accepted" if login_block.get("Login") else "login flag was not set",
        }
    )
    if not isinstance(data, dict) or not data:
        return {
            "vendor": "tenda",
            "base_url": base,
            "reachable": True,
            "steps": steps,
            "verdict": "the login endpoint did not return JSON; this firmware uses a different API",
        }
    try:
        status_result = session.request(
            "POST",
            "/goform/modules?status",
            json.dumps({"sysStatus": {}, "lanStatus": {}, "wifiClientNum": {}}).encode(),
            {"Content-Type": "application/json"},
        )
        status_data = status_result.json()
        steps.append(
            {
                "step": "POST /goform/modules (status)",
                "status": status_result.status,
                "response_keys": sorted(status_data) if isinstance(status_data, dict) else [],
                "uptime_raw": (status_data.get("sysStatus") or {}).get("runningTime", "<absent>"),
                "note": "status module answered",
            }
        )
    except (HttpError, ValueError) as exc:
        steps.append({"step": "POST /goform/modules (status)", "error": str(exc)})
    return {
        "vendor": "tenda",
        "base_url": base,
        "reachable": True,
        "steps": steps,
        "verdict": "login and status both answered" if login_block.get("Login") else "login was not accepted",
    }


def diagnose_device(device: Device, password: str) -> dict[str, Any]:
    if device.transport == "ssh":
        return {
            "vendor": "ssh",
            "reachable": None,
            "steps": [
                {
                    "step": "ssh",
                    "note": "SSH devices are not diagnosed over HTTP; "
                    "check reachability and host key acceptance instead",
                }
            ],
            "verdict": "use the status command; SSH is not covered by this diagnostic",
        }
    if device.vendor == "tenda":
        return diagnose_tenda(device, password)
    return diagnose_cudy(device, password)


__all__ = ["diagnose_device"]
