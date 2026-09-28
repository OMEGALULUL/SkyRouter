import base64
import html
import json
import re
import time
from typing import Any
from urllib.parse import urlencode, urlsplit, urlunsplit

from .adapters import (
    _TPLINK_LOCKOUT_SECONDS,
    _TPLINK_MAX_ATTEMPTS,
    _block,
    _FormParser,
    _host_for_url,
    _looks_like_login,
    _luci_login_required,
    cudy_login_form,
    fetch_cudy_token,
    parse_cudy_login_page,
)
from .http_client import HttpError, HttpSession
from .models import Device

REDIRECT_STATUSES = {301, 302, 303, 307, 308}
MAX_SNIPPET = 400
_URL_SESSION = re.compile(r";stok=[^/\s\"'&<>]*", re.IGNORECASE)


def _secret_forms(secret: str) -> set[str]:
    # A router echoes a submitted value re-encoded for wherever it lands: escaped
    # inside a JSON string, or entity-escaped in an HTML page.
    escaped = json.dumps(secret)[1:-1]
    forms = {
        secret,
        escaped,
        escaped.replace("/", "\\/"),
        json.dumps(secret, ensure_ascii=False)[1:-1],
        html.escape(secret),
        html.escape(secret, quote=False),
    }
    return {" ".join(form.split()) for form in forms} - {""}


def _snippet(text: str, *secrets: str) -> str:
    """Collapse a response body for display, redacting anything sensitive.

    A router is free to echo the submitted password back in an error page, so the
    known secret values are masked before the text ever reaches a terminal, a log,
    or the API. Both sides are compared whitespace-collapsed, so a secret with a
    double space or a newline is still found after the body is collapsed.
    """
    collapsed = " ".join(text.split())
    forms: set[str] = set()
    for secret in secrets:
        if secret:
            forms |= _secret_forms(secret)
    # Longest first, so a secret that contains a shorter one is masked whole.
    for form in sorted(forms, key=len, reverse=True):
        collapsed = collapsed.replace(form, "<redacted>")
    collapsed = _URL_SESSION.sub(";stok=<redacted>", collapsed)
    if len(collapsed) <= MAX_SNIPPET:
        return collapsed
    return collapsed[:MAX_SNIPPET] + f"... (+{len(collapsed) - MAX_SNIPPET} chars)"


def _form_fields(html: str) -> dict[str, str]:
    parser = _FormParser()
    parser.feed(html)
    return {key: ("<empty>" if not value else f"<{len(value)} chars>") for key, value in parser.inputs.items()}


def _location(value: str) -> str:
    """The Location header without anything that can carry a session.

    LuCI firmware that keeps the session in the URL answers a login with
    ``/cgi-bin/luci/;stok=<token>/``, and that token is a live admin session.
    """
    if not value:
        return ""
    try:
        parts = urlsplit(value)
    except ValueError:
        return "<unparseable, redacted>"
    return urlunsplit(
        (
            parts.scheme,
            parts.netloc.rpartition("@")[2],
            re.sub(r";[^/]*", ";<redacted>", parts.path),
            "<redacted>" if parts.query else "",
            "<redacted>" if parts.fragment else "",
        )
    )


def _interpret(response) -> str:
    if response.status in REDIRECT_STATUSES:
        return "redirect, which is what a successful Cudy login returns"
    if response.status == 404:
        return "404 not found, so the port or path is wrong rather than the password"
    if response.status == 401 or response.status == 403:
        return "the router refused the request outright; wrong credentials or a locked account"
    if response.status >= 400:
        return f"server error {response.status}, so this is not a credential problem"
    if "luci_username" in response.text:
        return "login form found, so the endpoint and port are correct"
    return "no login form here, so the path or port is probably wrong"


def _login_outcome(result) -> str:
    """Classify the login reply by the tests CudyAdapter.login applies.

    diagnose exists to explain what status does, so a verdict reached by other
    rules would contradict it. One split is deliberate: the adapter calls every
    remaining reply a rejection, and here one without the login form is named a
    protocol mismatch, since that is the case diagnose is run to find.
    """
    if result.status in {401, 403} and (_looks_like_login(result.text) or _luci_login_required(result)):
        return "rejected"
    if result.status >= 400:
        return "error"
    if result.status in {301, 302, 303} or (result.status == 200 and not _looks_like_login(result.text)):
        return "accepted"
    if _looks_like_login(result.text):
        return "rejected"
    return "mismatch"


_LOGIN_NOTES = {
    "accepted": "a redirect or a page other than the login form, which status counts as logged in",
    "rejected": "the login form came back, which status reports as rejected credentials",
    "error": "an HTTP error, which status reports as such rather than as a bad password",
    "mismatch": "neither a session nor the login form; a protocol mismatch rather than a bad password",
}


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
            "note": _interpret(landing),
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
    login_page = parse_cudy_login_page(page.text)
    # Stock LuCI serves its login form with 403 to anyone not yet signed in.
    if page.status >= 400 and not (page.status in {401, 403} and login_page.is_login):
        return {
            "vendor": "cudy",
            "base_url": base,
            "reachable": True,
            "steps": steps,
            "verdict": f"login page returned HTTP {page.status}; this is not a credential problem",
        }
    if login_page.first_boot:
        return {
            "vendor": "cudy",
            "base_url": base,
            "reachable": True,
            "steps": steps,
            "verdict": "the router shows its first-time setup page and has no admin password yet; set one in its "
            "web UI first (no login was attempted, since submitting that page would set the password)",
        }
    if not salt and not device.allow_legacy_login:
        return {
            "vendor": "cudy",
            "base_url": base,
            "reachable": True,
            "steps": steps,
            "verdict": "login page has no salt; the login flow for this firmware is not implemented",
        }
    fresh = fetch_cudy_token(session, f"{base}/cgi-bin/luci/")
    steps.append(
        {
            "step": "POST /cgi-bin/luci/admin/get_token",
            "token_fetched": fresh is not None,
            "note": "per-login token received, used in place of the page's token"
            if fresh
            else "no per-login token endpoint; using the token embedded in the page",
        }
    )
    token = fresh or token
    form = cudy_login_form(login_page, password, device.username, token)
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
    # A session cookie's value is as good as the password while it lasts. Short
    # values (lang=en, a 0/1 flag) are not tokens, and masking them blanked every
    # matching substring of the snippet.
    cookie_values = [
        cookie.value
        for cookie in session.cookie_jar
        if cookie.value and (cookie.name in {"sysauth", "sysauth_https"} or len(cookie.value) >= 8)
    ]
    derived = form["luci_password"]
    outcome = _login_outcome(result)
    steps.append(
        {
            "step": "POST /cgi-bin/luci/ (login)",
            "flow": "salted challenge/response" if salt else "legacy plaintext (allow_legacy_login)",
            "status": result.status,
            "location": _location(result.headers.get("Location", "")),
            "cookies_set": cookies,
            "body_snippet": _snippet(result.text, derived, password, salt, token, csrf, *cookie_values),
            "note": _LOGIN_NOTES[outcome],
        }
    )
    sysauth = any(name in {"sysauth", "sysauth_https"} for name in cookies)
    if outcome == "accepted" and sysauth:
        verdict = "login accepted; the router issued a session cookie"
    elif outcome == "accepted":
        verdict = f"login accepted; HTTP {result.status} without the login form, though no sysauth cookie was set"
    elif outcome == "rejected":
        verdict = "credentials rejected; the login form came back"
    elif outcome == "error":
        verdict = f"login POST returned HTTP {result.status}; status reports this as an HTTP error, not a bad password"
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
    # Valid JSON that is not an object is exactly the "different API" firmware
    # this report exists to identify, so it must be described, not raised on.
    if not isinstance(data, dict):
        data = {}
    login_block = _block(data, "sysLogin")
    steps.append(
        {
            "step": "POST /goform/modules?login",
            "status": result.status,
            "response_keys": sorted(data),
            "login_flag": login_block.get("Login"),
            "cookies_set": sorted({cookie.name for cookie in session.cookie_jar}),
            "body_snippet": _snippet(result.text, encoded, password),
            "note": "login accepted" if login_block.get("Login") else "login flag was not set",
        }
    )
    if not data:
        return {
            "vendor": "tenda",
            "base_url": base,
            "reachable": True,
            "steps": steps,
            "verdict": "the login endpoint did not return a JSON object; this firmware uses a different API",
        }
    status_answered = False
    try:
        status_result = session.request(
            "POST",
            "/goform/modules?status",
            json.dumps({"sysStatus": {}, "lanStatus": {}, "wifiClientNum": {}}).encode(),
            {"Content-Type": "application/json"},
        )
        status_data = status_result.json()
    except (HttpError, ValueError) as exc:
        steps.append({"step": "POST /goform/modules (status)", "error": str(exc)})
    else:
        if not isinstance(status_data, dict):
            note = "status module did not return a JSON object"
            status_data = {}
        elif not 200 <= status_result.status < 300:
            note = f"status module answered HTTP {status_result.status}"
        else:
            note = "status module answered"
            status_answered = True
        steps.append(
            {
                "step": "POST /goform/modules (status)",
                "status": status_result.status,
                "response_keys": sorted(status_data),
                "uptime_raw": _block(status_data, "sysStatus").get("runningTime", "<absent>"),
                "note": note,
            }
        )
    if not login_block.get("Login"):
        verdict = "login was not accepted"
    elif status_answered:
        verdict = "login and status both answered"
    else:
        verdict = "login accepted, but the status module did not answer as expected"
    return {
        "vendor": "tenda",
        "base_url": base,
        "reachable": True,
        "steps": steps,
        "verdict": verdict,
    }


def _js_int(name: str, text: str) -> int | None:
    match = re.search(rf"{name}\s*=\s*(\d+)", text)
    return int(match.group(1)) if match else None


def diagnose_tplink(device: Device, password: str) -> dict[str, Any]:
    """Read the TP-Link login page's failed-login counter without logging in.

    This firmware locks its web UI for two hours after ten failed logins, and
    diagnose is usually run straight after one was rejected, so the credential is
    never presented. The counter on the unauthenticated page already tells a wrong
    password, a lockout and a wrong address apart.
    """
    scheme = "https" if device.https else "http"
    base = f"{scheme}://{_host_for_url(device.host)}:{device.http_port}"
    session = HttpSession(base, verify_tls=device.verify_tls)
    try:
        page = session.request("GET", "/", headers={"Referer": f"{base}/"})
    except HttpError as exc:
        return {
            "vendor": "tplink",
            "base_url": base,
            "reachable": False,
            "steps": [{"step": "GET / (no credentials)", "error": str(exc)}],
            "verdict": "the router did not answer on this address",
        }
    auth_times = _js_int("authTimes", page.text)
    model = re.search(r"modelName\s*=\s*\"([^\"]*)\"", page.text)
    steps: list[dict[str, Any]] = [
        {
            "step": "GET / (no credentials)",
            "status": page.status,
            "server": page.headers.get("Server", ""),
            "auth_times": auth_times,
            "forbid_time": _js_int("forbidTime", page.text),
            "model": html.unescape(model.group(1)).strip() if model else "",
            "username": device.username or "admin",
            "note": "requested without the Authorization cookie, so the router does not count it as a login",
        }
    ]
    hours = _TPLINK_LOCKOUT_SECONDS // 3600
    if page.status >= 400:
        verdict = (
            f"{base}/ returned HTTP {page.status}, so this is not the TP-Link login page; "
            "check the port and that http is the right scheme"
        )
    elif auth_times is None:
        verdict = (
            f"the page at {base}/ has no authTimes counter, so it is not the older TP-Link web UI this tool "
            "speaks; check the port, or the firmware uses another login flow"
        )
    elif auth_times >= _TPLINK_MAX_ATTEMPTS:
        verdict = (
            f"the web UI is locked after {auth_times} failed logins; for about {hours} hours it refuses every "
            "password, the right one too, so wait before trying again"
        )
    elif auth_times:
        verdict = (
            f"the router has counted {auth_times} failed logins, {_TPLINK_MAX_ATTEMPTS - auth_times} left before "
            f"a {hours}-hour lockout; the address is right, so a rejection is the username or password"
        )
    else:
        verdict = (
            "the TP-Link login page answered with no failed logins counted, so the address is right; "
            "diagnose does not present the password, so test it once with status"
        )
    return {"vendor": "tplink", "base_url": base, "reachable": True, "steps": steps, "verdict": verdict}


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
    if device.vendor == "tplink":
        return diagnose_tplink(device, password)
    return diagnose_cudy(device, password)


__all__ = ["diagnose_device"]
