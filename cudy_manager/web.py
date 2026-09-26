import asyncio
import hmac
import html
import json
import logging
import os
import secrets
import threading
import time
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from .adapters import AdapterError, UnsupportedOperation
from .manager import DeviceManager, ManagerError
from .models import ValidationError
from .scheduler import RebootScheduler
from .secrets import SecretStoreError

logger = logging.getLogger(__name__)

PACKAGE_DIR = Path(__file__).resolve().parent
TEMPLATE_PATH = PACKAGE_DIR / "dashboard.html"
# Write-only credential inputs such as "password" and "snmp_community" are accepted
# and converted to vault references before anything is written to disk. These names
# are rejected because they either name a secret directly, or are legacy aliases
# that would let a caller store or repoint a reference.
PLAINTEXT_CREDENTIAL_FIELDS = {
    "ssh_password",
    "luci_password",
    "password_ref",
    "snmp_community_ref",
}


def _positive_int(name: str, default: int, minimum: int = 1) -> int:
    """Read an integer from the environment without failing startup on junk."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return max(minimum, int(raw))
    except ValueError:
        logger.warning("ignoring invalid %s=%r; using %d", name, raw, default)
        return default


@dataclass
class Settings:
    username: str
    password: str
    secure_cookie: bool
    scheduler_interval: int
    config_path: Path
    data_dir: Path

    @classmethod
    def from_env(cls) -> "Settings":
        password = os.environ.get("ROUTER_MANAGER_PASSWORD", os.environ.get("AUTH_PASSWORD", ""))
        default_data = Path.home() / ".local/state/skybre-router-manager"
        return cls(
            username=os.environ.get("ROUTER_MANAGER_USERNAME", os.environ.get("AUTH_USERNAME", "admin")),
            password=password,
            secure_cookie=os.environ.get("ROUTER_MANAGER_SECURE_COOKIE", "0") == "1",
            scheduler_interval=_positive_int("ROUTER_MANAGER_SCHEDULER_INTERVAL", 30, minimum=15),
            config_path=Path(os.environ.get("ROUTER_MANAGER_CONFIG", PACKAGE_DIR / "cudy_devices.yaml")),
            data_dir=Path(os.environ.get("ROUTER_MANAGER_DATA_DIR", default_data)),
        )


class SessionStore:
    def __init__(self, ttl_seconds: int = 43200):
        self.ttl_seconds = ttl_seconds
        self._sessions: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def create(self) -> dict[str, str]:
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        with self._lock:
            self._prune()
            self._sessions[token] = {"expires": time.time() + self.ttl_seconds, "csrf": csrf}
        return {"token": token, "csrf": csrf}

    def _prune(self) -> None:
        now = time.time()
        for token, session in list(self._sessions.items()):
            if session["expires"] <= now:
                self._sessions.pop(token, None)

    def get(self, token: str | None) -> dict[str, Any] | None:
        if not token:
            return None
        with self._lock:
            self._prune()
            return self._sessions.get(token)

    def delete(self, token: str | None) -> None:
        if token:
            with self._lock:
                self._sessions.pop(token, None)


class LoginLimiter:
    def __init__(self, maximum: int = 5, window_seconds: int = 900, max_keys: int = 4096):
        self.maximum = maximum
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self._values: dict[str, list[float]] = {}
        self._lock = threading.Lock()
        self._sweeps = 0

    def _prune(self, now: float) -> None:
        for key, values in list(self._values.items()):
            kept = [value for value in values if now - value < self.window_seconds]
            if kept:
                self._values[key] = kept
            else:
                del self._values[key]

    def _remember(self, key: str, values: list[float], now: float) -> None:
        if values:
            self._values[key] = values
        else:
            self._values.pop(key, None)
        # Bound memory even inside one window: a flood of unique source addresses
        # must not be able to grow the table without limit. The least recently
        # active keys are dropped first.
        while len(self._values) > self.max_keys:
            oldest = min(self._values, key=lambda item: self._values[item][-1])
            del self._values[oldest]

    def blocked(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            # Sweep periodically so addresses that are never queried again (rotating
            # sources, IPv6 privacy addresses) do not accumulate forever.
            self._sweeps += 1
            if self._sweeps % 50 == 0:
                self._prune(now)
            values = [value for value in self._values.get(key, []) if now - value < self.window_seconds]
            self._remember(key, values, now)
            return len(values) >= self.maximum

    def fail(self, key: str) -> None:
        now = time.time()
        with self._lock:
            self._values.setdefault(key, []).append(now)
            while len(self._values) > self.max_keys:
                oldest = min(self._values, key=lambda item: self._values[item][-1])
                del self._values[oldest]

    def success(self, key: str) -> None:
        with self._lock:
            self._values.pop(key, None)


LOGIN_PAGE_TEMPLATE = """<!doctype html>
<html lang=en><head><meta charset=utf-8>
<meta name=viewport content='width=device-width,initial-scale=1'>
<title>Router Manager Login</title>
<style>
body{font-family:system-ui,sans-serif;background:#10131a;color:#edf0f5;display:grid;place-items:center;min-height:100vh;margin:0}
main{background:#191e28;padding:32px;border:1px solid #303847;border-radius:12px;width:min(380px,90vw)}
h1{margin:0 0 24px;font-size:22px}
label{display:block;margin:14px 0 6px}
input{box-sizing:border-box;width:100%;padding:11px;border-radius:7px;
      border:1px solid #465064;background:#10131a;color:#fff}
button{margin-top:22px;width:100%;padding:11px;border:0;border-radius:7px;background:#4778e8;color:#fff;font-weight:700;cursor:pointer}
.error{color:#ff8e8e}
</style></head>
<body><main><h1>Router Manager</h1>{notice}
<form id=login>
<label>Username<input name=username autocomplete=username required></label>
<label>Password<input name=password type=password autocomplete=current-password required></label>
<button>Sign in</button>
</form>
<p id=message></p></main>
<script nonce="{nonce}">
document.getElementById('login').addEventListener('submit', async event => {
  event.preventDefault();
  const form = new FormData(event.target);
  const response = await fetch('/login', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(Object.fromEntries(form))
  });
  if (response.ok) { location.href = '/'; }
  else { document.getElementById('message').textContent = (await response.json()).detail || 'Login failed'; }
});
</script></body></html>"""


def _login_page(message: str = "", nonce: str = "") -> str:
    notice = f"<p class=error>{html.escape(message)}</p>" if message else ""
    return LOGIN_PAGE_TEMPLATE.replace("{notice}", notice).replace("{nonce}", nonce)


def _nonce() -> str:
    return secrets.token_urlsafe(18)


def _dashboard_page(nonce: str) -> str:
    return TEMPLATE_PATH.read_text(encoding="utf-8").replace("__CSP_NONCE__", nonce)


async def _body(request: Request) -> dict[str, Any]:
    try:
        value = json.loads((await request.body()).decode("utf-8") or "{}")
    except (UnicodeDecodeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="request body must be valid JSON") from exc
    if not isinstance(value, dict):
        raise HTTPException(status_code=400, detail="request body must be an object")
    return value


def _client_key(request: Request) -> str:
    """Identify the caller for login throttling.

    X-Forwarded-For is attacker-controlled unless a trusted proxy sets it, so it is
    only honoured when ROUTER_MANAGER_TRUST_PROXY is set explicitly. Otherwise
    everyone who can reach the service would share the loopback bucket and a single
    client could lock everyone else out, or rotate headers to bypass the limit.
    """
    if os.environ.get("ROUTER_MANAGER_TRUST_PROXY", "").strip().lower() in {"1", "true", "yes"}:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded.split(",")[0].strip():
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _error_detail(exc: Exception) -> str:
    if isinstance(exc, (ValidationError, ManagerError, SecretStoreError, AdapterError, UnsupportedOperation)):
        return str(exc)[:240]
    return "router operation failed"


def _reject_plaintext_credentials(body: dict[str, Any]) -> None:
    forbidden = PLAINTEXT_CREDENTIAL_FIELDS.intersection(body)
    if forbidden:
        raise HTTPException(
            status_code=400,
            detail=(
                "plaintext credentials and secret references are not accepted through the API: "
                f"{', '.join(sorted(forbidden))}"
            ),
        )


def create_app(manager: DeviceManager | None = None, settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    manager = manager or DeviceManager(settings.config_path, settings.data_dir)
    sessions = SessionStore()
    limiter = LoginLimiter()
    scheduler = RebootScheduler(manager, settings.data_dir / "scheduler_state.json")

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        stop = asyncio.Event()

        async def scheduler_loop() -> None:
            while not stop.is_set():
                try:
                    await asyncio.to_thread(app.state.scheduler.run_once)
                except Exception:
                    logger.exception("scheduled reboot check failed")
                try:
                    await asyncio.wait_for(stop.wait(), timeout=settings.scheduler_interval)
                except TimeoutError:
                    continue

        task = asyncio.create_task(scheduler_loop())
        try:
            yield
        finally:
            stop.set()
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task

    app = FastAPI(title="Skybre Router Manager", lifespan=lifespan)
    app.state.manager = manager
    app.state.settings = settings
    app.state.sessions = sessions
    app.state.scheduler = scheduler

    def _harden(response, nonce=None):
        """Apply the security headers to every response, including early returns.

        Authentication failures, CSRF rejections, and redirects are the responses an
        attacker most wants to embed or cache, so they must be covered too.
        """
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        # The dashboard has no third-party assets and no inline event handlers, so a
        # strict policy applies. The script nonce is injected per request in
        # _dashboard_page; 'strict-dynamic' lets that one script load nothing else.
        script_src = "'strict-dynamic'" if nonce is None else f"'nonce-{nonce}' 'strict-dynamic'"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; "
            f"script-src {script_src}; "
            "style-src 'unsafe-inline'; "
            "img-src 'self' data:; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'none'"
        )
        return response

    @app.middleware("http")
    async def authentication(request: Request, call_next):
        # One nonce per request, shared by the template body and the CSP header.
        request.state.csp_nonce = _nonce()
        path = request.url.path
        public = path in {"/login", "/healthz", "/favicon.ico"}
        if not public:
            if not settings.password:
                if path.startswith("/api/"):
                    return _harden(
                        JSONResponse({"detail": "ROUTER_MANAGER_PASSWORD is not configured"}, status_code=503),
                        request.state.csp_nonce,
                    )
                return _harden(
                    HTMLResponse(
                        _login_page("Server authentication is not configured", request.state.csp_nonce),
                        status_code=503,
                    ),
                    request.state.csp_nonce,
                )
            session = sessions.get(request.cookies.get("router_session"))
            if session is None:
                if path.startswith("/api/"):
                    return _harden(
                    JSONResponse({"detail": "authentication required"}, status_code=401),
                    request.state.csp_nonce,
                )
                return _harden(
                    RedirectResponse("/login", status_code=303), request.state.csp_nonce
                )
            if request.method in {"POST", "PUT", "PATCH", "DELETE"} and path != "/login":
                supplied = request.headers.get("x-csrf-token", "")
                if not hmac.compare_digest(supplied, str(session["csrf"])):
                    return _harden(
                        JSONResponse({"detail": "CSRF validation failed"}, status_code=403),
                        request.state.csp_nonce,
                    )
            request.state.session = session
        return _harden(await call_next(request), request.state.csp_nonce)

    @app.exception_handler(AdapterError)
    async def adapter_error_handler(_, exc: AdapterError):
        return JSONResponse({"detail": _error_detail(exc)}, status_code=502)

    @app.exception_handler(ValidationError)
    async def validation_error_handler(_, exc: ValidationError):
        return JSONResponse({"detail": _error_detail(exc)}, status_code=400)

    @app.exception_handler(ManagerError)
    async def manager_error_handler(_, exc: ManagerError):
        return JSONResponse({"detail": _error_detail(exc)}, status_code=400)

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok", "authentication_configured": bool(settings.password)}

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request):
        return HTMLResponse(_login_page(nonce=request.state.csp_nonce))

    @app.post("/login")
    async def login(request: Request):
        if not settings.password:
            raise HTTPException(status_code=503, detail="ROUTER_MANAGER_PASSWORD is not configured")
        key = _client_key(request)
        if limiter.blocked(key):
            raise HTTPException(status_code=429, detail="too many login attempts")
        body = await _body(request)
        username = str(body.get("username", ""))
        password = str(body.get("password", ""))
        # Both comparisons always run. Short-circuiting on the username would make a
        # wrong username measurably faster than a wrong password, which is enough to
        # enumerate the configured username.
        username_ok = hmac.compare_digest(username.encode(), settings.username.encode())
        password_ok = hmac.compare_digest(password.encode(), settings.password.encode())
        if not (username_ok and password_ok):
            limiter.fail(key)
            raise HTTPException(status_code=401, detail="invalid credentials")
        limiter.success(key)
        session = sessions.create()
        response = JSONResponse({"authenticated": True, "csrf_token": session["csrf"]})
        response.set_cookie(
            "router_session",
            session["token"],
            max_age=43200,
            httponly=True,
            secure=settings.secure_cookie,
            samesite="strict",
            path="/",
        )
        return response

    @app.post("/logout")
    async def logout(request: Request):
        sessions.delete(request.cookies.get("router_session"))
        response = JSONResponse({"authenticated": False})
        response.delete_cookie("router_session", path="/")
        return response

    @app.get("/", response_class=HTMLResponse)
    async def dashboard_page(request: Request):
        return HTMLResponse(_dashboard_page(request.state.csp_nonce))

    @app.get("/api/csrf")
    async def csrf(request: Request):
        return {"csrf_token": request.state.session["csrf"]}

    @app.get("/api/devices")
    async def list_devices(include_status: bool = Query(False)):
        data = await asyncio.to_thread(manager.dashboard, include_status)
        return data

    @app.post("/api/devices")
    async def add_device(request: Request):
        body = await _body(request)
        _reject_plaintext_credentials(body)
        required = ("id", "host", "vendor", "password")
        if any(not body.get(key) for key in required):
            raise HTTPException(status_code=400, detail="id, host, vendor, and password are required")
        allowed = {
            key: body[key]
            for key in (
                "username",
                "model",
                "http_port",
                "https",
                "verify_tls",
                "ssh_port",
                "snmp_port",
                "transport",
                "rpc_path",
                "allow_legacy_login",
                "accept_unknown_host_key",
                "enabled",
                "reboot",
                "metadata",
                "snmp_community",
            )
            if key in body
        }
        try:
            device = await asyncio.to_thread(
                manager.add_device,
                body["id"],
                body["host"],
                body["vendor"],
                password=body["password"],
                **allowed,
            )
        except (ValidationError, ManagerError, SecretStoreError) as exc:
            raise HTTPException(status_code=400, detail=_error_detail(exc)) from exc
        return {"device": device.to_public()}

    @app.put("/api/devices/{identifier}")
    async def update_device(identifier: str, request: Request):
        body = await _body(request)
        _reject_plaintext_credentials(body)
        body.pop("id", None)
        try:
            device = await asyncio.to_thread(manager.update_device, identifier, **body)
        except (ValidationError, ManagerError, SecretStoreError) as exc:
            raise HTTPException(status_code=400, detail=_error_detail(exc)) from exc
        return {"device": device.to_public()}

    @app.post("/api/devices/{identifier}/password")
    async def set_password(identifier: str, request: Request):
        body = await _body(request)
        _reject_plaintext_credentials(body)
        password = body.get("password")
        if not isinstance(password, str) or not password:
            raise HTTPException(status_code=400, detail="password is required and must be a non-empty string")
        verify = body.get("verify", True)
        if not isinstance(verify, bool):
            raise HTTPException(status_code=400, detail="verify must be a boolean")
        try:
            result = await asyncio.to_thread(manager.set_password, identifier, password, verify=verify)
        except (ValidationError, ManagerError, SecretStoreError) as exc:
            raise HTTPException(status_code=400, detail=_error_detail(exc)) from exc
        return result

    @app.delete("/api/devices/{identifier}")
    async def delete_device(identifier: str):
        try:
            await asyncio.to_thread(manager.remove_device, identifier)
        except ManagerError as exc:
            raise HTTPException(status_code=404, detail=_error_detail(exc)) from exc
        return {"deleted": identifier}

    @app.get("/api/devices/{identifier}/status")
    async def device_status(identifier: str):
        try:
            manager.get_device(identifier)
        except ManagerError as exc:
            raise HTTPException(status_code=404, detail=_error_detail(exc)) from exc
        return {"device": identifier, "status": await asyncio.to_thread(manager.get_status, identifier)}

    @app.post("/api/devices/{identifier}/reboot")
    async def reboot_device(identifier: str, request: Request):
        body = await _body(request)
        if body.get("confirm") is not True:
            raise HTTPException(status_code=400, detail="confirm must be true")
        try:
            manager.get_device(identifier)
            success = await asyncio.to_thread(manager.reboot_device, identifier)
        except ManagerError as exc:
            raise HTTPException(status_code=404, detail=_error_detail(exc)) from exc
        if not success:
            raise HTTPException(status_code=502, detail="router did not confirm reboot")
        return {"device": identifier, "status": "initiated"}

    @app.get("/api/devices/{identifier}/clients")
    async def device_clients(identifier: str):
        try:
            manager.get_device(identifier)
            clients = await asyncio.to_thread(manager.get_connected_clients, identifier)
        except ManagerError as exc:
            raise HTTPException(status_code=404, detail=_error_detail(exc)) from exc
        return {"device": identifier, "clients": clients}

    @app.post("/api/devices/{identifier}/ssid")
    async def device_ssid(identifier: str, request: Request):
        body = await _body(request)
        try:
            manager.get_device(identifier)
            changed = await asyncio.to_thread(
                manager.set_wifi_ssid, identifier, body.get("ssid", ""), body.get("radio")
            )
        except ManagerError as exc:
            raise HTTPException(status_code=404, detail=_error_detail(exc)) from exc
        if not changed:
            raise HTTPException(status_code=502, detail="SSID change was not confirmed")
        return {"device": identifier, "status": "changed"}

    @app.get("/api/devices/{identifier}/mesh")
    async def device_mesh(identifier: str):
        try:
            manager.get_device(identifier)
            mesh = await asyncio.to_thread(manager.get_mesh_status, identifier)
        except ManagerError as exc:
            raise HTTPException(status_code=404, detail=_error_detail(exc)) from exc
        return {"device": identifier, "mesh": mesh}

    @app.post("/api/discover")
    async def discover(request: Request):
        body = await _body(request)
        subnet = str(body.get("subnet", "192.168.1.0/24"))
        try:
            devices = await asyncio.to_thread(manager.discover_network, subnet)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=_error_detail(exc)) from exc
        return {"devices": [device.to_dict() for device in devices]}

    @app.get("/api/scheduler")
    async def scheduler_state():
        return {"state": scheduler.get_state()}

    return app


app = create_app()
