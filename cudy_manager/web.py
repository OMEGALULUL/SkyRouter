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
PLAINTEXT_CREDENTIAL_FIELDS = {
    "ssh_password",
    "luci_password",
    "snmp_community",
    "password_ref",
    "snmp_community_ref",
}


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
            scheduler_interval=max(15, int(os.environ.get("ROUTER_MANAGER_SCHEDULER_INTERVAL", "30"))),
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
    def __init__(self, maximum: int = 5, window_seconds: int = 900):
        self.maximum = maximum
        self.window_seconds = window_seconds
        self._values: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def blocked(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            values = [value for value in self._values.get(key, []) if now - value < self.window_seconds]
            self._values[key] = values
            return len(values) >= self.maximum

    def fail(self, key: str) -> None:
        with self._lock:
            self._values.setdefault(key, []).append(time.time())

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
<script>
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


def _login_page(message: str = "") -> str:
    notice = f"<p class=error>{html.escape(message)}</p>" if message else ""
    return LOGIN_PAGE_TEMPLATE.replace("{notice}", notice)


def _dashboard_page() -> str:
    return TEMPLATE_PATH.read_text(encoding="utf-8")


async def _body(request: Request) -> dict[str, Any]:
    try:
        value = json.loads((await request.body()).decode("utf-8") or "{}")
    except (UnicodeDecodeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="request body must be valid JSON") from exc
    if not isinstance(value, dict):
        raise HTTPException(status_code=400, detail="request body must be an object")
    return value


def _client_key(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    return forwarded.split(",")[0].strip() or (request.client.host if request.client else "unknown")


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

    @app.middleware("http")
    async def authentication(request: Request, call_next):
        path = request.url.path
        public = path in {"/login", "/healthz", "/favicon.ico"}
        if not public:
            if not settings.password:
                if path.startswith("/api/"):
                    return JSONResponse({"detail": "ROUTER_MANAGER_PASSWORD is not configured"}, status_code=503)
                return HTMLResponse(_login_page("Server authentication is not configured"), status_code=503)
            session = sessions.get(request.cookies.get("router_session"))
            if session is None:
                if path.startswith("/api/"):
                    return JSONResponse({"detail": "authentication required"}, status_code=401)
                return RedirectResponse("/login", status_code=303)
            if request.method in {"POST", "PUT", "PATCH", "DELETE"} and path != "/login":
                supplied = request.headers.get("x-csrf-token", "")
                if not hmac.compare_digest(supplied, str(session["csrf"])):
                    return JSONResponse({"detail": "CSRF validation failed"}, status_code=403)
            request.state.session = session
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

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
    async def login_page():
        return HTMLResponse(_login_page())

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
        if not hmac.compare_digest(username.encode(), settings.username.encode()) or not hmac.compare_digest(
            password.encode(), settings.password.encode()
        ):
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
    async def dashboard_page():
        return HTMLResponse(_dashboard_page())

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
            device = manager.add_device(
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
            device = manager.update_device(identifier, **body)
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
            result = manager.set_password(identifier, password, verify=verify)
        except (ValidationError, ManagerError, SecretStoreError) as exc:
            raise HTTPException(status_code=400, detail=_error_detail(exc)) from exc
        return result

    @app.delete("/api/devices/{identifier}")
    async def delete_device(identifier: str):
        try:
            manager.remove_device(identifier)
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
