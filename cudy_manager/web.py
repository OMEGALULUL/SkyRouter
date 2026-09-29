import asyncio
import contextvars
import functools
import hmac
import html
import json
import logging
import os
import re
import secrets
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from .acs import bootstrap as acs_bootstrap
from .acs.bootstrap import BootstrapRefused
from .acs.client import (
    MAX_LIMIT,
    AcsBusy,
    AcsClient,
    AcsNotFound,
    AcsRejected,
    AcsUnavailable,
    validate_device_id,
    validate_file_metadata,
)
from .acs.jobs import JobStoreError
from .acs.params import BAND_CHOICES, REFRESH_SCOPES
from .acs.service import MAX_FIRMWARE_BYTES, AcsConfirmationRequired, AcsService
from .activity import MAX_LIST as ACTIVITY_MAX_LIST
from .activity import ActivityLog
from .adapters import AdapterError, UnsupportedOperation
from .discovery import DiscoveryError
from .maintenance import STATE_FILE as MAINTENANCE_STATE_FILE
from .maintenance import MaintenanceBusy, MaintenanceError, MaintenanceRunner, MaintenanceStore, PlanNotFound
from .manager import DeviceManager, ManagerError, default_config_path, default_data_dir
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
# Far above any real request: the largest is an add with its metadata.
MAX_BODY_BYTES = 64 * 1024
# The radio names every SSID-capable adapter understands.
SSID_RADIOS = ("2.4G", "5G")
# Brief §3.6: each poll is a few short GETs to the NBI, so a moving job can be
# followed closely without any thread waiting on a router session.
ACS_POLL_ACTIVE = 3.0
ACS_POLL_IDLE = 30.0
ACS_OFF_DETAIL = "TR-069 management is off: set ROUTER_MANAGER_ACS_URL to the GenieACS NBI address"
_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}
_PAGE_NUMBER = re.compile(r"[0-9]{1,9}")
# Who the activity log names for a dashboard change. Everyone signs in with the one
# configured password, so there is no individual to name yet.
DASHBOARD_ACTOR = "Skybre staff"
# A firmware image is the one body larger than MAX_BODY_BYTES, so its route reads
# the raw bytes under this limit instead of through _body().
MAX_FIRMWARE_UPLOAD = MAX_FIRMWARE_BYTES
# The upload's metadata, each from a query field or, failing that, this header.
FIRMWARE_METADATA = {
    "filename": "X-Firmware-Filename",
    "model_hint": "X-Firmware-Model-Hint",
    "version": "X-Firmware-Version",
    "oui": "X-Firmware-OUI",
    "product_class": "X-Firmware-Product-Class",
}
# How long shutdown waits for a maintenance pass to record its outcome.
MAINTENANCE_SHUTDOWN_WAIT = 5.0
# A firmware check holds its thread for up to about a minute and a plan run by hand
# until every router has been visited. Each gets threads of its own, so a few clicks
# cannot take the event loop's default executor, which every other route, the
# scheduler tick and the ACS poll loop share. Requests beyond these wait their turn.
FIRMWARE_CHECK_WORKERS = 4
MAINTENANCE_RUN_WORKERS = 2


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


def _flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    if raw in _TRUE:
        return True
    if raw in _FALSE:
        return False
    raise ValueError(f"{name} must be 1 or 0, not {raw!r}")


def _acs_from_env() -> dict[str, Any]:
    """The ROUTER_MANAGER_ACS_* settings; nothing at all while ROUTER_MANAGER_ACS_URL is unset.

    Unlike the settings above, a bad value stops startup rather than falling back:
    the interval is pushed to every router, and an NBI off this host would hand its
    unauthenticated API, and so every router, to whoever can reach it (F3).
    """
    url = os.environ.get("ROUTER_MANAGER_ACS_URL", "").strip()
    if not url:
        return {}
    allow_remote = _flag("ROUTER_MANAGER_ACS_ALLOW_REMOTE", False)
    try:
        # The client refuses what it would refuse at request time: a scheme other than
        # http(s), credentials, a path, and a non-loopback host unless allowed.
        base_url = AcsClient(url, allow_remote=allow_remote).base_url
    except ValidationError as exc:
        hint = ""
        if "loopback" in str(exc):
            hint = "; set ROUTER_MANAGER_ACS_ALLOW_REMOTE=1 only if the NBI is protected some other way"
        raise ValueError(f"ROUTER_MANAGER_ACS_URL is refused: {exc}{hint}") from None
    raw_interval = os.environ.get("ROUTER_MANAGER_ACS_INFORM_INTERVAL", "").strip()
    interval = acs_bootstrap.DEFAULT_INFORM_INTERVAL
    if raw_interval:
        try:
            interval = acs_bootstrap.validate_inform_interval(int(raw_interval))
        except ValueError:
            raise ValueError(
                f"ROUTER_MANAGER_ACS_INFORM_INTERVAL must be whole seconds from "
                f"{acs_bootstrap.MIN_INFORM_INTERVAL} to {acs_bootstrap.MAX_INFORM_INTERVAL}, not {raw_interval!r}"
            ) from None
    return {
        "acs_url": base_url,
        "acs_allow_remote": allow_remote,
        "acs_inform_interval": interval,
        "acs_scrub_secrets": _flag("ROUTER_MANAGER_ACS_SCRUB_SECRETS", True),
    }


@dataclass
class Settings:
    username: str
    password: str
    secure_cookie: bool
    scheduler_interval: int
    config_path: Path
    data_dir: Path
    # None switches TR-069 management off entirely (brief §2.4).
    acs_url: str | None = None
    acs_allow_remote: bool = False
    acs_inform_interval: int = acs_bootstrap.DEFAULT_INFORM_INTERVAL
    acs_scrub_secrets: bool = True

    @classmethod
    def from_env(cls) -> "Settings":
        password = os.environ.get("ROUTER_MANAGER_PASSWORD", os.environ.get("AUTH_PASSWORD", ""))
        data_dir = default_data_dir()
        return cls(
            username=os.environ.get("ROUTER_MANAGER_USERNAME", os.environ.get("AUTH_USERNAME", "admin")),
            password=password,
            secure_cookie=os.environ.get("ROUTER_MANAGER_SECURE_COOKIE", "0") == "1",
            scheduler_interval=_positive_int("ROUTER_MANAGER_SCHEDULER_INTERVAL", 30, minimum=15),
            config_path=default_config_path(data_dir),
            data_dir=data_dir,
            **_acs_from_env(),
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

    def _recent(self, key: str, now: float) -> list[float]:
        # Sweep periodically so addresses that are never queried again (rotating
        # sources, IPv6 privacy addresses) do not accumulate forever.
        self._sweeps += 1
        if self._sweeps % 50 == 0:
            self._prune(now)
        return [value for value in self._values.get(key, []) if now - value < self.window_seconds]

    def blocked(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            values = self._recent(key, now)
            self._remember(key, values, now)
            return len(values) >= self.maximum

    def attempt(self, key: str) -> bool:
        """Count one login attempt up front, or refuse it when the window is full.

        Checking and counting must be one step. With a separate check before the
        request body was read and a failure recorded after it, every request
        already in flight passed the check, so a burst of parallel guesses was
        not limited at all. A correct login clears the count with success().
        """
        now = time.time()
        with self._lock:
            values = self._recent(key, now)
            allowed = len(values) < self.maximum
            if allowed:
                values.append(now)
            self._remember(key, values, now)
            return allowed

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
<form id=login method=post action=/login>
<label>Username<input name=username autocomplete=username required></label>
<label>Password<input name=password type=password autocomplete=current-password required></label>
<button>Sign in</button>
</form>
<p id=message></p></main>
<script nonce="{nonce}">
document.getElementById('login').addEventListener('submit', async event => {
  event.preventDefault();
  const form = new FormData(event.target);
  const message = document.getElementById('message');
  try {
    const response = await fetch('/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(Object.fromEntries(form))
    });
    if (response.ok) { location.href = '/'; return; }
    message.textContent = (await response.json().catch(() => ({}))).detail || 'Login failed';
  } catch (error) {
    message.textContent = 'The server could not be reached';
  }
});
</script></body></html>"""


def _login_page(message: str = "", nonce: str = "") -> str:
    notice = f"<p class=error>{html.escape(message)}</p>" if message else ""
    return LOGIN_PAGE_TEMPLATE.replace("{notice}", notice).replace("{nonce}", nonce)


def _nonce() -> str:
    return secrets.token_urlsafe(18)


def _dashboard_page(nonce: str) -> str:
    return TEMPLATE_PATH.read_text(encoding="utf-8").replace("__CSP_NONCE__", nonce)


async def _read_capped(request: Request, limit: int, detail: str) -> bytes:
    """The whole request body, refused with 413 as soon as it passes ``limit``."""
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > limit:
        raise HTTPException(status_code=413, detail=detail)
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise HTTPException(status_code=413, detail=detail)
        chunks.append(chunk)
    return b"".join(chunks)


async def _body(request: Request) -> dict[str, Any]:
    # /login is public, so reading without a cap would let anyone make the server
    # buffer an arbitrarily large upload before any check has run.
    raw = await _read_capped(request, MAX_BODY_BYTES, "request body is too large")
    try:
        value = json.loads(raw.decode("utf-8") or "{}")
    # Deeply nested input exhausts the parser's recursion limit rather than
    # raising ValueError.
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise HTTPException(status_code=400, detail="request body must be valid JSON") from exc
    if not isinstance(value, dict):
        raise HTTPException(status_code=400, detail="request body must be an object")
    return value


def session_actor(request: Request) -> str:
    """Who the activity log names for a change made through this request.

    The one place a request becomes an actor: a sign-in handed over from Vexar will
    name the person here. Never taken from a request body, or a client could choose
    what the audit log says about it.
    """
    if getattr(request.state, "session", None) is None:
        raise HTTPException(status_code=401, detail="authentication required")
    return DASHBOARD_ACTOR


def _client_key(request: Request) -> str:
    """Identify the caller for login throttling.

    X-Forwarded-For is attacker-controlled unless a trusted proxy sets it, so it is
    only honoured when ROUTER_MANAGER_TRUST_PROXY is set explicitly. Otherwise
    everyone who can reach the service would share the loopback bucket and a single
    client could lock everyone else out, or rotate headers to bypass the limit.

    Even a trusted proxy only vouches for the entry it appended, the rightmost:
    common proxies keep whatever X-Forwarded-For the client sent and add to it.
    """
    forwarded = ",".join(request.headers.getlist("x-forwarded-for"))
    hops = [hop.strip() for hop in forwarded.split(",") if hop.strip()]
    if os.environ.get("ROUTER_MANAGER_TRUST_PROXY", "").strip().lower() in {"1", "true", "yes"} and hops:
        return hops[-1]
    peer = request.client.host if request.client else "unknown"
    # uvicorn's default proxy_headers trusts loopback peers and swaps the client
    # address for an X-Forwarded-For entry before this code runs. A peer address
    # that could have come from the header is therefore not the caller's own, and
    # keying on it would give a local caller a fresh bucket on every guess.
    if peer in hops:
        return "untrusted-forwarded"
    return peer


def _error_detail(exc: Exception) -> str:
    if isinstance(exc, (ValidationError, ManagerError, SecretStoreError, AdapterError, DiscoveryError)):
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


def _only(body: dict[str, Any], allowed: set[str]) -> None:
    """Refuse fields a route does not take, so a secret can only arrive where it is used."""
    unexpected = sorted(key[:40] for key in body if key not in allowed)
    if unexpected:
        raise HTTPException(status_code=400, detail=f"unexpected field(s): {', '.join(unexpected[:8])}")


def _page_param(value: str | None, name: str, default: int, minimum: int, maximum: int) -> int:
    # Parsed here rather than by FastAPI so a bad value is a 400 like every other
    # refusal, instead of a 422 in a different shape.
    if value is None or value == "":
        return default
    if not _PAGE_NUMBER.fullmatch(value) or not minimum <= int(value) <= maximum:
        raise HTTPException(status_code=400, detail=f"{name} must be a whole number from {minimum} to {maximum}")
    return int(value)


def _text_param(value: str | None, name: str, maximum: int = 200) -> str | None:
    if value is None or value == "":
        return None
    if len(value) > maximum:
        raise HTTPException(status_code=400, detail=f"{name} must be at most {maximum} characters")
    return value


def _stripped(value: str | None) -> str | None:
    return value.strip() if value is not None else None


def _query_flag(value: str | None, name: str) -> bool:
    raw = (value or "").strip().lower()
    if raw in _TRUE:
        return True
    if raw in _FALSE or not raw:
        return False
    raise HTTPException(status_code=400, detail=f"{name} must be true or false")


class AcsNotConfigured(Exception):
    """An /api/acs route was called while ROUTER_MANAGER_ACS_URL is unset."""


# Most specific first. The ACS handlers use it, and so does a route that had to
# withhold an error's text, so both answer with the same status.
_ERROR_STATUS: tuple[tuple[type[BaseException], int], ...] = (
    (AcsConfirmationRequired, 409),
    (BootstrapRefused, 409),
    (AcsBusy, 409),
    (MaintenanceBusy, 409),
    (AcsNotFound, 404),
    (PlanNotFound, 404),
    (AcsUnavailable, 502),
    (AcsRejected, 502),
    (UnsupportedOperation, 501),
    (ValidationError, 400),
    (ManagerError, 400),
    (AdapterError, 502),
)


def _status_of(exc: BaseException) -> int:
    return next((status for kind, status in _ERROR_STATUS if isinstance(exc, kind)), 500)


async def _run_on[T](pool: ThreadPoolExecutor, func: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    """asyncio.to_thread, on the given pool rather than the loop's shared default one."""
    context = contextvars.copy_context()
    call = functools.partial(context.run, func, *args, **kwargs)
    return await asyncio.get_running_loop().run_in_executor(pool, call)


async def _call_with_secret[T](secret: str | None, func: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    """Run a blocking call that is handed a secret, keeping the secret out of any error it raises.

    Nothing is meant to put it there, but an error's text goes back to the browser
    and can reach the log, so it is checked rather than trusted.
    """
    try:
        return await asyncio.to_thread(func, *args, **kwargs)
    except Exception as exc:
        text = str(exc) + json.dumps(getattr(exc, "plan", None), default=str)
        if secret and secret in text:
            logger.error(
                "%s failed with an error that quoted the new password; its text was withheld (%s)",
                getattr(func, "__name__", "the change"),
                type(exc).__name__,
            )
            raise HTTPException(
                status_code=_status_of(exc),
                detail="the change failed, and its error details were withheld because they quoted the new password",
            ) from None
        raise


def _job_without_secret(job: dict[str, Any], secret: str | None) -> dict[str, Any]:
    """The job view, or only its identity if it somehow carries the secret it was given."""
    if not secret or secret not in json.dumps(job, default=str):
        return job
    logger.error("ACS job %s quoted the new Wi-Fi password; its details were withheld", job.get("id"))
    kept = {key: job.get(key) for key in ("id", "acs_id", "kind", "state", "terminal", "done")}
    return {**kept, "message": "Details withheld: they quoted the new password. Check the job list."}


def build_acs_service(
    settings: Settings, manager: DeviceManager, activity: ActivityLog | None = None
) -> AcsService | None:
    """The AcsService the server runs, or None while TR-069 management is off.

    The CLI builds its own through this too, so both share one job file and vault.
    ``activity`` defaults to the manager's log, so both kinds of router share one history.
    """
    if not settings.acs_url:
        return None
    client = AcsClient(settings.acs_url, allow_remote=settings.acs_allow_remote)
    # The manager's vault, so an ACS passphrase sits beside every other router secret.
    return AcsService(
        client,
        manager.secrets,
        settings.data_dir,
        settings.acs_inform_interval,
        settings.acs_scrub_secrets,
        activity=activity if activity is not None else manager.activity,
    )


def _log_scheduled(result: dict[str, Any]) -> None:
    """One log line for a scheduled outcome worth one.

    Otherwise a reboot or plan that keeps failing, say from a bad timezone, is
    invisible until someone asks why the router never restarted.
    """
    status = result.get("status")
    if result.get("source") == "maintenance":
        plan = result.get("plan_name") or result.get("plan")
        if plan is None:
            # The pass itself stopped, say over an unreadable plan file.
            logger.warning("maintenance plans could not run: %s", result.get("reason"))
            return
        device = result.get("device")
        where = "its TR-069 routers" if device == "*" else device or "its routers"
        if status in ("failed", "partial"):
            verdict = "failed" if status == "failed" else "partly failed"
            logger.warning("maintenance plan %s on %s %s: %s", plan, where, verdict, result.get("reason"))
        elif status == "skipped":
            logger.info("maintenance plan %s skipped %s: %s", plan, where, result.get("reason"))
        elif status == "queued":
            # The ACS logs how the job ends.
            logger.info("maintenance plan %s on %s queued: %s", plan, where, result.get("reason"))
        elif status == "done":
            logger.info("maintenance plan %s on %s done", plan, where)
        return
    if status == "failed":
        logger.warning("scheduled reboot of %s failed: %s", result.get("device"), result.get("reason"))
    elif status == "initiated":
        logger.info("scheduled reboot of %s initiated", result.get("device"))


def _recent_runs(state: dict[str, Any], plan: str | None, limit: int) -> list[dict[str, Any]]:
    """The maintenance occurrences in the runner's state, latest first, optionally for one plan."""
    occurrences = state.get("occurrences")
    runs = []
    for key, entry in (occurrences if isinstance(occurrences, dict) else {}).items():
        if not isinstance(entry, dict) or (plan is not None and entry.get("plan") != plan):
            continue
        targets = entry.get("targets")
        held = entry.get("held")
        runs.append(
            {
                "occurrence": key,
                "plan": entry.get("plan"),
                "plan_name": entry.get("plan_name"),
                "trigger": entry.get("trigger"),
                "started": entry.get("created"),
                "targets": {
                    name: item
                    for name, item in (targets if isinstance(targets, dict) else {}).items()
                    if isinstance(item, dict)
                },
                "held": dict(held) if isinstance(held, dict) else {},
            }
        )
    runs.sort(key=lambda run: str(run["started"] or ""), reverse=True)
    return runs[:limit]


def _plan_view(runner: MaintenanceRunner, plan_id: str) -> dict[str, Any]:
    runner.store.get(plan_id)  # 400 for a malformed id, 404 for an unknown one
    view = next((item for item in runner.overview() if item["id"] == plan_id), None)
    if view is None:
        # Deleted between the two reads.
        raise PlanNotFound("no such maintenance plan")
    return view


def create_app(
    manager: DeviceManager | None = None,
    settings: Settings | None = None,
    acs_service: AcsService | None = None,
    activity: ActivityLog | None = None,
) -> FastAPI:
    settings = settings or Settings.from_env()
    if activity is None:
        # An injected manager's own log, so the routes read what it writes.
        activity = (manager.activity if manager is not None else None) or ActivityLog(settings.data_dir)
    manager = manager or DeviceManager(settings.config_path, settings.data_dir, activity=activity)
    sessions = SessionStore()
    limiter = LoginLimiter()
    scan_lock = threading.Lock()
    acs = acs_service if acs_service is not None else build_acs_service(settings, manager, activity)
    plans = MaintenanceStore(settings.data_dir)
    # Built before the scheduler, which shares its reboot history with the runner so
    # either kind of restart starts the other's cooldown.
    maintenance = MaintenanceRunner(
        manager, acs, plans, activity=activity, state_path=settings.data_dir / MAINTENANCE_STATE_FILE
    )
    scheduler = RebootScheduler(manager, settings.data_dir / "scheduler_state.json", maintenance=maintenance)
    check_pool = ThreadPoolExecutor(FIRMWARE_CHECK_WORKERS, thread_name_prefix="firmware-check")
    run_pool = ThreadPoolExecutor(MAINTENANCE_RUN_WORKERS, thread_name_prefix="maintenance-run")

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        stop = asyncio.Event()

        async def scheduler_loop() -> None:
            while not stop.is_set():
                try:
                    # The devices' reboot policies, then a pass over the maintenance
                    # plans in the scheduler's own thread; a pass's results come back
                    # from the tick after it finishes.
                    results = await asyncio.to_thread(app.state.scheduler.tick)
                    for result in results:
                        _log_scheduled(result)
                except Exception:
                    logger.exception("scheduled reboot check failed")
                try:
                    await asyncio.wait_for(stop.wait(), timeout=settings.scheduler_interval)
                except TimeoutError:
                    continue

        async def acs_loop(wake: asyncio.Event) -> None:
            while not stop.is_set():
                # Cleared before polling, so a job started mid-poll still gets its own.
                wake.clear()
                busy = False
                service = app.state.acs
                try:
                    if service is not None:
                        await asyncio.to_thread(service.poll_jobs)
                        busy = await asyncio.to_thread(service.has_active_jobs)
                except JobStoreError as exc:
                    # Not transient: acs_jobs.json needs the operator, and a traceback
                    # every poll would bury the one line that says so.
                    logger.error("ACS jobs cannot advance: %s", exc)
                except Exception:
                    logger.exception("ACS job poll failed")
                with suppress(TimeoutError):
                    await asyncio.wait_for(wake.wait(), timeout=ACS_POLL_ACTIVE if busy else ACS_POLL_IDLE)

        tasks = [asyncio.create_task(scheduler_loop())]
        if app.state.acs is not None:
            app.state.acs_wake = asyncio.Event()
            tasks.append(asyncio.create_task(acs_loop(app.state.acs_wake)))
        try:
            yield
        finally:
            stop.set()
            if app.state.acs_wake is not None:
                app.state.acs_wake.set()
            for task in tasks:
                task.cancel()
            for task in tasks:
                with suppress(asyncio.CancelledError):
                    await task
            # A pass cut off mid-way has already claimed its routers, so nothing is
            # repeated; waiting a little lets it record how each one ended.
            try:
                finished = await asyncio.to_thread(app.state.scheduler.join_maintenance, MAINTENANCE_SHUTDOWN_WAIT)
                if not finished:
                    logger.warning("stopping while a maintenance pass is still running")
            except Exception:
                logger.exception("could not wait for the maintenance pass")

    app = FastAPI(title="Skybre Router Manager", lifespan=lifespan)
    app.state.manager = manager
    app.state.settings = settings
    app.state.sessions = sessions
    app.state.scheduler = scheduler
    app.state.acs = acs
    app.state.activity = activity
    app.state.maintenance = maintenance
    # Set by the lifespan; started jobs set it so the poll loop need not sleep out
    # its idle interval before following them.
    app.state.acs_wake = None

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
            # The dashboard and the login form both talk to this origin with fetch().
            # Without connect-src they fall back to default-src 'none' and every
            # request is blocked while the page still looks fine.
            "connect-src 'self'; "
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
                # Compare bytes: header values arrive latin-1 decoded, and
                # compare_digest raises TypeError for a non-ASCII str.
                supplied = request.headers.get("x-csrf-token", "").encode("latin-1", "replace")
                if not hmac.compare_digest(supplied, str(session["csrf"]).encode()):
                    return _harden(
                        JSONResponse({"detail": "CSRF validation failed"}, status_code=403),
                        request.state.csp_nonce,
                    )
            request.state.session = session
        try:
            response = await call_next(request)
        except Exception:
            # Without this the server's bare 500 bypasses _harden entirely.
            logger.exception("unhandled error serving %s %s", request.method, path)
            response = JSONResponse({"detail": "internal server error"}, status_code=500)
        return _harden(response, request.state.csp_nonce)

    @app.exception_handler(AdapterError)
    async def adapter_error_handler(_, exc: AdapterError):
        return JSONResponse({"detail": _error_detail(exc)}, status_code=502)

    # The operation cannot succeed as configured however often it is retried, and
    # a gateway error would invite retry-on-502 clients to keep repeating it.
    @app.exception_handler(UnsupportedOperation)
    async def unsupported_operation_handler(_, exc: UnsupportedOperation):
        return JSONResponse({"detail": _error_detail(exc)}, status_code=501)

    @app.exception_handler(ValidationError)
    async def validation_error_handler(_, exc: ValidationError):
        return JSONResponse({"detail": _error_detail(exc)}, status_code=400)

    @app.exception_handler(ManagerError)
    async def manager_error_handler(_, exc: ManagerError):
        return JSONResponse({"detail": _error_detail(exc)}, status_code=400)

    @app.exception_handler(AcsNotConfigured)
    async def acs_not_configured_handler(_, exc: AcsNotConfigured):
        # configured: false lets the dashboard tell "off" from "broken".
        return JSONResponse({"detail": ACS_OFF_DETAIL, "configured": False}, status_code=503)

    async def acs_error_handler(_, exc: Exception):
        body: dict[str, Any] = {"detail": _error_detail(exc)}
        if isinstance(exc, AcsConfirmationRequired):
            # The dialog shows how the band was worked out and asks before resending.
            body["plan"] = exc.plan
        elif isinstance(exc, BootstrapRefused):
            body["seeded"] = list(exc.seeded)
        elif isinstance(exc, AcsUnavailable):
            if not body["detail"].startswith("ACS unavailable"):
                body["detail"] = f"ACS unavailable: {body['detail']}"
            body["outcome_unknown"] = exc.outcome_unknown
        return JSONResponse(body, status_code=_status_of(exc))

    for kind in (AcsConfirmationRequired, BootstrapRefused, AcsBusy, AcsNotFound, AcsUnavailable, AcsRejected):
        app.add_exception_handler(kind, acs_error_handler)

    @app.exception_handler(JobStoreError)
    async def job_store_error_handler(_, exc: JobStoreError):
        logger.error("ACS job store: %s", exc)
        return JSONResponse({"detail": f"{str(exc)[:200]}; see the SkyRouter log"}, status_code=500)

    # Both are ValidationErrors, so without their own handlers they would answer 400.
    @app.exception_handler(PlanNotFound)
    async def plan_not_found_handler(_, exc: PlanNotFound):
        return JSONResponse({"detail": _error_detail(exc)}, status_code=404)

    @app.exception_handler(MaintenanceBusy)
    async def maintenance_busy_handler(_, exc: MaintenanceBusy):
        return JSONResponse({"detail": _error_detail(exc)}, status_code=409)

    @app.exception_handler(MaintenanceError)
    async def maintenance_error_handler(_, exc: MaintenanceError):
        # Not transient: the plan or state file needs the operator.
        logger.error("maintenance: %s", exc)
        return JSONResponse({"detail": f"{str(exc)[:200]}; see the SkyRouter log"}, status_code=500)

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
        if not limiter.attempt(key):
            raise HTTPException(status_code=429, detail="too many login attempts")
        body = await _body(request)
        username = str(body.get("username", ""))
        password = str(body.get("password", ""))
        # Both comparisons always run. Short-circuiting on the username would make a
        # wrong username measurably faster than a wrong password, which is enough to
        # enumerate the configured username. surrogatepass because JSON can carry a
        # lone surrogate ("\ud800"), which a plain encode() refuses.
        username_ok = hmac.compare_digest(
            username.encode("utf-8", "surrogatepass"), settings.username.encode("utf-8", "surrogatepass")
        )
        password_ok = hmac.compare_digest(
            password.encode("utf-8", "surrogatepass"), settings.password.encode("utf-8", "surrogatepass")
        )
        if not (username_ok and password_ok):
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
                actor=session_actor(request),
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
        if "actor" in body:
            # Forwarded as keywords, it would let a client choose what the audit log says.
            raise HTTPException(status_code=400, detail="actor is set by SkyRouter from the signed-in session")
        try:
            device = await asyncio.to_thread(manager.update_device, identifier, actor=session_actor(request), **body)
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
            result = await asyncio.to_thread(
                manager.set_password, identifier, password, verify=verify, actor=session_actor(request)
            )
        except (ValidationError, ManagerError, SecretStoreError) as exc:
            raise HTTPException(status_code=400, detail=_error_detail(exc)) from exc
        return result

    @app.delete("/api/devices/{identifier}")
    async def delete_device(identifier: str, request: Request):
        try:
            await asyncio.to_thread(manager.remove_device, identifier, actor=session_actor(request))
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
            success = await asyncio.to_thread(manager.reboot_device, identifier, actor=session_actor(request))
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
        radio = body.get("radio")
        if radio is not None and (not isinstance(radio, str) or radio not in SSID_RADIOS):
            raise HTTPException(status_code=400, detail=f"radio must be one of {', '.join(SSID_RADIOS)}, or omitted")
        try:
            manager.get_device(identifier)
            changed = await asyncio.to_thread(
                manager.set_wifi_ssid, identifier, body.get("ssid", ""), radio, actor=session_actor(request)
            )
        except ManagerError as exc:
            raise HTTPException(status_code=404, detail=_error_detail(exc)) from exc
        if not changed:
            raise HTTPException(status_code=502, detail="SSID change was not confirmed")
        return {"device": identifier, "status": "changed"}

    @app.post("/api/devices/{identifier}/wifi-password")
    async def device_wifi_password(identifier: str, request: Request):
        body = await _body(request)
        _only(body, {"password", "radio", "confirm"})
        # Every client on the network drops off, so the caller has to mean it.
        if body.get("confirm") is not True:
            raise HTTPException(
                status_code=400, detail="confirm must be true: every Wi-Fi client is disconnected by this change"
            )
        password = body.get("password")
        if not isinstance(password, str) or not password:
            raise HTTPException(status_code=400, detail="password is required and must be a non-empty string")
        radio = body.get("radio")
        if radio is not None and (not isinstance(radio, str) or radio not in SSID_RADIOS):
            raise HTTPException(status_code=400, detail=f"radio must be one of {', '.join(SSID_RADIOS)}, or omitted")
        try:
            manager.get_device(identifier)
            changed = await _call_with_secret(
                password, manager.set_wifi_password, identifier, password, radio, actor=session_actor(request)
            )
        except ManagerError as exc:
            raise HTTPException(status_code=404, detail=_error_detail(exc)) from exc
        if not changed:
            raise HTTPException(status_code=502, detail="the router did not confirm the Wi-Fi password change")
        return {"device": identifier, "status": "changed", "radio": radio}

    @app.get("/api/devices/{identifier}/mesh")
    async def device_mesh(identifier: str):
        try:
            manager.get_device(identifier)
            mesh = await asyncio.to_thread(manager.get_mesh_status, identifier)
        except ManagerError as exc:
            raise HTTPException(status_code=404, detail=_error_detail(exc)) from exc
        return {"device": identifier, "mesh": mesh}

    # --- firmware on a directly managed router's own web UI

    def known(identifier: str) -> str:
        try:
            return manager.get_device(identifier).identifier
        except ManagerError as exc:
            raise HTTPException(status_code=404, detail=_error_detail(exc)) from exc

    @app.get("/api/devices/{identifier}/firmware")
    async def device_firmware(identifier: str):
        device = known(identifier)
        return {"device": device, "firmware": await asyncio.to_thread(manager.firmware_info, device)}

    @app.put("/api/devices/{identifier}/firmware/auto-update")
    async def device_auto_update(identifier: str, request: Request):
        body = await _body(request)
        _only(body, {"enabled", "window_start_hour"})
        enabled = body.get("enabled")
        if not isinstance(enabled, bool):
            raise HTTPException(status_code=400, detail="enabled must be true or false")
        hour = body.get("window_start_hour")
        if hour is not None and (isinstance(hour, bool) or not isinstance(hour, int) or not 0 <= hour <= 23):
            raise HTTPException(
                status_code=400, detail="window_start_hour must be a whole hour from 0 to 23, or omitted"
            )
        if hour is not None and not enabled:
            raise HTTPException(
                status_code=400, detail="window_start_hour can only be given while turning automatic update on"
            )
        device = known(identifier)
        changed = await asyncio.to_thread(manager.set_auto_update, device, enabled, hour, actor=session_actor(request))
        if not changed:
            raise HTTPException(status_code=502, detail="the router did not confirm the automatic-update change")
        # Without an hour the router keeps its own window, which is not read again here.
        window = None if hour is None else f"{hour:02d}:00-{(hour + 2) % 24:02d}:00"
        return {"device": device, "status": "changed", "enabled": enabled, "window_start_hour": hour, "window": window}

    @app.post("/api/devices/{identifier}/firmware/check")
    async def device_firmware_check(identifier: str, request: Request):
        _only(await _body(request), set())
        device = known(identifier)
        # Blocks for as long as the router takes to answer, up to about a minute.
        found = await _run_on(check_pool, manager.check_firmware_update, device, actor=session_actor(request))
        return {
            "device": device,
            "check": found,
            "installed": False,
            "message": "An update check only asks the router whether newer firmware exists; nothing was installed.",
        }

    @app.post("/api/discover")
    async def discover(request: Request):
        body = await _body(request)
        subnet = str(body.get("subnet", "192.168.1.0/24"))
        # A /22 scan holds a shared worker thread for minutes and starts its own
        # pool of probes. Unguarded, a few clicks starve every other to_thread
        # route and the scheduler's reboot checks.
        if not scan_lock.acquire(blocking=False):
            raise HTTPException(status_code=409, detail="a network scan is already running")
        try:
            devices = await asyncio.to_thread(manager.discover_network, subnet)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=_error_detail(exc)) from exc
        finally:
            scan_lock.release()
        return {"devices": [device.to_dict() for device in devices]}

    @app.get("/api/scheduler")
    async def scheduler_state():
        return {"state": scheduler.get_state()}

    # --- the activity log: who changed what on which router. ActivityError is a
    # ValidationError, so a bad filter is a 400 like every other refusal.

    @app.get("/api/activity")
    async def activity_list(
        router: str | None = Query(None),
        who: str | None = Query(None),
        kind: str | None = Query(None),
        limit: str | None = Query(None),
        before: str | None = Query(None),
    ):
        count = _page_param(limit, "limit", 200, 1, ACTIVITY_MAX_LIST)
        entries = await asyncio.to_thread(
            activity.list,
            _text_param(router, "router"),
            _text_param(who, "who"),
            _text_param(kind, "kind"),
            count,
            _text_param(before, "before"),
        )
        # The next page starts after the last entry of a full one.
        return {"entries": entries, "next_before": entries[-1]["id"] if len(entries) == count else None}

    @app.get("/api/activity.csv")
    async def activity_csv(
        router: str | None = Query(None),
        who: str | None = Query(None),
        kind: str | None = Query(None),
        limit: str | None = Query(None),
        before: str | None = Query(None),
    ):
        # Without a limit, every entry the log still keeps.
        count = None if not limit else _page_param(limit, "limit", 1, 1, 999_999_999)
        text = await asyncio.to_thread(
            activity.export_csv,
            _text_param(router, "router"),
            _text_param(who, "who"),
            _text_param(kind, "kind"),
            count,
            _text_param(before, "before"),
        )
        stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        return Response(
            text,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="skyrouter-activity-{stamp}.csv"'},
        )

    # --- TR-069 through GenieACS (brief §3.8). Session and CSRF come from the
    # middleware above; every service call blocks, so each goes through to_thread.

    def require_acs() -> AcsService:
        service = app.state.acs
        if service is None:
            raise AcsNotConfigured()
        return service

    def started(job: dict[str, Any]) -> dict[str, Any]:
        if app.state.acs_wake is not None:
            app.state.acs_wake.set()
        return {"job": job}

    @app.get("/api/acs")
    async def acs_health():
        return await asyncio.to_thread(require_acs().health)

    @app.get("/api/acs/devices")
    async def acs_devices(
        q: str | None = Query(None),
        tag: str | None = Query(None),
        skip: str | None = Query(None),
        limit: str | None = Query(None),
    ):
        service = require_acs()
        offset = _page_param(skip, "skip", 0, 0, 999_999_999)
        count = _page_param(limit, "limit", 50, 1, MAX_LIMIT)
        return await asyncio.to_thread(service.list_devices, q, tag or None, offset, count)

    @app.get("/api/acs/devices/{acs_id}")
    async def acs_device(acs_id: str):
        return await asyncio.to_thread(require_acs().device_detail, acs_id)

    @app.post("/api/acs/devices/{acs_id}/refresh", status_code=202)
    async def acs_refresh(acs_id: str, request: Request):
        service = require_acs()
        body = await _body(request)
        _only(body, {"scope"})
        scope = body.get("scope")
        if not isinstance(scope, str) or scope not in REFRESH_SCOPES:
            raise HTTPException(status_code=400, detail=f"scope must be one of {', '.join(REFRESH_SCOPES)}")
        return started(await asyncio.to_thread(service.refresh, acs_id, scope))

    @app.post("/api/acs/devices/{acs_id}/wifi", status_code=202)
    async def acs_wifi(acs_id: str, request: Request):
        service = require_acs()
        body = await _body(request)
        # The one route that takes a Wi-Fi passphrase. It goes to the service, which
        # keeps it in the vault and the write task only; it is never sent back.
        _only(body, {"band", "ssid", "passphrase", "confirm_guessed_band"})
        band = body.get("band")
        if not isinstance(band, str) or band not in BAND_CHOICES:
            raise HTTPException(status_code=400, detail=f"band must be one of {', '.join(BAND_CHOICES)}")
        ssid = body.get("ssid")
        if ssid is not None and not isinstance(ssid, str):
            raise HTTPException(status_code=400, detail="ssid must be a string, or omitted to keep the current one")
        passphrase = body.get("passphrase")
        if passphrase is not None and not isinstance(passphrase, str):
            raise HTTPException(status_code=400, detail="passphrase must be a string, or omitted to keep it")
        if ssid is None and passphrase is None:
            raise HTTPException(status_code=400, detail="give a new network name (ssid), a new passphrase, or both")
        confirm_guessed_band = body.get("confirm_guessed_band", False)
        if not isinstance(confirm_guessed_band, bool):
            raise HTTPException(status_code=400, detail="confirm_guessed_band must be true or false")
        job = await _call_with_secret(
            passphrase,
            service.set_wifi,
            acs_id,
            band,
            ssid,
            passphrase,
            confirm_guessed_band,
            actor=session_actor(request),
        )
        return started(_job_without_secret(job, passphrase))

    @app.post("/api/acs/devices/{acs_id}/reboot", status_code=202)
    async def acs_reboot(acs_id: str, request: Request):
        service = require_acs()
        body = await _body(request)
        _only(body, {"confirm"})
        if body.get("confirm") is not True:
            raise HTTPException(status_code=400, detail="confirm must be true")
        return started(await asyncio.to_thread(service.reboot, acs_id, actor=session_actor(request)))

    @app.post("/api/acs/devices/{acs_id}/tags/{tag}")
    async def acs_add_tag(acs_id: str, tag: str, request: Request):
        service = require_acs()
        _only(await _body(request), set())
        return await asyncio.to_thread(service.add_tag, acs_id, tag)

    @app.delete("/api/acs/devices/{acs_id}/tags/{tag}")
    async def acs_remove_tag(acs_id: str, tag: str):
        return await asyncio.to_thread(require_acs().remove_tag, acs_id, tag)

    # The "New devices" inbox (§3.9): adopting only removes the first-contact tag.
    @app.post("/api/acs/devices/{acs_id}/adopt")
    async def acs_adopt(acs_id: str, request: Request):
        service = require_acs()
        _only(await _body(request), set())
        return await asyncio.to_thread(service.adopt, acs_id)

    # Lets a reloaded dashboard pick up the jobs it was following.
    @app.get("/api/acs/jobs")
    async def acs_jobs(acs_id: str | None = Query(None), active: str | None = Query(None)):
        service = require_acs()
        if acs_id:
            validate_device_id(acs_id)
        active_only = _query_flag(active, "active")
        return {"jobs": await asyncio.to_thread(service.list_jobs, acs_id or None, active_only)}

    @app.get("/api/acs/jobs/{job_id}")
    async def acs_job(job_id: str):
        return {"job": await asyncio.to_thread(require_acs().get_job, job_id)}

    @app.delete("/api/acs/jobs/{job_id}")
    async def acs_cancel_job(job_id: str, request: Request):
        service = require_acs()
        return {"job": await asyncio.to_thread(service.cancel_job, job_id, actor=session_actor(request))}

    @app.post("/api/acs/faults/{fault_id}/retry")
    async def acs_retry_fault(fault_id: str, request: Request):
        service = require_acs()
        _only(await _body(request), set())
        return await asyncio.to_thread(service.retry_fault, fault_id)

    @app.delete("/api/acs/faults/{fault_id}")
    async def acs_clear_fault(fault_id: str):
        return await asyncio.to_thread(require_acs().clear_fault, fault_id)

    @app.post("/api/acs/bootstrap")
    async def acs_install_bootstrap(request: Request):
        service = require_acs()
        body = await _body(request)
        _only(body, {"confirm", "remove_seeded"})
        if body.get("confirm") is not True:
            raise HTTPException(status_code=400, detail="confirm must be true")
        remove_seeded = body.get("remove_seeded", False)
        if not isinstance(remove_seeded, bool):
            raise HTTPException(status_code=400, detail="remove_seeded must be true or false")
        return await asyncio.to_thread(service.bootstrap, remove_seeded)

    # --- the TR-069 firmware library and upgrades

    @app.get("/api/acs/firmware")
    async def acs_firmware_list():
        return {"firmware": await asyncio.to_thread(require_acs().list_firmware)}

    @app.post("/api/acs/firmware", status_code=201)
    async def acs_firmware_add(request: Request):
        service = require_acs()
        # Raw bytes rather than a multipart form, which would need a parser this
        # project does not ship; a form's framing stored as firmware would be flashed.
        media = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if media not in {"", "application/octet-stream"}:
            raise HTTPException(
                status_code=415,
                detail="send the firmware image itself as the request body, as application/octet-stream",
            )
        unexpected = sorted(key[:40] for key in request.query_params if key not in FIRMWARE_METADATA)
        if unexpected:
            raise HTTPException(status_code=400, detail=f"unexpected field(s): {', '.join(unexpected[:8])}")
        values: dict[str, str | None] = {}
        for name, header in FIRMWARE_METADATA.items():
            query, sent = request.query_params.get(name), request.headers.get(header)
            if query is not None and sent is not None and query != sent:
                raise HTTPException(status_code=400, detail=f"{name} was given twice with different values")
            values[name] = query if query is not None else sent
        # Checked before the upload is read, so a typo costs nobody 64 MiB of buffering.
        version, oui, product_class = (
            validate_file_metadata(_stripped(values[name]), label)
            for name, label in (("version", "version"), ("oui", "OUI"), ("product_class", "product class"))
        )
        limit_mib = MAX_FIRMWARE_UPLOAD // (1024 * 1024)
        data = await _read_capped(request, MAX_FIRMWARE_UPLOAD, f"the firmware file is larger than {limit_mib} MiB")
        record = await asyncio.to_thread(
            service.add_firmware, data, values["filename"], values["model_hint"], version, oui, product_class
        )
        return {"firmware": record}

    @app.delete("/api/acs/firmware/{name}")
    async def acs_firmware_remove(name: str):
        return await asyncio.to_thread(require_acs().remove_firmware, name)

    @app.post("/api/acs/devices/{acs_id}/firmware", status_code=202)
    async def acs_firmware_upgrade(acs_id: str, request: Request):
        service = require_acs()
        body = await _body(request)
        _only(body, {"firmware", "confirm", "confirm_model_mismatch"})
        if body.get("confirm") is not True:
            raise HTTPException(
                status_code=400, detail="confirm must be true: the router installs the firmware and restarts"
            )
        firmware = body.get("firmware")
        if not isinstance(firmware, str):
            raise HTTPException(status_code=400, detail="firmware must name a file in the firmware library")
        mismatch = body.get("confirm_model_mismatch", False)
        if not isinstance(mismatch, bool):
            raise HTTPException(status_code=400, detail="confirm_model_mismatch must be true or false")
        job = await asyncio.to_thread(
            service.firmware_upgrade, acs_id, firmware, mismatch, actor=session_actor(request)
        )
        return started(job)

    # --- maintenance plans. Their changes are not in the activity log, which is
    # about routers; each router a plan acts on is logged under the plan's name.

    @app.get("/api/maintenance/plans")
    async def maintenance_plans():
        return {"plans": await asyncio.to_thread(maintenance.overview)}

    @app.post("/api/maintenance/plans", status_code=201)
    async def maintenance_create(request: Request):
        body = await _body(request)
        who = session_actor(request)
        plan = await asyncio.to_thread(plans.create, body)
        logger.info("maintenance plan %s (%s) created by %s", plan["id"], plan["name"], who)
        return {"plan": plan}

    @app.get("/api/maintenance/plans/{plan_id}")
    async def maintenance_plan(plan_id: str):
        return {"plan": await asyncio.to_thread(_plan_view, maintenance, plan_id)}

    @app.put("/api/maintenance/plans/{plan_id}")
    async def maintenance_update(plan_id: str, request: Request):
        body = await _body(request)
        who = session_actor(request)
        plan = await asyncio.to_thread(plans.update, plan_id, body)
        logger.info("maintenance plan %s (%s) changed by %s", plan["id"], plan["name"], who)
        return {"plan": plan}

    @app.delete("/api/maintenance/plans/{plan_id}")
    async def maintenance_delete(plan_id: str, request: Request):
        who = session_actor(request)
        deleted = await asyncio.to_thread(plans.delete, plan_id)
        logger.info("maintenance plan %s (%s) deleted by %s", deleted["id"], deleted["name"], who)
        return deleted

    @app.post("/api/maintenance/plans/{plan_id}/run")
    async def maintenance_run(plan_id: str, request: Request):
        body = await _body(request)
        _only(body, {"confirm"})
        if body.get("confirm") is not True:
            raise HTTPException(
                status_code=400,
                detail="confirm must be true: the plan acts on its routers now, whether or not its window is open",
            )
        # Blocks until every router has been visited: minutes for a large plan.
        results = await _run_on(run_pool, maintenance.run_now, plan_id, session_actor(request))
        if app.state.acs_wake is not None and any(
            action.get("status") == "queued" for result in results for action in result.get("actions", [])
        ):
            app.state.acs_wake.set()
        return {"plan": plan_id, "results": results}

    @app.get("/api/maintenance/runs")
    async def maintenance_runs(plan: str | None = Query(None), limit: str | None = Query(None)):
        count = _page_param(limit, "limit", 50, 1, 500)
        state = await asyncio.to_thread(maintenance.get_state)
        return {"runs": _recent_runs(state, _text_param(plan, "plan", 64), count)}

    return app


def __getattr__(name: str) -> Any:
    """Build the default application on first access.

    ``uvicorn cudy_manager.web:app`` needs a module-level attribute, but
    constructing it eagerly meant that merely importing this module read the
    device config and opened the credential vault. Under test that wrote a real
    config file into the working directory and made collection order-dependent.
    """
    if name == "app":
        application = create_app()
        globals()["app"] = application
        return application
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
