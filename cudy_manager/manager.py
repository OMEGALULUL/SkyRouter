import contextlib
import fcntl
import hashlib
import hmac
import logging
import os
import tempfile
import threading
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from .activity import ActivityError, ActivityLog, normalise_actor
from .adapters import (
    AdapterError,
    AuthenticationRejected,
    CudyAdapter,
    ProtocolMismatch,
    RouterLockedOut,
    TendaAdapter,
    TpLinkAdapter,
    UnsupportedOperation,
)
from .diagnose import diagnose_device
from .discovery import CudyDiscovery, DiscoveredDevice
from .models import Device, RebootPolicy, ValidationError
from .openwrt import OpenWrtAdapter
from .secrets import SecretStore, SecretStoreError

logger = logging.getLogger(__name__)


class ManagerError(RuntimeError):
    pass


class CredentialLatched(AuthenticationRejected):
    """Raised without contacting the router, because it already refused this credential."""


def _env_path(name: str) -> Path | None:
    # Path("") is truthy and means ".", so an exported-but-empty variable has to be
    # treated as unset; otherwise the vault and config land in the working directory.
    raw = os.environ.get(name, "").strip()
    return Path(raw).expanduser() if raw else None


def default_data_dir() -> Path:
    return _env_path("ROUTER_MANAGER_DATA_DIR") or Path.home() / ".local" / "state" / "skybre-router-manager"


def default_config_path(data_dir: Path) -> Path:
    """The config lives beside the vault, never in the package.

    The CLI and the web server must resolve the same file: when they disagreed,
    one process rewrote a config the other had never read.
    """
    return _env_path("ROUTER_MANAGER_CONFIG") or data_dir / "cudy_devices.yaml"


def _require_secret(kind: str, value: str | None) -> None:
    if value is not None and (not isinstance(value, str) or not value):
        raise ValidationError(f"{kind} must be a non-empty string")


# Positional-only, like the DeviceManager methods that take **values: the dashboard
# forwards a JSON body as keywords, and a key named "identifier" or "self" was a TypeError.
def _rebuild(identifier: str, existing: Device, /, **values: Any) -> Device:
    """Rebuild a device from its stored config while keeping runtime state.

    ``Device.to_config`` deliberately omits the cached status and last_seen, so
    naively rebuilding from it would blank the dashboard's status every time a
    device is edited or its password is rotated.
    """
    replacement = Device.from_dict(identifier, {**existing.to_config(), **values})
    replacement.status = existing.status
    replacement.last_seen = existing.last_seen
    return replacement


class _StatusSweep:
    """One status sweep, shared by every caller that asks while it is running.

    Each sweep opens its own bounded thread pool, so starting a second sweep while
    the first is still talking to slow or offline routers would double the thread
    count and re-query every device. Callers therefore join the in-flight sweep
    instead of launching their own.
    """

    def __init__(self, devices: list[Device], fetch: Any) -> None:
        self._devices = devices
        self._fetch = fetch
        self._done = threading.Event()
        self._result: dict[str, dict[str, Any]] = {}
        self._thread = threading.Thread(target=self._run, name="status-sweep", daemon=True)
        self._thread.start()

    @property
    def finished(self) -> bool:
        return self._done.is_set()

    def _run(self) -> None:
        results: dict[str, dict[str, Any]] = {}
        try:
            with ThreadPoolExecutor(max_workers=min(8, len(self._devices))) as pool:
                futures = {pool.submit(self._fetch, device.identifier): device.identifier for device in self._devices}
                for future in as_completed(futures):
                    identifier = futures[future]
                    try:
                        results[identifier] = future.result()
                    except (AdapterError, SecretStoreError, ValidationError, OSError, RuntimeError) as exc:
                        results[identifier] = {"online": False, "error": str(exc)[:200]}
                    except Exception as exc:
                        # One router answering with something no adapter anticipated
                        # (http.client.BadStatusLine, a paramiko error) must not end the
                        # sweep and leave every other router reported offline.
                        logger.exception("status check for %s raised an unexpected error", identifier)
                        results[identifier] = {"online": False, "error": str(exc)[:200]}
        finally:
            self._result = results
            self._done.set()

    def join(self) -> dict[str, dict[str, Any]]:
        self._done.wait()
        return dict(self._result)


def validate_wifi_passphrase(password: Any) -> None:
    """WPA2/WPA3 personal passphrases are 8 to 63 printable ASCII characters.

    A 64-digit hex PSK is refused on purpose: WPA3 (SAE) does not accept one, and a
    router given one on a mixed network can take the radio down for every client.
    """
    if not isinstance(password, str):
        raise ValidationError("Wi-Fi password must be a string")
    if not 8 <= len(password) <= 63:
        raise ValidationError("Wi-Fi password must be 8 to 63 characters")
    if any(not " " <= char <= "~" for char in password):
        raise ValidationError("Wi-Fi password may only use printable ASCII characters (no accents or emoji)")


def validate_wifi_ssid(ssid: Any) -> str:
    """The SSID with surrounding whitespace trimmed, if it is 1 to 32 UTF-8 bytes."""
    if not isinstance(ssid, str) or not ssid.strip():
        raise ValidationError("SSID must not be empty")
    ssid = ssid.strip()
    try:
        size = len(ssid.encode("utf-8"))
    except UnicodeEncodeError:
        # A lone surrogate, which JSON's \ud800 escapes can carry, has no UTF-8 form.
        raise ValidationError("SSID must be valid Unicode text") from None
    # 802.11 caps the SSID at 32 bytes, not characters: accented letters and
    # emoji take several bytes each and routers truncate or reject them.
    if size > 32:
        raise ValidationError("SSID must be at most 32 bytes (fewer characters if it uses accents or emoji)")
    return ssid


# Compared field by field so an edit's entry names what actually changed, after
# Device normalised it, not what the request happened to contain.
_SHOWN_SETTINGS = (
    "vendor",
    "host",
    "http_port",
    "https",
    "verify_tls",
    "ssh_port",
    "snmp_port",
    "transport",
    "rpc_path",
    "username",
    "model",
    "allow_legacy_login",
    "accept_unknown_host_key",
    "enabled",
)
_WITHHELD = "error details withheld because they quoted the new password"
# How long a dashboard or CLI update check waits for the router's own answer. Below
# router_lock_timeout, so a status poll queued behind the check is answered, not
# told the router is busy.
FIRMWARE_CHECK_TIMEOUT = 45.0


def _display_name(device: Device) -> str:
    name = device.metadata.get("name")
    return name.strip() if isinstance(name, str) and name.strip() else device.identifier


def _address(device: Device) -> str:
    host = f"[{device.host}]" if ":" in device.host and not device.host.startswith("[") else device.host
    return f"{host}:{device.ssh_port if device.transport == 'ssh' else device.http_port}"


def _shown(value: Any) -> str:
    if isinstance(value, bool):
        return "on" if value else "off"
    if isinstance(value, str):
        return f'"{value}"'
    return str(value)


def _schedule(policy: RebootPolicy) -> str:
    return f"daily at {policy.at} {policy.timezone}" if policy.enabled else "off"


def _setting_changes(before: Device, after: Device) -> list[tuple[str, str]]:
    changes = [
        (name, f"{name} {_shown(getattr(before, name))} \u2192 {_shown(getattr(after, name))}")
        for name in _SHOWN_SETTINGS
        if getattr(before, name) != getattr(after, name)
    ]
    if before.reboot.to_dict() != after.reboot.to_dict():
        old, new = _schedule(before.reboot), _schedule(after.reboot)
        changes.append(("reboot", f"reboot schedule {old} \u2192 {new}" if old != new else "reboot schedule"))
    if before.metadata != after.metadata:
        # Metadata is free-form and an operator may keep anything in it, so only
        # the fact that it changed is recorded.
        changes.append(("metadata", "metadata"))
    return changes


def _wifi_bands(device: Device, radio: str | None) -> list[str]:
    """The bands a Wi-Fi change reaches, as the dashboard's radio choices describe them."""
    if radio:
        return [radio]
    if device.transport == "ssh":
        section = device.metadata.get("uci_section")
        return [section] if isinstance(section, str) and section else ["all bands"]
    if device.vendor == "tenda":
        return [str(device.metadata.get("radio", "2.4G"))]
    if device.vendor == "cudy":
        return ["2.4G", "5G"]
    return ["all bands"]


def _known_ssids(device: Device) -> dict[str, str]:
    """Network names per band from the last status read, for adapters that report them."""
    ssids = device.status.get("ssids") if isinstance(device.status, dict) else None
    if not isinstance(ssids, dict):
        return {}
    return {str(band): name for band, name in ssids.items() if isinstance(name, str) and name}


def _renamed(bands: list[str], old: dict[str, str], ssid: str) -> str:
    if not any(band in old for band in bands):
        return f'Wi-Fi name changed to "{ssid}" ({", ".join(bands)})'
    steps = [f'{band} "{old[band]}" \u2192 "{ssid}"' if band in old else f'{band} \u2192 "{ssid}"' for band in bands]
    return "Wi-Fi name changed: " + ", ".join(steps)


def _window(hour: int) -> str:
    return f"{hour:02d}:00-{(hour + 2) % 24:02d}:00"


def _check_auto_update(enabled: Any, hour: Any) -> None:
    if not isinstance(enabled, bool):
        raise ValidationError("enabled must be true or false")
    if hour is not None and (isinstance(hour, bool) or not isinstance(hour, int) or not 0 <= hour <= 23):
        raise ValidationError("window_start_hour must be a whole hour from 0 to 23")
    if hour is not None and not enabled:
        # The router's page only sends the window while auto-update is on.
        raise ValidationError("an update window can only be set while turning automatic update on")


def _auto_update_text(enabled: bool, hour: int | None) -> str:
    if not enabled:
        return "Automatic firmware update turned off"
    if hour is None:
        return "Automatic firmware update turned on (the router's update window kept)"
    return f"Automatic firmware update turned on (window {_window(hour)})"


def _check_summary(found: Any) -> tuple[str, dict[str, Any]]:
    found = found if isinstance(found, dict) else {}
    available = found.get("available")
    current = str(found.get("current") or "") or "unknown"
    latest = found.get("latest") if isinstance(found.get("latest"), str) else None
    note = str(found.get("note") or "")
    if available is True:
        text = f"Firmware check: {latest or 'newer firmware'} is available (running {current}); nothing was installed"
    elif available is False:
        text = f"Firmware check: no newer firmware than {current}"
    else:
        # Never reported as "none available": the router's answer was not understood.
        text = f"Firmware check: could not tell whether newer firmware exists ({note or 'no answer'})"
    details = {
        "available": available if isinstance(available, bool) else None,
        "current": current,
        "latest": latest,
        "note": note,
    }
    return text, details


def _refusal(exc: Exception) -> bool:
    """Whether SkyRouter declined the change itself, as opposed to trying and failing."""
    return isinstance(exc, (ValidationError, ManagerError, UnsupportedOperation, CredentialLatched))


def _error_text(exc: Exception, secrets: tuple[str, ...]) -> str:
    text = str(exc) or type(exc).__name__
    # Our own validation and lookup messages never quote a value, and checking them
    # would withhold "must be 8 to 63 characters" for a short passphrase that is a
    # substring of it. An adapter's error is checked rather than trusted.
    if not isinstance(exc, (ValidationError, ManagerError)) and any(secret in text for secret in secrets):
        return _WITHHELD
    return text[:200]


class _Audit:
    """The activity entry for one mutation, filled in as it runs."""

    def __init__(self, actor: str, kind: str, identifier: Any, attempt: str, device: Device | None) -> None:
        self.actor = actor
        self.kind = kind
        self.router = str(identifier).strip() or "unknown"
        self.router_name = ""
        self.attempt = attempt
        self.what = ""
        self.result = "applied"
        self.details: dict[str, Any] = {}
        self.secrets: tuple[str, ...] = ()
        if device is not None:
            self.about(device)

    def about(self, device: Device) -> Device:
        self.router = device.identifier
        self.router_name = _display_name(device)
        return device

    def keep_out(self, *values: Any) -> None:
        self.secrets = tuple(value for value in values if isinstance(value, str) and value)

    def confirmed(self, done: Any, what: str) -> None:
        if done:
            self.what = what
        else:
            self.result = "failed"
            self.what = f"{self.attempt} not confirmed by the router"

    def failed(self, exc: Exception) -> None:
        self.result = "refused" if _refusal(exc) else "failed"
        self.what = f"{self.attempt} {self.result}: {_error_text(exc, self.secrets)}"


class DeviceManager:
    def __init__(
        self,
        config_path: str | Path | None = None,
        data_dir: str | Path | None = None,
        secret_store: SecretStore | None = None,
        activity: ActivityLog | None = None,
    ):
        self.data_dir = Path(data_dir).expanduser() if data_dir else default_data_dir()
        self.config_path = Path(config_path).expanduser() if config_path else default_config_path(self.data_dir)
        self.secrets = secret_store or SecretStore(self.data_dir)
        self.activity = activity
        self.devices: dict[str, Device] = {}
        self._lock = threading.RLock()
        self._transaction_state = threading.local()
        self._status_lock = threading.Lock()
        self._status_flight: _StatusSweep | None = None
        # identifier -> (credential fingerprint, router's refusal). The TP-Link WR840N
        # locks its UI for two hours after ten failed logins, and the dashboard polls
        # every 30 seconds, so a credential the router refused must not be sent again
        # by polling, the scheduler, or any action until the operator changes it or
        # explicitly re-verifies it.
        self._rejected: dict[str, tuple[str, str]] = {}
        self._rejected_lock = threading.Lock()
        self._fingerprint_key = os.urandom(32)
        # Long enough for a slow router's full status read, short enough that a
        # wedged operation reports "busy" instead of hanging the dashboard.
        self.router_lock_timeout = 60.0
        self._load_config()

    def _load_config(self) -> None:
        if not self.config_path.exists():
            if getattr(self._transaction_state, "depth", 0):
                self.save_config()
            else:
                # Created under the transaction lock, which re-checks for the file:
                # an unlocked create at startup could publish an empty inventory over
                # a device another process had just added.
                with self._transaction():
                    pass
            return
        try:
            data = yaml.safe_load(self.config_path.read_text())
        except (OSError, ValueError, yaml.YAMLError) as exc:
            raise ManagerError(f"device config is unreadable: {self.config_path}") from exc
        # Only a missing file means "no devices yet". An empty, scalar, or mis-keyed
        # file is what a crash mid-write or a hand-edit typo leaves behind, and a fresh
        # process has nothing in memory for the truncation guard to compare against,
        # so adopting it would let the next mutation write the loss over the original.
        if not isinstance(data, dict) or "devices" not in data:
            raise ManagerError(
                f"{self.config_path} has no devices mapping; refusing to treat it as empty "
                "(restore it, or write 'devices: {}' to start with no devices)"
            )
        entries = data["devices"]
        if isinstance(entries, list):
            converted = {}
            for item in entries:
                identifier = item.get("id") if isinstance(item, dict) else None
                if not identifier:
                    raise ManagerError(f"{self.config_path} lists a device without an id")
                if str(identifier) in converted:
                    raise ManagerError(f"{self.config_path} lists device {identifier!r} more than once")
                converted[str(identifier)] = item
            entries = converted
        if not isinstance(entries, dict):
            raise ManagerError("device config must contain a devices mapping")
        loaded = {}
        for identifier, raw in entries.items():
            try:
                loaded[str(identifier)] = Device.from_dict(str(identifier), raw)
            except (ValidationError, TypeError, ValueError) as exc:
                raise ManagerError(f"invalid device {identifier!r}: {exc}") from exc
        with self._lock:
            gone = {name: self.devices[name] for name in set(self.devices) - set(loaded)}
        # A removal through this class also destroys the stored password, so a
        # device that vanished from the file while its secret still exists means
        # the file was truncated behind the manager's back. Every mutation
        # re-reads the config and writes it straight back, so adopting that file
        # would persist the loss on the next add, remove, or password change.
        # remove_device keeps a secret a surviving device still uses, so such a
        # reference is no evidence of truncation.
        live = {ref for device in loaded.values() for ref in (device.password_ref, device.snmp_community_ref) if ref}
        stranded = sorted(
            name
            for name, device in gone.items()
            if device.password_ref and device.password_ref not in live and self.secrets.has(device.password_ref)
        )
        if stranded:
            raise ManagerError(
                f"{self.config_path} no longer lists {', '.join(stranded)} but their "
                "credentials are still stored; refusing to continue from a shrunken "
                "device list"
            )
        with self._lock:
            for identifier, device in loaded.items():
                previous = self.devices.get(identifier)
                if previous is not None:
                    device.status = previous.status
                    device.last_seen = previous.last_seen
            self.devices = loaded
        self._validate_references()

    def _validate_references(self) -> None:
        for device in self.devices.values():
            for reference in (device.password_ref, device.snmp_community_ref):
                if reference and not self.secrets.has(reference):
                    raise ManagerError(f"device {device.identifier!r} references a missing secret")

    def save_config(self) -> None:
        with self._lock:
            payload = {"devices": {identifier: device.to_config() for identifier, device in self.devices.items()}}
        directory = self.config_path.parent
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        # A unique name per write (mkstemp also creates it 0600): with one fixed
        # "<config>.tmp", two writers truncated, published, or unlinked each other's file.
        fd, temporary = tempfile.mkstemp(prefix=self.config_path.name + ".", suffix=".tmp", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(yaml.safe_dump(payload, sort_keys=False))
                handle.flush()
                # Without this a power cut can leave the renamed config zero-length.
                os.fsync(handle.fileno())
            os.replace(temporary, self.config_path)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary)
        # The new config is already in place, so a directory that cannot be synced
        # must not fail the save: the caller would roll back secrets it references.
        with contextlib.suppress(OSError):
            directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)

    def _store_secret(self, identifier: str, kind: str, value: str | None, current_ref: str = "") -> str:
        """Store a secret for one device without touching any other device's.

        A reference can be shared (remove_device keeps a secret another device still
        uses), so the conventional name ``device-<id>-<kind>`` may already belong to
        someone else: re-adding a removed id used to silently replace the survivor's
        password. Only ``current_ref`` is ever overwritten, and only when no other
        device uses it; otherwise a fresh name is allocated.
        """
        if value is None:
            return ""
        _require_secret(kind, value)
        others = {
            ref
            for device in self.devices.values()
            if device.identifier != identifier
            for ref in (device.password_ref, device.snmp_community_ref)
            if ref
        }
        if current_ref and current_ref not in others:
            return self.secrets.put(value, current_ref)
        name = f"device-{identifier}-{kind}"
        if name in others or self.secrets.has(name):
            return self.secrets.put(value)
        return self.secrets.put(value, name)

    @contextlib.contextmanager
    def _transaction(self):
        # The depth must be per thread. The dashboard runs these mutations in a
        # thread pool, so a shared counter would let a second thread see a non-zero
        # depth and skip both the file lock and the mutex entirely.
        depth = getattr(self._transaction_state, "depth", 0)
        if depth:
            self._transaction_state.depth = depth + 1
            try:
                yield
            finally:
                self._transaction_state.depth = depth
            return
        lock_path = self.config_path.with_suffix(self.config_path.suffix + ".lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        handle = os.open(lock_path, os.O_WRONLY | os.O_CREAT, 0o600)
        self._transaction_state.depth = 1
        try:
            fcntl.flock(handle, fcntl.LOCK_EX)
            self._lock.acquire()
            try:
                self._load_config()
                # Reads never reload, so a mutation that failed (or whose save failed)
                # would otherwise stay on the dashboard without existing on disk.
                # Mutations replace or pop Device objects, so a shallow copy suffices.
                snapshot = dict(self.devices)
                try:
                    yield
                    self.save_config()
                except BaseException:
                    self.devices = snapshot
                    raise
            finally:
                self._lock.release()
        finally:
            self._transaction_state.depth = 0
            with contextlib.suppress(OSError):
                fcntl.flock(handle, fcntl.LOCK_UN)
            os.close(handle)

    def _peek(self, identifier: str, by_host: bool) -> Device | None:
        """The device an entry is about, for naming it even when the operation fails."""
        if not by_host:
            with self._lock:
                return self.devices.get(identifier)
        try:
            return self.get_device(identifier)
        except ManagerError:
            return None

    @contextlib.contextmanager
    def _audited(
        self, actor: str, kind: str, identifier: Any, attempt: str, device: Device | None = None
    ) -> Iterator[_Audit]:
        """Record one activity entry once the operation inside has finished, however it ends."""
        entry = _Audit(actor, kind, identifier, attempt, device)
        try:
            yield entry
        except Exception as exc:
            entry.failed(exc)
            self._log(entry)
            raise
        self._log(entry)

    def _log(self, entry: _Audit) -> None:
        if self.activity is None:
            return
        try:
            self.activity.record(
                who=entry.actor,
                router=entry.router,
                router_name=entry.router_name,
                kind=entry.kind,
                what=entry.what,
                result=entry.result,
                details=entry.details,
            )
        except (ActivityError, OSError) as exc:
            # The router or config has already changed (or refused). Failing the
            # request now would report a change as not made, and a retry repeats it.
            logger.warning("could not record activity for %s: %s", entry.router, exc)
        except Exception:
            logger.exception("recording activity for %s raised an unexpected error", entry.router)

    def add_device(
        self,
        identifier: str,
        /,
        host: str,
        vendor: str,
        password: str | None = None,
        *,
        actor: str = "system",
        **values: Any,
    ) -> Device:
        # Checked before anything happens: a change must never be made by nobody.
        actor = normalise_actor(actor)
        with self._audited(actor, "setup", identifier, "Adding the router") as entry:
            entry.keep_out(password, values.get("snmp_community"))
            device_id = str(identifier).strip()
            community = values.pop("snmp_community", None)
            candidate = Device.from_dict(device_id, {**values, "vendor": vendor, "host": host})
            refs: dict[str, str] = {}
            try:
                with self._transaction():
                    if device_id in self.devices:
                        raise ManagerError(f"device {device_id!r} already exists")
                    if password is not None:
                        refs["password_ref"] = self._store_secret(device_id, "password", password)
                    if community is not None:
                        refs["snmp_community_ref"] = self._store_secret(device_id, "snmp-community", community)
                    self.devices[device_id] = Device.from_dict(device_id, {**candidate.to_config(), **refs})
                    device = self.devices[device_id]
            except Exception:
                for reference in refs.values():
                    self.secrets.delete(reference)
                raise
            entry.about(device)
            entry.what = f"Added {device.vendor} router at {_address(device)}"
            entry.details = {"vendor": device.vendor, "host": device.host, "transport": device.transport}
        return device

    def update_device(self, identifier: str, /, *, actor: str = "system", **values: Any) -> Device:
        actor = normalise_actor(actor)
        password = values.pop("password", None)
        community = values.pop("snmp_community", None)
        kind = "credentials" if password is not None or community is not None else "setup"
        with self._audited(actor, kind, identifier, "Settings change", self._peek(identifier, by_host=False)) as entry:
            entry.keep_out(password, community)
            # Every input is checked before the first secret is written: the vault write
            # is in place and is not undone, so a request rejected after it still
            # changed the password.
            _require_secret("password", password)
            _require_secret("snmp-community", community)
            with self._transaction():
                # Looked up after the reload rather than in the in-memory snapshot, which
                # does not see devices another process (the CLI) has added.
                existing = self.devices.get(identifier)
                if existing is None:
                    raise ManagerError(f"device {identifier!r} does not exist")
                _rebuild(identifier, existing, **values)
                # The returned reference must be written back: it differs from the stored
                # one whenever that one was shared or empty, and dropping it used to leave
                # the device on its old password.
                if password is not None:
                    values["password_ref"] = self._store_secret(
                        identifier, "password", password, existing.password_ref
                    )
                if community is not None:
                    values["snmp_community_ref"] = self._store_secret(
                        identifier, "snmp-community", community, existing.snmp_community_ref
                    )
                # Rebuild from the state reloaded inside the transaction, not the
                # pre-transaction snapshot, so a concurrent edit is not overwritten.
                self.devices[identifier] = _rebuild(identifier, existing, **values)
                device = self.devices[identifier]
            # Only a new password releases the latch outright; a username or host change
            # releases it through the fingerprint. Clearing on any edit meant renaming the
            # model re-sent a credential the router had already refused.
            if password is not None:
                self._clear_rejection(identifier)
            entry.about(device)
            changes = _setting_changes(existing, device)
            changed = [name for name, _ in changes]
            parts = ["Settings changed: " + ", ".join(text for _, text in changes)] if changes else []
            if password is not None:
                changed.append("password")
                parts.append("router login password replaced")
            if community is not None:
                changed.append("snmp_community")
                parts.append("SNMP community replaced")
            entry.what = "; ".join(parts) if parts else "Settings saved with no changes"
            entry.details = {"changed": changed}
        return device

    def set_password(
        self, identifier: str, password: str, verify: bool = True, *, actor: str = "system"
    ) -> dict[str, Any]:
        actor = normalise_actor(actor)
        attempt = "Router login password change"
        with self._audited(actor, "credentials", identifier, attempt, self._peek(identifier, by_host=True)) as entry:
            entry.keep_out(password)
            with self._transaction():
                # Resolved after the reload, so a device the CLI added is found, and through
                # get_device, so the host the CLI's own pre-check accepted is not refused here.
                device = entry.about(self.get_device(identifier))
                identifier = device.identifier
                if not isinstance(password, str) or not password:
                    raise ValidationError("password must be a non-empty string")
                reference = self._store_secret(identifier, "password", password, device.password_ref)
                if device.password_ref != reference:
                    self.devices[identifier] = _rebuild(identifier, device, password_ref=reference)
            self._clear_rejection(identifier)
            result: dict[str, Any] = {"device": identifier, "password_updated": True}
            reason = "skipped"
            if verify:
                result["verified"] = self.verify_credentials(identifier)
                reason = result["verified"].get("reason", "unreachable")
                if not result["verified"]["ok"]:
                    if reason == "rejected":
                        logger.warning("password for %s was rejected by the router", identifier)
                    else:
                        logger.warning(
                            "could not verify the password for %s: %s", identifier, result["verified"].get("error")
                        )
            # The verification's error text is left out: it comes from the router.
            entry.what = "Router login password changed" + {
                "skipped": " (not tested)",
                "ok": " and accepted by the router",
                "rejected": ", but the router rejected it",
                "locked": ", but the router is locked out so it was not tested",
            }.get(reason, f"; it could not be tested ({reason})")
            entry.details = {"verification": reason}
        return result

    def diagnose(self, identifier: str) -> dict[str, Any]:
        device = self.get_device(identifier)
        if device.transport == "ssh":
            return diagnose_device(device, "")
        try:
            password = self.credentials(device)
        except (SecretStoreError, AdapterError) as exc:
            return {
                "vendor": device.vendor,
                "base_url": f"{'https' if device.https else 'http'}://{device.host}:{device.http_port}",
                "reachable": None,
                "steps": [{"step": "read stored password", "error": str(exc)}],
                "verdict": "no stored password, so run set-password first",
            }
        return diagnose_device(device, password)

    def verify_credentials(self, identifier: str) -> dict[str, Any]:
        device = self.get_device(identifier)
        checked_at = datetime.now(UTC).isoformat()
        try:
            with self._adapter(device) as adapter:
                adapter.status()
        except RouterLockedOut as exc:
            # A locked router refuses every password, so this one is untested rather
            # than wrong; the latch still stops polling from extending the lockout.
            self._record_rejection(device, exc)
            return {"ok": False, "reason": "locked", "error": str(exc)[:200], "checked_at": checked_at}
        except AuthenticationRejected as exc:
            # The router answered and refused the credentials.
            self._record_rejection(device, exc)
            return {"ok": False, "reason": "rejected", "error": str(exc)[:200], "checked_at": checked_at}
        except (ProtocolMismatch, UnsupportedOperation) as exc:
            # The router answered, but not with a login flow this adapter speaks, so
            # neither the password nor the network is what needs fixing.
            return {"ok": False, "reason": "protocol", "error": str(exc)[:200], "checked_at": checked_at}
        except (AdapterError, SecretStoreError, ValidationError, OSError, RuntimeError) as exc:
            # The router could not be checked at all. Saying "rejected" here would
            # send the operator after the password when the real problem is that the
            # device is asleep, unreachable, or on another subnet.
            return {"ok": False, "reason": "unreachable", "error": str(exc)[:200], "checked_at": checked_at}
        except Exception as exc:
            # The password is already saved when set_password verifies it, so an
            # exception no adapter wraps must not turn that into a failed request.
            logger.exception("verifying %s raised an unexpected error", device.identifier)
            return {"ok": False, "reason": "unreachable", "error": str(exc)[:200], "checked_at": checked_at}
        self._clear_rejection(device.identifier)
        return {"ok": True, "reason": "ok", "checked_at": checked_at}

    def remove_device(self, identifier: str, *, actor: str = "system") -> None:
        actor = normalise_actor(actor)
        with self._audited(actor, "setup", identifier, "Removing the router", self._peek(identifier, False)) as entry:
            with self._transaction():
                device = self.devices.pop(identifier, None)
                if device is None:
                    raise ManagerError(f"device {identifier!r} does not exist")
                entry.about(device)
                remaining_refs = {item.password_ref for item in self.devices.values()}
                remaining_refs.update(item.snmp_community_ref for item in self.devices.values())
                # Saved before the delete, because a config still naming a deleted secret
                # stops every device loading; deleted before the lock is released, because
                # another manager that still lists the device would read it gone with its
                # secret present and refuse to continue.
                self.save_config()
                for reference in (device.password_ref, device.snmp_community_ref):
                    if not reference or reference in remaining_refs:
                        continue
                    try:
                        self.secrets.delete(reference)
                    except (SecretStoreError, OSError) as exc:
                        # The removal is already saved; undoing it here would leave memory
                        # and disk disagreeing, so the orphaned secret is only reported.
                        logger.warning("removed %s but could not delete secret %s: %s", identifier, reference, exc)
            entry.what = f"Removed {device.vendor} router at {_address(device)}"
            entry.details = {"vendor": device.vendor, "host": device.host, "transport": device.transport}

    def get_device(self, identifier: str) -> Device:
        with self._lock:
            device = self.devices.get(identifier)
            if device is not None:
                return device
            matches = [candidate for candidate in self.devices.values() if candidate.host == identifier]
        if len(matches) > 1:
            # Several routers behind one public IP differ only by port; guessing the
            # first would reboot the wrong one.
            names = ", ".join(sorted(candidate.identifier for candidate in matches))
            raise ManagerError(f"{identifier!r} is the host of more than one device ({names}); use the device id")
        if matches:
            return matches[0]
        raise ManagerError(f"device {identifier!r} does not exist")

    def get_all_devices(self) -> list[Device]:
        with self._lock:
            return list(self.devices.values())

    def credentials(self, device: Device) -> str:
        if not device.password_ref:
            raise AdapterError(f"device {device.identifier!r} has no password secret")
        try:
            return self.secrets.get(device.password_ref)
        except SecretStoreError as exc:
            raise AdapterError(str(exc)) from exc

    def _fingerprint(self, device: Device) -> str:
        try:
            secret = self.credentials(device)
        except AdapterError:
            secret = ""
        material = "\0".join(
            (device.vendor, device.host, str(device.http_port), device.transport, device.username, secret)
        )
        # Keyed so no plain hash of the router password sits in memory.
        return hmac.new(self._fingerprint_key, material.encode(), hashlib.sha256).hexdigest()

    def _record_rejection(self, device: Device, exc: AuthenticationRejected) -> None:
        fingerprint = self._fingerprint(device)
        with self._rejected_lock:
            self._rejected[device.identifier] = (fingerprint, str(exc)[:200])

    def _clear_rejection(self, identifier: str) -> None:
        with self._rejected_lock:
            self._rejected.pop(identifier, None)

    def rejected_credential(self, device: Device) -> str | None:
        """The router's refusal, if the credential now stored was already rejected.

        Keyed on a fingerprint of the credential rather than cleared only by our own
        setters, so a password rotated by another process (the CLI) releases it.
        """
        with self._rejected_lock:
            entry = self._rejected.get(device.identifier)
        if entry is None:
            return None
        if entry[0] != self._fingerprint(device):
            self._clear_rejection(device.identifier)
            return None
        return entry[1]

    def _call(self, device: Device, operation: str, *args: Any) -> Any:
        rejected = self.rejected_credential(device)
        if rejected is not None:
            raise CredentialLatched(
                f"not contacting {device.identifier}: the router already rejected this credential "
                f"({rejected}); correct the username or password, or re-test it"
            )
        try:
            with self._adapter(device) as adapter:
                return getattr(adapter, operation)(*args)
        except AuthenticationRejected as exc:
            self._record_rejection(device, exc)
            raise

    def _router_lock(self, device: Device) -> int:
        """Hold the one conversation this router may have at a time.

        A Cudy issues a single login token and invalidates it when the next login
        asks for one, so the dashboard's poll and a Clients click logging in at the
        same moment made one of them look like a wrong password, and the rejection
        latch then stopped all polling. An flock (not a thread lock) so the CLI and
        the server exclude each other too; keyed on the router, not the device id.
        """
        lock_dir = self.data_dir / "locks"
        lock_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        key = hashlib.sha256(f"{device.host}:{device.http_port}:{device.ssh_port}".encode()).hexdigest()[:16]
        handle = os.open(lock_dir / f"router-{key}.lock", os.O_RDWR | os.O_CREAT, 0o600)
        deadline = time.monotonic() + self.router_lock_timeout
        try:
            while True:
                try:
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise AdapterError(
                            f"{device.identifier} is busy with another operation; try again shortly"
                        ) from None
                    time.sleep(0.05)
        except BaseException:
            os.close(handle)
            raise
        return handle

    @contextlib.contextmanager
    def _adapter(self, device: Device):
        handle = self._router_lock(device)
        try:
            with self._built_adapter(device) as adapter:
                yield adapter
        finally:
            with contextlib.suppress(OSError):
                fcntl.flock(handle, fcntl.LOCK_UN)
            os.close(handle)

    @contextlib.contextmanager
    def _built_adapter(self, device: Device):
        adapter = self.adapter_for(device)
        try:
            yield adapter
        finally:
            # The SSH adapter keeps its session, a dropbear process on the router,
            # open until closed, and a new adapter is built for every call.
            close = getattr(adapter, "close", None)
            if callable(close):
                # A failed close must not turn a completed reboot into an error.
                with contextlib.suppress(Exception):
                    close()

    def adapter_for(self, device: Device):
        password = self.credentials(device)
        # Transport first: an OpenWrt-flashed TP-Link or Tenda is still an SSH device,
        # as diagnose() and the README ("Any vendor, selected by transport: ssh") say.
        if device.transport == "ssh":
            # Beside the vault, so a key trusted on first use is remembered across
            # restarts instead of any key being accepted on every connection.
            return OpenWrtAdapter(device, password, known_hosts=self.data_dir / "ssh_known_hosts")
        if device.vendor == "tenda":
            return TendaAdapter(device, password)
        if device.vendor == "tplink":
            return TpLinkAdapter(device, password)
        return CudyAdapter(device, password)

    def get_status(self, identifier: str) -> dict[str, Any]:
        device = self.get_device(identifier)
        checked_at = datetime.now(UTC).isoformat()
        rejected = self.rejected_credential(device)
        status: dict[str, Any]
        if rejected is not None:
            status = {"online": None, "reason": "credentials_rejected", "error": rejected, "checked_at": checked_at}
            device.status = status
            return status
        try:
            with self._adapter(device) as adapter:
                status = adapter.status()
            status.setdefault("online", False)
            status["checked_at"] = checked_at
        except AuthenticationRejected as exc:
            self._record_rejection(device, exc)
            status = {
                "online": None,
                "reason": "credentials_rejected",
                "error": str(exc)[:200],
                "checked_at": checked_at,
            }
        except (AdapterError, SecretStoreError, ValidationError, OSError, RuntimeError) as exc:
            logger.debug("status check failed for %s: %s", device.identifier, exc)
            status = {"online": False, "error": str(exc)[:200], "checked_at": checked_at}
        except Exception as exc:
            # A status read reports a failure rather than raising; this one escaped
            # the adapter's own wrapping (http.client.BadStatusLine, a paramiko error).
            logger.exception("status check for %s raised an unexpected error", device.identifier)
            status = {"online": False, "error": str(exc)[:200], "checked_at": checked_at}
        device.status = status
        device.last_seen = checked_at
        return status

    def get_all_statuses(self) -> dict[str, dict[str, Any]]:
        devices = self.get_all_devices()
        # Disabling a device is how an operator stops the manager contacting it, for
        # example a router that locks its UI after repeated logins.
        polled = [device for device in devices if device.enabled]
        disabled: dict[str, dict[str, Any]] = {
            device.identifier: {"online": None, "reason": "disabled"} for device in devices if not device.enabled
        }
        if not polled:
            return disabled
        with self._status_lock:
            flight = self._status_flight
            if flight is None or flight.finished:
                flight = _StatusSweep(polled, self.get_status)
                self._status_flight = flight
        return {**flight.join(), **disabled}

    def reboot_device(self, identifier: str, *, actor: str = "system") -> bool:
        actor = normalise_actor(actor)
        with self._audited(actor, "reboot", identifier, "Reboot", self._peek(identifier, by_host=True)) as entry:
            done = self._call(entry.about(self.get_device(identifier)), "reboot")
            entry.confirmed(done, "Reboot started")
        return done

    def get_connected_clients(self, identifier: str) -> list[dict[str, Any]]:
        return self._call(self.get_device(identifier), "clients")

    def set_wifi_ssid(self, identifier: str, ssid: str, radio: str | None = None, *, actor: str = "system") -> bool:
        actor = normalise_actor(actor)
        attempt = "Wi-Fi name change"
        with self._audited(actor, "wifi", identifier, attempt, self._peek(identifier, by_host=True)) as entry:
            ssid = validate_wifi_ssid(ssid)
            device = entry.about(self.get_device(identifier))
            bands = _wifi_bands(device, radio)
            # Read before the change: a status poll finishing meanwhile may already
            # report the new name.
            old = _known_ssids(device)
            entry.attempt = f'Wi-Fi name change to "{ssid}" ({", ".join(bands)})'
            entry.details = {"bands": bands, "ssid": ssid, "old": {band: old[band] for band in bands if band in old}}
            changed = self._call(device, "set_ssid", ssid, radio)
            entry.confirmed(changed, _renamed(bands, old, ssid))
        return changed

    def set_wifi_password(
        self, identifier: str, password: str, radio: str | None = None, *, actor: str = "system"
    ) -> bool:
        actor = normalise_actor(actor)
        attempt = "Wi-Fi password change"
        with self._audited(actor, "wifi", identifier, attempt, self._peek(identifier, by_host=True)) as entry:
            entry.keep_out(password)
            validate_wifi_passphrase(password)
            device = entry.about(self.get_device(identifier))
            bands = _wifi_bands(device, radio)
            # The bands only: nothing about the passphrase, not even its length.
            entry.attempt = f"Wi-Fi password change ({', '.join(bands)})"
            entry.details = {"bands": bands}
            changed = self._call(device, "set_wifi_password", password, radio)
            entry.confirmed(changed, f"Wi-Fi password changed ({', '.join(bands)})")
        return changed

    def get_mesh_status(self, identifier: str) -> dict[str, Any]:
        return self._call(self.get_device(identifier), "mesh_status")

    # -- firmware on the router's own web UI ------------------------------------------
    # MaintenanceRunner calls _call for these operations directly and logs its own
    # entries under the plan's name, so these wrappers serve the dashboard and CLI.

    def firmware_info(self, identifier: str) -> dict[str, Any]:
        """The running version, hardware and automatic-update setting; changes nothing."""
        return self._call(self.get_device(identifier), "firmware_info")

    def set_auto_update(
        self, identifier: str, enabled: bool, window_start_hour: int | None = None, *, actor: str = "system"
    ) -> bool:
        """Switch the router's own automatic firmware update; the hour starts its 2-hour window."""
        actor = normalise_actor(actor)
        attempt = "Turning automatic firmware update " + ("on" if enabled is True else "off")
        with self._audited(actor, "firmware", identifier, attempt, self._peek(identifier, by_host=True)) as entry:
            # Checked here as well as in the adapter, so a bad request is recorded as
            # SkyRouter's refusal rather than as the router failing.
            _check_auto_update(enabled, window_start_hour)
            device = entry.about(self.get_device(identifier))
            entry.details = {"enabled": enabled, "window_start_hour": window_start_hour}
            done = self._call(device, "set_auto_update", enabled, window_start_hour)
            entry.confirmed(done, _auto_update_text(enabled, window_start_hour))
        return done

    def check_firmware_update(
        self, identifier: str, timeout: float = FIRMWARE_CHECK_TIMEOUT, *, actor: str = "system"
    ) -> dict[str, Any]:
        """Ask the router whether newer firmware exists. Nothing is installed."""
        actor = normalise_actor(actor)
        if isinstance(timeout, bool) or not isinstance(timeout, int | float) or not 0 < timeout <= 300:
            raise ValidationError("the update check timeout must be more than 0 and at most 300 seconds")
        with self._audited(
            actor, "firmware", identifier, "Firmware check", self._peek(identifier, by_host=True)
        ) as entry:
            device = entry.about(self.get_device(identifier))
            found = self._call(device, "check_firmware_update", timeout)
            # A check changes nothing on the router: information, not a change.
            entry.result = "info"
            entry.what, entry.details = _check_summary(found)
        return found

    def discover_network(self, subnet: str = "192.168.1.0/24") -> list[DiscoveredDevice]:
        return CudyDiscovery(subnet).discover()

    def dashboard(self, include_status: bool = True) -> dict[str, Any]:
        devices = self.get_all_devices()
        statuses = self.get_all_statuses() if include_status else {}
        public = []
        for device in devices:
            item = device.to_public()
            if include_status:
                # Absent when the device was added after the sweep we joined began: it
                # has not been contacted, so it is unknown rather than offline.
                item["status"] = statuses.get(device.identifier, {"online": None, "reason": "not_checked"})
            public.append(item)
        online = sum(1 for item in public if item.get("status", {}).get("online"))
        unchecked = sum(1 for item in public if item.get("status", {}).get("reason") in {"disabled", "not_checked"})
        return {
            "devices": public,
            "summary": {
                "total_devices": len(public),
                "online": online,
                "offline": len(public) - online - unchecked,
            },
        }

    def get_dashboard_data(self) -> dict[str, Any]:
        return self.dashboard()


CudyManager = DeviceManager
CudyDevice = Device
