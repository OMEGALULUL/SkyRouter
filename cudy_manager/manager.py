import contextlib
import fcntl
import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from .adapters import AdapterError, AuthenticationRejected, CudyAdapter, TendaAdapter
from .diagnose import diagnose_device
from .discovery import CudyDiscovery, DiscoveredDevice
from .models import Device, ValidationError
from .openwrt import OpenWrtAdapter
from .secrets import SecretStore, SecretStoreError

logger = logging.getLogger(__name__)


class ManagerError(RuntimeError):
    pass


def _rebuild(identifier: str, existing: Device, **values: Any) -> Device:
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
        finally:
            self._result = results
            self._done.set()

    def join(self) -> dict[str, dict[str, Any]]:
        self._done.wait()
        return dict(self._result)


class DeviceManager:
    def __init__(
        self,
        config_path: str | Path | None = None,
        data_dir: str | Path | None = None,
        secret_store: SecretStore | None = None,
    ):
        package_dir = Path(__file__).resolve().parent
        self.config_path = Path(
            config_path or os.environ.get("ROUTER_MANAGER_CONFIG") or package_dir / "cudy_devices.yaml"
        ).expanduser()
        default_data = os.environ.get(
            "ROUTER_MANAGER_DATA_DIR",
            str(Path.home() / ".local" / "state" / "skybre-router-manager"),
        )
        self.data_dir = Path(data_dir or default_data).expanduser()
        self.secrets = secret_store or SecretStore(self.data_dir)
        self.devices: dict[str, Device] = {}
        self._lock = threading.RLock()
        self._transaction_state = threading.local()
        self._status_lock = threading.Lock()
        self._status_flight: _StatusSweep | None = None
        self._load_config()

    def _load_config(self) -> None:
        if not self.config_path.exists():
            self.save_config()
            return
        try:
            data = yaml.safe_load(self.config_path.read_text()) or {}
        except (OSError, ValueError) as exc:
            raise ManagerError(f"device config is unreadable: {self.config_path}") from exc
        entries = data.get("devices", {}) if isinstance(data, dict) else {}
        if isinstance(entries, list):
            converted = {}
            for item in entries:
                if isinstance(item, dict) and item.get("id"):
                    converted[str(item["id"])] = item
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
        self.config_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = self.config_path.with_suffix(self.config_path.suffix + ".tmp")
        temporary.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
        try:
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.config_path)
        finally:
            if temporary.exists():
                temporary.unlink()

    def _store_secret(self, identifier: str, kind: str, value: str | None) -> str:
        if value is None:
            return ""
        if not isinstance(value, str) or not value:
            raise ValidationError(f"{kind} must be a non-empty string")
        return self.secrets.put(value, f"device-{identifier}-{kind}")

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
                yield
                self.save_config()
            finally:
                self._lock.release()
        finally:
            self._transaction_state.depth = 0
            with contextlib.suppress(OSError):
                fcntl.flock(handle, fcntl.LOCK_UN)
            os.close(handle)

    def add_device(self, identifier: str, host: str, vendor: str, password: str | None = None, **values: Any) -> Device:
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
        return device

    def update_device(self, identifier: str, **values: Any) -> Device:
        password = values.pop("password", None)
        community = values.pop("snmp_community", None)
        with self._lock:
            current = self.devices.get(identifier)
            if current is None:
                raise ManagerError(f"device {identifier!r} does not exist")
            # Validate against the current snapshot first so a bad value is
            # rejected before any secret is written.
            Device.from_dict(identifier, {**current.to_config(), **values})
        with self._transaction():
            if identifier not in self.devices:
                raise ManagerError(f"device {identifier!r} does not exist")
            if password is not None:
                self._store_secret(identifier, "password", password)
            if community is not None:
                self._store_secret(identifier, "snmp-community", community)
            # Rebuild from the state reloaded inside the transaction, not the
            # pre-transaction snapshot, so a concurrent edit is not overwritten.
            self.devices[identifier] = _rebuild(identifier, self.devices[identifier], **values)
            device = self.devices[identifier]
        return device

    def set_password(self, identifier: str, password: str, verify: bool = True) -> dict[str, Any]:
        self.get_device(identifier)
        if not isinstance(password, str) or not password:
            raise ValidationError("password must be a non-empty string")
        with self._transaction():
            if identifier not in self.devices:
                raise ManagerError(f"device {identifier!r} does not exist")
            reference = self._store_secret(identifier, "password", password)
            if self.devices[identifier].password_ref != reference:
                self.devices[identifier] = _rebuild(
                    identifier, self.devices[identifier], password_ref=reference
                )
        result: dict[str, Any] = {"device": identifier, "password_updated": True}
        if verify:
            result["verified"] = self.verify_credentials(identifier)
            if not result["verified"]["ok"]:
                if result["verified"].get("reason") == "rejected":
                    logger.warning("password for %s was rejected by the router", identifier)
                else:
                    logger.warning(
                        "could not verify the password for %s: %s", identifier, result["verified"].get("error")
                    )
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
            self.adapter_for(device).status()
        except AuthenticationRejected as exc:
            # The router answered and refused the credentials.
            return {"ok": False, "reason": "rejected", "error": str(exc)[:200], "checked_at": checked_at}
        except (AdapterError, SecretStoreError, ValidationError, OSError, RuntimeError) as exc:
            # The router could not be checked at all. Saying "rejected" here would
            # send the operator after the password when the real problem is that the
            # device is asleep, unreachable, or on another subnet.
            return {"ok": False, "reason": "unreachable", "error": str(exc)[:200], "checked_at": checked_at}
        return {"ok": True, "reason": "ok", "checked_at": checked_at}

    def remove_device(self, identifier: str) -> None:
        with self._transaction():
            device = self.devices.pop(identifier, None)
            if device is None:
                raise ManagerError(f"device {identifier!r} does not exist")
            remaining_refs = {item.password_ref for item in self.devices.values()}
            remaining_refs.update(item.snmp_community_ref for item in self.devices.values())
        if device.password_ref not in remaining_refs:
            self.secrets.delete(device.password_ref)
        if device.snmp_community_ref not in remaining_refs:
            self.secrets.delete(device.snmp_community_ref)

    def get_device(self, identifier: str) -> Device:
        with self._lock:
            device = self.devices.get(identifier)
        if device is not None:
            return device
        with self._lock:
            for candidate in self.devices.values():
                if candidate.host == identifier:
                    return candidate
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

    def adapter_for(self, device: Device):
        password = self.credentials(device)
        if device.vendor == "tenda":
            return TendaAdapter(device, password)
        if device.transport == "ssh":
            return OpenWrtAdapter(device, password)
        return CudyAdapter(device, password)

    def get_status(self, identifier: str) -> dict[str, Any]:
        device = self.get_device(identifier)
        checked_at = datetime.now(UTC).isoformat()
        try:
            status = self.adapter_for(device).status()
            status.setdefault("online", False)
            status["checked_at"] = checked_at
        except (AdapterError, SecretStoreError, ValidationError, OSError, RuntimeError) as exc:
            logger.debug("status check failed for %s: %s", device.identifier, exc)
            status = {"online": False, "error": str(exc)[:200], "checked_at": checked_at}
        device.status = status
        device.last_seen = checked_at
        return status

    def get_all_statuses(self) -> dict[str, dict[str, Any]]:
        devices = self.get_all_devices()
        if not devices:
            return {}
        with self._status_lock:
            flight = self._status_flight
            if flight is None or flight.finished:
                flight = _StatusSweep(devices, self.get_status)
                self._status_flight = flight
        return flight.join()

    def reboot_device(self, identifier: str) -> bool:
        device = self.get_device(identifier)
        adapter = self.adapter_for(device)
        return adapter.reboot()

    def get_connected_clients(self, identifier: str) -> list[dict[str, Any]]:
        adapter = self.adapter_for(self.get_device(identifier))
        return adapter.clients()

    def set_wifi_ssid(self, identifier: str, ssid: str, radio: str | None = None) -> bool:
        if not isinstance(ssid, str) or not ssid.strip() or len(ssid) > 32:
            raise ValidationError("SSID must be between 1 and 32 characters")
        return self.adapter_for(self.get_device(identifier)).set_ssid(ssid.strip(), radio)

    def get_mesh_status(self, identifier: str) -> dict[str, Any]:
        return self.adapter_for(self.get_device(identifier)).mesh_status()

    def discover_network(self, subnet: str = "192.168.1.0/24") -> list[DiscoveredDevice]:
        return CudyDiscovery(subnet).discover()

    def dashboard(self, include_status: bool = True) -> dict[str, Any]:
        devices = self.get_all_devices()
        statuses = self.get_all_statuses() if include_status else {}
        public = []
        for device in devices:
            item = device.to_public()
            if include_status:
                item["status"] = statuses.get(device.identifier, {"online": False})
            public.append(item)
        online = sum(1 for item in public if item.get("status", {}).get("online"))
        return {
            "devices": public,
            "summary": {
                "total_devices": len(public),
                "online": online,
                "offline": len(public) - online,
            },
        }

    def get_dashboard_data(self) -> dict[str, Any]:
        return self.dashboard()


CudyManager = DeviceManager
CudyDevice = Device
