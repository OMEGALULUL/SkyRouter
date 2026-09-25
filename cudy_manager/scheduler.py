import contextlib
import json
import os
import tempfile
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .adapters import AdapterError
from .models import Device, ValidationError
from .secrets import SecretStoreError


class SchedulerError(RuntimeError):
    pass


class RebootScheduler:
    def __init__(
        self,
        manager,
        state_path: str | Path,
        clock: Callable[[], datetime] | None = None,
    ):
        self.manager = manager
        self.state_path = Path(state_path).expanduser()
        self.clock = clock or (lambda: datetime.now(UTC))
        self._lock = threading.RLock()
        self.state_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.state = self._load()

    def _load(self) -> dict[str, Any]:
        if not self.state_path.exists():
            return {}
        try:
            data = json.loads(self.state_path.read_text())
        except (OSError, ValueError) as exc:
            raise SchedulerError("scheduler state is unreadable") from exc
        if not isinstance(data, dict):
            raise SchedulerError("scheduler state has an invalid format")
        return data

    def _save(self) -> None:
        payload = json.dumps(self.state, indent=2, sort_keys=True).encode()
        fd, temporary = tempfile.mkstemp(prefix="scheduler.", dir=self.state_path.parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.state_path)
            with contextlib.suppress(OSError):
                os.chmod(self.state_path, 0o600)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary)

    @staticmethod
    def _utc_now(now: datetime) -> datetime:
        if now.tzinfo is None:
            return now.replace(tzinfo=UTC)
        return now.astimezone(UTC)

    @staticmethod
    def _local_now(now: datetime, zone: str) -> datetime:
        try:
            return now.astimezone(ZoneInfo(zone))
        except ZoneInfoNotFoundError as exc:
            raise ValidationError(f"unknown reboot timezone {zone!r}") from exc

    @staticmethod
    def _parse_timestamp(value: Any) -> datetime | None:
        if not value:
            return None
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)

    def _due(self, device: Device, now: datetime) -> bool:
        policy = device.reboot
        if not policy.enabled:
            return False
        local = self._local_now(now, policy.timezone)
        hour, minute = (int(part) for part in policy.at.split(":"))
        scheduled = local.replace(hour=hour, minute=minute, second=0, microsecond=0)
        elapsed = (local - scheduled).total_seconds() / 60
        if elapsed < 0 or elapsed >= policy.window_minutes:
            return False
        with self._lock:
            return self.state.get(device.identifier, {}).get("last_schedule_date") != local.date().isoformat()

    def _last_reboot(self, identifier: str) -> datetime | None:
        with self._lock:
            return self._parse_timestamp(self.state.get(identifier, {}).get("last_reboot"))

    def run_once(self, now: datetime | None = None) -> list[dict[str, Any]]:
        current = self._utc_now(now or self.clock())
        results = []
        for device in self.manager.get_all_devices():
            if not device.enabled or not self._due(device, current):
                continue
            result: dict[str, Any] = {"device": device.identifier, "action": "reboot", "status": "skipped"}
            try:
                status = self.manager.get_status(device.identifier)
                uptime = status.get("uptime_seconds")
                if not status.get("online"):
                    result["reason"] = "device is offline"
                    results.append(result)
                    continue
                if uptime is not None and int(uptime) < device.reboot.min_uptime_seconds:
                    result["reason"] = "minimum uptime not reached"
                    results.append(result)
                    continue
                if uptime is None:
                    result["reason"] = "uptime unavailable; automatic reboot requires a reliable status reading"
                    results.append(result)
                    continue
                last = self._last_reboot(device.identifier)
                if last is not None:
                    age = (current - last).total_seconds()
                    if age < device.reboot.cooldown_seconds:
                        result["reason"] = "cooldown active"
                        results.append(result)
                        continue
                success = self.manager.reboot_device(device.identifier)
                if not success:
                    result["status"] = "failed"
                    result["reason"] = "adapter did not confirm reboot"
                    results.append(result)
                    continue
                with self._lock:
                    entry = self.state.setdefault(device.identifier, {})
                    entry["last_schedule_date"] = self._local_now(current, device.reboot.timezone).date().isoformat()
                    entry["last_reboot"] = current.isoformat()
                    self._save()
                result["status"] = "initiated"
            except (AdapterError, SecretStoreError, ValidationError, OSError, RuntimeError) as exc:
                result["status"] = "failed"
                result["reason"] = str(exc)[:160]
            results.append(result)
        return results

    def get_state(self) -> dict[str, Any]:
        with self._lock:
            return json.loads(json.dumps(self.state))
