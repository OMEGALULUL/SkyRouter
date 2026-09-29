import contextlib
import fcntl
import json
import logging
import os
import tempfile
import threading
from collections.abc import Callable, Iterator
from datetime import UTC, date, datetime, time, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .adapters import AdapterError
from .models import Device, ValidationError
from .secrets import SecretStoreError

if TYPE_CHECKING:
    from .maintenance import MaintenanceRunner

logger = logging.getLogger(__name__)

# The actor recorded in the activity log for a reboot a device's own policy sent.
SCHEDULER_ACTOR = "scheduler"


class SchedulerError(RuntimeError):
    pass


class RebootScheduler:
    def __init__(
        self,
        manager,
        state_path: str | Path,
        clock: Callable[[], datetime] | None = None,
        maintenance: "MaintenanceRunner | None" = None,
    ):
        self.manager = manager
        self.state_path = Path(state_path).expanduser()
        self.clock = clock or (lambda: datetime.now(UTC))
        self._lock = threading.RLock()
        self._lock_path = self.state_path.with_name(self.state_path.name + ".lock")
        self.state_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.state = self._load()
        self.maintenance = maintenance
        self._maintenance_lock = threading.Lock()
        self._maintenance_thread: threading.Thread | None = None
        self._maintenance_results: list[dict[str, Any]] = []
        if maintenance is not None:
            # Either kind of restart starts the other's cooldown: a plan's reboot an
            # hour after the device's own scheduled one only interrupts its users again.
            maintenance.reboot_history = self.last_reboot

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

    @contextlib.contextmanager
    def _exclusive(self) -> Iterator[None]:
        handle = os.open(self._lock_path, os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            fcntl.flock(handle, fcntl.LOCK_EX)
            yield
        finally:
            os.close(handle)

    def _save(self, state: dict[str, Any]) -> None:
        payload = json.dumps(state, indent=2, sort_keys=True).encode()
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

    def _due(self, device: Device, now: datetime) -> date | None:
        """The local date of the scheduled time whose window contains ``now``, if not yet used."""
        policy = device.reboot
        if not policy.enabled:
            return None
        local = self._local_now(now, policy.timezone)
        hour, minute = (int(part) for part in policy.at.split(":"))
        # Yesterday's too, because a window may run past midnight.
        for day in (local.date(), local.date() - timedelta(days=1)):
            # Subtracting across two tzinfos is in real time, so a DST change does not
            # stretch or shrink the window, and fold=0 puts a time skipped by the
            # spring-forward jump just after it rather than dropping that day.
            scheduled = datetime.combine(day, time(hour, minute), tzinfo=local.tzinfo)
            elapsed = (now - scheduled).total_seconds() / 60
            if 0 <= elapsed < policy.window_minutes:
                with self._lock:
                    done = self.state.get(device.identifier, {}).get("last_schedule_date")
                return None if done == day.isoformat() else day
        return None

    def _last_reboot(self, identifier: str) -> datetime | None:
        with self._lock:
            return self._parse_timestamp(self.state.get(identifier, {}).get("last_reboot"))

    def last_reboot(self, identifier: str) -> datetime | None:
        """When a scheduler on this state file last sent (or tried to send) the device a reboot.

        Read from the file every time, not from this scheduler's copy: the CLI builds
        one only for this, then waits at its prompt while the server's own scheduler
        may reboot the device. The file is replaced in one step, so it needs no lock
        to be read whole. An unreadable file raises, and the plan asking holds back.
        """
        entry = self._load().get(identifier)
        return self._parse_timestamp(entry.get("last_reboot")) if isinstance(entry, dict) else None

    def _record_attempt(self, identifier: str, occurrence: date, current: datetime) -> None:
        with self._lock:
            entry = {
                **self.state.get(identifier, {}),
                "last_schedule_date": occurrence.isoformat(),
                "last_reboot": current.isoformat(),
            }
            updated = {**self.state, identifier: entry}
            self._save(updated)
            self.state = updated

    def run_once(self, now: datetime | None = None) -> list[dict[str, Any]]:
        current = self._utc_now(now or self.clock())
        results = []
        # Two dashboards on one data dir each run a scheduler over the same devices.
        # Holding the lock for the whole tick and re-reading the state under it lets
        # the second one see a reboot the first has just sent, rather than sending
        # another and then overwriting the first one's record with its own.
        with self._exclusive():
            loaded = self._load()
            with self._lock:
                self.state = loaded
            for device in self.manager.get_all_devices():
                result = self._run_device(device, current)
                if result is not None:
                    results.append(result)
        return results

    def _run_device(self, device: Device, current: datetime) -> dict[str, Any] | None:
        result: dict[str, Any] = {"device": device.identifier, "action": "reboot", "status": "skipped"}
        try:
            occurrence = self._due(device, current) if device.enabled else None
        except (ValidationError, ZoneInfoNotFoundError, KeyError, ValueError) as exc:
            result["status"] = "failed"
            result["reason"] = f"reboot policy is invalid: {exc}"[:160]
            return result
        if occurrence is None:
            return None
        try:
            status = self.manager.get_status(device.identifier)
            uptime = status.get("uptime_seconds")
            if status.get("reason") == "credentials_rejected":
                result["reason"] = "router rejected the stored credentials"
                return result
            if not status.get("online"):
                result["reason"] = "device is offline"
                return result
            if uptime is not None and int(uptime) < device.reboot.min_uptime_seconds:
                result["reason"] = "minimum uptime not reached"
                return result
            if uptime is None:
                result["reason"] = "uptime unavailable; automatic reboot requires a reliable status reading"
                return result
            last = self._last_reboot(device.identifier)
            if last is not None:
                age = (current - last).total_seconds()
                if age < device.reboot.cooldown_seconds:
                    result["reason"] = "cooldown active"
                    return result
            restarted = self.maintenance.last_restart(device.identifier) if self.maintenance is not None else None
            if restarted is not None and (current - restarted).total_seconds() < device.reboot.cooldown_seconds:
                result["reason"] = "cooldown active: a maintenance plan restarted it recently"
                return result
            # Recorded before the request goes out: a router that drops the connection
            # as it goes down, or a reply the adapter cannot read, may still have
            # rebooted, and an unrecorded attempt is sent again every tick once the
            # uptime guard passes. If the record cannot be written, nothing is sent,
            # because the guard would not survive a restart.
            try:
                self._record_attempt(device.identifier, occurrence, current)
            except OSError as exc:
                result["status"] = "failed"
                result["reason"] = f"reboot not sent; could not record the attempt: {exc}"[:160]
                return result
            if not self.manager.reboot_device(device.identifier, actor=SCHEDULER_ACTOR):
                result["status"] = "failed"
                result["reason"] = "adapter did not confirm reboot"
                return result
            result["status"] = "initiated"
        except (AdapterError, SecretStoreError, ValidationError, OSError, RuntimeError) as exc:
            result["status"] = "failed"
            result["reason"] = str(exc)[:160]
        except Exception as exc:
            # An error the adapter did not wrap (http.client, paramiko) must not end the
            # tick and cost every later device its reboot.
            logger.exception("scheduled reboot of %s raised an unexpected error", device.identifier)
            result["status"] = "failed"
            result["reason"] = (str(exc) or type(exc).__name__)[:160]
        return result

    def get_state(self) -> dict[str, Any]:
        with self._lock:
            return json.loads(json.dumps(self.state))

    # -- one tick for the web lifespan -------------------------------------------------

    def tick(self, now: datetime | None = None, *, wait: bool = False) -> list[dict[str, Any]]:
        """Run the per-device reboot policies, then start a pass over the maintenance plans.

        The plans run in a background thread: one pass can spend minutes in firmware
        checks, and a device's reboot window (15 minutes by default) must not close
        while it waits. Their results come back from a later tick, once the pass has
        finished; ``wait`` blocks for this tick's own pass instead. Every result
        carries ``source`` ("reboot" or "maintenance"); one side failing never stops
        the other.
        """
        current = self._utc_now(now or self.clock())
        try:
            results = [{**result, "source": "reboot"} for result in self.run_once(current)]
        except Exception as exc:
            logger.exception("scheduled reboot check failed")
            results = [{"source": "reboot", "action": "reboot", "status": "failed", "reason": str(exc)[:160]}]
        if self.maintenance is not None:
            # Not this tick's moment, which the reboots above may have spent minutes
            # past: without one, the pass reads its own clock as it starts.
            results.extend(self._tick_maintenance(None if now is None else current, wait))
        return results

    def _tick_maintenance(self, current: datetime | None, wait: bool) -> list[dict[str, Any]]:
        with self._maintenance_lock:
            thread = self._maintenance_thread
            if thread is None or not thread.is_alive():
                # A pass still running keeps going; this tick's moment is simply skipped,
                # which costs nothing because the plans' windows last minutes.
                thread = threading.Thread(
                    target=self._run_maintenance, args=(self.maintenance, current), name="maintenance", daemon=True
                )
                self._maintenance_thread = thread
                thread.start()
        if wait:
            thread.join()
        with self._maintenance_lock:
            finished, self._maintenance_results = self._maintenance_results, []
        return finished

    def _run_maintenance(self, runner: "MaintenanceRunner", current: datetime | None) -> None:
        try:
            results = runner.run_once(current)
        except Exception as exc:
            logger.exception("maintenance plan pass failed")
            results = [{"source": "maintenance", "status": "failed", "reason": str(exc)[:160]}]
        with self._maintenance_lock:
            self._maintenance_results.extend(results)

    def join_maintenance(self, timeout: float | None = None) -> bool:
        """Wait for a maintenance pass in progress; False if it is still running after ``timeout``."""
        with self._maintenance_lock:
            thread = self._maintenance_thread
        if thread is not None:
            thread.join(timeout)
            return not thread.is_alive()
        return True
