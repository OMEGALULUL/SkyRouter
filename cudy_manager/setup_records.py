"""Setup records: what a technician programmed into a router before it left.

The Setup page saves one record per router: the Vexar customer, the model, its
address, the Wi-Fi it was given and the checklist ticked before it went out. The
Wi-Fi password is kept only in the SecretStore vault, by reference. The record
file never holds a secret, and neither does a listing or an activity entry;
reading the Wi-Fi password back is an explicit reveal, recorded in the activity
log before it is handed over.

The record keeps no router admin password. A router reached directly signs in
with the copy DeviceManager stores, which goes when the router is removed or its
password changed; a second copy here would outlive both. One that checks in by
itself is never signed in to, so an admin password given for it is not kept.

A router programmed to be reached directly is also added to DeviceManager, so it
is in the router list at once. One that checks in by itself over TR-069 shows up
when it first does.

Everything here blocks: call it from async code through asyncio.to_thread.
"""

import contextlib
import ipaddress
import json
import logging
import re
import secrets
import threading
import unicodedata
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .activity import ActivityError, ActivityLog, normalise_actor
from .maintenance import _flocked, _write_json
from .manager import validate_wifi_passphrase, validate_wifi_ssid
from .models import Device, ValidationError
from .secrets import SecretStore, SecretStoreError

if TYPE_CHECKING:
    from .manager import DeviceManager

logger = logging.getLogger(__name__)

RECORDS_FILE = "setup_records.json"
FORMAT_VERSION = 1
MAX_RECORDS = 5000
# The Setup page's model list. The leading word is the make, which picks the adapter
# for a router reached directly; "Other" can only be set up to check in by itself.
MODELS = (
    "Cudy WR3000",
    "Cudy WR1300",
    "Cudy M3000 mesh",
    "Cudy AP1300 access point",
    "TP-Link Archer C64",
    "TP-Link TL-WR840N",
    "Tenda",
    "Other",
)
_VENDORS = (("Cudy", "cudy"), ("TP-Link", "tplink"), ("Tenda", "tenda"))
METHODS = ("managed", "direct")
CHECKLIST = ("remote_management", "acs_configured", "default_password_changed", "firmware_updated")
# A router reached directly never talks to the ACS, so that item does not apply to it.
_DIRECT_CHECKLIST = ("remote_management", "default_password_changed", "firmware_updated")
REMOTE_MANAGEMENT_REQUIRED = (
    'Tick "Remote web management is on" first. Without it Skybre cannot reach this router after installation.'
)
DIRECT_UNSUPPORTED = (
    'Skybre can only sign in to Cudy, TP-Link and Tenda routers. Choose "Checks in by itself (TR-069)" for this model.'
)
FIELDS = (
    "customer",
    "name",
    "model",
    "ip",
    "method",
    "admin_username",
    "admin_password",
    "ssid_24",
    "ssid_5",
    "wifi_password",
    "notes",
    "checklist",
)
CUSTOMER_MAX = 80
# Long enough for the default, "<customer> router".
NAME_MAX = 100
NOTES_MAX = 500
USERNAME_MAX = 64
ADMIN_PASSWORD_MAX = 128
HOST_MAX = 253
# Only these reach a listing. A vault reference is not the secret, but nothing
# outside this module has any use for one.
_PUBLIC = (
    "id",
    "customer",
    "name",
    "model",
    "vendor",
    "ip",
    "method",
    "admin_username",
    "ssid_24",
    "ssid_5",
    "notes",
    "checklist",
    "device_id",
    "created_at",
    "created_by",
)
_RECORD_ID = re.compile(r"[0-9a-f]{12}")
_DOTTED = re.compile(r"[0-9.]+")
# Bidirectional overrides can make a customer read as another one in a listing.
_BIDI = frozenset(chr(code) for code in (*range(0x202A, 0x202F), *range(0x2066, 0x206A)))
_ADDRESS_MISSING = "Enter the router IP address, e.g. 10.20.0.15."
_ADDRESS_INVALID = (
    "Enter the router IP address or hostname on its own, without http://, a path or a port, e.g. 10.20.0.15."
)


class SetupRecordsError(RuntimeError):
    """The record file or the vault cannot be read or written, or a reveal cannot be audited."""


class RecordNotFound(ValidationError):
    """No setup record has this id."""


class SavedPasswordMissing(RecordNotFound):
    """The record's Wi-Fi password is no longer in the vault."""


# --- validation -----------------------------------------------------------------------


def vendor_of(model: str) -> str | None:
    """The DeviceManager vendor for a model on the list, or None for one no adapter speaks to."""
    return next((vendor for prefix, vendor in _VENDORS if model.startswith(prefix)), None)


def _refuse_controls(text: str, label: str, allowed: str = "") -> None:
    for char in text:
        if char in allowed:
            continue
        category = unicodedata.category(char)
        if category == "Cs":
            # A lone surrogate, which JSON's \ud800 escapes can carry, has no UTF-8
            # form: the activity log could not store the entry naming it.
            raise ValidationError(f"{label} must be valid Unicode text")
        if char in _BIDI or category in {"Cc", "Zl", "Zp"}:
            raise ValidationError(f"{label} must not contain control characters")


def _line(value: Any, label: str, maximum: int, missing: str | None = None) -> str:
    """One line of text with its runs of whitespace collapsed, or "" when it is optional and left out."""
    if value is None or (isinstance(value, str) and not value.strip()):
        if missing is not None:
            raise ValidationError(missing)
        return ""
    if not isinstance(value, str):
        raise ValidationError(f"{label} must be text")
    text = " ".join(value.split())
    _refuse_controls(text, label)
    if len(text) > maximum:
        raise ValidationError(f"{label} must be at most {maximum} characters")
    return text


def _notes(value: Any) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValidationError("notes must be text")
    # Line breaks are kept, since the field is a text area; anything else is a space.
    text = "\n".join(" ".join(line.split()) for line in value.replace("\r\n", "\n").split("\n")).strip()
    _refuse_controls(text, "notes", allowed="\n")
    if len(text) > NOTES_MAX:
        raise ValidationError(f"notes must be at most {NOTES_MAX} characters")
    return text


def validate_address(value: Any) -> str:
    """The router's IPv4 address or hostname, by the rule Device applies to a host."""
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(_ADDRESS_MISSING)
    host = value.strip()
    # Device lets through characters that are not whitespace, such as NUL.
    if len(host) > HOST_MAX or any(unicodedata.category(char) in {"Cc", "Cs"} for char in host):
        raise ValidationError(_ADDRESS_INVALID)
    try:
        # Its own rule, so an address accepted here is one DeviceManager accepts too.
        host = Device.from_dict("setup", {"vendor": "cudy", "host": host}).host
    except ValidationError:
        raise ValidationError(_ADDRESS_INVALID) from None
    if _DOTTED.fullmatch(host):
        # No hostname is only digits and dots, so this is a mistyped IPv4 address.
        try:
            ipaddress.IPv4Address(host)
        except ValueError:
            raise ValidationError(
                "That is not an IPv4 address: it needs four numbers from 0 to 255, e.g. 10.20.0.15."
            ) from None
    return host


def _ssid(value: Any, band: str, missing: str | None = None) -> str:
    if value is None or (isinstance(value, str) and not value.strip()):
        if missing is not None:
            raise ValidationError(missing)
        return ""
    try:
        return validate_wifi_ssid(value)
    except ValidationError as exc:
        raise ValidationError(f"{band} Wi-Fi name: {exc}") from None


def _checklist(value: Any) -> dict[str, bool]:
    if value is None:
        value = {}
    if not isinstance(value, Mapping):
        raise ValidationError("checklist must be an object")
    unknown = sorted(str(key)[:40] for key in value if key not in CHECKLIST)
    if unknown:
        raise ValidationError(f"checklist has unknown field(s): {', '.join(unknown[:8])}")
    ticked: dict[str, bool] = {}
    for item in CHECKLIST:
        done = value.get(item)
        if done is not None and not isinstance(done, bool):
            raise ValidationError(f"checklist.{item} must be true or false")
        ticked[item] = done is True
    if not ticked["remote_management"]:
        raise ValidationError(REMOTE_MANAGEMENT_REQUIRED)
    return ticked


@dataclass(frozen=True)
class SetupRequest:
    """A validated Setup form. The passwords are kept out of repr, which a traceback may print."""

    customer: str
    name: str
    model: str
    vendor: str | None
    ip: str
    method: str
    admin_username: str | None
    ssid_24: str
    ssid_5: str
    notes: str
    checklist: dict[str, bool]
    wifi_password: str = field(repr=False)
    admin_password: str | None = field(default=None, repr=False)


def validate_setup(body: Any) -> SetupRequest:
    """The Setup form as SkyRouter will store it, or ValidationError naming the first problem."""
    if not isinstance(body, Mapping):
        raise ValidationError("the setup record must be an object")
    unknown = sorted(str(key)[:40] for key in body if key not in FIELDS)
    if unknown:
        raise ValidationError(f"unexpected field(s): {', '.join(unknown[:8])}")
    customer = _line(body.get("customer"), "customer", CUSTOMER_MAX, missing="Enter the Vexar customer.")
    model = body.get("model")
    if not isinstance(model, str) or model.strip() not in MODELS:
        raise ValidationError(f"Choose the router model from the list: {', '.join(MODELS)}.")
    model = model.strip()
    vendor = vendor_of(model)
    ip = validate_address(body.get("ip"))
    method = body.get("method")
    if not isinstance(method, str) or method not in METHODS:
        raise ValidationError(
            'method must be "managed" (the router checks in by itself over TR-069) '
            'or "direct" (Skybre signs in to its web page)'
        )
    name = _line(body.get("name"), "name", NAME_MAX) or f"{customer} router"
    admin_username = _line(body.get("admin_username"), "admin_username", USERNAME_MAX) or None
    admin_password = body.get("admin_password")
    if admin_password is not None and not isinstance(admin_password, str):
        raise ValidationError("admin_password must be text")
    admin_password = admin_password or None
    if method == "direct":
        if vendor is None:
            raise ValidationError(DIRECT_UNSUPPORTED)
        if admin_password is None:
            raise ValidationError("Enter the router admin password so Skybre can sign in to it.")
    if admin_password is not None and len(admin_password) > ADMIN_PASSWORD_MAX:
        raise ValidationError(f"The router admin password must be at most {ADMIN_PASSWORD_MAX} characters.")
    ssid_24 = _ssid(body.get("ssid_24"), "2.4 GHz", missing="Enter the Wi-Fi name.")
    ssid_5 = _ssid(body.get("ssid_5"), "5 GHz") or ssid_24
    wifi_password = body.get("wifi_password")
    if wifi_password is None or wifi_password == "":
        raise ValidationError("Enter the Wi-Fi password.")
    validate_wifi_passphrase(wifi_password)
    notes = _notes(body.get("notes"))
    # Typed into a field everyone sees, the password would be in every listing
    # without anyone having to reveal it, and so without the reveal being logged.
    shown = (
        ("customer", customer),
        ("router name", name),
        ("admin username", admin_username or ""),
        ("Wi-Fi name", ssid_24),
        ("Wi-Fi name", ssid_5),
        ("notes", notes),
    )
    for label, text in shown:
        if wifi_password in text:
            raise ValidationError(
                f"The Wi-Fi password must not appear in the {label}: that is shown to everyone who opens the record."
            )
    return SetupRequest(
        customer=customer,
        name=name,
        model=model,
        vendor=vendor,
        ip=ip,
        method=method,
        admin_username=admin_username,
        ssid_24=ssid_24,
        ssid_5=ssid_5,
        notes=notes,
        checklist=_checklist(body.get("checklist")),
        wifi_password=wifi_password,
        admin_password=admin_password,
    )


def _wifi_ref(record_id: str) -> str:
    """The vault name of a record's Wi-Fi password: the only secret a record may name."""
    return f"setup-{record_id}-wifi"


def _check_id(record_id: Any) -> str:
    if not isinstance(record_id, str) or not _RECORD_ID.fullmatch(record_id):
        raise ValidationError("not a setup record id")
    return record_id


def _device_id(name: str, taken: set[str]) -> str:
    """A device id readable in the router list and the activity log, from the router's name."""
    plain = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode()
    slug = re.sub(r"[^a-z0-9]+", "-", plain.lower()).strip("-")[:56].strip("-") or "router"
    for candidate in (slug, *(f"{slug}-{number}" for number in range(2, 100))):
        if candidate not in taken:
            return candidate
    return f"{slug}-{secrets.token_hex(3)}"


def _router_of(record: Mapping[str, Any]) -> str:
    """As the activity log names the record's router: its device id, or the record until it has one."""
    device = record.get("device_id")
    return device if isinstance(device, str) and device else f"setup:{record.get('id')}"


def _programmed(record: Mapping[str, Any]) -> str:
    ssid_24, ssid_5 = record["ssid_24"], record["ssid_5"]
    wifi = f'"{ssid_24}"' if ssid_24 == ssid_5 else f'"{ssid_24}" (2.4 GHz), "{ssid_5}" (5 GHz)'
    return f"Programmed: linked to {record['customer']}, IP {record['ip']}, Wi-Fi {wifi}"


def _order(record: Mapping[str, Any]) -> tuple[int, str]:
    # A sequence number rather than the clock alone, which can repeat or step back.
    seq = record.get("seq")
    return (seq if isinstance(seq, int) and not isinstance(seq, bool) else 0, str(record.get("created_at") or ""))


# --- the store ------------------------------------------------------------------------


class SetupRecords:
    """The records, in data_dir/setup_records.json. Every change re-reads the file under an flock."""

    def __init__(
        self,
        data_dir: str | Path,
        vault: SecretStore,
        manager: "DeviceManager | None" = None,
        activity: ActivityLog | None = None,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.data_dir = Path(data_dir).expanduser()
        self.path = self.data_dir / RECORDS_FILE
        self.lock_path = self.data_dir / "setup_records.lock"
        self.vault = vault
        self.manager = manager
        self.activity = activity
        self._clock = clock or (lambda: datetime.now(UTC))
        # flock alone would do across processes; this keeps one process's threads in line too.
        self._thread_lock = threading.Lock()

    def _read(self) -> dict[str, dict[str, Any]]:
        try:
            raw = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return {}
        except OSError as exc:
            raise SetupRecordsError(f"setup records are unreadable: {self.path}") from exc
        try:
            data = json.loads(raw)
        except ValueError as exc:
            raise SetupRecordsError(f"setup records are unreadable: {self.path}") from exc
        records = data.get("records") if isinstance(data, dict) else None
        # Only a missing file means "no records": the next save over a damaged one
        # would lose every record for good, and strand their passwords in the vault.
        if not isinstance(records, dict) or not all(isinstance(entry, dict) for entry in records.values()):
            raise SetupRecordsError(f"{self.path} has no records mapping; refusing to treat it as empty")
        return records

    @contextlib.contextmanager
    def _changing(self) -> Iterator[dict[str, dict[str, Any]]]:
        with self._thread_lock, _flocked(self.lock_path):
            records = self._read()
            yield records
            try:
                _write_json(self.path, {"version": FORMAT_VERSION, "records": records}, "setup_records.")
            except OSError as exc:
                raise SetupRecordsError(f"setup records could not be saved: {exc}") from exc

    def _log(self, who: str, record: Mapping[str, Any], what: str, details: Mapping[str, Any]) -> None:
        if self.activity is None:
            return
        try:
            self.activity.record(
                who=who,
                router=_router_of(record),
                router_name=str(record.get("name") or ""),
                kind="setup",
                what=what,
                result="applied",
                details=details,
            )
        except (ActivityError, OSError) as exc:
            # The record is already saved; failing now would report it as not made.
            logger.warning("could not record setup activity for record %s: %s", record.get("id"), exc)
        except Exception:
            logger.exception("recording setup activity for record %s raised an unexpected error", record.get("id"))

    def _saved_references(self) -> set[str]:
        try:
            return set(self.vault.references())
        except SecretStoreError as exc:
            raise SetupRecordsError(f"the vault is unreadable: {exc}") from exc

    def _public(self, record: Mapping[str, Any], saved: set[str], present: set[str]) -> dict[str, Any]:
        view = {key: record.get(key) for key in _PUBLIC}
        wifi, admin, device = (record.get(key) for key in ("wifi_password_ref", "admin_password_ref", "device_id"))
        view["password_saved"] = isinstance(wifi, str) and wifi in saved
        # Only a record made before admin passwords stopped being kept can still have one.
        view["admin_password_saved"] = isinstance(admin, str) and admin in saved
        # The router list is where a direct router lives; it may have been removed there since.
        view["device_present"] = isinstance(device, str) and device in present
        ticked = record.get("checklist")
        checklist = ticked if isinstance(ticked, dict) else {}
        needed = CHECKLIST if record.get("method") == "managed" else _DIRECT_CHECKLIST
        view["checklist_complete"] = all(checklist.get(item) is True for item in needed)
        return view

    def _devices(self) -> set[str]:
        return {device.identifier for device in self.manager.get_all_devices()} if self.manager is not None else set()

    # -- reads -----------------------------------------------------------------------------

    def list(self) -> list[dict[str, Any]]:
        """Every record, newest first, with no secret: password_saved says whether one is stored."""
        records = self._read()
        if not records:
            return []
        saved, present = self._saved_references(), self._devices()
        ordered = sorted(records.items(), key=lambda item: (_order(item[1]), item[0]), reverse=True)
        return [self._public({**record, "id": record_id}, saved, present) for record_id, record in ordered]

    def _get(self, record_id: str) -> dict[str, Any]:
        record = self._read().get(_check_id(record_id))
        if record is None:
            raise RecordNotFound("no such setup record")
        return {**record, "id": record_id}

    # -- changes ---------------------------------------------------------------------------

    def create(self, body: Mapping[str, Any], actor: str) -> dict[str, Any]:
        """Save a record, and add a direct router to DeviceManager. Returns {record, device}."""
        who = normalise_actor(actor)
        request = validate_setup(body)
        if request.method == "direct" and self.manager is None:
            raise ValidationError("this SkyRouter has no router list to add a directly managed router to")
        stored: list[str] = []
        device: Device | None = None
        try:
            with self._changing() as records:
                if len(records) >= MAX_RECORDS:
                    raise ValidationError(f"there can be at most {MAX_RECORDS} setup records; remove old ones first")
                record_id = secrets.token_hex(6)
                while record_id in records:
                    record_id = secrets.token_hex(6)
                refs = {"wifi_password_ref": _wifi_ref(record_id), "admin_password_ref": ""}
                try:
                    stored.append(self.vault.put(request.wifi_password, refs["wifi_password_ref"]))
                except SecretStoreError as exc:
                    raise SetupRecordsError(f"the vault could not store the Wi-Fi password: {exc}") from exc
                if request.method == "direct":
                    device = self._add_device(request, record_id, who)
                record = {
                    "id": record_id,
                    "seq": max((_order(entry)[0] for entry in records.values()), default=0) + 1,
                    "customer": request.customer,
                    "name": request.name,
                    "model": request.model,
                    "vendor": request.vendor,
                    "ip": request.ip,
                    "method": request.method,
                    "admin_username": device.username if device is not None else request.admin_username,
                    "ssid_24": request.ssid_24,
                    "ssid_5": request.ssid_5,
                    "notes": request.notes,
                    "checklist": dict(request.checklist),
                    "device_id": device.identifier if device is not None else None,
                    "created_at": self._clock().astimezone(UTC).isoformat(),
                    "created_by": who,
                    **refs,
                }
                records[record_id] = record
        except BaseException:
            self._undo(device, stored, who)
            raise
        self._log(
            who,
            record,
            _programmed(record),
            {
                "record": record_id,
                "customer": request.customer,
                "model": request.model,
                "method": request.method,
                "ip": request.ip,
                "ssids": {"2.4G": request.ssid_24, "5G": request.ssid_5},
                "checks": [item for item in CHECKLIST if request.checklist[item]],
            },
        )
        present = {device.identifier} if device is not None else set()
        return {
            "record": self._public(record, set(stored), present),
            "device": device.to_public() if device is not None else None,
        }

    def _add_device(self, request: SetupRequest, record_id: str, who: str) -> Device:
        if self.manager is None or request.vendor is None:
            raise ValidationError(DIRECT_UNSUPPORTED)
        values: dict[str, Any] = {
            "model": request.model,
            # Shown in the router list, and how a direct router finds its record again.
            "metadata": {"name": request.name, "customer": request.customer, "setup_record": record_id},
        }
        if request.admin_username:
            values["username"] = request.admin_username
        taken = {device.identifier for device in self.manager.get_all_devices()}
        # Nothing contacts the router here: a TP-Link locks its web page after a few
        # refused logins, so the first login is left to the dashboard's own poll.
        return self.manager.add_device(
            _device_id(request.name, taken),
            host=request.ip,
            vendor=request.vendor,
            password=request.admin_password,
            actor=who,
            **values,
        )

    def _undo(self, device: Device | None, stored: Sequence[str], who: str) -> None:
        """Take back what a create that failed part-way had already done."""
        if device is not None and self.manager is not None:
            try:
                self.manager.remove_device(device.identifier, actor=who)
            except Exception:
                logger.exception(
                    "could not remove router %s, added for a setup record that was not saved", device.identifier
                )
        for reference in stored:
            try:
                self.vault.delete(reference)
            except (SecretStoreError, OSError) as exc:
                logger.warning("could not delete secret %s of a setup record that was not saved: %s", reference, exc)

    def reveal(self, record_id: str, actor: str) -> str:
        """The record's Wi-Fi password, once the view is in the activity log."""
        who = normalise_actor(actor)
        record = self._get(record_id)
        reference = record.get("wifi_password_ref")
        # Only the record's own name, as delete() checks: a hand-edited or restored
        # file must not be able to hand over a router's password as this one's.
        if isinstance(reference, str) and reference and reference != _wifi_ref(record["id"]):
            raise SetupRecordsError(
                f"setup record {record['id']} does not name its own saved Wi-Fi password, so nothing was shown; "
                "the record file may have been edited"
            )
        try:
            if not isinstance(reference, str) or not reference or not self.vault.has(reference):
                raise SavedPasswordMissing("this record's Wi-Fi password is no longer stored")
            password = self.vault.get(reference)
        except SecretStoreError as exc:
            raise SetupRecordsError(f"the saved Wi-Fi password could not be read from the vault: {exc}") from exc
        # Recorded before it is handed over, and never without: a view nobody can
        # see in the log is exactly what the log exists to rule out.
        if self.activity is None:
            raise SetupRecordsError("there is no activity log to record the view in, so the password was not shown")
        try:
            self.activity.record(
                who=who,
                router=_router_of(record),
                router_name=str(record.get("name") or ""),
                kind="access",
                what="Viewed the saved Wi-Fi password",
                result="info",
                details={"record": record["id"]},
            )
        except (ActivityError, OSError) as exc:
            raise SetupRecordsError(
                f"the view could not be recorded in the activity log, so the password was not shown: {exc}"
            ) from exc
        return password

    def delete(self, record_id: str, actor: str) -> dict[str, Any]:
        """Remove a record and its passwords from the vault; its router, if any, stays."""
        who = normalise_actor(actor)
        _check_id(record_id)
        with self._changing() as records:
            record = records.pop(record_id, None)
            if record is None:
                raise RecordNotFound("no such setup record")
        record = {**record, "id": record_id}
        # After the record is gone, so a failure leaves a secret nothing refers to
        # rather than a record whose password was lost. Only the record's own names
        # are deleted: a hand-edited file must not be able to take a router's password.
        # A record made before admin passwords stopped being kept may still name one.
        for key in ("wifi_password_ref", "admin_password_ref"):
            reference = record.get(key)
            if isinstance(reference, str) and reference.startswith(f"setup-{record_id}-"):
                try:
                    self.vault.delete(reference)
                except (SecretStoreError, OSError) as exc:
                    logger.warning(
                        "removed setup record %s but could not delete secret %s: %s", record_id, reference, exc
                    )
        what = (
            f"Setup record removed: {record.get('customer')}, IP {record.get('ip')}; "
            "the router itself was left as it is"
        )
        self._log(who, record, what, {"record": record_id})
        return {"id": record_id, "deleted": True, "device_id": record.get("device_id")}
