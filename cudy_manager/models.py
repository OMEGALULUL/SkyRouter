import re
from dataclasses import dataclass, field
from typing import Any


class ValidationError(ValueError):
    pass


def _bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() in {"1", "true", "yes", "on", "enabled"}


def _int(value: Any, name: str, minimum: int, maximum: int, default: int) -> int:
    if value is None or value == "":
        return default
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"{name} must be an integer") from exc
    if result < minimum or result > maximum:
        raise ValidationError(f"{name} must be between {minimum} and {maximum}")
    return result


@dataclass
class RebootPolicy:
    enabled: bool = False
    at: str = "04:00"
    timezone: str = "UTC"
    window_minutes: int = 15
    min_uptime_seconds: int = 3600
    cooldown_seconds: int = 21600

    def validate(self) -> None:
        if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", self.at):
            raise ValidationError("reboot.at must use HH:MM format")
        if not self.timezone or not re.fullmatch(r"[A-Za-z0-9_+\-/:]+", self.timezone):
            raise ValidationError("reboot.timezone is invalid")
        self.window_minutes = _int(self.window_minutes, "reboot.window_minutes", 1, 180, 15)
        self.min_uptime_seconds = _int(
            self.min_uptime_seconds, "reboot.min_uptime_seconds", 0, 31_536_000, 3600
        )
        self.cooldown_seconds = _int(
            self.cooldown_seconds, "reboot.cooldown_seconds", 0, 31_536_000, 21600
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "RebootPolicy":
        data = data or {}
        if not isinstance(data, dict):
            raise ValidationError("reboot must be an object")
        policy = cls(
            enabled=_bool(data.get("enabled"), False),
            at=str(data.get("at", "04:00")),
            timezone=str(data.get("timezone", "UTC")),
            window_minutes=data.get("window_minutes", 15),
            min_uptime_seconds=data.get("min_uptime_seconds", 3600),
            cooldown_seconds=data.get("cooldown_seconds", 21600),
        )
        policy.validate()
        return policy

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "at": self.at,
            "timezone": self.timezone,
            "window_minutes": self.window_minutes,
            "min_uptime_seconds": self.min_uptime_seconds,
            "cooldown_seconds": self.cooldown_seconds,
        }


@dataclass
class Device:
    identifier: str
    vendor: str
    host: str
    username: str = "root"
    password_ref: str = ""
    snmp_community_ref: str = ""
    model: str = ""
    http_port: int = 80
    https: bool = False
    verify_tls: bool = True
    ssh_port: int = 22
    snmp_port: int = 161
    transport: str = "web"
    rpc_path: str = "/ubus"
    allow_legacy_login: bool = False
    accept_unknown_host_key: bool = False
    enabled: bool = True
    reboot: RebootPolicy = field(default_factory=RebootPolicy)
    metadata: dict[str, Any] = field(default_factory=dict)
    status: dict[str, Any] = field(default_factory=dict)
    last_seen: str = ""

    def validate(self) -> None:
        self.identifier = str(self.identifier).strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}", self.identifier):
            raise ValidationError("device identifier contains unsupported characters")
        self.vendor = str(self.vendor).strip().lower()
        if self.vendor not in {"cudy", "tenda", "tplink"}:
            raise ValidationError("vendor must be cudy, tenda, or tplink")
        self.host = str(self.host).strip()
        if not self.host or any(char.isspace() for char in self.host):
            raise ValidationError("host is required")
        if "://" in self.host or any(char in self.host for char in "/@?#"):
            raise ValidationError("host must be an IP address or hostname, not a URL")
        self.username = str(self.username).strip()
        if not self.username:
            raise ValidationError("username is required")
        self.transport = str(self.transport).strip().lower()
        if self.transport not in {"web", "ssh"}:
            raise ValidationError("transport must be web or ssh")
        if not re.fullmatch(r"/[A-Za-z0-9_./;:-]*", self.rpc_path):
            raise ValidationError("rpc_path must be an absolute URL path")
        self.http_port = _int(self.http_port, "http_port", 1, 65535, 80)
        self.ssh_port = _int(self.ssh_port, "ssh_port", 1, 65535, 22)
        self.snmp_port = _int(self.snmp_port, "snmp_port", 1, 65535, 161)
        self.https = _bool(self.https, False)
        self.verify_tls = _bool(self.verify_tls, True)
        self.allow_legacy_login = _bool(self.allow_legacy_login, False)
        self.accept_unknown_host_key = _bool(self.accept_unknown_host_key, False)
        self.enabled = _bool(self.enabled, True)
        if not isinstance(self.metadata, dict):
            raise ValidationError("metadata must be an object")
        self.reboot = RebootPolicy.from_dict(
            self.reboot.to_dict() if isinstance(self.reboot, RebootPolicy) else self.reboot
        )
        self.reboot.validate()

    @classmethod
    def from_dict(cls, identifier: str, data: dict[str, Any]) -> "Device":
        if not isinstance(data, dict):
            raise ValidationError(f"device {identifier} must be an object")
        forbidden = {"password", "ssh_password", "luci_password", "snmp_community"}
        present = forbidden.intersection(data)
        if present:
            raise ValidationError(
                f"device {identifier} contains plaintext credential fields; use secret references"
            )
        host = data.get("host", data.get("ip", ""))
        vendor = data.get("vendor", "cudy" if data.get("is_cudy", True) else "tenda")
        device = cls(
            identifier=identifier,
            vendor=str(vendor),
            host=str(host),
            username=str(data.get("username", "root")),
            password_ref=str(data.get("password_ref", "")),
            snmp_community_ref=str(data.get("snmp_community_ref", "")),
            model=str(data.get("model", "")),
            http_port=data.get("http_port", 80),
            https=_bool(data.get("https", data.get("use_https", False)), False),
            verify_tls=_bool(data.get("verify_tls", True), True),
            ssh_port=data.get("ssh_port", 22),
            snmp_port=data.get("snmp_port", 161),
            transport=data.get("transport", "web"),
            rpc_path=data.get("rpc_path", "/ubus"),
            allow_legacy_login=data.get("allow_legacy_login", False),
            accept_unknown_host_key=data.get("accept_unknown_host_key", False),
            enabled=data.get("enabled", True),
            reboot=RebootPolicy.from_dict(data.get("reboot")),
            metadata=dict(data.get("metadata", {})),
            last_seen=str(data.get("last_seen", "")),
        )
        device.validate()
        return device

    def to_config(self) -> dict[str, Any]:
        return {
            "vendor": self.vendor,
            "host": self.host,
            "username": self.username,
            "password_ref": self.password_ref,
            "snmp_community_ref": self.snmp_community_ref,
            "model": self.model,
            "http_port": self.http_port,
            "https": self.https,
            "verify_tls": self.verify_tls,
            "ssh_port": self.ssh_port,
            "snmp_port": self.snmp_port,
            "transport": self.transport,
            "rpc_path": self.rpc_path,
            "allow_legacy_login": self.allow_legacy_login,
            "accept_unknown_host_key": self.accept_unknown_host_key,
            "enabled": self.enabled,
            "reboot": self.reboot.to_dict(),
            "metadata": self.metadata,
        }

    def to_public(self) -> dict[str, Any]:
        return {
            "id": self.identifier,
            "vendor": self.vendor,
            "host": self.host,
            "username": self.username,
            "model": self.model,
            "http_port": self.http_port,
            "https": self.https,
            "ssh_port": self.ssh_port,
            "transport": self.transport,
            "enabled": self.enabled,
            "credential_configured": bool(self.password_ref),
            "reboot": self.reboot.to_dict(),
            "metadata": self.metadata,
            "status": self.status,
            "last_seen": self.last_seen,
        }
