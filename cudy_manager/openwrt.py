import shlex
from typing import Any

from .adapters import AdapterError, RouterAdapter
from .models import Device


def _parse_stations(output: str) -> list[dict[str, Any]]:
    """Parse `iw dev <radio> station dump` output.

    Field names contain spaces ("rx bytes", "signal avg") and values contain
    colons, so each field is split on its first colon only. Splitting on
    whitespace instead would truncate every multi-word key and collide
    "rx bytes" with "tx bytes".
    """
    clients: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for raw in output.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("Station "):
            if current:
                clients.append(current)
            parts = line.split(None, 2)
            current = {"mac": parts[1] if len(parts) > 1 else ""}
            if len(parts) > 2:
                # The trailing group is "(on br-lan)".
                interface = parts[2].strip().strip("()")
                if interface.lower().startswith("on "):
                    interface = interface[3:].strip()
                if interface:
                    current["interface"] = interface
            continue
        if current is None:
            continue
        key, separator, value = line.partition(":")
        if not separator or not key.strip():
            continue
        current[key.strip()] = value.strip()
    if current:
        clients.append(current)
    return clients


class OpenWrtAdapter(RouterAdapter):
    def __init__(self, device: Device, password: str):
        super().__init__(device, password)
        self.client: Any = None
        self.connected = False

    def connect(self) -> bool:
        try:
            import paramiko
        except ImportError as exc:
            raise AdapterError("paramiko is required for SSH transport") from exc
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        if self.device.accept_unknown_host_key:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # noqa: S507
        else:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        try:
            client.connect(
                hostname=self.device.host,
                port=self.device.ssh_port,
                username=self.device.username,
                password=self.password,
                timeout=8,
                banner_timeout=8,
                auth_timeout=8,
                allow_agent=False,
                look_for_keys=False,
            )
        except Exception as exc:
            raise AdapterError(f"SSH connection failed: {exc}") from exc
        self.client = client
        self.connected = True
        return True

    def execute(self, command: str) -> tuple[int, str, str]:
        if not self.connected:
            self.connect()
        if self.client is None:
            raise AdapterError("SSH client is not connected")
        stdin, stdout, stderr = self.client.exec_command(command, timeout=20)
        stdin.close()
        output = stdout.read().decode(errors="replace").strip()
        error = stderr.read().decode(errors="replace").strip()
        code = stdout.channel.recv_exit_status()
        return code, output, error

    def status(self) -> dict[str, Any]:
        code, uptime, error = self.execute("cat /proc/uptime")
        if code != 0:
            raise AdapterError(error or "could not read uptime")
        try:
            uptime_seconds = int(float(uptime.split()[0]))
        except (IndexError, ValueError) as exc:
            # Malformed output must surface as an adapter failure, otherwise the
            # dashboard reports an internal error instead of a device problem.
            raise AdapterError(f"could not parse uptime from {uptime[:40]!r}") from exc
        _, release, _ = self.execute("cat /etc/openwrt_release 2>/dev/null || cat /etc/os-release")
        _, load, _ = self.execute("cat /proc/loadavg")
        _, memory, _ = self.execute("free -m")
        return {
            "online": True,
            "uptime_seconds": uptime_seconds,
            "firmware": release,
            "load": load,
            "memory": memory,
            "source": "openwrt-ssh",
        }

    def clients(self, radio: str = "radio0") -> list[dict[str, Any]]:
        code, output, error = self.execute(f"iw dev {shlex.quote(radio)} station dump")
        if code != 0:
            raise AdapterError(error or "could not read wireless stations")
        return _parse_stations(output)

    def set_ssid(self, ssid: str, radio: str | None = None) -> bool:
        section = str(self.device.metadata.get("uci_section", ""))
        if not section:
            raise AdapterError("metadata.uci_section is required for SSH SSID changes")
        if not ssid or any(ord(char) < 32 for char in ssid):
            raise AdapterError("SSID is invalid")
        value = shlex.quote(ssid)
        code, _, error = self.execute(
            f"uci set {shlex.quote(section)}.ssid={value} && uci commit wireless && wifi reload"
        )
        if code != 0:
            raise AdapterError(error or "could not set SSID")
        return True

    def reboot(self) -> bool:
        code, _, error = self.execute("reboot")
        if code != 0:
            raise AdapterError(error or "reboot command failed")
        return True

    def close(self) -> None:
        if self.client is not None:
            self.client.close()
        self.client = None
        self.connected = False
