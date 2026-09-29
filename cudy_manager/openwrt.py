import contextlib
import json
import logging
import os
import re
import shlex
import tempfile
import threading
from pathlib import Path
from typing import Any

from .adapters import AdapterError, AuthenticationRejected, RouterAdapter, UnsupportedOperation
from .models import Device

logger = logging.getLogger(__name__)

_CONNECT_TIMEOUT = 8
_COMMAND_TIMEOUT = 20
# Status sweeps connect to several routers at once, and each records its key by
# rewriting the whole file.
_KNOWN_HOSTS_LOCK = threading.Lock()


def _parse_stations(output: str) -> list[dict[str, Any]]:
    """Parse `iw dev <interface> station dump` output.

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
                # The trailing group is "(on wlan0)".
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


def _access_point_interfaces(output: str) -> list[str]:
    """The AP netdevs in `iw dev` output.

    iw needs kernel interface names (wlan0, phy0-ap0), not uci's radio0, and a
    station interface's "station" is the upstream AP rather than a client.
    """
    found: list[str] = []
    name: str | None = None
    for raw in output.splitlines():
        line = raw.strip()
        if line.startswith("Interface "):
            name = line.split(None, 1)[1].strip()
        elif line.startswith(("phy#", "Unnamed")):
            name = None
        elif name and line == "type AP":
            found.append(name)
    return found


# Encryption modes whose secret is a passphrase in the iface's "key" option. Open,
# WEP and 802.1X networks have none, and giving them one changes nothing.
_PASSPHRASE_ENCRYPTIONS = {"psk", "psk2", "psk-mixed", "sae", "sae-mixed"}
_WIRELESS_SECTION = re.compile(r"wireless\.[A-Za-z0-9_]+")
_BAND_BY_OPTION = {"2g": "2.4G", "5g": "5G"}
# Pre-21.02 configs have no "band"; hwmode 11n/11ac alone does not name the band.
_BAND_BY_HWMODE = {"11a": "5G", "11b": "2.4G", "11g": "2.4G"}


def _wireless_sections(output: str) -> dict[str, dict[str, str]]:
    """Parse `uci -q show wireless` into {section: {option: value}}.

    The current passphrase is skipped rather than parsed: nothing here needs it, and
    it should not sit in memory longer than the SSH read that carried it.
    """
    sections: dict[str, dict[str, str]] = {}
    for line in output.splitlines():
        name, separator, raw = line.partition("=")
        parts = name.split(".")
        if not separator or parts[0] != "wireless":
            continue
        if len(parts) == 2:
            sections.setdefault(name, {})[".type"] = raw.strip()
        elif len(parts) == 3 and parts[2] != "key":
            try:
                value = " ".join(shlex.split(raw))
            except ValueError:
                continue
            sections.setdefault(f"{parts[0]}.{parts[1]}", {})[parts[2]] = value
    return sections


def _band(sections: dict[str, dict[str, str]], iface: str) -> str | None:
    radio = sections.get(f"wireless.{sections[iface].get('device', '')}", {})
    return _BAND_BY_OPTION.get(radio.get("band", "")) or _BAND_BY_HWMODE.get(radio.get("hwmode", ""))


def _record_new_host_keys(path: Path) -> Any:
    import paramiko

    class RecordNewHostKeys(paramiko.MissingHostKeyPolicy):
        # paramiko's AutoAddPolicy keeps a new key in memory unless the client loaded
        # a host-key file, and a fresh client per call means every connection would
        # trust whatever key answers and send it the root password.
        def missing_host_key(self, client: Any, hostname: str, key: Any) -> None:
            with _KNOWN_HOSTS_LOCK:
                keys = paramiko.HostKeys()
                if path.exists():
                    keys.load(str(path))
                known = keys.lookup(hostname)
                if known is not None:
                    # Another adapter recorded this router after our client read the file.
                    if known.get(key.get_name()) != key:
                        raise paramiko.BadHostKeyException(hostname, key, next(iter(known.values())))
                    return
                keys.add(hostname, key.get_name(), key)
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
                os.close(descriptor)
                try:
                    keys.save(temporary)
                    os.replace(temporary, path)
                except BaseException:
                    with contextlib.suppress(OSError):
                        os.unlink(temporary)
                    raise
            logger.warning("recorded new SSH host key for %s: %s %s", hostname, key.get_name(), key.fingerprint)

    return RecordNewHostKeys()


def _router_refused(client: Any) -> bool:
    # paramiko raises the same AuthenticationException when the router refuses the
    # password, when auth_timeout runs out and when the link drops mid-login. Only a
    # refusal leaves the session up with the request answered, and anything else must
    # not be reported, or latched, as a wrong password.
    transport = client.get_transport()
    event = getattr(getattr(transport, "auth_handler", None), "auth_event", None)
    return bool(transport is not None and transport.is_active() and event is not None and event.is_set())


def _release_values(text: str) -> dict[str, str]:
    """KEY='value' lines of /etc/openwrt_release, a shell fragment, unquoted."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        name, equals, raw = line.strip().partition("=")
        if not equals or not re.fullmatch(r"[A-Z_][A-Z0-9_]*", name):
            continue
        try:
            words = shlex.split(raw)
        except ValueError:
            # An unbalanced quote: keep what is there rather than lose the version.
            words = [raw.strip("'\"")]
        values[name] = " ".join(words).strip()
    return values


class OpenWrtAdapter(RouterAdapter):
    def __init__(self, device: Device, password: str, known_hosts: str | Path | None = None):
        super().__init__(device, password)
        self.known_hosts = Path(known_hosts) if known_hosts is not None else None
        self.client: Any = None
        self.connected = False

    def connect(self) -> bool:
        try:
            import paramiko
        except ImportError as exc:
            raise AdapterError("paramiko is required for SSH transport") from exc
        if self.device.accept_unknown_host_key and self.known_hosts is None:
            raise AdapterError("accept_unknown_host_key needs a known_hosts file to remember the router's key in")
        client = paramiko.SSHClient()
        try:
            client.load_system_host_keys()
            if self.known_hosts is not None and self.known_hosts.exists():
                client.get_host_keys().load(str(self.known_hosts))
            if self.device.accept_unknown_host_key and self.known_hosts is not None:
                client.set_missing_host_key_policy(_record_new_host_keys(self.known_hosts))
            else:
                client.set_missing_host_key_policy(paramiko.RejectPolicy())
            client.connect(
                hostname=self.device.host,
                port=self.device.ssh_port,
                username=self.device.username,
                password=self.password,
                timeout=_CONNECT_TIMEOUT,
                banner_timeout=_CONNECT_TIMEOUT,
                auth_timeout=_CONNECT_TIMEOUT,
                allow_agent=False,
                look_for_keys=False,
            )
        except paramiko.BadHostKeyException as exc:
            client.close()
            raise AdapterError(
                f"SSH host key for {self.device.host} does not match the one recorded, so the password was not "
                "sent; if the router was reset or reflashed, remove its old entry from known_hosts"
            ) from exc
        except paramiko.BadAuthenticationType as exc:
            client.close()
            allowed = ", ".join(exc.allowed_types) or "none"
            raise AuthenticationRejected(
                f"SSH login rejected: the router does not accept password logins for {self.device.username} "
                f"(it allows: {allowed})"
            ) from exc
        except paramiko.AuthenticationException as exc:
            refused = _router_refused(client)
            client.close()
            if refused:
                raise AuthenticationRejected(
                    f"SSH login rejected: the router refused the password for {self.device.username}"
                ) from exc
            raise AdapterError(f"SSH login got no answer: {exc}") from exc
        except Exception as exc:
            client.close()
            raise AdapterError(f"SSH connection failed: {exc}") from exc
        self.client = client
        self.connected = True
        return True

    def execute(self, command: str, stdin_data: str | None = None) -> tuple[int, str, str]:
        if not self.connected:
            self.connect()
        if self.client is None:
            raise AdapterError("SSH client is not connected")
        import paramiko

        failures = (paramiko.SSHException, OSError, EOFError)
        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=_COMMAND_TIMEOUT)
        except failures as exc:
            self.close()
            raise AdapterError(f"SSH command could not be started: {exc}") from exc
        # From here the router has the command, so a failure leaves a reboot or an
        # SSID change in an unknown state; the message has to say so.
        try:
            if stdin_data is not None:
                stdin.write(stdin_data)
                stdin.flush()
            stdin.close()
            output = stdout.read().decode(errors="replace").strip()
            error = stderr.read().decode(errors="replace").strip()
            code = stdout.channel.recv_exit_status()
        except failures as exc:
            self.close()
            raise AdapterError(f"SSH session failed before the command finished; it may still have run: {exc}") from exc
        if code == -1:
            # paramiko's value when no exit status arrived: the session closed, or the
            # command was killed by a signal.
            self.close()
            raise AdapterError("SSH command ended without an exit status; it may still have run")
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

    def clients(self, interface: str | None = None) -> list[dict[str, Any]]:
        if interface:
            interfaces = [interface]
        else:
            code, output, error = self.execute("iw dev")
            if code != 0:
                raise AdapterError(error or "could not list wireless interfaces")
            interfaces = _access_point_interfaces(output)
        clients: list[dict[str, Any]] = []
        for name in interfaces:
            code, output, error = self.execute(f"iw dev {shlex.quote(name)} station dump")
            if code != 0:
                raise AdapterError(error or f"could not read wireless stations on {name}")
            clients.extend(_parse_stations(output))
        return clients

    def set_ssid(self, ssid: str, radio: str | None = None) -> bool:
        if radio:
            # Renaming uci_section regardless would report the chosen band changed
            # while the other one was renamed.
            raise UnsupportedOperation(
                "SSH SSID changes rename metadata.uci_section and cannot choose a band; leave the radio unset"
            )
        section = str(self.device.metadata.get("uci_section", ""))
        if not section:
            raise AdapterError("metadata.uci_section is required for SSH SSID changes")
        if not section.startswith("wireless.") or section == "wireless.":
            # Only the wireless config is committed and reloaded below.
            raise AdapterError("metadata.uci_section must name a wireless section, such as wireless.default_radio0")
        if not ssid or any(ord(char) < 32 for char in ssid):
            raise AdapterError("SSID is invalid")
        value = shlex.quote(ssid)
        code, _, error = self.execute(
            f"uci set {shlex.quote(section)}.ssid={value} && uci commit wireless && wifi reload"
        )
        if code != 0:
            raise AdapterError(error or "could not set SSID")
        return True

    def _wifi_targets(self, sections: dict[str, dict[str, str]], radio: str | None) -> list[str]:
        configured = str(self.device.metadata.get("uci_section", ""))
        if configured and radio is None:
            if configured not in sections:
                raise AdapterError(f"metadata.uci_section {configured} does not exist on the router")
            return [configured]
        access_points = [
            name
            for name, options in sections.items()
            if options.get(".type") == "wifi-iface" and options.get("mode") == "ap" and options.get("disabled") != "1"
        ]
        if radio is not None:
            if any(_band(sections, name) is None for name in access_points):
                raise AdapterError(
                    "cannot tell which band each wireless interface is on; set metadata.uci_section, "
                    "or change the password on all bands"
                )
            access_points = [name for name in access_points if _band(sections, name) == radio]
        if not access_points:
            raise AdapterError("the router has no enabled access-point interface" + (f" on {radio}" if radio else ""))
        return access_points

    def set_wifi_password(self, password: str, radio: str | None = None) -> bool:
        code, output, error = self.execute("uci -q show wireless")
        if code != 0:
            raise AdapterError(error or "could not read the wireless configuration")
        sections = _wireless_sections(output)
        targets = self._wifi_targets(sections, radio)
        for name in targets:
            if not _WIRELESS_SECTION.fullmatch(name) or sections[name].get(".type") != "wifi-iface":
                raise AdapterError(f"{name} is not a wireless interface section")
            encryption = sections[name].get("encryption", "none")
            mode = encryption.split("+", 1)[0]
            if mode not in _PASSPHRASE_ENCRYPTIONS:
                raise AdapterError(
                    f"{name} uses encryption {encryption!r}, which has no passphrase to change; "
                    "set up WPA2 or WPA3 on the router first"
                )
            if mode.startswith("sae") and len(password) == 64:
                raise AdapterError(f"{name} uses WPA3 (SAE), which needs a passphrase of 8 to 63 characters")
        # Committing would also apply whatever someone else has staged, under our name.
        code, staged, error = self.execute("uci changes wireless")
        if code != 0 or staged:
            raise AdapterError(
                "the router has uncommitted wireless changes; commit or revert them on the router first"
                if code == 0
                else error or "could not check for uncommitted wireless changes"
            )
        # The passphrase travels on stdin: in the command line it would sit in the
        # router's process list and in anything that logs SSH commands. uci's stored
        # value is compared before committing so a mangled key is never applied.
        steps = [f'uci set {name}.key="$key" && [ "$(uci -q get {name}.key)" = "$key" ]' for name in targets]
        script = (
            'IFS= read -r key || exit 3; { '
            + " && ".join(steps)
            + " && uci commit wireless; } || { uci revert wireless; exit 4; }"
        )
        code, _, error = self.execute(script, stdin_data=password + "\n")
        if code != 0:
            raise AdapterError(
                "the router did not store the new Wi-Fi password, and nothing was changed: "
                + (error.replace(password, "<redacted>") or f"exit status {code}")
            )
        code, _, error = self.execute("wifi reload")
        if code != 0:
            raise AdapterError(
                "the new Wi-Fi password is saved on the router, but reloading Wi-Fi failed, so it takes effect "
                f"at the next reboot: {error or f'exit status {code}'}"
            )
        return True

    def firmware_info(self) -> dict[str, Any]:
        code, release, error = self.execute("cat /etc/openwrt_release")
        if code != 0:
            raise AdapterError(error or "could not read /etc/openwrt_release; the router may not run OpenWrt")
        values = _release_values(release)
        version = " ".join(part for part in (values.get("DISTRIB_RELEASE"), values.get("DISTRIB_REVISION")) if part)
        hardware = ""
        code, board, _ = self.execute("ubus call system board")
        if code == 0:
            with contextlib.suppress(ValueError, AttributeError):
                hardware = str(json.loads(board).get("model") or "").strip()
        if not hardware:
            # Older releases, or an image built without ubus's system object.
            code, model, _ = self.execute("cat /tmp/sysinfo/model")
            hardware = model.strip() if code == 0 else ""
        return {"version": version, "hardware": hardware, "auto_update": None, "source": "openwrt-ssh"}

    # Both refuse without connecting: nothing on the router could answer them.
    def set_auto_update(self, enabled: bool, window_start_hour: int | None = None) -> bool:
        raise UnsupportedOperation(
            "OpenWrt has no built-in automatic firmware update; upgrade it on the router with sysupgrade"
        )

    def check_firmware_update(self, timeout: float = 60) -> dict[str, Any]:
        raise UnsupportedOperation(
            "OpenWrt has no built-in update check SkyRouter can run; compare the release with openwrt.org"
        )

    def reboot(self) -> bool:
        code, _, error = self.execute("reboot")
        if code != 0:
            raise AdapterError(error or "reboot command failed")
        return True

    def close(self) -> None:
        client = self.client
        self.client = None
        self.connected = False
        if client is not None:
            client.close()
