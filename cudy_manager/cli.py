import argparse
import contextlib
import getpass
import json
import logging
import os
import sys
import time
from collections.abc import Callable, Iterator, Sequence
from typing import TYPE_CHECKING, Any

from .adapters import AdapterError
from .discovery import DiscoveryError
from .manager import DeviceManager, ManagerError, validate_wifi_passphrase
from .models import Device, ValidationError
from .secrets import SecretStore, SecretStoreError

if TYPE_CHECKING:
    from .acs.service import AcsService

ASSUME_YES_ENV = "ROUTER_MANAGER_ASSUME_YES"
DEVICE_PASSWORD_ENV = "ROUTER_MANAGER_DEVICE_PASSWORD"  # noqa: S105 - a variable's name, not its value
# Separate from DEVICE_PASSWORD on purpose: a script that exported a router's admin
# password for set-password must not make it the Wi-Fi passphrase one command later.
WIFI_PASSPHRASE_ENV = "ROUTER_MANAGER_WIFI_PASSPHRASE"  # noqa: S105 - a variable's name, not its value
ACS_URL_ENV = "ROUTER_MANAGER_ACS_URL"

# web.SSID_RADIOS and params.BAND_CHOICES, spelled out so building the parser loads
# neither the web stack nor the ACS package; tests keep the copies equal.
WIFI_RADIOS = ("2.4G", "5G")
ACS_BANDS = ("2.4GHz", "5GHz", "6GHz", "all")
JOB_POLL_SECONDS = 3.0
MAX_WAIT_SECONDS = 86400
FOLLOW_WAIT_SECONDS = 600
REDACTED = "<redacted>"

# Indirections so tests can drive --wait without real time passing.
_sleep: Callable[[float], None] = time.sleep
_clock: Callable[[], float] = time.monotonic


def _manager() -> DeviceManager:
    return DeviceManager()


def _scrub(value: Any, secrets: Sequence[str] = ()) -> Any:
    """``value`` with every secret the command holds replaced, however deeply it is nested."""
    if isinstance(value, str):
        for secret in secrets:
            if secret:
                value = value.replace(secret, REDACTED)
        return value
    if isinstance(value, dict):
        return {_scrub(key, secrets): _scrub(item, secrets) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_scrub(item, secrets) for item in value]
    return value


def _print(value: Any, secrets: Sequence[str] = ()) -> None:
    print(json.dumps(_scrub(value, secrets), indent=2, default=str))


def _one_line(text: str) -> str:
    return " ".join(text.split())


def _error(message: str, secrets: Sequence[str] = ()) -> None:
    # A router's or the ACS's own text can carry newlines; scripts read one line.
    print(f"error: {_one_line(_scrub(message, secrets))}", file=sys.stderr)


def _prompt_password(prompt: str, *, env: str = DEVICE_PASSWORD_ENV, noun: str = "password") -> str | None:
    # Only the documented "1" opts in: ASSUME_YES=0 left in a shell beside a stale
    # DEVICE_PASSWORD silently stored that password without asking.
    if os.environ.get(ASSUME_YES_ENV, "").strip() == "1":
        value = os.environ.get(env, "")
        if not value:
            print(f"error: {ASSUME_YES_ENV} is set but {env} is empty", file=sys.stderr)
            return None
        return value
    if not sys.stdin.isatty():
        print(
            f"error: {prompt} needs an interactive terminal so it can ask for confirmation. "
            f"For unattended use set {env} and {ASSUME_YES_ENV}=1.",
            file=sys.stderr,
        )
        return None
    try:
        first = getpass.getpass(f"{prompt}: ")
        if not first:
            print(f"error: {noun} must not be empty", file=sys.stderr)
            return None
        second = getpass.getpass(f"Confirm {noun}: ")
    except (EOFError, KeyboardInterrupt):
        print(f"\nerror: no {noun} was entered, nothing was changed", file=sys.stderr)
        return None
    if first != second:
        print(f"error: {noun}s did not match, nothing was changed", file=sys.stderr)
        return None
    return first


def _read_router_password() -> str | None:
    # getpass prefers /dev/tty even when stdin is a pipe, so the password a script
    # piped in was ignored and the prompt blocked whenever a terminal was attached.
    try:
        if sys.stdin.isatty():
            return getpass.getpass("Router password: ")
        line = sys.stdin.readline()
    except (EOFError, KeyboardInterrupt):
        print("\nerror: no password was entered, nothing was added", file=sys.stderr)
        return None
    if not line:
        print("error: stdin is not a terminal and held no password, nothing was added", file=sys.stderr)
        return None
    return line.removesuffix("\n")


def _report_unverified(device: Device, checked: dict[str, Any]) -> None:
    name = device.identifier
    # diagnose replays the HTTP login only, so it has nothing to say about an SSH device.
    ssh = device.transport == "ssh"
    if checked.get("reason") == "rejected":
        headline = f"was added but the router rejected the password: {checked.get('error', 'authentication failed')}"
        retry = f"'router-manager set-password {name}' to try again"
        hint = f"run {retry}" if ssh else f"run 'router-manager diagnose {name}' for the full exchange, or {retry}"
    else:
        # The password may well be right, so set-password is not the next step: on a
        # TP-Link WR840N every retry of a correct password counts toward its lockout.
        headline = f"was added but the router could not be checked: {checked.get('error', 'no response')}"
        if ssh:
            hint = (
                f"check that its host key is in known_hosts and port {device.ssh_port} is reachable, "
                f"then run 'router-manager status {name}'"
            )
        else:
            hint = f"run 'router-manager diagnose {name}' to see where the login stops"
    print(f"error: {name} {headline}\n       {hint}", file=sys.stderr)


def _set_password(manager: DeviceManager, args: argparse.Namespace) -> int:
    manager.get_device(args.device)
    password = _prompt_password(f"New password for {args.device}")
    if password is None:
        return 1
    result = manager.set_password(args.device, password, verify=not args.no_verify)
    _print(result)
    verified = result.get("verified")
    if verified is not None and not verified.get("ok"):
        if verified.get("reason") == "rejected":
            print(
                f"error: password saved for {args.device} but the router rejected it: "
                f"{verified.get('error', 'authentication failed')}",
                file=sys.stderr,
            )
        else:
            print(
                f"error: password saved for {args.device} but the router could not be checked: "
                f"{verified.get('error', 'no response')}",
                file=sys.stderr,
            )
        return 1
    if verified is not None:
        print(f"password for {args.device} saved and verified against the router", file=sys.stderr)
    return 0


def _wifi_password(manager: DeviceManager, args: argparse.Namespace) -> int:
    # Resolved first, so a typo in the name fails before anyone types a passphrase twice.
    identifier = manager.get_device(args.device).identifier
    passphrase = _prompt_password(f"New Wi-Fi passphrase for {identifier}", env=WIFI_PASSPHRASE_ENV, noun="passphrase")
    if passphrase is None:
        return 1
    try:
        validate_wifi_passphrase(passphrase)
        changed = manager.set_wifi_password(identifier, passphrase, args.radio)
    except (ManagerError, ValidationError, SecretStoreError, AdapterError, ValueError, OSError) as exc:
        # Router replies end up in adapter errors, and one could echo the form it was sent.
        _error(str(exc), [passphrase])
        return 1
    if not changed:
        _error(f"{identifier} did not confirm the Wi-Fi passphrase change")
        return 1
    _print({"device": identifier, "radio": args.radio or "all", "status": "changed"})
    print(f"Wi-Fi passphrase for {identifier} changed; clients must reconnect with the new one", file=sys.stderr)
    return 0


# --- TR-069 through GenieACS ------------------------------------------------------------


def _acs_service() -> "AcsService":
    """The server's AcsService, from the server's own Settings: the same NBI, job file and vault.

    Settings.from_env() is the one reader of the ROUTER_MANAGER_ACS_* variables, so
    the CLI cannot drift from the server; it raises ValueError for a value it refuses.
    The web and ACS modules are only imported here, so the direct commands never load them.
    """
    from .acs.client import AcsClient
    from .acs.service import AcsService
    from .web import Settings

    settings = Settings.from_env()
    if not settings.acs_url:
        raise ValidationError(
            f"{ACS_URL_ENV} is not set, so TR-069 support is off; set it to the GenieACS NBI address, "
            "for example http://127.0.0.1:7557"
        )
    client = AcsClient(settings.acs_url, allow_remote=settings.acs_allow_remote)
    # The same directory as the server's DeviceManager vault, without loading the
    # device config: TR-069 routers are not in it.
    return AcsService(
        client,
        SecretStore(settings.data_dir),
        settings.data_dir,
        inform_interval=settings.acs_inform_interval,
        scrub_secrets=settings.acs_scrub_secrets,
    )


class _WarningLine(logging.Handler):
    """A log record as one "warning:" line on whatever stderr is now, never with a traceback."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            print(f"warning: {_one_line(record.getMessage())}", file=sys.stderr)
        except Exception:  # noqa: BLE001 - logging must never take the command down
            self.handleError(record)


@contextlib.contextmanager
def _warnings_as_lines() -> Iterator[None]:
    # Without a handler, logging's last resort prints logger.exception() records with
    # their traceback. Removed afterwards so nothing outlives the command.
    handler = _WarningLine(logging.WARNING)
    package = logging.getLogger("cudy_manager")
    package.addHandler(handler)
    try:
        yield
    finally:
        package.removeHandler(handler)


def _wait_seconds(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        value = -1
    if not 0 <= value <= MAX_WAIT_SECONDS:
        raise argparse.ArgumentTypeError(f"must be whole seconds from 0 to {MAX_WAIT_SECONDS}")
    return value


def _bootstrap_problems(state: dict[str, Any] | None) -> list[str]:
    if not state:
        return ["SkyRouter's bootstrap could not be checked"]
    if state.get("error"):
        return [f"SkyRouter's bootstrap could not be checked: {state['error']}"]
    problems = []
    seeded = state.get("seeded_presets") or []
    if seeded:
        problems.append(
            f"GenieACS still has the presets its UI seeds ({', '.join(seeded)}), which override SkyRouter's "
            "inform settings; run 'router-manager acs bootstrap --remove-seeded'"
        )
    if not state.get("installed"):
        drift = state.get("drift") or []
        shown = ", ".join(f"{item['kind']} {item['name']} {item['state']}" for item in drift[:8])
        more = f" and {len(drift) - 8} more" if len(drift) > 8 else ""
        command = "router-manager acs bootstrap" + (" --remove-seeded" if seeded else "")
        problems.append(f"SkyRouter's bootstrap is not installed in GenieACS ({shown}{more}); run '{command}'")
    return problems


def _acs_status(acs: "AcsService", args: argparse.Namespace, held: list[str]) -> int:
    health = acs.health()
    _print(health)
    where = acs.client.base_url
    if not health["reachable"] or health["error"]:
        _error(f"GenieACS at {where} is not usable: {health['error'] or 'no reply'}")
        return 1
    problems = [*health["problems"], *_bootstrap_problems(health["bootstrap"])]
    for problem in problems:
        _error(problem)
    if problems:
        return 1
    faults = health["channel_faults"]
    if faults:
        print(
            f"warning: {len(faults)} provisioning fault(s) on SkyRouter's channels; see channel_faults",
            file=sys.stderr,
        )
    print(
        f"GenieACS {health['version']} at {where} is reachable and SkyRouter's bootstrap is installed",
        file=sys.stderr,
    )
    return 0


def _acs_devices(acs: "AcsService", args: argparse.Namespace, held: list[str]) -> int:
    _print(acs.list_devices(q=args.q, tag=args.tag, skip=args.skip, limit=args.limit))
    return 0


def _acs_dump(acs: "AcsService", args: argparse.Namespace, held: list[str]) -> int:
    from .acs import params
    from .acs.client import validate_device_id
    from .acs.tree import DeviceTree

    acs_id = validate_device_id(args.acs_id)
    doc = acs.client.get_device(acs_id, params.DETAIL_PROJECTION)
    if doc is None:
        _error(f"GenieACS has no device {acs_id}")
        return 1
    # A secret can also turn up under a harmless name, such as a vendor leaf echoing
    # the key, so the vault's copies are redacted by value, and so is the plaintext
    # GenieACS caches in a secret leaf after a write (F15) wherever the tree repeats it.
    held.extend(acs.known_secrets(acs_id))
    held.extend(
        leaf.value
        for leaf in DeviceTree(doc).iter_leaves()
        if isinstance(leaf.value, str) and len(leaf.value) >= 8 and params.is_secret_path(leaf.path)
    )
    _print(params.redact(doc, known_values=held), held)
    return 0


def _acs_bootstrap(acs: "AcsService", args: argparse.Namespace, held: list[str]) -> int:
    report = acs.bootstrap(remove_seeded=args.remove_seeded)
    print(f"GenieACS {report['version']}")
    for name in report["removed_seeded"]:
        print(f"removed seeded preset {name}")
    for kind, objects in (("provision", report["provisions"]), ("preset", report["presets"])):
        for name, action in objects.items():
            print(f"{kind} {name}: {action}")
    print(f"writes: {report['writes']}")
    return 0


def _follow(acs: "AcsService", job: dict[str, Any], seconds: int) -> dict[str, Any]:
    """Advance the job until it has a verdict or ``seconds`` pass.

    poll_jobs() rather than get_job() alone, so a change made from the CLI still
    finishes when the server is not running; the job file's leases keep the two
    from advancing the same job at once.
    """
    deadline = _clock() + seconds
    try:
        while not job["terminal"] and _clock() < deadline:
            _sleep(max(0.0, min(JOB_POLL_SECONDS, deadline - _clock())))
            acs.poll_jobs()
            job = acs.get_job(job["id"])
    except KeyboardInterrupt:
        # The job carries on in the ACS; only the waiting stops.
        print(file=sys.stderr)
    return job


def _report_job(job: dict[str, Any], waited: bool, held: Sequence[str]) -> int:
    from .acs.jobs import ACKNOWLEDGED, VERIFIED

    name = f"{job['kind']} job {job['id']}"
    text = job.get("message") or job["state"]
    if job.get("last_error"):
        text += f" (last ACS error: {job['last_error']})"
    if job["terminal"]:
        if job["state"] in (ACKNOWLEDGED, VERIFIED):
            print(_one_line(_scrub(f"{name} {job['state']}: {text}", held)), file=sys.stderr)
            return 0
        _error(f"{name} {job['state']}: {text}", held)
        return 1
    follow = f"follow it with 'router-manager acs job {job['id']} --wait {FOLLOW_WAIT_SECONDS}'"
    if waited:
        _error(f"{name} has not finished ({job['state']}): {text}; {follow}", held)
        return 1
    print(_one_line(_scrub(f"{name} {job['state']}: {text}; {follow}", held)), file=sys.stderr)
    return 0


def _show_job(acs: "AcsService", job: dict[str, Any], wait: int, held: Sequence[str]) -> int:
    if wait:
        job = _follow(acs, job, wait)
    _print(job, held)
    return _report_job(job, bool(wait), held)


def _acs_wifi(acs: "AcsService", args: argparse.Namespace, held: list[str]) -> int:
    from .acs.client import validate_device_id
    from .acs.service import validate_ssid

    # Everything that can be refused without the passphrase is refused before asking for it.
    acs_id = validate_device_id(args.acs_id)
    ssid = validate_ssid(args.ssid) if args.ssid is not None else None
    if args.keep_passphrase and ssid is None:
        raise ValidationError("nothing to change: --keep-passphrase needs --ssid")
    passphrase = None
    if not args.keep_passphrase:
        passphrase = _prompt_password(
            f"New Wi-Fi passphrase for {acs_id}", env=WIFI_PASSPHRASE_ENV, noun="passphrase"
        )
        if passphrase is None:
            return 1
        held.append(passphrase)
        validate_wifi_passphrase(passphrase)
    job = acs.set_wifi(
        acs_id, args.band, ssid=ssid, passphrase=passphrase, confirm_guessed_band=args.confirm_guessed_band
    )
    return _show_job(acs, job, args.wait, held)


def _acs_job(acs: "AcsService", args: argparse.Namespace, held: list[str]) -> int:
    return _show_job(acs, acs.get_job(args.job_id), args.wait, held)


_ACS_COMMANDS: dict[str, Callable[["AcsService", argparse.Namespace, list[str]], int]] = {
    "status": _acs_status,
    "devices": _acs_devices,
    "dump": _acs_dump,
    "bootstrap": _acs_bootstrap,
    "wifi": _acs_wifi,
    "job": _acs_job,
}


def _acs(args: argparse.Namespace) -> int:
    from .acs.bootstrap import BootstrapRefused
    from .acs.client import AcsError
    from .acs.jobs import JobStoreError
    from .acs.service import AcsConfirmationRequired

    # Secrets this command has in hand, scrubbed from everything it prints.
    held: list[str] = []
    with _warnings_as_lines():
        try:
            return _ACS_COMMANDS[args.acs_command](_acs_service(), args, held)
        except AcsConfirmationRequired as exc:
            _print(exc.plan, held)
            _error(f"{exc} Re-run with --confirm-guessed-band once the band is right.", held)
        except BootstrapRefused as exc:
            hint = " ('router-manager acs bootstrap --remove-seeded')" if exc.seeded else ""
            _error(f"{exc}{hint}", held)
        except (AcsError, ValidationError, SecretStoreError, JobStoreError, ValueError, OSError) as exc:
            _error(str(exc), held)
        except KeyboardInterrupt:
            print(file=sys.stderr)
            _error("interrupted", held)
    return 1


def _add_acs_parser(sub: Any) -> argparse.ArgumentParser:
    acs = sub.add_parser(
        "acs",
        help="TR-069 routers managed through GenieACS",
        description=f"TR-069 routers managed through GenieACS. Needs {ACS_URL_ENV}, as the server does.",
    )
    commands = acs.add_subparsers(dest="acs_command")
    commands.add_parser("status", help="check GenieACS and SkyRouter's bootstrap in it")
    devices = commands.add_parser("devices", help="list the routers GenieACS knows, latest check-in first")
    devices.add_argument("--q", "--search", dest="q", help="part of an ID, serial, product class or manufacturer")
    devices.add_argument("--tag")
    devices.add_argument("--skip", type=int, default=0)
    devices.add_argument("--limit", type=int, default=50)
    dump = commands.add_parser("dump", help="print a router's cached parameter tree with its secrets redacted")
    dump.add_argument("acs_id")
    bootstrap = commands.add_parser("bootstrap", help="install SkyRouter's provisions and presets into GenieACS")
    bootstrap.add_argument(
        "--remove-seeded",
        action="store_true",
        help="delete the presets GenieACS's UI seeds (bootstrap, default, inform)",
    )
    wifi = commands.add_parser("wifi", help="change a router's SSID and/or Wi-Fi passphrase")
    wifi.add_argument("acs_id")
    wifi.add_argument("--band", required=True, choices=ACS_BANDS)
    wifi.add_argument("--ssid")
    wifi.add_argument(
        "--keep-passphrase", action="store_true", help="change only the SSID; the passphrase is not asked for"
    )
    wifi.add_argument(
        "--confirm-guessed-band",
        action="store_true",
        help="write to a band SkyRouter inferred because the router does not report it",
    )
    job = commands.add_parser("job", help="show an ACS job")
    job.add_argument("job_id")
    for command in (wifi, job):
        command.add_argument(
            "--wait",
            type=_wait_seconds,
            default=0,
            metavar="SECONDS",
            help="wait up to this long for the router's answer, moving the job along meanwhile",
        )
    return acs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Standalone Cudy and Tenda router manager")
    sub = parser.add_subparsers(dest="command")
    serve = sub.add_parser("serve")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8091)
    add = sub.add_parser("add")
    add.add_argument("id")
    add.add_argument("host")
    add.add_argument("--vendor", choices=["cudy", "tenda", "tplink"], default="cudy")
    add.add_argument("--username", help="defaults to admin for tplink, root otherwise")
    add.add_argument("--model", default="")
    add.add_argument("--transport", choices=["web", "ssh"], default="web")
    add.add_argument("--no-verify", action="store_true", help="skip the authentication check against the router")
    sub.add_parser("list")
    discover = sub.add_parser("discover")
    discover.add_argument("--subnet", default="192.168.1.0/24")
    status = sub.add_parser("status")
    status.add_argument("device")
    reboot = sub.add_parser("reboot")
    reboot.add_argument("device")
    diag = sub.add_parser("diagnose", help="show the raw login exchange for a device")
    diag.add_argument("device")
    reset = sub.add_parser("set-password", help="replace a device's stored password")
    reset.add_argument("device")
    reset.add_argument("--no-verify", action="store_true", help="skip the authentication check against the router")
    wifi_password = sub.add_parser("wifi-password", help="change a directly managed router's Wi-Fi passphrase")
    wifi_password.add_argument("device")
    wifi_password.add_argument("--radio", choices=WIFI_RADIOS, help="only this band (default: every band)")
    acs = _add_acs_parser(sub)
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    if args.command == "serve":
        import uvicorn
        os.environ.setdefault("ROUTER_MANAGER_PASSWORD", os.environ.get("AUTH_PASSWORD", ""))
        # uvicorn otherwise rewrites the client address from X-Forwarded-For for any
        # loopback peer, which would let a local caller pick its login-limiter bucket.
        trust = os.environ.get("ROUTER_MANAGER_TRUST_PROXY", "").strip().lower() in {"1", "true", "yes"}
        uvicorn.run("cudy_manager.web:app", host=args.host, port=args.port, proxy_headers=trust)
        return 0
    if args.command == "acs":
        if args.acs_command is None:
            acs.print_help()
            return 0
        # Before the manager loads: TR-069 routers live in GenieACS, so a broken
        # device config must not stop them being managed.
        return _acs(args)
    try:
        # Inside the handler: loading refuses a truncated config or a dangling secret
        # reference on purpose, and that refusal must read as an error line.
        manager = _manager()
        if args.command == "add":
            password = _read_router_password()
            if password is None:
                return 1
            optional = {"username": args.username} if args.username else {}
            device = manager.add_device(
                args.id,
                args.host,
                args.vendor,
                password=password,
                model=args.model,
                transport=args.transport,
                **optional,
            )
            _print({"device": device.to_public()})
            if not args.no_verify:
                checked = manager.verify_credentials(device.identifier)
                if not checked["ok"]:
                    _report_unverified(device, checked)
                    return 1
                print(f"{device.identifier} added and the password was accepted by the router", file=sys.stderr)
        elif args.command == "diagnose":
            _print(manager.diagnose(args.device))
        elif args.command == "set-password":
            return _set_password(manager, args)
        elif args.command == "wifi-password":
            return _wifi_password(manager, args)
        elif args.command == "list":
            _print([device.to_public() for device in manager.get_all_devices()])
        elif args.command == "discover":
            _print([device.to_dict() for device in manager.discover_network(args.subnet)])
        elif args.command == "status":
            reading = manager.get_status(args.device)
            _print(reading)
            if not reading.get("online"):
                print(
                    f"error: {args.device} is offline: {reading.get('error', 'no response from the router')}",
                    file=sys.stderr,
                )
                return 1
        elif args.command == "reboot":
            if not manager.reboot_device(args.device):
                raise ManagerError("router did not confirm reboot")
            _print({"device": args.device, "status": "initiated"})
    except (ManagerError, ValidationError, SecretStoreError, AdapterError, DiscoveryError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
