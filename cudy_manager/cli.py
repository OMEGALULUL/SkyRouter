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

from .activity import KINDS as ACTIVITY_KINDS
from .activity import ActivityLog
from .adapters import AdapterError
from .discovery import DiscoveryError
from .manager import DeviceManager, ManagerError, default_data_dir, validate_wifi_passphrase
from .models import Device, ValidationError
from .secrets import SecretStore, SecretStoreError

if TYPE_CHECKING:
    from .acs.service import AcsService
    from .maintenance import MaintenanceRunner, MaintenanceStore

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
    data_dir = default_data_dir()
    # The server's activity log, so a change made here is in the same history.
    return DeviceManager(data_dir=data_dir, activity=ActivityLog(data_dir))


def _actor() -> str:
    """Who the activity log names for a change made from this command line."""
    try:
        user = getpass.getuser()
    except (KeyError, OSError, ImportError):
        # No login name (a container without a passwd entry) must not stop the command.
        user = ""
    return f"cli ({user or 'unknown'})"


def _confirm(question: str) -> bool:
    """Ask before a change nobody can take back; ASSUME_YES=1 answers for unattended use."""
    if os.environ.get(ASSUME_YES_ENV, "").strip() == "1":
        return True
    if not sys.stdin.isatty():
        print(
            f"error: this needs an interactive terminal to confirm. For unattended use set {ASSUME_YES_ENV}=1.",
            file=sys.stderr,
        )
        return False
    # The question goes to stderr, so stdout stays the command's JSON.
    print(f"{question} [y/N] ", end="", file=sys.stderr, flush=True)
    try:
        answer = sys.stdin.readline()
    except KeyboardInterrupt:
        answer = ""
    if not answer.endswith("\n"):
        # Ctrl-D or Ctrl-C: the terminal echoed no newline, so the error needs its own line.
        print(file=sys.stderr)
    if answer.strip().lower() not in {"y", "yes"}:
        print("error: not confirmed, nothing was changed", file=sys.stderr)
        return False
    return True


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
    result = manager.set_password(args.device, password, verify=not args.no_verify, actor=_actor())
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
        changed = manager.set_wifi_password(identifier, passphrase, args.radio, actor=_actor())
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
        activity=ActivityLog(settings.data_dir),
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
        acs_id,
        args.band,
        ssid=ssid,
        passphrase=passphrase,
        confirm_guessed_band=args.confirm_guessed_band,
        actor=_actor(),
    )
    return _show_job(acs, job, args.wait, held)


def _acs_job(acs: "AcsService", args: argparse.Namespace, held: list[str]) -> int:
    return _show_job(acs, acs.get_job(args.job_id), args.wait, held)


def _acs_firmware(acs: "AcsService", args: argparse.Namespace, held: list[str]) -> int:
    from .acs.client import validate_device_id
    from .acs.service import MAX_FIRMWARE_BYTES
    from .acs.tasks import validate_firmware_name

    action = args.acs_firmware_command
    if action == "list":
        _print(acs.list_firmware())
        return 0
    if action == "add":
        size = os.stat(args.path).st_size
        # Checked before reading, so a wrong path to a disk image is not loaded into memory.
        if size > MAX_FIRMWARE_BYTES:
            raise ValidationError(f"{args.path} is larger than {MAX_FIRMWARE_BYTES // (1024 * 1024)} MiB")
        with open(args.path, "rb") as handle:
            data = handle.read(MAX_FIRMWARE_BYTES + 1)
        record = acs.add_firmware(
            data,
            os.path.basename(args.path),
            args.model_hint,
            args.version,
            args.oui,
            args.product_class,
            actor=_actor(),
        )
        # The record, never the file: an image can embed default credentials.
        _print(record)
        print(f"stored as {record['name']}; install it with 'router-manager acs firmware upgrade'", file=sys.stderr)
        return 0
    if action == "remove":
        _print(acs.remove_firmware(args.name, actor=_actor()))
        return 0
    acs_id = validate_device_id(args.acs_id)
    chosen = acs.firmware.get(validate_firmware_name(args.name))
    if chosen is None:
        raise ValidationError(f"firmware {args.name} is not in the firmware library")
    if not _confirm(f"Install firmware {chosen.get('version')} ({args.name}) on {acs_id}? The router restarts."):
        return 1
    job = acs.firmware_upgrade(acs_id, args.name, confirm_model_mismatch=args.confirm_model_mismatch, actor=_actor())
    return _show_job(acs, job, args.wait, held)


_ACS_COMMANDS: dict[str, Callable[["AcsService", argparse.Namespace, list[str]], int]] = {
    "status": _acs_status,
    "devices": _acs_devices,
    "dump": _acs_dump,
    "bootstrap": _acs_bootstrap,
    "wifi": _acs_wifi,
    "job": _acs_job,
    "firmware": _acs_firmware,
}


def _acs(args: argparse.Namespace) -> int:
    from .acs.bootstrap import BootstrapRefused
    from .acs.client import AcsError
    from .acs.jobs import JobStoreError
    from .acs.service import AcsConfirmationRequired, FirmwareMismatch

    # Secrets this command has in hand, scrubbed from everything it prints.
    held: list[str] = []
    with _warnings_as_lines():
        try:
            return _ACS_COMMANDS[args.acs_command](_acs_service(), args, held)
        except FirmwareMismatch as exc:
            _print(exc.plan, held)
            _error(f"{exc} Re-run with --confirm-model-mismatch only if the file is right for this router.", held)
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
    firmware = commands.add_parser("firmware", help="the firmware library, and installing from it")
    firmware.set_defaults(firmware_parser=firmware)
    library = firmware.add_subparsers(dest="acs_firmware_command")
    library.add_parser("list", help="the library, newest first, with what each file is being installed on")
    add = library.add_parser("add", help="store a firmware image on the ACS for later upgrades")
    add.add_argument("path")
    add.add_argument(
        "--version", required=True, help="exactly what the router will report as its software version once it runs it"
    )
    add.add_argument("--oui", required=True, help="the OUI in the routers' DeviceId, such as 80AFCA")
    add.add_argument("--product-class", required=True, help="the product class in the routers' DeviceId")
    add.add_argument("--model-hint", help="a name for people, such as 'Cudy AP1300'")
    remove = library.add_parser("remove", help="delete a file from the ACS and the library")
    remove.add_argument("name")
    upgrade = library.add_parser("upgrade", help="install a library file on a router; it restarts to do so")
    upgrade.add_argument("acs_id")
    upgrade.add_argument("name")
    upgrade.add_argument(
        "--confirm-model-mismatch",
        action="store_true",
        help="install although the router reports another OUI or product class than the file was stored for",
    )
    for command in (wifi, job, upgrade):
        command.add_argument(
            "--wait",
            type=_wait_seconds,
            default=0,
            metavar="SECONDS",
            help="wait up to this long for the router's answer, moving the job along meanwhile",
        )
    return acs


# --- the activity log ---------------------------------------------------------------------


def _count(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        value = 0
    if value < 1:
        raise argparse.ArgumentTypeError("must be a whole number of at least 1")
    return value


def _activity(args: argparse.Namespace) -> int:
    # Read straight from the log, without loading the device config: the history of
    # a router must stay readable when its config is what broke.
    log = ActivityLog(default_data_dir())
    filters = {"router": args.router, "who": args.who, "kind": args.kind, "before": args.before}
    try:
        if args.csv:
            sys.stdout.write(log.export_csv(**filters, limit=args.limit))
        else:
            _print(log.list(**filters, limit=args.limit or 200))
    except (ValidationError, OSError) as exc:
        _error(str(exc))
        return 1
    return 0


# --- firmware on a directly managed router -----------------------------------------------


def _hour(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        value = -1
    if not 0 <= value <= 23:
        raise argparse.ArgumentTypeError("must be a whole hour from 0 to 23")
    return value


def _firmware(manager: DeviceManager, args: argparse.Namespace) -> int:
    identifier = manager.get_device(args.device).identifier
    if args.firmware_command == "status":
        _print({"device": identifier, "firmware": manager.firmware_info(identifier)})
        return 0
    if args.firmware_command == "check":
        found = manager.check_firmware_update(identifier, actor=_actor())
        _print({"device": identifier, "check": found, "installed": False})
        current = found.get("current") or "unknown"
        if found.get("available") is True:
            latest = found.get("latest") or "newer firmware"
            print(f"{identifier}: {latest} is available (running {current}); nothing was installed", file=sys.stderr)
        elif found.get("available") is False:
            print(f"{identifier}: no newer firmware than {current}", file=sys.stderr)
        else:
            # A script must not read "could not tell" as "up to date".
            _error(f"{identifier}: could not tell whether newer firmware exists: {found.get('note') or 'no answer'}")
            return 1
        return 0
    if args.window is not None and not args.enabled:
        _error("--window can only be given with --on")
        return 1
    if not manager.set_auto_update(identifier, args.enabled, args.window, actor=_actor()):
        _error(f"{identifier} did not confirm the automatic-update change")
        return 1
    _print({"device": identifier, "auto_update": "on" if args.enabled else "off", "window_start_hour": args.window})
    return 0


# --- maintenance plans -----------------------------------------------------------------------


def _maintenance_runner(manager: DeviceManager, with_acs: bool) -> "tuple[MaintenanceRunner, MaintenanceStore]":
    """The server's runner: the same plans, state, activity log and reboot history."""
    from .maintenance import MaintenanceRunner, MaintenanceStore
    from .scheduler import RebootScheduler

    data_dir = manager.data_dir
    store = MaintenanceStore(data_dir)
    acs = None
    if with_acs and os.environ.get(ACS_URL_ENV, "").strip():
        acs = _acs_service()
    runner = MaintenanceRunner(manager, acs, store, activity=manager.activity)
    # Only for its reboot history, which starts a plan's cooldown as it does in the server.
    RebootScheduler(manager, data_dir / "scheduler_state.json", maintenance=runner)
    return runner, store


def _maintenance(args: argparse.Namespace) -> int:
    from .acs.client import AcsError
    from .acs.jobs import JobStoreError
    from .maintenance import MaintenanceError

    with _warnings_as_lines():
        try:
            manager = _manager()
            runner, store = _maintenance_runner(manager, with_acs=args.maintenance_command == "run")
            if args.maintenance_command == "list":
                _print(runner.overview())
                return 0
            plan = store.plan(args.plan_id)
            if args.maintenance_command == "show":
                view = next((item for item in runner.overview() if item["id"] == plan.id), None)
                _print(view if view is not None else plan.to_dict())
                return 0
            targets = plan.targets.to_dict()
            named = len(targets["devices"]) + len(targets["acs_devices"])
            # A group is worked out when the plan runs, so it is named rather than counted.
            groups = f"groups: {', '.join(targets['groups'])}" if targets["groups"] else ""
            reach = "every router" if targets["all"] else " and ".join(
                part for part in (f"{named} router(s)" if named else "", groups) if part
            )
            question = f'Run maintenance plan "{plan.name}" ({", ".join(plan.actions)}) on {reach} now?'
            if not _confirm(question):
                return 1
            results = runner.run_now(plan.id, _actor())
            _print({"plan": plan.id, "results": results})
            for result in results:
                line = f"{result.get('target') or result.get('device') or plan.name}: {result.get('status')}"
                if result.get("reason"):
                    line += f" ({result['reason']})"
                print(_one_line(line), file=sys.stderr)
            return 1 if any(result.get("status") in {"failed", "partial"} for result in results) else 0
        except (
            ManagerError,
            ValidationError,
            SecretStoreError,
            AdapterError,
            AcsError,
            JobStoreError,
            MaintenanceError,
            ValueError,
            OSError,
        ) as exc:
            _error(str(exc))
        except KeyboardInterrupt:
            print(file=sys.stderr)
            _error("interrupted")
    return 1


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
    activity = sub.add_parser("activity", help="who changed what on which router, newest first")
    activity.add_argument("--router", help="a device id, or acs:<GenieACS ID> for a TR-069 router")
    activity.add_argument("--who", help="the actor exactly as recorded, such as 'Skybre staff'")
    activity.add_argument("--kind", choices=sorted(ACTIVITY_KINDS))
    activity.add_argument("--before", help="an entry id (the page after it) or an ISO 8601 time")
    activity.add_argument("--limit", type=_count, help="at most this many entries (default 200; CSV: all)")
    activity.add_argument("--csv", action="store_true", help="print CSV, for a spreadsheet")
    firmware = sub.add_parser("firmware", help="firmware on a directly managed router's own web UI")
    firmware_commands = firmware.add_subparsers(dest="firmware_command")
    firmware_status = firmware_commands.add_parser("status", help="the running firmware and the auto-update setting")
    firmware_status.add_argument("device")
    firmware_check = firmware_commands.add_parser(
        "check", help="ask the router whether newer firmware exists; installs nothing"
    )
    firmware_check.add_argument("device")
    auto_update = firmware_commands.add_parser("auto-update", help="turn the router's own automatic update on or off")
    auto_update.add_argument("device")
    switch = auto_update.add_mutually_exclusive_group(required=True)
    switch.add_argument("--on", dest="enabled", action="store_true", default=None)
    switch.add_argument("--off", dest="enabled", action="store_false")
    auto_update.add_argument(
        "--window", type=_hour, metavar="HH", help="with --on: the hour the router's 2-hour update window starts"
    )
    maintenance = sub.add_parser("maintenance", help="maintenance plans: routine work on groups of routers")
    maintenance_commands = maintenance.add_subparsers(dest="maintenance_command")
    maintenance_commands.add_parser("list", help="every plan with its next window and latest run")
    maintenance_show = maintenance_commands.add_parser("show", help="one plan with its next window and latest run")
    maintenance_show.add_argument("plan_id")
    maintenance_run = maintenance_commands.add_parser(
        "run", help="run a plan now, whether or not its window is open; its guards still apply"
    )
    maintenance_run.add_argument("plan_id")
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
        if args.acs_command == "firmware" and args.acs_firmware_command is None:
            args.firmware_parser.print_help()
            return 0
        # Before the manager loads: TR-069 routers live in GenieACS, so a broken
        # device config must not stop them being managed.
        return _acs(args)
    if args.command == "activity":
        return _activity(args)
    if args.command == "maintenance":
        if args.maintenance_command is None:
            maintenance.print_help()
            return 0
        return _maintenance(args)
    if args.command == "firmware" and args.firmware_command is None:
        firmware.print_help()
        return 0
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
                actor=_actor(),
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
        elif args.command == "firmware":
            return _firmware(manager, args)
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
            if not manager.reboot_device(args.device, actor=_actor()):
                raise ManagerError("router did not confirm reboot")
            _print({"device": args.device, "status": "initiated"})
    except (ManagerError, ValidationError, SecretStoreError, AdapterError, DiscoveryError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
