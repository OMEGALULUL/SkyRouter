import argparse
import getpass
import json
import os
import sys

from .manager import DeviceManager, ManagerError
from .models import ValidationError
from .secrets import SecretStoreError


def _manager() -> DeviceManager:
    return DeviceManager()


def _print(value) -> None:
    print(json.dumps(value, indent=2, default=str))


def _prompt_password(prompt: str) -> str | None:
    if os.environ.get("ROUTER_MANAGER_ASSUME_YES"):
        value = os.environ.get("ROUTER_MANAGER_DEVICE_PASSWORD", "")
        if not value:
            print(
                "error: ROUTER_MANAGER_ASSUME_YES is set but ROUTER_MANAGER_DEVICE_PASSWORD is empty",
                file=sys.stderr,
            )
            return None
        return value
    if not sys.stdin.isatty():
        print(
            f"error: {prompt} needs an interactive terminal so it can ask for confirmation. "
            "For unattended use set ROUTER_MANAGER_DEVICE_PASSWORD and ROUTER_MANAGER_ASSUME_YES=1.",
            file=sys.stderr,
        )
        return None
    first = getpass.getpass(f"{prompt}: ")
    if not first:
        print("error: password must not be empty", file=sys.stderr)
        return None
    second = getpass.getpass("Confirm password: ")
    if first != second:
        print("error: passwords did not match, nothing was changed", file=sys.stderr)
        return None
    return first


def _set_password(manager: DeviceManager, args: argparse.Namespace) -> int:
    manager.get_device(args.device)
    password = _prompt_password(f"New password for {args.device}")
    if password is None:
        return 1
    result = manager.set_password(args.device, password, verify=not args.no_verify)
    _print(result)
    verified = result.get("verified")
    if verified is not None and not verified.get("ok"):
        print(
            f"error: password saved for {args.device} but the router rejected it: "
            f"{verified.get('error', 'authentication failed')}",
            file=sys.stderr,
        )
        return 1
    if verified is not None:
        print(f"password for {args.device} saved and verified against the router", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Standalone Cudy and Tenda router manager")
    sub = parser.add_subparsers(dest="command")
    serve = sub.add_parser("serve")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8091)
    add = sub.add_parser("add")
    add.add_argument("id")
    add.add_argument("host")
    add.add_argument("--vendor", choices=["cudy", "tenda"], default="cudy")
    add.add_argument("--username", default="root")
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
    args = parser.parse_args(argv)
    if args.command == "serve":
        import uvicorn
        os.environ.setdefault("ROUTER_MANAGER_PASSWORD", os.environ.get("AUTH_PASSWORD", ""))
        uvicorn.run("cudy_manager.web:app", host=args.host, port=args.port)
        return 0
    manager = _manager()
    try:
        if args.command == "add":
            password = getpass.getpass("Router password: ")
            device = manager.add_device(
                args.id,
                args.host,
                args.vendor,
                password=password,
                username=args.username,
                model=args.model,
                transport=args.transport,
            )
            _print({"device": device.to_public()})
            if not args.no_verify:
                checked = manager.verify_credentials(args.id)
                if not checked["ok"]:
                    print(
                        f"error: {args.id} was added but the router rejected the password: {checked['error']}\n"
                        f"       run 'router-manager diagnose {args.id}' for the full exchange, "
                        f"or 'router-manager set-password {args.id}' to try again",
                        file=sys.stderr,
                    )
                    return 1
                print(f"{args.id} added and the password was accepted by the router", file=sys.stderr)
        elif args.command == "diagnose":
            _print(manager.diagnose(args.device))
        elif args.command == "set-password":
            return _set_password(manager, args)
        elif args.command == "list":
            _print([device.to_public() for device in manager.get_all_devices()])
        elif args.command == "discover":
            _print([device.to_dict() for device in manager.discover_network(args.subnet)])
        elif args.command == "status":
            _print(manager.get_status(args.device))
        elif args.command == "reboot":
            if not manager.reboot_device(args.device):
                raise ManagerError("router did not confirm reboot")
            _print({"device": args.device, "status": "initiated"})
        else:
            parser.print_help()
    except (ManagerError, ValidationError, SecretStoreError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
