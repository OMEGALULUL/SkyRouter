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
    sub.add_parser("list")
    discover = sub.add_parser("discover")
    discover.add_argument("--subnet", default="192.168.1.0/24")
    status = sub.add_parser("status")
    status.add_argument("device")
    reboot = sub.add_parser("reboot")
    reboot.add_argument("device")
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
