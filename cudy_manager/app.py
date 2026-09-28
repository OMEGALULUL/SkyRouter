from typing import Any

from . import web
from .web import Settings, create_app

__all__ = ["Settings", "app", "create_app"]  # noqa: F822 - app comes from __getattr__


def __getattr__(name: str) -> Any:
    # Forwarded instead of imported: `from .web import app` built the app, and so
    # read the config and opened the vault, merely because this module was imported.
    if name == "app":
        return web.app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
