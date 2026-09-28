import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture(autouse=True)
def _isolated_environment(tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep every test away from the operator's real state.

    The default data dir is under HOME, so a test that forgot to pass paths wrote
    a vault into the real state dir; ROUTER_MANAGER_* and AUTH_* variables exported
    in the developer's shell leaked into tests that assumed they were unset.
    """
    monkeypatch.setenv("HOME", str(tmp_path_factory.mktemp("home")))
    for name in list(os.environ):
        if name.startswith(("ROUTER_MANAGER_", "AUTH_")) or name == "XDG_STATE_HOME":
            monkeypatch.delenv(name)
