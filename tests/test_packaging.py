"""Guards on what a built wheel or sdist may contain.

setuptools collects package data by globbing the disk (and re-reading a stale
egg-info SOURCES.txt), not git, so .gitignore does not keep the runtime device
inventory out of a distribution: only pyproject.toml does. It also only packages
the packages it is told about, so a new subpackage or data file is silently left
out of the wheel until pyproject.toml names it.
"""

import os
import shutil
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from fnmatch import fnmatch
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent
PACKAGE = PROJECT / "cudy_manager"
PROVISIONS = PACKAGE / "acs" / "provisions"
# What the ACS bootstrap loads through importlib.resources.
REQUIRED_PROVISIONS = {"skybre-bootstrap.js", "skybre-inform.js", "skybre-refresh.js"}


def _setuptools_config() -> dict:
    return tomllib.loads((PROJECT / "pyproject.toml").read_text())["tool"]["setuptools"]


def test_dashboard_is_shipped():
    shipped = _setuptools_config().get("package-data", {}).get("cudy_manager", [])
    assert any(fnmatch("dashboard.html", pattern) for pattern in shipped)


def test_runtime_device_config_is_never_shipped():
    config = _setuptools_config()
    shipped = config.get("package-data", {}).get("cudy_manager", [])
    excluded = config.get("exclude-package-data", {}).get("cudy_manager", [])
    for name in ("cudy_devices.yaml", "cudy_devices.yaml.lock"):
        assert not any(fnmatch(name, pattern) for pattern in shipped), f"package-data ships {name}"
        # include-package-data also pulls in anything a stale egg-info manifest lists.
        assert any(fnmatch(name, pattern) for pattern in excluded), f"{name} is not excluded"


def test_the_sdist_manifest_excludes_the_runtime_device_config():
    """exclude-package-data only filters wheels; an sdist also reads a stale egg-info SOURCES.txt."""
    manifest = (PROJECT / "MANIFEST.in").read_text().split()
    for name in ("cudy_manager/cudy_devices.yaml", "cudy_manager/cudy_devices.yaml.lock"):
        assert name in manifest, f"MANIFEST.in does not exclude {name}"


def test_every_subpackage_on_disk_is_packaged():
    """packages is an explicit list, so cudy_manager.acs was missing from the wheel until named."""
    listed = set(_setuptools_config()["packages"])
    on_disk = {
        ".".join(init.parent.relative_to(PROJECT).parts)
        for init in PACKAGE.rglob("__init__.py")
        if "__pycache__" not in init.parts
    }
    assert "cudy_manager.acs" in on_disk
    assert on_disk <= listed, f"not packaged: {sorted(on_disk - listed)}"


def test_the_acs_provisions_are_package_data():
    on_disk = {path.name for path in PROVISIONS.glob("*.js")}
    assert on_disk >= REQUIRED_PROVISIONS
    shipped = _setuptools_config().get("package-data", {}).get("cudy_manager.acs", [])
    for name in sorted(on_disk):
        assert any(fnmatch(f"provisions/{name}", pattern) for pattern in shipped), f"package-data drops {name}"


def test_the_sdist_manifest_includes_the_acs_provisions():
    commands = [
        line.split() for line in (PROJECT / "MANIFEST.in").read_text().splitlines() if line.strip()[:1] not in ("", "#")
    ]
    assert ["recursive-include", "cudy_manager/acs/provisions", "*.js"] in commands


# --- built distributions ------------------------------------------------------------------


def _builder() -> str | None:
    """A Python that has setuptools>=68 (pyproject's build requirement) to build with, offline."""
    for candidate in (sys.executable, shutil.which("python3"), "/usr/bin/python3"):
        if not candidate or not Path(candidate).exists():
            continue
        probe = subprocess.run(
            [candidate, "-c", "import setuptools, sys; sys.exit(int(setuptools.__version__.split('.')[0]) < 68)"],
            capture_output=True,
            timeout=60,
            check=False,
        )
        if probe.returncode == 0:
            return candidate
    return None


@pytest.fixture(scope="module")
def built(tmp_path_factory: pytest.TempPathFactory) -> tuple[set[str], set[str], str]:
    """The names in a wheel and an sdist built from a copy of the project, and the wheel's entry points.

    A copy, because a build writes build/ and an egg-info next to pyproject.toml.
    """
    python = _builder()
    if python is None:
        pytest.skip("no Python with setuptools>=68 to build a wheel with")
    root = tmp_path_factory.mktemp("project")
    shutil.copy(PROJECT / "pyproject.toml", root)
    shutil.copy(PROJECT / "MANIFEST.in", root)
    shutil.copytree(
        PACKAGE, root / "cudy_manager", ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "cudy_devices.yaml*")
    )
    # What an old checkout carries: the live inventory in the package directory, and
    # a stale egg-info manifest that still lists it.
    (root / "cudy_manager" / "cudy_devices.yaml").write_text("devices: {}\n")
    (root / "cudy_manager" / "cudy_devices.yaml.lock").write_text("")
    (root / "skybre_router_manager.egg-info").mkdir()
    (root / "skybre_router_manager.egg-info" / "SOURCES.txt").write_text(
        "cudy_manager/cudy_devices.yaml\ncudy_manager/cudy_devices.yaml.lock\n"
    )
    result = subprocess.run(
        [python, "-c", "from setuptools import build_meta as b; b.build_wheel('dist'); b.build_sdist('dist')"],
        cwd=root,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(root), "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert result.returncode == 0, result.stderr[-3000:]
    [wheel] = (root / "dist").glob("*.whl")
    [sdist] = (root / "dist").glob("*.tar.gz")
    with zipfile.ZipFile(wheel) as archive:
        wheel_names = set(archive.namelist())
        [entry_points] = [name for name in wheel_names if name.endswith(".dist-info/entry_points.txt")]
        scripts = archive.read(entry_points).decode()
    with tarfile.open(sdist) as archive:
        # Drop the "<name>-<version>/" prefix every member carries.
        sdist_names = {name.split("/", 1)[1] for name in archive.getnames() if "/" in name}
    return wheel_names, sdist_names, scripts


def test_the_wheel_ships_the_acs_package_and_its_provisions(built):
    wheel, _, _ = built
    for module in sorted((PACKAGE / "acs").glob("*.py")):
        assert f"cudy_manager/acs/{module.name}" in wheel
    for name in {"__init__.py", "client.py", "tasks.py", "bootstrap.py", "service.py"}:
        assert f"cudy_manager/acs/{name}" in wheel
    for name in REQUIRED_PROVISIONS | {path.name for path in PROVISIONS.glob("*.js")}:
        assert f"cudy_manager/acs/provisions/{name}" in wheel
    assert "cudy_manager/dashboard.html" in wheel


def test_the_wheel_keeps_the_cli_entry_point(built):
    _, _, scripts = built
    assert "router-manager = cudy_manager.cli:main" in scripts


def test_the_wheel_never_ships_runtime_state_or_bytecode(built):
    wheel, _, _ = built
    assert not [name for name in wheel if "cudy_devices.yaml" in name]
    assert not [name for name in wheel if "__pycache__" in name or name.endswith(".pyc")]


def test_the_sdist_ships_the_provisions_but_not_the_inventory(built):
    _, sdist, _ = built
    for name in REQUIRED_PROVISIONS:
        assert f"cudy_manager/acs/provisions/{name}" in sdist
    assert not [name for name in sdist if "cudy_devices.yaml" in name]
