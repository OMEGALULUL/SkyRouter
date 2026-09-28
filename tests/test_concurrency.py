"""Regression tests for concurrent access between the dashboard and the CLI.

The dashboard and `router-manager` are separate processes sharing one config file and
one vault. These cover the cases where a long-running process writes state it loaded
before another process changed it.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from cudy_manager.manager import DeviceManager, ManagerError
from cudy_manager.secrets import SecretStore

PROJECT = Path(__file__).resolve().parent.parent


def store(tmp_path: Path) -> SecretStore:
    return SecretStore(tmp_path / "data")


class TestVaultConcurrentAccess:
    def test_put_does_not_clobber_another_process(self, tmp_path: Path):
        data = tmp_path / "data"
        server_side = SecretStore(data)          # loaded first, like the dashboard
        cli_side = store(tmp_path)             # loaded second, like the CLI
        cli_side.put("two", "device-r2-password")
        server_side.put("one", "device-r1-password")

        on_disk = json.loads((data / "secrets.json").read_text())
        assert sorted(on_disk) == ["device-r1-password", "device-r2-password"]
        assert server_side.get("device-r2-password") == "two"

    def test_delete_only_removes_its_own_reference(self, tmp_path: Path):
        a = store(tmp_path)
        a.put("one", "device-r1-password")
        b = store(tmp_path)
        b.put("two", "device-r2-password")
        a.delete("device-r1-password")
        assert b.references() == ["device-r2-password"]

    def test_references_include_writes_from_other_processes(self, tmp_path: Path):
        a = store(tmp_path)
        b = store(tmp_path)
        b.put("two", "device-r2-password")
        assert a.references() == ["device-r2-password"]

    def test_has_sees_other_processes(self, tmp_path: Path):
        a = store(tmp_path)
        b = store(tmp_path)
        b.put("two", "device-r2-password")
        assert a.has("device-r2-password") is True
        assert a.has("nope") is False


class TestConfigConcurrentAccess:
    def test_stale_manager_does_not_delete_new_devices(self, tmp_path: Path):
        config = tmp_path / "d.yaml"
        dashboard = DeviceManager(config_path=config, data_dir=tmp_path / "data", secret_store=store(tmp_path))
        dashboard.add_device("r1", "192.168.1.1", "cudy", password="one")
        cli = DeviceManager(config_path=config, data_dir=tmp_path / "data", secret_store=store(tmp_path))
        cli.add_device("r2", "192.168.1.2", "cudy", password="two")

        dashboard.update_device("r1", password="rotated")

        on_disk = yaml.safe_load(config.read_text())["devices"]
        assert sorted(on_disk) == ["r1", "r2"]
        assert dashboard.get_device("r2").host == "192.168.1.2"

    def test_duplicate_is_detected_across_processes(self, tmp_path: Path):
        config = tmp_path / "d.yaml"
        a = DeviceManager(config_path=config, data_dir=tmp_path / "data", secret_store=store(tmp_path))
        a.add_device("r1", "192.168.1.1", "cudy", password="one")
        b = DeviceManager(config_path=config, data_dir=tmp_path / "data", secret_store=store(tmp_path))
        with pytest.raises(ManagerError):
            b.add_device("r1", "192.168.1.9", "cudy", password="other")
        with pytest.raises(ManagerError):
            a.add_device("r1", "192.168.1.5", "cudy", password="dup")
        assert sorted(yaml.safe_load(config.read_text())["devices"]) == ["r1"]

    def test_delete_from_one_process_is_respected_by_the_other(self, tmp_path: Path):
        config = tmp_path / "d.yaml"
        a = DeviceManager(config_path=config, data_dir=tmp_path / "data", secret_store=store(tmp_path))
        a.add_device("r1", "192.168.1.1", "cudy", password="one")
        a.add_device("r2", "192.168.1.2", "cudy", password="two")
        b = DeviceManager(config_path=config, data_dir=tmp_path / "data", secret_store=store(tmp_path))
        b.remove_device("r2")
        a.update_device("r1", password="rotated")
        assert sorted(yaml.safe_load(config.read_text())["devices"]) == ["r1"]

    def test_secrets_survive_a_config_write_from_a_stale_manager(self, tmp_path: Path):
        config = tmp_path / "d.yaml"
        data = tmp_path / "data"
        a = DeviceManager(config_path=config, data_dir=data, secret_store=SecretStore(data))
        a.add_device("r1", "192.168.1.1", "cudy", password="one")
        b = DeviceManager(config_path=config, data_dir=data, secret_store=SecretStore(data))
        b.add_device("r2", "192.168.1.2", "cudy", password="two")
        a.update_device("r1", password="rotated")
        reopened = DeviceManager(config_path=config, data_dir=data, secret_store=SecretStore(data))
        assert reopened.credentials(reopened.get_device("r2")) == "two"


class TestRealProcessSeparation:
    """The above use separate objects in one process; this uses genuine processes."""

    def _run(self, tmp_path: Path, code: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            cwd=PROJECT,
            env={
                **os.environ,
                "ROUTER_MANAGER_CONFIG": str(tmp_path / "d.yaml"),
                "ROUTER_MANAGER_DATA_DIR": str(tmp_path / "data"),
                "PYTHONPATH": str(PROJECT),
            },
            timeout=60,
        )

    def test_cli_add_is_not_undone_by_a_running_server(self, tmp_path: Path):
        server = subprocess.Popen(
            [sys.executable, "-c", _LONG_RUNNING_SCRIPT.format(config=tmp_path / "d.yaml", data=tmp_path / "data")],
            cwd=PROJECT,
            env={**os.environ, "PYTHONPATH": str(PROJECT)},
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        try:
            assert server.stdout is not None
            assert server.stdout.readline().strip() == "ready"
            result = self._run(
                tmp_path,
                "from cudy_manager.manager import DeviceManager, ManagerError\n"
                "m = DeviceManager()\n"
                "m.add_device('from-cli', '192.168.1.2', 'cudy', password='two')\n"
                "print('added')\n",
            )
            assert "added" in result.stdout, result.stderr
            # A handshake rather than a timer: the stale write must both happen and
            # come after the CLI's add, or this test proves nothing.
            remaining, _ = server.communicate("go\n", timeout=60)
        finally:
            if server.poll() is None:
                server.kill()
                server.wait()
        assert server.returncode == 0 and remaining.strip() == "wrote", "the server never made its stale write"
        devices = sorted(yaml.safe_load((tmp_path / "d.yaml").read_text())["devices"])
        assert devices == ["from-cli", "r1"], f"server clobbered the CLI device: {devices}"


_LONG_RUNNING_SCRIPT = """
import sys
from cudy_manager.manager import DeviceManager, ManagerError
m = DeviceManager(config_path="{config}", data_dir="{data}")
m.add_device("r1", "192.168.1.1", "cudy", password="one")
print("ready", flush=True)
sys.stdin.readline()
m.update_device("r1", password="rotated")
print("wrote", flush=True)
"""


class TestThreadedMutations:
    """The dashboard serves sync endpoints from a thread pool, so these must
    serialise correctly inside a single DeviceManager as well as across processes."""

    def test_parallel_adds_all_persist(self, tmp_path: Path):
        import threading

        manager = DeviceManager(
            config_path=tmp_path / "d.yaml",
            data_dir=tmp_path / "data",
            secret_store=store(tmp_path),
        )
        errors: list[Exception] = []

        def add(index: int) -> None:
            try:
                manager.add_device(f"r{index}", f"192.0.2.{index}", "cudy", password=f"pw{index}")
            except Exception as exc:  # noqa: BLE001 - recorded and asserted below
                errors.append(exc)

        threads = [threading.Thread(target=add, args=(i,)) for i in range(1, 9)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)

        assert errors == []
        assert sorted(yaml.safe_load((tmp_path / "d.yaml").read_text())["devices"]) == [f"r{i}" for i in range(1, 9)]

    def test_parallel_updates_do_not_lose_fields(self, tmp_path: Path):
        import threading

        manager = DeviceManager(
            config_path=tmp_path / "d.yaml",
            data_dir=tmp_path / "data",
            secret_store=store(tmp_path),
        )
        manager.add_device("r1", "192.0.2.1", "cudy", password="one")
        errors: list[Exception] = []

        def update(field: str, value: object) -> None:
            try:
                manager.update_device("r1", **{field: value})
            except Exception as exc:  # noqa: BLE001 - recorded and asserted below
                errors.append(exc)

        fields = {
            "model": "Cudy-X1",
            "username": "admin2",
            "http_port": 8081,
            "allow_legacy_login": True,
        }
        threads = [threading.Thread(target=update, args=item) for item in fields.items()]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)

        assert errors == []
        final = manager.get_device("r1")
        assert all(getattr(final, field) == value for field, value in fields.items())
