import errno
import os
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from cudy_manager.secrets import SecretStore, SecretStoreError


class _WriteHook:
    """Stands in for the first file os.fdopen opens, running ``before_write`` first."""

    def __init__(self, handle, before_write):
        self._handle = handle
        self._before_write = before_write

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return self._handle.__exit__(*exc_info)

    def write(self, data):
        self._before_write()
        return self._handle.write(data)

    def __getattr__(self, name):
        return getattr(self._handle, name)


def _hook_first_write(monkeypatch, before_write):
    real_fdopen = os.fdopen
    calls = []

    def fdopen(fd, *args, **kwargs):
        handle = real_fdopen(fd, *args, **kwargs)
        calls.append(fd)
        return _WriteHook(handle, before_write) if len(calls) == 1 else handle

    monkeypatch.setattr(os, "fdopen", fdopen)


class TestLostKeyIsNotSilentlyReplaced:
    """Minting a new key over a populated vault leaves it readable by neither key."""

    def test_missing_key_with_stored_secrets_is_refused(self, tmp_path: Path, monkeypatch):
        monkeypatch.delenv("ROUTER_MANAGER_KEY_LOST", raising=False)
        store = SecretStore(tmp_path)
        store.put("old-password", "ref-a")
        backup = (tmp_path / "master.key").read_bytes()
        (tmp_path / "master.key").unlink()

        with pytest.raises(SecretStoreError, match="master.key"):
            SecretStore(tmp_path)
        assert not (tmp_path / "master.key").exists()

        (tmp_path / "master.key").write_bytes(backup)
        assert SecretStore(tmp_path).get("ref-a") == "old-password"

    def test_the_manager_refuses_to_start_on_a_vault_whose_key_is_missing(self, tmp_path: Path, monkeypatch):
        from cudy_manager.manager import DeviceManager

        monkeypatch.delenv("ROUTER_MANAGER_KEY_LOST", raising=False)
        manager = DeviceManager(config_path=tmp_path / "c.yaml", data_dir=tmp_path)
        manager.add_device("r1", "192.168.1.1", "cudy", password="old")
        (tmp_path / "master.key").unlink()

        with pytest.raises(SecretStoreError):
            DeviceManager(config_path=tmp_path / "c.yaml", data_dir=tmp_path)

    def test_an_emptied_vault_may_get_a_new_key(self, tmp_path: Path, monkeypatch):
        monkeypatch.delenv("ROUTER_MANAGER_KEY_LOST", raising=False)
        store = SecretStore(tmp_path)
        store.delete(store.put("gone", "ref-a"))
        (tmp_path / "master.key").unlink()

        assert SecretStore(tmp_path).get(SecretStore(tmp_path).put("fresh", "ref-b")) == "fresh"

    def test_declaring_the_key_lost_keeps_references_so_passwords_can_be_reset(self, tmp_path: Path, monkeypatch):
        from cudy_manager.manager import DeviceManager

        manager = DeviceManager(config_path=tmp_path / "c.yaml", data_dir=tmp_path)
        manager.add_device("r1", "192.168.1.1", "cudy", password="old")
        (tmp_path / "master.key").unlink()
        monkeypatch.setenv("ROUTER_MANAGER_KEY_LOST", "1")

        recovered = DeviceManager(config_path=tmp_path / "c.yaml", data_dir=tmp_path)
        recovered.set_password("r1", "reset", verify=False)

        monkeypatch.delenv("ROUTER_MANAGER_KEY_LOST")
        reopened = DeviceManager(config_path=tmp_path / "c.yaml", data_dir=tmp_path)
        assert reopened.credentials(reopened.get_device("r1")) == "reset"


class TestKeyCreationIsAtomic:
    """master.key must only ever be visible complete, and must be durable before use."""

    def test_a_store_opened_while_the_key_is_written_shares_that_key(self, tmp_path: Path, monkeypatch):
        opened = []
        _hook_first_write(monkeypatch, lambda: opened.append(SecretStore(tmp_path)))

        first = SecretStore(tmp_path)

        (second,) = opened
        second.put("shared", "ref-a")
        assert first.get("ref-a") == "shared"

    def test_a_failed_key_write_does_not_leave_an_unusable_key_behind(self, tmp_path: Path, monkeypatch):
        def disk_full():
            raise OSError(errno.ENOSPC, "No space left on device")

        _hook_first_write(monkeypatch, disk_full)
        with pytest.raises(OSError):
            SecretStore(tmp_path)
        monkeypatch.undo()

        store = SecretStore(tmp_path)
        assert store.get(store.put("value", "ref-a")) == "value"

    def test_a_key_published_by_someone_else_is_validated(self, tmp_path: Path, monkeypatch):
        real_generate = Fernet.generate_key

        def generate_after_a_rival_left_an_empty_key(cls):
            (tmp_path / "master.key").write_bytes(b"")
            return real_generate()

        monkeypatch.setattr(Fernet, "generate_key", classmethod(generate_after_a_rival_left_an_empty_key))

        with pytest.raises(SecretStoreError, match="master key is invalid"):
            SecretStore(tmp_path)

    def test_the_new_key_reaches_the_disk_before_it_is_used(self, tmp_path: Path, monkeypatch):
        synced = set()
        real_fsync = os.fsync

        def fsync(fd):
            synced.add(os.fstat(fd).st_ino)
            real_fsync(fd)

        monkeypatch.setattr(os, "fsync", fsync)
        SecretStore(tmp_path / "data")

        assert (tmp_path / "data" / "master.key").stat().st_ino in synced
        assert (tmp_path / "data").stat().st_ino in synced


class TestReadsDoNotDiscardWrites:
    """A read must never drop a write another thread has staged but not yet flushed."""

    def _read_during_write(self, store, read):
        original = store._save_values

        def save_after_reading():
            read()
            original()

        store._save_values = save_after_reading

    def test_get_during_put_does_not_lose_the_new_secret(self, tmp_path: Path):
        store = SecretStore(tmp_path)
        store.put("first", "ref-a")
        self._read_during_write(store, lambda: store.get("ref-a"))

        store.put("second", "ref-b")

        assert store.get("ref-b") == "second"

    def test_has_during_put_does_not_lose_the_new_secret(self, tmp_path: Path):
        store = SecretStore(tmp_path)
        store.put("first", "ref-a")
        self._read_during_write(store, lambda: store.has("ref-a"))

        store.put("second", "ref-b")

        assert store.get("ref-b") == "second"

    def test_references_during_put_does_not_lose_the_new_secret(self, tmp_path: Path):
        store = SecretStore(tmp_path)
        store.put("first", "ref-a")
        self._read_during_write(store, lambda: store.references())

        store.put("second", "ref-b")

        assert store.get("ref-b") == "second"

    def test_rotation_keeps_the_config_reference_valid(self, tmp_path: Path):
        from cudy_manager.manager import DeviceManager

        store = SecretStore(tmp_path)
        manager = DeviceManager(
            config_path=tmp_path / "c.yaml",
            data_dir=tmp_path,
            secret_store=store,
        )
        manager.add_device("r1", "192.168.1.1", "cudy", password="old")
        self._read_during_write(store, lambda: store.has(manager.get_device("r1").password_ref))

        manager.set_password("r1", "rotated", verify=False)

        reopened = DeviceManager(config_path=tmp_path / "c.yaml", data_dir=tmp_path, secret_store=SecretStore(tmp_path))
        assert reopened.credentials(reopened.get_device("r1")) == "rotated"
