from pathlib import Path

from cudy_manager.secrets import SecretStore


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
