import stat
from pathlib import Path

import pytest

from cudy_manager.models import Device, RebootPolicy, ValidationError
from cudy_manager.secrets import SecretStore, SecretStoreError


def make_device(**overrides) -> Device:
    data = {"vendor": "cudy", "host": "192.168.1.1", "username": "root"}
    data.update(overrides)
    return Device.from_dict("test-device", data)


class TestSecretStore:
    def test_round_trip_and_at_rest_encryption(self, tmp_path: Path):
        store = SecretStore(tmp_path / "data")
        reference = store.put("super-secret-password", "device-test-password")
        assert store.get(reference) == "super-secret-password"
        vault = (tmp_path / "data" / "secrets.json").read_text()
        assert "super-secret-password" not in vault
        assert reference in vault

    def test_key_and_vault_permissions(self, tmp_path: Path):
        store = SecretStore(tmp_path / "data")
        store.put("value", "name")
        directory = tmp_path / "data"
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
        assert stat.S_IMODE((directory / "master.key").stat().st_mode) == 0o600
        assert stat.S_IMODE((directory / "secrets.json").stat().st_mode) == 0o600

    def test_reload_with_same_key(self, tmp_path: Path):
        store = SecretStore(tmp_path / "data")
        reference = store.put("persist-me", "name")
        assert SecretStore(tmp_path / "data").get(reference) == "persist-me"

    def test_rejects_empty_and_unknown(self, tmp_path: Path):
        store = SecretStore(tmp_path / "data")
        with pytest.raises(SecretStoreError):
            store.put("", "name")
        with pytest.raises(SecretStoreError):
            store.get("missing-reference")

    def test_rejects_bad_reference_characters(self, tmp_path: Path):
        store = SecretStore(tmp_path / "data")
        with pytest.raises(SecretStoreError):
            store.put("value", "../escape")

    def test_delete(self, tmp_path: Path):
        store = SecretStore(tmp_path / "data")
        reference = store.put("value", "name")
        assert store.has(reference)
        assert store.delete(reference)
        assert not store.has(reference)
        assert not store.delete(reference)

    def test_tampered_key_fails_closed(self, tmp_path: Path):
        store = SecretStore(tmp_path / "data")
        store.put("value", "name")
        key = tmp_path / "data" / "master.key"
        key.write_bytes(b"not-a-fernet-key")
        with pytest.raises(SecretStoreError):
            SecretStore(tmp_path / "data")


class TestDeviceModel:
    def test_rejects_plaintext_credential_fields(self):
        for field in ("password", "ssh_password", "luci_password", "snmp_community"):
            with pytest.raises(ValidationError):
                make_device(**{field: "admin"})

    def test_rejects_url_in_host(self):
        with pytest.raises(ValidationError):
            make_device(host="http://192.168.1.1")

    def test_rejects_unknown_vendor_and_transport(self):
        with pytest.raises(ValidationError):
            make_device(vendor="ubiquiti")
        with pytest.raises(ValidationError):
            make_device(transport="telnet")

    def test_rejects_out_of_range_ports(self):
        with pytest.raises(ValidationError):
            make_device(http_port=70000)
        with pytest.raises(ValidationError):
            make_device(ssh_port=0)

    def test_rejects_bad_identifier(self):
        with pytest.raises(ValidationError):
            Device.from_dict("bad id/../etc", {"vendor": "cudy", "host": "192.168.1.1"})

    def test_rejects_non_absolute_rpc_path(self):
        with pytest.raises(ValidationError):
            make_device(rpc_path="ubus")

    def test_public_view_has_no_secrets(self):
        device = make_device(password_ref="device-test-password")
        rendered = str(device.to_public())
        assert "password_ref" not in rendered
        assert "snmp_community_ref" not in rendered

    def test_config_round_trip(self):
        device = make_device(
            password_ref="device-test-password",
            reboot={"enabled": True, "at": "04:30", "timezone": "Europe/Lisbon"},
        )
        again = Device.from_dict("test-device", device.to_config())
        assert again.password_ref == "device-test-password"
        assert again.reboot.at == "04:30"
        assert again.reboot.timezone == "Europe/Lisbon"

    def test_reboot_policy_validation(self):
        with pytest.raises(ValidationError):
            RebootPolicy.from_dict({"at": "25:00"})
        with pytest.raises(ValidationError):
            RebootPolicy.from_dict({"at": "04:60"})
        with pytest.raises(ValidationError):
            RebootPolicy.from_dict({"window_minutes": 0})
        with pytest.raises(ValidationError):
            RebootPolicy.from_dict({"timezone": "not a zone!"})

    def test_legacy_login_disabled_by_default(self):
        assert make_device().allow_legacy_login is False

    def test_unknown_host_key_rejected_by_default(self):
        assert make_device().accept_unknown_host_key is False
