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


class TestWrongJsonTypes:
    """The web routes turn only ValidationError into a 400; anything else was a 500."""

    @pytest.mark.parametrize("metadata", ["abc", 5, ["uci_section"], True])
    def test_non_object_metadata_is_a_validation_error(self, metadata):
        with pytest.raises(ValidationError, match="metadata"):
            make_device(metadata=metadata)

    @pytest.mark.parametrize("rpc_path", [5, ["/ubus"], {"path": "/ubus"}])
    def test_non_string_rpc_path_is_a_validation_error(self, rpc_path):
        with pytest.raises(ValidationError, match="rpc_path"):
            make_device(rpc_path=rpc_path)

    def test_rpc_path_checked_on_a_directly_built_device(self):
        device = Device(identifier="r1", vendor="cudy", host="192.168.1.1", rpc_path=5)  # type: ignore[arg-type]
        with pytest.raises(ValidationError, match="rpc_path"):
            device.validate()

    @pytest.mark.parametrize("field", ["username", "model", "password_ref", "transport"])
    @pytest.mark.parametrize("value", [["admin"], {"name": "admin"}, True])
    def test_non_scalar_text_field_is_a_validation_error(self, field, value):
        with pytest.raises(ValidationError, match=field):
            make_device(**{field: value})

    def test_non_string_reboot_timezone_is_a_validation_error(self):
        with pytest.raises(ValidationError, match="timezone"):
            RebootPolicy.from_dict({"timezone": ["UTC"]})


class TestNullMeansUnset:
    """JSON null, or a YAML key with no value, used to be stored as the word "None"."""

    def test_null_text_fields_take_their_defaults(self):
        device = make_device(
            username=None, model=None, password_ref=None, snmp_community_ref=None, last_seen=None
        )
        assert device.username == "root"
        assert device.model == ""
        assert device.password_ref == ""
        assert device.snmp_community_ref == ""
        assert device.last_seen == ""

    def test_null_username_takes_the_vendor_default(self):
        assert make_device(vendor="tplink", username=None).username == "admin"

    def test_null_host_is_rejected_not_stored(self):
        with pytest.raises(ValidationError, match="host"):
            make_device(host=None)

    def test_null_structured_fields_take_their_defaults(self):
        device = make_device(metadata=None, rpc_path=None, transport=None)
        assert device.metadata == {}
        assert device.rpc_path == "/ubus"
        assert device.transport == "web"

    def test_null_reboot_fields_take_their_defaults(self):
        policy = RebootPolicy.from_dict({"at": None, "timezone": None})
        assert policy.at == "04:00"
        assert policy.timezone == "UTC"


class TestHostWithPort:
    """A port typed into the host was bracketed as IPv6 and crashed every status check."""

    @pytest.mark.parametrize("host", ["192.168.0.1:8080", "router.lan:80", "[fd00::1]:8080", "[router]"])
    def test_host_with_port_is_rejected(self, host):
        with pytest.raises(ValidationError, match="http_port"):
            make_device(host=host)

    @pytest.mark.parametrize("host", ["fd00::1", "[fd00::1]", "fe80::1%eth0", "::ffff:192.168.0.1"])
    def test_ipv6_addresses_are_still_accepted(self, host):
        assert make_device(host=host).host == host

    def test_plain_hosts_are_still_accepted(self):
        assert make_device(host="192.168.0.1").host == "192.168.0.1"
        assert make_device(host="router.lan").host == "router.lan"


class TestBooleanFields:
    @pytest.mark.parametrize("value", ["enable", "ture", "maybe", "Yess", ["false"]])
    def test_unrecognised_verify_tls_is_rejected_rather_than_turning_tls_off(self, value):
        with pytest.raises(ValidationError, match="verify_tls"):
            make_device(verify_tls=value)

    def test_unrecognised_value_rejected_on_a_directly_built_device(self):
        device = Device(identifier="r1", vendor="cudy", host="192.168.1.1", verify_tls="enable")  # type: ignore[arg-type]
        with pytest.raises(ValidationError, match="verify_tls"):
            device.validate()

    @pytest.mark.parametrize("value", ["0", "false", "No", "off", "disabled", "n", False, 0])
    def test_explicit_false_values(self, value):
        assert make_device(verify_tls=value).verify_tls is False

    @pytest.mark.parametrize("value", ["1", "TRUE", "yes", "on", "enabled", "Y", True, 1])
    def test_explicit_true_values(self, value):
        assert make_device(https=value).https is True

    def test_missing_or_empty_takes_the_secure_default(self):
        assert make_device(verify_tls=None).verify_tls is True
        assert make_device(verify_tls="").verify_tls is True
        assert make_device(allow_legacy_login="").allow_legacy_login is False

    def test_unrecognised_reboot_enabled_is_rejected(self):
        with pytest.raises(ValidationError, match="reboot.enabled"):
            RebootPolicy.from_dict({"enabled": "sometimes"})
