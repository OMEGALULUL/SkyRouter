import json
import logging
from pathlib import Path

import pytest

from cudy_manager.acs import bootstrap
from cudy_manager.acs.bootstrap import (
    BootstrapRefused,
    desired_objects,
    drift,
    install,
    validate_inform_interval,
    validate_preset,
)
from cudy_manager.acs.client import AcsError, Page
from cudy_manager.models import ValidationError

PROVISIONS_DIR = Path(bootstrap.__file__).parent / "provisions"
VERSION = "1.2.16+20260329"


class MemoryAcs:
    """Stands in for AcsClient: the calls bootstrap makes, over in-memory collections.

    Presets are kept as the JSON text they were sent as, so a caller can never
    change what is "stored" by mutating an object after handing it over.
    """

    def __init__(self, version=VERSION, presets=None, provisions=None):
        self._version = version
        self.presets = {name: json.dumps(preset) for name, preset in (presets or {}).items()}
        self.provisions = dict(provisions or {})
        self.calls = []

    def writes(self):
        return [call for call in self.calls if call[0] in ("put_provision", "put_preset", "delete_preset")]

    def version(self):
        self.calls.append(("version",))
        return self._version

    def find(self, collection, query, projection=None, sort=None, skip=0, limit=50):
        self.calls.append(("find", collection))
        assert collection == "presets" and query == {} and projection is None
        assert 1 <= limit <= 200
        items = [{"_id": name, **json.loads(text)} for name, text in sorted(self.presets.items())]
        return Page(items=items[skip : skip + limit], total=len(items))

    def get_provision(self, name):
        self.calls.append(("get_provision", name))
        return self.provisions.get(name)

    def put_provision(self, name, script):
        self.calls.append(("put_provision", name))
        self.provisions[name] = script

    def get_preset(self, name):
        self.calls.append(("get_preset", name))
        text = self.presets.get(name)
        return None if text is None else json.loads(text)

    def put_preset(self, name, preset):
        self.calls.append(("put_preset", name))
        self.presets[name] = json.dumps(preset)

    def delete_preset(self, name):
        self.calls.append(("delete_preset", name))
        self.presets.pop(name, None)


def seeded_preset(name):
    # Roughly what the UI's wizard stores; its content does not matter here.
    return {"weight": 0, "channel": name, "events": {}, "precondition": "", "configurations": []}


@pytest.fixture
def presets():
    return desired_objects(300)[1]


def valid(**changes):
    preset = {
        "weight": 5,
        "channel": "skybre-x",
        "events": {"1 BOOT": True},
        "precondition": "",
        "configurations": [{"type": "provision", "name": "skybre-refresh", "args": ["a", 3, True]}],
    }
    preset.update(changes)
    return preset


# --- validate_preset ------------------------------------------------------------------


class TestValidatePreset:
    def test_accepts_every_shipped_preset(self, presets):
        for name, preset in presets.items():
            validate_preset(name, preset)

    def test_accepts_a_minimal_valid_preset(self):
        validate_preset("skybre-x", valid())
        validate_preset("skybre-x", valid(configurations=[{"type": "delete_tag", "tag": "skybre_new"}]))
        validate_preset("skybre-x", valid(precondition="Tags.skybre_new IS NOT NULL", events={}))

    def test_errors_are_value_errors(self):
        # The public contract is ValueError; ValidationError is what web.py maps to 400.
        with pytest.raises(ValueError, match="configurations"):
            validate_preset("skybre-x", valid(configurations=[]))
        assert issubclass(ValidationError, ValueError)

    @pytest.mark.parametrize("missing", ["configurations", "weight", "channel", "events", "precondition"])
    def test_rejects_a_missing_field(self, missing):
        preset = valid()
        del preset[missing]
        with pytest.raises(ValidationError, match=f"missing {missing}"):
            validate_preset("skybre-x", preset)

    @pytest.mark.parametrize("extra", ["schedule", "_id", "provision", "provisionArgs"])
    def test_rejects_fields_skybre_never_writes(self, extra):
        with pytest.raises(ValidationError, match="unsupported"):
            validate_preset("skybre-x", valid(**{extra: "0 2 * * *"}))

    @pytest.mark.parametrize("configurations", [[], None, "skybre-refresh", {"type": "provision"}, [None], ["x"]])
    def test_rejects_empty_or_malformed_configurations(self, configurations):
        with pytest.raises(ValidationError):
            validate_preset("skybre-x", valid(configurations=configurations))

    def test_rejects_too_many_configurations(self):
        entry = {"type": "add_tag", "tag": "a"}
        with pytest.raises(ValidationError, match="1-8"):
            validate_preset("skybre-x", valid(configurations=[entry] * 9))

    @pytest.mark.parametrize("kind", ["value", "age", "add_object", "delete_object", "bogus", None, 1])
    def test_rejects_unknown_or_unused_configuration_types(self, kind):
        with pytest.raises(ValidationError, match="configuration type"):
            validate_preset("skybre-x", valid(configurations=[{"type": kind, "name": "x", "value": 1}]))

    @pytest.mark.parametrize("arg", [None, 1.5, 300.0, [1], {"a": 1}, 2**53, -(2**53), "x" * 257, "a\nb", "\x00"])
    def test_rejects_non_scalar_or_unsafe_args(self, arg):
        entry = {"type": "provision", "name": "skybre-inform", "args": [arg]}
        with pytest.raises(ValidationError, match="argument"):
            validate_preset("skybre-x", valid(configurations=[entry]))

    @pytest.mark.parametrize("args", [None, "300", (300,), {"0": 300}, list(range(9))])
    def test_rejects_args_that_are_not_a_short_list(self, args):
        entry = {"type": "provision", "name": "skybre-inform", "args": args}
        with pytest.raises(ValidationError, match="args"):
            validate_preset("skybre-x", valid(configurations=[entry]))

    @pytest.mark.parametrize("keys", [{"type": "provision", "name": "skybre-a"}, {"type": "add_tag"}])
    def test_rejects_configurations_missing_their_fields(self, keys):
        with pytest.raises(ValidationError, match="exactly"):
            validate_preset("skybre-x", valid(configurations=[keys]))

    def test_rejects_configurations_with_extra_fields(self):
        entry = {"type": "add_tag", "tag": "a", "name": "b"}
        with pytest.raises(ValidationError, match="exactly"):
            validate_preset("skybre-x", valid(configurations=[entry]))

    @pytest.mark.parametrize("builtin", sorted(bootstrap.BUILTIN_PROVISIONS))
    def test_rejects_built_in_names_as_preset_or_provision(self, builtin):
        # A provision named after a built-in replaces the built-in inside every NBI task.
        with pytest.raises(ValidationError, match="names must be skybre-"):
            validate_preset(builtin, valid(channel=builtin))
        entry = {"type": "provision", "name": builtin, "args": []}
        with pytest.raises(ValidationError, match="names must be skybre-"):
            validate_preset("skybre-x", valid(configurations=[entry]))

    @pytest.mark.parametrize(
        "name",
        ["inform", "skybre-", "skybre_x", "Skybre-x", "skybre-X", "skybre-a.b", "skybre-a~b", "skybre-" + "a" * 41, 7],
    )
    def test_rejects_bad_names(self, name):
        with pytest.raises(ValidationError, match="names must be skybre-"):
            validate_preset(name, valid(channel=name))

    def test_rejects_a_channel_other_than_the_name(self):
        with pytest.raises(ValidationError, match="channel"):
            validate_preset("skybre-x", valid(channel="default"))

    @pytest.mark.parametrize("weight", [True, "10", 1.0, None, 1001, -1001])
    def test_rejects_a_weight_that_is_not_a_small_int(self, weight):
        with pytest.raises(ValidationError, match="weight"):
            validate_preset("skybre-x", valid(weight=weight))

    @pytest.mark.parametrize(
        "events",
        [
            {"0 BOOTSTRAP": 1},
            {"0 BOOTSTRAP": "true"},
            {"0 BOOTSTRAP": None},
            {"0_BOOTSTRAP": True},
            {"bootstrap": True},
            {"": True},
            {"1 BOOT\n": True},
            "0 BOOTSTRAP",
            ["0 BOOTSTRAP"],
            None,
            {f"{n} BOOT": True for n in range(9)},
        ],
    )
    def test_rejects_events_that_are_not_codes_mapped_to_booleans(self, events):
        with pytest.raises(ValidationError, match="events"):
            validate_preset("skybre-x", valid(events=events))

    @pytest.mark.parametrize(
        "precondition",
        [
            "Tags.skybre-new IS NOT NULL",
            "Tags.other IS NOT NULL",
            'DeviceID.ProductClass = "X"',
            '{"_tags": "skybre_new"}',
            "true",
            None,
            " ",
            [],
            {"_tags": "skybre_new"},
        ],
    )
    def test_rejects_preconditions_outside_the_fixed_set(self, precondition):
        with pytest.raises(ValidationError, match="precondition"):
            validate_preset("skybre-x", valid(precondition=precondition))

    @pytest.mark.parametrize("tag", ["", "Skybre", "a.b", "a b", "x" * 33, 5])
    def test_rejects_bad_tags(self, tag):
        with pytest.raises(ValidationError, match="tags"):
            validate_preset("skybre-x", valid(configurations=[{"type": "add_tag", "tag": tag}]))

    @pytest.mark.parametrize("preset", [None, [], "{}", 3])
    def test_rejects_a_preset_that_is_not_an_object(self, preset):
        with pytest.raises(ValidationError, match="object"):
            validate_preset("skybre-x", preset)


# --- desired_objects ------------------------------------------------------------------


class TestDesiredObjects:
    def test_names_and_package_files(self):
        provisions, presets = desired_objects(300)
        assert list(provisions) == ["skybre-bootstrap", "skybre-inform", "skybre-refresh"]
        assert list(presets) == ["skybre-bootstrap", "skybre-registered", "skybre-inform", "skybre-refresh"]
        assert tuple(presets) == bootstrap.CHANNELS
        for name, script in provisions.items():
            assert script == (PROVISIONS_DIR / f"{name}.js").read_text(encoding="utf-8")
            assert script.strip()

    def test_presets_are_the_briefs_raw_shape(self, presets):
        assert presets["skybre-bootstrap"] == {
            "weight": 0,
            "channel": "skybre-bootstrap",
            "events": {"0 BOOTSTRAP": True},
            "precondition": "",
            "configurations": [{"type": "provision", "name": "skybre-bootstrap", "args": []}],
        }
        assert presets["skybre-registered"]["events"] == {"Registered": True}
        assert presets["skybre-registered"]["configurations"] == [{"type": "add_tag", "tag": "skybre_new"}]
        assert presets["skybre-inform"]["weight"] == 10
        assert presets["skybre-inform"]["events"] == {}
        assert presets["skybre-refresh"]["weight"] == 20
        assert presets["skybre-refresh"]["configurations"] == [
            {"type": "provision", "name": "skybre-refresh", "args": []}
        ]

    @pytest.mark.parametrize("interval", [60, 300, 3600, 86400])
    def test_the_inform_interval_is_the_inform_provisions_argument(self, interval):
        presets = desired_objects(interval)[1]
        assert presets["skybre-inform"]["configurations"] == [
            {"type": "provision", "name": "skybre-inform", "args": [interval]}
        ]

    @pytest.mark.parametrize("interval", [0, 59, 86401, -300, True, "300", 300.0, None])
    def test_rejects_an_unusable_inform_interval(self, interval):
        with pytest.raises(ValueError, match="inform interval"):
            desired_objects(interval)
        with pytest.raises(ValidationError):
            validate_inform_interval(interval)

    def test_each_call_returns_fresh_presets(self):
        first = desired_objects(300)[1]
        first["skybre-inform"]["configurations"][0]["args"][0] = 5
        first["skybre-bootstrap"]["events"]["1 BOOT"] = True
        assert desired_objects(300)[1]["skybre-inform"]["configurations"][0]["args"] == [300]
        assert desired_objects(300)[1]["skybre-bootstrap"]["events"] == {"0 BOOTSTRAP": True}

    def test_every_provision_file_is_installed(self):
        # A script added to the package but not to PROVISION_NAMES would never reach GenieACS.
        shipped = sorted(path.stem for path in PROVISIONS_DIR.glob("*.js"))
        assert shipped == sorted(bootstrap.PROVISION_NAMES)


# --- install --------------------------------------------------------------------------


class TestInstall:
    def test_fresh_install_writes_every_object_as_desired(self):
        acs = MemoryAcs()
        report = install(acs)
        provisions, presets = desired_objects(300)
        assert acs.provisions == provisions
        assert {name: json.loads(text) for name, text in acs.presets.items()} == presets
        assert report == {
            "version": VERSION,
            "removed_seeded": [],
            "provisions": dict.fromkeys(provisions, "created"),
            "presets": dict.fromkeys(presets, "created"),
            "writes": 7,
        }
        json.dumps(report)

    def test_provisions_are_written_before_presets(self):
        acs = MemoryAcs()
        install(acs)
        kinds = [call[0] for call in acs.writes()]
        assert kinds == ["put_provision"] * 3 + ["put_preset"] * 4

    def test_second_run_makes_no_writes(self):
        acs = MemoryAcs()
        install(acs)
        acs.calls.clear()
        report = install(acs)
        assert acs.writes() == []
        assert report["writes"] == 0
        assert set(report["provisions"].values()) == {"unchanged"}
        assert set(report["presets"].values()) == {"unchanged"}

    def test_every_write_is_read_back(self):
        acs = MemoryAcs()
        install(acs)
        for kind, name in [call for call in acs.calls if call[0].startswith("put_")]:
            getter = "get_provision" if kind == "put_provision" else "get_preset"
            after = acs.calls[acs.calls.index((kind, name)) + 1]
            assert after == (getter, name)

    def test_a_new_interval_rewrites_only_the_inform_preset(self):
        acs = MemoryAcs()
        install(acs, inform_interval=300)
        acs.calls.clear()
        report = install(acs, inform_interval=900)
        assert acs.writes() == [("put_preset", "skybre-inform")]
        assert report["presets"]["skybre-inform"] == "updated"
        assert json.loads(acs.presets["skybre-inform"])["configurations"][0]["args"] == [900]

    def test_a_hand_edited_provision_is_restored_alone(self):
        acs = MemoryAcs()
        install(acs)
        acs.provisions["skybre-refresh"] = "declare('Device.X', {value: 1});"
        acs.calls.clear()
        report = install(acs)
        assert acs.writes() == [("put_provision", "skybre-refresh")]
        assert report["provisions"]["skybre-refresh"] == "updated"
        assert acs.provisions["skybre-refresh"] == desired_objects(300)[0]["skybre-refresh"]

    def test_stored_values_that_only_look_equal_are_rewritten(self):
        # True == 1 in Python, but GenieACS stores and compares JSON.
        acs = MemoryAcs()
        install(acs)
        stored = json.loads(acs.presets["skybre-bootstrap"])
        stored["events"]["0 BOOTSTRAP"] = 1
        acs.presets["skybre-bootstrap"] = json.dumps(stored)
        acs.calls.clear()
        install(acs)
        assert acs.writes() == [("put_preset", "skybre-bootstrap")]

    def test_key_order_is_not_a_change(self):
        acs = MemoryAcs()
        install(acs)
        stored = json.loads(acs.presets["skybre-inform"])
        acs.presets["skybre-inform"] = json.dumps(dict(reversed(list(stored.items()))))
        acs.calls.clear()
        install(acs)
        assert acs.writes() == []

    @pytest.mark.parametrize("version", ["1.3.0-dev", "1.3.0", "2.0.0", "1.20.1", "1.1.9", ""])
    def test_refuses_anything_but_1_2(self, version):
        acs = MemoryAcs(version=version)
        with pytest.raises(BootstrapRefused, match="not a 1.2 release") as refused:
            install(acs)
        assert refused.value.version == version
        assert acs.calls == [("version",)]
        assert isinstance(refused.value, AcsError)

    @pytest.mark.parametrize("seeded", [["bootstrap", "default", "inform"], ["inform"], ["default"]])
    def test_refuses_while_ui_seeded_presets_exist(self, seeded):
        acs = MemoryAcs(presets={name: seeded_preset(name) for name in seeded})
        with pytest.raises(BootstrapRefused, match="remove_seeded") as refused:
            install(acs)
        assert refused.value.seeded == [name for name in bootstrap.SEEDED_PRESETS if name in seeded]
        assert acs.writes() == []
        assert set(acs.presets) == set(seeded)

    def test_remove_seeded_deletes_them_then_installs(self):
        acs = MemoryAcs(presets={name: seeded_preset(name) for name in bootstrap.SEEDED_PRESETS})
        report = install(acs, remove_seeded=True)
        assert report["removed_seeded"] == ["bootstrap", "default", "inform"]
        assert acs.writes()[:3] == [("delete_preset", name) for name in bootstrap.SEEDED_PRESETS]
        assert set(acs.presets) == set(desired_objects(300)[1])
        assert report["writes"] == 10

    def test_remove_seeded_with_nothing_seeded_changes_nothing_extra(self):
        acs = MemoryAcs()
        install(acs)
        acs.calls.clear()
        assert install(acs, remove_seeded=True)["writes"] == 0
        assert acs.writes() == []

    def test_other_presets_are_left_alone_and_stale_skybre_ones_removed(self):
        acs = MemoryAcs(
            presets={
                "operator-thing": seeded_preset("operator-thing"),
                "skybre-old": seeded_preset("skybre-old"),
            }
        )
        report = install(acs)
        assert "operator-thing" in acs.presets
        assert "skybre-old" not in acs.presets
        assert report["presets"]["skybre-old"] == "removed"
        assert ("delete_preset", "operator-thing") not in acs.calls

    def test_lists_presets_across_pages(self, monkeypatch):
        monkeypatch.setattr(bootstrap, "_PAGE", 2)
        extra = {f"aaa-{index}": seeded_preset(f"aaa-{index}") for index in range(5)}
        acs = MemoryAcs(presets={**extra, "inform": seeded_preset("inform")})
        # The stand-in lists by name, so "inform" is only on the last of three pages.
        with pytest.raises(BootstrapRefused):
            install(acs)
        assert [call for call in acs.calls if call[0] == "find"] == [("find", "presets")] * 3

    def test_an_invalid_desired_preset_stops_everything_before_any_request(self, monkeypatch):
        real = bootstrap.desired_objects

        def broken(interval):
            provisions, presets = real(interval)
            presets["skybre-refresh"]["configurations"][0]["type"] = "value"
            return provisions, presets

        monkeypatch.setattr(bootstrap, "desired_objects", broken)
        acs = MemoryAcs(presets={"inform": seeded_preset("inform")})
        with pytest.raises(ValidationError, match="configuration type"):
            install(acs, remove_seeded=True)
        assert acs.calls == []
        assert "inform" in acs.presets

    def test_a_preset_naming_a_provision_not_installed_is_refused(self, monkeypatch):
        real = bootstrap.desired_objects

        def typo(interval):
            provisions, presets = real(interval)
            presets["skybre-refresh"]["configurations"][0]["name"] = "skybre-refreshh"
            return provisions, presets

        monkeypatch.setattr(bootstrap, "desired_objects", typo)
        acs = MemoryAcs()
        with pytest.raises(ValidationError, match="does not install"):
            install(acs)
        assert acs.calls == []

    def test_a_preset_not_stored_as_sent_is_an_error(self):
        class Mangling(MemoryAcs):
            def put_preset(self, name, preset):
                super().put_preset(name, {**preset, "weight": preset["weight"] + 1})

        with pytest.raises(AcsError, match="did not store preset skybre-bootstrap"):
            install(Mangling())

    def test_a_provision_not_stored_as_sent_is_an_error(self):
        class Trimming(MemoryAcs):
            def put_provision(self, name, script):
                super().put_provision(name, script.strip())

        with pytest.raises(AcsError, match="did not store provision skybre-bootstrap"):
            install(Trimming())

    def test_rejects_a_bad_interval_before_any_request(self):
        acs = MemoryAcs()
        with pytest.raises(ValidationError, match="inform interval"):
            install(acs, inform_interval=10)
        assert acs.calls == []

    def test_writes_are_logged_without_content(self, caplog):
        caplog.set_level(logging.INFO, logger="cudy_manager.acs.bootstrap")
        install(MemoryAcs(presets={"inform": seeded_preset("inform")}), remove_seeded=True)
        text = caplog.text
        assert "created provision skybre-inform" in text
        assert "created preset skybre-registered" in text
        assert "removed seeded preset inform" in text
        assert "declare(" not in text


# --- drift ----------------------------------------------------------------------------


class TestDrift:
    def test_empty_acs_reports_everything_missing(self):
        report = drift(MemoryAcs())
        assert report["installed"] is False
        assert report["seeded_presets"] == []
        assert [(item["kind"], item["name"], item["state"]) for item in report["drift"]] == [
            ("provision", "skybre-bootstrap", "missing"),
            ("provision", "skybre-inform", "missing"),
            ("provision", "skybre-refresh", "missing"),
            ("preset", "skybre-bootstrap", "missing"),
            ("preset", "skybre-registered", "missing"),
            ("preset", "skybre-inform", "missing"),
            ("preset", "skybre-refresh", "missing"),
        ]

    def test_after_install_there_is_no_drift(self):
        acs = MemoryAcs()
        install(acs)
        acs.calls.clear()
        assert drift(acs) == {"installed": True, "drift": [], "seeded_presets": []}
        assert acs.writes() == []

    def test_reports_changes_extras_and_seeded_presets(self):
        acs = MemoryAcs()
        install(acs, inform_interval=300)
        acs.provisions["skybre-bootstrap"] += "\n// edited"
        acs.presets["skybre-old"] = json.dumps(seeded_preset("skybre-old"))
        acs.presets["default"] = json.dumps(seeded_preset("default"))
        acs.presets["operator-thing"] = json.dumps(seeded_preset("operator-thing"))
        acs.calls.clear()
        report = drift(acs, inform_interval=600)
        assert report["installed"] is False
        assert report["seeded_presets"] == ["default"]
        assert report["drift"] == [
            {"kind": "provision", "name": "skybre-bootstrap", "state": "changed"},
            {"kind": "preset", "name": "skybre-inform", "state": "changed"},
            {"kind": "preset", "name": "skybre-old", "state": "unexpected"},
        ]
        assert acs.writes() == []

    def test_seeded_presets_alone_do_not_count_as_drift(self):
        # They block install(), which /api/acs shows separately from SkyRouter's own objects.
        acs = MemoryAcs()
        install(acs)
        acs.presets["bootstrap"] = json.dumps(seeded_preset("bootstrap"))
        report = drift(acs)
        assert report["installed"] is True
        assert report["seeded_presets"] == ["bootstrap"]

    def test_rejects_a_bad_interval(self):
        with pytest.raises(ValidationError):
            drift(MemoryAcs(), inform_interval=True)
