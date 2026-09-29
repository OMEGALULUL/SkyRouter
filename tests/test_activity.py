import csv
import fcntl
import io
import json
import os
import stat
import subprocess
import sys
import threading
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from cudy_manager.activity import (
    CSV_COLUMNS,
    KINDS,
    RESULTS,
    ActivityError,
    ActivityLog,
    normalise_actor,
)
from cudy_manager.models import ValidationError


def entry(**overrides):
    values = {"who": "alice", "router": "r1", "kind": "reboot", "what": "Reboot started", "result": "applied"}
    return {**values, **overrides}


class Clock:
    """A clock the test moves by hand, one second per reading."""

    def __init__(self, start: datetime | None = None):
        self.now = start or datetime(2026, 9, 28, 8, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        self.now += timedelta(seconds=1)
        return self.now


def lines(log: ActivityLog) -> list[dict]:
    return [json.loads(line) for line in log.path.read_text().splitlines() if line]


class TestRecord:
    def test_an_entry_holds_every_field_and_is_returned_as_stored(self, tmp_path: Path):
        log = ActivityLog(tmp_path / "data", clock=Clock())
        stored = log.record(
            **entry(router_name="Shop", details={"bands": ["2.4G"], "old": {"2.4G": "Home"}, "count": 2})
        )
        assert set(stored) == {"id", "at", "who", "router", "router_name", "kind", "what", "result", "details"}
        assert stored["at"] == "2026-09-28T08:00:01+00:00"
        assert stored["router_name"] == "Shop"
        assert stored["details"] == {"bands": ["2.4G"], "old": {"2.4G": "Home"}, "count": 2}
        assert lines(log) == [stored]
        assert log.list() == [stored]

    def test_the_log_and_its_directory_are_private(self, tmp_path: Path):
        log = ActivityLog(tmp_path / "data")
        log.record(**entry())
        assert stat.S_IMODE(os.stat(tmp_path / "data").st_mode) == 0o700
        assert stat.S_IMODE(os.stat(log.path).st_mode) == 0o600

    def test_an_existing_log_readable_by_others_is_made_private(self, tmp_path: Path):
        log = ActivityLog(tmp_path)
        log.path.write_text("")
        os.chmod(log.path, 0o644)
        log.record(**entry())
        assert stat.S_IMODE(os.stat(log.path).st_mode) == 0o600

    def test_times_are_stored_in_utc(self, tmp_path: Path):
        lisbon_summer = timezone(timedelta(hours=1))
        log = ActivityLog(tmp_path, clock=lambda: datetime(2026, 9, 28, 9, 30, tzinfo=lisbon_summer))
        assert log.record(**entry())["at"] == "2026-09-28T08:30:00+00:00"
        naive = ActivityLog(tmp_path / "naive", clock=lambda: datetime(2026, 9, 28, 9, 30))
        assert naive.record(**entry())["at"] == "2026-09-28T09:30:00+00:00"

    def test_ids_are_unique(self, tmp_path: Path):
        log = ActivityLog(tmp_path)
        ids = {log.record(**entry())["id"] for _ in range(50)}
        assert len(ids) == 50

    @pytest.mark.parametrize(
        "overrides",
        [
            {"kind": "hacking"},
            {"kind": "Wifi"},
            {"result": "done"},
            {"who": ""},
            {"who": "   "},
            {"who": None},
            {"router": ""},
            {"what": ""},
            {"what": 7},
            {"router_name": None},
        ],
    )
    def test_an_invalid_entry_is_refused_and_nothing_is_written(self, tmp_path: Path, overrides):
        log = ActivityLog(tmp_path / "data")
        with pytest.raises(ActivityError):
            log.record(**entry(**overrides))
        assert not log.path.exists()

    def test_every_kind_and_result_the_spec_names_is_accepted(self, tmp_path: Path):
        assert {"wifi", "reboot", "firmware", "setup", "credentials", "maintenance", "access"} == KINDS
        assert {"applied", "queued", "refused", "failed", "info"} == RESULTS
        log = ActivityLog(tmp_path)
        for kind in KINDS:
            for result in RESULTS:
                log.record(**entry(kind=kind, result=result))
        assert len(log.list(limit=1000)) == len(KINDS) * len(RESULTS)

    def test_an_activity_error_is_a_validation_error(self):
        """The dashboard already answers ValidationError with a 400."""
        assert issubclass(ActivityError, ValidationError)


class TestSecretsAreRefused:
    @pytest.mark.parametrize(
        "details",
        [
            {"password": "hunter2hunter2"},
            {"new_passphrase": "hunter2hunter2"},
            {"wifi_key": "hunter2hunter2"},
            {"KEY": "hunter2hunter2"},
            {"Secret": "hunter2hunter2"},
            {"api_token": "hunter2hunter2"},
            {"PSK": "hunter2hunter2"},
            {"wpa_psk": "hunter2hunter2"},
            {"band": {"preSharedKey": "hunter2hunter2"}},
            {"networks": [{"ssid": "Home", "passphrase": "hunter2hunter2"}]},
        ],
    )
    def test_a_detail_key_that_names_a_secret_is_refused(self, tmp_path: Path, details):
        log = ActivityLog(tmp_path / "data")
        with pytest.raises(ActivityError, match="looks like a secret") as caught:
            log.record(**entry(details=details))
        assert "hunter2hunter2" not in str(caught.value), "the refusal quoted the secret it refused"
        assert not log.path.exists()

    def test_ordinary_detail_keys_are_kept(self, tmp_path: Path):
        log = ActivityLog(tmp_path)
        details = {"bands": ["5G"], "ssid": "Home", "old": {"5G": "Guest"}, "verification": "ok", "version": "2.5.25"}
        assert log.record(**entry(details=details))["details"] == details

    @pytest.mark.parametrize(
        "details",
        [
            {"x": object()},
            {"x": {1, 2}},
            {"x": b"bytes"},
            {"x": float("nan")},
            {"x": float("inf")},
            {3: "not a string key"},
            {"": "empty key"},
            {"k" * 65: "long key"},
            {"x": list(range(21))},
            {"a": {"b": {"c": {"d": 1}}}},
            {"x": "y" * 199, **{f"f{i}": "y" * 199 for i in range(19)}},
            "not a mapping",
        ],
    )
    def test_details_must_be_small_plain_data(self, tmp_path: Path, details):
        log = ActivityLog(tmp_path / "data")
        with pytest.raises(ActivityError):
            log.record(**entry(details=details))
        assert not log.path.exists()


class TestText:
    def test_long_text_is_truncated(self, tmp_path: Path):
        log = ActivityLog(tmp_path)
        stored = log.record(
            **entry(who="w" * 150, router="r" * 150, router_name="n" * 150, what="x" * 900, details={"s": "d" * 300})
        )
        assert stored["who"] == "w" * 99 + "\u2026"
        assert stored["router"] == "r" * 99 + "\u2026"
        assert stored["router_name"] == "n" * 99 + "\u2026"
        assert stored["what"] == "x" * 499 + "\u2026"
        assert stored["details"]["s"] == "d" * 199 + "\u2026"

    def test_line_breaks_and_direction_overrides_cannot_forge_entries(self, tmp_path: Path):
        log = ActivityLog(tmp_path)
        stored = log.record(**entry(what="Reboot started\nfake entry\u2028more\u202eevil\x00", who="bob\r\n"))
        assert stored["what"] == "Reboot started fake entry more evil"
        assert stored["who"] == "bob"

    def test_a_line_separator_inside_an_entry_does_not_split_it(self, tmp_path: Path):
        """str.splitlines breaks at U+2028, which JSON leaves unescaped with ensure_ascii off."""
        log = ActivityLog(tmp_path)
        raw = {**entry(), "id": "a" * 32, "at": "2026-01-01T00:00:00+00:00", "details": {"ssid": "a\u2028b"}}
        log.path.write_text(json.dumps(raw, ensure_ascii=False) + "\n", encoding="utf-8")
        assert "\u2028".encode() in log.path.read_bytes()
        (only,) = log.list()
        assert only["details"] == {"ssid": "a\u2028b"}

    def test_non_ascii_is_stored_readably(self, tmp_path: Path):
        log = ActivityLog(tmp_path)
        log.record(**entry(what='Wi-Fi name changed to "Caf\u00e9 \U0001f4f6"'))
        assert "Caf\u00e9 \U0001f4f6" in log.path.read_text(encoding="utf-8")

    def test_the_actor_is_normalised_like_the_entry(self):
        assert normalise_actor("  alice ") == "alice"
        for bad in ("", "  ", None, 5, ["alice"]):
            with pytest.raises(ActivityError):
                normalise_actor(bad)


class TestList:
    def fill(self, tmp_path: Path) -> tuple[ActivityLog, list[dict]]:
        log = ActivityLog(tmp_path, clock=Clock())
        made = [
            log.record(**entry(who="alice", router="r1", kind="reboot")),
            log.record(**entry(who="bob", router="r2", kind="wifi", what="Wi-Fi name changed")),
            log.record(**entry(who="alice", router="r2", kind="setup", what="Added router")),
            log.record(**entry(who="system", router="r1", kind="reboot")),
            log.record(**entry(who="bob", router="acs:00259E-X-1", kind="firmware", result="queued")),
        ]
        return log, made

    def test_newest_first(self, tmp_path: Path):
        log, made = self.fill(tmp_path)
        assert log.list() == made[::-1]

    def test_filters(self, tmp_path: Path):
        log, made = self.fill(tmp_path)
        assert log.list(router="r1") == [made[3], made[0]]
        assert log.list(who="alice") == [made[2], made[0]]
        assert log.list(kind="reboot") == [made[3], made[0]]
        assert log.list(router="r2", who="alice") == [made[2]]
        assert log.list(router="acs:00259E-X-1") == [made[4]]
        assert log.list(router="nobody") == []

    def test_limit(self, tmp_path: Path):
        log, made = self.fill(tmp_path)
        assert log.list(limit=2) == [made[4], made[3]]
        for bad in (0, -1, 1001, True, 2.0, "2"):
            with pytest.raises(ActivityError):
                log.list(limit=bad)

    def test_an_unknown_kind_filter_is_an_error_not_an_empty_page(self, tmp_path: Path):
        log, _ = self.fill(tmp_path)
        with pytest.raises(ActivityError):
            log.list(kind="reboots")

    def test_before_an_id_pages_through_the_log(self, tmp_path: Path):
        log, made = self.fill(tmp_path)
        first = log.list(limit=2)
        second = log.list(limit=2, before=first[-1]["id"])
        third = log.list(limit=2, before=second[-1]["id"])
        assert first + second + third == made[::-1]
        assert log.list(before=made[0]["id"]) == []

    def test_before_an_id_keeps_the_other_filters(self, tmp_path: Path):
        log, made = self.fill(tmp_path)
        assert log.list(router="r1", before=made[3]["id"]) == [made[0]]

    def test_an_id_no_longer_in_the_log_gives_nothing(self, tmp_path: Path):
        log, _ = self.fill(tmp_path)
        assert log.list(before="0" * 32) == []

    def test_before_a_time(self, tmp_path: Path):
        log, made = self.fill(tmp_path)
        assert log.list(before=made[2]["at"]) == [made[1], made[0]]
        assert log.list(before="2026-09-28T08:00:03") == [made[1], made[0]], "a naive time is UTC"
        assert log.list(before="2026-09-28T10:00:03+02:00") == [made[1], made[0]]

    @pytest.mark.parametrize("before", ["yesterday", "", "g" * 32, 12])
    def test_an_unreadable_before_is_an_error(self, tmp_path: Path, before):
        log, _ = self.fill(tmp_path)
        with pytest.raises(ActivityError):
            log.list(before=before)

    def test_a_missing_log_is_empty_and_nothing_is_created(self, tmp_path: Path):
        log = ActivityLog(tmp_path / "nowhere")
        assert log.list() == []
        assert log.export_csv() == ",".join(CSV_COLUMNS) + "\r\n"
        assert not (tmp_path / "nowhere").exists()

    def test_the_returned_entries_are_copies(self, tmp_path: Path):
        log, _ = self.fill(tmp_path)
        log.list()[0]["details"]["x"] = 1
        assert log.list()[0]["details"] == {}


class TestDamage:
    def test_a_torn_last_line_is_skipped_and_the_next_entry_lands_on_its_own_line(self, tmp_path: Path):
        log = ActivityLog(tmp_path)
        first = log.record(**entry(what="first"))
        with open(log.path, "ab") as handle:
            handle.write(b'{"id": "torn", "at": "2026-')
        second = log.record(**entry(what="second"))
        assert log.list() == [second, first]
        assert log.path.read_bytes().count(b"\n") == 3

    def test_lines_that_are_not_entries_are_skipped(self, tmp_path: Path):
        log = ActivityLog(tmp_path)
        log.path.write_text('[1, 2]\n{"id": 5}\nnot json\n\n{"id": "x", "at": "t"}\n')
        kept = log.record(**entry())
        assert log.list() == [kept]

    def test_missing_optional_fields_are_filled_in(self, tmp_path: Path):
        log = ActivityLog(tmp_path)
        raw = {"id": "a" * 32, "at": "2026-01-01T00:00:00+00:00", "who": "w", "router": "r"}
        log.path.write_text(json.dumps({**raw, "kind": "reboot", "what": "x", "result": "applied"}) + "\n")
        (only,) = log.list()
        assert (only["router_name"], only["details"]) == ("", {})


class TestRotation:
    def test_the_log_rotates_and_keeps_three_old_files(self, tmp_path: Path):
        log = ActivityLog(tmp_path, max_bytes=600)
        made = [log.record(**entry(what=f"entry {index:03d} " + "x" * 30)) for index in range(40)]
        assert log.path.stat().st_size <= 600
        rotated = sorted(path.name for path in tmp_path.glob("activity.jsonl.*"))
        assert rotated == ["activity.jsonl.1", "activity.jsonl.2", "activity.jsonl.3"]
        for path in tmp_path.glob("activity.jsonl*"):
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
            assert path.stat().st_size <= 600
        kept = log.list(limit=1000)
        # Newest first across every file, with the oldest entries dropped whole.
        assert kept == made[-len(kept) :][::-1]
        assert 4 <= len(kept) < 40

    def test_the_default_bound_is_five_megabytes(self, tmp_path: Path):
        assert ActivityLog(tmp_path).max_bytes == 5 * 1024 * 1024
        assert ActivityLog(tmp_path).keep == 3

    def test_an_entry_larger_than_the_bound_is_still_written(self, tmp_path: Path):
        log = ActivityLog(tmp_path, max_bytes=100)
        log.record(**entry(what="x" * 400))
        log.record(**entry(what="y" * 400))
        assert [item["what"][0] for item in log.list()] == ["y", "x"]

    @pytest.mark.parametrize("settings", [{"max_bytes": 0}, {"keep": 0}])
    def test_the_bound_must_be_positive(self, tmp_path: Path, settings):
        with pytest.raises(ValueError):
            ActivityLog(tmp_path, **settings)


class TestConcurrentWriters:
    def test_threads_with_their_own_logs_never_interleave_lines(self, tmp_path: Path):
        """Each thread opens its own ActivityLog, as the CLI and the server do."""
        errors: list[BaseException] = []

        def write(worker: int) -> None:
            try:
                log = ActivityLog(tmp_path, max_bytes=20_000)
                for index in range(40):
                    log.record(**entry(who=f"w{worker}", what=f"{worker}-{index} " + "z" * 100))
            except BaseException as exc:  # noqa: BLE001 - surfaced by the assert below
                errors.append(exc)

        threads = [threading.Thread(target=write, args=(worker,)) for worker in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert errors == []
        seen = []
        for path in [tmp_path / "activity.jsonl", *tmp_path.glob("activity.jsonl.*")]:
            for line in path.read_text().splitlines():
                seen.append(json.loads(line)["what"].split()[0])
        # Rotation may have dropped the oldest file, but every surviving line is whole.
        assert len(seen) == len(set(seen))
        assert len(seen) >= 100

    def test_another_process_waits_for_the_lock(self, tmp_path: Path):
        """The CLI and the dashboard are separate processes writing the same log."""
        log = ActivityLog(tmp_path)
        log.record(**entry(what="parent first"))
        before = log.path.read_bytes()
        script = (
            "import sys\n"
            "from cudy_manager.activity import ActivityLog\n"
            "print('ready', flush=True)\n"
            "ActivityLog(sys.argv[1]).record(who='cli', router='r1', kind='reboot', what='child', result='applied')\n"
        )
        handle = os.open(log.lock_path, os.O_RDWR)
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            child = subprocess.Popen(
                [sys.executable, "-c", script, str(tmp_path)],
                cwd=Path(__file__).resolve().parents[1],
                stdout=subprocess.PIPE,
                text=True,
            )
            assert child.stdout is not None
            assert child.stdout.readline().strip() == "ready"
            # Long enough for an unlocked append to land. Read raw: list() would
            # wait for the lock this test is holding.
            threading.Event().wait(0.5)
            assert child.poll() is None
            assert log.path.read_bytes() == before
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)
            os.close(handle)
        assert child.wait(timeout=20) == 0
        assert [item["what"] for item in log.list()] == ["child", "parent first"]


class TestCsv:
    def rows(self, text: str) -> list[list[str]]:
        return list(csv.reader(io.StringIO(text)))

    def test_columns_and_quoting_survive_a_round_trip(self, tmp_path: Path):
        log = ActivityLog(tmp_path, clock=Clock())
        made = log.record(
            **entry(
                router_name='Shop, "front"',
                what='Wi-Fi name changed: 2.4G "Old" \u2192 "New, improved"',
                details={"bands": ["2.4G"], "ssid": "New, improved"},
            )
        )
        header, row = self.rows(log.export_csv())
        assert tuple(header) == CSV_COLUMNS
        record = dict(zip(header, row, strict=True))
        assert record["router_name"] == 'Shop, "front"'
        assert record["what"] == made["what"]
        assert json.loads(record["details"]) == made["details"]
        assert record["id"] == made["id"]
        assert record["at"] == made["at"]

    @pytest.mark.parametrize("start", ["=", "+", "-", "@"])
    def test_cells_that_a_spreadsheet_would_run_as_a_formula_are_defused(self, tmp_path: Path, start: str):
        log = ActivityLog(tmp_path)
        payload = f'{start}HYPERLINK("http://evil.example/","x")'
        log.record(**entry(who=payload, router=payload, router_name=payload, what=payload))
        _, row = self.rows(log.export_csv())
        record = dict(zip(CSV_COLUMNS, row, strict=True))
        for column in ("who", "router", "router_name", "what"):
            assert record[column] == "'" + payload, column

    @pytest.mark.parametrize("start", ["\t", "\r"])
    def test_a_tab_or_return_at_the_start_of_a_stored_cell_is_defused_too(self, tmp_path: Path, start: str):
        """record() strips them, but an entry written by anything else is exported as found."""
        log = ActivityLog(tmp_path)
        raw = {**entry(what=f"{start}=1+1"), "id": "a" * 32, "at": "2026-01-01T00:00:00+00:00"}
        log.path.write_text(json.dumps(raw) + "\n")
        _, row = self.rows(log.export_csv())
        assert dict(zip(CSV_COLUMNS, row, strict=True))["what"] == f"'{start}=1+1"

    def test_ordinary_cells_are_left_alone(self, tmp_path: Path):
        log = ActivityLog(tmp_path)
        log.record(**entry(what="Reboot started - by the scheduler"))
        _, row = self.rows(log.export_csv())
        assert dict(zip(CSV_COLUMNS, row, strict=True))["what"] == "Reboot started - by the scheduler"

    def test_filters_and_the_whole_log_by_default(self, tmp_path: Path):
        log = ActivityLog(tmp_path, clock=Clock())
        for index in range(250):
            log.record(**entry(router="r1" if index % 2 else "r2", what=f"entry {index}"))
        assert len(self.rows(log.export_csv())) == 251, "export is not capped at the page size"
        only_r1 = self.rows(log.export_csv(router="r1", limit=3))
        assert [row[CSV_COLUMNS.index("what")] for row in only_r1[1:]] == ["entry 249", "entry 247", "entry 245"]
        with pytest.raises(ActivityError):
            log.export_csv(limit=0)
        with pytest.raises(ActivityError):
            log.export_csv(kind="nope")

    def test_empty_details_export_as_an_empty_cell(self, tmp_path: Path):
        log = ActivityLog(tmp_path)
        log.record(**entry())
        _, row = self.rows(log.export_csv())
        assert dict(zip(CSV_COLUMNS, row, strict=True))["details"] == ""
