"""Firmware information, automatic update and update checks over each router's own web UI.

The Cudy side runs against fake_router's "ap1300" mode, whose Auto Update page is
reconstructed from the field list of a real AP1300 (2.5.25) rather than captured;
the result page of its update check has never been seen, so the notices the tests
insert are guesses and the parser must stay non-committal about anything else.
"""

import time

import pytest
from fake_router import (
    AP1300_AUTOUPGRADE_TOKEN,
    FIXTURES,
    FakeRouter,
    FakeTpLink,
    ap1300_autoupgrade_page,
)

from cudy_manager import adapters
from cudy_manager.adapters import (
    AdapterError,
    CudyAdapter,
    ProtocolMismatch,
    RouterAdapter,
    TendaAdapter,
    TpLinkAdapter,
    UnsupportedOperation,
    _cudy_firmware_details,
    _cudy_update_result,
)
from cudy_manager.models import Device

CURRENT = "2.5.25-20260820-141832"
NEWER = "2.5.26-20261001-101010"


def cudy(router) -> CudyAdapter:
    device = Device.from_dict("c1", {"vendor": "cudy", "host": "127.0.0.1", "http_port": router.port})
    return CudyAdapter(device, "goodpass")


def fixture_page() -> str:
    return (FIXTURES / "ap1300_autoupgrade.html").read_text()


def labelled_row(label: str, value: str) -> str:
    # The same shape as the page's own read-only rows: a label, then doubled value copies.
    return (
        f'<div class="form-group"><label class="col-sm-4 control-label">{label}</label>'
        f'<div class="col-sm-5"><p class="form-control-static hidden-xs ">{value}</p>'
        f'<p class="visible-xs ">{value}</p></div></div>'
    )


def alert(text: str) -> str:
    return f'<div class="alert alert-info">{text}</div>'


class TestCudyFirmwareInfo:
    def test_version_hardware_and_auto_update_come_from_the_auto_update_page(self):
        with FakeRouter("ap1300") as router:
            assert cudy(router).firmware_info() == {
                "version": CURRENT,
                "hardware": "AP1300 V1.1",
                "auto_update": {"enabled": True, "window_start_hour": 3, "window": "03:00-05:00"},
                "source": "cudy-luci",
            }

    def test_a_window_is_still_reported_while_auto_update_is_off(self):
        """The page keeps the window (only hidden); it is the one used when turned back on."""
        with FakeRouter("ap1300") as router:
            router.state["autoupgrade"] = {"auto_upgrade": "0", "upgrade_time": "22"}
            assert cudy(router).firmware_info()["auto_update"] == {
                "enabled": False,
                "window_start_hour": 22,
                "window": "22:00-00:00",
            }

    def test_no_selected_window_is_reported_as_none_not_as_the_first_slot(self):
        with FakeRouter("ap1300") as router:
            router.state["autoupgrade"] = {"auto_upgrade": "0", "upgrade_time": None}
            auto = cudy(router).firmware_info()["auto_update"]
        assert auto == {"enabled": False, "window_start_hour": None, "window": None}

    def test_firmware_without_the_auto_update_page_falls_back_to_the_status_page(self, monkeypatch):
        with FakeRouter("ap1300") as router:
            router.state["autoupgrade_missing"] = True
            adapter = cudy(router)
            monkeypatch.setattr(adapter, "status", lambda: {"firmware": "2.5.25"})
            assert adapter.firmware_info() == {
                "version": "2.5.25",
                "hardware": "",
                "auto_update": None,
                "source": "cudy-luci",
            }

    def test_a_page_without_the_switch_reports_no_auto_update(self, monkeypatch):
        with FakeRouter("ap1300") as router:
            adapter = cudy(router)
            monkeypatch.setattr(adapter, "_autoupgrade_page", lambda: fixture_page().replace("auto_upgrade", "other"))
            info = adapter.firmware_info()
        assert info["auto_update"] is None
        assert info["version"] == CURRENT

    @pytest.mark.parametrize(
        "page,expected",
        [
            # The status page's table layout, where labels are doubled as well.
            (
                "<table><tr><td><p>Firmware Version</p><p>Firmware Version</p></td>"
                "<td><p>2.5.25 DE</p><p>2.5.25 DE</p></td></tr>"
                "<tr><td><p>Hardware</p></td><td><p>AP1300 V1.1</p></td></tr></table>",
                ("2.5.25", "AP1300 V1.1"),
            ),
            ("<p>Firmware Version: 2.3.1</p><p>Hardware: AP1300 V1.0</p>", ("2.3.1", "AP1300 V1.0")),
            # A "Firmware" menu link is not the Firmware Version label.
            ('<a href="/fw">Firmware</a> <a href="/hw">Hardware Info</a>', ("", "")),
            # An empty value: the next label is not the value.
            ("<label>Firmware Version</label><p></p><label>Hardware</label><p></p>"
             "<label>Firmware File Path</label>", ("", "")),
            # Script text is never shown, so it is never read.
            ("<script>Firmware Version: 9.9.9</script>", ("", "")),
        ],
    )
    def test_static_values_are_read_after_their_own_label(self, page, expected):
        assert _cudy_firmware_details(page) == expected


class TestCudySetAutoUpdate:
    def original_fields(self) -> dict:
        return dict(adapters._cbi_fields(fixture_page()))

    def test_turning_on_with_a_window_sends_the_whole_form_back_with_two_fields_changed(self):
        with FakeRouter("ap1300") as router:
            router.state["autoupgrade"] = {"auto_upgrade": "0", "upgrade_time": "3"}
            assert cudy(router).set_auto_update(True, 5) is True
            assert router.state["autoupgrade"] == {"auto_upgrade": "1", "upgrade_time": "5"}
            (posted,) = router.state["autoupgrade_posts"]
        sent = dict(posted)
        assert len(sent) == len(posted), "no field is sent twice"
        assert sent.pop("cbid.upgrade.1.auto_upgrade") == "1"
        assert sent.pop("cbid.upgrade.1.upgrade_time") == "5"
        assert sent.pop("cbi.apply") == ""
        assert sent.pop("timeclock").isdigit()
        expected = self.original_fields()
        for changed in ("cbid.upgrade.1.auto_upgrade", "cbid.upgrade.1.upgrade_time", "timeclock"):
            expected.pop(changed)
        assert sent == expected
        assert sent["token"] == AP1300_AUTOUPGRADE_TOKEN
        assert sent["cbi.cbe.upgrade.1.auto_upgrade"] == "1"
        assert "cbi.rlf.1.firmware" not in sent, "the manual firmware upload field is never sent"

    def test_turning_off_leaves_the_window_out_as_the_pages_dependency_rule_does(self):
        with FakeRouter("ap1300") as router:
            assert cudy(router).set_auto_update(False) is True
            (posted,) = router.state["autoupgrade_posts"]
            assert router.state["autoupgrade"] == {"auto_upgrade": "0", "upgrade_time": "3"}
        sent = dict(posted)
        assert sent["cbid.upgrade.1.auto_upgrade"] == "0"
        assert "cbid.upgrade.1.upgrade_time" not in sent
        assert set(sent) == {
            "token", "timeclock", "cbi.submit", "cbi.cbe.upgrade.1.auto_upgrade", "cbid.upgrade.1.auto_upgrade",
            "cbi.apply",
        }

    def test_turning_on_without_a_window_keeps_the_one_the_router_holds(self):
        with FakeRouter("ap1300") as router:
            router.state["autoupgrade"] = {"auto_upgrade": "0", "upgrade_time": "7"}
            assert cudy(router).set_auto_update(True) is True
            (posted,) = router.state["autoupgrade_posts"]
            assert router.state["autoupgrade"] == {"auto_upgrade": "1", "upgrade_time": "7"}
        assert dict(posted)["cbid.upgrade.1.upgrade_time"] == "7"

    def test_turning_on_without_any_window_is_refused_before_posting(self):
        """The browser would send the list's first slot (00:00-02:00), which nobody chose."""
        with FakeRouter("ap1300") as router:
            router.state["autoupgrade"] = {"auto_upgrade": "0", "upgrade_time": None}
            with pytest.raises(AdapterError, match="no update window set"):
                cudy(router).set_auto_update(True)
            assert router.state["autoupgrade_posts"] == []

    @pytest.mark.parametrize(
        "enabled,hour",
        [(True, 24), (True, -1), (True, True), (True, "3"), (True, 3.0), ("yes", None), (1, None), (False, 4)],
    )
    def test_invalid_arguments_are_refused_before_the_router_is_contacted(self, enabled, hour):
        adapter = CudyAdapter(Device.from_dict("c1", {"vendor": "cudy", "host": "127.0.0.1"}), "goodpass")
        adapter.http = Exploding()  # type: ignore[assignment]
        # Any request raises AssertionError, which pytest.raises(AdapterError) lets through.
        with pytest.raises(AdapterError):
            adapter.set_auto_update(enabled, hour)

    def test_a_window_the_page_does_not_offer_is_a_protocol_mismatch(self, monkeypatch):
        page = fixture_page().replace('value="23">23:00 - 01:00</option>', ">")
        with FakeRouter("ap1300") as router:
            adapter = cudy(router)
            monkeypatch.setattr(adapter, "_autoupgrade_page", lambda: page)
            with pytest.raises(ProtocolMismatch, match="no window starting at 23:00"):
                adapter.set_auto_update(True, 23)
            assert router.state["autoupgrade_posts"] == []

    def test_a_page_without_the_switch_is_a_protocol_mismatch(self, monkeypatch):
        with FakeRouter("ap1300") as router:
            adapter = cudy(router)
            monkeypatch.setattr(adapter, "_autoupgrade_page", lambda: "<form method='post'></form>")
            with pytest.raises(ProtocolMismatch, match="no Auto Update switch"):
                adapter.set_auto_update(False)

    def test_firmware_without_the_page_is_unsupported(self):
        with FakeRouter("ap1300") as router:
            router.state["autoupgrade_missing"] = True
            with pytest.raises(UnsupportedOperation, match="no Auto Update page"):
                cudy(router).set_auto_update(False)
            with pytest.raises(UnsupportedOperation, match="no Auto Update page"):
                cudy(router).check_firmware_update()

    def test_a_refused_post_is_an_error(self):
        with FakeRouter("ap1300") as router:
            router.state["stale_page_token"] = True
            with pytest.raises(AdapterError, match=r"did not accept the auto-update change \(HTTP 403\)"):
                cudy(router).set_auto_update(False)
            assert router.state["autoupgrade"]["auto_upgrade"] == "1"

    def test_a_window_the_router_did_not_keep_is_an_error(self):
        with FakeRouter("ap1300") as router:
            router.state["ignore_autoupgrade_writes"] = True
            with pytest.raises(AdapterError, match="did not keep the auto-update change") as caught:
                cudy(router).set_auto_update(True, 5)
        assert "auto-update on, window 03:00-05:00" in str(caught.value)

    def test_a_switch_the_router_did_not_keep_is_an_error(self):
        with FakeRouter("ap1300") as router:
            router.state["ignore_autoupgrade_writes"] = True
            with pytest.raises(AdapterError, match="it now shows auto-update on"):
                cudy(router).set_auto_update(False)


class TestCudyCheckFirmwareUpdate:
    @pytest.fixture(autouse=True)
    def fast_polls(self, monkeypatch):
        monkeypatch.setattr(adapters, "_CUDY_CHECK_POLL", 0.01)

    @pytest.mark.parametrize(
        "notice",
        [
            labelled_row("New Version", NEWER),
            labelled_row("Latest Version", NEWER),
            alert(f"New firmware v{NEWER} found."),
            alert(f"Firmware {NEWER} is available."),
        ],
    )
    def test_a_named_newer_version_is_reported_and_nothing_is_installed(self, notice):
        with FakeRouter("ap1300") as router:
            router.state["check_result_html"] = ap1300_autoupgrade_page(router.state["autoupgrade"], notice)
            result = cudy(router).check_firmware_update()
            assert result == {
                "available": True,
                "current": CURRENT,
                "latest": NEWER,
                "note": f"the router reports firmware {NEWER} is available; nothing was installed",
            }
            (check,) = router.state["update_checks"]
            assert check == {"form": [("token", AP1300_AUTOUPGRADE_TOKEN)], "ajax": "XMLHttpRequest"}
            assert router.state["check_polls"] == 2
            assert router.state["result_fetches"] == 1
            assert router.state["autoupgrade_posts"] == [], "a check changes no setting"

    @pytest.mark.parametrize(
        "notice,latest",
        [
            (alert("Your firmware is already the latest version."), None),
            (alert("No new firmware version was found."), None),
            (labelled_row("Latest Version", CURRENT), CURRENT),
        ],
    )
    def test_an_up_to_date_answer_is_reported(self, notice, latest):
        with FakeRouter("ap1300") as router:
            router.state["check_result_html"] = ap1300_autoupgrade_page(router.state["autoupgrade"], notice)
            result = cudy(router).check_firmware_update()
        assert result["available"] is False
        assert result["latest"] == latest
        assert result["note"] == "the router reports it already runs the latest firmware"

    def test_an_unrecognised_result_is_none_not_a_guess(self):
        """The plain page comes back: its labels and the current version are not an answer."""
        with FakeRouter("ap1300") as router:
            result = cudy(router).check_firmware_update()
            assert router.state["result_fetches"] == 1
        assert result["available"] is None
        assert result["latest"] is None
        assert result["current"] == CURRENT
        assert result["note"].startswith("result not recognised")

    def test_anything_but_checkdone_or_timeout_means_keep_waiting(self):
        with FakeRouter("ap1300") as router:
            router.state["check_sequence"] = ["checking", "busy", "", "checkdone"]
            cudy(router).check_firmware_update()
            assert router.state["check_polls"] == 4
            assert router.state["result_fetches"] == 1

    def test_the_routers_own_timeout_is_reported_without_reading_a_result(self):
        with FakeRouter("ap1300") as router:
            router.state["check_sequence"] = ["checking", "timeout"]
            result = cudy(router).check_firmware_update()
            assert router.state["result_fetches"] == 0
        assert result == {
            "available": None,
            "current": CURRENT,
            "latest": None,
            "note": "the router's own update check timed out, so it could not say whether newer firmware exists",
        }

    def test_a_check_that_never_finishes_gives_up_at_the_timeout(self):
        with FakeRouter("ap1300") as router:
            router.state["check_sequence"] = ["checking"]
            started = time.monotonic()
            result = cudy(router).check_firmware_update(timeout=0.2)
            elapsed = time.monotonic() - started
            assert router.state["result_fetches"] == 0
            assert router.state["check_polls"] >= 2
        assert 0.2 <= elapsed < 5
        assert result["available"] is None
        assert result["note"] == "the router had not finished its update check after 0.2 s"

    def test_a_refused_check_is_an_error(self):
        with FakeRouter("ap1300") as router:
            router.state["stale_page_token"] = True
            with pytest.raises(AdapterError, match=r"did not start its update check \(HTTP 403\)"):
                cudy(router).check_firmware_update()
            assert router.state["check_polls"] == 0


class TestCudyUpdateResultIsConservative:
    """The result page has never been seen: evidence or None, never a guess."""

    def plain(self) -> str:
        return fixture_page()

    def with_notice(self, notice: str) -> str:
        marker = '<div class="form-group" id="cbi-rlf-1-firmware">'
        return fixture_page().replace(marker, notice + marker)

    @pytest.mark.parametrize(
        "notice",
        [
            alert("New firmware 2.5.24-20250101-000000 is available."),  # older than what runs
            alert("Could not reach the new update server at 192.168.100.200."),  # an address, not a version
            alert(f"Firmware {NEWER}"),  # a version with no word saying it is new
            labelled_row("Build", NEWER),
            # Script strings (translations, templates) are never shown as they stand.
            f'<script>var text = "New firmware {NEWER} is available";</script>',
        ],
    )
    def test_no_evidence_of_a_newer_version_is_not_an_update(self, notice):
        result = _cudy_update_result(self.plain(), self.with_notice(notice), CURRENT)
        assert result["available"] is None
        assert result["note"].startswith("result not recognised")

    def test_a_contradictory_answer_is_not_a_result(self):
        notice = alert(f"New version {NEWER} found.") + alert("Your firmware is up to date.")
        result = _cudy_update_result(self.plain(), self.with_notice(notice), CURRENT)
        assert result["available"] is None
        assert "both names a newer version" in result["note"]

    def test_text_already_on_the_page_before_the_check_is_not_its_answer(self):
        page = self.with_notice(labelled_row("New Version", NEWER))
        assert _cudy_update_result(page, page, CURRENT)["available"] is None

    def test_a_label_the_page_already_had_is_read_with_the_value_the_check_filled_in(self):
        before = self.with_notice(labelled_row("Latest Version", "-"))
        after = self.with_notice(labelled_row("Latest Version", NEWER))
        result = _cudy_update_result(before, after, CURRENT)
        assert (result["available"], result["latest"]) == (True, NEWER)

    def test_the_highest_of_several_newer_versions_is_the_latest(self):
        notice = alert("New version 2.5.26-20261001-101010 found.") + alert("Latest version 2.6.1 available.")
        result = _cudy_update_result(self.plain(), self.with_notice(notice), CURRENT)
        assert (result["available"], result["latest"]) == (True, "2.6.1")

    def test_without_a_known_current_version_nothing_is_newer(self):
        notice = alert(f"New version {NEWER} found.")
        assert _cudy_update_result(self.plain(), self.with_notice(notice), "")["available"] is None


class Exploding:
    """An HttpSession stand-in for calls that must not reach the router at all."""

    cookie_jar: list = []

    def request(self, *args, **kwargs):
        raise AssertionError("the router was contacted")


class TestOtherVendors:
    def test_tplink_firmware_info_comes_from_its_status_page(self):
        with FakeTpLink(password="admin") as router:
            device = Device.from_dict("t1", {"vendor": "tplink", "host": "127.0.0.1", "http_port": router.port})
            assert TpLinkAdapter(device, "admin").firmware_info() == {
                "version": "3.14.3",
                "hardware": "TL-WR840N",
                "auto_update": None,
                "source": "tplink-11n",
            }
            assert router.attempts == 0

    @pytest.mark.parametrize("call", ["set", "check"])
    def test_tplink_firmware_changes_are_refused_without_a_login(self, call):
        """A login spent on a refused call would count toward the WR840N's ten."""
        adapter = TpLinkAdapter(Device.from_dict("t1", {"vendor": "tplink", "host": "127.0.0.1"}), "admin")
        adapter.http = Exploding()  # type: ignore[assignment]
        with pytest.raises(UnsupportedOperation, match="TP-Link firmware"):
            adapter.set_auto_update(True, 3) if call == "set" else adapter.check_firmware_update()

    def test_tenda_firmware_info_comes_from_its_status_module(self, monkeypatch):
        adapter = TendaAdapter(Device.from_dict("d1", {"vendor": "tenda", "host": "127.0.0.1"}), "pw")
        monkeypatch.setattr(adapter, "request", lambda payload: {"sysStatus": {"softwareVersion": "V16.03.07.45"}})
        assert adapter.firmware_info() == {
            "version": "V16.03.07.45",
            "hardware": "",
            "auto_update": None,
            "source": "tenda-goform",
        }

    @pytest.mark.parametrize("call", ["set", "check"])
    def test_tenda_firmware_changes_are_refused_without_contacting_it(self, call):
        adapter = TendaAdapter(Device.from_dict("d1", {"vendor": "tenda", "host": "127.0.0.1"}), "pw")
        adapter.http = Exploding()  # type: ignore[assignment]
        with pytest.raises(UnsupportedOperation, match="Tenda firmware"):
            adapter.set_auto_update(False) if call == "set" else adapter.check_firmware_update()

    def test_adapters_without_firmware_support_refuse_every_firmware_call(self):
        class Minimal(RouterAdapter):
            def status(self):
                return {}

            def reboot(self):
                return True

        adapter = Minimal(Device.from_dict("m1", {"vendor": "cudy", "host": "127.0.0.1"}), "pw")
        for call in (adapter.firmware_info, lambda: adapter.set_auto_update(True, 3), adapter.check_firmware_update):
            with pytest.raises(UnsupportedOperation):
                call()
