"""Signing in with the Skybre passkey, the signed-in identity, and the public images.

The login page is the approved Skybre design's sign-in view; its own script runs
here under node against stand-ins for the few DOM calls it makes, so what it
sends and what it shows are checked, not only the markup.
"""

import json
import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from test_dashboard_ui import contrast, theme_tokens

from cudy_manager import web
from cudy_manager.activity import ActivityLog
from cudy_manager.manager import DeviceManager
from cudy_manager.secrets import SecretStore
from cudy_manager.web import Settings, create_app

PASSKEY = "4071 9925 1108"
STATIC = Path(web.__file__).resolve().parent / "static"
NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="node is needed to run the login page's script")


def build_app(tmp_path: Path, password: str = PASSKEY, username: str = "admin"):
    data = tmp_path / "data"
    log = ActivityLog(data)
    manager = DeviceManager(
        config_path=tmp_path / "devices.yaml", data_dir=data, secret_store=SecretStore(data), activity=log
    )
    settings = Settings(
        username=username,
        password=password,
        secure_cookie=False,
        scheduler_interval=3600,
        config_path=tmp_path / "devices.yaml",
        data_dir=data,
    )
    return create_app(manager=manager, settings=settings, activity=log)


def signed_in(tmp_path: Path) -> tuple[Any, TestClient, dict[str, str]]:
    app = build_app(tmp_path)
    client = TestClient(app)
    response = client.post("/login", json={"passkey": PASSKEY})
    assert response.status_code == 200, response.text
    return app, client, {"X-CSRF-Token": response.json()["csrf_token"]}


# --- signing in ------------------------------------------------------------------------------------


class TestPasskeyLogin:
    def test_the_passkey_alone_signs_in(self, tmp_path: Path):
        client = TestClient(build_app(tmp_path))
        response = client.post("/login", json={"passkey": PASSKEY})
        assert response.status_code == 200, response.text
        assert response.json()["authenticated"] is True
        assert "router_session=" in response.headers["set-cookie"]
        assert client.get("/api/csrf").json()["csrf_token"] == response.json()["csrf_token"]

    def test_a_wrong_passkey_is_refused_in_the_designs_words(self, tmp_path: Path):
        client = TestClient(build_app(tmp_path))
        for body in ({"passkey": "0000"}, {"passkey": ""}, {"passkey": None}, {}):
            response = client.post("/login", json=body)
            assert response.status_code == 401, body
            assert response.json() == {"detail": "That passkey is not right."}
        assert client.get("/api/devices").status_code == 401

    @pytest.mark.parametrize(
        "body",
        [
            {"username": "admin", "password": PASSKEY},
            {"username": "somebody-else", "password": PASSKEY},
            {"username": "", "password": PASSKEY},
            {"password": PASSKEY},
        ],
    )
    def test_the_old_body_still_signs_in_and_its_username_is_not_checked(self, tmp_path: Path, body):
        response = TestClient(build_app(tmp_path, username="admin")).post("/login", json=body)
        assert response.status_code == 200, response.text

    def test_a_given_passkey_is_the_one_checked(self, tmp_path: Path):
        client = TestClient(build_app(tmp_path))
        assert client.post("/login", json={"passkey": "0000", "password": PASSKEY}).status_code == 401
        assert client.post("/login", json={"passkey": PASSKEY, "password": "0000"}).status_code == 200

    @pytest.mark.parametrize(
        "body",
        [{"passkey": "0000"}, {"passkey": PASSKEY}, {"username": "x", "password": "0000"}, {"username": "admin"}, {}],
    )
    def test_every_attempt_makes_exactly_one_constant_time_comparison(self, tmp_path: Path, monkeypatch, body):
        import hmac

        calls: list[tuple[bytes, bytes]] = []
        original = hmac.compare_digest

        def counting(a, b):
            calls.append((a, b))
            return original(a, b)

        monkeypatch.setattr("cudy_manager.web.hmac.compare_digest", counting)
        TestClient(build_app(tmp_path)).post("/login", json=body)
        assert len(calls) == 1
        assert calls[0][1] == PASSKEY.encode()

    def test_wrong_passkeys_are_throttled_and_a_right_one_clears_the_count(self, tmp_path: Path):
        client = TestClient(build_app(tmp_path))
        for _ in range(4):
            assert client.post("/login", json={"passkey": "0000"}).status_code == 401
        assert client.post("/login", json={"passkey": PASSKEY}).status_code == 200
        for _ in range(5):
            assert client.post("/login", json={"passkey": "0000"}).status_code == 401
        response = client.post("/login", json={"passkey": PASSKEY})
        assert response.status_code == 429

    def test_the_passkey_is_never_logged_or_echoed(self, tmp_path: Path, caplog):
        caplog.set_level(logging.DEBUG)
        client = TestClient(build_app(tmp_path))
        texts = [client.post("/login", json={"passkey": body}).text for body in (PASSKEY + "x", PASSKEY)]
        assert all(PASSKEY not in text for text in texts)
        assert PASSKEY not in caplog.text

    def test_without_a_configured_passkey_nobody_signs_in(self, tmp_path: Path):
        client = TestClient(build_app(tmp_path, password=""))
        assert client.post("/login", json={"passkey": ""}).status_code == 503
        page = client.get("/")
        assert page.status_code == 503 and "Server authentication is not configured" in page.text


# --- the login page --------------------------------------------------------------------------------


def login_page(tmp_path: Path) -> tuple[str, str]:
    response = TestClient(build_app(tmp_path)).get("/login")
    assert response.status_code == 200
    policy = response.headers["Content-Security-Policy"]
    nonce = re.search(r"'nonce-([^']+)'", policy)
    assert nonce is not None
    return response.text, nonce.group(1)


class TestLoginPage:
    def test_it_is_the_skybre_sign_in_with_one_passkey_field(self, tmp_path: Path):
        page, _ = login_page(tmp_path)
        assert "<title>Skybre Router Manager</title>" in page
        assert "<h1 id=login-title>Skybre Router Manager</h1>" in page
        assert '<img src=/assets/skybre-icon.png width=72 height=72 alt="">' in page
        assert "<link rel=icon type=image/png href=/favicon.ico>" in page
        inputs = re.findall(r"<input\b[^>]*>", page)
        assert len(inputs) == 1, inputs
        assert "type=password" in inputs[0] and "name=passkey" in inputs[0]
        assert "<span>Passkey</span>" in page
        assert "username" not in page.lower()
        assert "Enter the Skybre passkey. Names for the history log come from Vexar later." in page

    def test_it_uses_the_skybre_tokens_in_light_and_dark(self, tmp_path: Path):
        page, _ = login_page(tmp_path)
        assert "--accent: #1070B0;" in page and "--accent: #5AA8DE;" in page
        # The system's dark mode unless light was chosen, and dark whenever it was.
        assert '@media (prefers-color-scheme: dark) {\n  :root:not([data-theme="light"]) {' in page
        assert ':root[data-theme="dark"] {' in page
        assert "localStorage.getItem('skybre-theme')" in page

    def test_its_focus_ring_stands_out_in_both_themes(self, tmp_path: Path):
        # WCAG 1.4.11: 3:1 against the card, the page and the tinted top the ring can sit on.
        page, _ = login_page(tmp_path)
        for name, tokens in theme_tokens(page).items():
            for surface in ("surface", "bg", "accent-soft"):
                ratio = contrast(tokens["focus"], tokens[surface])
                assert ratio >= 3, f"{name}: the focus ring is {ratio:.2f}:1 on --{surface}"

    def test_every_script_carries_the_nonce_and_no_handler_is_inline(self, tmp_path: Path):
        page, nonce = login_page(tmp_path)
        scripts = re.findall(r"<script\b[^>]*>", page)
        assert scripts and all(tag == f'<script nonce="{nonce}">' for tag in scripts)
        assert not re.search(r"""\son[a-z]+\s*=""", page), "an inline handler would be blocked by the policy"

    def test_a_message_for_the_page_is_escaped(self):
        page = web._login_page("<b>down</b>", "n")
        assert "<div class=error id=login-error role=alert>&lt;b&gt;down&lt;/b&gt;</div>" in page


LOGIN_HARNESS = r"""
const vm = require('vm');
const input = JSON.parse(require('fs').readFileSync(0, 'utf8'));
(async () => {
  const results = [];
  for (const scenario of input.scenarios) {
    const elements = {};
    const make = (id) => ({
      id, value: '', textContent: '', disabled: false, focused: false, selected: false, listeners: {},
      addEventListener(type, fn) { this.listeners[type] = fn; },
      focus() { this.focused = true; }, select() { this.selected = true; },
      querySelector(selector) { return selector === 'button' ? elements.button : null; },
    });
    for (const id of ['login', 'login-pass', 'login-error', 'button']) elements[id] = make(id);
    elements['login-pass'].value = scenario.passkey;
    const requests = [];
    const states = [];
    const saved = scenario.storage || {};
    const context = {
      JSON, TypeError, SyntaxError,
      document: { getElementById: (id) => elements[id] || null, documentElement: { dataset: {} } },
      localStorage: scenario.storage_blocked
        ? { getItem() { throw new Error('storage is blocked'); } }
        : { getItem: (key) => (key in saved ? saved[key] : null) },
      location: { href: '/login' },
      fetch: async (url, options) => {
        requests.push({ url, method: options.method, headers: options.headers, body: JSON.parse(options.body) });
        states.push(elements.button.disabled);
        if (scenario.reply === 'unreachable') throw new TypeError('Failed to fetch');
        const { status, body } = scenario.reply;
        return {
          ok: status >= 200 && status < 300,
          status,
          json: async () => { if (typeof body !== 'object') throw new SyntaxError('not JSON'); return body; },
        };
      },
    };
    vm.createContext(context);
    for (const code of input.scripts) vm.runInContext(code, context);
    let prevented = false;
    await elements.login.listeners.submit({ preventDefault() { prevented = true; } });
    results.push({
      message: elements['login-error'].textContent,
      href: context.location.href,
      theme: context.document.documentElement.dataset.theme || null,
      requests, prevented, disabled_while_sending: states, disabled_after: elements.button.disabled,
      selected: elements['login-pass'].selected,
    });
  }
  process.stdout.write(JSON.stringify(results));
})().catch((error) => { process.stderr.write(String(error && error.stack)); process.exit(1); });
"""


def run_login_page(tmp_path: Path, *scenarios: dict[str, Any]) -> list[dict[str, Any]]:
    page, nonce = login_page(tmp_path)
    scripts = re.findall(rf'<script nonce="{re.escape(nonce)}">(.*?)</script>', page, flags=re.S)
    assert len(scripts) == 2
    harness = tmp_path / "login_harness.js"
    harness.write_text(LOGIN_HARNESS, encoding="utf-8")
    assert NODE is not None
    completed = subprocess.run(
        [NODE, str(harness)],
        input=json.dumps({"scripts": scripts, "scenarios": list(scenarios)}),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


@needs_node
class TestLoginPageBehaviour:
    def test_it_sends_only_the_passkey_as_json_and_opens_the_dashboard(self, tmp_path: Path):
        (outcome,) = run_login_page(tmp_path, {"passkey": PASSKEY, "reply": {"status": 200, "body": {}}})
        assert outcome["prevented"] is True
        assert outcome["requests"] == [
            {
                "url": "/login",
                "method": "POST",
                "headers": {"Content-Type": "application/json"},
                "body": {"passkey": PASSKEY},
            }
        ]
        assert outcome["href"] == "/"
        # The button cannot send a second attempt while the first is out.
        assert outcome["disabled_while_sending"] == [True]

    def test_the_designs_messages(self, tmp_path: Path):
        empty, wrong, throttled, broken, unreachable = run_login_page(
            tmp_path,
            {"passkey": "", "reply": {"status": 200, "body": {}}},
            {"passkey": "0000", "reply": {"status": 401, "body": {"detail": "That passkey is not right."}}},
            {"passkey": "0000", "reply": {"status": 429, "body": {"detail": "too many login attempts"}}},
            {"passkey": "0000", "reply": {"status": 502, "body": "<html>Bad gateway</html>"}},
            {"passkey": "0000", "reply": "unreachable"},
        )
        assert (empty["message"], empty["requests"]) == ("Enter the passkey.", [])
        assert wrong["message"] == "That passkey is not right." and wrong["selected"] is True
        assert throttled["message"] == "too many login attempts"
        assert broken["message"] == "Signing in failed. Try again."
        assert unreachable["message"] == "The server could not be reached."
        for outcome in (wrong, throttled, broken, unreachable):
            assert outcome["href"] == "/login" and outcome["disabled_after"] is False

    def test_it_takes_the_dashboards_theme_and_survives_blocked_storage(self, tmp_path: Path):
        reply = {"status": 401, "body": {}}
        dark, light, unset, blocked = run_login_page(
            tmp_path,
            {"passkey": "x", "reply": reply, "storage": {"skybre-theme": "dark"}},
            {"passkey": "x", "reply": reply, "storage": {"skybre-theme": "light"}},
            {"passkey": "x", "reply": reply, "storage": {"skybre-theme": "sepia"}},
            {"passkey": "x", "reply": reply, "storage_blocked": True},
        )
        assert [dark["theme"], light["theme"], unset["theme"], blocked["theme"]] == ["dark", "light", None, None]
        assert blocked["message"] == "That passkey is not right."


# --- who is signed in ------------------------------------------------------------------------------


class TestMe:
    def test_it_needs_a_session(self, tmp_path: Path):
        assert TestClient(build_app(tmp_path)).get("/api/me").status_code == 401

    def test_it_names_the_session_as_the_activity_log_does(self, tmp_path: Path):
        _, client, _ = signed_in(tmp_path)
        assert client.get("/api/me").json() == {"actor": "Skybre staff", "mode": "standalone"}

    def test_the_name_shown_and_the_name_logged_come_from_one_function(self, tmp_path: Path, monkeypatch):
        # What a Vexar hand-off will do: replace session_actor, and nothing else.
        monkeypatch.setattr(web, "session_actor", lambda request: "Thandi (Vexar)")
        app, client, headers = signed_in(tmp_path)
        assert client.get("/api/me").json()["actor"] == "Thandi (Vexar)"
        added = client.post(
            "/api/devices", json={"id": "r1", "host": "192.0.2.1", "vendor": "cudy", "password": "p"}, headers=headers
        )
        assert added.status_code == 200, added.text
        (entry,) = app.state.activity.list()
        assert entry["who"] == "Thandi (Vexar)"


# --- the images ------------------------------------------------------------------------------------


class TestAssets:
    @pytest.mark.parametrize(
        "path,name", [("/assets/skybre-icon.png", "skybre-icon.png"), ("/favicon.ico", "favicon.png")]
    )
    def test_the_logo_and_favicon_are_public_pngs(self, tmp_path: Path, path, name):
        response = TestClient(build_app(tmp_path)).get(path)
        assert response.status_code == 200
        assert response.headers["content-type"] == "image/png"
        assert response.content == (STATIC / name).read_bytes()
        assert response.content.startswith(b"\x89PNG\r\n\x1a\n")
        assert response.headers["Cache-Control"] == "public, max-age=604800"
        assert response.headers["X-Content-Type-Options"] == "nosniff"

    def test_they_are_served_before_a_passkey_is_configured(self, tmp_path: Path):
        # The login page shows them while it says authentication is not configured.
        client = TestClient(build_app(tmp_path, password=""))
        assert client.get("/assets/skybre-icon.png").status_code == 200
        assert client.get("/favicon.ico").status_code == 200

    @pytest.mark.parametrize(
        "path",
        [
            "/assets/favicon.png",
            "/assets/",
            "/assets/SKYBRE-ICON.PNG",
            "/assets/../web.py",
            "/assets/%2e%2e/web.py",
            "/assets/..%2fweb.py",
            "/assets/static/skybre-icon.png",
        ],
    )
    def test_nothing_else_under_assets_is_served(self, tmp_path: Path, path):
        client = TestClient(build_app(tmp_path))
        anonymous = client.get(path, follow_redirects=False)
        assert anonymous.status_code in (303, 404), (path, anonymous.status_code)
        assert anonymous.headers["Cache-Control"] == "no-store"
        client.post("/login", json={"passkey": PASSKEY})
        response = client.get(path, follow_redirects=False)
        assert response.status_code == 404, (path, response.status_code)
        assert response.headers["Cache-Control"] == "no-store"
        assert b"import " not in response.content

    def test_a_trailing_slash_only_leads_back_to_the_logo(self, tmp_path: Path):
        client = TestClient(build_app(tmp_path))
        # Not public: only the exact path is.
        assert client.get("/assets/skybre-icon.png/", follow_redirects=False).headers["location"] == "/login"
        client.post("/login", json={"passkey": PASSKEY})
        # Starlette's own redirect, which names the served file and nothing else.
        response = client.get("/assets/skybre-icon.png/", follow_redirects=False)
        assert response.status_code == 307
        assert response.headers["location"].endswith("/assets/skybre-icon.png")

    def test_only_the_assets_may_be_cached(self, tmp_path: Path):
        app, client, _ = signed_in(tmp_path)
        for path in ("/login", "/api/me", "/healthz", "/"):
            assert client.get(path).headers["Cache-Control"] == "no-store", path

    def test_a_missing_image_is_a_404_not_a_500(self, tmp_path: Path, monkeypatch):
        monkeypatch.setattr(web, "STATIC_DIR", tmp_path / "nowhere")
        response = TestClient(build_app(tmp_path), raise_server_exceptions=False).get("/favicon.ico")
        assert response.status_code == 404
        assert response.headers["Cache-Control"] == "no-store"
