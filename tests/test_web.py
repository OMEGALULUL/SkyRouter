from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# The dashboard's script is exercised in test_dashboard_ui.py. test_web_acs.py still
# imports these names from here, so they are re-exported.
from test_dashboard_ui import HARNESS as DASHBOARD_HARNESS  # noqa: F401
from test_dashboard_ui import NODE as NODE
from test_dashboard_ui import dashboard_markup as _dashboard_markup  # noqa: F401
from test_dashboard_ui import needs_node as needs_node

from cudy_manager.manager import DeviceManager
from cudy_manager.secrets import SecretStore
from cudy_manager.web import Settings, create_app

PASSWORD = "correct horse battery staple"


def rejected():
    return {"ok": False, "reason": "rejected", "error": "authentication failed"}


def build_client(tmp_path: Path, password: str = PASSWORD) -> TestClient:
    return TestClient(build_app(tmp_path, password))


def build_app(tmp_path: Path, password: str = PASSWORD):
    store = SecretStore(tmp_path / "data")
    manager = DeviceManager(config_path=tmp_path / "devices.yaml", data_dir=tmp_path / "data", secret_store=store)
    settings = Settings(
        username="admin",
        password=password,
        secure_cookie=False,
        scheduler_interval=3600,
        config_path=tmp_path / "devices.yaml",
        data_dir=tmp_path / "data",
    )
    return create_app(manager=manager, settings=settings)


def login(client: TestClient, password: str = PASSWORD) -> str:
    response = client.post("/login", json={"username": "admin", "password": password})
    assert response.status_code == 200, response.text
    return response.json()["csrf_token"]


class TestLifespan:
    def test_app_serves_requests_while_lifespan_runs(self, tmp_path: Path):
        with TestClient(build_app(tmp_path)) as client:
            assert client.get("/healthz").status_code == 200
            assert client.get("/api/devices").status_code == 401

    def test_lifespan_shuts_down_cleanly(self, tmp_path: Path):
        client = TestClient(build_app(tmp_path))
        client.__enter__()
        client.__exit__(None, None, None)

    def test_scheduler_runs_during_lifespan(self, tmp_path: Path):
        calls = []

        class RecordingScheduler:
            def tick(self):
                calls.append(1)
                return []

            def join_maintenance(self, timeout=None):
                return True

            def get_state(self):
                return {}

        app = build_app(tmp_path)
        app.state.scheduler = RecordingScheduler()
        with TestClient(app) as client:
            assert client.get("/healthz").status_code == 200
        assert calls


class TestAuthentication:
    def test_health_is_public(self, tmp_path: Path):
        client = build_client(tmp_path)
        response = client.get("/healthz")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    def test_api_requires_session(self, tmp_path: Path):
        client = build_client(tmp_path)
        assert client.get("/api/devices").status_code == 401
        assert client.get("/api/csrf").status_code == 401

    def test_dashboard_redirects_to_login(self, tmp_path: Path):
        client = build_client(tmp_path)
        response = client.get("/", follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"] == "/login"

    def test_login_rejects_bad_password(self, tmp_path: Path):
        client = build_client(tmp_path)
        assert client.post("/login", json={"username": "admin", "password": "wrong"}).status_code == 401

    def test_nothing_but_the_passkey_signs_in(self, tmp_path: Path):
        # Sign-in is by passkey alone, so the username that older clients send proves nothing.
        client = build_client(tmp_path)
        assert client.post("/login", json={"username": "admin"}).status_code == 401
        assert client.post("/login", json={"username": "admin", "password": ""}).status_code == 401
        assert client.post("/login", json={"username": "admin", "passkey": "wrong"}).status_code == 401

    def test_login_sets_httponly_cookie(self, tmp_path: Path):
        client = build_client(tmp_path)
        response = client.post("/login", json={"username": "admin", "password": PASSWORD})
        cookie = response.headers["set-cookie"]
        assert "router_session=" in cookie
        assert "HttpOnly" in cookie
        assert "SameSite=strict" in cookie.replace("samesite", "SameSite")

    def test_rate_limit_blocks_repeated_failures(self, tmp_path: Path):
        client = build_client(tmp_path)
        for _ in range(5):
            client.post("/login", json={"username": "admin", "password": "wrong"})
        assert client.post("/login", json={"username": "admin", "password": PASSWORD}).status_code == 429

    def test_server_refuses_to_run_without_password(self, tmp_path: Path):
        client = build_client(tmp_path, password="")
        assert client.get("/api/devices").status_code == 503
        assert client.get("/").status_code == 503
        assert client.post("/login", json={"username": "admin", "password": ""}).status_code == 503

    def test_logout_invalidates_session(self, tmp_path: Path):
        client = build_client(tmp_path)
        token = login(client)
        assert client.post("/logout", headers={"X-CSRF-Token": token}).status_code == 200
        assert client.get("/api/devices").status_code == 401

    def test_logout_requires_csrf(self, tmp_path: Path):
        client = build_client(tmp_path)
        login(client)
        assert client.post("/logout").status_code == 403


class TestCsrf:
    def test_mutation_without_csrf_is_rejected(self, tmp_path: Path):
        client = build_client(tmp_path)
        login(client)
        response = client.post(
            "/api/devices", json={"id": "r1", "host": "192.168.1.1", "vendor": "cudy", "password": "p"}
        )
        assert response.status_code == 403

    def test_mutation_with_wrong_csrf_is_rejected(self, tmp_path: Path):
        client = build_client(tmp_path)
        login(client)
        response = client.post(
            "/api/devices",
            json={"id": "r1", "host": "192.168.1.1", "vendor": "cudy", "password": "p"},
            headers={"X-CSRF-Token": "forged"},
        )
        assert response.status_code == 403

    def test_mutation_with_valid_csrf_succeeds(self, tmp_path: Path):
        client = build_client(tmp_path)
        token = login(client)
        response = client.post(
            "/api/devices",
            json={"id": "r1", "host": "192.168.1.1", "vendor": "cudy", "password": "p"},
            headers={"X-CSRF-Token": token},
        )
        assert response.status_code == 200, response.text

    def test_csrf_token_is_per_session(self, tmp_path: Path):
        client = build_client(tmp_path)
        first = login(client)
        second = login(client)
        assert first != second


class TestDeviceApi:
    def test_add_requires_fields(self, tmp_path: Path):
        client = build_client(tmp_path)
        token = login(client)
        response = client.post("/api/devices", json={"id": "r1"}, headers={"X-CSRF-Token": token})
        assert response.status_code == 400

    def test_add_never_echoes_password(self, tmp_path: Path):
        client = build_client(tmp_path)
        token = login(client)
        response = client.post(
            "/api/devices",
            json={
                "id": "r1",
                "host": "192.168.1.1",
                "vendor": "cudy",
                "password": "top-secret-value",
            },
            headers={"X-CSRF-Token": token},
        )
        assert "top-secret-value" not in response.text
        assert "password_ref" not in response.text

    def test_list_does_not_leak_password(self, tmp_path: Path):
        client = build_client(tmp_path)
        token = login(client)
        client.post(
            "/api/devices",
            json={"id": "r1", "host": "192.168.1.1", "vendor": "cudy", "password": "top-secret-value"},
            headers={"X-CSRF-Token": token},
        )
        response = client.get("/api/devices")
        assert "top-secret-value" not in response.text
        assert "password_ref" not in response.text

    def test_reboot_requires_confirmation(self, tmp_path: Path):
        client = build_client(tmp_path)
        token = login(client)
        client.post(
            "/api/devices",
            json={"id": "r1", "host": "192.168.1.1", "vendor": "cudy", "password": "p"},
            headers={"X-CSRF-Token": token},
        )
        response = client.post("/api/devices/r1/reboot", json={}, headers={"X-CSRF-Token": token})
        assert response.status_code == 400

    def test_unknown_device_returns_404(self, tmp_path: Path):
        client = build_client(tmp_path)
        token = login(client)
        assert client.get("/api/devices/missing/status").status_code == 404
        response = client.post("/api/devices/missing/reboot", json={"confirm": True}, headers={"X-CSRF-Token": token})
        assert response.status_code == 404

    def test_delete_removes_device(self, tmp_path: Path):
        client = build_client(tmp_path)
        token = login(client)
        client.post(
            "/api/devices",
            json={"id": "r1", "host": "192.168.1.1", "vendor": "cudy", "password": "p"},
            headers={"X-CSRF-Token": token},
        )
        assert client.delete("/api/devices/r1", headers={"X-CSRF-Token": token}).status_code == 200
        assert client.get("/api/devices").json()["devices"] == []

    def test_invalid_vendor_is_rejected(self, tmp_path: Path):
        client = build_client(tmp_path)
        token = login(client)
        response = client.post(
            "/api/devices",
            json={"id": "r1", "host": "192.168.1.1", "vendor": "ubiquiti", "password": "p"},
            headers={"X-CSRF-Token": token},
        )
        assert response.status_code == 400

    def test_plaintext_fields_rejected_on_add(self, tmp_path: Path):
        client = build_client(tmp_path)
        token = login(client)
        response = client.post(
            "/api/devices",
            json={
                "id": "r1",
                "host": "192.168.1.1",
                "vendor": "cudy",
                "password": "p",
                "luci_password": "leak",
            },
            headers={"X-CSRF-Token": token},
        )
        assert response.status_code == 400
        assert "luci_password" in response.text
        assert client.get("/api/devices").json()["devices"] == []

    def test_mesh_reports_unsupported_for_vendor_without_mesh(self, tmp_path: Path):
        client = build_client(tmp_path)
        token = login(client)
        client.post(
            "/api/devices",
            json={"id": "r1", "host": "192.168.1.1", "vendor": "tenda", "password": "p"},
            headers={"X-CSRF-Token": token},
        )
        response = client.get("/api/devices/r1/mesh")
        # 501, not 502: no router was contacted, so a retry-on-502 client must not retry.
        assert response.status_code == 501
        assert "not supported" in response.text

    def test_plaintext_fields_rejected_on_update(self, tmp_path: Path):
        client = build_client(tmp_path)
        token = login(client)
        client.post(
            "/api/devices",
            json={"id": "r1", "host": "192.168.1.1", "vendor": "cudy", "password": "p"},
            headers={"X-CSRF-Token": token},
        )
        response = client.put("/api/devices/r1", json={"luci_password": "x"}, headers={"X-CSRF-Token": token})
        assert response.status_code == 400
        assert "plaintext" in response.text

    def test_malformed_json_rejected(self, tmp_path: Path):
        client = build_client(tmp_path)
        token = login(client)
        response = client.post(
            "/api/devices",
            content=b"{not json",
            headers={"X-CSRF-Token": token, "Content-Type": "application/json"},
        )
        assert response.status_code == 400

    def test_dashboard_page_served_after_login(self, tmp_path: Path):
        client = build_client(tmp_path)
        login(client)
        response = client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_scheduler_state_endpoint(self, tmp_path: Path):
        client = build_client(tmp_path)
        login(client)
        assert client.get("/api/scheduler").json() == {"state": {}}

    def test_security_headers_present(self, tmp_path: Path):
        client = build_client(tmp_path)
        response = client.get("/healthz")
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers["Cache-Control"] == "no-store"


class TestPasswordReset:
    def _add(self, client: TestClient, token: str, password: str = "old"):
        return client.post(
            "/api/devices",
            json={"id": "r1", "host": "192.168.1.1", "vendor": "cudy", "password": password},
            headers={"X-CSRF-Token": token},
        )

    def test_requires_authentication(self, tmp_path: Path):
        with TestClient(build_app(tmp_path)) as client:
            assert client.post("/api/devices/r1/password", json={"password": "new"}).status_code == 401

    def test_requires_csrf(self, tmp_path: Path):
        with TestClient(build_app(tmp_path)) as client:
            token = login(client)
            self._add(client, token)
            assert client.post("/api/devices/r1/password", json={"password": "new"}).status_code == 403

    def test_rotates_password_without_leaking_it(self, tmp_path: Path):
        with TestClient(build_app(tmp_path)) as client:
            token = login(client)
            self._add(client, token)
            response = client.post(
                "/api/devices/r1/password",
                json={"password": "brand-new-secret", "verify": False},
                headers={"X-CSRF-Token": token},
            )
            assert response.status_code == 200
            body = response.text
            assert "brand-new-secret" not in body
            assert "password_ref" not in body
            assert response.json()["password_updated"] is True

            assert "brand-new-secret" not in (tmp_path / "devices.yaml").read_text()
            assert "brand-new-secret" not in (tmp_path / "data" / "secrets.json").read_text()

    def test_missing_password_rejected(self, tmp_path: Path):
        with TestClient(build_app(tmp_path)) as client:
            token = login(client)
            self._add(client, token)
            for payload in ({}, {"password": ""}, {"password": None}, {"password": 5}, {"password": ["a"]}):
                response = client.post("/api/devices/r1/password", json=payload, headers={"X-CSRF-Token": token})
                assert response.status_code == 400, payload

    def test_non_boolean_verify_rejected(self, tmp_path: Path):
        with TestClient(build_app(tmp_path)) as client:
            token = login(client)
            self._add(client, token)
            response = client.post(
                "/api/devices/r1/password",
                json={"password": "new", "verify": "yes"},
                headers={"X-CSRF-Token": token},
            )
            assert response.status_code == 400

    def test_secret_reference_injection_rejected(self, tmp_path: Path):
        with TestClient(build_app(tmp_path)) as client:
            token = login(client)
            self._add(client, token)
            response = client.post(
                "/api/devices/r1/password",
                json={"password": "new", "password_ref": "device-r1-password"},
                headers={"X-CSRF-Token": token},
            )
            assert response.status_code == 400
            assert "password_ref" in response.json()["detail"]

    def test_unknown_device_rejected(self, tmp_path: Path):
        with TestClient(build_app(tmp_path)) as client:
            token = login(client)
            response = client.post(
                "/api/devices/ghost/password",
                json={"password": "new", "verify": False},
                headers={"X-CSRF-Token": token},
            )
            assert response.status_code == 400

    def test_verification_failure_is_reported_but_password_saved(self, tmp_path: Path, monkeypatch):
        with TestClient(build_app(tmp_path)) as client:
            token = login(client)
            self._add(client, token)

            monkeypatch.setattr(client.app.state.manager, "verify_credentials", lambda identifier: rejected())
            response = client.post(
                "/api/devices/r1/password",
                json={"password": "typo", "verify": True},
                headers={"X-CSRF-Token": token},
            )
            assert response.status_code == 200
            assert response.json()["verified"]["ok"] is False
            assert "typo" not in response.text
            monkeypatch.undo()

    def test_dashboard_exposes_a_password_control(self, tmp_path: Path):
        with TestClient(build_app(tmp_path)) as client:
            login(client)
            page = client.get("/").text
            assert "/password" in page
            assert "showPassword" in page
            assert "Confirm password" in page


class TestCredentialFieldHandling:
    def test_snmp_community_is_stored_as_a_reference_not_plaintext(self, tmp_path: Path):
        client = build_client(tmp_path)
        auth = {"x-csrf-token": login(client)}
        response = client.post(
            "/api/devices",
            headers=auth,
            json={
                "id": "snmp1",
                "host": "192.168.1.5",
                "vendor": "cudy",
                "password": "pw",
                "snmp_community": "publicsecret",
            },
        )
        assert response.status_code == 200, response.text
        body = response.json()["device"]
        assert "snmp_community" not in body
        assert "publicsecret" not in response.text

        from cudy_manager.manager import DeviceManager

        reloaded = DeviceManager(
            config_path=tmp_path / "devices.yaml",
            data_dir=tmp_path / "data",
            secret_store=SecretStore(tmp_path / "data"),
        ).get_device("snmp1")
        assert reloaded.snmp_community_ref
        assert "publicsecret" not in reloaded.to_config()["snmp_community_ref"]

    def test_secret_reference_cannot_be_injected(self, tmp_path: Path):
        client = build_client(tmp_path)
        auth = {"x-csrf-token": login(client)}
        response = client.post(
            "/api/devices",
            headers=auth,
            json={
                "id": "ref1",
                "host": "192.168.1.6",
                "vendor": "cudy",
                "password": "pw",
                "password_ref": "device-other-password",
            },
        )
        assert response.status_code == 400
        assert "ref" in response.json()["detail"].lower()

    def test_legacy_plaintext_aliases_are_rejected(self, tmp_path: Path):
        client = build_client(tmp_path)
        auth = {"x-csrf-token": login(client)}
        for field in ("ssh_password", "luci_password"):
            response = client.post(
                "/api/devices",
                headers=auth,
                json={
                    "id": f"legacy-{field}",
                    "host": "192.168.1.7",
                    "vendor": "cudy",
                    "password": "pw",
                    field: "x",
                },
            )
            assert response.status_code == 400, field


class TestLoginRateLimitKeying:
    def test_forwarded_header_is_used_when_proxy_is_trusted(self, monkeypatch):
        from starlette.datastructures import Headers

        monkeypatch.setenv("ROUTER_MANAGER_TRUST_PROXY", "1")
        from cudy_manager.web import _client_key

        class FakeRequest:
            client = type("C", (), {"host": "127.0.0.1"})()
            headers = Headers({"x-forwarded-for": "5.6.7.8, 9.9.9.9"})

        # The rightmost entry is the one the trusted proxy appended; the rest came
        # from the client.
        assert _client_key(FakeRequest()) == "9.9.9.9"

    def test_socket_peer_is_used_when_not_trusted(self, monkeypatch):
        from starlette.datastructures import Headers

        monkeypatch.delenv("ROUTER_MANAGER_TRUST_PROXY", raising=False)
        from cudy_manager.web import _client_key

        class FakeRequest:
            client = type("C", (), {"host": "127.0.0.1"})()
            headers = Headers({"x-forwarded-for": "1.2.3.4"})

        assert _client_key(FakeRequest()) == "127.0.0.1"


class TestSecurityHeadersOnEveryResponse:
    def _assert_hardened(self, response):
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers["Referrer-Policy"] == "no-referrer"
        assert response.headers["Cache-Control"] == "no-store"

    def test_unauthenticated_api_is_hardened(self, tmp_path: Path):
        self._assert_hardened(TestClient(build_app(tmp_path)).get("/api/devices"))

    def test_redirect_to_login_is_hardened(self, tmp_path: Path):
        self._assert_hardened(TestClient(build_app(tmp_path)).get("/"))

    def test_unconfigured_server_is_hardened(self, tmp_path: Path):
        app = build_app(tmp_path)
        app.state.settings.password = ""
        self._assert_hardened(TestClient(app).get("/api/devices"))

    def test_csrf_rejection_is_hardened(self, tmp_path: Path):
        with TestClient(build_app(tmp_path)) as client:
            token = login(client)
            response = client.post("/api/devices", json={"id": "a", "host": "h", "vendor": "cudy", "password": "p"})
            assert response.status_code == 403
            self._assert_hardened(response)
            assert token

    def test_successful_response_is_hardened(self, tmp_path: Path):
        with TestClient(build_app(tmp_path)) as client:
            self._assert_hardened(client.get("/login"))


class TestEventLoopResponsiveness:
    """Router calls must never block the event loop.

    Every endpoint that can touch a router runs in a worker thread. A synchronous
    call inside an ``async def`` route stalls the whole server, including the cheap
    endpoints the dashboard polls.
    """

    def test_password_reset_does_not_block_other_requests(self, tmp_path: Path):
        import threading
        import time

        app = build_app(tmp_path)
        manager = app.state.manager
        manager.add_device("r1", "192.0.2.1", "cudy", password="pw")

        def slow_verify(identifier):
            time.sleep(1.0)
            return {"ok": True}

        manager.verify_credentials = slow_verify

        with TestClient(app) as client:
            token = login(client)
            headers = {"x-csrf-token": token}
            elapsed: dict[str, float] = {}

            def reset() -> None:
                started = time.time()
                client.post("/api/devices/r1/password", headers=headers, json={"password": "new", "verify": True})
                elapsed["reset"] = time.time() - started

            worker = threading.Thread(target=reset)
            worker.start()
            time.sleep(0.3)

            started = time.time()
            response = client.get("/api/csrf", headers=headers)
            elapsed["other"] = time.time() - started
            worker.join()

        assert response.status_code == 200
        assert elapsed["reset"] >= 1.0
        # A trivial endpoint must stay responsive while the router call is in flight.
        assert elapsed["other"] < 0.5, f"event loop was blocked for {elapsed['other']:.2f}s"

    def test_add_device_does_not_block_other_requests(self, tmp_path: Path):
        import threading
        import time

        app = build_app(tmp_path)
        manager = app.state.manager
        original = manager.add_device

        def slow_add(*args, **kwargs):
            time.sleep(1.0)
            return original(*args, **kwargs)

        manager.add_device = slow_add

        with TestClient(app) as client:
            token = login(client)
            headers = {"x-csrf-token": token}
            elapsed: dict[str, float] = {}

            def add() -> None:
                started = time.time()
                client.post(
                    "/api/devices",
                    headers=headers,
                    json={"id": "r9", "host": "192.0.2.9", "vendor": "cudy", "password": "pw"},
                )
                elapsed["add"] = time.time() - started

            worker = threading.Thread(target=add)
            worker.start()
            time.sleep(0.3)

            started = time.time()
            client.get("/api/csrf", headers=headers)
            elapsed["other"] = time.time() - started
            worker.join()

        assert elapsed["add"] >= 1.0
        assert elapsed["other"] < 0.5, f"event loop was blocked for {elapsed['other']:.2f}s"


class TestLoginLimiter:
    def test_expired_keys_are_reclaimed(self):
        import time

        from cudy_manager.web import LoginLimiter

        limiter = LoginLimiter(window_seconds=1)
        for index in range(200):
            limiter.attempt(f"10.0.0.{index}")
        assert len(limiter._values) == 200
        time.sleep(1.1)
        for index in range(50):
            limiter.blocked(f"10.0.0.{index}")
        assert len(limiter._values) == 0

    def test_key_count_is_capped(self):
        from cudy_manager.web import LoginLimiter

        limiter = LoginLimiter(max_keys=100)
        for index in range(5000):
            limiter.attempt(f"10.{(index // 256) % 256}.{index % 256}.{index // 65536}")
        assert len(limiter._values) <= 100

    def test_throttling_still_works(self):
        from cudy_manager.web import LoginLimiter

        limiter = LoginLimiter(maximum=3, window_seconds=60)
        for _ in range(3):
            limiter.attempt("1.2.3.4")
        assert limiter.blocked("1.2.3.4")
        assert not limiter.blocked("5.6.7.8")
        limiter.success("1.2.3.4")
        assert not limiter.blocked("1.2.3.4")


class TestLoginTiming:
    @pytest.mark.parametrize(
        "body", [{"username": "wrong", "password": PASSWORD}, {"username": "wrong"}, {}, {"passkey": "x" * 64}]
    )
    def test_every_attempt_runs_one_constant_time_comparison(self, tmp_path: Path, monkeypatch, body):
        """No body shape may skip the comparison, or its timing would tell a probe what the server checks."""
        import hmac

        app = build_app(tmp_path)
        calls: list[bytes] = []
        original = hmac.compare_digest

        def counting(a, b):
            calls.append(a)
            return original(a, b)

        monkeypatch.setattr("cudy_manager.web.hmac.compare_digest", counting)
        with TestClient(app) as client:
            client.post("/login", json=body)

        assert len(calls) == 1, "the passkey comparison was skipped or repeated"


class TestSettingsFromEnv:
    def test_invalid_interval_falls_back(self, monkeypatch):
        from cudy_manager.web import Settings

        monkeypatch.setenv("ROUTER_MANAGER_SCHEDULER_INTERVAL", "abc")
        assert Settings.from_env().scheduler_interval == 30

    def test_interval_below_minimum_is_raised(self, monkeypatch):
        from cudy_manager.web import Settings

        monkeypatch.setenv("ROUTER_MANAGER_SCHEDULER_INTERVAL", "5")
        assert Settings.from_env().scheduler_interval == 15

    def test_valid_interval_is_used(self, monkeypatch):
        from cudy_manager.web import Settings

        monkeypatch.setenv("ROUTER_MANAGER_SCHEDULER_INTERVAL", "90")
        assert Settings.from_env().scheduler_interval == 90


class TestContentSecurityPolicy:
    """The dashboard must work under a strict policy.

    There is no XSS sink in the dashboard today, so the policy is defence in depth.
    It still has to be correct, or the page silently stops working.
    """

    @staticmethod
    def _nonce_from(response) -> str:
        header = response.headers["Content-Security-Policy"]
        assert "'nonce-" in header, header
        start = header.index("'nonce-") + len("'nonce-")
        return header[start : header.index("'", start)]

    def test_policy_is_present_on_json_responses(self, tmp_path: Path):
        client = build_client(tmp_path)
        login(client)
        policy = client.get("/api/csrf").headers["Content-Security-Policy"]
        assert "default-src 'none'" in policy
        assert "frame-ancestors 'none'" in policy
        assert "form-action 'self'" in policy

    def test_dashboard_nonce_matches_the_header(self, tmp_path: Path):
        client = build_client(tmp_path)
        login(client)
        response = client.get("/")
        assert response.status_code == 200
        nonce = self._nonce_from(response)
        assert f'<script nonce="{nonce}">' in response.text
        assert "__CSP_NONCE__" not in response.text

    def test_login_nonce_matches_the_header(self, tmp_path: Path):
        response = build_client(tmp_path).get("/login")
        nonce = self._nonce_from(response)
        assert f'<script nonce="{nonce}">' in response.text
        assert "{nonce}" not in response.text

    def test_nonce_changes_per_request(self, tmp_path: Path):
        client = build_client(tmp_path)
        login(client)
        first = self._nonce_from(client.get("/"))
        second = self._nonce_from(client.get("/"))
        assert first != second

    def test_dashboard_has_no_inline_event_handlers(self, tmp_path: Path):
        import re

        client = build_client(tmp_path)
        login(client)
        body = client.get("/").text
        # Inline handler attributes need 'unsafe-inline' in script-src, which this
        # policy omits. Assigning element.onclick from script is unaffected, so match
        # only the attribute form: a quoted value after whitespace.
        assert not re.search(r"""\son[a-z]+\s*=\s*["']""", body), "inline event handler would be blocked"
        # Every control must therefore be wired up from script instead.
        controls = (
            "theme-toggle",
            "signout",
            "d-close",
            "d-wifi",
            "d-refresh",
            "d-reboot",
            "d-more",
            "wifi-cancel",
            "pw-cancel",
            "plan-cancel",
            "auto-cancel",
            "new-close",
            "new-plan",
            "check-all",
            "fw-upload",
            "activity-more",
        )
        for control in controls:
            assert f'id="{control}"' in body
            assert f"'{control}'" in body

    def test_policy_is_also_set_on_error_responses(self, tmp_path: Path):
        client = build_client(tmp_path)
        response = client.get("/api/devices")
        assert response.status_code == 401
        assert "Content-Security-Policy" in response.headers


class TestPolicyAllowsWhatTheAppDoes:
    """The policy must permit the requests the pages actually make.

    A policy that is present and syntactically valid can still be functionally
    broken: fetch() falls back to default-src, so omitting connect-src blocks
    every API call while the page still renders and looks healthy.
    """

    @staticmethod
    def _directives(response) -> dict[str, str]:
        header = response.headers["Content-Security-Policy"]
        parsed: dict[str, str] = {}
        for part in header.split(";"):
            tokens = part.split()
            if tokens:
                parsed[tokens[0]] = " ".join(tokens[1:])
        return parsed

    def test_connect_src_permits_same_origin_fetch(self, tmp_path: Path):
        client = build_client(tmp_path)
        login(client)
        directives = self._directives(client.get("/"))
        assert directives.get("connect-src") == "'self'", "fetch() to the API would be blocked"

    def test_login_page_permits_same_origin_fetch(self, tmp_path: Path):
        response = build_client(tmp_path).get("/login")
        assert self._directives(response).get("connect-src") == "'self'"

    def test_policy_permits_the_scripts_and_styles_the_pages_use(self, tmp_path: Path):
        client = build_client(tmp_path)
        login(client)
        for page in (client.get("/"), build_client(tmp_path).get("/login")):
            directives = self._directives(page)
            # An inline <script> needs a nonce, which the header must carry.
            assert "'nonce-" in directives["script-src"]
            # The pages ship a <style> block, which needs style-src.
            assert "style-src" in directives
            assert directives["form-action"] == "'self'"


class TestRemoveDevice:
    """The Remove button deletes config and the stored password together.

    Leaving an orphaned password in the vault after a device is removed would be
    a quiet way to accumulate credentials nobody is tracking.
    """

    def _token(self, client) -> str:
        return client.post("/login", json={"username": "admin", "password": PASSWORD}).json()["csrf_token"]

    def _add(self, client, identifier: str = "r1", password: str = "hunter2") -> None:
        response = client.post(
            "/api/devices",
            json={"id": identifier, "host": "192.168.1.1", "vendor": "cudy", "password": password},
            headers={"X-CSRF-Token": self._token(client)},
        )
        assert response.status_code == 200, response.text

    def _delete(self, client, identifier: str):
        return client.request("DELETE", f"/api/devices/{identifier}", headers={"X-CSRF-Token": self._token(client)})

    def test_delete_removes_the_device_from_the_dashboard(self, tmp_path: Path):
        client = build_client(tmp_path)
        login(client)
        self._add(client)
        assert client.get("/api/devices").json()["devices"]
        response = self._delete(client, "r1")
        assert response.status_code == 200, response.text
        assert response.json() == {"deleted": "r1"}
        assert client.get("/api/devices").json()["devices"] == []

    def test_delete_also_destroys_the_stored_password(self, tmp_path: Path):
        app = build_app(tmp_path)
        manager = app.state.manager
        with TestClient(app) as client:
            login(client)
            self._add(client, password="super-secret-value")
            reference = manager.get_device("r1").password_ref
            assert manager.secrets.has(reference)
            self._delete(client, "r1")
            assert not manager.secrets.has(reference), "the password outlived the device"

    def test_delete_is_covered_by_csrf_protection(self, tmp_path: Path):
        client = build_client(tmp_path)
        login(client)
        self._add(client)
        response = client.request("DELETE", "/api/devices/r1")  # no CSRF header
        assert response.status_code == 403, response.text
        assert client.get("/api/devices").json()["devices"], "device was removed despite a failed CSRF check"

    def test_deleting_an_unknown_device_reports_not_found(self, tmp_path: Path):
        client = build_client(tmp_path)
        login(client)
        assert self._delete(client, "nope").status_code == 404

    def test_delete_requires_authentication(self, tmp_path: Path):
        client = build_client(tmp_path)
        assert client.request("DELETE", "/api/devices/r1").status_code == 401

    def test_a_shared_password_is_kept_for_the_remaining_device(self, tmp_path: Path):
        """Two devices may point at one stored password; do not delete it early."""
        app = build_app(tmp_path)
        manager = app.state.manager
        with TestClient(app) as client:
            login(client)
            self._add(client, identifier="r1", password="shared-secret")
            reference = manager.get_device("r1").password_ref
            # Point a second device at the same stored password.
            manager.add_device("r2", "192.168.1.2", "cudy", password_ref=reference)
            self._delete(client, "r1")
            assert manager.secrets.has(reference), "a password still in use was deleted"

    def test_dashboard_offers_a_remove_control(self, tmp_path: Path):
        client = build_client(tmp_path)
        login(client)
        body = client.get("/").text
        assert "removeDevice" in body
        assert "`/api/devices/${enc(r.id)}`, { method: 'DELETE' }" in body


class TestConfigLocation:
    """The device config must not default to a path inside the package.

    A tracked file inside the repo meant every device the operator added landed
    in a git-visible location, one ``git add -A`` away from being published.
    """

    def test_default_config_sits_beside_the_vault(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        state = tmp_path / "state"
        monkeypatch.delenv("ROUTER_MANAGER_CONFIG", raising=False)
        monkeypatch.setenv("ROUTER_MANAGER_DATA_DIR", str(state))
        assert Settings.from_env().config_path == state / "cudy_devices.yaml"

    def test_the_package_directory_is_not_the_default_config_location(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("ROUTER_MANAGER_CONFIG", raising=False)
        settings = Settings.from_env()
        package_dir = Path(__file__).resolve().parents[1] / "cudy_manager"
        assert package_dir not in settings.config_path.parents, "config would be written inside the repo"

    def test_an_explicit_override_still_wins(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        custom = tmp_path / "custom.yaml"
        monkeypatch.setenv("ROUTER_MANAGER_CONFIG", str(custom))
        assert Settings.from_env().config_path == custom

    def test_an_empty_data_dir_does_not_mean_the_working_directory(self, monkeypatch: pytest.MonkeyPatch):
        """An unset-but-present env var used to resolve to Path(""), i.e. "."."""
        monkeypatch.setenv("ROUTER_MANAGER_DATA_DIR", "")
        monkeypatch.delenv("ROUTER_MANAGER_CONFIG", raising=False)
        settings = Settings.from_env()
        assert settings.data_dir != Path(".")
        assert settings.config_path.is_absolute()

    def test_importing_web_writes_nothing_to_the_working_directory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        import importlib
        import sys

        work = tmp_path / "work"
        home = tmp_path / "home"
        work.mkdir()
        home.mkdir()
        monkeypatch.chdir(work)
        # An eager app would write under the default state dir, which lives in
        # $HOME rather than the working directory, so point HOME somewhere watched
        # instead of letting a regression touch the developer's real vault.
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.delenv("ROUTER_MANAGER_DATA_DIR", raising=False)
        monkeypatch.delenv("ROUTER_MANAGER_CONFIG", raising=False)
        monkeypatch.delitem(sys.modules, "cudy_manager.web", raising=False)
        module = importlib.import_module("cudy_manager.web")
        assert "app" not in vars(module), "the app was built at import time"
        assert list(work.iterdir()) == [], "importing the module touched the working directory"
        assert list(home.iterdir()) == [], "importing the module touched the default state directory"


def _post_guesses(client: TestClient, count: int, **kwargs) -> list[int]:
    return [
        client.post("/login", json={"username": "admin", "password": "wrong"}, **kwargs).status_code
        for _ in range(count)
    ]


class TestLoginLimiterUnderConcurrency:
    """The limit must hold for guesses sent in parallel, not only one at a time."""

    def test_parallel_guesses_from_one_address_are_limited(self, tmp_path: Path):
        import asyncio

        import httpx

        app = build_app(tmp_path)

        async def burst() -> list[int]:
            transport = httpx.ASGITransport(app=app, client=("10.0.0.5", 1234))
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                responses = await asyncio.gather(
                    *(client.post("/login", json={"username": "admin", "password": "wrong"}) for _ in range(40))
                )
            return [response.status_code for response in responses]

        codes = asyncio.run(burst())
        assert codes.count(401) == 5, codes
        assert codes.count(429) == 35, codes

    def test_attempt_reserves_a_slot_atomically(self):
        from cudy_manager.web import LoginLimiter

        limiter = LoginLimiter(maximum=3, window_seconds=60)
        assert [limiter.attempt("k") for _ in range(5)] == [True, True, True, False, False]
        assert len(limiter._values["k"]) == 3, "a refused attempt must not grow the list"
        limiter.success("k")
        assert limiter.attempt("k")

    def test_a_malformed_body_still_counts_as_an_attempt(self, tmp_path: Path):
        client = build_client(tmp_path)
        for _ in range(5):
            client.post("/login", content=b"{not json", headers={"Content-Type": "application/json"})
        assert client.post("/login", json={"username": "admin", "password": PASSWORD}).status_code == 429


class TestProxyHeaderTrust:
    """Throttling must key on an address the caller cannot choose."""

    def test_uvicorn_proxy_rewrite_cannot_mint_a_fresh_bucket_per_guess(self, tmp_path: Path, monkeypatch):
        from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

        monkeypatch.delenv("ROUTER_MANAGER_TRUST_PROXY", raising=False)
        # uvicorn.run() wraps the app like this by default and trusts loopback peers.
        wrapped = ProxyHeadersMiddleware(build_app(tmp_path), trusted_hosts="127.0.0.1,::1")
        client = TestClient(wrapped, client=("127.0.0.1", 5555))
        codes = [
            client.post(
                "/login",
                json={"username": "admin", "password": "wrong"},
                headers={"X-Forwarded-For": f"198.51.100.{index}"},
            ).status_code
            for index in range(25)
        ]
        assert codes.count(401) == 5, codes
        response = client.post(
            "/login",
            json={"username": "admin", "password": PASSWORD},
            headers={"X-Forwarded-For": "198.51.100.200"},
        )
        assert response.status_code == 429

    def test_a_direct_peer_keeps_its_own_bucket_despite_a_forged_header(self, monkeypatch):
        from starlette.datastructures import Headers

        from cudy_manager.web import _client_key

        monkeypatch.delenv("ROUTER_MANAGER_TRUST_PROXY", raising=False)

        class FakeRequest:
            client = type("C", (), {"host": "192.0.2.10"})()
            headers = Headers(raw=[(b"x-forwarded-for", b"1.2.3.4")])

        assert _client_key(FakeRequest()) == "192.0.2.10"

    def test_trusted_proxy_uses_the_address_the_proxy_appended(self, tmp_path: Path, monkeypatch):
        monkeypatch.setenv("ROUTER_MANAGER_TRUST_PROXY", "1")
        client = build_client(tmp_path)
        codes = [
            client.post(
                "/login",
                json={"username": "admin", "password": "wrong"},
                # nginx's $proxy_add_x_forwarded_for keeps what the client sent and
                # appends the real peer, 192.0.2.77.
                headers={"X-Forwarded-For": f"203.0.113.{index}, 192.0.2.77"},
            ).status_code
            for index in range(25)
        ]
        assert codes.count(401) == 5, codes
        assert codes.count(429) == 20, codes

    def test_trusted_proxy_reads_every_forwarded_header_line(self, monkeypatch):
        from starlette.datastructures import Headers

        from cudy_manager.web import _client_key

        monkeypatch.setenv("ROUTER_MANAGER_TRUST_PROXY", "1")

        class FakeRequest:
            client = type("C", (), {"host": "127.0.0.1"})()
            # A proxy may add its own header line instead of extending the client's.
            headers = Headers(raw=[(b"x-forwarded-for", b"6.6.6.6"), (b"x-forwarded-for", b"5.5.5.5")])

        assert _client_key(FakeRequest()) == "5.5.5.5"

    def test_a_peer_is_only_pooled_when_it_is_exactly_a_forwarded_hop(self, monkeypatch):
        """A substring match put 10.0.0.1 in the shared bucket because of 10.0.0.12."""
        from starlette.datastructures import Headers

        from cudy_manager.web import _client_key

        monkeypatch.delenv("ROUTER_MANAGER_TRUST_PROXY", raising=False)

        class FakeRequest:
            client = type("C", (), {"host": "10.0.0.1"})()
            headers = Headers(raw=[(b"x-forwarded-for", b"10.0.0.12")])

        assert _client_key(FakeRequest()) == "10.0.0.1"


class TestHostileRequestBodies:
    """Bad input from anyone who can reach /login must not produce a 500."""

    def _assert_hardened(self, response):
        assert "Content-Security-Policy" in response.headers
        assert response.headers["X-Frame-Options"] == "DENY"

    def test_deeply_nested_json_is_a_client_error(self, tmp_path: Path):
        client = TestClient(build_app(tmp_path), raise_server_exceptions=False)
        response = client.post("/login", content=b"[" * 50000, headers={"Content-Type": "application/json"})
        assert response.status_code == 400, response.text
        self._assert_hardened(response)

    def test_an_oversized_body_is_refused(self, tmp_path: Path):
        client = TestClient(build_app(tmp_path), raise_server_exceptions=False)
        response = client.post("/login", content=b" " * (1024 * 1024), headers={"Content-Type": "application/json"})
        assert response.status_code == 413, response.text
        self._assert_hardened(response)

    def test_an_oversized_chunked_body_is_refused(self, tmp_path: Path):
        client = TestClient(build_app(tmp_path), raise_server_exceptions=False)

        # No Content-Length, so only counting while reading can catch it.
        def chunks():
            for _ in range(64):
                yield b" " * 16384

        response = client.post("/login", content=chunks(), headers={"Content-Type": "application/json"})
        assert response.status_code == 413, response.text

    def test_lone_surrogates_in_credentials_are_rejected_not_crashed(self, tmp_path: Path):
        client = TestClient(build_app(tmp_path), raise_server_exceptions=False)
        for body in (b'{"username":"\\ud800","password":"x"}', b'{"username":"admin","password":"\\ud800"}'):
            response = client.post("/login", content=body, headers={"Content-Type": "application/json"})
            assert response.status_code == 401, response.text
            self._assert_hardened(response)

    def test_non_ascii_csrf_header_is_a_csrf_failure(self, tmp_path: Path):
        client = TestClient(build_app(tmp_path), raise_server_exceptions=False)
        login(client)
        for path in ("/logout", "/api/devices/x/reboot"):
            response = client.post(path, json={"confirm": True}, headers={"X-CSRF-Token": b"\xe9t\xe9"})
            assert response.status_code == 403, response.text
            self._assert_hardened(response)
        assert client.get("/api/devices").status_code == 200, "the session must survive a refused logout"

    def test_an_unexpected_error_still_gets_the_security_headers(self, tmp_path: Path, monkeypatch):
        app = build_app(tmp_path)

        def explode(include_status):
            raise RuntimeError("secret internal detail")

        monkeypatch.setattr(app.state.manager, "dashboard", explode)
        client = TestClient(app, raise_server_exceptions=False)
        login(client)
        response = client.get("/api/devices")
        assert response.status_code == 500
        assert "secret internal detail" not in response.text
        self._assert_hardened(response)


class TestLoginPageWithoutJavaScript:
    def test_form_never_submits_the_password_in_the_url(self, tmp_path: Path):
        page = build_client(tmp_path).get("/login").text
        assert "<form id=login method=post action=/login>" in page

    def test_script_shows_a_message_when_the_reply_is_not_json(self, tmp_path: Path):
        page = build_client(tmp_path).get("/login").text
        assert "response.json().catch(" in page


class TestSsidRoute:
    def _add(self, client: TestClient, token: str, vendor: str = "tenda") -> None:
        response = client.post(
            "/api/devices",
            json={"id": "r1", "host": "192.0.2.1", "vendor": vendor, "password": "p"},
            headers={"X-CSRF-Token": token},
        )
        assert response.status_code == 200, response.text

    def test_invalid_radio_values_are_rejected_before_the_router_is_contacted(self, tmp_path: Path, monkeypatch):
        app = build_app(tmp_path)
        calls = []
        monkeypatch.setattr(app.state.manager, "set_wifi_ssid", lambda *args, **_: calls.append(args) or True)
        client = TestClient(app, raise_server_exceptions=False)
        token = login(client)
        self._add(client, token)
        for radio in (["5G"], {"band": "5G"}, 5, "6G", "", True):
            response = client.post(
                "/api/devices/r1/ssid", json={"ssid": "x", "radio": radio}, headers={"X-CSRF-Token": token}
            )
            assert response.status_code == 400, (radio, response.text)
            assert "radio" in response.json()["detail"]
        assert calls == []

    def test_valid_radio_values_reach_the_manager(self, tmp_path: Path, monkeypatch):
        app = build_app(tmp_path)
        calls = []
        monkeypatch.setattr(app.state.manager, "set_wifi_ssid", lambda *args, **_: calls.append(args) or True)
        client = TestClient(app)
        token = login(client)
        self._add(client, token)
        for radio in ("2.4G", "5G", None):
            body = {"ssid": "Home"} if radio is None else {"ssid": "Home", "radio": radio}
            response = client.post("/api/devices/r1/ssid", json=body, headers={"X-CSRF-Token": token})
            assert response.status_code == 200, response.text
        assert calls == [("r1", "Home", "2.4G"), ("r1", "Home", "5G"), ("r1", "Home", None)]

    def test_an_ssid_with_no_utf8_form_is_a_bad_request_not_a_server_error(self, tmp_path: Path, monkeypatch):
        app = build_app(tmp_path)
        client = TestClient(app, raise_server_exceptions=False)
        token = login(client)
        self._add(client, token, vendor="cudy")
        monkeypatch.setattr(app.state.manager, "adapter_for", lambda device: pytest.fail("the router was contacted"))
        response = client.post(
            "/api/devices/r1/ssid",
            content=b'{"ssid": "ab\\ud800cd"}',
            headers={"X-CSRF-Token": token, "Content-Type": "application/json"},
        )
        assert response.status_code == 400, response.text
        assert "Unicode" in response.json()["detail"]

    def test_an_unsupported_operation_is_not_a_gateway_error(self, tmp_path: Path):
        client = build_client(tmp_path)
        token = login(client)
        # TP-Link SSID writes stay excluded on purpose; Cudy web gained them from real firmware.
        self._add(client, token, vendor="tplink")
        response = client.post("/api/devices/r1/ssid", json={"ssid": "x"}, headers={"X-CSRF-Token": token})
        assert response.status_code == 501, response.text
        assert "not supported" in response.json()["detail"]


class TestDiscoverRoute:
    def test_subnet_validation_messages_reach_the_operator(self, tmp_path: Path):
        client = build_client(tmp_path)
        token = login(client)
        for subnet, expected in (("10.0.0.0/16", "too large"), ("not-a-subnet", "valid CIDR")):
            response = client.post("/api/discover", json={"subnet": subnet}, headers={"X-CSRF-Token": token})
            assert response.status_code == 400
            assert expected in response.json()["detail"], response.text

    def test_only_one_scan_runs_at_a_time(self, tmp_path: Path, monkeypatch):
        import threading

        app = build_app(tmp_path)
        started = threading.Event()
        release = threading.Event()

        def slow_scan(subnet):
            started.set()
            release.wait(5)
            return []

        monkeypatch.setattr(app.state.manager, "discover_network", slow_scan)
        with TestClient(app) as client:
            token = login(client)
            headers = {"X-CSRF-Token": token}
            first: dict[str, int] = {}

            def scan() -> None:
                response = client.post("/api/discover", json={"subnet": "192.0.2.0/24"}, headers=headers)
                first["status"] = response.status_code

            worker = threading.Thread(target=scan)
            worker.start()
            assert started.wait(5)
            timer = threading.Timer(2.0, release.set)
            timer.start()
            try:
                second = client.post("/api/discover", json={"subnet": "192.0.2.0/24"}, headers=headers)
            finally:
                release.set()
                timer.cancel()
                worker.join()
            assert second.status_code == 409, second.text
            assert first["status"] == 200
            # The guard is released once the scan finishes.
            assert client.post("/api/discover", json={"subnet": "192.0.2.0/24"}, headers=headers).status_code == 200


class TestSchedulerOutcomesAreLogged:
    def test_a_failed_scheduled_reboot_is_logged(self, tmp_path: Path, monkeypatch, caplog):
        """run_once's results were discarded, so a reboot that never happened left no trace."""
        import logging
        import time

        from cudy_manager.scheduler import RebootScheduler

        monkeypatch.setattr(
            RebootScheduler,
            "run_once",
            lambda self, now=None: [{"device": "r1", "status": "failed", "reason": "reboot policy is invalid"}],
        )
        caplog.set_level(logging.INFO, logger="cudy_manager.web")
        with TestClient(build_app(tmp_path)):
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and "scheduled reboot of r1 failed" not in caplog.text:
                time.sleep(0.05)
        assert "scheduled reboot of r1 failed: reboot policy is invalid" in caplog.text
