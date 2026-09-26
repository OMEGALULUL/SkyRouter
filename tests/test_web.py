from pathlib import Path

from fastapi.testclient import TestClient

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
            def run_once(self):
                calls.append(1)
                return []

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

    def test_login_rejects_bad_username(self, tmp_path: Path):
        client = build_client(tmp_path)
        assert client.post("/login", json={"username": "root", "password": PASSWORD}).status_code == 401

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
        assert response.status_code == 502
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
        monkeypatch.setenv("ROUTER_MANAGER_TRUST_PROXY", "1")
        from cudy_manager.web import _client_key

        class FakeRequest:
            client = type("C", (), {"host": "127.0.0.1"})()
            headers = {"x-forwarded-for": "5.6.7.8, 9.9.9.9"}

        assert _client_key(FakeRequest()) == "5.6.7.8"

    def test_socket_peer_is_used_when_not_trusted(self, monkeypatch):
        monkeypatch.delenv("ROUTER_MANAGER_TRUST_PROXY", raising=False)
        from cudy_manager.web import _client_key

        class FakeRequest:
            client = type("C", (), {"host": "127.0.0.1"})()
            headers = {"x-forwarded-for": "1.2.3.4"}

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
            limiter.fail(f"10.0.0.{index}")
        assert len(limiter._values) == 200
        time.sleep(1.1)
        for index in range(50):
            limiter.blocked(f"10.0.0.{index}")
        assert len(limiter._values) == 0

    def test_key_count_is_capped(self):
        from cudy_manager.web import LoginLimiter

        limiter = LoginLimiter(max_keys=100)
        for index in range(5000):
            limiter.fail(f"10.{(index // 256) % 256}.{index % 256}.{index // 65536}")
        assert len(limiter._values) <= 100

    def test_throttling_still_works(self):
        from cudy_manager.web import LoginLimiter

        limiter = LoginLimiter(maximum=3, window_seconds=60)
        for _ in range(3):
            limiter.fail("1.2.3.4")
        assert limiter.blocked("1.2.3.4")
        assert not limiter.blocked("5.6.7.8")
        limiter.success("1.2.3.4")
        assert not limiter.blocked("1.2.3.4")


class TestLoginTiming:
    def test_username_is_always_compared(self, tmp_path: Path, monkeypatch):
        """A wrong username must still run the password comparison."""
        import hmac

        app = build_app(tmp_path)
        calls: list[bytes] = []
        original = hmac.compare_digest

        def counting(a, b):
            calls.append(a)
            return original(a, b)

        monkeypatch.setattr("cudy_manager.web.hmac.compare_digest", counting)
        with TestClient(app) as client:
            client.post("/login", json={"username": "wrong", "password": PASSWORD})

        assert len(calls) == 2, "password comparison was skipped for a bad username"


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
            "refresh-button",
            "add-button",
            "discover-button",
            "logout-button",
            "add-cancel",
            "password-cancel",
        )
        for control in controls:
            assert f'id="{control}"' in body
            assert f"'{control}'" in body

    def test_policy_is_also_set_on_error_responses(self, tmp_path: Path):
        client = build_client(tmp_path)
        response = client.get("/api/devices")
        assert response.status_code == 401
        assert "Content-Security-Policy" in response.headers
