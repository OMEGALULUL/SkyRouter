from pathlib import Path

from fastapi.testclient import TestClient

from cudy_manager.manager import DeviceManager
from cudy_manager.secrets import SecretStore
from cudy_manager.web import Settings, create_app

PASSWORD = "correct horse battery staple"


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
