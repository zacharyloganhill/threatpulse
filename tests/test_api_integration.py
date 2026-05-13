"""
HTTP integration tests — exercises the full FastAPI middleware stack,
auth dependencies, CORS, and route composition using TestClient.

These catch regressions that unit tests can't: wrong dependency wiring,
missing auth on a route, middleware ordering bugs, etc.

Run: python -m pytest tests/test_api_integration.py -v
"""

import os
import sys

# Must be set before any app imports
os.environ["DB_PATH"] = ":memory:"
os.environ["SECRET_KEY"] = "test-secret-key-not-for-production"
os.environ["ADMIN_PASSWORD"] = "Admin1!"

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from unittest.mock import patch, AsyncMock


# ── App fixture ───────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def client():
    """Start the app with scheduler and initial poll disabled."""
    with (
        patch("ingest.scheduler.start_scheduler"),
        patch("ingest.scheduler.stop_scheduler"),
        patch("ingest.scheduler.run_all", new_callable=AsyncMock, return_value={}),
        patch("threat_actors.seed_data.seed_threat_actors", new_callable=AsyncMock, return_value=0),
    ):
        from fastapi.testclient import TestClient
        import main
        with TestClient(main.app, raise_server_exceptions=True) as c:
            yield c


@pytest.fixture(scope="module")
def admin_token(client):
    resp = client.post("/auth/login", json={"username": "admin", "password": "Admin1!"})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


@pytest.fixture(scope="module")
def admin_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


# ── Auth endpoint tests ───────────────────────────────────────────────────────

class TestAuthEndpoints:
    def test_login_success(self, client):
        resp = client.post("/auth/login", json={"username": "admin", "password": "Admin1!"})
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["role"] == "admin"

    def test_login_wrong_password(self, client):
        resp = client.post("/auth/login", json={"username": "admin", "password": "wrong"})
        assert resp.status_code == 401

    def test_login_empty_username_rejected(self, client):
        resp = client.post("/auth/login", json={"username": "", "password": "Admin1!"})
        assert resp.status_code == 422

    def test_me_requires_auth(self, client):
        resp = client.get("/auth/me")
        assert resp.status_code == 401

    def test_me_returns_user(self, client, admin_headers):
        resp = client.get("/auth/me", headers=admin_headers)
        assert resp.status_code == 200
        assert resp.json()["username"] == "admin"

    def test_logout_revokes_token(self, client, admin_token):
        # Get a fresh token to revoke
        resp = client.post("/auth/login", json={"username": "admin", "password": "Admin1!"})
        token = resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        logout = client.post("/auth/logout", headers=headers)
        assert logout.status_code == 200

        # Token must be rejected after logout
        me = client.get("/auth/me", headers=headers)
        assert me.status_code == 401


# ── Security headers ──────────────────────────────────────────────────────────

class TestSecurityHeaders:
    def test_csp_present(self, client, admin_headers):
        resp = client.get("/api/v1/stats", headers=admin_headers)
        assert "content-security-policy" in resp.headers

    def test_x_content_type_options(self, client, admin_headers):
        resp = client.get("/api/v1/stats", headers=admin_headers)
        assert resp.headers.get("x-content-type-options") == "nosniff"

    def test_x_frame_options(self, client, admin_headers):
        resp = client.get("/api/v1/stats", headers=admin_headers)
        assert resp.headers.get("x-frame-options") == "DENY"


# ── Docs require auth ─────────────────────────────────────────────────────────

class TestDocsAuth:
    def test_docs_unauthenticated_rejected(self, client):
        resp = client.get("/docs", follow_redirects=False)
        assert resp.status_code == 401

    def test_openapi_unauthenticated_rejected(self, client):
        resp = client.get("/openapi.json", follow_redirects=False)
        assert resp.status_code == 401

    def test_docs_authenticated(self, client, admin_headers):
        resp = client.get("/docs", headers=admin_headers)
        assert resp.status_code == 200


# ── Threat items endpoints ────────────────────────────────────────────────────

class TestItemsEndpoints:
    def test_list_items_requires_auth(self, client):
        resp = client.get("/api/v1/items")
        assert resp.status_code == 401

    def test_list_items_authenticated(self, client, admin_headers):
        resp = client.get("/api/v1/items", headers=admin_headers)
        assert resp.status_code == 200
        assert "items" in resp.json()

    def test_stats_requires_auth(self, client):
        resp = client.get("/api/v1/stats")
        assert resp.status_code == 401

    def test_stats_non_admin_strips_sensitive_fields(self, client, admin_headers):
        # Create an analyst user
        create = client.post(
            "/api/v1/admin/users",
            json={"username": "analyst_test", "password": "Analyst1!", "role": "analyst"},
            headers=admin_headers,
        )
        assert create.status_code == 200

        analyst_login = client.post("/auth/login", json={"username": "analyst_test", "password": "Analyst1!"})
        analyst_headers = {"Authorization": f"Bearer {analyst_login.json()['access_token']}"}

        resp = client.get("/api/v1/stats", headers=analyst_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "client_count" not in data
        assert "scanner_count" not in data


# ── Admin-only enforcement ────────────────────────────────────────────────────

class TestAdminEnforcement:
    def test_refresh_requires_admin(self, client, admin_headers):
        # Create an analyst user
        client.post(
            "/api/v1/admin/users",
            json={"username": "analyst_refresh", "password": "Analyst1!", "role": "analyst"},
            headers=admin_headers,
        )
        login = client.post("/auth/login", json={"username": "analyst_refresh", "password": "Analyst1!"})
        ah = {"Authorization": f"Bearer {login.json()['access_token']}"}

        resp = client.post("/api/v1/refresh", headers=ah)
        assert resp.status_code == 403

    def test_purge_requires_admin(self, client, admin_headers):
        create = client.post(
            "/api/v1/admin/users",
            json={"username": "analyst_purge", "password": "Analyst1!", "role": "analyst"},
            headers=admin_headers,
        )
        login = client.post("/auth/login", json={"username": "analyst_purge", "password": "Analyst1!"})
        ah = {"Authorization": f"Bearer {login.json()['access_token']}"}

        resp = client.delete("/api/v1/items/purge", headers=ah)
        assert resp.status_code == 403


# ── IDOR protection ───────────────────────────────────────────────────────────

class TestIDORProtection:
    def test_non_admin_cannot_access_other_client_ksi(self, client, admin_headers):
        # Create a client + user
        c1 = client.post("/api/v1/admin/clients", json={"name": "Client A"}, headers=admin_headers)
        client_a_id = c1.json()["id"]

        client.post(
            "/api/v1/admin/users",
            json={"username": "user_a", "password": "UserPassA1!", "role": "analyst", "client_id": client_a_id},
            headers=admin_headers,
        )
        login_a = client.post("/auth/login", json={"username": "user_a", "password": "UserPassA1!"})
        headers_a = {"Authorization": f"Bearer {login_a.json()['access_token']}"}

        # Create another client
        c2 = client.post("/api/v1/admin/clients", json={"name": "Client B"}, headers=admin_headers)
        client_b_id = c2.json()["id"]

        # user_a must not be able to read client_b's KSI results
        resp = client.get(f"/api/v1/clients/{client_b_id}/ksi", headers=headers_a)
        assert resp.status_code == 403


# ── Per-user read state ───────────────────────────────────────────────────────

class TestPerUserReadState:
    def test_mark_read_is_per_user(self, client, admin_headers):
        """Marking an item read for user A must not affect user B's view."""
        from db import database as db
        import uuid

        # Run the seed inside TestClient's own event loop so it shares the same
        # in-memory DB that the running app uses (avoids replacing _db).
        async def _seed():
            item_id = str(uuid.uuid4())[:24]
            await db.get_db().execute(
                "INSERT OR IGNORE INTO threat_items "
                "(id, feed_id, feed_label, title, description, severity, category, "
                " published_at, fetched_at, is_new) VALUES (?,?,?,?,?,?,?,?,?,1)",
                (item_id, "test", "Test", "Test Item", "", "HIGH", "cve",
                 "2025-01-01", "2025-01-01"),
            )
            await db.get_db().commit()
            return item_id

        item_id = client.portal.call(_seed)

        # Create two users
        client.post(
            "/api/v1/admin/users",
            json={"username": "read_user_a", "password": "ReadPassA1!", "role": "analyst"},
            headers=admin_headers,
        )
        client.post(
            "/api/v1/admin/users",
            json={"username": "read_user_b", "password": "ReadPassB1!", "role": "analyst"},
            headers=admin_headers,
        )
        login_a = client.post("/auth/login", json={"username": "read_user_a", "password": "ReadPassA1!"})
        login_b = client.post("/auth/login", json={"username": "read_user_b", "password": "ReadPassB1!"})
        ha = {"Authorization": f"Bearer {login_a.json()['access_token']}"}
        hb = {"Authorization": f"Bearer {login_b.json()['access_token']}"}

        # User A marks item as read
        resp = client.post(f"/api/v1/items/{item_id}/read", headers=ha)
        assert resp.status_code == 200

        # User A should not see it in is_new=true
        items_a = client.get("/api/v1/items?is_new=true", headers=ha).json()["items"]
        assert all(i["id"] != item_id for i in items_a), "User A should not see item as new"

        # User B must still see it as new
        items_b = client.get("/api/v1/items?is_new=true", headers=hb).json()["items"]
        assert any(i["id"] == item_id for i in items_b), "User B should still see item as new"


# ── Health endpoint ──────────────────────────────────────────────────────────

class TestHealthEndpoint:
    def test_health_unauthenticated(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_health_db_field_present(self, client):
        assert "db" in client.get("/health").json()


# ── Request correlation ID ────────────────────────────────────────────────────

class TestCorrelationID:
    def test_response_includes_x_request_id(self, client, admin_headers):
        resp = client.get("/api/v1/stats", headers=admin_headers)
        assert "x-request-id" in resp.headers, "Every API response must carry X-Request-ID"

    def test_client_supplied_request_id_is_echoed(self, client, admin_headers):
        custom_id = "test-correlation-abc-123"
        resp = client.get(
            "/api/v1/stats",
            headers={**admin_headers, "X-Request-ID": custom_id},
        )
        assert resp.headers.get("x-request-id") == custom_id


# ── Concurrent session cap ────────────────────────────────────────────────────

class TestSessionCap:
    def test_session_cap_enforced(self, client, admin_headers):
        """6th concurrent login for the same user must return 429."""
        from db.database import MAX_SESSIONS
        client.post(
            "/api/v1/admin/users",
            json={"username": "cap_user", "password": "CapPass1!", "role": "analyst"},
            headers=admin_headers,
        )
        creds = {"username": "cap_user", "password": "CapPass1!"}
        for i in range(MAX_SESSIONS):
            resp = client.post("/auth/login", json=creds)
            assert resp.status_code == 200, f"Login {i+1} should succeed"

        resp = client.post("/auth/login", json=creds)
        assert resp.status_code == 429, "Login beyond cap must be rejected"
        assert "session" in resp.json()["detail"].lower()

    def test_logout_frees_session_slot(self, client, admin_headers):
        """Logging out of one session allows a new login to succeed."""
        from db.database import MAX_SESSIONS
        client.post(
            "/api/v1/admin/users",
            json={"username": "cap_logout_user", "password": "CapPass2!", "role": "analyst"},
            headers=admin_headers,
        )
        creds = {"username": "cap_logout_user", "password": "CapPass2!"}
        tokens = []
        for _ in range(MAX_SESSIONS):
            resp = client.post("/auth/login", json=creds)
            assert resp.status_code == 200
            tokens.append(resp.json()["access_token"])

        # Logout one session
        client.post(
            "/auth/logout",
            headers={"Authorization": f"Bearer {tokens[0]}"},
        )

        # Now a new login must succeed
        resp = client.post("/auth/login", json=creds)
        assert resp.status_code == 200, "Login should succeed after freeing a session slot"
