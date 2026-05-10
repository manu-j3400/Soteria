"""
Integration tests for middleware/app.py Flask endpoints.

Run from project root:
    pytest backend/tests/ -v

Environment:
    JWT_SECRET is auto-generated at import time if not set — tests work without it.
    ML models are loaded at import; tests that hit /analyze may be slow on first run.
"""

from __future__ import annotations

import os
import sys
import json
import pytest

# Make sure project root is on the path so middleware.app can be imported.
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# ---------------------------------------------------------------------------
# App fixture — import once, share across all tests
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def app():
    """Import and configure the Flask app for testing."""
    # Suppress the JWT_SECRET warning — tests use the ephemeral secret.
    from middleware.app import app as flask_app
    flask_app.config.update({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
    })
    yield flask_app


@pytest.fixture(scope="session")
def client(app):
    return app.test_client()


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

_TEST_EMAIL = "pytest_user_soteria@example.com"
_TEST_PASS  = "PytestPass!99"


def _register_and_login(client) -> str:
    """Register (idempotent) and log in, returning a JWT token."""
    client.post(
        "/api/auth/signup",
        data=json.dumps({"name": "Pytest User", "email": _TEST_EMAIL, "password": _TEST_PASS}),
        content_type="application/json",
    )
    resp = client.post(
        "/api/auth/login",
        data=json.dumps({"email": _TEST_EMAIL, "password": _TEST_PASS}),
        content_type="application/json",
    )
    assert resp.status_code == 200, f"Login failed: {resp.data}"
    return resp.get_json()["token"]


# ---------------------------------------------------------------------------
# Auth endpoint tests
# ---------------------------------------------------------------------------

class TestAuth:
    def test_signup_and_login(self, client):
        """New user signup then login returns a JWT."""
        email = "pytest_new_user_1@example.com"
        pw    = "NewPass!1234"
        # Signup
        r = client.post(
            "/api/auth/signup",
            data=json.dumps({"name": "New User", "email": email, "password": pw}),
            content_type="application/json",
        )
        assert r.status_code in (200, 201, 409)  # 409 = already registered

        # Login
        r = client.post(
            "/api/auth/login",
            data=json.dumps({"email": email, "password": pw}),
            content_type="application/json",
        )
        if r.status_code == 200:
            data = r.get_json()
            assert "token" in data
            assert len(data["token"]) > 20

    def test_login_wrong_password(self, client):
        """Wrong password returns 401."""
        r = client.post(
            "/api/auth/login",
            data=json.dumps({"email": _TEST_EMAIL, "password": "WrongPass!"}),
            content_type="application/json",
        )
        assert r.status_code in (401, 403, 400)

    def test_me_requires_auth(self, client):
        """GET /api/auth/me without token returns 401."""
        r = client.get("/api/auth/me")
        assert r.status_code in (401, 403)


# ---------------------------------------------------------------------------
# /analyze endpoint tests
# ---------------------------------------------------------------------------

_BENIGN_PYTHON = """
def add(a, b):
    return a + b
"""

_MALICIOUS_PYTHON = """
import subprocess
import base64
cmd = base64.b64decode("d2hvYW1p").decode()
subprocess.run(cmd, shell=True)
"""

_JAVASCRIPT = """
function hello() { console.log('hello world'); }
"""


class TestAnalyze:
    def test_benign_python_200(self, client):
        """Benign Python code returns 200 with a risk_level field."""
        r = client.post(
            "/analyze",
            data=json.dumps({"code": _BENIGN_PYTHON, "language": "Python"}),
            content_type="application/json",
        )
        assert r.status_code == 200
        data = r.get_json()
        assert "risk_level" in data
        assert data["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    def test_malicious_python_detected(self, client):
        """Code with base64+subprocess pattern should not return LOW."""
        r = client.post(
            "/analyze",
            data=json.dumps({"code": _MALICIOUS_PYTHON, "language": "Python"}),
            content_type="application/json",
        )
        assert r.status_code == 200
        data = r.get_json()
        assert data["risk_level"] in ("MEDIUM", "HIGH", "CRITICAL")

    def test_javascript_200(self, client):
        """Non-Python code is supported and returns 200."""
        r = client.post(
            "/analyze",
            data=json.dumps({"code": _JAVASCRIPT, "language": "JavaScript"}),
            content_type="application/json",
        )
        assert r.status_code == 200

    def test_empty_code_rejected(self, client):
        """Empty code input is handled gracefully (400 or 200 with LOW)."""
        r = client.post(
            "/analyze",
            data=json.dumps({"code": "", "language": "Python"}),
            content_type="application/json",
        )
        assert r.status_code in (200, 400)

    def test_metadata_field_present(self, client):
        """Response includes a metadata dict."""
        r = client.post(
            "/analyze",
            data=json.dumps({"code": _BENIGN_PYTHON, "language": "Python"}),
            content_type="application/json",
        )
        assert r.status_code == 200
        data = r.get_json()
        assert "metadata" in data


# ---------------------------------------------------------------------------
# Authenticated endpoint tests
# ---------------------------------------------------------------------------

class TestAuthenticatedEndpoints:
    @pytest.fixture(autouse=True)
    def _setup_token(self, client):
        self.token = _register_and_login(client)
        self.headers = {"Authorization": f"Bearer {self.token}"}

    def test_scan_history_returns_list(self, client):
        """GET /scan-history returns a scans list for authenticated user."""
        r = client.get("/scan-history", headers=self.headers)
        assert r.status_code == 200
        data = r.get_json()
        assert "scans" in data
        assert isinstance(data["scans"], list)

    def test_scan_history_unauthenticated(self, client):
        """GET /scan-history without token returns 200 (optional auth — shows public scans)."""
        r = client.get("/scan-history")
        assert r.status_code == 200

    def test_drift_endpoint_returns_status(self, client):
        """GET /api/model/drift returns status field."""
        r = client.get("/api/model/drift", headers=self.headers)
        assert r.status_code == 200
        data = r.get_json()
        assert "status" in data
        assert data["status"] in ("ok", "insufficient_data")

    def test_drift_requires_auth(self, client):
        """GET /api/model/drift without token returns 401."""
        r = client.get("/api/model/drift")
        assert r.status_code in (401, 403)

    def test_export_csv_content_type(self, client):
        """GET /api/scan-history/export returns CSV content-type."""
        r = client.get("/api/scan-history/export", headers=self.headers)
        assert r.status_code == 200
        assert "text/csv" in r.content_type or "application/octet-stream" in r.content_type
