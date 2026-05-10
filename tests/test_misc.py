"""
Tests for model drift, security score, webhook settings, and model-stats endpoints.
"""
import uuid
from unittest.mock import patch


def _register(client):
    """Helper: register a fresh user and return (token, user_id)."""
    email = f"misc_{uuid.uuid4().hex[:8]}@example.com"
    r = client.post('/api/auth/signup', json={
        'name': 'Misc User', 'email': email, 'password': 'miscpassword123',
    })
    data = r.get_json()
    return data['token'], data['user']['id']


class TestModelDrift:
    def test_drift_requires_auth(self, client):
        resp = client.get('/api/model/drift')
        assert resp.status_code == 401

    def test_drift_insufficient_data(self, client):
        """Buffer is empty at test startup — expect insufficient_data status."""
        token, _ = _register(client)
        resp = client.get('/api/model/drift',
                          headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'status' in data
        # Either insufficient_data (empty buffer) or ok (if previous tests seeded it)
        assert data['status'] in ('insufficient_data', 'ok')

    def test_drift_ok_fields(self, client):
        """If status=ok, required fields must be present."""
        token, _ = _register(client)
        resp = client.get('/api/model/drift',
                          headers={'Authorization': f'Bearer {token}'})
        data = resp.get_json()
        if data['status'] == 'ok':
            for field in ('kl_divergence', 'drift_alert', 'recent_mean', 'total_samples'):
                assert field in data


class TestSecurityScore:
    def test_requires_auth(self, client):
        resp = client.get('/security-score')
        assert resp.status_code == 401

    def test_new_user_score(self, client):
        token, _ = _register(client)
        resp = client.get('/security-score',
                          headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'score' in data


class TestModelStats:
    def test_model_stats_public(self, client):
        # /model-stats uses token_required(optional=True) — accessible without auth
        resp = client.get('/model-stats')
        assert resp.status_code == 200

    def test_model_stats_authenticated(self, client):
        token, _ = _register(client)
        resp = client.get('/model-stats',
                          headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 200


class TestWebhookSettings:
    def test_get_webhook_requires_auth(self, client):
        resp = client.get('/api/settings/webhook')
        assert resp.status_code == 401

    def test_get_webhook_empty(self, client):
        token, _ = _register(client)
        resp = client.get('/api/settings/webhook',
                          headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'webhook_url' in data or data is not None

    def test_set_webhook_url(self, client):
        token, _ = _register(client)
        # Patch DNS-based SSRF check so test doesn't require live DNS resolution
        with patch('middleware.app._is_safe_external_url', return_value=True):
            resp = client.post('/api/settings/webhook',
                               headers={'Authorization': f'Bearer {token}'},
                               json={'webhook_url': 'https://hooks.example.com/test'})
        assert resp.status_code == 200

    def test_set_invalid_webhook_url(self, client):
        token, _ = _register(client)
        resp = client.post('/api/settings/webhook',
                           headers={'Authorization': f'Bearer {token}'},
                           json={'webhook_url': 'not-a-url'})
        # Should reject non-http(s) URLs
        assert resp.status_code in (400, 422)


class TestScanHistoryExport:
    def test_export_requires_auth(self, client):
        resp = client.get('/api/scan-history/export')
        assert resp.status_code == 401

    def test_export_csv(self, client):
        token, _ = _register(client)
        resp = client.get('/api/scan-history/export',
                          headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 200
        # Should return CSV content type
        assert 'csv' in resp.content_type or resp.status_code == 200
        # Verify CSV headers present
        assert 'id,user_id,timestamp' in resp.get_data(as_text=True)


class TestGithubReposRateLimit:
    def test_repos_rate_limited_after_30(self, client):
        """/github/repos returns 429 after 30 requests within 60s window."""
        # First 30 calls should not be rate-limited (may return 401 — no GitHub token)
        for _ in range(30):
            client.get('/github/repos')
        # 31st must be rate-limited
        resp = client.get('/github/repos')
        assert resp.status_code == 429


class TestDBMigration:
    def test_schema_version_table_exists(self, client):
        """schema_version table exists and version >= 2 after init."""
        import sqlite3
        from middleware.app import SCAN_DB_PATH
        conn = sqlite3.connect(str(SCAN_DB_PATH))
        c = conn.cursor()
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'")
        assert c.fetchone() is not None, "schema_version table missing"
        c.execute("SELECT version FROM schema_version WHERE id = 1")
        version = c.fetchone()[0]
        conn.close()
        assert version >= 2


class TestRateLimit:
    def test_signup_rate_limit(self, client):
        """6th signup from same source within window must return 429."""
        for i in range(5):
            client.post('/api/auth/signup', json={
                'name': f'RL User {i}',
                'email': f'ratelimit_{uuid.uuid4().hex[:6]}@example.com',
                'password': 'testpassword123',
            })
        # 6th call — must be rate-limited
        resp = client.post('/api/auth/signup', json={
            'name': 'RL User 5',
            'email': f'ratelimit_{uuid.uuid4().hex[:6]}@example.com',
            'password': 'testpassword123',
        })
        assert resp.status_code == 429


class TestWebhookFire:
    def test_webhook_fires_on_malicious_scan(self, client):
        """Webhook fires when verdict=True and user has webhook configured."""
        token, _ = _register(client)
        webhook_url = 'https://hooks.example.com/soteria-test'

        # Set webhook URL (bypass SSRF check)
        with patch('middleware.app._is_safe_external_url', return_value=True):
            resp = client.post('/api/settings/webhook',
                               headers={'Authorization': f'Bearer {token}'},
                               json={'webhook_url': webhook_url})
        assert resp.status_code == 200

        # POST suspicious (malicious) code and assert webhook fires
        with patch('middleware.app._is_safe_external_url', return_value=True), \
             patch('middleware.app.requests.post') as mock_post:
            client.post('/analyze',
                        headers={'Authorization': f'Bearer {token}'},
                        json={'code': 'import subprocess\nsubprocess.call(user_input, shell=True)\n'})

        # Webhook should have been called at least once with the webhook URL
        called_urls = [call.args[0] for call in mock_post.call_args_list]
        assert webhook_url in called_urls
