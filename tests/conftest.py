"""
Pytest fixtures for Soteria middleware tests.
Sets required environment variables BEFORE app import to prevent startup errors.
"""
import os
import pytest

# Must be set before middleware.app is imported
os.environ.setdefault('JWT_SECRET', 'ci-test-jwt-secret-do-not-use-in-prod')
os.environ.setdefault('GITHUB_CLIENT_ID', 'test-client-id-xxxxxx')
os.environ.setdefault('GITHUB_CLIENT_SECRET', 'test-client-secret-xxxxxx')
os.environ.setdefault('MAKE_WEBHOOK_SECRET', 'test_secret_for_ci')
os.environ.setdefault('ADMIN_PASSWORD', 'ci-test-admin-pw')


@pytest.fixture(scope='session')
def app():
    from middleware.app import app as flask_app, init_scan_db, init_users_db
    flask_app.config['TESTING'] = True
    flask_app.config['WTF_CSRF_ENABLED'] = False
    init_scan_db()
    init_users_db()
    yield flask_app


@pytest.fixture(scope='session')
def client(app):
    return app.test_client()


@pytest.fixture(autouse=True)
def clear_rate_limits():
    """Reset rate limit buckets between tests."""
    from middleware.app import RATE_LIMITS, RATE_LIMIT_LOCK
    with RATE_LIMIT_LOCK:
        RATE_LIMITS.clear()
    yield
    with RATE_LIMIT_LOCK:
        RATE_LIMITS.clear()
