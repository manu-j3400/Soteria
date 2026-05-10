"""
Pytest fixtures for backend/tests/test_middleware.py.
Mirrors the setup in tests/conftest.py for the project-root test suite.
"""
import os
import pytest

# Set required env vars before middleware.app is imported
os.environ.setdefault('JWT_SECRET', 'ci-test-jwt-secret-do-not-use-in-prod')
os.environ.setdefault('GITHUB_CLIENT_ID', 'test-client-id-xxxxxx')
os.environ.setdefault('GITHUB_CLIENT_SECRET', 'test-client-secret-xxxxxx')
os.environ.setdefault('MAKE_WEBHOOK_SECRET', 'ci-test-secret')


@pytest.fixture(autouse=True)
def clear_rate_limits():
    """Reset rate limit buckets between tests to prevent cross-test pollution."""
    from middleware.app import RATE_LIMITS, RATE_LIMIT_LOCK
    with RATE_LIMIT_LOCK:
        RATE_LIMITS.clear()
    yield
    with RATE_LIMIT_LOCK:
        RATE_LIMITS.clear()
