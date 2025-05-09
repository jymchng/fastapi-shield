import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI, Request, HTTPException, status
from fastapi_shield import shield
import time
from collections import defaultdict


# Rate Limiting Shield Example App
def create_app(max_requests=5, window_seconds=1):
    app = FastAPI()

    # Simple in-memory rate limiter
    request_counts = defaultdict(list)

    @shield(
        name="Rate Limiter",
        exception_to_raise_if_fail=HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Maximum {max_requests} requests per {window_seconds} seconds.",
            headers={"Retry-After": str(window_seconds)},
        ),
    )
    def rate_limit_shield(request: Request):
        """Limit requests based on client IP"""
        # For testing, use a fixed client IP
        client_ip = "127.0.0.1"
        now = time.time()

        # Remove expired timestamps
        request_counts[client_ip] = [
            ts for ts in request_counts[client_ip] if now - ts < window_seconds
        ]

        # Check if rate limit is exceeded
        if len(request_counts[client_ip]) >= max_requests:
            return None

        # Add current timestamp and allow request
        request_counts[client_ip].append(now)
        return True

    @app.get("/rate-limited")
    @rate_limit_shield
    async def rate_limited_endpoint():
        return {"message": "Rate limited endpoint"}

    # Reset function for testing
    def reset_rate_limits():
        request_counts.clear()

    # Attach reset function to app for tests
    app.reset_rate_limits = reset_rate_limits

    return app


@pytest.fixture
def client():
    app = create_app(max_requests=3, window_seconds=1)
    # Reset rate limits before each test
    app.reset_rate_limits()
    return TestClient(app)


def test_rate_limit_not_exceeded(client):
    """Test that requests within the rate limit succeed"""
    # Make requests within the rate limit (3 per second)
    for _ in range(3):
        response = client.get("/rate-limited")
        assert response.status_code == 200
        assert response.json() == {"message": "Rate limited endpoint"}


def test_rate_limit_exceeded(client):
    """Test that requests exceeding the rate limit are blocked"""
    # Make requests up to the limit
    for _ in range(3):
        response = client.get("/rate-limited")
        assert response.status_code == 200

    # This request should exceed the rate limit
    response = client.get("/rate-limited")
    assert response.status_code == 429
    assert "Rate limit exceeded" in response.json()["detail"]
    assert "Retry-After" in response.headers


def test_rate_limit_reset(client):
    """Test that rate limit resets after the time window"""
    # Make requests up to the limit
    for _ in range(3):
        response = client.get("/rate-limited")
        assert response.status_code == 200

    # Reset rate limits (simulating time passing)
    client.app.reset_rate_limits()

    # Should be able to make more requests after reset
    for _ in range(3):
        response = client.get("/rate-limited")
        assert response.status_code == 200
        assert response.json() == {"message": "Rate limited endpoint"}
