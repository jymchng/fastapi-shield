import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI, Header, HTTPException, Request, Response, status
from fastapi_shield import shield
from collections import defaultdict
import time

# Constants moved to module level
MAX_REQUESTS = 5
WINDOW_SECONDS = 0.25


def create_app():
    app = FastAPI()

    # API Token Authentication Shield
    @shield(
        name="API Token Auth",
        auto_error=True,
        exception_to_raise_if_fail=HTTPException(
            status_code=401, detail="Invalid API token"
        ),
    )
    def auth_shield(api_token: str = Header()):
        valid_tokens = ["admin_token", "user_token"]
        if api_token in valid_tokens:
            return api_token
        return None

    # Rate Limiting Shield
    request_counts = defaultdict(list)

    @shield(name="Rate Limiter")
    def rate_limit_shield(request: Request):
        client_ip = request.client.host
        now = time.time()

        # Remove expired timestamps
        request_counts[client_ip] = [
            ts for ts in request_counts[client_ip] if now - ts < WINDOW_SECONDS
        ]

        # Check if rate limit is exceeded
        if len(request_counts[client_ip]) >= MAX_REQUESTS:
            return None

        # Add current timestamp and allow request
        request_counts[client_ip].append(now)
        return True

    # Custom Error Shield
    @shield(
        name="Custom Error Shield",
        auto_error=True,
        exception_to_raise_if_fail=HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied by custom shield",
            headers={"X-Shield-Blocked": "true"},
        ),
    )
    def custom_error_shield():
        return None  # Always block the request

    # Custom Response Shield
    @shield(
        name="Custom Response Shield",
        auto_error=False,
        default_response_to_return_if_fail=Response(
            content="Request blocked by shield",
            media_type="text/plain; charset=utf-8",  # Updated to match FastAPI's default
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        ),
    )
    def custom_response_shield():
        return None  # Always block the request

    # Test endpoints
    @app.get("/protected")
    @auth_shield
    async def protected_endpoint():
        return {"message": "This endpoint is protected by auth_shield"}

    @app.get("/rate-limited")
    @rate_limit_shield
    async def rate_limited_endpoint():
        return {"message": "This endpoint is protected by rate_limit_shield"}

    @app.get("/doubly-protected")
    @auth_shield
    @rate_limit_shield
    async def doubly_protected_endpoint():
        return {"message": "This endpoint is protected by both shields"}

    @app.get("/custom-error")
    @custom_error_shield
    async def custom_error_endpoint():
        return {"message": "This should never be reached"}

    @app.get("/custom-response")
    @custom_response_shield
    async def custom_response_endpoint():
        return {"message": "This should never be reached"}

    @app.get("/multiple-shields")
    @auth_shield
    @rate_limit_shield
    @custom_error_shield
    async def multiple_shields_endpoint():
        return {"message": "All shields passed"}

    return app


@pytest.fixture
def client():
    app = create_app()
    return TestClient(app)


# API Token Authentication Tests
def test_protected_endpoint_with_valid_token(client):
    """Test protected endpoint with valid API token"""
    response = client.get("/protected", headers={"api-token": "admin_token"})
    assert response.status_code == 200
    assert response.json()["message"] == "This endpoint is protected by auth_shield"


def test_protected_endpoint_with_invalid_token(client):
    """Test protected endpoint with invalid API token"""
    response = client.get("/protected", headers={"api-token": "invalid_token"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid API token"


def test_protected_endpoint_without_token(client):
    """Test protected endpoint without API token"""
    response = client.get("/protected")
    assert response.status_code == 422  # FastAPI validation error for missing header


# Rate Limiting Tests
def test_rate_limited_endpoint_within_limits(client):
    """Test rate limited endpoint within limits"""
    for _ in range(MAX_REQUESTS):
        response = client.get("/rate-limited")
        assert response.status_code == 200
        assert (
            response.json()["message"]
            == "This endpoint is protected by rate_limit_shield"
        )


def test_rate_limited_endpoint_exceeding_limits(client):
    """Test rate limited endpoint exceeding limits"""
    # First make MAX_REQUESTS requests
    for _ in range(MAX_REQUESTS):
        response = client.get("/rate-limited")
        assert response.status_code == 200

    # Next request should be blocked
    response = client.get("/rate-limited")
    assert response.status_code == 500, response.json()  # Default shield error status
    assert (
        response.json()["detail"]
        == "Shield with name `Rate Limiter` blocks the request"
    ), response.json()


def test_rate_limit_reset_after_window(client):
    """Test rate limit reset after window period"""
    # Make MAX_REQUESTS requests
    for _ in range(MAX_REQUESTS):
        response = client.get("/rate-limited")
        assert response.status_code == 200

    # Wait for window to expire
    time.sleep(WINDOW_SECONDS + 1)

    # Should be able to make requests again
    response = client.get("/rate-limited")
    assert response.status_code == 200
    assert (
        response.json()["message"] == "This endpoint is protected by rate_limit_shield"
    )


# Custom Error Response Tests
def test_custom_error_shield(client):
    """Test custom error shield"""
    response = client.get("/custom-error")
    assert response.status_code == 403
    assert response.json()["detail"] == "Access denied by custom shield"
    assert response.headers["X-Shield-Blocked"] == "true"


def test_custom_response_shield(client):
    """Test custom response shield"""
    response = client.get("/custom-response")
    assert response.status_code == 429
    assert response.content == b"Request blocked by shield"
    assert (
        response.headers["content-type"] == "text/plain; charset=utf-8"
    )  # Updated to match FastAPI's default


# Multiple Shields Tests
def test_multiple_shields_with_valid_token(client):
    """Test multiple shields with valid token"""
    response = client.get("/multiple-shields", headers={"api-token": "admin_token"})
    assert response.status_code == 403  # Blocked by custom_error_shield
    assert response.json()["detail"] == "Access denied by custom shield"


def test_multiple_shields_with_invalid_token(client):
    """Test multiple shields with invalid token"""
    response = client.get("/multiple-shields", headers={"api-token": "invalid_token"})
    assert response.status_code == 401  # Blocked by auth_shield
    assert response.json()["detail"] == "Invalid API token"


def test_doubly_protected_endpoint(client):
    """Test endpoint with both auth and rate limit shields"""
    # Test with valid token
    response = client.get("/doubly-protected", headers={"api-token": "admin_token"})
    assert response.status_code == 200
    assert response.json()["message"] == "This endpoint is protected by both shields"

    # Test with invalid token
    response = client.get("/doubly-protected", headers={"api-token": "invalid_token"})
    assert response.status_code == 401  # Blocked by auth_shield before rate limit
    assert response.json()["detail"] == "Invalid API token"

    # Test rate limiting
    for _ in range(MAX_REQUESTS - 1):
        response = client.get("/doubly-protected", headers={"api-token": "admin_token"})
        assert response.status_code == 200

    response = client.get("/doubly-protected", headers={"api-token": "admin_token"})
    assert response.status_code == 500, response.json()  # Blocked by rate limit shield
    assert (
        response.json()["detail"]
        == "Shield with name `Rate Limiter` blocks the request"
    ), response.json()
