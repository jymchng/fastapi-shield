import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI, Header, Request, HTTPException, status, Query
from fastapi_shield import shield, ShieldedDepends
from typing import Optional
import time
from collections import defaultdict


# Combined Shield Examples App
def create_app():
    app = FastAPI(title="FastAPI Shield Combined Example Tests")

    # ------------------ Authentication Shield ------------------
    VALID_API_TOKENS = {
        "admin_token": {"user_id": "admin", "role": "admin"},
        "user_token": {"user_id": "user1", "role": "user"},
    }

    @shield(
        name="API Token Auth",
        exception_to_raise_if_fail=HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API token"
        ),
    )
    def auth_shield(api_token: str = Header()):
        """Shield that validates API tokens"""
        if api_token in VALID_API_TOKENS:
            return VALID_API_TOKENS[api_token]
        return None

    # ------------------ Role-Based Access Shield ------------------
    @shield(
        name="Admin Access",
        exception_to_raise_if_fail=HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required"
        ),
    )
    def admin_shield(user_data: dict = ShieldedDepends(lambda user: user)):
        """Check if user has admin role"""
        if user_data.get("role") == "admin":
            return user_data
        return None

    # ------------------ Rate Limiting Shield ------------------
    request_counts = defaultdict(list)
    MAX_REQUESTS = 3
    WINDOW_SECONDS = 1

    @shield(
        name="Rate Limiter",
        exception_to_raise_if_fail=HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Maximum {MAX_REQUESTS} requests per {WINDOW_SECONDS} seconds.",
            headers={"Retry-After": str(WINDOW_SECONDS)},
        ),
    )
    def rate_limit_shield(request: Request):
        """Limit requests based on client IP"""
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

    # ------------------ Parameter Validation Shield ------------------
    @shield(
        name="Parameters Validator",
        exception_to_raise_if_fail=HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid parameters"
        ),
    )
    def validate_parameters(
        page: int = Query(1),
        per_page: int = Query(10, ge=1, le=100),
        sort_by: Optional[str] = Query(None),
    ):
        """Validate and normalize query parameters"""
        valid_sort_fields = ["created_at", "updated_at", "name"]

        # Create normalized parameters
        normalized = {
            "page": max(1, page),
            "per_page": max(1, min(per_page, 100)),
            "sort_by": sort_by if sort_by in valid_sort_fields else "created_at",
        }

        return normalized

    # ------------------ Routes ------------------
    @app.get("/public")
    async def public_endpoint():
        return {"message": "This endpoint is public"}

    @app.get("/protected")
    @auth_shield
    async def protected_endpoint(user_data: dict = ShieldedDepends(lambda user: user)):
        return {"message": "This endpoint is protected", "user": user_data}

    @app.get("/admin")
    @auth_shield
    @admin_shield
    async def admin_endpoint(user_data: dict = ShieldedDepends(lambda user: user)):
        return {"message": "This endpoint is for admins only", "user": user_data}

    @app.get("/rate-limited")
    @rate_limit_shield
    async def rate_limited_endpoint():
        return {
            "message": "This endpoint is rate limited",
            "limit": f"{MAX_REQUESTS} requests per {WINDOW_SECONDS} seconds",
        }

    @app.get("/filtered-items")
    @auth_shield
    @validate_parameters
    async def list_items(
        user_data: dict = ShieldedDepends(lambda user: user),
        params: dict = ShieldedDepends(lambda params: params),
    ):
        return {
            "user": user_data,
            "items": [f"Item {i}" for i in range(1, 6)],
            "pagination": params,
        }

    # Combined shields (all protections)
    @app.get("/admin-items")
    @rate_limit_shield
    @auth_shield
    @admin_shield
    @validate_parameters
    async def admin_items(params: dict = ShieldedDepends(lambda params: params)):
        return {"items": [f"Admin Item {i}" for i in range(1, 6)], "pagination": params}

    # Reset function for rate limiting tests
    def reset_rate_limits():
        request_counts.clear()

    # Attach the reset function to the app
    app.reset_rate_limits = reset_rate_limits

    return app


@pytest.fixture
def client():
    app = create_app()
    app.reset_rate_limits()  # Reset rate limits before each test
    return TestClient(app)


# ------------------ Tests ------------------


def test_public_endpoint(client):
    """Test that public endpoint is accessible without authentication"""
    response = client.get("/public")
    assert response.status_code == 200
    assert response.json() == {"message": "This endpoint is public"}


def test_protected_endpoint_authentication(client):
    """Test protected endpoint with and without authentication"""
    # With valid token
    response = client.get("/protected", headers={"api-token": "admin_token"})
    assert response.status_code == 200
    assert response.json()["message"] == "This endpoint is protected"

    # Without token (should fail)
    response = client.get("/protected")
    assert response.status_code == 422  # FastAPI validation error

    # With invalid token (should fail)
    response = client.get("/protected", headers={"api-token": "invalid_token"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid API token"


def test_admin_endpoint_role_based_access(client):
    """Test admin endpoint with different role tokens"""
    # With admin token
    response = client.get("/admin", headers={"api-token": "admin_token"})
    assert response.status_code == 200
    assert response.json()["message"] == "This endpoint is for admins only"

    # With user token (should fail due to role)
    response = client.get("/admin", headers={"api-token": "user_token"})
    assert response.status_code == 403
    assert response.json()["detail"] == "Admin access required"


def test_rate_limiting(client):
    """Test rate limiting on rate-limited endpoint"""
    # Reset rate limits for this test
    client.app.reset_rate_limits()

    # Make requests up to the limit
    for i in range(3):
        response = client.get("/rate-limited")
        assert response.status_code == 200, f"Request {i + 1} failed"

    # This request should exceed the limit
    response = client.get("/rate-limited")
    assert response.status_code == 429
    assert "Rate limit exceeded" in response.json()["detail"]


def test_parameter_validation(client):
    """Test parameter validation on filtered items endpoint"""
    # With valid parameters and authentication
    response = client.get(
        "/filtered-items?page=2&per_page=15&sort_by=name",
        headers={"api-token": "user_token"},
    )
    assert response.status_code == 200
    assert response.json()["pagination"] == {
        "page": 2,
        "per_page": 15,
        "sort_by": "name",
    }

    # With invalid sort_by (should normalize)
    response = client.get(
        "/filtered-items?sort_by=invalid", headers={"api-token": "user_token"}
    )
    assert response.status_code == 200
    assert response.json()["pagination"]["sort_by"] == "created_at"  # Default value


def test_combined_shields(client):
    """Test endpoint with multiple shields stacked"""
    # 1. Reset rate limiter
    client.app.reset_rate_limits()

    # 2. Test with proper admin credentials and parameters
    response = client.get(
        "/admin-items?page=1&per_page=10&sort_by=name",
        headers={"api-token": "admin_token"},
    )
    assert response.status_code == 200
    assert response.json()["pagination"]["sort_by"] == "name"
    assert response.json() == {
        "items": [
            "Admin Item 1",
            "Admin Item 2",
            "Admin Item 3",
            "Admin Item 4",
            "Admin Item 5",
        ],
        "pagination": {"page": 1, "per_page": 10, "sort_by": "name"},
    }, f"Response: {response.json()}"

    # 3. Test with user credentials (should fail on admin check)
    response = client.get(
        "/admin-items?page=1&per_page=10", headers={"api-token": "user_token"}
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Admin access required"

    # 4. Test rate limiting (make requests until it fails)
    client.app.reset_rate_limits()
    for i in range(3):
        response = client.get("/admin-items", headers={"api-token": "admin_token"})
        assert response.status_code == 200, f"Request {i + 1} failed"

    # This request should exceed the rate limit
    response = client.get("/admin-items", headers={"api-token": "admin_token"})
    assert response.status_code == 429
    assert "Rate limit exceeded" in response.json()["detail"]
