from fastapi import Header, HTTPException
from fastapi_shield import shield
from fastapi import Request
from collections import defaultdict
import time
from fastapi import FastAPI
from fastapi.testclient import TestClient


app = FastAPI()


# Simple in-memory rate limiter
request_counts = defaultdict(list)
MAX_REQUESTS = 10
WINDOW_SECONDS = 60


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


# Tests

client = TestClient(app)


def test_protected_endpoint():
    response = client.get("/protected", headers={"API-Token": "admin_token"})
    assert response.status_code == 200, response.json()
    assert response.json() == {"message": "This endpoint is protected by auth_shield"}


def test_rate_limited_endpoint():
    for _ in range(MAX_REQUESTS // 2):
        response = client.get("/rate-limited")
        assert response.status_code == 200, response.json()


def test_doubly_protected_endpoint():
    response = client.get("/doubly-protected", headers={"API-Token": "admin_token"})
    assert response.status_code == 200, response.json()
    assert response.json() == {"message": "This endpoint is protected by both shields"}


def test_rate_limited_endpoint_fails():
    for _ in range((MAX_REQUESTS // 2) - 1):
        response = client.get("/rate-limited")
        assert response.status_code == 200, response.json()
    response = client.get("/rate-limited")
    assert response.status_code == 500, response.json()


# python -m pytest examples/basic_usage_one.py
