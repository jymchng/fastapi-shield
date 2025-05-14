import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI, Header, Query, HTTPException, status
from fastapi_shield import shield
import time


# Multiple Shields Example App
def create_app():
    app = FastAPI()

    # Simple rate limiting
    last_request_time = {}
    MIN_REQUEST_INTERVAL = 0.1  # reduced for testing

    @shield(name="Rate Limit Shield")
    def rate_limit_shield(client_id: str = Header()):
        """Limit request rate per client"""
        now = time.time()

        if client_id in last_request_time:
            time_since_last = now - last_request_time[client_id]
            if time_since_last < MIN_REQUEST_INTERVAL:
                return None

        last_request_time[client_id] = now
        return client_id

    @shield(name="API Key Shield")
    def api_key_shield(api_key: str = Header()):
        """Validate API key"""
        if api_key.startswith("valid_key_"):
            return api_key
        return None

    @shield(name="Parameter Validator")
    def param_validator(action: str = Query(...)):
        """Validate query parameters"""
        valid_actions = ["read", "write", "update", "delete"]
        if action in valid_actions:
            return action
        return None

    @app.get("/api/resource")
    @rate_limit_shield
    @api_key_shield
    @param_validator
    async def resource_endpoint(action: str = Query(...)):
        return {"message": f"Performing {action} action", "timestamp": time.time()}

    # Function to reset rate limits for testing
    def reset_rate_limits():
        last_request_time.clear()

    # Attach the reset function to the app for testing
    app.reset_rate_limits = reset_rate_limits

    return app


@pytest.fixture
def client():
    app = create_app()
    # Reset rate limits before each test
    app.reset_rate_limits()
    return TestClient(app)


def test_multiple_shields_success(client):
    """Test endpoint with all shields passing"""
    response = client.get(
        "/api/resource?action=read",
        headers={"client-id": "client1", "api-key": "valid_key_123"},
    )
    assert response.status_code == 200
    assert response.json()["message"] == "Performing read action"


def test_api_key_shield_failure(client):
    """Test failure due to invalid API key"""
    response = client.get(
        "/api/resource?action=read",
        headers={"client-id": "client1", "api-key": "invalid_key"},
    )
    assert response.status_code == 500  # Default shield failure
    assert "Shield with name" in response.json()["detail"]


def test_parameter_validator_failure(client):
    """Test failure due to invalid action parameter"""
    response = client.get(
        "/api/resource?action=invalid",
        headers={"client-id": "client1", "api-key": "valid_key_123"},
    )
    assert response.status_code == 500  # Default shield failure
    assert "Shield with name" in response.json()["detail"]


def test_rate_limit_shield(client):
    """Test rate limiting functionality"""
    # First request should succeed
    response1 = client.get(
        "/api/resource?action=read",
        headers={"client-id": "client2", "api-key": "valid_key_123"},
    )
    assert response1.status_code == 200

    # Second request immediately after should fail due to rate limiting
    response2 = client.get(
        "/api/resource?action=read",
        headers={"client-id": "client2", "api-key": "valid_key_123"},
    )
    assert response2.status_code == 500  # Default shield failure
    assert "Shield with name" in response2.json()["detail"]

    # After waiting, a new request should succeed
    time.sleep(0.2)  # Wait longer than MIN_REQUEST_INTERVAL
    response3 = client.get(
        "/api/resource?action=read",
        headers={"client-id": "client2", "api-key": "valid_key_123"},
    )
    assert response3.status_code == 200


def test_different_clients_not_affected_by_rate_limit(client):
    """Test that different clients have separate rate limits"""
    # Client 3 makes request
    response1 = client.get(
        "/api/resource?action=read",
        headers={"client-id": "client3", "api-key": "valid_key_123"},
    )
    assert response1.status_code == 200

    # Client 4 should not be affected by client 3's rate limit
    response2 = client.get(
        "/api/resource?action=read",
        headers={"client-id": "client4", "api-key": "valid_key_123"},
    )
    assert response2.status_code == 200
