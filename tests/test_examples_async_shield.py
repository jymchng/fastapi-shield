import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI, Header, HTTPException, status
from fastapi_shield import shield
import asyncio


# Shield with Asynchronous Function Example App
def create_app():
    app = FastAPI()

    async def validate_token_async(token: str) -> bool:
        """Simulate an asynchronous token validation process"""
        await asyncio.sleep(0.05)  # Simulate external API call, reduced for testing
        return token.startswith("valid_")

    @shield(
        name="Async Auth Shield",
        exception_to_raise_if_fail=HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        ),
    )
    async def async_auth_shield(auth_token: str = Header()):
        """Asynchronous shield for token validation"""
        # Simulate calling an external authentication service
        is_valid = await validate_token_async(auth_token)

        if is_valid:
            return {"token": auth_token, "validated": True}
        return None

    @app.get("/async-protected")
    @async_auth_shield
    async def async_protected_endpoint():
        return {"message": "Protected by async shield"}

    return app


@pytest.fixture
def client():
    app = create_app()
    return TestClient(app)


def test_async_shield_with_valid_token(client):
    """Test async shield with valid token format"""
    response = client.get("/async-protected", headers={"auth-token": "valid_token123"})
    assert response.status_code == 200
    assert response.json() == {"message": "Protected by async shield"}


def test_async_shield_with_invalid_token(client):
    """Test async shield with invalid token format"""
    response = client.get("/async-protected", headers={"auth-token": "invalid_token"})
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid authentication token"}


def test_async_shield_without_token(client):
    """Test async shield without token header"""
    response = client.get("/async-protected")
    assert response.status_code == 422  # FastAPI validation error
    assert "detail" in response.json()


def test_multiple_requests_with_async_shield(client):
    """Test that multiple requests with async shield work correctly"""
    # Make multiple requests in sequence
    for i in range(3):
        # Valid requests
        valid_response = client.get(
            "/async-protected", headers={"auth-token": f"valid_token{i}"}
        )
        assert valid_response.status_code == 200

        # Invalid requests
        invalid_response = client.get(
            "/async-protected", headers={"auth-token": f"invalid_{i}"}
        )
        assert invalid_response.status_code == 401
