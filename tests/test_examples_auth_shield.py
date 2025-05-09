import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI, Header, HTTPException, status
from fastapi_shield import shield


# Authentication Shield Example App
def create_app():
    app = FastAPI()

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

    @app.get("/protected")
    @auth_shield
    async def protected_endpoint():
        return {"message": "This endpoint is protected"}

    return app


@pytest.fixture
def client():
    app = create_app()
    return TestClient(app)


def test_auth_shield_with_valid_token(client):
    """Test endpoint with valid API token"""
    response = client.get("/protected", headers={"api-token": "admin_token"})
    assert response.status_code == 200
    assert response.json() == {"message": "This endpoint is protected"}


def test_auth_shield_with_invalid_token(client):
    """Test endpoint with invalid API token"""
    response = client.get("/protected", headers={"api-token": "invalid_token"})
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid API token"}


def test_auth_shield_without_token(client):
    """Test endpoint without API token header"""
    response = client.get("/protected")
    assert response.status_code == 422  # FastAPI validation error for missing header
    assert "detail" in response.json()
