import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI, Header, HTTPException, status
from fastapi_shield import shield


# Simple Authentication Shield Example App
def create_app():
    app = FastAPI()

    # Define valid API tokens
    VALID_TOKENS = ["token1", "token2", "token3"]

    @shield(
        name="API Token Auth",
        exception_to_raise_if_fail=HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API token"
        ),
    )
    def auth_shield(api_token: str = Header()):
        """Validate the API token"""
        if api_token in VALID_TOKENS:
            return api_token
        return None

    @app.get("/protected")
    @auth_shield
    async def protected_endpoint():
        return {"message": "You have access to the protected endpoint"}

    return app


@pytest.fixture
def client():
    app = create_app()
    return TestClient(app)


def test_protected_endpoint_with_valid_token(client):
    """Test protected endpoint with valid API token"""
    response = client.get("/protected", headers={"api-token": "token1"})
    assert response.status_code == 200
    assert response.json() == {"message": "You have access to the protected endpoint"}


def test_protected_endpoint_with_invalid_token(client):
    """Test protected endpoint with invalid API token"""
    response = client.get("/protected", headers={"api-token": "invalid_token"})
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid API token"}


def test_protected_endpoint_without_token(client):
    """Test protected endpoint without API token header"""
    response = client.get("/protected")
    assert response.status_code == 422  # FastAPI validation error for missing header
    assert "detail" in response.json()
