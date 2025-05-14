import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI, Depends, HTTPException, status, Header, Cookie
from fastapi.security import OAuth2PasswordBearer
from fastapi_shield import shield, ShieldedDepends
from typing import Optional, Dict


# Flexible Authentication Example App
def create_app():
    app = FastAPI()

    # OAuth2 scheme with auto_error=False to not automatically raise exceptions
    oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)

    # Valid credentials for different auth methods
    VALID_JWT = "valid-jwt"
    VALID_API_KEY = "valid-api-key"
    VALID_SESSION = "valid-session"

    # Mock user details
    JWT_USER = {
        "username": "jwt-user",
        "email": "jwt@example.com",
        "auth_method": "jwt",
    }
    API_KEY_USER = {
        "username": "api-key-user",
        "email": "apikey@example.com",
        "auth_method": "api_key",
    }
    SESSION_USER = {
        "username": "cookie-user",
        "email": "cookie@example.com",
        "auth_method": "cookie",
    }

    # Validation functions for different auth methods
    async def validate_jwt(token: str) -> Optional[Dict]:
        # Simple mock validation - in a real app, decode and validate JWT
        if token == VALID_JWT:
            return JWT_USER
        return None

    async def validate_api_key(api_key: str) -> Optional[Dict]:
        # Simple mock validation
        if api_key == VALID_API_KEY:
            return API_KEY_USER
        return None

    async def validate_session_cookie(session_id: str) -> Optional[Dict]:
        # Simple mock validation
        if session_id == VALID_SESSION:
            return SESSION_USER
        return None

    # Shield for flexible authentication
    @shield(
        name="Flexible Auth",
        exception_to_raise_if_fail=HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ),
    )
    async def authenticate(
        token: Optional[str] = Depends(oauth2_scheme),
        x_api_key: Optional[str] = Header(None),
        session: Optional[str] = Cookie(None),
    ):
        # Try JWT authentication
        if token:
            user = await validate_jwt(token)
            if user:
                return user

        # Try API key authentication
        if x_api_key:
            user = await validate_api_key(x_api_key)
            if user:
                return user

        # Try session cookie authentication
        if session:
            user = await validate_session_cookie(session)
            if user:
                return user

        # If no authentication method succeeded
        return None

    # Protected endpoint using the flexible authentication shield
    @app.get("/protected")
    @authenticate
    async def protected_route(user_data: dict = ShieldedDepends(lambda u: u)):
        return {
            "message": f"Hello {user_data['username']}! You are authenticated via {user_data['auth_method']}",
            "user": user_data,
        }

    return app


@pytest.fixture
def client():
    app = create_app()
    return TestClient(app)


def test_jwt_authentication(client):
    """Test authentication with JWT token"""
    response = client.get("/protected", headers={"Authorization": "Bearer valid-jwt"})
    assert response.status_code == 200
    assert response.json()["message"] == "Hello jwt-user! You are authenticated via jwt"
    assert response.json()["user"]["auth_method"] == "jwt"


def test_api_key_authentication(client):
    """Test authentication with API key"""
    response = client.get("/protected", headers={"x-api-key": "valid-api-key"})
    assert response.status_code == 200
    assert (
        response.json()["message"]
        == "Hello api-key-user! You are authenticated via api_key"
    )
    assert response.json()["user"]["auth_method"] == "api_key"


def test_session_cookie_authentication(client):
    """Test authentication with session cookie"""
    response = client.get("/protected", cookies={"session": "valid-session"})
    assert response.status_code == 200
    assert (
        response.json()["message"]
        == "Hello cookie-user! You are authenticated via cookie"
    )
    assert response.json()["user"]["auth_method"] == "cookie"


def test_invalid_jwt_authentication(client):
    """Test with invalid JWT token"""
    response = client.get("/protected", headers={"Authorization": "Bearer invalid-jwt"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid authentication credentials"


def test_invalid_api_key_authentication(client):
    """Test with invalid API key"""
    response = client.get("/protected", headers={"x-api-key": "invalid-api-key"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid authentication credentials"


def test_invalid_session_cookie_authentication(client):
    """Test with invalid session cookie"""
    response = client.get("/protected", cookies={"session": "invalid-session"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid authentication credentials"


def test_no_authentication(client):
    """Test with no authentication credentials"""
    response = client.get("/protected")
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid authentication credentials"


def test_preference_order(client):
    """Test authentication method preference order (JWT > API Key > Cookie)"""
    # When multiple methods are provided, JWT should be preferred
    response = client.get(
        "/protected",
        headers={"Authorization": "Bearer valid-jwt", "x-api-key": "valid-api-key"},
        cookies={"session": "valid-session"},
    )
    assert response.status_code == 200
    assert response.json()["user"]["auth_method"] == "jwt"

    # When JWT is invalid but API Key is valid
    response = client.get(
        "/protected",
        headers={"Authorization": "Bearer invalid-jwt", "x-api-key": "valid-api-key"},
        cookies={"session": "valid-session"},
    )
    assert response.status_code == 200
    assert response.json()["user"]["auth_method"] == "api_key"
