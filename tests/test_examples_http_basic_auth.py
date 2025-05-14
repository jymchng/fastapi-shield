import pytest
import base64
from fastapi.testclient import TestClient
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi_shield import shield, ShieldedDepends
import secrets
from typing import NewType


# Basic Authentication Example App
def create_app():
    app = FastAPI()

    # Security scheme
    security = HTTPBasic()

    # Define an authenticated user type
    AuthenticatedUser = NewType("AuthenticatedUser", str)

    # Mock user database
    USER_DB = {
        "johndoe": {
            "username": "johndoe",
            "password": "password123",
            "full_name": "John Doe",
        },
        "janedoe": {
            "username": "janedoe",
            "password": "secret456",
            "full_name": "Jane Doe",
        },
    }

    # Shield to authenticate the user
    @shield(
        name="HTTP Basic Auth",
        exception_to_raise_if_fail=HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        ),
    )
    def authenticate_user(
        credentials: HTTPBasicCredentials = Depends(security),
    ) -> AuthenticatedUser:
        username = credentials.username
        password = credentials.password

        user = USER_DB.get(username)
        if not user or not secrets.compare_digest(user["password"], password):
            return None

        return AuthenticatedUser(username)

    # Use the shield in an endpoint
    @app.get("/profile")
    @authenticate_user
    def get_profile(username: AuthenticatedUser = ShieldedDepends(lambda s: s)):
        user_data = USER_DB.get(str(username))
        return {"username": user_data["username"], "full_name": user_data["full_name"]}

    # Additional endpoint requiring authentication
    @app.get("/settings")
    @authenticate_user
    def get_settings(username: AuthenticatedUser = ShieldedDepends(lambda s: s)):
        return {"username": str(username), "theme": "dark", "notifications": True}

    return app


@pytest.fixture
def client():
    app = create_app()
    return TestClient(app)


def get_basic_auth_header(username: str, password: str) -> dict:
    """Create HTTP Basic Auth header"""
    credentials = f"{username}:{password}"
    encoded = base64.b64encode(credentials.encode()).decode()
    return {"Authorization": f"Basic {encoded}"}


def test_profile_with_valid_credentials(client):
    """Test accessing profile with valid credentials"""
    headers = get_basic_auth_header("johndoe", "password123")
    response = client.get("/profile", headers=headers)
    assert response.status_code == 200
    assert response.json() == {"username": "johndoe", "full_name": "John Doe"}


def test_profile_with_invalid_password(client):
    """Test accessing profile with invalid password"""
    headers = get_basic_auth_header("johndoe", "wrongpassword")
    response = client.get("/profile", headers=headers)
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid credentials"}
    assert "WWW-Authenticate" in response.headers
    assert response.headers["WWW-Authenticate"] == "Basic"


def test_profile_with_nonexistent_user(client):
    """Test accessing profile with non-existent username"""
    headers = get_basic_auth_header("nonexistentuser", "password123")
    response = client.get("/profile", headers=headers)
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid credentials"}


def test_profile_without_auth(client):
    """Test accessing profile without authentication"""
    response = client.get("/profile")
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers
    assert response.headers["WWW-Authenticate"] == "Basic"


def test_settings_with_valid_credentials(client):
    """Test accessing settings with valid credentials"""
    headers = get_basic_auth_header("janedoe", "secret456")
    response = client.get("/settings", headers=headers)
    assert response.status_code == 200
    assert response.json() == {
        "username": "janedoe",
        "theme": "dark",
        "notifications": True,
    }


def test_credentials_case_sensitivity(client):
    """Test that usernames and passwords are case-sensitive"""
    # Try with uppercase username
    headers = get_basic_auth_header("JOHNDOE", "password123")
    response = client.get("/profile", headers=headers)
    assert response.status_code == 401

    # Try with uppercase password
    headers = get_basic_auth_header("johndoe", "PASSWORD123")
    response = client.get("/profile", headers=headers)
    assert response.status_code == 401
