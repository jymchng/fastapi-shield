import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI, Header, HTTPException, status
from fastapi_shield import shield, ShieldedDepends
import jwt
from jwt.exceptions import PyJWTError


# JWT Authentication Example App
def create_app():
    app = FastAPI()

    # Configuration
    JWT_SECRET = "test-secret-key"
    JWT_ALGORITHM = "HS256"

    @shield(
        name="JWT Auth",
        exception_to_raise_if_fail=HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ),
    )
    def jwt_shield(authorization: str = Header()):
        """Validate JWT token and return decoded payload"""
        if not authorization.startswith("Bearer "):
            return None

        token = authorization.replace("Bearer ", "")

        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            return payload
        except PyJWTError:
            return None

    @shield(name="Admin Access")
    def admin_access(payload: dict = ShieldedDepends(lambda payload: payload)):
        """Check if user has admin role in JWT payload"""
        if payload.get("role") == "admin":
            return payload
        return None

    @app.get("/protected")
    @jwt_shield
    async def protected_endpoint():
        return {"message": "Protected endpoint"}

    @app.get("/admin-only")
    @jwt_shield
    @admin_access
    async def admin_endpoint():
        return {"message": "Admin only endpoint"}

    # Helper function to create test tokens
    def create_token(role: str):
        payload = {"sub": "test_user", "role": role}
        return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    # Attach the token creation function to the app for testing
    app.create_token = create_token

    return app


@pytest.fixture
def client():
    app = create_app()
    return TestClient(app)


@pytest.fixture
def admin_token(client):
    app = client.app
    return app.create_token("admin")


@pytest.fixture
def user_token(client):
    app = client.app
    return app.create_token("user")


def test_protected_endpoint_with_admin_token(client, admin_token):
    """Test protected endpoint with admin token"""
    response = client.get(
        "/protected", headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    assert response.json() == {"message": "Protected endpoint"}


def test_protected_endpoint_with_user_token(client, user_token):
    """Test protected endpoint with user token"""
    response = client.get(
        "/protected", headers={"Authorization": f"Bearer {user_token}"}
    )
    assert response.status_code == 200
    assert response.json() == {"message": "Protected endpoint"}


def test_protected_endpoint_with_invalid_token(client):
    """Test protected endpoint with invalid token"""
    response = client.get(
        "/protected", headers={"Authorization": "Bearer invalid.token.format"}
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid authentication credentials"}


def test_protected_endpoint_without_token(client):
    """Test protected endpoint without token"""
    response = client.get("/protected")
    assert response.status_code == 422  # FastAPI validation error for missing header


def test_admin_endpoint_with_admin_token(client, admin_token):
    """Test admin endpoint with admin token"""
    response = client.get(
        "/admin-only", headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    assert response.json() == {"message": "Admin only endpoint"}


def test_admin_endpoint_with_user_token(client, user_token):
    """Test admin endpoint with user token (should fail)"""
    response = client.get(
        "/admin-only", headers={"Authorization": f"Bearer {user_token}"}
    )
    assert response.status_code == 500  # Default shield failure
    assert "Shield with name" in response.json()["detail"]
