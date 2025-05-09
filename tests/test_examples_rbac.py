import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI, Header, HTTPException
from fastapi_shield import shield, ShieldedDepends


# Role-Based Access Control Example App
def create_app():
    app = FastAPI()

    # User database with roles
    USERS = {
        "admin_token": {"user_id": "admin", "roles": ["admin", "user"]},
        "editor_token": {"user_id": "editor", "roles": ["editor", "user"]},
        "user_token": {"user_id": "user1", "roles": ["user"]},
    }

    @shield(name="Authentication")
    def auth_shield(api_token: str = Header()):
        """Authenticate the user and return user data"""
        if api_token in USERS:
            return USERS[api_token]
        return None

    def role_shield(required_roles: list[str]):
        """Factory function to create a role-checking shield"""

        @shield(name=f"Role Check ({', '.join(required_roles)})")
        def check_role(user_data: dict = ShieldedDepends(lambda user: user)):
            """Check if the user has any of the required roles"""
            user_roles = user_data.get("roles", [])
            if any(role in required_roles for role in user_roles):
                return user_data
            return None

        return check_role

    # Create specific role shields
    admin_shield = role_shield(["admin"])
    editor_shield = role_shield(["admin", "editor"])
    user_shield = role_shield(["admin", "editor", "user"])

    @app.get("/admin")
    @auth_shield
    @admin_shield
    async def admin_endpoint():
        return {"message": "Admin endpoint"}

    @app.get("/editor")
    @auth_shield
    @editor_shield
    async def editor_endpoint():
        return {"message": "Editor endpoint"}

    @app.get("/user")
    @auth_shield
    @user_shield
    async def user_endpoint():
        return {"message": "User endpoint"}

    return app


@pytest.fixture
def client():
    app = create_app()
    return TestClient(app)


def test_admin_endpoint_with_admin_token(client):
    """Test admin endpoint with admin token"""
    response = client.get("/admin", headers={"api-token": "admin_token"})
    assert response.status_code == 200
    assert response.json() == {"message": "Admin endpoint"}


def test_admin_endpoint_with_editor_token(client):
    """Test admin endpoint with editor token (should fail)"""
    response = client.get("/admin", headers={"api-token": "editor_token"})
    assert response.status_code == 500  # Default shield failure
    assert "Shield with name" in response.json()["detail"]


def test_admin_endpoint_with_user_token(client):
    """Test admin endpoint with user token (should fail)"""
    response = client.get("/admin", headers={"api-token": "user_token"})
    assert response.status_code == 500  # Default shield failure
    assert "Shield with name" in response.json()["detail"]


def test_editor_endpoint_with_admin_token(client):
    """Test editor endpoint with admin token (should pass)"""
    response = client.get("/editor", headers={"api-token": "admin_token"})
    assert response.status_code == 200
    assert response.json() == {"message": "Editor endpoint"}


def test_editor_endpoint_with_editor_token(client):
    """Test editor endpoint with editor token"""
    response = client.get("/editor", headers={"api-token": "editor_token"})
    assert response.status_code == 200
    assert response.json() == {"message": "Editor endpoint"}


def test_editor_endpoint_with_user_token(client):
    """Test editor endpoint with user token (should fail)"""
    response = client.get("/editor", headers={"api-token": "user_token"})
    assert response.status_code == 500  # Default shield failure
    assert "Shield with name" in response.json()["detail"]


def test_user_endpoint_all_tokens(client):
    """Test user endpoint with all types of tokens (all should pass)"""
    tokens = ["admin_token", "editor_token", "user_token"]
    for token in tokens:
        response = client.get("/user", headers={"api-token": token})
        assert response.status_code == 200, f"Failed with token: {token}"
        assert response.json() == {"message": "User endpoint"}
