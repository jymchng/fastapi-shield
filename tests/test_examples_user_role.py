import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI, Header, HTTPException, status
from fastapi_shield import shield, ShieldedDepends


# User Role Shield Example App
def create_app():
    app = FastAPI()

    # User database with roles
    USERS = {
        "token1": {"user_id": 1, "role": "admin"},
        "token2": {"user_id": 2, "role": "editor"},
        "token3": {"user_id": 3, "role": "user"},
    }

    @shield(name="Auth Shield")
    def auth_shield(api_token: str = Header()):
        """Authenticate the user and return user data"""
        if api_token in USERS:
            return USERS[api_token]
        return None

    @shield(name="Admin Shield")
    def admin_shield(user_data=ShieldedDepends(lambda user: user)):
        """Check if the user has admin role"""
        if user_data["role"] == "admin":
            return user_data
        return None

    @shield(name="Editor Shield")
    def editor_shield(user_data=ShieldedDepends(lambda user: user)):
        """Check if the user has editor role"""
        if user_data["role"] in ["admin", "editor"]:
            return user_data
        return None

    @app.get("/admin-only")
    @auth_shield
    @admin_shield
    async def admin_endpoint():
        return {"message": "Admin endpoint"}

    @app.get("/editor-access")
    @auth_shield
    @editor_shield
    async def editor_endpoint():
        return {"message": "Editor endpoint"}

    @app.get("/all-users")
    @auth_shield
    async def all_users_endpoint(user_data=ShieldedDepends(lambda user: user)):
        return {
            "message": f"Welcome, {user_data['role']}",
            "user_id": user_data["user_id"],
        }

    return app


@pytest.fixture
def client():
    app = create_app()
    return TestClient(app)


def test_admin_endpoint_access(client):
    """Test admin endpoint access with different roles"""
    # Admin token should have access
    response = client.get("/admin-only", headers={"api-token": "token1"})
    assert response.status_code == 200
    assert response.json() == {"message": "Admin endpoint"}

    # Editor token should not have access
    response = client.get("/admin-only", headers={"api-token": "token2"})
    assert response.status_code == 500  # Default shield failure
    assert "Shield with name" in response.json()["detail"]

    # User token should not have access
    response = client.get("/admin-only", headers={"api-token": "token3"})
    assert response.status_code == 500  # Default shield failure
    assert "Shield with name" in response.json()["detail"]


def test_editor_endpoint_access(client):
    """Test editor endpoint access with different roles"""
    # Admin token should have access (admin can access editor endpoints)
    response = client.get("/editor-access", headers={"api-token": "token1"})
    assert response.status_code == 200
    assert response.json() == {"message": "Editor endpoint"}

    # Editor token should have access
    response = client.get("/editor-access", headers={"api-token": "token2"})
    assert response.status_code == 200
    assert response.json() == {"message": "Editor endpoint"}

    # User token should not have access
    response = client.get("/editor-access", headers={"api-token": "token3"})
    assert response.status_code == 500  # Default shield failure
    assert "Shield with name" in response.json()["detail"]


def test_all_users_endpoint(client):
    """Test endpoint accessible to all authenticated users"""
    # Test with all valid tokens
    tokens = {
        "token1": {"role": "admin", "user_id": 1},
        "token2": {"role": "editor", "user_id": 2},
        "token3": {"role": "user", "user_id": 3},
    }

    for token, expected_data in tokens.items():
        response = client.get("/all-users", headers={"api-token": token})
        assert response.status_code == 200
        assert response.json() == {
            "message": f"Welcome, {expected_data['role']}",
            "user_id": expected_data["user_id"],
        }

    # Invalid token should not have access
    response = client.get("/all-users", headers={"api-token": "invalid_token"})
    assert response.status_code == 500  # Default shield failure
    assert "Shield with name" in response.json()["detail"]
