import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI, Header, HTTPException, status
from fastapi_shield import shield


# Shield with Parameters Example App
def create_app():
    app = FastAPI()

    def create_permission_shield(required_permission: str):
        """Factory function to create a permission shield"""

        @shield(
            name=f"Permission Shield ({required_permission})",
            exception_to_raise_if_fail=HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required permission: {required_permission}",
            ),
        )
        def permission_shield(permissions: str = Header()):
            """Check if the user has the required permission"""
            user_permissions = permissions.split(",")
            if required_permission in user_permissions:
                return {"granted_permission": required_permission}
            return None

        return permission_shield

    read_shield = create_permission_shield("read")
    write_shield = create_permission_shield("write")
    delete_shield = create_permission_shield("delete")

    @app.get("/data")
    @read_shield
    async def read_data():
        return {"message": "Reading data"}

    @app.post("/data")
    @write_shield
    async def write_data():
        return {"message": "Writing data"}

    @app.delete("/data")
    @delete_shield
    async def delete_data():
        return {"message": "Deleting data"}

    return app


@pytest.fixture
def client():
    app = create_app()
    return TestClient(app)


def test_read_permission(client):
    """Test endpoint with read permission"""
    # With read permission
    response = client.get("/data", headers={"permissions": "read,list"})
    assert response.status_code == 200
    assert response.json() == {"message": "Reading data"}

    # Without read permission
    response = client.get("/data", headers={"permissions": "list,view"})
    assert response.status_code == 403
    assert response.json() == {"detail": "Missing required permission: read"}


def test_write_permission(client):
    """Test endpoint with write permission"""
    # With write permission
    response = client.post("/data", headers={"permissions": "read,write"})
    assert response.status_code == 200
    assert response.json() == {"message": "Writing data"}

    # Without write permission
    response = client.post("/data", headers={"permissions": "read,list"})
    assert response.status_code == 403
    assert response.json() == {"detail": "Missing required permission: write"}


def test_delete_permission(client):
    """Test endpoint with delete permission"""
    # With delete permission
    response = client.delete("/data", headers={"permissions": "read,delete"})
    assert response.status_code == 200
    assert response.json() == {"message": "Deleting data"}

    # Without delete permission
    response = client.delete("/data", headers={"permissions": "read,write"})
    assert response.status_code == 403
    assert response.json() == {"detail": "Missing required permission: delete"}


def test_missing_permissions_header(client):
    """Test endpoints without permissions header"""
    # Should fail with 422 (validation error)
    for method, endpoint in [
        (client.get, "/data"),
        (client.post, "/data"),
        (client.delete, "/data"),
    ]:
        response = method(endpoint)
        assert response.status_code == 422
        assert "detail" in response.json()
