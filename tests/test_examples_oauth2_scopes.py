import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi_shield import shield, ShieldedDepends
import jwt
from datetime import datetime, timedelta
from typing import List, Optional, Dict


# OAuth2 Authentication with Scopes Example App
def create_app():
    app = FastAPI()

    # Configuration
    SECRET_KEY = "test-secret-key"
    ALGORITHM = "HS256"

    # OAuth2 scheme
    oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

    # Mock user database with scopes
    USERS_DB = {
        "johndoe": {
            "username": "johndoe",
            "password": "password123",  # In a real app, this would be hashed
            "email": "john@example.com",
            "full_name": "John Doe",
            "scopes": ["read:profile", "read:items", "write:items"],
        },
        "alice": {
            "username": "alice",
            "password": "alice123",  # In a real app, this would be hashed
            "email": "alice@example.com",
            "full_name": "Alice Smith",
            "scopes": ["read:profile", "read:items"],
        },
    }

    # Function to create access token
    def create_access_token(data: dict, expires_delta: timedelta = None):
        to_encode = data.copy()
        expire = datetime.utcnow() + (expires_delta or timedelta(minutes=30))
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt

    # Shield to validate token and check scopes
    def authenticate_with_scopes(required_scopes: List[str] = []):
        @shield(
            name="OAuth2 Scope Auth",
            exception_to_raise_if_fail=HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            ),
        )
        def scope_shield(token: str = Depends(oauth2_scheme)):
            try:
                payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
                username = payload.get("sub")
                if username is None:
                    return None

                token_scopes = payload.get("scopes", [])

                # Check if user has any of the required scopes
                for scope in required_scopes:
                    if scope in token_scopes:
                        return {"username": username, "scopes": token_scopes}

                # If we reach here, the user doesn't have the required scopes
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Not enough permissions. Required scope: {required_scopes}",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            except jwt.PyJWTError:
                return None

        return scope_shield

    # Login endpoint to get token
    @app.post("/token")
    async def login(form_data: OAuth2PasswordRequestForm = Depends()):
        user = USERS_DB.get(form_data.username)
        if not user or user["password"] != form_data.password:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Filter requested scopes against available scopes
        scopes = [scope for scope in form_data.scopes if scope in user["scopes"]]

        token_data = {"sub": user["username"], "scopes": scopes}

        access_token = create_access_token(data=token_data)

        return {"access_token": access_token, "token_type": "bearer"}

    # Endpoints with different scope requirements
    @app.get("/users/me")
    @authenticate_with_scopes(["read:profile"])
    async def get_profile(user_data: dict = ShieldedDepends(lambda u: u)):
        username = user_data["username"]
        user = USERS_DB[username]
        return {
            "username": username,
            "email": user["email"],
            "full_name": user["full_name"],
        }

    @app.get("/items")
    @authenticate_with_scopes(["read:items"])
    async def get_items():
        return {"items": [{"id": 1, "name": "Item 1"}, {"id": 2, "name": "Item 2"}]}

    @app.post("/items")
    @authenticate_with_scopes(["write:items"])
    async def create_item(item: Dict):
        return {"id": 3, **item}

    # Helper function to create test tokens with specific scopes
    def create_test_token(username: str, scopes: List[str]):
        token_data = {"sub": username, "scopes": scopes}
        return create_access_token(token_data)

    # Attach the token creation function to the app for testing
    app.create_test_token = create_test_token

    return app


@pytest.fixture
def client():
    app = create_app()
    return TestClient(app)


@pytest.fixture
def full_access_token(client):
    """Token with all scopes"""
    app = client.app
    return app.create_test_token(
        "johndoe", ["read:profile", "read:items", "write:items"]
    )


@pytest.fixture
def read_only_token(client):
    """Token with read-only scopes"""
    app = client.app
    return app.create_test_token("alice", ["read:profile", "read:items"])


@pytest.fixture
def profile_only_token(client):
    """Token with only profile scope"""
    app = client.app
    return app.create_test_token("alice", ["read:profile"])


def test_get_profile_with_profile_scope(client, profile_only_token):
    """Test getting user profile with profile scope"""
    response = client.get(
        "/users/me", headers={"Authorization": f"Bearer {profile_only_token}"}
    )
    assert response.status_code == 200
    assert response.json()["username"] == "alice"
    assert "email" in response.json()
    assert "full_name" in response.json()


def test_get_items_with_items_scope(client, read_only_token):
    """Test getting items with items scope"""
    response = client.get(
        "/items", headers={"Authorization": f"Bearer {read_only_token}"}
    )
    assert response.status_code == 200
    assert "items" in response.json()
    assert len(response.json()["items"]) > 0


def test_get_items_without_items_scope(client, profile_only_token):
    """Test getting items without items scope (should fail)"""
    response = client.get(
        "/items", headers={"Authorization": f"Bearer {profile_only_token}"}
    )
    assert response.status_code == 403
    assert "Not enough permissions" in response.json()["detail"]


def test_create_item_with_write_scope(client, full_access_token):
    """Test creating item with write scope"""
    response = client.post(
        "/items",
        json={"name": "New Item"},
        headers={"Authorization": f"Bearer {full_access_token}"},
    )
    assert response.status_code == 200
    assert response.json()["name"] == "New Item"
    assert "id" in response.json()


def test_create_item_without_write_scope(client, read_only_token):
    """Test creating item without write scope (should fail)"""
    response = client.post(
        "/items",
        json={"name": "New Item"},
        headers={"Authorization": f"Bearer {read_only_token}"},
    )
    assert response.status_code == 403
    assert "Not enough permissions" in response.json()["detail"]


def test_with_invalid_token(client):
    """Test with invalid token"""
    response = client.get(
        "/users/me", headers={"Authorization": f"Bearer invalid.token.here"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid authentication credentials"


def test_without_token(client):
    """Test without token"""
    response = client.get("/users/me")
    assert response.status_code == 401  # OAuth2 returns 401 for missing token
