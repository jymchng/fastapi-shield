from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from fastapi_shield import shield, ShieldedDepends
import jwt
from dataclasses import dataclass
import pytest
from fastapi.testclient import TestClient

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"


# User model and database omitted for brevity (same as above)
@dataclass
class User:
    username: str
    is_admin: bool
    history: list[str]


USERS = {
    "admin": User(username="admin", is_admin=True, history=[]),
    "user": User(username="user", is_admin=False, history=[]),
}


class Database:
    def get_user(self, user_id: str):
        return USERS.get(user_id)

    def get_user_history(self, user_id: str):
        return USERS[user_id].history


@shield(
    name="JWT Auth",
    exception_to_raise_if_fail=HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    ),
)
def auth_shield(token: str = Depends(oauth2_scheme)):
    """Authenticate user with JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None or username not in USERS:
            return None
        return USERS[username]
    except jwt.PyJWTError:
        return None


@shield(
    name="Admin Check",
    exception_to_raise_if_fail=HTTPException(
        status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions"
    ),
)
def admin_shield(user: User = ShieldedDepends(lambda user: user)):
    """Check if user has admin role"""
    if not user.is_admin:
        return None
    return user


def get_db():
    """Provide database connection"""
    print("Opening database connection")
    db = Database()  # Simulated database connection
    try:
        return db
    finally:
        # Connection closing happens in a different mechanism
        # This is simplified for the example
        pass


# User profile endpoint with clean signature
@app.get("/admin/users/{user_id}")
@auth_shield
@admin_shield
async def get_user_profile(
    user_id: str,
    include_history: bool = False,
    admin: User = ShieldedDepends(lambda user: user),
    db: Database = Depends(get_db),
):
    """Get detailed user profile (admin only)"""
    # Clean business logic
    user = db.get_user(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    if include_history:
        user.history = db.get_user_history(user_id)

    return {
        "user": user,
        "requested_by": admin.username,
        "api_version": "1.0",
    }


client = TestClient(app)


def create_jwt_token(username: str) -> str:
    """Create a JWT token for testing"""
    payload = {"sub": username}
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token


@pytest.fixture
def admin_token():
    """Get a JWT token for the admin user"""
    return create_jwt_token("admin")


@pytest.fixture
def user_token():
    """Get a JWT token for a regular user"""
    return create_jwt_token("user")


@pytest.fixture
def invalid_token():
    """Get an invalid JWT token"""
    return "invalid_token"


def test_missing_token():
    """Test that requests without a token are rejected"""
    response = client.get("/admin/users/user")
    assert response.status_code == 401, response.json()
    assert "Not authenticated" in response.text


def test_invalid_token():
    """Test that requests with an invalid token are rejected"""
    response = client.get(
        "/admin/users/user",
        headers={"Authorization": f"Bearer {create_jwt_token('nonexistent')}"},
    )
    assert response.status_code == 401, response.json()
    assert "Could not validate credentials" in response.text


def test_non_admin_access(user_token):
    """Test that non-admin users cannot access admin endpoints"""
    response = client.get(
        "/admin/users/user", headers={"Authorization": f"Bearer {user_token}"}
    )
    assert response.status_code == 403, response.json()
    assert "Not enough permissions" in response.text


def test_admin_access(admin_token):
    """Test that admin users can access admin endpoints"""
    response = client.get(
        "/admin/users/user", headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200, response.json()
    data = response.json()
    assert data["user"]["username"] == "user"
    assert data["requested_by"] == "admin"
    assert data["api_version"] == "1.0"


def test_include_history_parameter(admin_token):
    """Test that the include_history parameter works correctly"""
    # Test with include_history=True
    response = client.get(
        "/admin/users/user?include_history=true",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200, response.json()
    data = response.json()
    assert "history" in data["user"]

    # Test with include_history=False (default)
    response = client.get(
        "/admin/users/user", headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    # History is set but empty in this implementation
    assert data["user"]["history"] == []


def test_nonexistent_user(admin_token):
    """Test requesting data for a nonexistent user"""
    response = client.get(
        "/admin/users/nonexistent", headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 404, response.json()
    assert "User not found" in response.text


def test_shield_dependency_chain():
    """Test that shields properly depend on each other"""
    # Create a fake JWT token that would fail at the admin check
    fake_token = create_jwt_token("user")  # Regular user, not admin

    response = client.get(
        "/admin/users/admin", headers={"Authorization": f"Bearer {fake_token}"}
    )
    assert response.status_code == 403, response.json()  # Should fail at admin_shield


def test_admin_accessing_own_profile(admin_token):
    """Test admin accessing their own profile data"""
    response = client.get(
        "/admin/users/admin", headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200, response.json()
    data = response.json()
    assert data["user"]["username"] == "admin"
    assert data["user"]["is_admin"] is True


def test_token_expiration():
    """Test behavior with an expired token"""
    # Create an expired token (would require mocking time or using a token with a past exp)
    # For simplicity, we'll simulate by using a token with invalid signature
    payload = {"sub": "admin", "exp": 1}  # Expired long ago
    token = jwt.encode(payload, "wrong_key", algorithm=ALGORITHM)

    response = client.get(
        "/admin/users/user", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 401, response.json()
    assert "Could not validate credentials" in response.text


def test_malformed_token():
    """Test behavior with a malformed token"""
    response = client.get(
        "/admin/users/user", headers={"Authorization": "Bearer not.a.jwt.token"}
    )
    assert response.status_code == 401, response.json()
    assert "Could not validate credentials" in response.text


# python -m pytest examples/clean_logic_one.py
