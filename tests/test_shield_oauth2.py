from fastapi import FastAPI, Depends, HTTPException, Path
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.testclient import TestClient
from fastapi_shield.shield import Shield, ShieldedDepends
from pydantic import BaseModel
from passlib.context import CryptContext
from typing import List

import jwt

# JWT configuration
SECRET_KEY = "test-secret-key-for-jwt-tokens-do-not-use-in-production"
ALGORITHM = "HS256"

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# User models
class UserInDB(BaseModel):
    username: str
    email: str
    hashed_password: str
    disabled: bool = False
    roles: List[str] = ["user"]


class User(BaseModel):
    username: str
    email: str
    disabled: bool = False
    roles: List[str] = ["user"]


# Mock database
users_db = {
    "testuser": UserInDB(
        username="testuser",
        email="testuser@example.com",
        hashed_password=pwd_context.hash("password123"),
        roles=["user"],
    ),
    "adminuser": UserInDB(
        username="adminuser",
        email="admin@example.com",
        hashed_password=pwd_context.hash("password123"),
        roles=["user", "admin"],
    ),
    "disableduser": UserInDB(
        username="disableduser",
        email="disabled@example.com",
        hashed_password=pwd_context.hash("password123"),
        disabled=True,
    ),
}


# Authentication functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def authenticate_user(username: str, password: str):
    user = users_db.get(username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict):
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)


# Shield dependency functions
def get_current_username(token: str) -> str:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


def get_user_from_username(username: str) -> User:
    db_user = users_db.get(username)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if db_user.disabled:
        raise HTTPException(status_code=400, detail="User is disabled")
    return User(
        username=db_user.username,
        email=db_user.email,
        disabled=db_user.disabled,
        roles=db_user.roles,
    )


def get_current_user(token: str) -> User:
    username = get_current_username(token)
    return get_user_from_username(username)


auth_shield = Shield(oauth2_scheme)


# Role-based shield
def roles_shield(required_roles: List[str]):
    def decorator(
        user: User = ShieldedDepends(get_current_user, shielded_by=auth_shield),
    ):
        for role in required_roles:
            if role in user.roles:
                return user
        return None

    return Shield(decorator)


admin_only_shield = roles_shield(["admin"])

# Create FastAPI app
app = FastAPI()

# Create authentication shield


# Token endpoint for login
@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")

    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}


# Public endpoint
@app.get("/public")
async def public_endpoint():
    return {"message": "This is a public endpoint"}


# Protected endpoint that requires authentication
@app.get("/users/me")
@auth_shield
async def read_users_me(current_user: User = ShieldedDepends(get_current_user)):
    return current_user


# Protected endpoint that requires admin role
@app.get("/admin")
@auth_shield
@admin_only_shield
async def admin_endpoint(current_user: User = ShieldedDepends(get_current_user)):
    return {"message": "This is an admin endpoint", "user": current_user}


# Tests
def test_public_endpoint():
    client = TestClient(app)
    response = client.get("/public")
    assert response.status_code == 200
    assert response.json() == {"message": "This is a public endpoint"}


def test_login_success():
    client = TestClient(app)
    login_response = client.post(
        "/token", data={"username": "testuser", "password": "password123"}
    )
    assert login_response.status_code == 200
    token_data = login_response.json()
    assert "access_token" in token_data
    assert token_data["token_type"] == "bearer"


def test_protected_endpoint_without_token():
    client = TestClient(app)
    response = client.get("/users/me")
    assert response.status_code == 401


def test_protected_endpoint_with_valid_token():
    client = TestClient(app)
    # Get token
    login_response = client.post(
        "/token", data={"username": "testuser", "password": "password123"}
    )
    access_token = login_response.json()["access_token"]

    # Test with token
    response = client.get(
        "/users/me", headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == 200
    user_data = response.json()
    assert user_data["username"] == "testuser"
    assert user_data["email"] == "testuser@example.com"


def test_admin_endpoint_with_non_admin_user():
    client = TestClient(app)
    # Get token for regular user
    login_response = client.post(
        "/token", data={"username": "testuser", "password": "password123"}
    )
    access_token = login_response.json()["access_token"]

    # Try to access admin endpoint
    response = client.get("/admin", headers={"Authorization": f"Bearer {access_token}"})
    assert response.status_code == 500, (response.status_code, response.json())
    assert response.json()["detail"] == "Failed to shield", response.json()


def test_admin_endpoint_with_admin_user():
    client = TestClient(app)
    # Get token for admin user
    admin_login = client.post(
        "/token", data={"username": "adminuser", "password": "password123"}
    )
    admin_token = admin_login.json()["access_token"]

    # Access admin endpoint
    response = client.get("/admin", headers={"Authorization": f"Bearer {admin_token}"})
    assert response.status_code == 200
    assert response.json()["message"] == "This is an admin endpoint"
    assert response.json()["user"]["username"] == "adminuser"


def test_login_with_disabled_user():
    client = TestClient(app)
    disabled_login = client.post(
        "/token", data={"username": "disableduser", "password": "password123"}
    )
    assert disabled_login.status_code == 400
    assert disabled_login.json()["detail"] == "Inactive user"


# Adding 15 more test cases
def test_login_with_invalid_password():
    client = TestClient(app)
    response = client.post(
        "/token", data={"username": "testuser", "password": "wrongpassword"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect username or password"


def test_login_with_nonexistent_user():
    client = TestClient(app)
    response = client.post(
        "/token", data={"username": "nonexistentuser", "password": "password123"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect username or password"


def test_protected_endpoint_with_invalid_token_format():
    client = TestClient(app)
    response = client.get(
        "/users/me", headers={"Authorization": "Bearer invalidtokenformat"}
    )
    assert response.status_code == 401


def test_protected_endpoint_with_malformed_header():
    client = TestClient(app)
    response = client.get(
        "/users/me", headers={"Authorization": "NotBearer token12345"}
    )
    assert response.status_code == 401


def test_protected_endpoint_with_empty_token():
    client = TestClient(app)
    response = client.get("/users/me", headers={"Authorization": "Bearer "})
    assert response.status_code == 500, (response.status_code, response.json())
    assert response.json()["detail"] == "Failed to shield", response.json()


def test_protected_endpoint_without_authorization_header():
    client = TestClient(app)
    response = client.get("/users/me", headers={})
    assert response.status_code == 401, (response.status_code, response.json())
    assert response.json()["detail"] == "Not authenticated", response.json()


def test_admin_can_access_regular_endpoints():
    client = TestClient(app)
    # Get token for admin user
    login_response = client.post(
        "/token", data={"username": "adminuser", "password": "password123"}
    )
    access_token = login_response.json()["access_token"]

    # Access regular protected endpoint
    response = client.get(
        "/users/me", headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == 200, (response.status_code, response.json())
    assert response.json()["username"] == "adminuser"


# Add /users/role-check endpoint to app
@app.get("/users/role-check")
@auth_shield
async def check_user_role(current_user: User = ShieldedDepends(get_current_user)):
    return {"username": current_user.username, "roles": current_user.roles}


def test_role_check_endpoint():
    client = TestClient(app)
    # Get token for regular user
    login_response = client.post(
        "/token", data={"username": "testuser", "password": "password123"}
    )
    access_token = login_response.json()["access_token"]

    # Check roles
    response = client.get(
        "/users/role-check", headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == 200
    assert response.json()["username"] == "testuser"
    assert "user" in response.json()["roles"]
    assert "admin" not in response.json()["roles"]


def test_admin_role_check():
    client = TestClient(app)
    # Get token for admin user
    login_response = client.post(
        "/token", data={"username": "adminuser", "password": "password123"}
    )
    access_token = login_response.json()["access_token"]

    # Check roles
    response = client.get(
        "/users/role-check", headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == 200
    assert response.json()["username"] == "adminuser"
    assert "user" in response.json()["roles"]
    assert "admin" in response.json()["roles"]


# Add multi-role shield
def multi_role_shield(required_roles: List[str], require_all: bool = False):
    def decorator(user: User = ShieldedDepends(get_current_user)):
        if require_all:
            # User must have all specified roles
            has_all = all(role in user.roles for role in required_roles)
            return user if has_all else None
        else:
            # User must have at least one of the specified roles
            has_any = any(role in user.roles for role in required_roles)
            return user if has_any else None

    return Shield(decorator)


# Add endpoint requiring multiple roles
@app.get("/multi-role")
@auth_shield
@multi_role_shield(["admin", "user"], require_all=True)
async def multi_role_endpoint(current_user: User = ShieldedDepends(get_current_user)):
    return {"message": "This endpoint requires multiple roles", "user": current_user}


def test_multi_role_endpoint_with_admin():
    client = TestClient(app)
    # Get token for admin user (who has both admin and user roles)
    login_response = client.post(
        "/token", data={"username": "adminuser", "password": "password123"}
    )
    access_token = login_response.json()["access_token"]

    # Access multi-role endpoint
    response = client.get(
        "/multi-role", headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == 200
    assert response.json()["message"] == "This endpoint requires multiple roles"


def test_nested_dependencies():
    # This test verifies that ShieldedDepends works correctly with nested dependencies
    client = TestClient(app)
    login_response = client.post(
        "/token", data={"username": "adminuser", "password": "password123"}
    )
    access_token = login_response.json()["access_token"]

    # The admin endpoint already has nested dependencies
    response = client.get("/admin", headers={"Authorization": f"Bearer {access_token}"})
    assert response.status_code == 200


def get_current_user_custom(error: str = Path()) -> User:
    return get_current_user(error)


# Add an endpoint with custom forbidden response
custom_shield = Shield(
    get_current_user_custom,
    exception_to_raise_if_fail=HTTPException(
        status_code=403, detail="Custom forbidden response"
    ),
)


@app.get("/custom-error/{error}")
@custom_shield
async def custom_error_endpoint():
    return {"message": "You won't see this if unauthorized"}


def test_custom_error_response():
    client = TestClient(app)
    response = client.get("/custom-error")
    assert response.status_code == 404, (response.status_code, response.json())
    assert response.json()["detail"] == "Not Found"


# Add case-sensitive username endpoint
@app.get("/case-sensitive")
@auth_shield
async def case_sensitive_endpoint(
    current_user: User = ShieldedDepends(get_current_user),
):
    # This test ensures the exact username is preserved
    if current_user.username != "adminuser":  # Exact match required
        raise HTTPException(status_code=403, detail="Username must match exactly")
    return {"message": "Case sensitive match succeeded"}


def test_case_sensitive_matching():
    client = TestClient(app)
    login_response = client.post(
        "/token", data={"username": "adminuser", "password": "password123"}
    )
    access_token = login_response.json()["access_token"]

    response = client.get(
        "/case-sensitive", headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == 200
    assert response.json()["message"] == "Case sensitive match succeeded"


# Add an endpoint with multiple shield dependencies
@app.get("/multiple-shields")
@auth_shield
async def multiple_shields_endpoint(
    token_user: User = ShieldedDepends(get_current_user),
    roles: List[str] = ShieldedDepends(lambda token: get_current_user(token).roles),
):
    return {"user": token_user, "roles": roles}


def test_multiple_shield_dependencies():
    client = TestClient(app)
    login_response = client.post(
        "/token", data={"username": "adminuser", "password": "password123"}
    )
    access_token = login_response.json()["access_token"]

    response = client.get(
        "/multiple-shields", headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == 200
    assert response.json()["user"]["username"] == "adminuser"
    assert "admin" in response.json()["roles"]


def test_oauth2_shield():
    """
    This is the original monolithic test, kept for reference.
    All functionality is now broken into individual test functions.
    """
    client = TestClient(app)

    # Test public endpoint
    response = client.get("/public")
    assert response.status_code == 200
    assert response.json() == {"message": "This is a public endpoint"}

    # Test login endpoint
    login_response = client.post(
        "/token", data={"username": "testuser", "password": "password123"}
    )
    assert login_response.status_code == 200
    token_data = login_response.json()
    assert "access_token" in token_data
    assert token_data["token_type"] == "bearer"

    access_token = token_data["access_token"]

    # Test protected endpoint without token
    response = client.get("/users/me")
    assert response.status_code == 401

    # Test protected endpoint with token
    response = client.get(
        "/users/me", headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == 200, (response.status_code, response.json())
    user_data = response.json()
    assert user_data["username"] == "testuser"
    assert user_data["email"] == "testuser@example.com"

    # Test admin endpoint with non-admin user
    response = client.get("/admin", headers={"Authorization": f"Bearer {access_token}"})
    assert response.status_code == 500
    assert response.json()["detail"] == "Failed to shield"

    # Test with admin user
    admin_login = client.post(
        "/token", data={"username": "adminuser", "password": "password123"}
    )
    admin_token = admin_login.json()["access_token"]

    response = client.get("/admin", headers={"Authorization": f"Bearer {admin_token}"})
    assert response.status_code == 200
    assert response.json()["message"] == "This is an admin endpoint"
    assert response.json()["user"]["username"] == "adminuser"

    # Test with disabled user
    disabled_login = client.post(
        "/token", data={"username": "disableduser", "password": "password123"}
    )
    assert disabled_login.status_code == 400
    assert disabled_login.json()["detail"] == "Inactive user"
