from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import NewType, Optional, List
from pydantic import BaseModel
from fastapi_shield import shield, ShieldedDepends
import jwt
from datetime import datetime, timedelta
from passlib.context import CryptContext
from fastapi.testclient import TestClient

app = FastAPI()

# OAuth2 and password hashing setup
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Secret key for JWT signing
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


# Define user models
class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str
    scopes: List[str] = []


class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    scopes: List[str] = []


# Define an authenticated user type
AuthenticatedUser = NewType("AuthenticatedUser", User)

# Mock user database with hashed passwords and scopes
USER_DB = {
    "johndoe": {
        "username": "johndoe",
        "email": "johndoe@example.com",
        "full_name": "John Doe",
        "hashed_password": pwd_context.hash("password123"),
        "scopes": ["read:profile", "read:items", "write:items"],
    }
}


# Verify password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


# Function to create access token
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# Shield to validate JWT and authenticate user with scope checking
def authenticate_with_scopes(required_scopes: List[str] = []) -> AuthenticatedUser:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    @shield
    def inner_auth_shield(token: str = Depends(oauth2_scheme)) -> AuthenticatedUser:
        try:
            payload: dict = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username: Optional[str] = payload.get("sub")
            token_scopes: List[str] = payload.get("scopes", [])

            if username is None:
                raise credentials_exception

            token_data = TokenData(username=username, scopes=token_scopes)

            user_data = USER_DB.get(token_data.username)
            if not user_data:
                raise credentials_exception

            user = User(
                username=user_data["username"],
                email=user_data["email"],
                full_name=user_data["full_name"],
                scopes=token_data.scopes,
            )

            # Check if user has all required scopes
            for scope in required_scopes:
                if scope in user.scopes:
                    return AuthenticatedUser(user)

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Not enough permissions. Required scope: {scope}",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except jwt.PyJWTError:
            raise credentials_exception

    return inner_auth_shield


# Function to authenticate user and generate token
@app.post("/token", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = USER_DB.get(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
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


# Use the shield in endpoints with different scope requirements
@app.get("/users/me")
@authenticate_with_scopes(required_scopes=["read:profile"])
def get_current_user(user: AuthenticatedUser = ShieldedDepends(lambda user: user)):
    return user


@app.get("/items")
@authenticate_with_scopes(required_scopes=["read:items"])
def get_items():
    return {"items": [{"item_id": 1, "name": "Foo"}, {"item_id": 2, "name": "Bar"}]}


@app.post("/items")
@authenticate_with_scopes(required_scopes=["write:items"])
def create_item(
    item: dict,
):
    return {"item_id": 3, **item}


# python -m pytest examples/oauth_scopes_one.py


# Test client
def test_get_current_user():
    client = TestClient(app)
    token_response = client.post(
        "/token",
        data={
            "username": "johndoe",
            "password": "password123",
            "scope": "read:profile",
        },
    )
    access_token = token_response.json()["access_token"]
    token_type = token_response.json()["token_type"]
    response = client.get(
        "/users/me", headers={"Authorization": f"{token_type} {access_token}"}
    )
    assert response.status_code == 200
    assert response.json() == {
        "username": "johndoe",
        "email": "johndoe@example.com",
        "full_name": "John Doe",
        "scopes": ["read:profile"],
    }


def test_get_items():
    client = TestClient(app)
    token_response = client.post(
        "/token",
        data={"username": "johndoe", "password": "password123", "scope": "read:items"},
    )
    access_token = token_response.json()["access_token"]
    token_type = token_response.json()["token_type"]
    response = client.get(
        "/items", headers={"Authorization": f"{token_type} {access_token}"}
    )
    assert response.status_code == 200
    assert response.json() == {
        "items": [{"item_id": 1, "name": "Foo"}, {"item_id": 2, "name": "Bar"}]
    }


def test_create_item():
    client = TestClient(app)
    token_response = client.post(
        "/token",
        data={"username": "johndoe", "password": "password123", "scope": "write:items"},
    )
    access_token = token_response.json()["access_token"]
    token_type = token_response.json()["token_type"]
    response = client.post(
        "/items",
        headers={"Authorization": f"{token_type} {access_token}"},
        json={"name": "Baz"},
    )
    assert response.status_code == 200
    assert response.json() == {"item_id": 3, "name": "Baz"}


def test_unauthorized_access():
    client = TestClient(app)
    response = client.get("/users/me")
    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}


def test_missing_scope():
    client = TestClient(app)
    # Get a token without any scopes
    token_response = client.post(
        "/token",
        data={
            "username": "johndoe",
            "password": "password123",
            # No scope provided intentionally
        },
    )
    access_token = token_response.json()["access_token"]
    token_type = token_response.json()["token_type"]

    # Try to access endpoints that require specific scopes
    items_response = client.get(
        "/items", headers={"Authorization": f"{token_type} {access_token}"}
    )
    assert items_response.status_code == 403
    assert "Not enough permissions" in items_response.json()["detail"]

    profile_response = client.get(
        "/users/me", headers={"Authorization": f"{token_type} {access_token}"}
    )
    assert profile_response.status_code == 403
    assert "Not enough permissions" in profile_response.json()["detail"]

    create_response = client.post(
        "/items",
        headers={"Authorization": f"{token_type} {access_token}"},
        json={"name": "Baz"},
    )
    assert create_response.status_code == 403
    assert "Not enough permissions" in create_response.json()["detail"]
