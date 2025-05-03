from fastapi import Cookie, FastAPI, Depends, HTTPException, status, Header
from fastapi.security import OAuth2PasswordBearer
from typing import NewType, Optional
from pydantic import BaseModel
from fastapi_shield import shield, ShieldedDepends
from fastapi.testclient import TestClient

app = FastAPI()

# OAuth2 setup
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)

# Define user models
class User(BaseModel):
    username: str
    email: Optional[str] = None
    auth_method: str

# Define an authenticated user type
AuthenticatedUser = NewType("AuthenticatedUser", User)

# Mock functions for different auth methods
async def validate_jwt(token: str) -> Optional[User]:
    # In a real app, validate the JWT
    if token == "valid-jwt":
        return User(username="jwt-user", email="jwt@example.com", auth_method="jwt")
    return None

async def validate_api_key(api_key: str) -> Optional[User]:
    # In a real app, validate the API key
    if api_key == "valid-api-key":
        return User(username="api-key-user", email="apikey@example.com", auth_method="api_key")
    return None

async def validate_session_cookie(session_id: str) -> Optional[User]:
    # In a real app, validate the session
    if session_id == "valid-session":
        return User(username="cookie-user", email="cookie@example.com", auth_method="cookie")
    return None

# Shield for flexible authentication
@shield
async def authenticate(
    token: Optional[str] = Depends(oauth2_scheme),
    x_api_key: Optional[str] = Header(None),
    session: Optional[str] = Cookie(None),
) -> AuthenticatedUser:
    # Try JWT authentication
    if token:
        user = await validate_jwt(token)
        if user:
            return AuthenticatedUser(user)
    
    # Try API key authentication
    if x_api_key:
        user = await validate_api_key(x_api_key)
        if user:
            return AuthenticatedUser(user)
    
    # Try session cookie authentication
    if session:
        user = await validate_session_cookie(session)
        if user:
            return AuthenticatedUser(user)
    
    # If no authentication method succeeded
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

# Use the shield in an endpoint
@app.get("/protected")
@authenticate
async def protected_route(user: AuthenticatedUser = ShieldedDepends(lambda user: user)):
    return {
        "message": f"Hello {user.username}! You are authenticated via {user.auth_method}",
        "user": user
    }
    
# Tests

client = TestClient(app)

def test_jwt_auth():
    response = client.get("/protected", headers={"Authorization": "Bearer valid-jwt"})
    assert response.status_code == 200, response.json()
    assert response.json() == {"message": "Hello jwt-user! You are authenticated via jwt", "user": {"username": "jwt-user", "email": "jwt@example.com", "auth_method": "jwt"}}

def test_api_key_auth():
    response = client.get("/protected", headers={"X-API-Key": "valid-api-key"})
    assert response.status_code == 200, response.json()
    assert response.json() == {"message": "Hello api-key-user! You are authenticated via api_key", "user": {"username": "api-key-user", "email": "apikey@example.com", "auth_method": "api_key"}}

def test_session_cookie_auth():
    response = client.get("/protected", headers={"Cookie": "session=valid-session"})
    assert response.status_code == 200, response.json()
    assert response.json() == {"message": "Hello cookie-user! You are authenticated via cookie", "user": {"username": "cookie-user", "email": "cookie@example.com", "auth_method": "cookie"}}

# python -m pytest examples/multi_auth_one.py