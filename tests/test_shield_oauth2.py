from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.testclient import TestClient
from fastapi_shield.shield import Shield, ShieldedDepends
from pydantic import BaseModel
from passlib.context import CryptContext
from typing import Tuple, List

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
        roles=["user"]
    ),
    "adminuser": UserInDB(
        username="adminuser",
        email="admin@example.com",
        hashed_password=pwd_context.hash("password123"),
        roles=["user", "admin"]
    ),
    "disableduser": UserInDB(
        username="disableduser",
        email="disabled@example.com",
        hashed_password=pwd_context.hash("password123"),
        disabled=True
    )
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
            raise ValueError("Invalid token")
        return username
    except jwt.PyJWTError:
        raise ValueError("Invalid token")

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
        roles=db_user.roles
    )

def get_current_user(token: str) -> User:
    username = get_current_username(token)
    return get_user_from_username(username)

auth_shield = Shield(oauth2_scheme)

# Role-based shield
def roles_shield(required_roles: List[str]):
    def decorator(user: User = ShieldedDepends(get_current_user, shielded_by=auth_shield)):
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
    return {
        "message": "This is an admin endpoint",
        "user": current_user
    }

# Tests
def test_oauth2_shield():
    client = TestClient(app)
    
    # Test public endpoint
    response = client.get("/public")
    assert response.status_code == 200
    assert response.json() == {"message": "This is a public endpoint"}
    
    # Test login endpoint
    login_response = client.post(
        "/token",
        data={"username": "testuser", "password": "password123"}
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
        "/users/me",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == 200
    user_data = response.json()
    assert user_data["username"] == "testuser"
    assert user_data["email"] == "testuser@example.com"
    
    # Test admin endpoint with non-admin user
    response = client.get(
        "/admin",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == 401
    
    # Test with admin user
    admin_login = client.post(
        "/token",
        data={"username": "adminuser", "password": "password123"}
    )
    admin_token = admin_login.json()["access_token"]
    
    response = client.get(
        "/admin",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    assert response.json()["message"] == "This is an admin endpoint"
    assert response.json()["user"]["username"] == "adminuser"
    
    # Test with disabled user
    disabled_login = client.post(
        "/token",
        data={"username": "disableduser", "password": "password123"}
    )
    assert disabled_login.status_code == 400
    assert disabled_login.json()["detail"] == "Inactive user"
