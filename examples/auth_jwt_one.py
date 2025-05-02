from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import NewType, Optional
from pydantic import BaseModel
from fastapi_shield import shield, ShieldedDepends
from fastapi.testclient import TestClient
import jwt
from datetime import datetime, timedelta

app = FastAPI()

security = HTTPBearer()

# Secret key for JWT signing
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Define user models
class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None

# Define an authenticated user type
AuthenticatedUser = NewType("AuthenticatedUser", User)

# Mock user database
USER_DB = {
    "johndoe": {
        "username": "johndoe",
        "email": "johndoe@example.com",
        "full_name": "John Doe",
        "password": "password123"
    }
}

# Function to create access token
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Shield to validate token and authenticate user
@shield
def authenticate_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> AuthenticatedUser:
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
            )
        
        user_data = USER_DB.get(username)
        if not user_data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
            )
        
        user = User(
            username=user_data["username"],
            email=user_data["email"],
            full_name=user_data["full_name"]
        )
        
        return AuthenticatedUser(user)
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )

# Function to authenticate user and generate token
@app.post("/token")
def login(username: str, password: str):
    user = USER_DB.get(username)
    if not user or user["password"] != password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )
    
    access_token = create_access_token(
        data={"sub": username}
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

# Use the shield in an endpoint
@app.get("/users/me")
@authenticate_token
def get_current_user(user: AuthenticatedUser = ShieldedDepends(lambda user: user)):
    return user

# Test the endpoint
def test_get_current_user():
    client = TestClient(app)
    token_response = client.post("/token", params={"username": "johndoe", "password": "password123"})
    access_token = token_response.json()["access_token"]
    token_type = token_response.json()["token_type"]
    response = client.get("/users/me", headers={"Authorization": f"{token_type} {access_token}"})
    assert response.status_code == 200
    assert response.json() == {"username": "johndoe", "email": "johndoe@example.com", "full_name": "John Doe"}
    
def test_get_current_user_unauthorized():
    client = TestClient(app)
    response = client.get("/users/me", headers={"Authorization": "Bearer wrong-access-token"})
    assert response.status_code == 401

# python -m pytest examples/auth_jwt_one.py
