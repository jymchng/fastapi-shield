from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from typing import NewType
from fastapi_shield import shield, ShieldedDepends
import secrets
from fastapi.testclient import TestClient
app = FastAPI()

security = HTTPBasic()

# Define an authenticated user type
AuthenticatedUser = NewType("AuthenticatedUser", str)

# Mock user database
USER_DB = {
    "johndoe": {
        "username": "johndoe",
        "password": "password123",
        "full_name": "John Doe"
    }
}

# Shield to authenticate the user
@shield
def authenticate_user(credentials: HTTPBasicCredentials = Depends(security)) -> AuthenticatedUser:
    username = credentials.username
    password = credentials.password
    
    user = USER_DB.get(username)
    if not user or not secrets.compare_digest(user["password"], password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    
    return AuthenticatedUser(username)

# Use the shield in an endpoint
@app.get("/profile")
@authenticate_user
def get_profile(username: AuthenticatedUser = ShieldedDepends(lambda s: s)):
    # The user is authenticated at this point
    user_data = USER_DB.get(str(username))
    return {
        "username": user_data["username"],
        "full_name": user_data["full_name"]
    }
    
def test_get_profile():
    client = TestClient(app)
    response = client.get("/profile", auth=("johndoe", "password123"))
    assert response.status_code == 200
    assert response.json() == {
        "username": "johndoe",
        "full_name": "John Doe"
    }
    
def test_get_profile_unauthorized():
    client = TestClient(app)
    response = client.get("/profile", auth=("johndoe", "wrongpassword"))
    assert response.status_code == 401

# python -m pytest examples/basic_auth_one.py