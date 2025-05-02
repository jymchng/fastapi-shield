from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.testclient import TestClient
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import NewType, Optional
from pydantic import BaseModel
from fastapi_shield import shield, ShieldedDepends
import jwt
from datetime import datetime, timedelta
from passlib.context import CryptContext

app = FastAPI()

# OAuth2 and password hashing setup
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Secret key for JWT signing
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Define user models
class UserInDB(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    hashed_password: str

class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None

# Define an authenticated user type
AuthenticatedUser = NewType("AuthenticatedUser", User)

# Mock user database with hashed passwords
USER_DB = {
    "johndoe": {
        "username": "johndoe",
        "email": "johndoe@example.com",
        "full_name": "John Doe",
        "hashed_password": pwd_context.hash("password123")
    }
}

# Verify password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Function to create access token
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Shield to validate JWT and authenticate user
@shield
def authenticate_jwt(token: str = Depends(oauth2_scheme)) -> AuthenticatedUser:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        
        user_data = USER_DB.get(username)
        if not user_data:
            raise credentials_exception
        
        user = User(
            username=user_data["username"],
            email=user_data["email"],
            full_name=user_data["full_name"]
        )
        
        return AuthenticatedUser(user)
    except jwt.PyJWTError:
        raise credentials_exception

# Function to authenticate user and generate token
@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = USER_DB.get(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = create_access_token(
        data={"sub": user["username"]}
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

# Use the shield in an endpoint
@app.get("/users/me")
@authenticate_jwt
def get_current_user(user: AuthenticatedUser = ShieldedDepends(lambda user: user)):
    return user

# Test client
def test_get_current_user():
    client = TestClient(app)
    token_response = client.post("/token", data={"username": "johndoe", "password": "password123"})
    access_token = token_response.json()["access_token"]
    token_type = token_response.json()["token_type"]
    response = client.get("/users/me", headers={"Authorization": f"{token_type} {access_token}"})
    assert response.status_code == 200
    assert response.json() == {"username": "johndoe", "email": "johndoe@example.com", "full_name": "John Doe"}

def test_get_current_user_invalid_token():
    client = TestClient(app)
    response = client.get("/users/me", headers={"Authorization": "Bearer invalid-token"})
    assert response.status_code == 401
    assert response.json() == {"detail": "Could not validate credentials"}

# python -m pytest examples/auth_jwt_two.py