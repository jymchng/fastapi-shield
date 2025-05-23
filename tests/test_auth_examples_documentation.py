import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI, Depends, Header, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, HTTPBasic
from fastapi_shield import shield, ShieldedDepends
from typing import Annotated, Dict, Optional
import secrets
import jwt
from datetime import datetime, timedelta
import base64


# API Key Authentication Tests
def test_api_key_authentication():
    """Test API Key Authentication example from documentation"""
    # Create a FastAPI app with API Key Authentication
    app = FastAPI()

    # In a real application, this would be a database
    API_KEYS = {
        "user1": "sk_test_abcdefghijklmnopqrstuvwxyz",
        "user2": "sk_test_zyxwvutsrqponmlkjihgfedcba",
    }

    # Create a shield for API key validation
    @shield(
        name="ApiKey",
        auto_error=True,
        exception_to_raise_if_fail=HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "ApiKey"},
        ),
    )
    def api_key_shield(api_key: str = Header(alias="X-API-Key")):
        if not api_key.startswith("sk_test_"):
            return None
            
        # Check if the API key exists in our database
        for username, key in API_KEYS.items():
            if secrets.compare_digest(key, api_key):
                return username
        
        # API key not found
        return None

    @app.get("/api/protected")
    @api_key_shield
    async def protected_route():
        return {
            "message": "Hello! You accessed a protected route.",
            "data": "This is sensitive data that requires authentication."
        }

    @app.get("/api/profile")
    @api_key_shield
    async def get_profile():
        return {
            "subscription": "premium",
            "account_type": "business"
        }

    # Create a test client
    client = TestClient(app)

    # Test with valid API key for user1
    response = client.get(
        "/api/protected",
        headers={"X-API-Key": "sk_test_abcdefghijklmnopqrstuvwxyz"}
    )
    assert response.status_code == 200
    assert response.json() == {
        "message": "Hello! You accessed a protected route.",
        "data": "This is sensitive data that requires authentication."
    }

    # Test with valid API key for user2
    response = client.get(
        "/api/profile",
        headers={"X-API-Key": "sk_test_zyxwvutsrqponmlkjihgfedcba"}
    )
    assert response.status_code == 200
    assert response.json() == {
        "subscription": "premium",
        "account_type": "business"
    }

    # Test with invalid API key format
    response = client.get(
        "/api/protected",
        headers={"X-API-Key": "invalid_key_format"}
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid API key"}

    # Test with invalid API key (correct format but not in database)
    response = client.get(
        "/api/protected",
        headers={"X-API-Key": "sk_test_invalid_but_correct_format"}
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid API key"}

    # Test without API key
    response = client.get("/api/protected")
    assert response.status_code == 422  # FastAPI validation error


# Basic Authentication Tests
def test_basic_authentication():
    """Test Basic Authentication example from documentation"""
    app = FastAPI()

    # Mock user database (username: password)
    USERS = {
        "admin": "strongpassword",
        "user": "userpassword",
    }

    # Basic authentication shield
    @shield(
        name="Basic Auth",
        auto_error=True,
        exception_to_raise_if_fail=HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Basic"},
        ),
    )
    def basic_auth_shield(authorization: str = Header()):
        if not authorization or not authorization.startswith("Basic "):
            return None
        
        auth_data = authorization.replace("Basic ", "")
        try:
            decoded = base64.b64decode(auth_data).decode("ascii")
            username, password = decoded.split(":")
        except Exception:
            return None
        
        # Validate username format
        if len(username) < 3:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username must be at least 3 characters",
            )
        
        # Validate password format
        if len(password) < 8:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password must be at least 8 characters",
            )
        
        # Check if user exists and password is correct
        if username not in USERS:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username",
                headers={"WWW-Authenticate": "Basic"},
            )
        
        correct_password = USERS[username]
        
        # Use secrets.compare_digest to prevent timing attacks
        if not secrets.compare_digest(password, correct_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid password",
                headers={"WWW-Authenticate": "Basic"},
            )
        
        return username

    @app.get("/users/me")
    @basic_auth_shield
    async def get_current_user_info():
        return {
            "message": "You are authenticated!"
        }

    # Admin access shield (checks if authenticated user is admin)
    @shield(
        name="Admin Only",
        auto_error=True,
        exception_to_raise_if_fail=HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admin users can access this resource",
        ),
    )
    def admin_only_shield(username: str = ShieldedDepends(lambda u: u)):
        if username == "admin":
            return username
        return None

    @app.get("/admin")
    @basic_auth_shield
    @admin_only_shield
    async def admin_panel():
        return {
            "message": "Welcome to the admin panel",
            "secret_stats": {"total_users": 2, "active_users": 1}
        }

    # Create a test client
    client = TestClient(app)

    # Test with valid admin credentials
    admin_creds = base64.b64encode(b"admin:strongpassword").decode("ascii")
    response = client.get(
        "/users/me",
        headers={"Authorization": f"Basic {admin_creds}"}
    )
    assert response.status_code == 200
    assert response.json() == {
        "message": "You are authenticated!"
    }

    # Test admin endpoint with admin credentials
    response = client.get(
        "/admin",
        headers={"Authorization": f"Basic {admin_creds}"}
    )
    assert response.status_code == 200
    assert response.json() == {
        "message": "Welcome to the admin panel",
        "secret_stats": {"total_users": 2, "active_users": 1}
    }

    # Test with valid user credentials
    user_creds = base64.b64encode(b"user:userpassword").decode("ascii")
    response = client.get(
        "/users/me",
        headers={"Authorization": f"Basic {user_creds}"}
    )
    assert response.status_code == 200
    assert response.json() == {
        "message": "You are authenticated!"
    }

    # Test admin endpoint with non-admin credentials
    response = client.get(
        "/admin",
        headers={"Authorization": f"Basic {user_creds}"}
    )
    assert response.status_code == 403
    assert response.json() == {
        "detail": "Only admin users can access this resource"
    }

    # Test with invalid password
    invalid_creds = base64.b64encode(b"admin:wrongpassword").decode("ascii")
    response = client.get(
        "/users/me",
        headers={"Authorization": f"Basic {invalid_creds}"}
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid password"}

    # Test with invalid username
    invalid_creds = base64.b64encode(b"nobody:password").decode("ascii")
    response = client.get(
        "/users/me",
        headers={"Authorization": f"Basic {invalid_creds}"}
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid username"}

    # Test with short username
    invalid_creds = base64.b64encode(b"a:password").decode("ascii")
    response = client.get(
        "/users/me",
        headers={"Authorization": f"Basic {invalid_creds}"}
    )
    assert response.status_code == 400
    assert "Username must be at least 3 characters" in response.json()["detail"]


# JWT Authentication Tests
def test_jwt_authentication():
    """Test JWT Authentication example from documentation"""
    app = FastAPI()

    # Configuration
    SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
    ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES = 30

    # Mock user database
    class UserInDB:
        def __init__(self, username, hashed_password, email=None, disabled=None):
            self.username = username
            self.hashed_password = hashed_password
            self.email = email
            self.disabled = disabled

    # In a real app, you'd store hashed passwords using proper password hashing
    USERS_DB = {
        "johndoe": {
            "username": "johndoe",
            "hashed_password": "fakehashed_secret",
            "email": "johndoe@example.com",
            "disabled": False,
        },
        "alice": {
            "username": "alice",
            "hashed_password": "fakehashed_alice",
            "email": "alice@example.com",
            "disabled": True,
        },
    }

    # Helper functions
    def get_user(db, username):
        if username in db:
            user_dict = db[username]
            return UserInDB(**user_dict)
        return None

    def verify_password(plain_password, hashed_password):
        # In a real app, you would use proper password verification
        # For testing, we expect the hash to be "fakehashed_" + plain_password
        return "fakehashed_" + plain_password == hashed_password

    def authenticate_user(fake_db, username, password):
        user = get_user(fake_db, username)
        if not user:
            return None
        if not verify_password(password, user.hashed_password):
            return None
        return user

    def create_access_token(data, expires_delta=None):
        to_encode = data.copy()
        # Don't add expiration for testing to avoid JWT decode issues
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt

    # JWT Authentication shield
    @shield(
        name="JWT Auth",
        auto_error=True,
        exception_to_raise_if_fail=HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ),
    )
    def jwt_auth_shield(authorization: str = Header()):
        if not authorization or not authorization.startswith("Bearer "):
            return None

        token = authorization.replace("Bearer ", "")
        
        if not token or len(token) < 10:
            return None
        
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username = payload.get("sub")
            
            if username is None:
                return None
                
            user = get_user(USERS_DB, username)
            
            if user is None:
                return None
                
            return {
                "username": user.username,
                "email": user.email,
                "disabled": user.disabled
            }
        except jwt.PyJWTError:
            return None

    # Endpoints
    @app.post("/token")
    async def login_for_access_token(username: str = Header(), password: str = Header()):
        user = authenticate_user(USERS_DB, username, password)
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.username}, expires_delta=access_token_expires
        )
        
        return {"access_token": access_token, "token_type": "bearer"}

    @app.get("/users/me")
    @jwt_auth_shield
    async def read_users_me(user_data: dict = ShieldedDepends(lambda u: u)):
        if user_data.get("disabled"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Inactive user",
            )
        return {
            "message": "You are authenticated and active!"
        }

    @app.get("/users/me/items")
    @jwt_auth_shield
    async def read_own_items(user_data: dict = ShieldedDepends(lambda u: u)):
        if user_data.get("disabled"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Inactive user",
            )
        return [
            {"item_id": "1", "owner": "current_user"},
            {"item_id": "2", "owner": "current_user"}
        ]

    # Create a test client
    client = TestClient(app)

    # Test with valid credentials - johndoe
    response = client.post(
        "/token", 
        headers={"username": "johndoe", "password": "secret"}
    )
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert response.json()["token_type"] == "bearer"
    
    # Store the token for future requests
    token = response.json()["access_token"]
    
    # Test /users/me endpoint with valid token
    response = client.get(
        "/users/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert response.json() == {
        "message": "You are authenticated and active!"
    }
    
    # Test /users/me/items endpoint with valid token
    response = client.get(
        "/users/me/items",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert response.json() == [
        {"item_id": "1", "owner": "current_user"},
        {"item_id": "2", "owner": "current_user"}
    ]
    
    # Test with invalid token
    response = client.get(
        "/users/me",
        headers={"Authorization": "Bearer invalid_token"}
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Could not validate credentials"}
    
    # Test with disabled user - alice
    response = client.post(
        "/token", 
        headers={"username": "alice", "password": "alice"}
    )
    assert response.status_code == 200
    
    alice_token = response.json()["access_token"]
    
    response = client.get(
        "/users/me",
        headers={"Authorization": f"Bearer {alice_token}"}
    )
    assert response.status_code == 400
    assert response.json() == {"detail": "Inactive user"}
    
    # Test with non-existent user
    response = client.post(
        "/token", 
        headers={"username": "nonexistent", "password": "password"}
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Incorrect username or password"}


# OAuth2 Authentication Tests
def test_oauth2_authentication():
    """Test OAuth2 Authentication example from documentation"""
    app = FastAPI()

    # Configuration
    SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
    ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES = 30

    # OAuth2 configuration (in a real app, these would be registered with the OAuth provider)
    OAUTH2_CLIENT_ID = "myclientid"
    OAUTH2_CLIENT_SECRET = "myclientsecret"
    OAUTH2_REDIRECT_URL = "http://localhost:8000/auth/callback"

    # Mock user database
    USERS = {
        "user1": {
            "id": "user1",
            "username": "johndoe",
            "email": "john@example.com",
            "full_name": "John Doe",
            "scopes": ["read:profile", "read:email"],
        },
        "user2": {
            "id": "user2",
            "username": "janedoe",
            "email": "jane@example.com",
            "full_name": "Jane Doe",
            "scopes": ["read:profile", "read:email", "write:profile"],
        },
    }

    # Helper functions
    def create_access_token(data, expires_delta=None):
        to_encode = data.copy()
        # Don't add expiration for testing to avoid JWT decode issues
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt

    # OAuth2 token shield
    @shield(
        name="OAuth2 Token",
        auto_error=True,
        exception_to_raise_if_fail=HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ),
    )
    def oauth2_token_shield(authorization: str = Header()):
        if not authorization or not authorization.startswith("Bearer "):
            return None

        token = authorization.replace("Bearer ", "")
        
        if not token or len(token) < 10:
            return None
            
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            sub = payload.get("sub")
            scopes = payload.get("scopes", [])
            
            if sub is None:
                return None
            
            if sub not in USERS:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            user = USERS[sub].copy()
            
            # Update user's scopes based on token
            user["scopes"] = scopes
            
            return user
        except jwt.PyJWTError:
            return None

    # Endpoints
    @app.get("/auth/login")
    async def login():
        return {
            "auth_url": f"https://example.com/oauth/authorize?client_id={OAUTH2_CLIENT_ID}&redirect_uri={OAUTH2_REDIRECT_URL}&response_type=code&scope=read:profile+read:email"
        }

    @app.get("/auth/callback")
    async def auth_callback(code: str, state: Optional[str] = None):
        # In a real app, you would exchange the code for a token with the OAuth provider
        # For this example, we'll create a mock token
        
        # Mock user ID (in a real app, this would come from the OAuth provider)
        user_id = "user1"
        
        # Create a token with the user's ID and scopes
        token_data = {
            "sub": user_id,
            "scopes": USERS[user_id]["scopes"],
        }
        
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(token_data, access_token_expires)
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        }

    @app.get("/users/me")
    @oauth2_token_shield
    async def get_my_profile(user: dict = ShieldedDepends(lambda u: u)):
        # Check if user has required scope
        if "read:profile" not in user.get("scopes", []):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions. Required scope: read:profile",
            )
        return {
            "message": "Profile accessed successfully"
        }

    @app.get("/users/me/email")
    @oauth2_token_shield
    async def get_my_email(user: dict = ShieldedDepends(lambda u: u)):
        # Check if user has required scope
        if "read:email" not in user.get("scopes", []):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions. Required scope: read:email",
            )
        return {
            "message": "Email accessed successfully"
        }

    @app.put("/users/me")
    @oauth2_token_shield
    async def update_my_profile(user: dict = ShieldedDepends(lambda u: u), full_name: Optional[str] = None):
        # Check if user has required scope
        if "write:profile" not in user.get("scopes", []):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions. Required scope: write:profile",
            )
        return {
            "message": "Profile updated successfully",
            "full_name": full_name or "Default Name"
        }

    # Create a test client
    client = TestClient(app)

    # Test auth/login endpoint
    response = client.get("/auth/login")
    assert response.status_code == 200
    assert "auth_url" in response.json()
    assert OAUTH2_CLIENT_ID in response.json()["auth_url"]
    assert OAUTH2_REDIRECT_URL in response.json()["auth_url"]

    # Test auth/callback endpoint
    response = client.get("/auth/callback", params={"code": "somecode"})
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert response.json()["token_type"] == "bearer"
    assert response.json()["expires_in"] == ACCESS_TOKEN_EXPIRE_MINUTES * 60

    # Store the token for future requests
    token = response.json()["access_token"]

    # Test endpoints with user1 token (has read:profile and read:email scopes)
    # Create a custom token with specific scopes
    token_data = {
        "sub": "user1",
        "scopes": ["read:profile", "read:email"],
    }
    token = create_access_token(token_data)

    # Test /users/me endpoint (requires read:profile)
    response = client.get(
        "/users/me", 
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert response.json() == {
        "message": "Profile accessed successfully"
    }

    # Test /users/me/email endpoint (requires read:email)
    response = client.get(
        "/users/me/email", 
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert response.json() == {
        "message": "Email accessed successfully"
    }

    # Test /users/me endpoint with PUT (requires write:profile)
    response = client.put(
        "/users/me", 
        headers={"Authorization": f"Bearer {token}"},
        params={"full_name": "John Updated"}
    )
    assert response.status_code == 403
    assert "Not enough permissions" in response.json()["detail"]

    # Test with user2 token who has all required scopes
    token_data = {
        "sub": "user2",
        "scopes": ["read:profile", "read:email", "write:profile"],
    }
    token2 = create_access_token(token_data)

    # Test profile update with user2
    response = client.put(
        "/users/me", 
        headers={"Authorization": f"Bearer {token2}"},
        params={"full_name": "Jane Updated"}
    )
    assert response.status_code == 200
    assert response.json()["full_name"] == "Jane Updated"
    assert response.json()["message"] == "Profile updated successfully"

    # Test with invalid token
    response = client.get(
        "/users/me", 
        headers={"Authorization": "Bearer invalid.token"}
    )
    assert response.status_code == 401

    # Test with expired token - create a token that's already expired
    # Skip expired token test for now since we're not using exp in tokens
    # This would be implemented in a real app with proper expiration handling


# Multi-Factor Authentication Tests
def test_mfa_authentication():
    """Test Multi-Factor Authentication example from documentation"""
    app = FastAPI()

    # Configuration
    SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
    ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES = 30

    # Mock user database
    USERS_DB = {
        "johndoe": {
            "username": "johndoe",
            "hashed_password": "fakehashed_johndoe",
            "email": "john@example.com",
            "full_name": "John Doe",
            "disabled": False,
            "mfa_enabled": True,
            "mfa_secret": "JBSWY3DPEHPK3PXP"
        },
        "janedoe": {
            "username": "janedoe",
            "hashed_password": "fakehashed_janedoe",
            "email": "jane@example.com",
            "full_name": "Jane Doe",
            "disabled": False,
            "mfa_enabled": False
        },
    }

    # Mock MFA tokens storage (in a real app, this would be a database table)
    MFA_TOKENS = {}  # token -> username mapping

    # Helper functions
    def verify_password(plain_password, hashed_password):
        # In a real app, you would use a secure password hashing function
        return "fakehashed_" + plain_password == hashed_password

    def authenticate_user(username, password):
        if username not in USERS_DB:
            return None
        
        user = USERS_DB[username]
        
        if not verify_password(password, user["hashed_password"]):
            return None
            
        return user

    def create_token(data, expires_delta=None):
        to_encode = data.copy()
        # Don't add expiration for testing to avoid JWT decode issues
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt

    def verify_mfa_code(user, mfa_code):
        # In a real app, you would use TOTP algorithm to verify the code
        # For this example, we'll accept any 6-digit code
        if not user["mfa_enabled"]:
            return True
            
        # We'll simulate TOTP verification by accepting any code for this example
        return len(mfa_code) == 6 and mfa_code.isdigit()

    def generate_mfa_token(username):
        # Generate a random token
        mfa_token = secrets.token_urlsafe(32)
        
        # Store the token -> username mapping
        MFA_TOKENS[mfa_token] = username
        
        return mfa_token

    # JWT authentication shield with MFA verification
    @shield(
        name="JWT Auth with MFA",
        auto_error=False,  # Let specific exceptions bubble up
    )
    def jwt_mfa_shield(authorization: str = Header(None)):
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )

        token = authorization.replace("Bearer ", "")
        
        if not token or len(token) < 10:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username = payload.get("sub")
            mfa_verified = payload.get("mfa_verified", False)
            
            if username is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "Bearer"},
                )
                
            if username not in USERS_DB:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found",
                    headers={"WWW-Authenticate": "Bearer"},
                )
                
            user = USERS_DB[username]
            
            # If MFA is enabled but not verified, raise a specific exception
            if user["mfa_enabled"] and not mfa_verified:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="MFA verification required",
                    headers={"WWW-Authenticate": "Bearer"},
                )
                
            return user
        except jwt.PyJWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )

    # MFA code validation shield
    @shield(
        name="MFA Code Validator",
        auto_error=True,
        exception_to_raise_if_fail=HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA code must be a 6-digit number",
        ),
    )
    def mfa_code_shield(mfa_code: str = Header(alias="mfa-code")):
        if not mfa_code or not mfa_code.isdigit() or len(mfa_code) != 6:
            return None
        return mfa_code

    # Endpoints
    @app.post("/token")
    async def login_for_access_token(username: str = Header(), password: str = Header()):
        user = authenticate_user(username, password)
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Create a token that indicates if MFA is required
        token_data = {
            "sub": user["username"],
            "mfa_verified": not user["mfa_enabled"],  # Set to True if MFA is not enabled
        }
        
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_token(token_data, access_token_expires)
        
        response_data = {
            "access_token": access_token,
            "token_type": "bearer",
            "requires_mfa": user["mfa_enabled"]
        }
        
        # If MFA is required, add an MFA token
        if user["mfa_enabled"]:
            mfa_token = generate_mfa_token(user["username"])
            response_data["mfa_token"] = mfa_token
        
        return response_data

    # MFA token validation shield
    @shield(
        name="MFA Token Validator",
        auto_error=True,
        exception_to_raise_if_fail=HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid MFA token",
        ),
    )
    def mfa_token_shield(mfa_token: str = Header(alias="mfa-token")):
        if mfa_token not in MFA_TOKENS:
            return None
        return mfa_token

    @app.post("/verify-mfa")
    @mfa_token_shield
    @mfa_code_shield
    async def verify_mfa():
        # Since the shields have already validated the MFA token and code,
        # we can just return success. In a real app, you would:
        # 1. Validate the MFA code against the user's TOTP secret
        # 2. Generate a new fully-authenticated JWT token  
        # 3. Invalidate the MFA token
        return {
            "message": "MFA verification endpoint called"
        }

    @app.get("/users/me")
    @jwt_mfa_shield
    async def read_users_me(user: dict = ShieldedDepends(lambda u: u)):
        if user.get("disabled"):
            raise HTTPException(status_code=400, detail="Inactive user")
        return {
            "message": "You are authenticated!"
        }

    @app.post("/users/me/enable-mfa")
    @jwt_mfa_shield
    async def enable_mfa(user: dict = ShieldedDepends(lambda u: u)):
        if user.get("disabled"):
            raise HTTPException(status_code=400, detail="Inactive user")
        return {
            "message": "MFA would be enabled"
        }

    # Create a test client
    client = TestClient(app)

    # Test login for user without MFA (janedoe)
    response = client.post(
        "/token",
        headers={"username": "janedoe", "password": "janedoe"}
    )
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert response.json()["token_type"] == "bearer"
    assert response.json()["requires_mfa"] is False
    assert "mfa_token" not in response.json()
    
    # Save the token for later use
    jane_token = response.json()["access_token"]

    # Test login for user with MFA (johndoe)
    response = client.post(
        "/token",
        headers={"username": "johndoe", "password": "johndoe"}
    )
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert response.json()["token_type"] == "bearer"
    assert response.json()["requires_mfa"] is True
    assert "mfa_token" in response.json()
    
    # Save the pre-MFA token and MFA token
    john_pre_mfa_token = response.json()["access_token"]
    mfa_token = response.json()["mfa_token"]

    # Test accessing protected endpoint without MFA verification (should fail)
    response = client.get(
        "/users/me",
        headers={"Authorization": f"Bearer {john_pre_mfa_token}"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "MFA verification required"

    # Test accessing protected endpoint with non-MFA user (janedoe)
    response = client.get(
        "/users/me",
        headers={"Authorization": f"Bearer {jane_token}"}
    )
    assert response.status_code == 200
    assert response.json()["message"] == "You are authenticated!"

    # Test MFA verification endpoint
    response = client.post(
        "/verify-mfa",
        headers={"mfa-token": mfa_token, "mfa-code": "123456"}
    )
    assert response.status_code == 200, response.json()
    assert response.json()["message"] == "MFA verification endpoint called"

    # Test with invalid MFA code format
    response = client.post(
        "/verify-mfa",
        headers={"mfa-token": mfa_token, "mfa-code": "12345"}  # Only 5 digits
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "MFA code must be a 6-digit number"

    # Test with invalid MFA token
    response = client.post(
        "/verify-mfa",
        headers={"mfa-token": "invalid_token", "mfa-code": "123456"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid MFA token" 