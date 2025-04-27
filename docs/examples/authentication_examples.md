# Authentication Examples with FastAPI Shield

This page provides complete, working examples of various authentication methods implemented with FastAPI Shield.

## Basic API Key Authentication

This example shows how to implement a simple API key authentication system using FastAPI Shield.

```python
from fastapi import FastAPI, Depends, Header, HTTPException, status
from fastapi_shield import shield, ShieldedDepends
from typing import Annotated, Dict, Optional
import secrets

app = FastAPI()

# In a real application, this would be a database
API_KEYS = {
    "user1": "sk_test_abcdefghijklmnopqrstuvwxyz",
    "user2": "sk_test_zyxwvutsrqponmlkjihgfedcba",
}

# Create a shield type for the API key
def validate_api_key(api_key: str) -> str:
    if not api_key.startswith("sk_test_"):
        raise ValueError("Invalid API key format")
    return api_key

ApiKey = shield(str, name="ApiKey", validator=validate_api_key)

# Create a dependency for API key authentication
def get_user_from_api_key(
    api_key: Annotated[ApiKey, Header(name="X-API-Key")]
) -> str:
    for username, key in API_KEYS.items():
        if secrets.compare_digest(key, api_key):
            return username
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API key",
        headers={"WWW-Authenticate": "ApiKey"},
    )

@app.get("/api/protected")
async def protected_route(
    username: Annotated[str, Depends(get_user_from_api_key)]
):
    return {
        "message": f"Hello, {username}! You accessed a protected route.",
        "data": "This is sensitive data that requires authentication."
    }

@app.get("/api/profile")
async def get_profile(
    username: Annotated[str, Depends(get_user_from_api_key)]
):
    return {
        "username": username,
        "subscription": "premium",
        "account_type": "business"
    }
```

## Basic Authentication (Username/Password)

This example demonstrates HTTP Basic Authentication with FastAPI Shield.

```python
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi_shield import shield, ShieldedDepends
from typing import Annotated
import secrets

app = FastAPI()

# Security scheme
security = HTTPBasic()

# Mock user database (username: password)
USERS = {
    "admin": "strongpassword",
    "user": "userpassword",
}

# Create shield types for username and password
def validate_username(username: str) -> str:
    if len(username) < 3:
        raise ValueError("Username must be at least 3 characters")
    return username

def validate_password(password: str) -> str:
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters")
    return password

Username = shield(str, name="Username", validator=validate_username)
Password = shield(str, name="Password", validator=validate_password)

# Create a dependency for basic authentication
def get_current_user(
    credentials: Annotated[HTTPBasicCredentials, Depends(security)]
) -> str:
    # Validate username format
    try:
        username = Username(credentials.username)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
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
    if not secrets.compare_digest(credentials.password, correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid password",
            headers={"WWW-Authenticate": "Basic"},
        )
    
    return username

@app.get("/users/me")
async def get_current_user_info(
    username: Annotated[str, Depends(get_current_user)]
):
    return {
        "username": username,
        "message": "You are authenticated!"
    }

@app.get("/admin")
async def admin_panel(
    username: Annotated[str, Depends(get_current_user)]
):
    if username != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admin users can access this resource",
        )
    
    return {
        "message": "Welcome to the admin panel",
        "secret_stats": {"total_users": 2, "active_users": 1}
    }
```

## JWT Authentication

This example shows how to implement JWT (JSON Web Token) authentication with FastAPI Shield.

```python
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi_shield import shield, ShieldedDepends
from pydantic import BaseModel
from typing import Annotated, Dict, Optional
import jwt
from datetime import datetime, timedelta
import secrets

# Configuration
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Mock user database
class UserInDB(BaseModel):
    username: str
    hashed_password: str
    email: Optional[str] = None
    disabled: Optional[bool] = None

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

app = FastAPI()

# Security scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Token and user models
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class User(BaseModel):
    username: str
    email: Optional[str] = None
    disabled: Optional[bool] = None

# Create shield types for JWT
def validate_jwt(token: str) -> str:
    if not token or len(token) < 10:
        raise ValueError("Invalid token format")
    return token

JWT = shield(str, name="JWT", validator=validate_jwt)

# Helper functions
def get_user(db, username: str) -> Optional[UserInDB]:
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)
    return None

def verify_password(plain_password: str, hashed_password: str) -> bool:
    # In a real app, you would use proper password verification
    # e.g., return pwd_context.verify(plain_password, hashed_password)
    return plain_password + "hashed" == hashed_password

def authenticate_user(fake_db, username: str, password: str) -> Optional[UserInDB]:
    user = get_user(fake_db, username)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
        
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(
    token: Annotated[JWT, Depends(oauth2_scheme)]
) -> User:
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
            
        token_data = TokenData(username=username)
    except jwt.PyJWTError:
        raise credentials_exception
        
    user = get_user(USERS_DB, username=token_data.username)
    
    if user is None:
        raise credentials_exception
        
    return User(
        username=user.username,
        email=user.email,
        disabled=user.disabled
    )

async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)]
) -> User:
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

# Endpoints
@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    user = authenticate_user(USERS_DB, form_data.username, form_data.password)
    
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

@app.get("/users/me", response_model=User)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    return current_user

@app.get("/users/me/items")
async def read_own_items(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    return [
        {"item_id": "1", "owner": current_user.username},
        {"item_id": "2", "owner": current_user.username}
    ]
```

## OAuth2 Authentication with FastAPI Shield

This example demonstrates integrating OAuth2 authentication with FastAPI Shield.

```python
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2AuthorizationCodeBearer
from fastapi_shield import shield, ShieldedDepends
from pydantic import BaseModel
from typing import Annotated, Dict, List, Optional
import jwt
from datetime import datetime, timedelta
import secrets

app = FastAPI()

# Configuration
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# OAuth2 configuration (in a real app, these would be registered with the OAuth provider)
OAUTH2_CLIENT_ID = "myclientid"
OAUTH2_CLIENT_SECRET = "myclientsecret"
OAUTH2_REDIRECT_URL = "http://localhost:8000/auth/callback"

# OAuth2 Security Scheme
oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl="https://example.com/oauth/authorize",
    tokenUrl="https://example.com/oauth/token",
    refreshUrl="https://example.com/oauth/refresh",
    scopes={
        "read:profile": "Read user profile",
        "read:email": "Read user email",
        "write:profile": "Update user profile",
    },
)

# Models
class User(BaseModel):
    id: str
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    scopes: List[str] = []

class TokenData(BaseModel):
    sub: str
    scopes: List[str] = []
    exp: Optional[int] = None

# Mock user database
USERS = {
    "user1": User(
        id="user1",
        username="johndoe",
        email="john@example.com",
        full_name="John Doe",
        scopes=["read:profile", "read:email"],
    ),
    "user2": User(
        id="user2",
        username="janedoe",
        email="jane@example.com",
        full_name="Jane Doe",
        scopes=["read:profile", "read:email", "write:profile"],
    ),
}

# Create shield types
def validate_access_token(token: str) -> str:
    if not token or len(token) < 10:
        raise ValueError("Invalid token format")
    return token

AccessToken = shield(str, name="AccessToken", validator=validate_access_token)

# Helper functions
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
        
    to_encode.update({"exp": int(expire.timestamp())})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_token(token: str) -> TokenData:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return TokenData(**payload)
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )

# Dependencies
async def get_current_user(
    token: Annotated[AccessToken, Depends(oauth2_scheme)]
) -> User:
    token_data = decode_token(token)
    
    # Check if token is expired
    if token_data.exp and datetime.utcnow().timestamp() > token_data.exp:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user_id = token_data.sub
    if user_id not in USERS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user = USERS[user_id]
    
    # Update user's scopes based on token
    user.scopes = token_data.scopes
    
    return user

def require_scopes(required_scopes: List[str]):
    def scope_validator(
        current_user: Annotated[User, Depends(get_current_user)]
    ):
        for scope in required_scopes:
            if scope not in current_user.scopes:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Not enough permissions. Required scope: {scope}",
                )
        return current_user
    return scope_validator

# Endpoints
@app.get("/auth/login")
async def login():
    return {
        "auth_url": f"https://example.com/oauth/authorize?client_id={OAUTH2_CLIENT_ID}&redirect_uri={OAUTH2_REDIRECT_URL}&response_type=code&scope=read:profile+read:email"
    }

@app.get("/auth/callback")
async def auth_callback(
    code: str,
    state: Optional[str] = None,
):
    # In a real app, you would exchange the code for a token with the OAuth provider
    # For this example, we'll create a mock token
    
    # Mock user ID (in a real app, this would come from the OAuth provider)
    user_id = "user1"
    
    # Create a token with the user's ID and scopes
    token_data = {
        "sub": user_id,
        "scopes": USERS[user_id].scopes,
    }
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(token_data, access_token_expires)
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }

@app.get("/users/me")
async def get_my_profile(
    current_user: Annotated[User, Depends(require_scopes(["read:profile"]))]
):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "full_name": current_user.full_name,
    }

@app.get("/users/me/email")
async def get_my_email(
    current_user: Annotated[User, Depends(require_scopes(["read:email"]))]
):
    return {
        "email": current_user.email,
    }

@app.put("/users/me")
async def update_my_profile(
    current_user: Annotated[User, Depends(require_scopes(["write:profile"]))],
    full_name: Optional[str] = None,
):
    if full_name:
        current_user.full_name = full_name
    
    return {
        "id": current_user.id,
        "username": current_user.username,
        "full_name": current_user.full_name,
        "message": "Profile updated successfully",
    }
```

## Multi-Factor Authentication Example

This example demonstrates implementing multi-factor authentication (MFA) with FastAPI Shield.

```python
from fastapi import FastAPI, Depends, HTTPException, status, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi_shield import shield, ShieldedDepends
from pydantic import BaseModel
from typing import Annotated, Dict, List, Optional
import jwt
from datetime import datetime, timedelta
import secrets
import random

app = FastAPI()

# Configuration
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Models
class User(BaseModel):
    username: str
    hashed_password: str
    email: str
    full_name: Optional[str] = None
    disabled: Optional[bool] = False
    mfa_enabled: bool = False
    mfa_secret: Optional[str] = None

class Token(BaseModel):
    access_token: str
    token_type: str
    requires_mfa: bool = False
    mfa_token: Optional[str] = None

class TokenData(BaseModel):
    username: str
    mfa_verified: bool = False
    exp: Optional[int] = None

class MFARequest(BaseModel):
    mfa_token: str
    mfa_code: str

# Mock user database
USERS_DB = {
    "johndoe": User(
        username="johndoe",
        hashed_password="fakehashed_johndoe",
        email="john@example.com",
        full_name="John Doe",
        mfa_enabled=True,
        mfa_secret="JBSWY3DPEHPK3PXP"  # This would be securely stored in a real app
    ),
    "janedoe": User(
        username="janedoe",
        hashed_password="fakehashed_janedoe",
        email="jane@example.com",
        full_name="Jane Doe",
        mfa_enabled=False
    ),
}

# Mock MFA tokens storage (in a real app, this would be a database table)
MFA_TOKENS = {}  # token -> username mapping

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="token",
    auto_error=False
)

# Create shield types
def validate_token(token: str) -> str:
    if not token or len(token) < 10:
        raise ValueError("Invalid token format")
    return token

def validate_mfa_code(code: str) -> str:
    if not code or not code.isdigit() or len(code) != 6:
        raise ValueError("MFA code must be a 6-digit number")
    return code

Token = shield(str, name="Token", validator=validate_token)
MFACode = shield(str, name="MFACode", validator=validate_mfa_code)

# Helper functions
def verify_password(plain_password: str, hashed_password: str) -> bool:
    # In a real app, you would use a secure password hashing function
    return "fakehashed_" + plain_password == hashed_password

def authenticate_user(username: str, password: str) -> Optional[User]:
    if username not in USERS_DB:
        return None
    
    user = USERS_DB[username]
    
    if not verify_password(password, user.hashed_password):
        return None
        
    return user

def create_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
        
    to_encode.update({"exp": int(expire.timestamp())})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_mfa_code(user: User, mfa_code: str) -> bool:
    # In a real app, you would use TOTP algorithm to verify the code
    # For this example, we'll accept any 6-digit code
    if not user.mfa_enabled:
        return True
        
    # We'll simulate TOTP verification by accepting any code for this example
    # In a real app, you would use a library like pyotp to verify the code
    return len(mfa_code) == 6 and mfa_code.isdigit()

def generate_mfa_token(username: str) -> str:
    # Generate a random token
    mfa_token = secrets.token_urlsafe(32)
    
    # Store the token -> username mapping
    MFA_TOKENS[mfa_token] = username
    
    return mfa_token

# Dependencies
def get_current_user(
    token: Annotated[Optional[str], Depends(oauth2_scheme)]
) -> Optional[User]:
    if not token:
        return None
        
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        mfa_verified: bool = payload.get("mfa_verified", False)
        exp: int = payload.get("exp")
        
        if username is None:
            return None
            
        token_data = TokenData(
            username=username,
            mfa_verified=mfa_verified,
            exp=exp
        )
    except jwt.PyJWTError:
        return None
        
    if token_data.exp and datetime.utcnow().timestamp() > token_data.exp:
        return None
        
    if username not in USERS_DB:
        return None
        
    user = USERS_DB[username]
    
    # If MFA is enabled, check that it's been verified
    if user.mfa_enabled and not token_data.mfa_verified:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="MFA verification required",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    return user

def get_current_active_user(
    current_user: Annotated[Optional[User], Depends(get_current_user)]
) -> User:
    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
        
    return current_user

# Endpoints
@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    user = authenticate_user(form_data.username, form_data.password)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create a token that indicates if MFA is required
    token_data = {
        "sub": user.username,
        "mfa_verified": not user.mfa_enabled,  # Set to True if MFA is not enabled
    }
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_token(token_data, access_token_expires)
    
    # If MFA is not required, return a normal token
    if not user.mfa_enabled:
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "requires_mfa": False
        }
    
    # If MFA is required, return a token that requires MFA verification
    mfa_token = generate_mfa_token(user.username)
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "requires_mfa": True,
        "mfa_token": mfa_token
    }

@app.post("/verify-mfa", response_model=Token)
async def verify_mfa(
    mfa_request: MFARequest
):
    # Check if the MFA token is valid
    if mfa_request.mfa_token not in MFA_TOKENS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid MFA token",
        )
    
    # Get the username associated with the MFA token
    username = MFA_TOKENS[mfa_request.mfa_token]
    user = USERS_DB[username]
    
    # Verify the MFA code
    if not verify_mfa_code(user, mfa_request.mfa_code):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid MFA code",
        )
    
    # Remove the used MFA token
    del MFA_TOKENS[mfa_request.mfa_token]
    
    # Create a new token with MFA verified
    token_data = {
        "sub": user.username,
        "mfa_verified": True,
    }
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_token(token_data, access_token_expires)
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "requires_mfa": False
    }

@app.get("/users/me")
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    return {
        "username": current_user.username,
        "email": current_user.email,
        "full_name": current_user.full_name,
        "mfa_enabled": current_user.mfa_enabled
    }

@app.post("/users/me/enable-mfa")
async def enable_mfa(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    # In a real app, you would generate a secret key and return a QR code
    # For this example, we'll just simulate enabling MFA
    
    if current_user.mfa_enabled:
        return {"message": "MFA is already enabled"}
    
    # Generate a random MFA secret
    mfa_secret = "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", k=16))
    
    # Update the user record
    current_user.mfa_enabled = True
    current_user.mfa_secret = mfa_secret
    
    # In a real app, you would save this to the database
    USERS_DB[current_user.username] = current_user
    
    return {
        "message": "MFA enabled successfully",
        "mfa_secret": mfa_secret,
        "qr_code_url": f"otpauth://totp/FastAPI:{current_user.username}?secret={mfa_secret}&issuer=FastAPI"
    }

@app.post("/users/me/disable-mfa")
async def disable_mfa(
    current_user: Annotated[User, Depends(get_current_active_user)],
    mfa_code: Annotated[MFACode, Form()]
):
    if not current_user.mfa_enabled:
        return {"message": "MFA is already disabled"}
    
    # Verify the MFA code before disabling
    if not verify_mfa_code(current_user, mfa_code):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid MFA code",
        )
    
    # Disable MFA for the user
    current_user.mfa_enabled = False
    current_user.mfa_secret = None
    
    # In a real app, you would save this to the database
    USERS_DB[current_user.username] = current_user
    
    return {"message": "MFA disabled successfully"}
```

## Best Practices for Authentication

1. **Use HTTPS**: Always use HTTPS in production to protect authentication credentials.

2. **Hash Passwords**: Never store plaintext passwords. Use algorithms like Argon2, bcrypt, or PBKDF2.

3. **Rate Limiting**: Implement rate limiting for authentication endpoints to prevent brute force attacks.

4. **JWT Best Practices**:
   - Keep tokens short-lived
   - Use refresh tokens for long-lived sessions
   - Include only necessary claims in the token payload

5. **Security Headers**: Implement security headers like Content-Security-Policy, X-XSS-Protection, and X-Content-Type-Options.

6. **Cookie Security**: If using cookies, set Secure, HttpOnly, and SameSite flags.

7. **MFA**: Implement Multi-Factor Authentication for sensitive operations.

8. **Secure Key Storage**: Store API keys and secrets securely using environment variables or a secret management service.

9. **Audit Logging**: Log authentication events for security auditing.

10. **Token Revocation**: Implement a mechanism to revoke tokens if needed (e.g., for logout or compromised credentials).

By following these examples and best practices, you can implement secure authentication in your FastAPI applications using FastAPI Shield. 