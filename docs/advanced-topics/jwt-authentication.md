# JWT Authentication

This guide explores how to implement JSON Web Token (JWT) authentication in FastAPI applications using FastAPI Shield.

## Introduction to JWT Authentication

JSON Web Tokens (JWT) provide a compact, self-contained way to securely transmit information between parties as a JSON object. This information can be verified and trusted because it is digitally signed using a secret or a public/private key pair.

JWTs are commonly used for:

1. Authentication: After a user logs in, subsequent requests include the JWT, allowing the user to access routes, services, and resources permitted with that token.
2. Information Exchange: JWTs can securely transmit information between parties, as the signature ensures the sender is who they claim to be.

## JWT Structure

A JWT consists of three parts:

1. **Header**: Typically contains the token type and the signing algorithm.
2. **Payload**: Contains the claims (statements about an entity) and additional data.
3. **Signature**: Used to verify that the sender of the JWT is who it claims to be and to ensure the message wasn't changed along the way.

## Setting Up JWT Authentication with FastAPI Shield

### Installation Requirements

First, ensure you have the required dependencies:

```bash
pip install fastapi_shield python-jose[cryptography] passlib[bcrypt]
```

### Creating a JWT Authentication Shield

Let's create a JWT authentication system using FastAPI Shield:

```python
from typing import NewType, Optional, Dict, Any
from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from fastapi_shield import shield, ShieldedDepends

# Configuration (in a real application, store these in environment variables)
SECRET_KEY = "yoursecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 token URL
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

# User model
class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None

# Token model
class Token(BaseModel):
    access_token: str
    token_type: str

# Simulated database
fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # "secret"
        "disabled": False,
    }
}

# Define a validated user type
ValidatedUser = NewType("ValidatedUser", User)

# Function to verify password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Function to get password hash
def get_password_hash(password):
    return pwd_context.hash(password)

# Function to authenticate user
def authenticate_user(fake_db, username: str, password: str):
    user = fake_db.get(username)
    if not user:
        return False
    if not verify_password(password, user["hashed_password"]):
        return False
    return user

# Function to create access token
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Shield for JWT authentication
@shield
async def get_current_user(token: str = Depends(oauth2_scheme)) -> ValidatedUser:
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
    except JWTError:
        raise credentials_exception
        
    user_dict = fake_users_db.get(username)
    if user_dict is None:
        raise credentials_exception
        
    user = User(**user_dict)
    return ValidatedUser(user)

# Shield to check if user is active
@shield
def get_current_active_user(current_user: ValidatedUser = ShieldedDepends(get_current_user)) -> ValidatedUser:
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

# Login endpoint to create access token
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

# Protected route example
@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: ValidatedUser = ShieldedDepends(get_current_active_user)):
    return current_user

# Another protected route with additional logic
@app.get("/users/me/items/")
async def read_own_items(current_user: ValidatedUser = ShieldedDepends(get_current_active_user)):
    return [{"item_id": 1, "owner": current_user.username}]
```

## Enhanced JWT Authentication with Role-Based Access Control

Let's extend our JWT authentication to include role-based access control:

```python
from typing import NewType, Optional, Dict, Any, List
from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from fastapi_shield import shield, ShieldedDepends

# Configuration
SECRET_KEY = "yoursecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 token URL
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

# User model with roles
class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None
    roles: List[str] = []

# Token model
class Token(BaseModel):
    access_token: str
    token_type: str

# Simulated database with roles
fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # "secret"
        "disabled": False,
        "roles": ["user"]
    },
    "alice": {
        "username": "alice",
        "full_name": "Alice Wonderland",
        "email": "alice@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # "secret"
        "disabled": False,
        "roles": ["user", "admin"]
    }
}

# Define validated user types
ValidatedUser = NewType("ValidatedUser", User)
AdminUser = NewType("AdminUser", User)

# Helper functions for authentication
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def authenticate_user(fake_db, username: str, password: str):
    user = fake_db.get(username)
    if not user:
        return False
    if not verify_password(password, user["hashed_password"]):
        return False
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

# Shield for JWT authentication
@shield
async def get_current_user(token: str = Depends(oauth2_scheme)) -> ValidatedUser:
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
    except JWTError:
        raise credentials_exception
        
    user_dict = fake_users_db.get(username)
    if user_dict is None:
        raise credentials_exception
        
    user = User(**user_dict)
    return ValidatedUser(user)

# Shield to check if user is active
@shield
def get_current_active_user(current_user: ValidatedUser = ShieldedDepends(get_current_user)) -> ValidatedUser:
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

# Shield to check if user has admin role
@shield
def get_admin_user(current_user: ValidatedUser = ShieldedDepends(get_current_active_user)) -> AdminUser:
    if "admin" not in current_user.roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions"
        )
    return AdminUser(current_user)

# Login endpoint
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

# Regular user endpoint
@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: ValidatedUser = ShieldedDepends(get_current_active_user)):
    return current_user

# Admin-only endpoint
@app.get("/admin/")
async def admin_panel(admin_user: AdminUser = ShieldedDepends(get_admin_user)):
    return {
        "message": "Welcome to the admin panel",
        "admin": admin_user.username,
        "roles": admin_user.roles
    }

# Role-based endpoint with dynamic permission check
@app.get("/resources/{resource_id}")
async def get_resource(
    resource_id: int,
    current_user: ValidatedUser = ShieldedDepends(get_current_active_user)
):
    # Simulate resource ownership check
    if resource_id % 2 == 0:  # Even-numbered resources require admin
        if "admin" not in current_user.roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin role required for this resource"
            )
    
    return {
        "resource_id": resource_id,
        "owner": "system" if resource_id % 2 == 0 else current_user.username,
        "data": f"Resource data for ID {resource_id}"
    }
```

## Handling JWT Refresh Tokens

For better security, we can implement refresh tokens to obtain new access tokens without requiring the user to log in again:

```python
from typing import NewType, Optional, Dict, Any, List
from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException, status, Cookie
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from fastapi_shield import shield, ShieldedDepends

# Configuration
SECRET_KEY = "yoursecretkey"
REFRESH_SECRET_KEY = "yourrefreshsecretkey"  # Different key for refresh tokens
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 token URL
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

# User model
class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None
    roles: List[str] = []

# Token models
class Token(BaseModel):
    access_token: str
    token_type: str
    refresh_token: str

class TokenData(BaseModel):
    username: Optional[str] = None

# Simulated database
fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # "secret"
        "disabled": False,
        "roles": ["user"]
    },
    "alice": {
        "username": "alice",
        "full_name": "Alice Wonderland",
        "email": "alice@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # "secret"
        "disabled": False,
        "roles": ["user", "admin"]
    }
}

# In-memory token blacklist (replace with Redis or database in production)
token_blacklist = set()

# Define validated user type
ValidatedUser = NewType("ValidatedUser", User)

# Helper functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def authenticate_user(fake_db, username: str, password: str):
    user = fake_db.get(username)
    if not user:
        return False
    if not verify_password(password, user["hashed_password"]):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(days=7))
    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, REFRESH_SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Shield for JWT authentication
@shield
async def get_current_user(token: str = Depends(oauth2_scheme)) -> ValidatedUser:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    # Check if token is blacklisted
    if token in token_blacklist:
        raise credentials_exception
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        token_type = payload.get("type")
        
        if username is None or token_type != "access":
            raise credentials_exception
    except JWTError:
        raise credentials_exception
        
    user_dict = fake_users_db.get(username)
    if user_dict is None:
        raise credentials_exception
        
    user = User(**user_dict)
    return ValidatedUser(user)

# Shield to check if user is active
@shield
def get_current_active_user(current_user: ValidatedUser = ShieldedDepends(get_current_user)) -> ValidatedUser:
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

# Login endpoint with refresh token
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expires = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    
    access_token = create_access_token(
        data={"sub": user["username"]}, 
        expires_delta=access_token_expires
    )
    
    refresh_token = create_refresh_token(
        data={"sub": user["username"]},
        expires_delta=refresh_token_expires
    )
    
    return {
        "access_token": access_token, 
        "token_type": "bearer",
        "refresh_token": refresh_token
    }

# Refresh token endpoint
@app.post("/token/refresh", response_model=Token)
async def refresh_access_token(refresh_token: str):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate refresh token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    # Check if token is blacklisted
    if refresh_token in token_blacklist:
        raise credentials_exception
    
    try:
        payload = jwt.decode(refresh_token, REFRESH_SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        token_type = payload.get("type")
        
        if username is None or token_type != "refresh":
            raise credentials_exception
    except JWTError:
        raise credentials_exception
        
    user_dict = fake_users_db.get(username)
    if user_dict is None:
        raise credentials_exception
    
    # Add the old refresh token to the blacklist
    token_blacklist.add(refresh_token)
    
    # Create new tokens
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expires = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    
    access_token = create_access_token(
        data={"sub": username}, 
        expires_delta=access_token_expires
    )
    
    new_refresh_token = create_refresh_token(
        data={"sub": username},
        expires_delta=refresh_token_expires
    )
    
    return {
        "access_token": access_token, 
        "token_type": "bearer",
        "refresh_token": new_refresh_token
    }

# Logout endpoint to blacklist tokens
@app.post("/logout")
async def logout(
    current_user: ValidatedUser = ShieldedDepends(get_current_active_user),
    access_token: str = Depends(oauth2_scheme),
    refresh_token: Optional[str] = None
):
    # Add the current access token to the blacklist
    token_blacklist.add(access_token)
    
    # If refresh token is provided, blacklist it too
    if refresh_token:
        token_blacklist.add(refresh_token)
    
    return {"message": "Successfully logged out"}

# Protected route example
@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: ValidatedUser = ShieldedDepends(get_current_active_user)):
    return current_user
```

## JWT Claims and Custom Payloads

JWTs allow you to include custom claims in the token payload:

```python
from typing import NewType, Optional, Dict, Any, List
from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from fastapi_shield import shield, ShieldedDepends
import uuid

# Configuration
SECRET_KEY = "yoursecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 token URL
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

# User model
class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None
    roles: List[str] = []
    permissions: List[str] = []

# Token model
class Token(BaseModel):
    access_token: str
    token_type: str

# Token payload model for validation
class TokenPayload(BaseModel):
    sub: str
    exp: datetime
    jti: str
    roles: List[str]
    permissions: List[str]
    user_data: Dict[str, Any]

# Simulated database
fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # "secret"
        "disabled": False,
        "roles": ["user"],
        "permissions": ["read:own_data", "update:own_data"],
        "user_data": {
            "department": "Engineering",
            "location": "New York"
        }
    },
    "alice": {
        "username": "alice",
        "full_name": "Alice Wonderland",
        "email": "alice@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # "secret"
        "disabled": False,
        "roles": ["user", "admin"],
        "permissions": ["read:own_data", "update:own_data", "read:all_data", "update:all_data"],
        "user_data": {
            "department": "Management",
            "location": "San Francisco"
        }
    }
}

# Define validated user type
ValidatedUser = NewType("ValidatedUser", User)

# Define a type for users with specific permissions
HasReadAllPermission = NewType("HasReadAllPermission", User)
HasUpdateAllPermission = NewType("HasUpdateAllPermission", User)

# Helper functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def authenticate_user(fake_db, username: str, password: str):
    user = fake_db.get(username)
    if not user:
        return False
    if not verify_password(password, user["hashed_password"]):
        return False
    return user

def create_access_token(user_data: dict):
    # Prepare payload with standard and custom claims
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    payload = {
        "sub": user_data["username"],
        "exp": expire,
        "jti": str(uuid.uuid4()),  # Unique token ID
        "roles": user_data["roles"],
        "permissions": user_data["permissions"],
        "user_data": {
            "department": user_data.get("user_data", {}).get("department", ""),
            "location": user_data.get("user_data", {}).get("location", "")
        }
    }
    
    encoded_jwt = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Shield for JWT authentication with enhanced validation
@shield
async def get_current_user(token: str = Depends(oauth2_scheme)) -> ValidatedUser:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        # Decode the JWT
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        # Validate the payload structure
        token_data = TokenPayload(**payload)
        
        # Check token expiration
        if datetime.utcnow() > token_data.exp:
            raise credentials_exception
            
        username = token_data.sub
    except (JWTError, ValueError):
        raise credentials_exception
        
    user_dict = fake_users_db.get(username)
    if user_dict is None:
        raise credentials_exception
        
    user = User(**user_dict)
    return ValidatedUser(user)

# Shield to check if user is active
@shield
def get_current_active_user(current_user: ValidatedUser = ShieldedDepends(get_current_user)) -> ValidatedUser:
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

# Shield to check for specific permission
@shield
def check_read_all_permission(current_user: ValidatedUser = ShieldedDepends(get_current_active_user)) -> HasReadAllPermission:
    if "read:all_data" not in current_user.permissions:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to access this resource"
        )
    return HasReadAllPermission(current_user)

@shield
def check_update_all_permission(current_user: ValidatedUser = ShieldedDepends(get_current_active_user)) -> HasUpdateAllPermission:
    if "update:all_data" not in current_user.permissions:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to modify this resource"
        )
    return HasUpdateAllPermission(current_user)

# Login endpoint
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = create_access_token(user)
    
    return {"access_token": access_token, "token_type": "bearer"}

# User profile endpoint (any authenticated user can access their own profile)
@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: ValidatedUser = ShieldedDepends(get_current_active_user)):
    return current_user

# Endpoint requiring read:all_data permission
@app.get("/users/all/")
async def read_all_users(admin_user: HasReadAllPermission = ShieldedDepends(check_read_all_permission)):
    # Convert user dictionaries to User models
    users = [User(**user_data) for user_data in fake_users_db.values()]
    return users

# Endpoint requiring update:all_data permission
@app.put("/users/{username}/disable")
async def disable_user(
    username: str,
    admin_user: HasUpdateAllPermission = ShieldedDepends(check_update_all_permission)
):
    if username not in fake_users_db:
        raise HTTPException(status_code=404, detail="User not found")
    
    # In a real app, you would update the database
    fake_users_db[username]["disabled"] = True
    
    return {"message": f"User {username} has been disabled"}

# Endpoint showcasing JWT payload information
@app.get("/token/info")
async def token_info(current_user: ValidatedUser = ShieldedDepends(get_current_active_user)):
    return {
        "username": current_user.username,
        "roles": current_user.roles,
        "permissions": current_user.permissions,
        "user_data": {
            "department": current_user.user_data.get("department"),
            "location": current_user.user_data.get("location")
        }
    }
```

## Security Considerations

When working with JWTs, consider these security best practices:

1. **Use HTTPS**: Always use HTTPS to transfer tokens to prevent interception.

2. **Keep Secrets Secure**: Store your secret keys securely, preferably in environment variables or a secure key management system.

3. **Set Short Expiration Times**: Use short-lived access tokens (15-30 minutes) and longer-lived refresh tokens.

4. **Validate All Claims**: Validate all claims in the token, including issuer, audience, and expiration time.

5. **Implement Token Revocation**: Use a token blacklist or maintain a version number for user accounts.

6. **Monitor for Suspicious Activity**: Implement logging and monitoring for unsuccessful authentication attempts.

7. **CSRF Protection**: Even with JWT-based authentication, include CSRF protection for browser-based applications.

8. **Payload Size**: Keep JWT payloads small, as they are included in every request.

9. **Don't Store Sensitive Data**: Never store sensitive information like passwords or credit card numbers in JWTs.

10. **Proper Key Rotation**: Implement a key rotation strategy for your signing keys.

## JWT Authentication in Production

For production environments:

1. **Use Environment Variables**: Store secrets, keys, and configuration in environment variables:

```python
import os
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env file

SECRET_KEY = os.getenv("JWT_SECRET_KEY")
REFRESH_SECRET_KEY = os.getenv("JWT_REFRESH_SECRET_KEY")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
```

2. **Use a Database for Blacklisting**: Replace the in-memory blacklist with a database or Redis:

```python
import redis

# Redis connection
redis_client = redis.Redis(
    host=os.getenv("REDIS_HOST", "localhost"),
    port=int(os.getenv("REDIS_PORT", "6379")),
    db=int(os.getenv("REDIS_DB", "0"))
)

# Add token to blacklist with expiration
def blacklist_token(token: str, expires_delta: timedelta):
    redis_client.setex(f"blacklist:{token}", int(expires_delta.total_seconds()), "true")

# Check if token is blacklisted
def is_token_blacklisted(token: str) -> bool:
    return redis_client.exists(f"blacklist:{token}") == 1
```

3. **Implement Rate Limiting**: Protect authentication endpoints from brute-force attacks:

```python
from fastapi import Request
from fastapi.middleware.base import BaseHTTPMiddleware
import time

class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, rate_limit_per_minute: int = 60):
        super().__init__(app)
        self.rate_limit = rate_limit_per_minute
        self.request_counts = {}
        
    async def dispatch(self, request: Request, call_next):
        if request.url.path == "/token":
            client_ip = request.client.host
            current_time = int(time.time() / 60)  # Current minute
            
            # Get request count for this minute
            request_key = f"{client_ip}:{current_time}"
            current_count = self.request_counts.get(request_key, 0)
            
            # Check if rate limit exceeded
            if current_count >= self.rate_limit:
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={"detail": "Rate limit exceeded. Try again later."}
                )
            
            # Increment counter
            self.request_counts[request_key] = current_count + 1
            
        response = await call_next(request)
        return response

# Add middleware to app
app.add_middleware(RateLimitMiddleware, rate_limit_per_minute=10)
```

## Conclusion

Implementing JWT authentication with FastAPI Shield provides a robust, type-safe way to secure your APIs. By leveraging Shield's dependency injection and type-wrapping capabilities, you can create clean, maintainable authentication systems with strong type safety.

JWT authentication is particularly well-suited for modern, distributed architectures and client-side applications. By following the patterns demonstrated in this guide, you can implement secure, scalable authentication for your FastAPI applications. 