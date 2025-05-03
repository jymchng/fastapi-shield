# Authentication Patterns

FastAPI Shield provides powerful abstractions for implementing secure authentication in your FastAPI applications. This guide covers common authentication patterns and best practices.

## Basic Authentication

Basic authentication is a simple authentication scheme built into the HTTP protocol. FastAPI Shield makes it easy to implement:

```python
# Found in `examples/basic_auth_one.py`
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
@authenticate_user # Use the shield as a decorator
def get_profile(username: AuthenticatedUser = ShieldedDepends(lambda s: s)):
    # `lambda s: s` because `authenticate_user` returns an instance of `AuthenticatedUser` 
    # which is passed into the shielded dependency function of `ShieldedDepends`.
    # The user is authenticated at this point
    user_data = USER_DB.get(str(username))
    return {
        "username": user_data["username"],
        "full_name": user_data["full_name"]
    }
```

## Token-Based Authentication

Token-based authentication is widely used in modern APIs:

```python
# Found in `/examples/auth_jwt_one.py`
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
```

## JWT Authentication

JSON Web Tokens (JWT) offer a secure way to encode information:

```python
# Found in: `examples/auth_jwt_two.py`
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
```

## OAuth2 Authentication

OAuth2 is a standard protocol for authorization:

```python
# Found in `examples/oauth_scopes_one.py`
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
        "scopes": ["read:profile", "read:items", "write:items"]
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
                scopes=token_data.scopes
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
    token_data = {
        "sub": user["username"],
        "scopes": scopes
    }
    
    access_token = create_access_token(data=token_data)
    
    return {"access_token": access_token, "token_type": "bearer"}

# Use the shield in endpoints with different scope requirements
@app.get("/users/me")
@authenticate_with_scopes(required_scopes=["read:profile"])
def get_current_user(
    user: AuthenticatedUser = ShieldedDepends(lambda user: user)
):
    return user

@app.get("/items")
@authenticate_with_scopes(required_scopes=["read:items"])
def get_items(
):
    return {"items": [{"item_id": 1, "name": "Foo"}, {"item_id": 2, "name": "Bar"}]}

@app.post("/items")
@authenticate_with_scopes(required_scopes=["write:items"])
def create_item(
    item: dict,
):
    return {"item_id": 3, **item}
```

## Flexible Authentication

You can combine multiple authentication methods for flexibility:

```python
# Found in `examples/multi_auth_one.py`
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
```

## Authentication Best Practices

When implementing authentication with FastAPI Shield, it's crucial to follow security best practices to protect your application and user data.

Always use HTTPS in production to encrypt sensitive information during transmission. Never store plaintext passwords; instead, use secure hashing algorithms like bcrypt. 

For token-based authentication, implement proper token management by setting appropriate expiration times, creating a token revocation mechanism for logout functionality, and considering refresh tokens for long-lived sessions. 

Protect against brute force attacks by implementing rate limiting on authentication endpoints. Thoroughly validate all inputs, especially on authentication endpoints, and provide generic error messages that don't reveal whether a username exists in your system. 

Implement comprehensive logging of authentication attempts while being careful not to log sensitive information like passwords. 

For applications requiring higher security, consider implementing multi-factor authentication. If using session-based authentication, ensure proper session management. Implement fine-grained access control with scopes or roles for authorization. 

Set appropriate security headers like `X-Content-Type-Options` and `Strict-Transport-Security`. 

Finally, regularly update your dependencies to patch security vulnerabilities. 

By following these patterns and best practices, you can build secure and flexible authentication systems in your FastAPI applications using FastAPI Shield.

