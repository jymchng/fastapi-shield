<!--Examples tested-->

# JWT Authentication

This guide explores how to implement JSON Web Token (JWT) authentication in FastAPI applications using FastAPI Shield, based on proven patterns and real-world implementations.

## Introduction to JWT Authentication

JSON Web Tokens (JWT) provide a compact, self-contained way to securely transmit information between parties as a JSON object. This information can be verified and trusted because it is digitally signed using a secret or a public/private key pair.

JWTs are commonly used for:

1. **Authentication**: After a user logs in, subsequent requests include the JWT, allowing the user to access routes, services, and resources permitted with that token.
2. **Information Exchange**: JWTs can securely transmit information between parties, as the signature ensures the sender is who they claim to be.

## JWT Structure

A JWT consists of three parts:

1. **Header**: Typically contains the token type and the signing algorithm.
2. **Payload**: Contains the claims (statements about an entity) and additional data.
3. **Signature**: Used to verify that the sender of the JWT is who it claims to be and to ensure the message wasn't changed along the way.

## Setting Up JWT Authentication with FastAPI Shield

### Installation Requirements

First, ensure you have the required dependencies:

```bash
pip install fastapi_shield PyJWT[crypto]
```

### Basic JWT Authentication Shield

Let's start with a simple JWT authentication system using FastAPI Shield's decorator pattern:

```python
from fastapi import FastAPI, Header, HTTPException, status
from fastapi_shield import shield, ShieldedDepends
import jwt
from jwt.exceptions import PyJWTError

app = FastAPI()

# Configuration (store these securely in production!)
JWT_SECRET = "your-secret-key"
JWT_ALGORITHM = "HS256"

@shield(
    name="JWT Authentication",
    exception_to_raise_if_fail=HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    ),
)
def jwt_auth_shield(authorization: str = Header()) -> dict:
    """Validate JWT token and return decoded payload"""
    if not authorization.startswith("Bearer "):
        return None

    token = authorization.replace("Bearer ", "")

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except PyJWTError:
        return None

# Protected endpoint using the shield
@app.get("/protected")
@jwt_auth_shield
async def protected_endpoint(
    payload: dict = ShieldedDepends(lambda payload: payload)
):
    return {
        "message": "Access granted",
        "user": payload.get("sub"),
        "roles": payload.get("roles", [])
    }
```

### Key Shield Patterns

Notice the important patterns in the above example:

1. **Shield as Decorator**: Use `@shield` as a decorator, not a function call
2. **Return None for Failure**: When validation fails, return `None` to trigger the shield's failure response
3. **Named Shields**: Give descriptive names to shields for better debugging
4. **Custom Exceptions**: Define specific HTTP exceptions for different failure scenarios
5. **ShieldedDepends**: Use `ShieldedDepends(lambda payload: payload)` to access the shield's return value

## Role-Based Access Control with Shield Chaining

FastAPI Shield excels at chaining multiple shields for complex authorization flows:

```python
from fastapi import FastAPI, Header, HTTPException, status
from fastapi_shield import shield, ShieldedDepends

app = FastAPI()

# User database with roles
USERS = {
    "admin_token": {"user_id": "admin", "roles": ["admin", "user"]},
    "editor_token": {"user_id": "editor", "roles": ["editor", "user"]},
    "user_token": {"user_id": "user1", "roles": ["user"]},
}

@shield(name="Authentication")
def auth_shield(api_token: str = Header()) -> dict:
    """Authenticate the user and return user data"""
    if api_token in USERS:
        return USERS[api_token]
    return None

def role_shield(required_roles: list[str]):
    """Factory function to create a role-checking shield"""
    
    @shield(
        name=f"Role Check ({', '.join(required_roles)})",
        exception_to_raise_if_fail=HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied. Required roles: {', '.join(required_roles)}"
        )
    )
    def check_role(user_data: dict = ShieldedDepends(lambda user: user)) -> dict:
        """Check if the user has any of the required roles"""
        user_roles = user_data.get("roles", [])
        if any(role in required_roles for role in user_roles):
            return user_data
        return None
    
    return check_role

# Create specific role shields
admin_shield = role_shield(["admin"])
editor_shield = role_shield(["admin", "editor"])
user_shield = role_shield(["admin", "editor", "user"])

@app.get("/admin")
@auth_shield
@admin_shield
async def admin_endpoint(
    user: dict = ShieldedDepends(lambda user: user)
):
    return {"message": "Admin endpoint", "user": user["user_id"]}

@app.get("/editor")
@auth_shield
@editor_shield
async def editor_endpoint(
    user: dict = ShieldedDepends(lambda user: user)
):
    return {"message": "Editor endpoint", "user": user["user_id"]}

@app.get("/user")
@auth_shield
@user_shield
async def user_endpoint(
    user: dict = ShieldedDepends(lambda user: user)
):
    return {"message": "User endpoint", "user": user["user_id"]}
```

## Advanced JWT Authentication with Chained Shields

For more sophisticated authentication flows, you can chain multiple shields to build complex authorization logic:

```python
from fastapi import FastAPI, Header, HTTPException, status
from fastapi_shield import shield, ShieldedDepends
import jwt
from jwt.exceptions import PyJWTError
from typing import List, Optional
from datetime import datetime, timedelta

app = FastAPI()

# Configuration
JWT_SECRET = "your-secret-key"
JWT_ALGORITHM = "HS256"

class AuthData:
    """Class to hold authentication data and provide helper methods"""
    
    def __init__(self, user_id: str, roles: List[str], permissions: List[str]):
        self.user_id = user_id
        self.roles = roles
        self.permissions = permissions
    
    def has_role(self, role: str) -> bool:
        """Check if user has a specific role"""
        return role in self.roles
    
    def has_permission(self, permission: str) -> bool:
        """Check if user has a specific permission"""
        return permission in self.permissions

@shield(
    name="JWT Authentication",
    exception_to_raise_if_fail=HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
        headers={"WWW-Authenticate": "Bearer"}
    )
)
async def jwt_auth_shield(authorization: str = Header()) -> Optional[dict]:
    """Validate JWT token and extract payload"""
    if not authorization.startswith("Bearer "):
        return None

    token = authorization.replace("Bearer ", "")

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except PyJWTError:
        return None

@shield(
    name="User Role Extraction",
    exception_to_raise_if_fail=HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid user data in token"
    )
)
async def role_extraction_shield(
    payload: dict = ShieldedDepends(lambda payload: payload),
) -> Optional[AuthData]:
    """Extract user roles from the JWT payload and create AuthData object"""
    if not payload or "user_id" not in payload:
        return None

    user_id = payload.get("user_id")
    roles = payload.get("roles", [])
    permissions = payload.get("permissions", [])

    return AuthData(user_id, roles, permissions)

def require_role(role: str):
    """Create a shield that requires a specific role"""
    
    @shield(
        name=f"Role Requirement ({role})",
        exception_to_raise_if_fail=HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Requires role: {role}",
        ),
    )
    async def role_shield(
        auth_data: AuthData = ShieldedDepends(lambda auth_data: auth_data),
    ) -> Optional[AuthData]:
        if auth_data.has_role(role):
            return auth_data
        return None

    return role_shield

def require_permission(permission: str):
    """Create a shield that requires a specific permission"""
    
    @shield(
        name=f"Permission Requirement ({permission})",
        exception_to_raise_if_fail=HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Requires permission: {permission}",
        ),
    )
    async def permission_shield(
        auth_data: AuthData = ShieldedDepends(lambda auth_data: auth_data),
    ) -> Optional[AuthData]:
        if auth_data.has_permission(permission):
            return auth_data
        return None

    return permission_shield

# Usage examples
@app.get("/user-profile")
@jwt_auth_shield
@role_extraction_shield
async def user_profile(
    auth_data: AuthData = ShieldedDepends(lambda auth_data: auth_data),
):
    return {
        "user_id": auth_data.user_id,
        "roles": auth_data.roles,
        "permissions": auth_data.permissions,
    }

@app.get("/admin-panel")
@jwt_auth_shield
@role_extraction_shield
@require_role("admin")
async def admin_panel(
    auth_data: AuthData = ShieldedDepends(lambda auth_data: auth_data),
):
    return {"message": "Welcome to admin panel", "user_id": auth_data.user_id}

@app.post("/user-management")
@jwt_auth_shield
@role_extraction_shield
@require_permission("manage_users")
async def user_management(
    auth_data: AuthData = ShieldedDepends(lambda auth_data: auth_data),
):
    return {
        "message": "User management access granted",
        "user_id": auth_data.user_id,
    }
```

## OAuth2 Integration with JWT

FastAPI Shield integrates seamlessly with FastAPI's OAuth2 patterns:

```python
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi_shield import shield, ShieldedDepends
import jwt
from jwt.exceptions import PyJWTError
from datetime import datetime, timedelta
from typing import Optional, List
from pydantic import BaseModel

app = FastAPI()

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Configuration
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Models
class Token(BaseModel):
    access_token: str
    token_type: str

class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    roles: List[str] = []

# Mock database
fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "fakehashedsecret",
        "roles": ["user"]
    },
    "alice": {
        "username": "alice",
        "full_name": "Alice Admin",
        "email": "alice@example.com",
        "hashed_password": "fakehashedsecret2",
        "roles": ["admin", "user"]
    }
}

def verify_password(plain_password: str, hashed_password: str) -> bool:
    # In production, use proper password hashing
    return plain_password == "secret"

def authenticate_user(username: str, password: str):
    user = fake_users_db.get(username)
    if not user or not verify_password(password, user["hashed_password"]):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

@shield(
    name="OAuth2 JWT Authentication",
    exception_to_raise_if_fail=HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
)
async def oauth2_jwt_shield(token: str = Depends(oauth2_scheme)) -> User:
    """Validate OAuth2 JWT token and return user"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
    except PyJWTError:
        return None
    
    user_dict = fake_users_db.get(username)
    if user_dict is None:
        return None
    
    return User(**user_dict)

def require_oauth2_role(role: str):
    """Create a shield that requires a specific OAuth2 role"""
    
    @shield(
        name=f"OAuth2 Role ({role})",
        exception_to_raise_if_fail=HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role {role} required",
        ),
    )
    async def role_check(user: User = ShieldedDepends(lambda user: user)) -> User:
        if role in user.roles:
            return user
        return None
    
    return role_check

# Token endpoint
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
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

# Protected endpoints
@app.get("/users/me")
@oauth2_jwt_shield
async def read_users_me(
    user: User = ShieldedDepends(lambda user: user),
):
    return user

@app.get("/admin/settings")
@oauth2_jwt_shield
@require_oauth2_role("admin")
async def admin_settings(
    user: User = ShieldedDepends(lambda user: user),
):
    return {"message": "Admin settings", "user": user.username}
```

## JWT Token Creation and Management

Here's how to properly create and manage JWT tokens:

```python
import jwt
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

def create_jwt_token(
    user_id: str,
    roles: List[str] = None,
    permissions: List[str] = None,
    expires_delta: Optional[timedelta] = None
) -> str:
    """Create a JWT token with user information"""
    payload = {
        "user_id": user_id,
        "roles": roles or [],
        "permissions": permissions or [],
    }
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=1)
    
    payload["exp"] = expire
    
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

# Example usage
admin_token = create_jwt_token(
    user_id="admin_user",
    roles=["admin", "user"],
    permissions=["read", "write", "delete"],
    expires_delta=timedelta(hours=8)
)

user_token = create_jwt_token(
    user_id="regular_user",
    roles=["user"],
    permissions=["read"],
    expires_delta=timedelta(hours=1)
)
```

## Error Handling and Security Best Practices

### Proper Error Handling

```python
@shield(
    name="Secure JWT Authentication",
    exception_to_raise_if_fail=HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication failed",
        headers={"WWW-Authenticate": "Bearer"},
    )
)
def secure_jwt_shield(authorization: str = Header()) -> Optional[dict]:
    """Secure JWT validation with proper error handling"""
    
    # Check authorization header format
    if not authorization or not authorization.startswith("Bearer "):
        return None
    
    token = authorization.replace("Bearer ", "")
    
    try:
        # Decode and validate token
        payload = jwt.decode(
            token, 
            JWT_SECRET, 
            algorithms=[JWT_ALGORITHM],
            options={"verify_exp": True}  # Ensure expiration is checked
        )
        
        # Validate required claims
        if not payload.get("user_id"):
            return None
        
        # Check token expiration explicitly
        exp = payload.get("exp")
        if exp and datetime.utcnow().timestamp() > exp:
            return None
        
        return payload
        
    except jwt.ExpiredSignatureError:
        # Token has expired
        return None
    except jwt.InvalidTokenError:
        # Token is invalid
        return None
    except Exception:
        # Any other error
        return None
```

### Security Considerations

When implementing JWT authentication with FastAPI Shield, follow these security best practices:

1. **Use Strong Secrets**: Store JWT secrets securely and use strong, random keys
2. **Set Short Expiration Times**: Use short-lived tokens (15-30 minutes) with refresh tokens
3. **Validate All Claims**: Always validate required claims and token structure
4. **Handle Errors Gracefully**: Return `None` from shields for security failures
5. **Use HTTPS**: Always transmit tokens over HTTPS in production
6. **Implement Token Blacklisting**: Consider maintaining a blacklist for revoked tokens

### Environment Configuration

```python
import os
from typing import Optional

# Production configuration
JWT_SECRET = os.getenv("JWT_SECRET_KEY", "fallback-secret-for-dev")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

# Validate configuration
if not JWT_SECRET or JWT_SECRET == "fallback-secret-for-dev":
    if os.getenv("ENVIRONMENT") == "production":
        raise ValueError("JWT_SECRET_KEY must be set in production")
```

## Testing JWT Authentication

When testing JWT authentication with FastAPI Shield, create helper functions for token generation:

```python
import pytest
from fastapi.testclient import TestClient

def create_test_token(user_id: str, roles: List[str] = None) -> str:
    """Create a test JWT token"""
    payload = {
        "user_id": user_id,
        "roles": roles or ["user"]
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def test_protected_endpoint():
    """Test protected endpoint with valid token"""
    client = TestClient(app)
    token = create_test_token("test_user", ["user"])
    
    response = client.get(
        "/protected",
        headers={"Authorization": f"Bearer {token}"}
    )
    
    assert response.status_code == 200
    assert response.json()["user"] == "test_user"

def test_admin_endpoint():
    """Test admin endpoint with admin token"""
    client = TestClient(app)
    token = create_test_token("admin_user", ["admin"])
    
    response = client.get(
        "/admin",
        headers={"Authorization": f"Bearer {token}"}
    )
    
    assert response.status_code == 200
```

## Conclusion

FastAPI Shield provides a powerful, type-safe way to implement JWT authentication in your FastAPI applications. By using the shield decorator pattern and chaining multiple shields, you can create sophisticated authentication and authorization flows that are both secure and maintainable.

Key takeaways:

1. **Use shields as decorators** with descriptive names
2. **Return `None` for validation failures** to trigger shield error responses
3. **Chain shields** for complex authorization logic
4. **Use `ShieldedDepends`** to access shield return values in endpoints
5. **Implement proper error handling** and security best practices
6. **Test thoroughly** with realistic token scenarios

This approach ensures your JWT authentication is robust, secure, and follows FastAPI Shield's proven patterns. 