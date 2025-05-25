<!--Examples tested-->

# Advanced Examples

This section provides advanced examples of using FastAPI Shield for more complex security and validation requirements. These examples have been thoroughly tested and validated.

## Chained Shield Processing

Creating shields that work together and pass data between them in a chain:

```python
from fastapi import FastAPI, Header, HTTPException, status, Depends
from fastapi_shield import shield, ShieldedDepends
import jwt
from typing import Dict, Optional, List
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

@shield(name="JWT Authentication")
async def jwt_auth_shield(authorization: str = Header()) -> Optional[Dict]:
    """Validate JWT token and extract payload"""
    if not authorization.startswith("Bearer "):
        return None
        
    token = authorization.replace("Bearer ", "")
    
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except Exception:
        return None

@shield(name="User Role Extraction")
async def role_extraction_shield(payload = ShieldedDepends(lambda payload: payload)) -> Optional[AuthData]:
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
            detail=f"Requires role: {role}"
        )
    )
    async def role_shield(auth_data: AuthData = ShieldedDepends(lambda auth_data: auth_data)) -> Optional[AuthData]:
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
            detail=f"Requires permission: {permission}"
        )
    )
    async def permission_shield(auth_data: AuthData = ShieldedDepends(lambda auth_data: auth_data)) -> Optional[AuthData]:
        if auth_data.has_permission(permission):
            return auth_data
        return None
        
    return permission_shield

# Endpoints with chained shield protection
@app.get("/user-profile")
@jwt_auth_shield
@role_extraction_shield
async def user_profile(auth_data: AuthData = ShieldedDepends(lambda auth_data: auth_data)):
    return {
        "user_id": auth_data.user_id,
        "roles": auth_data.roles,
        "permissions": auth_data.permissions
    }

@app.get("/admin-panel")
@jwt_auth_shield
@role_extraction_shield
@require_role("admin")
async def admin_panel(auth_data: AuthData = ShieldedDepends(lambda auth_data: auth_data)):
    return {
        "message": "Welcome to admin panel",
        "user_id": auth_data.user_id
    }

@app.post("/user-management")
@jwt_auth_shield
@role_extraction_shield
@require_permission("manage_users")
async def user_management(auth_data: AuthData = ShieldedDepends(lambda auth_data: auth_data)):
    return {
        "message": "User management access granted",
        "user_id": auth_data.user_id
    }

# Helper function to create test tokens
def create_test_token(user_id: str, roles: List[str] = None, permissions: List[str] = None):
    """Create a test JWT token"""
    payload = {
        "user_id": user_id,
        "roles": roles or [],
        "permissions": permissions or [],
        "exp": datetime.utcnow() + timedelta(hours=1)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
```

### Key Features of Chained Processing

1. **Sequential Execution**: Shields execute in sequence, with each shield depending on the previous one
2. **Data Flow**: Each shield can access and transform data from previous shields using `ShieldedDepends`
3. **Validation Chain**: If any shield in the chain fails, the entire request is rejected
4. **Flexible Composition**: Shield factories allow dynamic creation of requirement shields

## Dynamic Shield Configuration with Database

Loading shield configuration and user data from a database:

```python
from fastapi import FastAPI, Depends, Header, HTTPException, status
from fastapi_shield import shield, ShieldedDepends
from pydantic import BaseModel
from typing import List, Optional

app = FastAPI()

# Mock database storage (in production, use actual database)
api_keys_data = {}
user_permissions_data = {}

# Models
class Permission(BaseModel):
    permission: str

class User(BaseModel):
    id: int
    permissions: List[Permission]

# Database dependency (mock)
async def get_db():
    """Mock database dependency - in production, return actual database session"""
    return None  # Mock database connection

@shield(name="Database Auth Shield")
async def db_auth_shield(api_key: str = Header(), db = Depends(get_db)):
    """Authenticate using API key from database"""
    # Mock database query - in production, query actual database
    result = api_keys_data.get(api_key)
    if not result or not result.get("is_active", False):
        return None
        
    return {"user_id": result["user_id"], "key": result["key"]}

@shield(name="Permission Shield")
async def permission_shield(auth_data = ShieldedDepends(lambda auth_data: auth_data), db = Depends(get_db)):
    """Load user permissions from database"""
    if not auth_data:
        return None
        
    user_id = auth_data["user_id"]
    
    # Mock database query for permissions - in production, query actual database
    user_perms = user_permissions_data.get(user_id, [])
    permissions = [Permission(permission=perm) for perm in user_perms]
    
    return User(id=user_id, permissions=permissions)

def require_db_permission(required_permission: str):
    """Create a shield that requires a database-stored permission"""
    
    @shield(
        name=f"DB Permission Requirement ({required_permission})",
        exception_to_raise_if_fail=HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Requires permission: {required_permission}"
        )
    )
    async def permission_check(user: User = ShieldedDepends(lambda auth_data: auth_data)):
        user_permissions = [p.permission for p in user.permissions]
        if required_permission in user_permissions:
            return user
        return None
        
    return permission_check

@app.get("/db-protected")
@db_auth_shield
@permission_shield
async def db_protected_endpoint(user: User = ShieldedDepends(lambda auth_data: auth_data)):
    return {
        "message": "Access granted via database authentication",
        "user_id": user.id,
        "permissions": [p.permission for p in user.permissions]
    }

@app.get("/admin-access")
@db_auth_shield
@permission_shield
@require_db_permission("admin_access")
async def admin_access_endpoint(user: User = ShieldedDepends(lambda auth_data: auth_data)):
    return {
        "message": "Admin access granted",
        "user_id": user.id
    }

# Setup functions for testing/demo
def setup_test_data():
    """Setup test data for demonstration"""
    # Mock API key
    api_keys_data["valid_key"] = {
        "user_id": 1,
        "key": "valid_key",
        "is_active": True
    }
    
    # Mock user permissions
    user_permissions_data[1] = ["read_data", "write_data", "admin_access"]

# Call setup for demo
setup_test_data()
```

### Database Integration Features

1. **Dynamic Configuration**: Authentication and authorization rules stored in database
2. **Runtime Permissions**: User permissions loaded at request time from database
3. **Scalable Architecture**: Easy to add new permissions without code changes
4. **Audit Trail**: All access attempts can be logged to database

## OAuth2 Integration

Integrating FastAPI Shield with OAuth2 authentication flows:

```python
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi_shield import shield, ShieldedDepends
from pydantic import BaseModel
from typing import Dict, Optional
import jwt
from datetime import datetime, timedelta

# OAuth2 configuration
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Mock user database
USERS_DB = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "john@example.com",
        "hashed_password": "fakehashedsecret",
        "roles": ["user"]
    },
    "alice": {
        "username": "alice",
        "full_name": "Alice Smith",
        "email": "alice@example.com",
        "hashed_password": "fakehashedsecret2",
        "roles": ["user", "admin"]
    }
}

# Models
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None
    roles: list[str] = []

class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    roles: list[str] = []

app = FastAPI()

# Helper functions
def verify_password(plain_password, hashed_password):
    """Verify password (simplified for example)"""
    return plain_password == hashed_password

def get_user(db, username: str):
    """Get user from database"""
    if username in db:
        user_dict = db[username]
        return User(**user_dict)
    return None

def authenticate_user(fake_db, username: str, password: str):
    """Authenticate user"""
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, fake_db[username]["hashed_password"]):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """OAuth2 token endpoint"""
    user = authenticate_user(USERS_DB, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "roles": user.roles},
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@shield(name="OAuth2 Shield")
async def oauth2_shield(token: str = Depends(oauth2_scheme)):
    """Shield that validates OAuth2 tokens"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
        token_data = TokenData(username=username, roles=payload.get("roles", []))
    except Exception:
        return None
    
    user = get_user(USERS_DB, username=token_data.username)
    if user is None:
        return None
    
    # Return both user and token data
    return {"user": user, "token_data": token_data}

def require_oauth2_role(role: str):
    """Shield factory for OAuth2 role checking"""
    
    @shield(
        name=f"OAuth2 Role ({role})",
        exception_to_raise_if_fail=HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role {role} required"
        )
    )
    async def role_check(oauth_data = ShieldedDepends(lambda payload: payload)):
        token_data = oauth_data["token_data"]
        if role in token_data.roles:
            return oauth_data
        return None
    
    return role_check

@app.get("/users/me")
@oauth2_shield
async def read_users_me(oauth_data = ShieldedDepends(lambda oauth_data: oauth_data)):
    """Get current user information"""
    user = oauth_data["user"]
    return user

@app.get("/admin/settings")
@oauth2_shield
@require_oauth2_role("admin")
async def admin_settings(oauth_data = ShieldedDepends(lambda oauth_data: oauth_data)):
    """Admin-only endpoint"""
    return {
        "message": "Admin settings",
        "user": oauth_data["user"].username
    }

# Helper function to create test tokens
def create_oauth2_token(username: str, roles: List[str] = None):
    """Create a test OAuth2 JWT token"""
    payload = {
        "sub": username,
        "roles": roles or ["user"],
        "exp": datetime.utcnow() + timedelta(hours=1)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
```

### OAuth2 Integration Features

1. **Standard OAuth2 Flow**: Implements proper OAuth2 password bearer flow
2. **Token Validation**: Comprehensive JWT token validation with expiry checking
3. **Role-Based Access**: Dynamic role checking through shield factories
4. **User Context**: Full user information available in protected endpoints
5. **Token Generation**: Secure token generation with configurable expiry

## Advanced Error Handling

Robust error handling in shield implementations:

```python
from fastapi import FastAPI, Header
from fastapi_shield import shield, ShieldedDepends
import asyncio

app = FastAPI()

@shield(name="Error Test Shield")
async def error_shield(test_mode: str = Header(None)):
    """Shield that demonstrates various error handling scenarios"""
    if test_mode == "exception":
        # Shield handles exceptions gracefully
        raise ValueError("Simulated shield error")
    elif test_mode == "timeout":
        # Shield can handle slow operations
        await asyncio.sleep(0.1)  # Simulate slow operation
        return {"mode": "timeout"}
    elif test_mode == "none":
        # Shield returns None to block access
        return None
    elif test_mode == "valid":
        # Shield returns valid data
        return {"mode": "valid"}
    else:
        # Default case - no access
        return None

@app.get("/error-test")
@error_shield
async def error_test_endpoint(data = ShieldedDepends(lambda data: data)):
    return {"message": "Success", "data": data}
```

## Complex Shield Composition

Advanced patterns for composing multiple shields:

```python
from fastapi import FastAPI, Header
from fastapi_shield import shield, ShieldedDepends

app = FastAPI()

@shield(name="Shield A")
async def shield_a(value_a: str = Header(None)):
    """First shield in the chain"""
    if value_a == "valid_a":
        return {"from_a": "data_a"}
    return None

@shield(name="Shield B")
async def shield_b(
    value_b: str = Header(None),
    data_from_a = ShieldedDepends(lambda data: data)
):
    """Second shield that depends on Shield A"""
    if value_b == "valid_b" and data_from_a:
        return {"from_b": "data_b", "chain_data": data_from_a}
    return None

@shield(name="Shield C")
async def shield_c(
    value_c: str = Header(None),
    data_from_b = ShieldedDepends(lambda data: data)
):
    """Third shield that depends on Shield B"""
    if value_c == "valid_c" and data_from_b:
        return {"from_c": "data_c", "chain_data": data_from_b}
    return None

@app.get("/triple-shield")
@shield_a
@shield_b
@shield_c
async def triple_shield_endpoint(final_data = ShieldedDepends(lambda data: data)):
    """Endpoint protected by three chained shields"""
    return {"message": "Triple shield success", "final_data": final_data}
```

### Composition Features

1. **Data Chaining**: Each shield can access and transform data from previous shields
2. **Fail-Fast**: If any shield in the chain fails, the entire request is rejected
3. **Flexible Ordering**: Shields execute in decorator order (bottom to top)
4. **Context Preservation**: Rich context data flows through the entire chain

## Testing Your Advanced Implementations

These examples include comprehensive testing patterns:

```python
import pytest
from fastapi.testclient import TestClient

def test_chained_shields():
    """Test chained shield processing"""
    client = TestClient(app)
    
    # Test with valid token
    token = create_test_token("user123", ["admin"], ["manage_users"])
    headers = {"Authorization": f"Bearer {token}"}
    
    response = client.get("/admin-panel", headers=headers)
    assert response.status_code == 200
    
    # Test without required role
    token = create_test_token("user123", ["user"], ["read_profile"])
    headers = {"Authorization": f"Bearer {token}"}
    
    response = client.get("/admin-panel", headers=headers)
    assert response.status_code == 403

def test_database_shields():
    """Test database-driven shields"""
    client = TestClient(app)
    
    # Setup test data
    api_keys_data["test_key"] = {
        "user_id": 1,
        "key": "test_key",
        "is_active": True
    }
    user_permissions_data[1] = ["admin_access"]
    
    headers = {"api-key": "test_key"}
    response = client.get("/admin-access", headers=headers)
    assert response.status_code == 200

def test_oauth2_integration():
    """Test OAuth2 integration"""
    client = TestClient(app)
    
    # Test token generation
    form_data = {"username": "johndoe", "password": "fakehashedsecret"}
    response = client.post("/token", data=form_data)
    assert response.status_code == 200
    
    # Test protected endpoint
    token = response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/users/me", headers=headers)
    assert response.status_code == 200
```

## Production Considerations

When implementing these advanced patterns in production:

1. **Error Handling**: Implement comprehensive error logging and monitoring
2. **Performance**: Cache database queries and token validations where appropriate
3. **Security**: Use proper password hashing and secure JWT secrets
4. **Scalability**: Consider distributed caching for multi-instance deployments
5. **Monitoring**: Track shield execution times and failure rates
6. **Testing**: Implement comprehensive test suites covering all edge cases
7. **Documentation**: Maintain clear documentation of shield dependencies and data flow

These advanced examples demonstrate the full power and flexibility of FastAPI Shield for complex authentication and authorization scenarios. 