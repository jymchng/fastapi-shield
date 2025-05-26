<!--Examples tested-->

# Dependency Injection with FastAPI Shield

FastAPI Shield provides a powerful dependency injection system that extends FastAPI's built-in dependency injection with shield-based validation and transformation. This guide explores how to use shields with dependencies based on the actual implementation patterns.

## Understanding Shield Architecture

FastAPI Shield works by decorating endpoints with shields that:
1. Execute before the endpoint function
2. Can validate, transform, or block requests
3. Pass validated data to the endpoint via `ShieldedDepends`

The key components are:
- `@shield` decorator: Creates a shield function that validates/transforms data
- `ShieldedDepends`: A dependency that receives data from shield functions
- Shield composition: Multiple shields can be chained together

## Basic Shield with Dependencies

Here's how shields work with dependencies:

```python
from fastapi import FastAPI, Header, HTTPException, Depends
from fastapi_shield import shield, ShieldedDepends
from typing import Optional

app = FastAPI()

# Mock database
USERS_DB = {
    "user1": {"username": "user1", "email": "user1@example.com", "roles": ["user"]},
    "admin1": {"username": "admin1", "email": "admin1@example.com", "roles": ["admin", "user"]},
}

def get_database():
    """Dependency that provides database access"""
    return USERS_DB

def validate_token(token: str) -> bool:
    """Helper function to validate tokens"""
    return token in ["valid_user_token", "valid_admin_token"]

def get_user_from_token(token: str) -> Optional[str]:
    """Helper function to extract username from token"""
    if token == "valid_user_token":
        return "user1"
    elif token == "valid_admin_token":
        return "admin1"
    return None

# Authentication shield
@shield(name="Authentication Shield")
def auth_shield(authorization: str = Header()) -> Optional[str]:
    """Shield that validates authorization header and returns token"""
    if not authorization.startswith("Bearer "):
        return None
    
    token = authorization.replace("Bearer ", "")
    if validate_token(token):
        return token
    return None

# User data retrieval function (used with ShieldedDepends)
def get_user_data(
    token: str,  # This comes from the shield
    db: dict = Depends(get_database)  # This is a regular FastAPI dependency
) -> dict:
    """Function that gets user data using token from shield and database dependency"""
    username = get_user_from_token(token)
    if username and username in db:
        return db[username]
    raise HTTPException(status_code=404, detail="User not found")

# Endpoint using shield and ShieldedDepends
@app.get("/profile")
@auth_shield
async def get_profile(
    user: dict = ShieldedDepends(get_user_data)
):
    """Endpoint that requires authentication and returns user profile"""
    return {
        "username": user["username"],
        "email": user["email"],
        "roles": user["roles"]
    }
```

## Shield Composition and Chaining

Shields can be composed to create complex validation chains:

```python
from fastapi import FastAPI, Header, HTTPException
from fastapi_shield import shield, ShieldedDepends
from typing import List, Optional

app = FastAPI()

# Authentication shield (first in chain)
@shield(name="JWT Auth")
def jwt_auth_shield(authorization: str = Header()) -> Optional[dict]:
    """Validates JWT token and returns payload"""
    if not authorization.startswith("Bearer "):
        return None
    
    token = authorization.replace("Bearer ", "")
    # In real app, decode JWT here
    if token == "valid_jwt_token":
        return {
            "user_id": "user123",
            "username": "john_doe",
            "roles": ["user", "admin"],
            "permissions": ["read:profile", "write:profile"]
        }
    return None

# Role validation shield (second in chain)
def require_role(required_role: str):
    """Factory function that creates role-checking shields"""
    
    @shield(
        name=f"Role Check ({required_role})",
        exception_to_raise_if_fail=HTTPException(
            status_code=403,
            detail=f"Role '{required_role}' required"
        )
    )
    def role_shield(
        payload: dict = ShieldedDepends(lambda payload: payload)  # Gets data from previous shield
    ) -> Optional[dict]:
        """Shield that checks if user has required role"""
        user_roles = payload.get("roles", [])
        if required_role in user_roles:
            return payload
        return None
    
    return role_shield

# Permission validation shield (third in chain)
def require_permission(required_permission: str):
    """Factory function that creates permission-checking shields"""
    
    @shield(
        name=f"Permission Check ({required_permission})",
        exception_to_raise_if_fail=HTTPException(
            status_code=403,
            detail=f"Permission '{required_permission}' required"
        )
    )
    def permission_shield(
        payload: dict = ShieldedDepends(lambda payload: payload)  # Gets data from previous shield
    ) -> Optional[dict]:
        """Shield that checks if user has required permission"""
        user_permissions = payload.get("permissions", [])
        if required_permission in user_permissions:
            return payload
        return None
    
    return permission_shield

# Create specific shield instances
admin_role_shield = require_role("admin")
write_permission_shield = require_permission("write:profile")

# Endpoint with multiple shields
@app.get("/admin-profile")
@jwt_auth_shield
@admin_role_shield
async def admin_profile(
    user_data: dict = ShieldedDepends(lambda payload: payload)
):
    """Endpoint requiring JWT auth and admin role"""
    return {
        "message": "Admin profile access granted",
        "user_id": user_data["user_id"],
        "username": user_data["username"]
    }

@app.post("/update-profile")
@jwt_auth_shield
@write_permission_shield
async def update_profile(
    profile_data: dict,
    user_data: dict = ShieldedDepends(lambda payload: payload)
):
    """Endpoint requiring JWT auth and write permission"""
    return {
        "message": "Profile updated",
        "user_id": user_data["user_id"],
        "updated_data": profile_data
    }
```

## Working with Pydantic Models

FastAPI Shield integrates seamlessly with Pydantic for data validation:

```python
from fastapi import FastAPI, Body, HTTPException
from fastapi_shield import shield, ShieldedDepends
from pydantic import BaseModel, Field, field_validator
from typing import Optional, List

app = FastAPI()

# Pydantic models
class UserInput(BaseModel):
    username: str = Field(..., min_length=3, max_length=20)
    email: str = Field(..., pattern=r'^[^@]+@[^@]+\.[^@]+$')
    full_name: Optional[str] = None
    age: int = Field(..., ge=13, le=120)

class ValidatedUser(BaseModel):
    username: str
    email: str
    full_name: Optional[str]
    age: int
    is_valid: bool = True
    validation_notes: List[str] = []

# Shield that validates and transforms user data
@shield(
    name="User Validator",
    exception_to_raise_if_fail=HTTPException(
        status_code=400,
        detail="User validation failed"
    )
)
def validate_user_shield(user_input: UserInput = Body()) -> Optional[ValidatedUser]:
    """Shield that performs additional validation beyond Pydantic"""
    
    # Check for reserved usernames
    reserved_usernames = ["admin", "system", "root", "api"]
    if user_input.username.lower() in reserved_usernames:
        return None
    
    # Check email domain restrictions
    allowed_domains = ["company.com", "partner.org"]
    email_domain = user_input.email.split("@")[1]
    if email_domain not in allowed_domains:
        return None
    
    # Create validated user with additional metadata
    validated_user = ValidatedUser(
        username=user_input.username,
        email=user_input.email,
        full_name=user_input.full_name,
        age=user_input.age,
        validation_notes=["Email domain approved", "Username available"]
    )
    
    return validated_user

# Function to enrich user data (used with ShieldedDepends)
def enrich_user_data(validated_user: ValidatedUser) -> dict:
    """Function that enriches validated user data"""
    return {
        "user": validated_user.dict(),
        "account_type": "premium" if validated_user.age >= 18 else "standard",
        "welcome_message": f"Welcome, {validated_user.username}!",
        "next_steps": ["verify_email", "complete_profile"]
    }

@app.post("/register")
@validate_user_shield
async def register_user(
    enriched_data: dict = ShieldedDepends(enrich_user_data)
):
    """Endpoint that registers a user with validation and enrichment"""
    return {
        "message": "User registered successfully",
        "data": enriched_data
    }
```

## Database Integration with Shields

Here's how to integrate shields with database operations:

```python
from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi_shield import shield, ShieldedDepends
from typing import Optional, Dict, Any
import asyncio

app = FastAPI()

# Mock database
USERS_DB = {
    "user1": {"id": 1, "username": "user1", "active": True, "role": "user"},
    "admin1": {"id": 2, "username": "admin1", "active": True, "role": "admin"},
    "inactive1": {"id": 3, "username": "inactive1", "active": False, "role": "user"},
}

async def get_database():
    """Async database dependency"""
    # Simulate database connection
    await asyncio.sleep(0.01)
    return USERS_DB

# Authentication shield with database lookup
@shield(name="Database Auth")
async def db_auth_shield(
    api_key: str = Header(),
    db: Dict[str, Any] = Depends(get_database)
) -> Optional[dict]:
    """Shield that authenticates user against database"""
    
    # Simple API key to username mapping
    api_key_mapping = {
        "user1_key": "user1",
        "admin1_key": "admin1",
        "inactive1_key": "inactive1"
    }
    
    username = api_key_mapping.get(api_key)
    if not username:
        return None
    
    user = db.get(username)
    if not user or not user["active"]:
        return None
    
    return user

# Function to get user permissions (used with ShieldedDepends)
async def get_user_permissions(
    user: dict,  # Comes from shield
    db: Dict[str, Any] = Depends(get_database)  # Database dependency
) -> dict:
    """Function that retrieves user permissions from database"""
    
    # Mock permission lookup
    permissions_map = {
        "user": ["read:own_data"],
        "admin": ["read:own_data", "read:all_data", "write:all_data"]
    }
    
    permissions = permissions_map.get(user["role"], [])
    
    return {
        "user": user,
        "permissions": permissions,
        "can_read_all": "read:all_data" in permissions,
        "can_write_all": "write:all_data" in permissions
    }

@app.get("/user-data")
@db_auth_shield
async def get_user_data(
    user_info: dict = ShieldedDepends(get_user_permissions)
):
    """Endpoint that returns user data based on permissions"""
    
    if user_info["can_read_all"]:
        # Admin can see all users
        return {
            "message": "All user data",
            "data": list(USERS_DB.values()),
            "user": user_info["user"]
        }
    else:
        # Regular user can only see their own data
        return {
            "message": "Your user data",
            "data": user_info["user"],
            "permissions": user_info["permissions"]
        }
```

## Advanced Shield Patterns

### Conditional Shield Execution

```python
from fastapi import FastAPI, Header, Query
from fastapi_shield import shield, ShieldedDepends
from typing import Optional

app = FastAPI()

# Feature flag shield
@shield(name="Feature Flag Check")
def feature_flag_shield(
    feature: str = Query(...),
    user_type: str = Header(default="regular")
) -> Optional[dict]:
    """Shield that checks if feature is enabled for user type"""
    
    feature_flags = {
        "beta_feature": ["premium", "admin"],
        "experimental_api": ["admin"],
        "new_ui": ["regular", "premium", "admin"]
    }
    
    allowed_user_types = feature_flags.get(feature, [])
    if user_type in allowed_user_types:
        return {
            "feature": feature,
            "user_type": user_type,
            "access_granted": True
        }
    return None

@app.get("/feature/{feature_name}")
@feature_flag_shield
async def access_feature(
    feature_name: str,
    access_info: dict = ShieldedDepends(lambda info: info)
):
    """Endpoint that provides access to features based on user type"""
    return {
        "message": f"Access granted to {access_info['feature']}",
        "user_type": access_info["user_type"],
        "feature_data": f"Data for {feature_name}"
    }
```

### Error Handling in Shields

```python
from fastapi import FastAPI, HTTPException, Header
from fastapi_shield import shield, ShieldedDepends
from typing import Optional

app = FastAPI()

# Shield with custom error handling
@shield(
    name="Rate Limit Shield",
    exception_to_raise_if_fail=HTTPException(
        status_code=429,
        detail="Rate limit exceeded",
        headers={"Retry-After": "60"}
    )
)
def rate_limit_shield(
    x_client_id: str = Header()
) -> Optional[dict]:
    """Shield that implements rate limiting"""
    
    # Mock rate limiting logic
    rate_limits = {
        "client1": {"requests": 5, "window": 60},
        "client2": {"requests": 100, "window": 60}
    }
    
    if x_client_id not in rate_limits:
        return None
    
    # In real implementation, check against Redis or similar
    # For demo, always allow
    return {
        "client_id": x_client_id,
        "rate_limit": rate_limits[x_client_id]
    }

@app.get("/api/data")
@rate_limit_shield
async def get_api_data(
    client_info: dict = ShieldedDepends(lambda info: info)
):
    """Rate-limited API endpoint"""
    return {
        "data": "API response data",
        "client": client_info["client_id"],
        "rate_limit": client_info["rate_limit"]
    }
```

## Best Practices

### 1. Shield Naming and Organization

```python
# Good: Descriptive shield names
@shield(name="JWT Authentication")
def jwt_auth_shield(token: str = Header()) -> Optional[dict]:
    pass

@shield(name="Admin Role Check")
def admin_role_shield(user: dict = ShieldedDepends(lambda u: u)) -> Optional[dict]:
    pass

# Good: Shield factory functions for reusability
def require_role(role: str):
    @shield(name=f"Require {role} Role")
    def role_shield(user: dict = ShieldedDepends(lambda u: u)) -> Optional[dict]:
        return user if role in user.get("roles", []) else None
    return role_shield
```

### 2. Proper ShieldedDepends Usage

```python
# Correct: Use lambda functions to pass data from shields
@app.get("/endpoint")
@auth_shield
async def endpoint(
    user_data: dict = ShieldedDepends(lambda user: user)  # Gets data from auth_shield
):
    pass

# Correct: Use functions for complex dependency resolution
def get_user_with_permissions(user_data: dict, db = Depends(get_db)) -> dict:
    # Complex logic here
    return enriched_user_data

@app.get("/endpoint")
@auth_shield
async def endpoint(
    user: dict = ShieldedDepends(get_user_with_permissions)
):
    pass
```

### 3. Shield Composition Order

```python
# Correct order: Authentication -> Authorization -> Business Logic
@app.get("/admin-endpoint")
@jwt_auth_shield          # 1. Authenticate user
@admin_role_shield        # 2. Check admin role
@rate_limit_shield        # 3. Apply rate limiting
async def admin_endpoint(
    user: dict = ShieldedDepends(lambda user: user)
):
    pass
```

### 4. Error Handling

```python
# Good: Specific error messages and status codes
@shield(
    name="Permission Check",
    exception_to_raise_if_fail=HTTPException(
        status_code=403,
        detail="Insufficient permissions for this operation",
        headers={"X-Required-Permission": "admin:write"}
    )
)
def permission_shield(user: dict = ShieldedDepends(lambda u: u)) -> Optional[dict]:
    return user if "admin:write" in user.get("permissions", []) else None
```

### 5. Testing Shields

```python
# Test shields independently
def test_auth_shield():
    # Test shield logic directly
    result = auth_shield.__wrapped__("Bearer valid_token")
    assert result is not None
    
    result = auth_shield.__wrapped__("Bearer invalid_token")
    assert result is None

# Test shield composition
def test_endpoint_with_shields(client):
    response = client.get("/protected", headers={"Authorization": "Bearer valid_token"})
    assert response.status_code == 200
```

This documentation reflects the actual implementation patterns used in FastAPI Shield, showing how shields work as decorators that validate requests and pass data to endpoints via `ShieldedDepends`. 