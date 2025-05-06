# Examples

This page contains example usage patterns for FastAPI Shield in common scenarios.

## Authentication Shield

A basic authentication shield using API tokens:

```python
from fastapi import FastAPI, Header, HTTPException, status
from fastapi_shield import shield

app = FastAPI()

VALID_API_TOKENS = {
    "admin_token": {"user_id": "admin", "role": "admin"},
    "user_token": {"user_id": "user1", "role": "user"}
}

@shield(
    name="API Token Auth",
    exception_to_raise_if_fail=HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API token"
    )
)
def auth_shield(api_token: str = Header()):
    """Shield that validates API tokens"""
    if api_token in VALID_API_TOKENS:
        return VALID_API_TOKENS[api_token]
    return None

@app.get("/protected")
@auth_shield
async def protected_endpoint():
    return {"message": "This endpoint is protected"}
```

## Role-Based Access Control

A more advanced example with role-based access control:

```python
from fastapi import FastAPI, Header, HTTPException
from fastapi_shield import shield, ShieldedDepends

app = FastAPI()

# User database with roles
USERS = {
    "admin_token": {"user_id": "admin", "roles": ["admin", "user"]},
    "editor_token": {"user_id": "editor", "roles": ["editor", "user"]},
    "user_token": {"user_id": "user1", "roles": ["user"]}
}

@shield(name="Authentication")
def auth_shield(api_token: str = Header()):
    """Authenticate the user and return user data"""
    if api_token in USERS:
        return USERS[api_token]
    return None

def role_shield(required_roles: list[str]):
    """Factory function to create a role-checking shield"""
    
    @shield(name=f"Role Check ({', '.join(required_roles)})")
    def check_role(user_data = ShieldedDepends(auth_shield)):
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
async def admin_endpoint():
    return {"message": "Admin endpoint"}

@app.get("/editor")
@auth_shield
@editor_shield
async def editor_endpoint():
    return {"message": "Editor endpoint"}

@app.get("/user")
@auth_shield
@user_shield
async def user_endpoint():
    return {"message": "User endpoint"}
```

## JWT Authentication

Using JWT tokens with FastAPI Shield:

```python
from fastapi import FastAPI, Header, HTTPException, status
from fastapi_shield import shield, ShieldedDepends
import jwt
from jwt.exceptions import PyJWTError

app = FastAPI()

# Configuration
JWT_SECRET = "your-secret-key"  # In production, use a secure key
JWT_ALGORITHM = "HS256"

@shield(
    name="JWT Auth",
    exception_to_raise_if_fail=HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"}
    )
)
def jwt_shield(authorization: str = Header()):
    """Validate JWT token and return decoded payload"""
    if not authorization.startswith("Bearer "):
        return None
        
    token = authorization.replace("Bearer ", "")
    
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except PyJWTError:
        return None

@shield
def admin_access(payload = ShieldedDepends(lambda payload: payload)):
    """Check if user has admin role in JWT payload"""
    if payload.get("role") == "admin":
        return payload
    return None

@app.get("/protected")
@jwt_shield
async def protected_endpoint():
    return {"message": "Protected endpoint"}

@app.get("/admin-only")
@jwt_shield
@admin_access
async def admin_endpoint():
    return {"message": "Admin only endpoint"}
```

## Rate Limiting Shield

Implementing rate limiting with FastAPI Shield:

```python
from fastapi import FastAPI, Request, HTTPException, status
from fastapi_shield import shield
import time
from collections import defaultdict

app = FastAPI()

# Simple in-memory rate limiter
request_counts = defaultdict(list)
MAX_REQUESTS = 5
WINDOW_SECONDS = 60

@shield(
    name="Rate Limiter",
    exception_to_raise_if_fail=HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail=f"Rate limit exceeded. Maximum {MAX_REQUESTS} requests per {WINDOW_SECONDS} seconds.",
        headers={"Retry-After": str(WINDOW_SECONDS)}
    )
)
def rate_limit_shield(request: Request):
    """Limit requests based on client IP"""
    client_ip = request.client.host
    now = time.time()
    
    # Remove expired timestamps
    request_counts[client_ip] = [ts for ts in request_counts[client_ip] 
                               if now - ts < WINDOW_SECONDS]
    
    # Check if rate limit is exceeded
    if len(request_counts[client_ip]) >= MAX_REQUESTS:
        return None
    
    # Add current timestamp and allow request
    request_counts[client_ip].append(now)
    return True

@app.get("/rate-limited")
@rate_limit_shield
async def rate_limited_endpoint():
    return {"message": "Rate limited endpoint"}
```

## Request Validation Shield

Validating request parameters with FastAPI Shield:

```python
from fastapi import FastAPI, Query, HTTPException, status
from fastapi_shield import shield
from typing import Optional

app = FastAPI()

@shield(
    name="Parameters Validator",
    exception_to_raise_if_fail=HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Invalid parameters"
    )
)
def validate_parameters(
    page: int = Query(1),
    per_page: int = Query(10, ge=1, le=100),
    sort_by: Optional[str] = Query(None)
):
    """Validate and normalize query parameters"""
    valid_sort_fields = ["created_at", "updated_at", "name"]
    
    # Create normalized parameters
    normalized = {
        "page": max(1, page),  # Ensure page is at least 1
        "per_page": max(1, min(per_page, 100)),  # Ensure per_page is between 1 and 100
        "sort_by": sort_by if sort_by in valid_sort_fields else "created_at"
    }
    
    return normalized

@app.get("/items")
@validate_parameters
async def list_items(params: dict = ShieldedDepends(lambda p: p)):
    # Use validated and normalized parameters
    return {
        "items": [f"Item {i}" for i in range(1, 6)],
        "pagination": {
            "page": params["page"],
            "per_page": params["per_page"],
            "sort_by": params["sort_by"]
        }
    }
```

## IP Restriction Shield

Restricting access by IP address:

```python
from fastapi import FastAPI, Request, HTTPException, status
from fastapi_shield import shield

app = FastAPI()

# List of allowed IP addresses
ALLOWED_IPS = ["127.0.0.1", "::1", "192.168.1.1"]

@shield(
    name="IP Restriction",
    exception_to_raise_if_fail=HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Access denied by IP restriction"
    )
)
def ip_restriction_shield(request: Request):
    """Shield that allows only specific IP addresses"""
    client_ip = request.client.host
    
    if client_ip in ALLOWED_IPS:
        return {"client_ip": client_ip}
    return None

@app.get("/internal-api")
@ip_restriction_shield
async def internal_api():
    return {"message": "Internal API endpoint"}
```

These examples showcase different ways to implement security and validation using FastAPI Shield. You can adapt and combine them to suit your application's needs. 