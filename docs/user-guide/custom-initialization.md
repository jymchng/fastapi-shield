<!-- Examples Tested -->

# Custom Initialization

FastAPI Shield provides flexible ways to customize how shields are initialized and configured.

## Shield Factory Pattern

The shield factory pattern allows you to create reusable, configurable shields:

```python
from fastapi import FastAPI, Header, Depends, HTTPException, status
from fastapi_shield import shield
from typing import List, Optional

app = FastAPI()

# Mock user data for testing
user_db = {
    "user1": {"username": "user1", "roles": ["viewer"]},
    "user2": {"username": "user2", "roles": ["editor", "viewer"]},
    "admin": {"username": "admin", "roles": ["admin", "editor", "viewer"]}
}

# Dependency to extract token from header
def get_token_from_header(authorization: str = Header(None)) -> Optional[str]:
    if not authorization or not authorization.startswith("Bearer "):
        return None
    return authorization.replace("Bearer ", "")

# Dependency to get current user from token
def get_current_user(token: str = Depends(get_token_from_header)) -> Optional[dict]:
    if not token:
        return None
    return user_db.get(token)

# Create a shield factory for role-based authorization
def create_role_shield(allowed_roles: List[str], auto_error: bool = True):
    """Factory function that creates a role-based shield"""
    exception = HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=f"Access denied. Required roles: {allowed_roles}"
    )
    
    @shield(
        name=f"Role Shield ({', '.join(allowed_roles)})",
        auto_error=auto_error,
        exception_to_raise_if_fail=exception
    )
    def role_checker(user: Optional[dict] = Depends(get_current_user)) -> Optional[dict]:
        if not user:
            return None
            
        user_roles = user.get("roles", [])
        for role in user_roles:
            if role in allowed_roles:
                return user
        return None
    
    return role_checker

# Create shields for different roles
admin_shield = create_role_shield(["admin"])
editor_shield = create_role_shield(["admin", "editor"])
viewer_shield = create_role_shield(["admin", "editor", "viewer"])
non_auto_error_shield = create_role_shield(["admin"], auto_error=False)

# Apply shields to endpoints
@app.get("/admin")
@admin_shield
def admin_endpoint(user: dict = Depends(lambda x: x)):
    return {"message": "Admin endpoint", "user": user["username"]}

@app.get("/editor")
@editor_shield
def editor_endpoint(user: dict = Depends(lambda x: x)):
    return {"message": "Editor endpoint", "user": user["username"]}

@app.get("/viewer")
@viewer_shield
def viewer_endpoint(user: dict = Depends(lambda x: x)):
    return {"message": "Viewer endpoint", "user": user["username"]}

# Example with non-auto-error shield
@app.get("/optional-admin")
@non_auto_error_shield
def optional_admin_endpoint(user: Optional[dict] = Depends(lambda x: x)):
    if user and "admin" in user.get("roles", []):
        return {"message": "Admin content", "is_admin": True}
    return {"message": "Regular content", "is_admin": False}

## Shield Classes

For more complex shields, you can use classes to encapsulate shield functionality:

```python
from fastapi import FastAPI, Request, HTTPException, status
from fastapi_shield import shield
import time
from typing import Dict, Any, Optional

app = FastAPI()

class RateLimiter:
    """Rate limiter class that enforces request limits per client"""
    
    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.client_requests: Dict[str, list] = {}
        
    def check_rate_limit(self, client_ip: str) -> bool:
        """Check if a client has exceeded their rate limit"""
        now = time.time()
        
        # Initialize or update client's request history
        if client_ip not in self.client_requests:
            self.client_requests[client_ip] = []
        
        # Remove expired timestamps
        self.client_requests[client_ip] = [
            ts for ts in self.client_requests[client_ip]
            if now - ts < self.window_seconds
        ]
        
        # Check if rate limit is exceeded
        if len(self.client_requests[client_ip]) >= self.max_requests:
            return False
        
        # Add current timestamp
        self.client_requests[client_ip].append(now)
        return True
        
    def create_shield(self, name: str = "Rate Limiter"):
        """Create a shield function from this rate limiter"""
        
        @shield(
            name=name,
            auto_error=True,
            exception_to_raise_if_fail=HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Maximum {self.max_requests} requests per {self.window_seconds} seconds.",
                headers={"Retry-After": str(self.window_seconds)}
            )
        )
        def rate_limit_shield(request: Request) -> Optional[Dict[str, Any]]:
            client_ip = request.client.host
            if self.check_rate_limit(client_ip):
                return {"client_ip": client_ip, "rate_limited": False}
            return None
            
        return rate_limit_shield

# Create rate limiters with different configurations
default_limiter = RateLimiter(max_requests=10, window_seconds=60)
strict_limiter = RateLimiter(max_requests=3, window_seconds=60)

# Create shields from the rate limiters
default_rate_shield = default_limiter.create_shield(name="Default Rate Limiter")
strict_rate_shield = strict_limiter.create_shield(name="Strict Rate Limiter")

# Apply the shields to different endpoints
@app.get("/normal")
@default_rate_shield
async def normal_endpoint():
    return {"message": "Normal endpoint with standard rate limiting"}

@app.get("/sensitive")
@strict_rate_shield
async def sensitive_endpoint():
    return {"message": "Sensitive endpoint with strict rate limiting"}
```

## Conditional Shield Creation

You can create shields conditionally based on configuration:

```python
from fastapi import FastAPI
from fastapi_shield import shield
import os

app = FastAPI()

# Get configuration from environment
ENABLE_SECURITY = os.getenv("ENABLE_SECURITY", "true").lower() == "true"
ENVIRONMENT = os.getenv("ENVIRONMENT", "production")

# Basic shield
@shield(name="Basic Security")
def basic_security():
    if ENABLE_SECURITY:
        return True
    return None

# Create shields conditionally
if ENVIRONMENT == "production":
    # In production, use strict checks
    @shield(name="Strict Mode")
    def environment_shield():
        return True
else:
    # In development, be more lenient
    @shield(name="Development Mode")
    def environment_shield():
        # Always pass in development
        return {"development_mode": True}

@app.get("/api/data")
@basic_security
@environment_shield
async def get_data():
    return {"message": "Secured data endpoint"}
```

## Using Dependency Injection for Shield Configuration

You can use FastAPI's dependency injection to configure shields:

```python
from fastapi import FastAPI, Depends
from fastapi_shield import shield
from functools import lru_cache
from pydantic import BaseSettings

class SecuritySettings(BaseSettings):
    """Security settings that can be loaded from environment variables"""
    enable_auth: bool = True
    admin_token: str = "admin_token"
    required_role: str = "admin"
    
    class Config:
        env_prefix = "SECURITY_"

@lru_cache()
def get_security_settings():
    """Cache the settings object"""
    return SecuritySettings()

def create_auth_shield(settings: SecuritySettings = Depends(get_security_settings)):
    """Create an authentication shield based on settings"""
    
    @shield(name="Auth Shield")
    def auth_shield(api_token: str = Header()):
        if not settings.enable_auth:
            # Skip auth check if disabled
            return {"auth_skipped": True}
            
        if api_token == settings.admin_token:
            return {"role": settings.required_role}
        return None
        
    return auth_shield

app = FastAPI()

@app.get("/admin")
@create_auth_shield()
async def admin_endpoint():
    return {"message": "Admin endpoint"}
```

## Dynamic Shield Configuration

For even more flexibility, you can create shields that adjust their behavior dynamically:

```python
from fastapi import FastAPI, Header, Request
from fastapi_shield import shield
import json
import os

app = FastAPI()

# Load shield configuration from file
def load_shield_config():
    config_path = os.getenv("SHIELD_CONFIG", "shield_config.json")
    try:
        with open(config_path, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        # Return default config if file not found or invalid
        return {
            "enabled": True,
            "allowed_tokens": ["admin_token", "user_token"],
            "allowed_ips": ["127.0.0.1"]
        }

@shield(name="Configurable Shield")
def configurable_shield(request: Request, api_token: str = Header()):
    # Load config on each request (could be cached for performance)
    config = load_shield_config()
    
    # Check if shield is enabled
    if not config.get("enabled", True):
        return {"shield_disabled": True}
    
    # Check if client IP is allowed
    client_ip = request.client.host
    allowed_ips = config.get("allowed_ips", [])
    if allowed_ips and client_ip in allowed_ips:
        return {"allowed_by_ip": True}
    
    # Check if token is allowed
    allowed_tokens = config.get("allowed_tokens", [])
    if api_token in allowed_tokens:
        return {"allowed_by_token": True}
    
    # If none of the checks passed, block the request
    return None

@app.get("/configurable")
@configurable_shield
async def configurable_endpoint():
    return {"message": "Endpoint with configurable shield"}
```

These patterns provide flexible ways to customize and configure shields in your FastAPI application. 