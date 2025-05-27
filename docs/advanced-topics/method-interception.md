<!--Examples tested-->

# Advanced Method Interception

FastAPI Shield provides powerful method interception capabilities that allow you to modify, validate, or enhance request processing in sophisticated ways. This guide explores advanced method interception techniques using FastAPI Shield based on real-world patterns.

## Understanding Shield Architecture

FastAPI Shield works by intercepting requests before they reach your endpoint handlers. A shield is a function that:

1. **Validates** incoming requests
2. **Transforms** or **enriches** request data
3. **Returns** validated data or `None` to block the request
4. **Integrates** seamlessly with FastAPI's dependency injection system

```python
from fastapi import FastAPI, Header, HTTPException, Depends, Request
from fastapi_shield import shield, ShieldedDepends
from typing import Optional, Dict, Any
import time

app = FastAPI()

# Basic shield pattern
@shield(name="Request Logger")
async def log_request(request: Request) -> Optional[Dict[str, Any]]:
    """Shield that logs request details and returns request metadata"""
    start_time = time.time()
    
    print(f"Request: {request.method} {request.url.path}")
    print(f"Client IP: {request.client.host}")
    print(f"Headers: {dict(request.headers)}")
    
    # Return enriched data that can be used by the endpoint
    return {
        "start_time": start_time,
        "method": request.method,
        "path": request.url.path,
        "client_ip": request.client.host
    }

@app.get("/api/data")
@log_request
async def get_data(
    request_info: Dict[str, Any] = ShieldedDepends(lambda data: data)
):
    """Endpoint that uses logged request information"""
    return {
        "message": "Data retrieved successfully",
        "request_info": request_info
    }
```

## Shield Chaining and Composition

One of the most powerful features of FastAPI Shield is the ability to chain multiple shields together, where each shield can depend on the output of previous shields.

```python
from fastapi import FastAPI, Header, HTTPException, Depends
from fastapi_shield import shield, ShieldedDepends
from typing import Optional, Dict, List
import jwt

app = FastAPI()

# First shield: JWT Authentication
@shield(name="JWT Authentication")
async def jwt_auth_shield(authorization: str = Header()) -> Optional[Dict]:
    """Validates JWT token and extracts payload"""
    if not authorization.startswith("Bearer "):
        return None
    
    token = authorization.replace("Bearer ", "")
    
    try:
        # In real app, use proper secret key
        payload = jwt.decode(token, "secret-key", algorithms=["HS256"])
        return payload
    except jwt.PyJWTError:
        return None

# Second shield: Role Extraction (depends on first shield)
@shield(name="Role Extraction")
async def role_extraction_shield(
    payload: Dict = ShieldedDepends(lambda payload: payload)
) -> Optional[Dict]:
    """Extracts user roles and creates user context"""
    if not payload or "user_id" not in payload:
        return None
    
    user_context = {
        "user_id": payload.get("user_id"),
        "username": payload.get("username"),
        "roles": payload.get("roles", []),
        "permissions": payload.get("permissions", [])
    }
    
    return user_context

# Third shield: Role Validation (depends on second shield)
def require_role(required_role: str):
    """Factory function that creates role-checking shields"""
    
    @shield(
        name=f"Role Check ({required_role})",
        exception_to_raise_if_fail=HTTPException(
            status_code=403,
            detail=f"Role '{required_role}' required"
        )
    )
    async def role_shield(
        user_context: Dict = ShieldedDepends(lambda user_context: user_context)
    ) -> Optional[Dict]:
        """Shield that checks if user has required role"""
        user_roles = user_context.get("roles", [])
        if required_role in user_roles:
            return user_context
        return None
    
    return role_shield

# Create specific role shields
admin_role_shield = require_role("admin")
editor_role_shield = require_role("editor")

# Endpoints using chained shields
@app.get("/user-profile")
@jwt_auth_shield
@role_extraction_shield
async def user_profile(
    user: Dict = ShieldedDepends(lambda user_context: user_context)
):
    """Endpoint accessible to any authenticated user"""
    return {
        "user_id": user["user_id"],
        "username": user["username"],
        "roles": user["roles"]
    }

@app.get("/admin-panel")
@jwt_auth_shield
@role_extraction_shield
@admin_role_shield
async def admin_panel(
    user: Dict = ShieldedDepends(lambda user_context: user_context)
):
    """Endpoint accessible only to admin users"""
    return {
        "message": "Welcome to admin panel",
        "user": user
    }
```

## Database Integration with Shields

Shields can integrate with FastAPI's dependency injection system to access databases and other services.

```python
from fastapi import FastAPI, Header, HTTPException, Depends
from fastapi_shield import shield, ShieldedDepends
from typing import Optional, Dict, Any
import asyncio

app = FastAPI()

# Mock database dependency
async def get_database():
    """Simulated database connection"""
    return {
        "api_keys": {
            "valid_key_123": {
                "user_id": "user1",
                "permissions": ["read", "write"],
                "active": True
            },
            "admin_key_456": {
                "user_id": "admin1", 
                "permissions": ["read", "write", "admin"],
                "active": True
            }
        },
        "users": {
            "user1": {"username": "john_doe", "email": "john@example.com"},
            "admin1": {"username": "admin", "email": "admin@example.com"}
        }
    }

# Database authentication shield
@shield(name="Database Auth")
async def db_auth_shield(
    api_key: str = Header(),
    db: Dict[str, Any] = Depends(get_database)
) -> Optional[Dict]:
    """Shield that validates API key against database"""
    api_keys = db.get("api_keys", {})
    
    if api_key not in api_keys:
        return None
    
    key_data = api_keys[api_key]
    if not key_data.get("active", False):
        return None
    
    return {
        "user_id": key_data["user_id"],
        "permissions": key_data["permissions"]
    }

# User enrichment function (used with ShieldedDepends)
async def enrich_user_data(
    auth_data: Dict,  # Comes from shield
    db: Dict[str, Any] = Depends(get_database)  # Database dependency
) -> Dict:
    """Function that enriches auth data with user information"""
    user_id = auth_data["user_id"]
    users = db.get("users", {})
    
    user_info = users.get(user_id, {})
    
    return {
        **auth_data,
        "username": user_info.get("username"),
        "email": user_info.get("email")
    }

@app.get("/user-info")
@db_auth_shield
async def get_user_info(
    user_data: Dict = ShieldedDepends(enrich_user_data)
):
    """Endpoint that returns enriched user information"""
    return {
        "user_id": user_data["user_id"],
        "username": user_data["username"],
        "email": user_data["email"],
        "permissions": user_data["permissions"]
    }
```

## Advanced Shield Patterns

### Factory Pattern for Reusable Shields

Create shield factories for common patterns that can be reused across your application.

```python
from fastapi import FastAPI, Header, HTTPException, Query
from fastapi_shield import shield, ShieldedDepends
from typing import Optional, Dict, List
import time

app = FastAPI()

def create_rate_limit_shield(max_requests: int, window_seconds: int):
    """Factory function that creates rate limiting shields"""
    
    # In-memory storage (use Redis in production)
    request_counts = {}
    
    @shield(
        name=f"Rate Limit ({max_requests}/{window_seconds}s)",
        exception_to_raise_if_fail=HTTPException(
            status_code=429,
            detail="Rate limit exceeded",
            headers={"Retry-After": str(window_seconds)}
        )
    )
    async def rate_limit_shield(x_client_id: str = Header()) -> Optional[Dict]:
        """Shield that enforces rate limiting per client"""
        current_time = time.time()
        
        # Clean old entries
        cutoff_time = current_time - window_seconds
        request_counts[x_client_id] = [
            req_time for req_time in request_counts.get(x_client_id, [])
            if req_time > cutoff_time
        ]
        
        # Check rate limit
        client_requests = request_counts.get(x_client_id, [])
        if len(client_requests) >= max_requests:
            return None
        
        # Record this request
        client_requests.append(current_time)
        request_counts[x_client_id] = client_requests
        
        return {
            "client_id": x_client_id,
            "requests_made": len(client_requests),
            "requests_remaining": max_requests - len(client_requests)
        }
    
    return rate_limit_shield

def create_feature_flag_shield(feature_name: str):
    """Factory function that creates feature flag shields"""
    
    # Mock feature flags (use proper feature flag service in production)
    feature_flags = {
        "new_api": {"enabled": True, "allowed_users": ["premium"]},
        "beta_feature": {"enabled": False, "allowed_users": []},
        "admin_feature": {"enabled": True, "allowed_users": ["admin"]}
    }
    
    @shield(
        name=f"Feature Flag ({feature_name})",
        exception_to_raise_if_fail=HTTPException(
            status_code=404,
            detail=f"Feature '{feature_name}' not available"
        )
    )
    async def feature_flag_shield(
        user_type: str = Header(default="regular")
    ) -> Optional[Dict]:
        """Shield that checks feature flag availability"""
        flag = feature_flags.get(feature_name)
        
        if not flag or not flag.get("enabled", False):
            return None
        
        allowed_users = flag.get("allowed_users", [])
        if allowed_users and user_type not in allowed_users:
            return None
        
        return {
            "feature": feature_name,
            "user_type": user_type,
            "access_granted": True
        }
    
    return feature_flag_shield

# Create shield instances
api_rate_limit = create_rate_limit_shield(max_requests=100, window_seconds=60)
new_api_feature = create_feature_flag_shield("new_api")

@app.get("/api/limited")
@api_rate_limit
async def limited_endpoint(
    rate_info: Dict = ShieldedDepends(lambda info: info)
):
    """Endpoint with rate limiting"""
    return {
        "message": "API call successful",
        "rate_limit_info": rate_info
    }

@app.get("/api/new-feature")
@new_api_feature
async def new_feature_endpoint(
    feature_info: Dict = ShieldedDepends(lambda info: info)
):
    """Endpoint protected by feature flag"""
    return {
        "message": "New feature accessed",
        "feature_info": feature_info
    }
```

### Conditional Shield Application

Apply shields conditionally based on request characteristics.

```python
from fastapi import FastAPI, Header, Request, HTTPException
from fastapi_shield import shield, ShieldedDepends
from typing import Optional, Dict

app = FastAPI()

@shield(name="Conditional Auth")
async def conditional_auth_shield(
    request: Request,
    x_skip_auth: Optional[str] = Header(None)
) -> Optional[Dict]:
    """Shield that applies authentication conditionally"""
    
    # Skip auth for health check endpoints
    if request.url.path in ["/health", "/status"]:
        return {"auth_skipped": True, "reason": "health_check"}
    
    # Skip auth if special header is present (for testing)
    if x_skip_auth == "development":
        return {"auth_skipped": True, "reason": "development_mode"}
    
    # Apply normal authentication
    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    
    # Validate token (simplified)
    token = auth_header.replace("Bearer ", "")
    if token == "valid_token":
        return {
            "auth_skipped": False,
            "user_id": "authenticated_user",
            "token": token
        }
    
    return None

@app.get("/api/data")
@conditional_auth_shield
async def get_data(
    auth_info: Dict = ShieldedDepends(lambda info: info)
):
    """Endpoint with conditional authentication"""
    return {
        "message": "Data retrieved",
        "auth_info": auth_info
    }

@app.get("/health")
@conditional_auth_shield
async def health_check(
    auth_info: Dict = ShieldedDepends(lambda info: info)
):
    """Health check endpoint (auth skipped)"""
    return {
        "status": "healthy",
        "auth_info": auth_info
    }
```

## Error Handling and Custom Responses

FastAPI Shield provides flexible error handling mechanisms.

```python
from fastapi import FastAPI, Header, HTTPException, Response
from fastapi_shield import shield, ShieldedDepends
from typing import Optional, Dict

app = FastAPI()

# Shield with custom error handling
@shield(
    name="Custom Error Shield",
    exception_to_raise_if_fail=HTTPException(
        status_code=418,
        detail="I'm a teapot - custom error message",
        headers={"X-Custom-Header": "shield-blocked"}
    )
)
async def custom_error_shield(
    test_mode: str = Header(default="normal")
) -> Optional[Dict]:
    """Shield that demonstrates custom error responses"""
    
    if test_mode == "fail":
        return None  # This will trigger the custom exception
    
    if test_mode == "error":
        # Shield can raise its own exceptions
        raise HTTPException(
            status_code=400,
            detail="Shield internal error",
            headers={"X-Error-Source": "shield"}
        )
    
    return {"test_mode": test_mode, "status": "success"}

# Shield with custom response (no exception)
@shield(
    name="Custom Response Shield",
    auto_error=False,  # Don't raise exception on failure
    default_response_to_return_if_fail=Response(
        content="Access denied by shield",
        status_code=403,
        headers={"X-Shield-Response": "custom"}
    )
)
async def custom_response_shield(
    access_level: str = Header(default="guest")
) -> Optional[Dict]:
    """Shield that returns custom response instead of raising exception"""
    
    if access_level in ["admin", "user"]:
        return {"access_level": access_level, "granted": True}
    
    return None  # This will return the custom response

@app.get("/test-custom-error")
@custom_error_shield
async def test_custom_error(
    data: Dict = ShieldedDepends(lambda data: data)
):
    """Endpoint that tests custom error handling"""
    return {"message": "Success", "data": data}

@app.get("/test-custom-response")
@custom_response_shield
async def test_custom_response(
    data: Dict = ShieldedDepends(lambda data: data)
):
    """Endpoint that tests custom response handling"""
    return {"message": "Access granted", "data": data}
```

## Performance Monitoring and Metrics

Use shields to implement performance monitoring and metrics collection.

```python
from fastapi import FastAPI, Request, Header
from fastapi_shield import shield, ShieldedDepends
from typing import Optional, Dict
import time
import asyncio

app = FastAPI()

# Performance monitoring shield
@shield(name="Performance Monitor")
async def performance_monitor_shield(request: Request) -> Dict:
    """Shield that tracks request performance metrics"""
    
    start_time = time.time()
    
    # Simulate some processing
    await asyncio.sleep(0.001)  # 1ms delay
    
    return {
        "start_time": start_time,
        "method": request.method,
        "path": request.url.path,
        "client_ip": request.client.host,
        "user_agent": request.headers.get("user-agent", "unknown")
    }

# Function to calculate and log performance metrics
async def log_performance_metrics(
    metrics: Dict,  # Comes from shield
    request: Request  # Additional dependency
) -> Dict:
    """Function that calculates and logs performance metrics"""
    
    current_time = time.time()
    duration = current_time - metrics["start_time"]
    
    # Log metrics (in production, send to monitoring system)
    print(f"Request {metrics['method']} {metrics['path']} took {duration:.3f}s")
    
    if duration > 0.1:  # Log slow requests
        print(f"SLOW REQUEST: {duration:.3f}s for {metrics['path']}")
    
    return {
        **metrics,
        "duration": duration,
        "is_slow": duration > 0.1
    }

@app.get("/api/monitored")
@performance_monitor_shield
async def monitored_endpoint(
    perf_data: Dict = ShieldedDepends(log_performance_metrics)
):
    """Endpoint with performance monitoring"""
    
    # Simulate some work
    await asyncio.sleep(0.05)  # 50ms delay
    
    return {
        "message": "Operation completed",
        "performance": {
            "duration": perf_data["duration"],
            "is_slow": perf_data["is_slow"]
        }
    }
```

## Best Practices for Method Interception

### 1. Keep Shields Focused and Single-Purpose

Each shield should have a single responsibility:

```python
# Good: Single-purpose shields
@shield(name="Authentication")
async def auth_shield(token: str = Header()) -> Optional[Dict]:
    # Only handles authentication
    pass

@shield(name="Authorization") 
async def authz_shield(user: Dict = ShieldedDepends(lambda user: user)) -> Optional[Dict]:
    # Only handles authorization
    pass

# Avoid: Multi-purpose shields that do too much
@shield(name="Auth and Logging and Validation")  # Too much!
async def everything_shield(...):
    pass
```

### 2. Use Shield Factories for Reusability

```python
def create_permission_shield(required_permission: str):
    @shield(name=f"Permission: {required_permission}")
    async def permission_shield(user: Dict = ShieldedDepends(lambda user: user)) -> Optional[Dict]:
        if required_permission in user.get("permissions", []):
            return user
        return None
    return permission_shield

# Reuse across endpoints
read_permission = create_permission_shield("read")
write_permission = create_permission_shield("write")
```

### 3. Handle Errors Gracefully

```python
@shield(
    name="Robust Shield",
    exception_to_raise_if_fail=HTTPException(
        status_code=403,
        detail="Access denied"
    )
)
async def robust_shield(data: str = Header()) -> Optional[Dict]:
    try:
        # Shield logic here
        result = process_data(data)
        return result
    except ValueError as e:
        # Handle specific errors
        raise HTTPException(status_code=400, detail=f"Invalid data: {e}")
    except Exception as e:
        # Handle unexpected errors
        raise HTTPException(status_code=500, detail="Internal shield error")
```

### 4. Use Type Hints for Better Development Experience

```python
from typing import NewType, Dict, Optional

# Create specific types for your domain
AuthenticatedUser = NewType("AuthenticatedUser", Dict[str, Any])
AdminUser = NewType("AdminUser", Dict[str, Any])

@shield(name="User Auth")
async def user_auth_shield(...) -> Optional[AuthenticatedUser]:
    # Return type is clear
    pass

@app.get("/user-data")
@user_auth_shield
async def get_user_data(
    user: AuthenticatedUser = ShieldedDepends(lambda user: user)
):
    # Type hints help with IDE support and documentation
    pass
```

FastAPI Shield's method interception capabilities provide a powerful and flexible way to implement cross-cutting concerns in your FastAPI applications. By following these patterns and best practices, you can create maintainable, secure, and performant applications with clean separation of concerns. 