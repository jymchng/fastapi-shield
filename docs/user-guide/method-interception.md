# Method Interception

FastAPI Shield provides powerful method interception capabilities, allowing you to control how requests are processed before they reach your endpoint handlers.

## Understanding Method Interception

Method interception is the ability of shields to intercept, validate, and potentially modify the request flow before the actual endpoint function is called. This pattern enables powerful security, validation, and transformation capabilities.

## Basic Method Interception

At its core, method interception in FastAPI Shield works through the shield function's return value:

1. If the shield returns `None`, the request is blocked
2. If the shield returns a non-`None` value, the request is allowed to proceed
3. The returned value can be used by subsequent shields or by the endpoint function

```python
from fastapi import Header, HTTPException
from fastapi_shield import shield

@shield(name="Token Interceptor")
def token_interceptor(api_token: str = Header()):
    """
    Intercepts the request to validate the API token.
    Returns parsed token data if valid, None otherwise.
    """
    if api_token == "admin_token":
        # Return parsed token data
        return {"user_id": "admin", "role": "admin"}
    elif api_token == "user_token":
        # Return parsed token data
        return {"user_id": "user1", "role": "user"}
    # Block the request
    return None
```

## Passing Data Between Shields Using ShieldedDepends

A powerful feature of FastAPI Shield is the ability to pass data between shields using `ShieldedDepends`:

```python
from fastapi import FastAPI
from fastapi_shield import shield, ShieldedDepends

app = FastAPI()

@shield
def token_decoder(authorization: str = Header()):
    """Decode the token and return user data"""
    # In a real app, you would verify and decode a JWT token here
    if authorization.startswith("Bearer "):
        token = authorization[7:]
        if token == "admin_token":
            return {"user_id": "admin", "permissions": ["read", "write", "admin"]}
        elif token == "user_token":
            return {"user_id": "user1", "permissions": ["read"]}
    return None

@shield
def permission_checker(permission: str, token_data = ShieldedDepends(token_decoder)):
    """Check if the user has the required permission"""
    if permission in token_data.get("permissions", []):
        return token_data
    return None

def require_permission(permission: str):
    """Create a shield that requires a specific permission"""
    @shield
    def permission_shield(token_data = ShieldedDepends(token_decoder)):
        return permission_checker(permission, token_data)
    return permission_shield

@app.get("/admin-action")
@token_decoder
@require_permission("admin")
async def admin_action():
    return {"message": "Admin action performed"}

@app.get("/read-data")
@token_decoder
@require_permission("read")
async def read_data():
    return {"message": "Data read successfully"}
```

## Transforming Data

Shields can transform data before it reaches the endpoint:

```python
from fastapi import FastAPI, Depends
from fastapi_shield import shield, ShieldedDepends
from pydantic import BaseModel

app = FastAPI()

class UserInput(BaseModel):
    username: str
    email: str

class SanitizedUserInput(BaseModel):
    username: str
    email: str
    normalized_email: str

@shield
def input_sanitizer(user_input: UserInput = Depends()):
    """Sanitize and normalize user input"""
    # Create a sanitized version of the input
    return SanitizedUserInput(
        username=user_input.username.strip(),
        email=user_input.email.strip().lower(),
        normalized_email=user_input.email.strip().lower()
    )

@app.post("/users")
@input_sanitizer
async def create_user(sanitized_input: SanitizedUserInput = ShieldedDepends(input_sanitizer)):
    # Use the sanitized input
    return {"message": f"User created with email {sanitized_input.normalized_email}"}
```

## Advanced Method Interception

For more complex scenarios, you can create shields that modify request behavior:

```python
from fastapi import FastAPI, Request, Response
from fastapi_shield import shield
import time

app = FastAPI()

@shield(name="Request Logger")
async def request_logger(request: Request):
    """Log request details and measure response time"""
    # Store start time
    start_time = time.time()
    
    # Create a custom attribute on the request to access in the endpoint
    request.state.start_time = start_time
    request.state.logger_data = {
        "path": request.url.path,
        "method": request.method,
        "client_ip": request.client.host
    }
    
    # Allow request to proceed
    return request

@app.get("/timed-endpoint")
@request_logger
async def timed_endpoint(request: Request):
    # Access the custom attribute set by the shield
    elapsed = time.time() - request.state.start_time
    logger_data = request.state.logger_data
    
    return {
        "message": "Endpoint called successfully",
        "elapsed_ms": round(elapsed * 1000, 2),
        "request_info": logger_data
    }
```

## Conditional Interception

You can create shields that intercept requests conditionally:

```python
from fastapi import FastAPI, Request, Response
from fastapi_shield import shield

app = FastAPI()

@shield(name="Cache Control", auto_error=False)
async def cache_control(request: Request):
    """
    Intercept GET requests to check for cached responses.
    If cache hit, return cached response, otherwise let request proceed.
    """
    # Only intercept GET requests
    if request.method != "GET":
        return request
    
    # Check for cache key in headers
    cache_key = request.headers.get("X-Cache-Key")
    if not cache_key:
        return request
    
    # In a real app, you would check a cache here
    # This is a simplified example
    cache = {
        "products-list": Response(
            content='{"products": ["cached-item-1", "cached-item-2"]}',
            media_type="application/json"
        )
    }
    
    # If cache hit, return the cached response
    if cache_key in cache:
        return cache[cache_key]
    
    # Otherwise, proceed with the request
    return request

@app.get("/products")
@cache_control
async def get_products():
    # This code only runs on cache miss
    return {"products": ["item-1", "item-2", "item-3"]}
```

Method interception provides a powerful way to control request flow in your FastAPI application, enabling advanced security, validation, and transformation capabilities. 