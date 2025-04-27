# Basic Examples

This section provides basic examples of using FastAPI Shield. These examples demonstrate the fundamental features and patterns of FastAPI Shield.

## Simple Authentication Shield

Here's a basic authentication shield that validates API tokens:

```python
from fastapi import FastAPI, Header, HTTPException, status
from fastapi_shield import shield

app = FastAPI()

# Define valid API tokens
VALID_TOKENS = ["token1", "token2", "token3"]

@shield(
    name="API Token Auth",
    exception_to_raise_if_fail=HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API token"
    )
)
def auth_shield(api_token: str = Header()):
    """Validate the API token"""
    if api_token in VALID_TOKENS:
        return api_token
    return None

@app.get("/protected")
@auth_shield
async def protected_endpoint():
    return {"message": "You have access to the protected endpoint"}
```

## User Role Shield

A shield that checks user roles:

```python
from fastapi import FastAPI, Header, HTTPException, status
from fastapi_shield import shield, ShieldedDepends

app = FastAPI()

# User database with roles
USERS = {
    "token1": {"user_id": 1, "role": "admin"},
    "token2": {"user_id": 2, "role": "editor"},
    "token3": {"user_id": 3, "role": "user"}
}

@shield(name="Auth Shield")
def auth_shield(api_token: str = Header()):
    """Authenticate the user and return user data"""
    if api_token in USERS:
        return USERS[api_token]
    return None

@shield(name="Admin Shield")
def admin_shield(user_data = ShieldedDepends(auth_shield)):
    """Check if the user has admin role"""
    if user_data["role"] == "admin":
        return user_data
    return None

@shield(name="Editor Shield")
def editor_shield(user_data = ShieldedDepends(auth_shield)):
    """Check if the user has editor role"""
    if user_data["role"] in ["admin", "editor"]:
        return user_data
    return None

@app.get("/admin-only")
@auth_shield
@admin_shield
async def admin_endpoint():
    return {"message": "Admin endpoint"}

@app.get("/editor-access")
@auth_shield
@editor_shield
async def editor_endpoint():
    return {"message": "Editor endpoint"}

@app.get("/all-users")
@auth_shield
async def all_users_endpoint(user_data = ShieldedDepends(auth_shield)):
    return {
        "message": f"Welcome, {user_data['role']}",
        "user_id": user_data["user_id"]
    }
```

## Shield with Parameters

Creating a shield that accepts parameters:

```python
from fastapi import FastAPI, Header, HTTPException, status
from fastapi_shield import shield

app = FastAPI()

def create_permission_shield(required_permission: str):
    """Factory function to create a permission shield"""
    
    @shield(
        name=f"Permission Shield ({required_permission})",
        exception_to_raise_if_fail=HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Missing required permission: {required_permission}"
        )
    )
    def permission_shield(permissions: str = Header()):
        """Check if the user has the required permission"""
        user_permissions = permissions.split(",")
        if required_permission in user_permissions:
            return {"granted_permission": required_permission}
        return None
        
    return permission_shield

read_shield = create_permission_shield("read")
write_shield = create_permission_shield("write")
delete_shield = create_permission_shield("delete")

@app.get("/data")
@read_shield
async def read_data():
    return {"message": "Reading data"}

@app.post("/data")
@write_shield
async def write_data():
    return {"message": "Writing data"}

@app.delete("/data")
@delete_shield
async def delete_data():
    return {"message": "Deleting data"}
```

## Multiple Shields

Applying multiple shields to an endpoint:

```python
from fastapi import FastAPI, Header, Query, HTTPException, status
from fastapi_shield import shield
import time

app = FastAPI()

# Simple rate limiting
last_request_time = {}
MIN_REQUEST_INTERVAL = 2  # seconds

@shield(name="Rate Limit Shield")
def rate_limit_shield(client_id: str = Header()):
    """Limit request rate per client"""
    now = time.time()
    
    if client_id in last_request_time:
        time_since_last = now - last_request_time[client_id]
        if time_since_last < MIN_REQUEST_INTERVAL:
            return None
    
    last_request_time[client_id] = now
    return client_id

@shield(name="API Key Shield")
def api_key_shield(api_key: str = Header()):
    """Validate API key"""
    if api_key.startswith("valid_key_"):
        return api_key
    return None

@shield(name="Parameter Validator")
def param_validator(action: str = Query(...)):
    """Validate query parameters"""
    valid_actions = ["read", "write", "update", "delete"]
    if action in valid_actions:
        return action
    return None

@app.get("/api/resource")
@rate_limit_shield
@api_key_shield
@param_validator
async def resource_endpoint(action: str = Query(...)):
    return {
        "message": f"Performing {action} action",
        "timestamp": time.time()
    }
```

## Shield with Custom Response

Customizing the response when a shield blocks the request:

```python
from fastapi import FastAPI, Header, Response, status
from fastapi_shield import shield

app = FastAPI()

@shield(
    name="Feature Flag Shield",
    auto_error=False,
    default_response_to_return_if_fail=Response(
        content='{"message": "This feature is not available in your subscription plan"}',
        media_type="application/json",
        status_code=status.HTTP_402_PAYMENT_REQUIRED
    )
)
def feature_flag_shield(subscription_plan: str = Header()):
    """Check if the user's subscription plan includes the feature"""
    premium_plans = ["premium", "enterprise", "unlimited"]
    if subscription_plan in premium_plans:
        return subscription_plan
    return None

@app.get("/premium-feature")
@feature_flag_shield
async def premium_feature():
    return {"message": "Welcome to the premium feature!"}
```

## Shield with Asynchronous Function

Using an asynchronous function as a shield:

```python
from fastapi import FastAPI, Header, HTTPException, status
from fastapi_shield import shield
import asyncio

app = FastAPI()

async def validate_token_async(token: str) -> bool:
    """Simulate an asynchronous token validation process"""
    await asyncio.sleep(0.1)  # Simulate external API call
    return token.startswith("valid_")

@shield(
    name="Async Auth Shield",
    exception_to_raise_if_fail=HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication token"
    )
)
async def async_auth_shield(auth_token: str = Header()):
    """Asynchronous shield for token validation"""
    # Simulate calling an external authentication service
    is_valid = await validate_token_async(auth_token)
    
    if is_valid:
        return {"token": auth_token, "validated": True}
    return None

@app.get("/async-protected")
@async_auth_shield
async def async_protected_endpoint():
    return {"message": "Protected by async shield"}
```

These examples demonstrate the basic usage of FastAPI Shield. You can combine these patterns and extend them to implement more complex security requirements. 