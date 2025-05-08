# Quick Start

This guide will help you get started quickly with FastAPI Shield. We'll create a simple API with protected endpoints.

## Basic Usage

### Creating Your First Shield

Let's create a simple `@auth_shield` to shield against unauthenticated requests:

```python
from fastapi import Header
from fastapi_shield import shield

# Create a simple authentication shield
@shield
def auth_shield(api_token: str = Header()):
    """
    A basic shield that validates an API token.
    Returns the token if valid, otherwise returns None which blocks the request.
    """
    if api_token in ("admin_token", "user_token"):
        return api_token
    return None
```

The shield acts as a decorator that protects your endpoint from unauthorized access. When a request comes in, the shield evaluates the API token before the endpoint function is called. If the token is invalid (returning `None`), the request is blocked.

### Applying the Shield to an Endpoint

Now let's apply our shield to a FastAPI endpoint:

```python
from fastapi import FastAPI

app = FastAPI()

# Protected endpoint - requires authentication
@app.get("/protected/{name}")
@auth_shield  # Apply the auth_shield
async def protected_endpoint(name: str):
    return {
        "message": f"Hello {name}. This endpoint is protected!",
    }
```

### Testing the Protected Endpoint

Let's test our protected endpoint using FastAPI's test client:

```python
from fastapi.testclient import TestClient

client = TestClient(app)

# Test with valid token
response = client.get("/protected/John", headers={"api-token": "admin_token"})
print(response.status_code)  # 200
print(response.json())       # {"message": "Hello John. This endpoint is protected!"}

# Test with invalid token
response = client.get("/protected/John", headers={"api-token": "invalid_token"})
print(response.status_code)  # 500
print(response.json())       # {"detail": "Shield with name `unknown` blocks the request"}
```

## Role-Based Access Control

### Creating a Roles Shield

Let's create a more advanced shield for role-based access control:

```python
from fastapi_shield import shield, ShieldedDepends

# Simulate retrieving payload from token
def get_payload_from_token(api_token: str = Header()):
    payloads = {
        "admin_token": {"user_id": "admin1", "roles": ["admin", "user"]},
        "user_token": {"user_id": "user1", "roles": ["user"]},
    }
    return payloads.get(api_token, {})

# Role-based shield
def roles_shield(required_roles: list[str]):
    @shield
    def wrapper(payload = ShieldedDepends(get_payload_from_token)):
        if any(role in payload.get("roles", []) for role in required_roles):
            return payload
        return None
    return wrapper
```

### Using Multiple Shields

Now we can stack multiple shields for layered protection:

```python
@app.get("/admin-only")
@auth_shield
@roles_shield(["admin"])
async def admin_endpoint():
    return {"message": "This endpoint is for admins only!"}

@app.get("/user-content")
@auth_shield
@roles_shield(["user"])
async def user_endpoint():
    return {"message": "This endpoint is for users!"}
```

This is just a basic introduction to FastAPI Shield. For more advanced usage, check out our [User Guide](../user-guide/basic-usage.md) and [Examples](../examples/basic_examples.md). 