# Shield Class

The `Shield` class is the core component of FastAPI Shield, providing request interception and validation functionality.

## Overview

The `Shield` class works as a decorator that wraps FastAPI endpoint functions. It intercepts requests before they reach the endpoint, runs validation logic, and either allows or blocks the request based on the validation result.

## Class Reference

::: fastapi_shield.shield.Shield
    options:
      members:
        - __init__
        - __call__
        - _raise_or_return_default_response
      show_root_heading: false
      show_source: false
      heading_level: 3
      show_bases: true
      show_inheritance_diagram: false
      merge_init_into_class: false
      docstring_style: google
      docstring_options:
        ignore_init_summary: false
      filters:
        - "!^_"
        - "^__init__$"
        - "^__call__$"
        - "^_raise_or_return_default_response$"

## Usage Examples

### Basic Shield

```python
from fastapi import FastAPI, Request
from fastapi_shield import Shield

app = FastAPI()

def auth_validation(request: Request) -> dict | None:
    """Validate authentication token."""
    token = request.headers.get("Authorization")
    if validate_token(token):
        return {"user_id": 123, "role": "user"}
    return None

# Create shield instance
auth_shield = Shield(auth_validation, name="Authentication")

@app.get("/protected")
@auth_shield
def protected_endpoint():
    return {"message": "Access granted"}
```

### Custom Error Handling

```python
from fastapi import HTTPException, Response
from fastapi_shield import Shield

# Shield with custom exception
auth_shield = Shield(
    auth_validation,
    name="Authentication",
    exception_to_raise_if_fail=HTTPException(
        status_code=401,
        detail="Authentication required"
    )
)

# Shield with custom response (no exception)
auth_shield_no_error = Shield(
    auth_validation,
    name="Authentication",
    auto_error=False,
    default_response_to_return_if_fail=Response(
        content="Please authenticate",
        status_code=401,
        headers={"WWW-Authenticate": "Bearer"}
    )
)
```

### Async Shield Functions

```python
import aioredis
from fastapi import Request

async def rate_limit_shield(request: Request) -> dict | None:
    """Rate limiting with Redis."""
    redis = aioredis.from_url("redis://localhost")
    client_ip = request.client.host
    
    # Check rate limit
    current_count = await redis.incr(f"rate_limit:{client_ip}")
    if current_count == 1:
        await redis.expire(f"rate_limit:{client_ip}", 60)
    
    if current_count > 100:  # 100 requests per minute
        return None
    
    return {"requests_remaining": 100 - current_count}

rate_limiter = Shield(rate_limit_shield, name="RateLimit")

@app.get("/api/data")
@rate_limiter
def get_data():
    return {"data": "sensitive information"}
```

## Integration with Dependencies

Shields work seamlessly with FastAPI's dependency injection system and can access any parameters that the endpoint would receive:

```python
from fastapi import Depends, Path

def get_database():
    # Database connection logic
    return database

def ownership_shield(
    request: Request,
    user_id: int = Path(...),
    db = Depends(get_database)
) -> dict | None:
    """Verify user owns the resource."""
    current_user = get_current_user_from_token(request)
    if current_user.id == user_id or current_user.is_admin:
        return {"current_user": current_user}
    return None

ownership_guard = Shield(ownership_shield, name="Ownership")

@app.get("/users/{user_id}/profile")
@ownership_guard
def get_user_profile(user_id: int, db = Depends(get_database)):
    return get_profile_from_db(db, user_id)
```

## Shield Chaining

Multiple shields can be chained together for layered protection:

```python
@app.get("/admin/users/{user_id}")
@auth_shield
@admin_shield
@rate_limiter
def admin_get_user(user_id: int):
    return {"user": get_user(user_id)}
```

## Error Handling

Shields provide comprehensive error handling options:

- **auto_error=True** (default): Raises HTTP exceptions when validation fails
- **auto_error=False**: Returns custom responses without raising exceptions
- **Custom exceptions**: Define specific HTTPExceptions for different failure scenarios
- **Custom responses**: Full control over response content, headers, and status codes

## Performance Considerations

- Shield functions should be lightweight and fast
- Use async shield functions for I/O operations (database, Redis, HTTP calls)
- Consider caching validation results when appropriate
- Shields are called for every request, so optimize for performance

## See Also

- [ShieldDepends](shield-depends.md) - Dependency injection for shields
- [shield factory function](shield-factory.md) - Convenient decorator interface
- [Utils](utils.md) - Utility functions used internally 