# shield Function

The `shield` function is the main entry point for creating Shield instances. It can be used as a decorator with or without parameters, or as a factory function.

## Overview

The `shield` function provides a convenient interface for creating `Shield` instances. It supports multiple usage patterns:

- Direct decorator usage: `@shield`
- Parameterized decorator: `@shield(name="Auth", auto_error=False)`
- Factory function: `auth_shield = shield(my_function, name="Auth")`

## Function Reference

::: fastapi_shield.shield.shield
    options:
      show_root_heading: false
      show_source: false
      heading_level: 3
      docstring_style: google
      docstring_options:
        ignore_init_summary: false

## Usage Patterns

### Direct Decorator Usage

The simplest way to create a shield:

```python
from fastapi import FastAPI, Request
from fastapi_shield import shield

app = FastAPI()

@shield
def auth_shield(request: Request) -> dict | None:
    """Validate authentication token."""
    token = request.headers.get("Authorization")
    if validate_token(token):
        return {"user_id": 123, "username": "john"}
    return None

@app.get("/protected")
@auth_shield
def protected_endpoint():
    return {"message": "Access granted"}
```

### Parameterized Decorator

Configure shield behavior with parameters:

```python
@shield(name="Authentication", auto_error=False)
def auth_shield(request: Request) -> dict | None:
    """Named shield with custom error handling."""
    token = request.headers.get("Authorization")
    if validate_token(token):
        return {"user_id": 123}
    return None

@shield(
    name="RateLimit",
    exception_to_raise_if_fail=HTTPException(429, "Rate limit exceeded")
)
async def rate_limit_shield(request: Request) -> dict | None:
    """Rate limiting shield with custom exception."""
    client_ip = request.client.host
    if await check_rate_limit(client_ip):
        return {"client_ip": client_ip}
    return None
```

### Factory Function Usage

Create shield instances programmatically:

```python
def auth_validation(request: Request) -> dict | None:
    """Authentication validation logic."""
    # Validation logic here
    return user_data or None

# Create shield instance
auth_shield = shield(
    auth_validation,
    name="Authentication",
    auto_error=True,
    exception_to_raise_if_fail=HTTPException(401, "Unauthorized")
)

# Apply to endpoints
@app.get("/profile")
@auth_shield
def get_profile():
    return {"profile": "user data"}
```

### Dynamic Shield Creation

Create shields based on configuration:

```python
def create_auth_shield(config: dict):
    """Factory for creating authentication shields."""
    
    def auth_function(request: Request) -> dict | None:
        # Use config to determine validation method
        if config["method"] == "jwt":
            return validate_jwt(request)
        elif config["method"] == "api_key":
            return validate_api_key(request)
        return None
    
    return shield(
        auth_function,
        name=config.get("name", "Authentication"),
        auto_error=config.get("auto_error", True)
    )

# Create shields from configuration
jwt_config = {"method": "jwt", "name": "JWT Auth"}
api_key_config = {"method": "api_key", "name": "API Key Auth"}

jwt_shield = create_auth_shield(jwt_config)
api_key_shield = create_auth_shield(api_key_config)
```

## Advanced Patterns

### Conditional Shield Application

```python
def create_conditional_shield(condition_func):
    """Create a shield that only applies under certain conditions."""
    
    @shield
    def conditional_shield(request: Request) -> dict | None:
        if condition_func(request):
            return perform_validation(request)
        return {"bypass": True}  # Allow request without validation
    
    return conditional_shield

# Example: Only validate during business hours
def is_business_hours(request: Request) -> bool:
    from datetime import datetime
    now = datetime.now()
    return 9 <= now.hour <= 17  # 9 AM to 5 PM

business_hours_auth = create_conditional_shield(is_business_hours)

@app.get("/api/data")
@business_hours_auth
def get_data():
    return {"data": "sensitive information"}
```

### Shield with Retry Logic

```python
@shield(name="ResilientAuth")
async def resilient_auth_shield(request: Request) -> dict | None:
    """Authentication shield with retry logic."""
    max_retries = 3
    for attempt in range(max_retries):
        try:
            token = request.headers.get("Authorization")
            user_data = await validate_token_async(token)
            if user_data:
                return user_data
        except TemporaryError:
            if attempt == max_retries - 1:
                break
            await asyncio.sleep(0.1 * (2 ** attempt))  # Exponential backoff
    return None
```

### Multi-Environment Shields

```python
def create_environment_specific_shield(environment: str):
    """Create shields with environment-specific behavior."""
    
    if environment == "development":
        @shield(name="DevAuth", auto_error=False)
        def dev_shield(request: Request) -> dict | None:
            # Relaxed validation for development
            return {"user_id": 1, "username": "dev_user"}
        return dev_shield
    
    elif environment == "production":
        @shield(
            name="ProdAuth",
            exception_to_raise_if_fail=HTTPException(401, "Unauthorized")
        )
        def prod_shield(request: Request) -> dict | None:
            # Strict validation for production
            return validate_production_token(request)
        return prod_shield

# Usage
import os
env = os.getenv("ENVIRONMENT", "development")
auth_shield = create_environment_specific_shield(env)
```

## Shield Function Patterns

### Path Parameter Validation

```python
@shield
def ownership_shield(
    request: Request,
    user_id: int,  # Path parameter
    item_id: int   # Path parameter
) -> dict | None:
    """Validate user owns the item."""
    current_user = get_current_user_from_request(request)
    if current_user.id == user_id:
        item = get_item(item_id)
        if item and item.owner_id == user_id:
            return {"user": current_user, "item": item}
    return None

@app.get("/users/{user_id}/items/{item_id}")
@ownership_shield
def get_user_item(user_id: int, item_id: int):
    return {"message": "Access granted to item"}
```

### Query Parameter Validation

```python
@shield
def api_version_shield(
    request: Request,
    version: str = Query(default="v1")  # Query parameter
) -> dict | None:
    """Validate API version compatibility."""
    supported_versions = ["v1", "v2", "v3"]
    if version in supported_versions:
        return {"api_version": version, "features": get_features(version)}
    return None

@app.get("/api/data")
@api_version_shield
def get_api_data(version: str = Query(default="v1")):
    return {"data": "API response", "version": version}
```

### Request Body Validation

```python
from pydantic import BaseModel

class AuthRequest(BaseModel):
    username: str
    password: str

@shield
def login_shield(request: Request, auth_data: AuthRequest) -> dict | None:
    """Validate login credentials."""
    if authenticate_user(auth_data.username, auth_data.password):
        return {"user_id": get_user_id(auth_data.username)}
    return None

@app.post("/login")
@login_shield
def login(auth_data: AuthRequest):
    return {"message": "Login successful"}
```

## Error Handling Patterns

### Custom Error Responses

```python
from fastapi import Response

custom_auth_shield = shield(
    auth_function,
    name="CustomAuth",
    auto_error=False,
    default_response_to_return_if_fail=Response(
        content='{"error": "Authentication required", "code": "AUTH_001"}',
        status_code=401,
        headers={
            "Content-Type": "application/json",
            "WWW-Authenticate": "Bearer realm=\"API\""
        }
    )
)
```

### Progressive Error Responses

```python
def create_progressive_shield(max_attempts: int = 3):
    """Shield with progressive error responses."""
    
    @shield(name="ProgressiveAuth")
    def progressive_shield(request: Request) -> dict | None:
        client_ip = request.client.host
        attempts = get_failed_attempts(client_ip)
        
        if attempts >= max_attempts:
            # Temporary ban
            raise HTTPException(
                status_code=429,
                detail="Too many failed attempts. Try again later.",
                headers={"Retry-After": "300"}
            )
        
        auth_result = validate_request(request)
        if not auth_result:
            increment_failed_attempts(client_ip)
            if attempts >= max_attempts - 1:
                raise HTTPException(
                    status_code=401,
                    detail="Last attempt before temporary ban"
                )
            else:
                raise HTTPException(
                    status_code=401,
                    detail=f"Authentication failed. {max_attempts - attempts - 1} attempts remaining"
                )
        
        reset_failed_attempts(client_ip)
        return auth_result
    
    return progressive_shield
```

## Best Practices

1. **Name your shields** - Use descriptive names for better error messages and debugging
2. **Handle async properly** - Use async shield functions for I/O operations
3. **Return structured data** - Return dictionaries or objects that can be used by ShieldedDepends
4. **Fail fast** - Validate early and return None/False to block invalid requests
5. **Use type hints** - Provide proper type annotations for better IDE support
6. **Document shield behavior** - Include docstrings explaining what the shield validates

## See Also

- [Shield Class](shield.md) - The underlying Shield class
- [ShieldedDepends Factory](shielded-depends-factory.md) - Factory for creating dependencies
- [Authentication Patterns](../user-guide/authentication-patterns.md) - Common authentication use cases 