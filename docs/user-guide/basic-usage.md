# Basic Usage

This guide covers the fundamental concepts and patterns for using FastAPI Shield.

## The Shield Concept

At its core, FastAPI Shield uses a simple yet powerful concept: a shield is a function that validates a request and decides whether to allow it to proceed or block it. Shields are applied as decorators to FastAPI route handlers.

### Shield Function Structure

A shield function has the following characteristics:

1. It can accept any parameters that FastAPI's dependency injection system supports
2. It should return a value if the request should proceed, or `None` if the request should be blocked
3. It can be synchronous or asynchronous

## Creating Basic Shields

### Authentication Shield

Here's a simple authentication shield:

```python
from fastapi import Header, HTTPException
from fastapi_shield import shield

@shield(
    name="API Token Auth",
    auto_error=True,
    exception_to_raise_if_fail=HTTPException(
        status_code=401,
        detail="Invalid API token"
    )
)
def auth_shield(api_token: str = Header()):
    valid_tokens = ["admin_token", "user_token"]
    if api_token in valid_tokens:
        return api_token
    return None
```

### Rate Limiting Shield

Here's a rate limiting shield using a simple in-memory counter:

```python
from fastapi import Request
from fastapi_shield import shield
from collections import defaultdict
import time

# Simple in-memory rate limiter
request_counts = defaultdict(list)
MAX_REQUESTS = 5
WINDOW_SECONDS = 60

@shield(name="Rate Limiter")
def rate_limit_shield(request: Request):
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
```

## Applying Shields to Endpoints

Shields are applied as decorators to FastAPI route handlers:

```python
from fastapi import FastAPI

app = FastAPI()

@app.get("/protected")
@auth_shield
async def protected_endpoint():
    return {"message": "This endpoint is protected by auth_shield"}

@app.get("/rate-limited")
@rate_limit_shield
async def rate_limited_endpoint():
    return {"message": "This endpoint is protected by rate_limit_shield"}

@app.get("/doubly-protected")
@auth_shield
@rate_limit_shield
async def doubly_protected_endpoint():
    return {"message": "This endpoint is protected by both shields"}
```

## Shield Parameters

The `shield` decorator accepts the following parameters:

- `name`: A name for the shield (used in error messages)
- `auto_error`: Whether to automatically raise an exception when the shield blocks a request
- `exception_to_raise_if_fail`: A custom exception to raise when the shield blocks a request
- `default_response_to_return_if_fail`: A custom response to return when the shield blocks a request and `auto_error` is `False`

## Customizing Error Responses

You can customize the error response when a shield blocks a request:

```python
from fastapi import HTTPException, Response, status
from fastapi_shield import shield

@shield(
    name="Custom Error Shield",
    auto_error=True,
    exception_to_raise_if_fail=HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Access denied by custom shield",
        headers={"X-Shield-Blocked": "true"}
    )
)
def custom_error_shield():
    return None  # Always block the request

@shield(
    name="Custom Response Shield",
    auto_error=False,
    default_response_to_return_if_fail=Response(
        content="Request blocked by shield",
        media_type="text/plain",
        status_code=status.HTTP_429_TOO_MANY_REQUESTS
    )
)
def custom_response_shield():
    return None  # Always block the request
```

## Order of Shield Application

The order in which you apply shields matters. Shields are evaluated from top to bottom (outermost decorator to innermost), and processing stops at the first shield that blocks the request.

```python
@app.get("/example")
@first_shield    # Evaluated first
@second_shield   # Evaluated second (if first_shield passes)
@third_shield    # Evaluated third (if both previous shields pass)
async def example_endpoint():
    # This code runs only if all shields pass
    return {"message": "All shields passed"}
``` 