# API Reference

Welcome to the FastAPI Shield API reference. This section provides detailed documentation for all public APIs of FastAPI Shield.

## Core APIs

FastAPI Shield is organized into several modules:

- [shield](shield.md) - The core shield functionality
- [interceptors](interceptors.md) - Method interception and AOP
- [depends](depends.md) - Dependency injection integration
- [validators](validators.md) - Validation utilities
- [newtype](newtype.md) - Enhanced type safety with NewType

## Using the API

### Basic Usage

The most common way to use FastAPI Shield is with the `shield` function:

```python
from fastapi import FastAPI
from fastapi_shield import shield
from typing import NewType

app = FastAPI()

# Create a shielded type
UserId = NewType("UserId", int)
validated_user_id = shield(
    UserId,
    validators=[lambda v: v if v > 0 else ValueError("User ID must be positive")]
)

# Use in an endpoint
@app.get("/users/{user_id}")
async def get_user(user_id: validated_user_id):
    return {"user_id": user_id}
```

### Advanced Patterns

For more advanced use cases, you can use the various components of FastAPI Shield together:

```python
from fastapi import FastAPI, Depends
from fastapi_shield import shield, ShieldedDepends
from fastapi_shield.interceptors import LoggingInterceptor
from fastapi_shield.validation import min_length, pattern
from typing import NewType
import logging

# Set up logging
logger = logging.getLogger("api")
logging_interceptor = LoggingInterceptor(logger)

# Create a shielded type
Username = NewType("Username", str)
validated_username = shield(
    Username,
    validators=[
        min_length(3),
        pattern(r'^[a-zA-Z0-9_]+$')
    ],
    interceptors=[logging_interceptor],
    description="A valid username (alphanumeric with underscores, at least 3 characters)"
)

# Create a dependency
async def get_username_from_token(token: str):
    # In a real application, verify the token
    return "john_doe"

app = FastAPI()

# Use ShieldedDepends in an endpoint
@app.get("/users/me")
async def get_current_user(
    username: Username = ShieldedDepends(
        get_username_from_token,
        shield=validated_username
    )
):
    return {"username": username}
```

## Import Structure

The public API is organized as follows:

```python
# Core functionality
from fastapi_shield import shield, Shield, ShieldedDepends, ShieldDepends

# Interceptors
from fastapi_shield.interceptors import (
    Interceptor,
    InterceptorChain,
    LoggingInterceptor,
    ValidationInterceptor,
    CacheInterceptor,
    RateLimitInterceptor,
    Aspect,
    with_aspects
)

# Validators
from fastapi_shield.validation import (
    # String validators
    min_length, max_length, pattern, email, url, uuid, not_empty,
    
    # Numeric validators
    min_value, max_value, range_value, positive, negative, integer,
    
    # Collection validators
    min_items, max_items, unique_items, contains,
    
    # Datetime validators
    min_date, max_date, date_range, is_past, is_future
)

# Factory functions
from fastapi_shield import (
    create_shield_factory,
    shield_factory,
    depends_factory,
    shield_depends
)
```

## API Stability

FastAPI Shield follows Semantic Versioning:

- **Stable APIs**: All public APIs documented in this reference are considered stable within a major version
- **Experimental APIs**: APIs marked as experimental may change between minor versions
- **Internal APIs**: APIs not documented here are considered internal and may change at any time

## Versioning

The current version of FastAPI Shield is 0.1.0.

You can check the version at runtime with:

```python
import fastapi_shield

print(fastapi_shield.__version__)
``` 