# API Reference

Welcome to the FastAPI Shield API reference documentation. This section provides detailed documentation for all public classes, functions, and modules in the FastAPI Shield library.

## Overview

FastAPI Shield provides a powerful decorator-based system for intercepting and validating requests before they reach your FastAPI endpoints. The API is designed to be simple to use while providing extensive customization options.

## Core Components

### Main Classes and Functions

- **[Shield](shield.md)** - The main decorator class for request interception
- **[ShieldDepends](shield-depends.md)** - Dependency injection wrapper for shield-aware dependencies  
- **[shield](shield-factory.md)** - Factory function for creating Shield instances
- **[ShieldedDepends](shielded-depends-factory.md)** - Factory function for creating ShieldDepends instances

### Utility Modules

- **[Utils](utils.md)** - Core utility functions for dependency resolution and request processing
- **[OpenAPI Integration](openapi.md)** - OpenAPI schema generation utilities
- **[Type Definitions](typing.md)** - Type definitions and type variables
- **[Constants](constants.md)** - Internal constants and configuration

## Quick Start

Here's a simple example of how the main API components work together:

```python
from fastapi import FastAPI, Request
from fastapi_shield import shield, ShieldedDepends

app = FastAPI()

@shield
def auth_shield(request: Request) -> dict | None:
    """Validate authentication and return user data."""
    token = request.headers.get("Authorization")
    if validate_token(token):
        return {"user_id": 123, "username": "john"}
    return None  # Block the request

def get_current_user(user_data: dict) -> dict:
    """Get current user from shield data."""
    return {"id": user_data["user_id"], "name": user_data["username"]}

@app.get("/profile")
@auth_shield
def get_profile(user: dict = ShieldedDepends(get_current_user)):
    return {"profile": user}
```

## Module Structure

The FastAPI Shield package is organized into the following modules:

```
fastapi_shield/
├── __init__.py          # Main package exports
├── shield.py           # Core Shield and ShieldDepends classes
├── utils.py            # Utility functions
├── openapi.py          # OpenAPI integration
├── typing.py           # Type definitions
└── consts.py           # Constants
```

## API Design Principles

1. **Simplicity** - Easy to use for common cases with sensible defaults
2. **Flexibility** - Extensive customization options for advanced use cases
3. **Type Safety** - Full type hint support for better IDE integration
4. **FastAPI Integration** - Seamless integration with FastAPI's dependency injection
5. **Performance** - Optimized for minimal overhead in request processing

## Next Steps

- Browse the individual API pages for detailed documentation
- Check out the [User Guide](../user-guide/basic-usage.md) for practical examples
- Review [Advanced Topics](../advanced-topics/dependency-injection.md) for in-depth usage patterns 