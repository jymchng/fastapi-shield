# Constants

The `consts` module defines key constants used internally by FastAPI Shield to mark and identify shielded endpoints.

## Overview

These constants are used internally by the FastAPI Shield system to:
- Mark callables as shielded endpoints
- Store references to original endpoint functions
- Cache path format information for performance

**Important:** These constants are for internal use only and should not be modified by end users.

## Module Reference

::: fastapi_shield.consts
    options:
      members: true
      show_root_heading: false
      show_source: false
      heading_level: 3
      docstring_style: google
      docstring_options:
        ignore_init_summary: false

## Constants Reference

### IS_SHIELDED_ENDPOINT_KEY

**Value:** `"__shielded__"`

This attribute is set to `True` on callables that have been wrapped by Shield decorators. It's used internally to distinguish between regular FastAPI endpoints and shielded ones.

**Usage Example:**
```python
from fastapi_shield.consts import IS_SHIELDED_ENDPOINT_KEY
from fastapi_shield import shield

@shield
def my_shield(request: Request) -> dict | None:
    return {"user": "test"}

@app.get("/test")
@my_shield
def test_endpoint():
    return {"message": "Hello"}

# Check if endpoint is shielded
is_shielded = hasattr(test_endpoint, IS_SHIELDED_ENDPOINT_KEY)
print(f"Endpoint is shielded: {is_shielded}")  # True
```

### SHIELDED_ENDPOINT_KEY

**Value:** `"__shielded_endpoint__"`

This attribute stores a reference to the original, unshielded endpoint function. This allows the system to access the original function even after multiple shields have been applied in a decorator chain.

**Usage Example:**
```python
from fastapi_shield.consts import SHIELDED_ENDPOINT_KEY

def original_function():
    return {"original": True}

@shield
def my_shield(request: Request) -> dict | None:
    return {"validated": True}

# Apply shield
wrapped_function = my_shield(original_function)

# Access original function if needed
if hasattr(wrapped_function, SHIELDED_ENDPOINT_KEY):
    original = getattr(wrapped_function, SHIELDED_ENDPOINT_KEY)
    print(f"Original function: {original.__name__}")
```

### SHIELDED_ENDPOINT_PATH_FORMAT_KEY

**Value:** `"__shielded_endpoint_path_format__"`

This attribute stores the raw path format string (e.g., `/users/{user_id}`) for shielded endpoints. The path format is used internally for dependency resolution and OpenAPI schema generation.

**Usage Example:**
```python
from fastapi_shield.consts import SHIELDED_ENDPOINT_PATH_FORMAT_KEY

@app.get("/users/{user_id}")
@my_shield
def get_user(user_id: int):
    return {"user_id": user_id}

# The path format is automatically cached
path_format = getattr(get_user, SHIELDED_ENDPOINT_PATH_FORMAT_KEY, None)
print(f"Path format: {path_format}")  # "/users/{user_id}"
```

## Internal Usage Patterns

### Detecting Shielded Endpoints

The FastAPI Shield system uses these constants to identify and handle shielded endpoints:

```python
from fastapi_shield.consts import IS_SHIELDED_ENDPOINT_KEY

def is_endpoint_shielded(endpoint_func) -> bool:
    """Check if an endpoint function has been shielded."""
    return getattr(endpoint_func, IS_SHIELDED_ENDPOINT_KEY, False)

def get_shield_count(endpoint_func) -> int:
    """Count the number of shields applied to an endpoint."""
    count = 0
    current_func = endpoint_func
    
    while hasattr(current_func, '__wrapped__'):
        if hasattr(current_func, IS_SHIELDED_ENDPOINT_KEY):
            count += 1
        current_func = current_func.__wrapped__
    
    return count

# Usage
@shield
def auth_shield(request: Request) -> dict | None:
    return {"auth": True}

@shield
def rate_limit_shield(request: Request) -> dict | None:
    return {"rate_limit": True}

@auth_shield
@rate_limit_shield
def multi_shielded_endpoint():
    return {"message": "Protected"}

print(f"Is shielded: {is_endpoint_shielded(multi_shielded_endpoint)}")  # True
print(f"Shield count: {get_shield_count(multi_shielded_endpoint)}")    # 2
```

### OpenAPI Integration

The constants are used by the OpenAPI integration to generate correct schemas:

```python
from fastapi_shield.consts import IS_SHIELDED_ENDPOINT_KEY, SHIELDED_ENDPOINT_PATH_FORMAT_KEY

def analyze_endpoint_for_openapi(endpoint_func, route_path: str):
    """Analyze endpoint for OpenAPI schema generation."""
    
    analysis = {
        "is_shielded": getattr(endpoint_func, IS_SHIELDED_ENDPOINT_KEY, False),
        "path_format": getattr(endpoint_func, SHIELDED_ENDPOINT_PATH_FORMAT_KEY, route_path),
        "requires_special_handling": False
    }
    
    if analysis["is_shielded"]:
        analysis["requires_special_handling"] = True
        analysis["original_signature_needed"] = True
    
    return analysis
```

### Debugging and Introspection

These constants can be useful for debugging shield behavior:

```python
from fastapi_shield.consts import *

def debug_endpoint_shields(endpoint_func):
    """Debug information about an endpoint's shields."""
    
    print(f"Function: {endpoint_func.__name__}")
    print(f"Is shielded: {hasattr(endpoint_func, IS_SHIELDED_ENDPOINT_KEY)}")
    
    if hasattr(endpoint_func, SHIELDED_ENDPOINT_KEY):
        original = getattr(endpoint_func, SHIELDED_ENDPOINT_KEY)
        print(f"Original function: {original.__name__}")
    
    if hasattr(endpoint_func, SHIELDED_ENDPOINT_PATH_FORMAT_KEY):
        path_format = getattr(endpoint_func, SHIELDED_ENDPOINT_PATH_FORMAT_KEY)
        print(f"Path format: {path_format}")
    
    # Walk the wrapper chain
    current = endpoint_func
    wrapper_depth = 0
    while hasattr(current, '__wrapped__'):
        wrapper_depth += 1
        current = current.__wrapped__
        print(f"  Wrapper level {wrapper_depth}: {current.__name__}")

# Usage
debug_endpoint_shields(my_shielded_endpoint)
```

## Security Considerations

### Attribute Safety

These constants are designed with security in mind:

1. **Read-only nature**: The constants themselves cannot be modified
2. **Namespace isolation**: Using double underscores prevents accidental conflicts
3. **Internal use only**: These are implementation details, not public API

### Validation Patterns

```python
def validate_shield_attributes(endpoint_func):
    """Validate that shield attributes are properly set."""
    
    if not hasattr(endpoint_func, IS_SHIELDED_ENDPOINT_KEY):
        return False, "Missing shield marker"
    
    if not getattr(endpoint_func, IS_SHIELDED_ENDPOINT_KEY):
        return False, "Shield marker is False"
    
    # Additional validation...
    return True, "Valid shield attributes"
```

## Best Practices

### For Library Users

1. **Don't modify these constants** - They are internal implementation details
2. **Use the provided APIs** - Use the shield decorators and functions instead of manipulating attributes directly
3. **Debugging only** - These constants are useful for debugging but shouldn't be used in production logic

### For Contributors

1. **Consistent naming** - Follow the established pattern for any new constants
2. **Documentation** - Always document the purpose and usage of new constants
3. **Backward compatibility** - Changes to these constants can break existing code

## See Also

- [Shield Class](shield.md) - How these constants are used in the main implementation
- [OpenAPI Integration](openapi.md) - How constants are used for schema generation
- [Utils](utils.md) - Utility functions that work with these constants 