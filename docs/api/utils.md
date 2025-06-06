# Utils Module

The `utils` module provides core utility functions used throughout FastAPI Shield for dependency resolution, request processing, and signature manipulation.

## Overview

This module contains low-level utility functions that power the shield system's integration with FastAPI's dependency injection and request handling. While these functions are primarily for internal use, understanding them can be helpful for advanced use cases.

## Module Reference

::: fastapi_shield.utils
    options:
      members: true
      show_root_heading: false
      show_source: false
      heading_level: 3
      docstring_style: google
      docstring_options:
        ignore_init_summary: false
      filters:
        - "!^_"

## Function Categories

### Dependency Resolution

#### get_solved_dependencies

The core function for resolving FastAPI dependencies within the shield system.

**Usage Example:**
```python
from fastapi_shield.utils import get_solved_dependencies

async def my_shield(request: Request) -> dict | None:
    # Resolve dependencies manually if needed
    solved_deps, body = await get_solved_dependencies(
        request=request,
        path_format="/users/{user_id}",
        endpoint=my_endpoint_function,
        dependency_cache={}
    )
    
    if solved_deps.errors:
        return None  # Block request on dependency errors
    
    # Use resolved dependencies
    user_id = solved_deps.values.get("user_id")
    return {"resolved_user_id": user_id}
```

#### get_body_field_from_dependant

Extract body field configuration from FastAPI dependants for proper request parsing.

#### get_body_from_request

Parse request bodies with comprehensive error handling for various content types.

### Request Processing

#### get_path_format_from_request_for_endpoint

Extract path format information from FastAPI requests for use in dependency resolution.

**Usage Example:**
```python
from fastapi_shield.utils import get_path_format_from_request_for_endpoint

@shield
def path_aware_shield(request: Request) -> dict | None:
    path_format = get_path_format_from_request_for_endpoint(request)
    print(f"Endpoint path format: {path_format}")  # e.g., "/users/{user_id}"
    
    # Use path format for custom logic
    if "/admin/" in path_format:
        return validate_admin_access(request)
    return validate_regular_access(request)
```

#### generate_unique_id_for_fastapi_shield

Generate unique identifiers for shield-related operations, particularly useful for OpenAPI schema generation.

### Signature Manipulation

#### rearrange_params

Optimize parameter ordering according to Python's parameter rules for performance and compatibility.

**Technical Details:**
- Handles POSITIONAL_ONLY, POSITIONAL_OR_KEYWORD, VAR_POSITIONAL, KEYWORD_ONLY, and VAR_KEYWORD parameters
- Uses optimized alternating buffer algorithm for performance
- Properly handles required vs optional POSITIONAL_OR_KEYWORD parameters

#### merge_dedup_seq_params

Merge multiple parameter sequences while removing duplicates, essential for combining parameters from wrapped functions.

#### prepend_request_to_signature_params_of_function

Add Request parameter to function signatures for shield integration.

## Advanced Usage Examples

### Custom Dependency Resolution

```python
from fastapi_shield.utils import get_solved_dependencies, get_body_from_request
from fastapi.dependencies.utils import get_dependant

async def advanced_shield_with_custom_resolution(request: Request) -> dict | None:
    """Shield that manually resolves specific dependencies."""
    
    # Get dependant for a specific function
    dependant = get_dependant(path="/api/users", call=some_function)
    
    # Resolve dependencies manually
    solved_deps, body = await get_solved_dependencies(
        request=request,
        path_format="/api/users",
        endpoint=some_function,
        dependency_cache={}
    )
    
    # Check for validation errors
    if solved_deps.errors:
        logger.error(f"Dependency resolution failed: {solved_deps.errors}")
        return None
    
    # Access resolved values
    db_session = solved_deps.values.get("db")
    current_user = solved_deps.values.get("current_user")
    
    # Custom validation logic using resolved dependencies
    if db_session and current_user:
        user_permissions = check_permissions(db_session, current_user.id)
        if "admin" in user_permissions:
            return {"user": current_user, "permissions": user_permissions}
    
    return None
```

### Request Body Processing

```python
from fastapi_shield.utils import get_body_from_request, get_body_field_from_dependant
from fastapi.dependencies.utils import get_dependant

async def body_validation_shield(request: Request) -> dict | None:
    """Shield that validates request body before endpoint processing."""
    
    try:
        # For endpoints that expect a request body
        dependant = get_dependant(path="/api/data", call=endpoint_function)
        body_field, embed_fields = get_body_field_from_dependant(dependant, "/api/data")
        
        if body_field:
            # Parse and validate body
            body = await get_body_from_request(request, body_field)
            
            # Custom body validation
            if isinstance(body, dict):
                required_fields = ["user_id", "action"]
                if all(field in body for field in required_fields):
                    return {"validated_body": body}
        
        return None
        
    except Exception as e:
        logger.error(f"Body validation failed: {e}")
        return None
```

### Signature Analysis

```python
from fastapi_shield.utils import (
    merge_dedup_seq_params,
    rearrange_params,
    prepend_request_to_signature_params_of_function
)
from inspect import signature, Parameter

def analyze_endpoint_signature(endpoint_func):
    """Analyze and optimize endpoint function signatures."""
    
    # Get original parameters
    original_params = list(signature(endpoint_func).parameters.values())
    
    # Add Request parameter for shield compatibility
    shield_params = list(prepend_request_to_signature_params_of_function(endpoint_func))
    
    # Merge with additional parameters if needed
    additional_params = [
        Parameter("shield_data", Parameter.KEYWORD_ONLY, annotation=dict, default=None)
    ]
    
    merged_params = list(merge_dedup_seq_params(shield_params, additional_params))
    
    # Rearrange according to Python rules
    optimized_params = list(rearrange_params(iter(merged_params)))
    
    return {
        "original_count": len(original_params),
        "shield_count": len(shield_params),
        "merged_count": len(merged_params),
        "optimized_count": len(optimized_params),
        "parameter_names": [p.name for p in optimized_params]
    }

# Usage
result = analyze_endpoint_signature(my_endpoint)
print(f"Parameter analysis: {result}")
```

### Performance Monitoring

```python
from fastapi_shield.utils import get_solved_dependencies
import time
import asyncio

async def performance_monitoring_shield(request: Request) -> dict | None:
    """Shield that monitors dependency resolution performance."""
    
    start_time = time.time()
    
    try:
        solved_deps, body = await get_solved_dependencies(
            request=request,
            path_format=request.url.path,
            endpoint=request.scope.get("endpoint"),
            dependency_cache={}
        )
        
        resolution_time = time.time() - start_time
        
        # Log performance metrics
        logger.info(f"Dependency resolution took {resolution_time:.3f}s")
        
        if resolution_time > 0.1:  # Slow dependency resolution
            logger.warning(f"Slow dependency resolution: {resolution_time:.3f}s")
        
        if solved_deps.errors:
            return None
        
        return {
            "performance": {
                "dependency_resolution_time": resolution_time,
                "dependency_count": len(solved_deps.values)
            }
        }
        
    except Exception as e:
        logger.error(f"Performance monitoring failed: {e}")
        return None
```

## Integration with FastAPI Internals

### Custom Dependant Creation

```python
from fastapi.dependencies.utils import get_dependant
from fastapi_shield.utils import get_body_field_from_dependant

def create_custom_dependant(func, path: str):
    """Create a custom dependant with shield-specific configuration."""
    
    # Create base dependant
    dependant = get_dependant(path=path, call=func)
    
    # Get body field configuration
    body_field, embed_fields = get_body_field_from_dependant(dependant, path)
    
    # Custom modifications
    dependant.shield_enabled = True
    dependant.custom_body_field = body_field
    
    return dependant
```

### Error Handling Utilities

```python
from fastapi_shield.utils import get_body_from_request
from fastapi.exceptions import RequestValidationError

async def robust_request_parser(request: Request, body_field=None):
    """Robust request parsing with comprehensive error handling."""
    
    try:
        body = await get_body_from_request(request, body_field)
        return {"success": True, "body": body}
        
    except RequestValidationError as e:
        return {
            "success": False,
            "error": "validation_error",
            "details": e.errors()
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": "parsing_error",
            "message": str(e)
        }
```

## Performance Considerations

- **Caching**: Many utility functions benefit from caching resolved dependencies
- **Async Operations**: Use async versions when dealing with I/O operations
- **Parameter Optimization**: The `rearrange_params` function is highly optimized for performance
- **Memory Management**: Utility functions handle resource cleanup automatically

## Internal Architecture

The utils module serves as the bridge between FastAPI Shield and FastAPI's internal systems:

1. **Dependency Resolution**: Integrates with FastAPI's dependency injection system
2. **Request Processing**: Handles various content types and parsing scenarios
3. **Signature Management**: Optimizes function signatures for performance
4. **Error Handling**: Provides comprehensive error handling and validation

## See Also

- [Shield Class](shield.md) - Main shield implementation
- [ShieldDepends](shield-depends.md) - Dependency injection integration
- [OpenAPI Integration](openapi.md) - Schema generation utilities 