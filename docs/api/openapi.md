# OpenAPI Integration

The `openapi` module provides utilities for integrating FastAPI Shield with OpenAPI schema generation, ensuring that shielded endpoints are properly documented in API schemas.

## Overview

When shields are applied to FastAPI endpoints, they modify the function signatures which can interfere with automatic OpenAPI schema generation. This module provides tools to generate accurate schemas that reflect the original endpoint parameters rather than the shield wrapper parameters.

## Module Reference

::: fastapi_shield.openapi
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

## Key Concepts

### The Challenge

Shields wrap endpoint functions, which changes their signatures:

```python
# Original endpoint
def get_user(user_id: int, db: Session = Depends(get_db)) -> User:
    return db.query(User).filter(User.id == user_id).first()

# After applying shield
@auth_shield  # Modifies the signature
def get_user(user_id: int, db: Session = Depends(get_db)) -> User:
    # Same implementation, but signature is now wrapped
```

The OpenAPI schema should reflect the original signature, not the wrapper.

### The Solution

The openapi module provides utilities to:
1. Temporarily restore original signatures during schema generation
2. Collect parameters from the entire decorator chain
3. Generate accurate OpenAPI schemas for shielded endpoints

## Usage Examples

### Basic OpenAPI Integration

```python
from fastapi import FastAPI
from fastapi_shield.openapi import patch_get_openapi

app = FastAPI()

# Apply shields to endpoints
@shield
def auth_shield(request: Request) -> dict | None:
    # Authentication logic
    pass

@app.get("/users/{user_id}")
@auth_shield
def get_user(user_id: int, name: str = Query(None)) -> dict:
    return {"user_id": user_id, "name": name}

# Patch OpenAPI generation
app.openapi = patch_get_openapi(app)

# Now app.openapi() will generate correct schema for shielded endpoints
```

### Manual Schema Generation

```python
from fastapi_shield.openapi import switch_routes
from fastapi.openapi.utils import get_openapi

app = FastAPI()

# Add shielded endpoints...

def generate_custom_openapi():
    """Generate OpenAPI schema with custom configuration."""
    with switch_routes(app) as routes:
        return get_openapi(
            title="My API",
            version="1.0.0",
            description="API with FastAPI Shield integration",
            routes=routes,
            tags=[
                {"name": "users", "description": "User operations"},
                {"name": "auth", "description": "Authentication"}
            ]
        )

# Use custom schema generator
app.openapi_schema = generate_custom_openapi()
```

### Endpoint-Level Schema Patching

```python
from fastapi_shield.openapi import patch_shields_for_openapi

@patch_shields_for_openapi
@shield
def auth_shield(request: Request) -> dict | None:
    # This shield will generate correct OpenAPI schema
    pass

@app.get("/protected")
@auth_shield
def protected_endpoint(data: str = Query(...)) -> dict:
    return {"data": data}

# The endpoint will have correct schema automatically
```

### Conditional Schema Patching

```python
import os
from fastapi_shield.openapi import patch_shields_for_openapi

# Only patch in development for debugging
DEBUG_MODE = os.getenv("DEBUG", "false").lower() == "true"

@patch_shields_for_openapi(activated_when=DEBUG_MODE)
@shield
def debug_shield(request: Request) -> dict | None:
    # Schema patching only active in debug mode
    pass
```

## Advanced Integration Patterns

### Custom OpenAPI Schema with Shield Metadata

```python
from fastapi_shield.openapi import switch_routes, gather_signature_params_across_wrapped_endpoints
from fastapi.openapi.utils import get_openapi

def generate_shield_aware_openapi(app: FastAPI):
    """Generate OpenAPI schema with shield information."""
    
    with switch_routes(app) as routes:
        # Generate base schema
        openapi_schema = get_openapi(
            title=app.title,
            version=app.version,
            routes=routes
        )
        
        # Add shield metadata to schema
        for route in app.routes:
            if hasattr(route, 'endpoint') and hasattr(route.endpoint, '__shielded__'):
                endpoint_path = route.path
                method = list(route.methods)[0].lower()
                
                # Add shield information to endpoint documentation
                if endpoint_path in openapi_schema.get("paths", {}):
                    endpoint_schema = openapi_schema["paths"][endpoint_path][method]
                    endpoint_schema["x-shield-protected"] = True
                    endpoint_schema["x-shield-info"] = {
                        "description": "This endpoint is protected by FastAPI Shield",
                        "authentication_required": True
                    }
        
        return openapi_schema

app.openapi = lambda: generate_shield_aware_openapi(app)
```

### Multi-Environment Schema Generation

```python
from fastapi_shield.openapi import patch_shields_for_openapi

def create_environment_openapi(app: FastAPI, environment: str):
    """Create environment-specific OpenAPI schemas."""
    
    if environment == "production":
        # In production, hide internal endpoints
        filtered_routes = [
            route for route in app.routes 
            if not getattr(route, 'internal_only', False)
        ]
        
        with switch_routes(app) as routes:
            return get_openapi(
                title=f"{app.title} (Production)",
                version=app.version,
                routes=filtered_routes,
                description="Production API - Internal endpoints hidden"
            )
    
    else:
        # In development, show all endpoints with detailed shield info
        with switch_routes(app) as routes:
            schema = get_openapi(
                title=f"{app.title} (Development)",
                version=f"{app.version}-dev",
                routes=routes,
                description="Development API - All endpoints visible"
            )
            
            # Add development-specific information
            schema["info"]["x-development-mode"] = True
            return schema

# Usage
env = os.getenv("ENVIRONMENT", "development")
app.openapi = lambda: create_environment_openapi(app, env)
```

### Real-Time Schema Updates

```python
from fastapi_shield.openapi import switch_routes
import threading
import time

class DynamicOpenAPIGenerator:
    """Generate OpenAPI schemas that update dynamically."""
    
    def __init__(self, app: FastAPI):
        self.app = app
        self._schema_cache = None
        self._last_update = 0
        self._cache_ttl = 60  # Cache for 60 seconds
    
    def get_schema(self):
        """Get schema with automatic cache invalidation."""
        current_time = time.time()
        
        if (self._schema_cache is None or 
            current_time - self._last_update > self._cache_ttl):
            
            self._schema_cache = self._generate_fresh_schema()
            self._last_update = current_time
        
        return self._schema_cache
    
    def _generate_fresh_schema(self):
        """Generate a fresh OpenAPI schema."""
        with switch_routes(self.app) as routes:
            return get_openapi(
                title=self.app.title,
                version=self.app.version,
                routes=routes,
                description=f"Generated at {time.strftime('%Y-%m-%d %H:%M:%S')}"
            )
    
    def invalidate_cache(self):
        """Force schema regeneration on next request."""
        self._schema_cache = None

# Usage
dynamic_generator = DynamicOpenAPIGenerator(app)
app.openapi = dynamic_generator.get_schema

# Invalidate cache when shields change
def update_shield_configuration():
    # ... update shield logic ...
    dynamic_generator.invalidate_cache()
```

## Parameter Collection and Analysis

### Analyzing Shield Signatures

```python
from fastapi_shield.openapi import gather_signature_params_across_wrapped_endpoints
from inspect import signature

def analyze_shield_parameters(endpoint_func):
    """Analyze parameters across the entire shield chain."""
    
    # Collect all parameters from wrapped functions
    all_params = list(gather_signature_params_across_wrapped_endpoints(endpoint_func))
    
    analysis = {
        "total_parameters": len(all_params),
        "parameter_types": {},
        "duplicate_names": [],
        "shield_layers": 0
    }
    
    # Analyze parameter types
    seen_names = set()
    for param in all_params:
        param_kind = param.kind.name
        analysis["parameter_types"][param_kind] = analysis["parameter_types"].get(param_kind, 0) + 1
        
        if param.name in seen_names:
            analysis["duplicate_names"].append(param.name)
        seen_names.add(param.name)
    
    # Count shield layers
    current_func = endpoint_func
    while hasattr(current_func, '__wrapped__'):
        analysis["shield_layers"] += 1
        current_func = current_func.__wrapped__
    
    return analysis

# Usage
@shield
def auth_shield(request: Request) -> dict | None:
    pass

@shield  
def rate_limit_shield(request: Request) -> dict | None:
    pass

@app.get("/complex")
@auth_shield
@rate_limit_shield
def complex_endpoint(user_id: int, data: str = Query(...)) -> dict:
    return {"user_id": user_id, "data": data}

analysis = analyze_shield_parameters(complex_endpoint)
print(f"Shield analysis: {analysis}")
```

### Custom Parameter Processing

```python
from fastapi_shield.openapi import gather_signature_params_across_wrapped_endpoints
from fastapi_shield.utils import merge_dedup_seq_params, rearrange_params
from inspect import Parameter, Signature

def create_optimized_signature(endpoint_func, additional_params=None):
    """Create an optimized signature for OpenAPI generation."""
    
    # Gather all parameters
    base_params = gather_signature_params_across_wrapped_endpoints(endpoint_func)
    
    # Add custom parameters if provided
    if additional_params:
        all_params = merge_dedup_seq_params(base_params, additional_params)
    else:
        all_params = base_params
    
    # Optimize parameter order
    optimized_params = rearrange_params(all_params)
    
    # Create new signature
    return Signature(optimized_params)

# Usage
custom_params = [
    Parameter("api_version", Parameter.QUERY, annotation=str, default="v1"),
    Parameter("format", Parameter.QUERY, annotation=str, default="json")
]

optimized_sig = create_optimized_signature(my_endpoint, custom_params)
my_endpoint.__signature__ = optimized_sig
```

## Testing OpenAPI Integration

### Schema Validation Tests

```python
import pytest
from fastapi.testclient import TestClient
from fastapi_shield.openapi import patch_get_openapi

def test_shielded_endpoint_schema():
    """Test that shielded endpoints generate correct OpenAPI schema."""
    
    app = FastAPI()
    
    @shield
    def test_shield(request: Request) -> dict | None:
        return {"test": True}
    
    @app.get("/test/{item_id}")
    @test_shield
    def test_endpoint(item_id: int, query_param: str = Query(None)) -> dict:
        return {"item_id": item_id, "query_param": query_param}
    
    # Patch OpenAPI generation
    app.openapi = patch_get_openapi(app)
    
    # Get schema
    schema = app.openapi()
    
    # Validate endpoint is present
    assert "/test/{item_id}" in schema["paths"]
    
    # Validate parameters are correct
    endpoint_schema = schema["paths"]["/test/{item_id}"]["get"]
    parameters = endpoint_schema.get("parameters", [])
    
    # Should have path parameter
    path_params = [p for p in parameters if p["in"] == "path"]
    assert len(path_params) == 1
    assert path_params[0]["name"] == "item_id"
    
    # Should have query parameter  
    query_params = [p for p in parameters if p["in"] == "query"]
    assert len(query_params) == 1
    assert query_params[0]["name"] == "query_param"

def test_multiple_shields_schema():
    """Test schema generation with multiple shields."""
    
    app = FastAPI()
    
    @shield
    def auth_shield(request: Request) -> dict | None:
        return {"user": "test"}
    
    @shield
    def perm_shield(request: Request) -> dict | None:
        return {"permissions": ["read"]}
    
    @app.post("/protected")
    @auth_shield
    @perm_shield
    def protected_endpoint(data: dict) -> dict:
        return {"result": "success"}
    
    app.openapi = patch_get_openapi(app)
    schema = app.openapi()
    
    # Should have the endpoint
    assert "/protected" in schema["paths"]
    assert "post" in schema["paths"]["/protected"]
```

## Best Practices

1. **Always Use Patching**: Use `patch_get_openapi()` for automatic schema correction
2. **Test Schema Generation**: Validate that schemas reflect actual endpoint signatures
3. **Document Shield Behavior**: Add custom metadata to document shield requirements
4. **Environment-Specific Schemas**: Generate different schemas for different environments
5. **Performance Considerations**: Cache schemas when possible, especially with many shields

## Troubleshooting

### Common Issues

1. **Missing Parameters**: If parameters don't appear in schema, ensure the endpoint function has proper type hints
2. **Duplicate Parameters**: Use `merge_dedup_seq_params()` to handle parameter conflicts
3. **Performance Issues**: Cache OpenAPI schemas to avoid regenerating on every request
4. **Complex Signatures**: Use `gather_signature_params_across_wrapped_endpoints()` for deep analysis

### Debug Helpers

```python
def debug_endpoint_schema(app: FastAPI, path: str, method: str = "get"):
    """Debug helper for examining endpoint schemas."""
    
    schema = app.openapi()
    endpoint_schema = schema.get("paths", {}).get(path, {}).get(method.lower())
    
    if not endpoint_schema:
        print(f"No schema found for {method.upper()} {path}")
        return
    
    print(f"Schema for {method.upper()} {path}:")
    print(f"Parameters: {len(endpoint_schema.get('parameters', []))}")
    
    for param in endpoint_schema.get("parameters", []):
        print(f"  - {param['name']} ({param['in']}): {param.get('schema', {}).get('type', 'unknown')}")

# Usage
debug_endpoint_schema(app, "/users/{user_id}")
```

## See Also

- [Shield Class](shield.md) - Main shield implementation
- [Utils](utils.md) - Utility functions for signature manipulation
- [FastAPI OpenAPI Documentation](https://fastapi.tiangolo.com/advanced/extending-openapi/) - Official FastAPI OpenAPI guide 