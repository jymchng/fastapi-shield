# FastAPI Shield - Middleware Bridge

The Middleware Bridge provides seamless integration between FastAPI Shield and middleware systems, enabling shields to be deployed as ASGI middleware, Starlette middleware, or custom middleware components for maximum deployment flexibility.

## Overview

The middleware bridge allows you to:

- **Convert shields to middleware** for application-wide protection
- **Integrate with ASGI applications** of any type
- **Work with Starlette middleware** ecosystem  
- **Optimize middleware chains** for performance
- **Maintain compatibility** with existing middleware
- **Configure deployment options** flexibly

## Quick Start

### Basic Shield to Middleware Conversion

```python
from fastapi import FastAPI, Request
from fastapi_shield import shield, shield_to_middleware, MiddlewareType

# Create a shield
@shield
async def auth_shield(request: Request):
    token = request.headers.get("authorization")
    if validate_token(token):
        return {"user_id": 123}
    return None

# Convert to Starlette middleware
app = FastAPI()
AuthMiddleware = shield_to_middleware(
    auth_shield, 
    middleware_type=MiddlewareType.STARLETTE,
    name="auth_middleware"
)

# Add to application
app.add_middleware(AuthMiddleware)

@app.get("/protected")
def protected_endpoint():
    return {"message": "Protected resource"}
```

### ASGI Middleware Integration

```python
from fastapi_shield import create_asgi_shield_middleware

# Create ASGI middleware factory
asgi_middleware_factory = create_asgi_shield_middleware(
    auth_shield,
    name="asgi_auth",
    timeout_seconds=10.0,
    enable_caching=True
)

# Wrap any ASGI application
app = FastAPI()
wrapped_app = asgi_middleware_factory(app)
```

## Middleware Types

### Starlette Middleware

Best for FastAPI applications and Starlette-based frameworks:

```python
from fastapi_shield import create_starlette_shield_middleware

# Create Starlette middleware class
AuthMiddleware = create_starlette_shield_middleware(
    auth_shield,
    name="starlette_auth",
    position=ShieldPosition.BEFORE_ROUTING,
    timeout_seconds=15.0
)

app = FastAPI()
app.add_middleware(AuthMiddleware)
```

### ASGI Middleware  

Universal compatibility with any ASGI application:

```python
from fastapi_shield import ASGIShieldMiddleware, MiddlewareConfig

# Create configuration
config = MiddlewareConfig(
    shield=auth_shield,
    name="universal_auth",
    timeout_seconds=20.0,
    enable_caching=True,
    cache_ttl_seconds=300
)

# Create ASGI middleware
def create_middleware(app):
    return ASGIShieldMiddleware(app, config)

# Apply to any ASGI app
app = FastAPI()  # or Starlette(), Django(), etc.
wrapped_app = create_middleware(app)
```

## Configuration Options

### Basic Configuration

```python
from fastapi_shield import MiddlewareConfig, ShieldPosition

config = MiddlewareConfig(
    shield=my_shield,
    name="my_middleware",
    position=ShieldPosition.BEFORE_ROUTING,
    enabled=True,
    timeout_seconds=30.0,
    auto_error=True
)
```

### Advanced Configuration

```python
config = MiddlewareConfig(
    shield=my_shield,
    name="advanced_middleware",
    
    # Positioning
    position=ShieldPosition.AFTER_AUTH,
    
    # Path filtering
    ignore_paths={"/health", "/metrics", "/__health"},
    include_paths={"/api", "/admin"},
    methods={"GET", "POST", "PUT"},
    
    # Performance settings
    timeout_seconds=10.0,
    max_body_size=5 * 1024 * 1024,  # 5MB
    enable_caching=True,
    cache_ttl_seconds=300,
    
    # Error handling
    auto_error=True,
    error_response_type="json",  # or "plain"
    pass_through_on_error=False,
    
    # Processing phases
    process_phases={
        ProcessingPhase.REQUEST_START,
        ProcessingPhase.AUTHENTICATION,
        ProcessingPhase.AUTHORIZATION
    },
    
    # Debug options
    enable_debug_headers=True,
    preserve_original_headers=True
)
```

### Custom Error Handling

```python
from fastapi import Request, Response
from starlette.responses import JSONResponse

def custom_error_handler(error: Exception, request: Request) -> Response:
    return JSONResponse(
        status_code=429 if "rate limit" in str(error).lower() else 403,
        content={
            "error": "Access denied",
            "path": request.url.path,
            "timestamp": datetime.utcnow().isoformat(),
            "request_id": request.headers.get("x-request-id")
        }
    )

config = MiddlewareConfig(
    shield=rate_limit_shield,
    custom_error_handler=custom_error_handler,
    error_response_type="json"
)
```

## Shield Positions

Control where your middleware executes in the request pipeline:

```python
from fastapi_shield import ShieldPosition

# Execute before routing decisions
ShieldPosition.FIRST
ShieldPosition.BEFORE_ROUTING

# Execute after routing but before auth  
ShieldPosition.AFTER_ROUTING
ShieldPosition.BEFORE_AUTH

# Execute after authentication
ShieldPosition.AFTER_AUTH

# Execute last in the chain
ShieldPosition.LAST

# Custom positioning
ShieldPosition.CUSTOM
```

## Processing Phases

Fine-tune when your shield executes during request processing:

```python
from fastapi_shield import ProcessingPhase

phases = {
    ProcessingPhase.REQUEST_START,      # Very beginning
    ProcessingPhase.REQUEST_HEADERS,    # After headers parsed
    ProcessingPhase.REQUEST_BODY,       # After body available
    ProcessingPhase.ROUTING,            # During route matching
    ProcessingPhase.AUTHENTICATION,    # During auth processing
    ProcessingPhase.AUTHORIZATION,     # During authz processing
    ProcessingPhase.ENDPOINT_EXECUTION, # Before endpoint
    ProcessingPhase.RESPONSE_HEADERS,   # Before response headers
    ProcessingPhase.RESPONSE_BODY,      # Before response body
    ProcessingPhase.RESPONSE_END        # After response complete
}

config = MiddlewareConfig(
    shield=my_shield,
    process_phases=phases
)
```

## Middleware Chains

### Creating Middleware Chains

```python
from fastapi_shield import create_middleware_chain

# Create multiple shields
auth_shield = shield(auth_function)
rate_limit_shield = shield(rate_limit_function) 
cors_shield = shield(cors_function)

# Create middleware chain
middleware_chain = create_middleware_chain(
    auth_shield,
    rate_limit_shield,
    cors_shield,
    middleware_type=MiddlewareType.STARLETTE,
    timeout_seconds=15.0,
    enable_caching=True
)

# Add to application (order matters - first shield runs first)
app = FastAPI()
for middleware_class in reversed(middleware_chain):  # Reverse for correct order
    app.add_middleware(middleware_class)
```

### Chain Optimization

```python
from fastapi_shield import MiddlewareChainOptimizer

# Create optimizer
optimizer = MiddlewareChainOptimizer()

# Add middleware to optimization chain
for middleware in middleware_instances:
    optimizer.add_middleware(middleware)

# Process requests through optimized chain
async def process_request(request: Request):
    blocking_response = await optimizer.process_request_chain(request)
    if blocking_response:
        return blocking_response
    
    # Continue with normal processing
    return await call_next(request)

# Get optimization metrics
metrics = optimizer.get_chain_metrics()
print(f"Total middleware: {metrics['total_middleware']}")
print(f"Avg processing time: {metrics['avg_processing_time_ms']:.2f}ms")
```

## Integration Helpers

### FastAPI Integration

```python
from fastapi_shield import MiddlewareIntegrator

app = FastAPI()
shields = [auth_shield, rate_limit_shield, cors_shield]

# Automatic integration
MiddlewareIntegrator.integrate_with_fastapi(
    app, 
    shields,
    timeout_seconds=20.0,
    enable_caching=True,
    cache_ttl_seconds=300
)
```

### Starlette Integration

```python
from starlette.applications import Starlette

app = Starlette()
shields = [security_shield, validation_shield]

MiddlewareIntegrator.integrate_with_starlette(
    app,
    shields, 
    position=ShieldPosition.BEFORE_ROUTING,
    enable_debug_headers=True
)
```

### Universal ASGI Integration

```python
# Works with any ASGI application
app = your_asgi_app  # Django, FastAPI, Starlette, etc.

wrapped_app = MiddlewareIntegrator.integrate_with_asgi_app(
    app,
    shields=[auth_shield, rate_shield],
    timeout_seconds=10.0,
    max_body_size=1024 * 1024  # 1MB
)
```

## Performance Features

### Caching

```python
from fastapi_shield import ShieldMiddlewareCache

# Built-in caching
config = MiddlewareConfig(
    shield=my_shield,
    enable_caching=True,
    cache_ttl_seconds=300  # 5 minutes
)

# Manual cache management
cache = ShieldMiddlewareCache(max_size=10000, ttl_seconds=300)
cache.set("cache_key", shield_result)
cached_result = cache.get("cache_key")
```

### Request Filtering

```python
# Path-based filtering
config = MiddlewareConfig(
    shield=api_shield,
    include_paths={"/api", "/graphql"},      # Only these paths
    ignore_paths={"/health", "/metrics"},    # Skip these paths
    methods={"GET", "POST", "PUT"}           # Only these methods
)

# Advanced filtering function
def should_process_request(request: Request) -> bool:
    # Custom logic for request filtering
    if request.url.path.startswith("/static"):
        return False
    if request.headers.get("x-skip-shield") == "true":
        return False
    return True

# Use in custom middleware implementation
class CustomShieldMiddleware(ASGIShieldMiddleware):
    def should_process_request(self, request: Request) -> bool:
        return should_process_request(request)
```

## Monitoring and Metrics

### Built-in Metrics

```python
# Get middleware metrics
middleware = ASGIShieldMiddleware(app, config)

# After processing some requests
metrics = middleware.metrics

print(f"Total requests: {metrics.total_requests}")
print(f"Blocked requests: {metrics.blocked_requests}")
print(f"Allowed requests: {metrics.allowed_requests}")
print(f"Error count: {metrics.error_count}")
print(f"Avg processing time: {metrics.avg_processing_time_ms:.2f}ms")
print(f"Max processing time: {metrics.max_processing_time_ms:.2f}ms")

# Phase-specific metrics
for phase, data in metrics.phase_metrics.items():
    print(f"{phase.value}: {data['count']} calls, {data['total_time']:.2f}ms total")
```

### Chain Metrics

```python
# Optimizer provides chain-wide metrics
optimizer = MiddlewareChainOptimizer()
# ... add middleware to chain ...

chain_metrics = optimizer.get_chain_metrics()
print(f"Total middleware in chain: {chain_metrics['total_middleware']}")
print(f"Total requests processed: {chain_metrics['total_requests']}")
print(f"Overall avg processing time: {chain_metrics['avg_processing_time_ms']:.2f}ms")

# Per-middleware breakdown
for name, middleware_metrics in chain_metrics['middleware_metrics'].items():
    print(f"{name}: {middleware_metrics['requests']} requests, "
          f"{middleware_metrics['avg_time_ms']:.2f}ms avg")
```

## Migration from Shield Decorators

### Before: Shield Decorators

```python
from fastapi import FastAPI
from fastapi_shield import shield

app = FastAPI()

@shield
async def auth_shield(request: Request):
    # Auth logic
    return user_data_or_none

@app.get("/api/data")
@auth_shield  # Applied per endpoint
def get_data():
    return {"data": "value"}

@app.post("/api/data")  
@auth_shield  # Must apply to each endpoint
def create_data():
    return {"created": True}
```

### After: Middleware Bridge

```python
from fastapi import FastAPI
from fastapi_shield import shield_to_middleware, MiddlewareType

app = FastAPI()

@shield
async def auth_shield(request: Request):
    # Same auth logic - no changes needed
    return user_data_or_none

# Convert to middleware - now applies to ALL requests
AuthMiddleware = shield_to_middleware(
    auth_shield,
    middleware_type=MiddlewareType.STARLETTE,
    include_paths={"/api"}  # Optional: only API routes
)

app.add_middleware(AuthMiddleware)

# No decorators needed - middleware protects all endpoints
@app.get("/api/data")
def get_data():
    return {"data": "value"}

@app.post("/api/data")
def create_data():
    return {"created": True}
```

### Migration Benefits

1. **Reduced Code Duplication**: Apply once instead of to every endpoint
2. **Better Performance**: Middleware executes earlier in the pipeline
3. **Consistent Protection**: No risk of forgetting to apply shield decorators
4. **Framework Flexibility**: Works with any ASGI application
5. **Advanced Features**: Caching, path filtering, chain optimization

## Advanced Use Cases

### Multi-Tenant Applications

```python
@shield
async def tenant_shield(request: Request):
    tenant_id = request.headers.get("x-tenant-id")
    if not tenant_id:
        return None
    
    # Validate tenant and set context
    tenant = await get_tenant(tenant_id)
    if not tenant or not tenant.active:
        return None
    
    return {"tenant": tenant, "tenant_id": tenant_id}

# Apply as middleware with tenant-specific configuration
config = MiddlewareConfig(
    shield=tenant_shield,
    name="tenant_middleware",
    enable_caching=True,
    cache_ttl_seconds=600,  # Cache tenant lookups for 10 minutes
    include_paths={"/api", "/app"}  # Only protect application routes
)
```

### API Gateway Pattern

```python
# Rate limiting shield
@shield  
async def rate_limit_shield(request: Request):
    client_ip = request.client.host
    return await check_rate_limit(client_ip)

# Authentication shield
@shield
async def auth_shield(request: Request):
    return await validate_jwt_token(request.headers.get("authorization"))

# Authorization shield  
@shield
async def authz_shield(request: Request):
    user = request.state.user  # Set by previous shield
    return await check_permissions(user, request.url.path, request.method)

# Create API gateway middleware chain
gateway_chain = create_middleware_chain(
    rate_limit_shield,  # First: check rate limits
    auth_shield,        # Second: authenticate user
    authz_shield,       # Third: authorize action
    middleware_type=MiddlewareType.ASGI,
    timeout_seconds=5.0
)

# Apply to API gateway application
api_gateway = FastAPI()
wrapped_gateway = gateway_chain[0](
    gateway_chain[1](
        gateway_chain[2](api_gateway)
    )
)
```

### Microservices Integration

```python
# Service mesh authentication
@shield
async def service_mesh_auth(request: Request):
    # Validate service-to-service authentication
    service_token = request.headers.get("x-service-token") 
    calling_service = request.headers.get("x-calling-service")
    
    if not await validate_service_token(service_token, calling_service):
        return None
    
    return {"calling_service": calling_service, "authenticated": True}

# Circuit breaker shield
@shield  
async def circuit_breaker_shield(request: Request):
    service_name = request.url.path.split("/")[2]  # Extract service from path
    
    if await circuit_breaker.is_open(service_name):
        raise HTTPException(status_code=503, detail=f"Service {service_name} unavailable")
    
    return {"service_name": service_name}

# Configure for microservice
microservice_config = MiddlewareConfig(
    shield=service_mesh_auth,
    name="microservice_auth",
    timeout_seconds=2.0,  # Fast timeout for service calls
    enable_caching=False,  # Don't cache service auth
    ignore_paths={"/health", "/metrics", "/ready"}
)
```

## Best Practices

### 1. Choose the Right Middleware Type

```python
# Use ASGI for maximum compatibility
asgi_middleware = create_asgi_shield_middleware(
    universal_shield,
    name="universal_protection"
)

# Use Starlette for FastAPI/Starlette apps with better integration
starlette_middleware = create_starlette_shield_middleware(
    fastapi_specific_shield,
    enable_debug_headers=True
)
```

### 2. Optimize Performance

```python
# Enable caching for expensive shields
config = MiddlewareConfig(
    shield=expensive_shield,
    enable_caching=True,
    cache_ttl_seconds=300,
    timeout_seconds=5.0
)

# Use path filtering to reduce unnecessary processing
config = MiddlewareConfig(
    shield=api_only_shield,
    include_paths={"/api"},
    ignore_paths={"/static", "/health", "/metrics"}
)
```

### 3. Handle Errors Gracefully

```python
config = MiddlewareConfig(
    shield=my_shield,
    auto_error=True,
    pass_through_on_error=False,  # Block on errors for security
    custom_error_handler=create_custom_error_response,
    error_response_type="json"
)
```

### 4. Monitor Performance

```python
# Regularly check middleware metrics
async def metrics_endpoint():
    metrics = {
        middleware.config.name: {
            "total_requests": middleware.metrics.total_requests,
            "blocked_requests": middleware.metrics.blocked_requests,
            "avg_processing_time": middleware.metrics.avg_processing_time_ms,
            "error_rate": middleware.metrics.error_count / max(middleware.metrics.total_requests, 1)
        }
        for middleware in middleware_instances
    }
    return metrics
```

### 5. Test Thoroughly

```python
# Test middleware with various request types
import pytest
from fastapi.testclient import TestClient

def test_middleware_allows_valid_requests():
    client = TestClient(app)
    response = client.get("/api/data", headers={"authorization": "Bearer valid-token"})
    assert response.status_code == 200

def test_middleware_blocks_invalid_requests():
    client = TestClient(app)
    response = client.get("/api/data", headers={"authorization": "Bearer invalid-token"})
    assert response.status_code == 403

def test_middleware_ignores_health_checks():
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200  # Should pass through without shield check
```

## Troubleshooting

### Common Issues

#### Middleware Not Executing
```python
# Check if middleware is properly registered
app = FastAPI()
app.add_middleware(YourShieldMiddleware)

# Verify middleware configuration
config = MiddlewareConfig(
    shield=your_shield,
    enabled=True,  # Make sure it's enabled
    include_paths=None,  # None means all paths
    ignore_paths=set()   # Empty set means no ignored paths
)
```

#### Shield Timeouts
```python
# Increase timeout for slow shields
config = MiddlewareConfig(
    shield=slow_shield,
    timeout_seconds=30.0  # Increase from default 30s
)

# Or optimize the shield function
@shield
async def optimized_shield(request: Request):
    # Use async operations
    result = await async_database_query()
    return result
```

#### Memory Issues with Caching
```python
# Limit cache size and TTL
config = MiddlewareConfig(
    shield=cached_shield,
    enable_caching=True,
    cache_ttl_seconds=300,  # 5 minutes
)

# Clear cache periodically
middleware.cache.clear()  # Manual clearing
```

#### Request Body Issues
```python
# Handle large request bodies
config = MiddlewareConfig(
    shield=body_processing_shield,
    max_body_size=10 * 1024 * 1024,  # 10MB
    timeout_seconds=60.0  # Longer timeout for large bodies
)
```

The middleware bridge provides powerful, flexible integration options while maintaining the simplicity and security of FastAPI Shield decorators. Choose the approach that best fits your application architecture and deployment requirements.