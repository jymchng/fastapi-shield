# Interceptors API Reference

This document covers the interceptor system in FastAPI Shield, which allows for method interception and aspect-oriented programming.

## `Interceptor` Base Class

The `Interceptor` class is the base class for all interceptors in FastAPI Shield.

### Signature

```python
class Interceptor:
    """Base class for all interceptors."""
    
    async def before(self, *args, **kwargs) -> Dict[str, Any]:
        """Run before the target method."""
        return {}
    
    async def after(self, result: Any, *args, **kwargs) -> Any:
        """Run after the target method and potentially modify the result."""
        return result
    
    async def on_error(self, exception: Exception, *args, **kwargs) -> Any:
        """Handle exceptions raised by the target method."""
        raise exception
```

### Methods

#### `before(*args, **kwargs) -> Dict[str, Any]`

Run before the target method is called.

- **Parameters**:
  - `*args`: The arguments passed to the target method
  - `**kwargs`: The keyword arguments passed to the target method
- **Returns**: A dictionary of modifications to apply to `kwargs` before calling the target method
- **Note**: This method is called asynchronously, even if the target method is synchronous

#### `after(result: Any, *args, **kwargs) -> Any`

Run after the target method has been called.

- **Parameters**:
  - `result`: The result of the target method
  - `*args`: The arguments passed to the target method
  - `**kwargs`: The keyword arguments passed to the target method
- **Returns**: The potentially modified result
- **Note**: This method is called asynchronously, even if the target method is synchronous

#### `on_error(exception: Exception, *args, **kwargs) -> Any`

Handle exceptions raised by the target method.

- **Parameters**:
  - `exception`: The exception raised by the target method
  - `*args`: The arguments passed to the target method
  - `**kwargs`: The keyword arguments passed to the target method
- **Returns**: A value to use as the result (if the exception is handled)
- **Raises**: The original or a new exception
- **Note**: This method is called asynchronously, even if the target method is synchronous

### Example

```python
from fastapi_shield.interceptors import Interceptor

class LoggingInterceptor(Interceptor):
    """Interceptor that logs method calls."""
    
    async def before(self, *args, **kwargs):
        print(f"Calling method with args: {args}, kwargs: {kwargs}")
        return {}
    
    async def after(self, result, *args, **kwargs):
        print(f"Method returned: {result}")
        return result
    
    async def on_error(self, exception, *args, **kwargs):
        print(f"Method raised: {exception}")
        raise exception
```

## `InterceptorChain` Class

The `InterceptorChain` class manages a chain of interceptors and applies them in sequence.

### Signature

```python
class InterceptorChain:
    """Chain of interceptors that are applied in sequence."""
    
    def __init__(self, interceptors: List[Interceptor] = None):
        """Initialize with a list of interceptors."""
        self.interceptors = interceptors or []
    
    def add(self, interceptor: Interceptor) -> None:
        """Add an interceptor to the chain."""
        self.interceptors.append(interceptor)
    
    def extend(self, interceptors: List[Interceptor]) -> None:
        """Add multiple interceptors to the chain."""
        self.interceptors.extend(interceptors)
    
    async def apply(self, method: Callable, *args, **kwargs) -> Any:
        """Apply the interceptor chain to a method call."""
        ...
```

### Methods

#### `add(interceptor: Interceptor) -> None`

Add an interceptor to the chain.

- **Parameters**:
  - `interceptor`: The interceptor to add

#### `extend(interceptors: List[Interceptor]) -> None`

Add multiple interceptors to the chain.

- **Parameters**:
  - `interceptors`: The list of interceptors to add

#### `apply(method: Callable, *args, **kwargs) -> Any`

Apply the interceptor chain to a method call.

- **Parameters**:
  - `method`: The method to intercept
  - `*args`: The arguments to pass to the method
  - `**kwargs`: The keyword arguments to pass to the method
- **Returns**: The result of the method call, potentially modified by interceptors
- **Raises**: Any exception raised by the method or interceptors

### Example

```python
from fastapi_shield.interceptors import InterceptorChain, Interceptor

# Create interceptors
class TimingInterceptor(Interceptor):
    async def before(self, *args, **kwargs):
        import time
        self.start_time = time.time()
        return {}
    
    async def after(self, result, *args, **kwargs):
        import time
        elapsed = time.time() - self.start_time
        print(f"Method took {elapsed:.2f} seconds")
        return result

class ValidationInterceptor(Interceptor):
    async def before(self, *args, **kwargs):
        # Validate that 'id' is positive
        if "id" in kwargs and kwargs["id"] <= 0:
            raise ValueError("ID must be positive")
        return {}

# Create a chain
chain = InterceptorChain([
    TimingInterceptor(),
    ValidationInterceptor()
])

# Apply to a method
async def get_user(id: int):
    # ... fetch user from database
    return {"id": id, "name": "John Doe"}

# Later, in an endpoint handler:
try:
    result = await chain.apply(get_user, id=1)
    # Method executed successfully
except ValueError as e:
    # Validation failed
    ...
```

## Built-in Interceptors

FastAPI Shield provides several built-in interceptors for common use cases.

### `LoggingInterceptor`

Logs method calls, results, and exceptions.

```python
from fastapi_shield.interceptors import LoggingInterceptor
import logging

# Create a logger
logger = logging.getLogger("api")

# Create the interceptor
logging_interceptor = LoggingInterceptor(logger)

# Use in a shield
from fastapi_shield import shield
from typing import NewType

UserId = NewType("UserId", int)
logged_user_id = shield(
    UserId,
    interceptors=[logging_interceptor]
)
```

### `ValidationInterceptor`

Validates input parameters against a schema.

```python
from fastapi_shield.interceptors import ValidationInterceptor
from pydantic import BaseModel, Field

# Define validation schema
class UserParams(BaseModel):
    id: int = Field(..., gt=0)
    include_details: bool = False

# Create the interceptor
validation_interceptor = ValidationInterceptor(UserParams)

# Use in a shield
from fastapi_shield import shield
from typing import NewType

UserId = NewType("UserId", int)
validated_user_id = shield(
    UserId,
    interceptors=[validation_interceptor]
)

# Use in an endpoint
@app.get("/users/{id}")
async def get_user(
    id: validated_user_id,
    include_details: bool = False
):
    # id is guaranteed to be positive
    return {"id": id, "include_details": include_details}
```

### `CacheInterceptor`

Caches method results based on input parameters.

```python
from fastapi_shield.interceptors import CacheInterceptor

# Create a cache with a 1-minute TTL
cache_interceptor = CacheInterceptor(ttl=60)

# Use in a shield
from fastapi_shield import shield
from typing import NewType

UserId = NewType("UserId", int)
cached_user_id = shield(
    UserId,
    interceptors=[cache_interceptor]
)

# Define a function that will be cached
async def get_user_from_db(user_id: cached_user_id):
    # This function will only be called once per user_id per minute
    # ... expensive database query
    return {"id": user_id, "name": "John Doe"}
```

### `RateLimitInterceptor`

Limits the rate of method calls.

```python
from fastapi_shield.interceptors import RateLimitInterceptor

# Create a rate limiter: 10 requests per minute
rate_limit_interceptor = RateLimitInterceptor(
    limit=10,
    window=60,
    key_func=lambda *args, **kwargs: kwargs.get("client_ip", "default")
)

# Use in a shield
from fastapi_shield import shield
from typing import NewType

ClientIP = NewType("ClientIP", str)
rate_limited_ip = shield(
    ClientIP,
    interceptors=[rate_limit_interceptor]
)

# Use in an endpoint
from fastapi import Request

@app.get("/api/data")
async def get_data(request: Request, client_ip: rate_limited_ip = Depends(lambda r: r.client.host)):
    # This endpoint is rate-limited to 10 requests per minute per client IP
    return {"data": "..."}
```

## Custom Interceptors

You can create custom interceptors by subclassing `Interceptor`:

```python
from fastapi_shield.interceptors import Interceptor
from typing import Dict, Any

class AuthInterceptor(Interceptor):
    """Interceptor that checks for authentication."""
    
    def __init__(self, auth_service):
        self.auth_service = auth_service
    
    async def before(self, *args, **kwargs) -> Dict[str, Any]:
        # Check for token in headers
        if "headers" in kwargs:
            headers = kwargs["headers"]
            if "Authorization" in headers:
                token = headers["Authorization"].replace("Bearer ", "")
                # Verify token
                user = await self.auth_service.verify_token(token)
                # Add user to kwargs
                return {"current_user": user}
        
        # No token or invalid token
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    async def on_error(self, exception, *args, **kwargs):
        # Log authentication failures
        if isinstance(exception, HTTPException) and exception.status_code == 401:
            print(f"Authentication failed: {exception.detail}")
        raise exception
```

## Creating Interceptor Chains

You can combine multiple interceptors into a chain:

```python
from fastapi_shield.interceptors import InterceptorChain
from fastapi_shield import shield
from typing import NewType

# Create interceptors
logging_interceptor = LoggingInterceptor(logger)
validation_interceptor = ValidationInterceptor(UserParams)
auth_interceptor = AuthInterceptor(auth_service)

# Create a chain
api_chain = InterceptorChain([
    logging_interceptor,
    validation_interceptor,
    auth_interceptor
])

# Create a shield with the chain
ApiToken = NewType("ApiToken", str)
api_token = shield(
    ApiToken,
    interceptors=api_chain.interceptors
)

# Use in an endpoint
@app.get("/api/data")
async def get_data(token: api_token = Header(...)):
    # Request is logged, validated, and authenticated
    return {"data": "..."}
```

## Aspect-Oriented Programming

FastAPI Shield supports Aspect-Oriented Programming (AOP) through its interceptor system:

```python
from fastapi_shield.interceptors import Aspect, with_aspects
from fastapi import FastAPI

app = FastAPI()

# Define aspects
class LoggingAspect(Aspect):
    async def before(self, *args, **kwargs):
        print(f"Entering endpoint with {kwargs}")
        return {}
    
    async def after(self, result, *args, **kwargs):
        print(f"Exiting endpoint with result: {result}")
        return result

class PerformanceAspect(Aspect):
    async def before(self, *args, **kwargs):
        import time
        self.start_time = time.time()
        return {}
    
    async def after(self, result, *args, **kwargs):
        import time
        elapsed = time.time() - self.start_time
        print(f"Endpoint took {elapsed:.2f} seconds")
        return result

# Apply aspects to an endpoint
@app.get("/users/{user_id}")
@with_aspects([LoggingAspect(), PerformanceAspect()])
async def get_user(user_id: int):
    # ... fetch user from database
    return {"id": user_id, "name": "John Doe"}
```

## Best Practices

1. **Keep Interceptors Focused**: Each interceptor should have a single responsibility
2. **Handle Errors Gracefully**: Implement `on_error` to handle exceptions appropriately
3. **Use Type Hints**: Provide clear type hints for your interceptors
4. **Documentation**: Document the behavior of your interceptors
5. **Order Matters**: Consider the order of interceptors in a chain
6. **Optimize Performance**: Be aware of the performance impact of your interceptors
7. **Async Compatibility**: Ensure your interceptors work correctly with both sync and async methods 