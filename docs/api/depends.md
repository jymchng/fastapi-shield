# Dependency Injection API Reference

This document covers the dependency injection integration in FastAPI Shield, which allows for seamless integration with FastAPI's dependency injection system.

## `ShieldedDepends` Class

`ShieldedDepends` extends FastAPI's `Depends` class to integrate shield validation with the dependency injection system.

### Signature

```python
class ShieldedDepends(Depends):
    """A dependency that applies a shield to the resolved value."""
    
    def __init__(
        self,
        dependency: Callable,
        shield: Union[Shield, Callable],
        use_cache: bool = True
    ):
        """Initialize the ShieldedDepends."""
        ...
    
    async def __call__(self, *args, **kwargs) -> Any:
        """Resolve the dependency and apply the shield."""
        ...
```

### Parameters

- `dependency`: The dependency to resolve
- `shield`: The shield to apply to the resolved value
- `use_cache`: Whether to cache the resolved value (default: `True`)

### Methods

#### `__call__(*args, **kwargs) -> Any`

Resolve the dependency and apply the shield to the result.

- **Parameters**:
  - `*args`: The arguments passed to the dependency
  - `**kwargs`: The keyword arguments passed to the dependency
- **Returns**: The shielded result of the dependency
- **Raises**: Any exception raised by the dependency or shield

### Example

```python
from fastapi import FastAPI, Depends
from fastapi_shield import shield, ShieldedDepends
from typing import NewType

app = FastAPI()

# Create a dependency
async def get_user_id_from_token(token: str):
    # In a real application, verify the token
    return 123

# Create a shielded type
UserId = NewType("UserId", int)
validated_user_id = shield(
    UserId,
    validators=[lambda v: v if v > 0 else ValueError("User ID must be positive")]
)

# Use ShieldedDepends in an endpoint
@app.get("/users/me")
async def get_current_user(
    user_id: UserId = ShieldedDepends(
        get_user_id_from_token,
        shield=validated_user_id
    )
):
    # user_id is guaranteed to be a positive integer
    return {"user_id": user_id}
```

## `ShieldDepends` Class

`ShieldDepends` is a specialized version of `Depends` that directly creates and applies a shield.

### Signature

```python
class ShieldDepends(Depends):
    """A dependency that creates and applies a shield directly."""
    
    def __init__(
        self,
        dependency: Callable,
        type_: Type[T],
        validators: Optional[List[Callable]] = None,
        interceptors: Optional[List[Interceptor]] = None,
        use_cache: bool = True,
        alias: Optional[str] = None,
        description: Optional[str] = None
    ):
        """Initialize the ShieldDepends."""
        ...
    
    async def __call__(self, *args, **kwargs) -> T:
        """Resolve the dependency and apply the shield."""
        ...
```

### Parameters

- `dependency`: The dependency to resolve
- `type_`: The type to shield
- `validators`: Optional list of validators to apply
- `interceptors`: Optional list of interceptors to apply
- `use_cache`: Whether to cache the resolved value (default: `True`)
- `alias`: Optional name to use for the shielded type in the OpenAPI schema
- `description`: Optional description to include in the OpenAPI schema

### Methods

#### `__call__(*args, **kwargs) -> T`

Resolve the dependency and apply the shield to the result.

- **Parameters**:
  - `*args`: The arguments passed to the dependency
  - `**kwargs`: The keyword arguments passed to the dependency
- **Returns**: The shielded result of the dependency
- **Raises**: Any exception raised by the dependency or shield

### Example

```python
from fastapi import FastAPI, Depends
from fastapi_shield import ShieldDepends
from typing import NewType

app = FastAPI()

# Create a dependency
async def get_user_id_from_token(token: str):
    # In a real application, verify the token
    return 123

# Create a type
UserId = NewType("UserId", int)

# Define a validator
def validate_positive(value):
    if value <= 0:
        raise ValueError("User ID must be positive")
    return value

# Use ShieldDepends in an endpoint
@app.get("/users/me")
async def get_current_user(
    user_id: UserId = ShieldDepends(
        get_user_id_from_token,
        type_=UserId,
        validators=[validate_positive]
    )
):
    # user_id is guaranteed to be a positive integer
    return {"user_id": user_id}
```

## `shield_depends` Function

`shield_depends` is a function that creates a `ShieldDepends` instance with a specific shield type.

### Signature

```python
def shield_depends(
    type_: Type[T],
    *,
    validators: Optional[List[Callable]] = None,
    interceptors: Optional[List[Interceptor]] = None,
    alias: Optional[str] = None,
    description: Optional[str] = None
) -> Callable[[Callable], ShieldDepends]:
    """Create a ShieldDepends factory for a specific type."""
    ...
```

### Parameters

- `type_`: The type to shield
- `validators`: Optional list of validators to apply
- `interceptors`: Optional list of interceptors to apply
- `alias`: Optional name to use for the shielded type in the OpenAPI schema
- `description`: Optional description to include in the OpenAPI schema

### Returns

A function that takes a dependency and returns a `ShieldDepends` instance.

### Example

```python
from fastapi import FastAPI
from fastapi_shield import shield_depends
from typing import NewType

app = FastAPI()

# Create a type
UserId = NewType("UserId", int)

# Define a validator
def validate_positive(value):
    if value <= 0:
        raise ValueError("User ID must be positive")
    return value

# Create a shield_depends factory
user_id_depends = shield_depends(
    UserId,
    validators=[validate_positive]
)

# Create a dependency
async def get_user_id_from_token(token: str):
    # In a real application, verify the token
    return 123

# Use the factory in an endpoint
@app.get("/users/me")
async def get_current_user(
    user_id: UserId = user_id_depends(get_user_id_from_token)
):
    # user_id is guaranteed to be a positive integer
    return {"user_id": user_id}
```

## `depends_factory` Function

`depends_factory` creates a factory function that produces `ShieldedDepends` instances with common configurations.

### Signature

```python
def depends_factory(
    base_config: Optional[Dict[str, Any]] = None,
    validators: Optional[List[Callable]] = None,
    interceptors: Optional[List[Interceptor]] = None
) -> Callable[..., Callable]:
    """Create a factory for ShieldedDepends with common configurations."""
    ...
```

### Parameters

- `base_config`: Optional dictionary of base configuration for all dependencies created by this factory
- `validators`: Optional list of validators to apply to all dependencies created by this factory
- `interceptors`: Optional list of interceptors to apply to all dependencies created by this factory

### Returns

A factory function that creates `ShieldedDepends` instances with the specified configuration.

### Example

```python
from fastapi import FastAPI
from fastapi_shield import depends_factory
from typing import NewType

app = FastAPI()

# Define base validators
def validate_not_empty(value):
    if not value:
        raise ValueError("Value cannot be empty")
    return value

# Create a factory for string dependencies
string_depends_factory = depends_factory(
    validators=[validate_not_empty]
)

# Create specialized string types
Username = NewType("Username", str)
Email = NewType("Email", str)

# Define email validator
def validate_email(value):
    if "@" not in value:
        raise ValueError("Invalid email format")
    return value

# Create dependencies with the factory
async def get_username_from_request(request):
    return request.query_params.get("username", "")

async def get_email_from_request(request):
    return request.query_params.get("email", "")

# Use in an endpoint
@app.get("/users/")
async def create_user(
    username: Username = string_depends_factory(
        get_username_from_request,
        type_=Username
    ),
    email: Email = string_depends_factory(
        get_email_from_request,
        type_=Email,
        validators=[validate_email]
    )
):
    return {"username": username, "email": email}
```

## Integration with FastAPI

FastAPI Shield's dependency injection integrates seamlessly with FastAPI:

```python
from fastapi import FastAPI, Header, Depends
from fastapi_shield import shield, ShieldedDepends
from typing import NewType

app = FastAPI()

# Create shielded types
Token = NewType("Token", str)
validated_token = shield(
    Token,
    validators=[lambda v: v if len(v) >= 32 else ValueError("Invalid token")]
)

# Create a user service
class UserService:
    async def get_user_from_token(self, token: validated_token):
        # In a real application, verify the token
        return {"id": 123, "name": "John Doe"}

# Create a dependency
def get_user_service():
    return UserService()

# Use in an endpoint
@app.get("/users/me")
async def get_current_user(
    token: Token = Header(...),
    user_service: UserService = Depends(get_user_service)
):
    # token is guaranteed to be at least 32 characters
    user = await user_service.get_user_from_token(token)
    return user
```

## Caching Behavior

FastAPI Shield respects FastAPI's caching behavior for dependencies:

```python
from fastapi import FastAPI, Depends
from fastapi_shield import shield, ShieldedDepends
from typing import NewType

app = FastAPI()

# Create a counter
counter = 0

# Create a dependency that increments the counter
async def get_counter():
    global counter
    counter += 1
    return counter

# Create a shielded type
Counter = NewType("Counter", int)
validated_counter = shield(Counter)

# Use in endpoints
@app.get("/counter/cached")
async def get_cached_counter(
    count: Counter = ShieldedDepends(get_counter, shield=validated_counter)
):
    # This will use the cached value of get_counter
    return {"counter": count}

@app.get("/counter/uncached")
async def get_uncached_counter(
    count: Counter = ShieldedDepends(
        get_counter, 
        shield=validated_counter,
        use_cache=False
    )
):
    # This will call get_counter again
    return {"counter": count}
```

## Advanced Usage with Pydantic

FastAPI Shield's dependency injection works well with Pydantic models:

```python
from fastapi import FastAPI, Depends
from fastapi_shield import shield, ShieldedDepends
from typing import NewType
from pydantic import BaseModel, Field

app = FastAPI()

# Create a shielded type
UserId = NewType("UserId", int)
validated_user_id = shield(
    UserId,
    validators=[lambda v: v if v > 0 else ValueError("User ID must be positive")]
)

# Create a Pydantic model
class User(BaseModel):
    id: validated_user_id
    name: str = Field(..., min_length=2)
    email: str = Field(..., regex=r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")

# Create a dependency
async def get_user_from_db(user_id: validated_user_id):
    # In a real application, fetch from database
    return User(id=user_id, name="John Doe", email="john@example.com")

# Use in an endpoint
@app.get("/users/{user_id}")
async def get_user(
    user: User = ShieldedDepends(get_user_from_db, shield=lambda x: x)
):
    # user is a validated Pydantic model
    return user
```

## Best Practices

1. **Reuse Dependencies**: Create reusable dependencies that can be shared across endpoints
2. **Shield Early**: Apply shields as early as possible in the dependency chain
3. **Caching Considerations**: Be aware of caching behavior, especially for expensive operations
4. **Type Safety**: Use `NewType` to create distinct types for your shields
5. **Validation Composition**: Compose validators for complex validation logic
6. **Error Handling**: Provide clear error messages for validation failures
7. **Documentation**: Use the `description` parameter to document the dependency 