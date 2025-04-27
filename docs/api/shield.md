# Shield API Reference

This document covers the core `shield` module API, which provides the foundation for creating and using shields in FastAPI Shield.

## `shield` Function

The `shield` function is the primary way to create a shielded type in FastAPI Shield.

### Signature

```python
def shield(
    type_: Type[T],
    *, 
    validators: Optional[List[Callable[[Any], Any]]] = None,
    interceptors: Optional[List[Interceptor]] = None,
    alias: Optional[str] = None,
    description: Optional[str] = None
) -> Callable[[Any], T]:
    ...
```

### Parameters

- `type_`: The base type to shield (can be a basic type like `str`, `int`, or a Pydantic model)
- `validators`: Optional list of validation functions that take the input value and raise an exception if validation fails
- `interceptors`: Optional list of interceptors that can modify the value before or after processing
- `alias`: Optional name to use for the shielded type in the OpenAPI schema
- `description`: Optional description to include in the OpenAPI schema

### Returns

A callable that accepts a value of any type and returns a validated value of the specified type.

### Raises

- `ValidationError`: If the input fails validation
- `TypeError`: If the input cannot be converted to the target type

### Example

```python
from typing import NewType
from fastapi_shield import shield

# Create a shielded user ID type
UserId = NewType("UserId", int)

# Define a validator
def validate_positive(value):
    if value <= 0:
        raise ValueError("User ID must be positive")
    return value

# Create a shielded type with validation
validated_user_id = shield(
    UserId,
    validators=[validate_positive],
    description="A positive integer representing a user ID"
)

# Use in a FastAPI endpoint
@app.get("/users/{user_id}")
async def get_user(user_id: validated_user_id):
    return {"user_id": user_id}
```

## `Shield` Class

The `Shield` class is the base class for custom shield implementations.

### Signature

```python
class Shield(Generic[T]):
    """Base class for all shields."""
    
    def __init__(
        self, 
        base_type: Type[T],
        validators: Optional[List[Callable]] = None,
        interceptors: Optional[List[Interceptor]] = None,
        alias: Optional[str] = None,
        description: Optional[str] = None
    ):
        ...
    
    def __call__(self, value: Any) -> T:
        ...
    
    def _validate(self, value: Any) -> None:
        ...
    
    def _transform(self, value: Any) -> T:
        ...
    
    @property
    def openapi_schema(self) -> Dict[str, Any]:
        ...
```

### Methods

#### `__call__(value: Any) -> T`

Call the shield to validate and transform the input value.

- **Parameters**:
  - `value`: The input value to validate and transform
- **Returns**: A validated value of the shield's type
- **Raises**: `ValidationError` if validation fails

#### `_validate(value: Any) -> None`

Run all validators on the input value.

- **Parameters**:
  - `value`: The input value to validate
- **Returns**: `None`
- **Raises**: `ValidationError` if validation fails

#### `_transform(value: Any) -> T`

Transform the input value to the target type.

- **Parameters**:
  - `value`: The input value to transform
- **Returns**: The transformed value
- **Raises**: `TypeError` if the value cannot be transformed

#### `openapi_schema` (property)

Get the OpenAPI schema for this shield.

- **Returns**: A dictionary containing the OpenAPI schema

### Example

```python
from typing import NewType, Generic, TypeVar
from fastapi_shield import Shield

T = TypeVar('T')

class PositiveNumberShield(Shield[T]):
    """Shield that ensures a number is positive."""
    
    def _validate(self, value: Any) -> None:
        super()._validate(value)
        if value <= 0:
            raise ValueError(f"Value must be positive, got {value}")

# Create a positive integer type
PositiveInt = NewType("PositiveInt", int)
positive_int_shield = PositiveNumberShield(PositiveInt)

# Use in a FastAPI endpoint
@app.get("/items/{item_id}")
async def get_item(item_id: positive_int_shield):
    return {"item_id": item_id}
```

## `create_shield_factory` Function

The `create_shield_factory` function creates a factory function for generating shields with specific configurations.

### Signature

```python
def create_shield_factory(
    base_config: Optional[Dict[str, Any]] = None,
    validators: Optional[List[Callable]] = None,
    interceptors: Optional[List[Interceptor]] = None
) -> Callable[..., Callable]:
    ...
```

### Parameters

- `base_config`: Optional dictionary of base configuration for all shields created by this factory
- `validators`: Optional list of validators to apply to all shields created by this factory
- `interceptors`: Optional list of interceptors to apply to all shields created by this factory

### Returns

A factory function that can create shields with the specified configuration.

### Example

```python
from typing import NewType
from fastapi_shield import create_shield_factory

# Define base validators
def validate_not_empty(value):
    if not value:
        raise ValueError("Value cannot be empty")
    return value

# Create a factory for string shields
string_shield_factory = create_shield_factory(
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

# Create shields with the factory
username_shield = string_shield_factory(Username)
email_shield = string_shield_factory(
    Email, 
    validators=[validate_email]
)

# Use in a FastAPI endpoint
@app.post("/users/")
async def create_user(
    username: username_shield,
    email: email_shield
):
    return {"username": username, "email": email}
```

## `shield_factory` Class Decorator

The `shield_factory` decorator transforms a class into a shield factory.

### Signature

```python
def shield_factory(
    cls: Type[Any]
) -> Callable[..., Callable]:
    ...
```

### Parameters

- `cls`: The class to transform into a shield factory

### Returns

A factory function that creates shields based on the decorated class.

### Example

```python
from typing import NewType, List, Callable, Any
from fastapi_shield import shield_factory

@shield_factory
class StringShield:
    """Factory for string shields with common validators."""
    
    def __init__(
        self,
        type_: Type[str],
        min_length: Optional[int] = None,
        max_length: Optional[int] = None,
        pattern: Optional[str] = None,
        extra_validators: Optional[List[Callable]] = None
    ):
        self.type = type_
        self.min_length = min_length
        self.max_length = max_length
        self.pattern = pattern
        self.extra_validators = extra_validators or []
        
    def get_validators(self) -> List[Callable]:
        validators = []
        
        if self.min_length is not None:
            validators.append(
                lambda v: v if len(v) >= self.min_length else 
                    ValueError(f"String too short, min {self.min_length}")
            )
            
        if self.max_length is not None:
            validators.append(
                lambda v: v if len(v) <= self.max_length else 
                    ValueError(f"String too long, max {self.max_length}")
            )
        
        if self.pattern is not None:
            import re
            pattern = re.compile(self.pattern)
            validators.append(
                lambda v: v if pattern.match(v) else 
                    ValueError(f"String doesn't match pattern {self.pattern}")
            )
        
        validators.extend(self.extra_validators)
        return validators

# Create specialized string types
Username = NewType("Username", str)
Email = NewType("Email", str)

# Use the factory
username_shield = StringShield(
    Username,
    min_length=3,
    max_length=20
)

email_shield = StringShield(
    Email,
    pattern=r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
)

# Use in a FastAPI endpoint
@app.post("/users/")
async def create_user(
    username: username_shield,
    email: email_shield
):
    return {"username": username, "email": email}
```

## Integration with FastAPI

FastAPI Shield integrates seamlessly with FastAPI's dependency injection system and type annotations:

```python
from typing import NewType
from fastapi import FastAPI, Depends
from fastapi_shield import shield

app = FastAPI()

# Create shielded types
UserId = NewType("UserId", int)
Username = NewType("Username", str)

validated_user_id = shield(
    UserId,
    validators=[lambda v: v if v > 0 else ValueError("User ID must be positive")]
)

validated_username = shield(
    Username,
    validators=[
        lambda v: v if len(v) >= 3 else ValueError("Username too short"),
        lambda v: v if len(v) <= 20 else ValueError("Username too long")
    ]
)

# Use in path parameters
@app.get("/users/{user_id}")
async def get_user(user_id: validated_user_id):
    return {"user_id": user_id}

# Use in query parameters
@app.get("/users/")
async def search_users(username: validated_username = None):
    return {"username": username}

# Use in request body with Pydantic
from pydantic import BaseModel

class User(BaseModel):
    user_id: validated_user_id
    username: validated_username

@app.post("/users/")
async def create_user(user: User):
    return user
```

## Best Practices

1. **Define New Types**: Always use `NewType` to create distinct types for your shields
2. **Reuse Validators**: Create reusable validation functions
3. **Use Shield Factories**: For related types with similar validation
4. **Add Documentation**: Use the `description` parameter to document the shield
5. **Keep Shields Simple**: Each shield should have a single responsibility
6. **Layer Shields**: Compose shields for complex validation logic
7. **Error Messages**: Provide clear error messages in validators 