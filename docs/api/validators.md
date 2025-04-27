# Validators API Reference

This document covers the validation system in FastAPI Shield, which allows for robust input validation and transformation.

## Core Validation Concepts

FastAPI Shield uses validators to ensure that input values meet specific criteria before they are processed.

### Validator Function Signature

A validator function in FastAPI Shield has the following signature:

```python
def validator(value: Any) -> Any:
    """Validate and optionally transform a value."""
    if not valid(value):
        raise ValueError("Validation error message")
    return value  # or a transformed version of the value
```

Validators can either:
- Return the original value if it's valid
- Return a transformed version of the value
- Raise an exception if the value is invalid

## Built-in Validators

FastAPI Shield provides several built-in validators for common validation scenarios.

### String Validators

```python
from fastapi_shield.validation import (
    min_length,
    max_length,
    pattern,
    email,
    url,
    uuid,
    not_empty
)
```

#### `min_length(min_len: int)`

Validates that a string has at least the specified length.

```python
from fastapi_shield.validation import min_length
from fastapi_shield import shield
from typing import NewType

# Create a validator that ensures a string is at least 8 characters
password_min_length = min_length(8)

# Create a shielded type
Password = NewType("Password", str)
validated_password = shield(
    Password,
    validators=[password_min_length]
)

# Use in an endpoint
@app.post("/users/")
async def create_user(password: validated_password):
    # password is guaranteed to be at least 8 characters
    return {"message": "User created"}
```

#### `max_length(max_len: int)`

Validates that a string does not exceed the specified length.

```python
from fastapi_shield.validation import max_length

# Create a validator that ensures a string is at most 20 characters
username_max_length = max_length(20)
```

#### `pattern(regex: str)`

Validates that a string matches the specified regular expression pattern.

```python
from fastapi_shield.validation import pattern

# Create a validator that ensures a string is alphanumeric
alphanumeric = pattern(r'^[a-zA-Z0-9]+$')
```

#### `email()`

Validates that a string is a valid email address.

```python
from fastapi_shield.validation import email

# Create a validator that ensures a string is a valid email
is_email = email()
```

#### `url()`

Validates that a string is a valid URL.

```python
from fastapi_shield.validation import url

# Create a validator that ensures a string is a valid URL
is_url = url()
```

#### `uuid()`

Validates that a string is a valid UUID.

```python
from fastapi_shield.validation import uuid

# Create a validator that ensures a string is a valid UUID
is_uuid = uuid()
```

#### `not_empty()`

Validates that a string is not empty.

```python
from fastapi_shield.validation import not_empty

# Create a validator that ensures a string is not empty
non_empty = not_empty()
```

### Numeric Validators

```python
from fastapi_shield.validation import (
    min_value,
    max_value,
    range_value,
    positive,
    negative,
    integer
)
```

#### `min_value(min_val: Union[int, float])`

Validates that a number is at least the specified value.

```python
from fastapi_shield.validation import min_value
from fastapi_shield import shield
from typing import NewType

# Create a validator that ensures a number is at least 18
age_min = min_value(18)

# Create a shielded type
Age = NewType("Age", int)
validated_age = shield(
    Age,
    validators=[age_min]
)

# Use in an endpoint
@app.post("/users/")
async def create_user(age: validated_age):
    # age is guaranteed to be at least 18
    return {"message": "User created"}
```

#### `max_value(max_val: Union[int, float])`

Validates that a number does not exceed the specified value.

```python
from fastapi_shield.validation import max_value

# Create a validator that ensures a number is at most 120
age_max = max_value(120)
```

#### `range_value(min_val: Union[int, float], max_val: Union[int, float])`

Validates that a number is within the specified range.

```python
from fastapi_shield.validation import range_value

# Create a validator that ensures a number is between 18 and 120
age_range = range_value(18, 120)
```

#### `positive()`

Validates that a number is positive (greater than 0).

```python
from fastapi_shield.validation import positive

# Create a validator that ensures a number is positive
is_positive = positive()
```

#### `negative()`

Validates that a number is negative (less than 0).

```python
from fastapi_shield.validation import negative

# Create a validator that ensures a number is negative
is_negative = negative()
```

#### `integer()`

Validates that a number is an integer.

```python
from fastapi_shield.validation import integer

# Create a validator that ensures a number is an integer
is_integer = integer()
```

### Collection Validators

```python
from fastapi_shield.validation import (
    min_items,
    max_items,
    unique_items,
    contains
)
```

#### `min_items(min_count: int)`

Validates that a collection has at least the specified number of items.

```python
from fastapi_shield.validation import min_items
from fastapi_shield import shield
from typing import NewType, List

# Create a validator that ensures a list has at least 1 item
non_empty_list = min_items(1)

# Create a shielded type
TagList = NewType("TagList", List[str])
validated_tags = shield(
    TagList,
    validators=[non_empty_list]
)

# Use in an endpoint
@app.post("/posts/")
async def create_post(tags: validated_tags):
    # tags is guaranteed to have at least 1 item
    return {"message": "Post created", "tags": tags}
```

#### `max_items(max_count: int)`

Validates that a collection does not exceed the specified number of items.

```python
from fastapi_shield.validation import max_items

# Create a validator that ensures a list has at most 10 items
limited_list = max_items(10)
```

#### `unique_items()`

Validates that all items in a collection are unique.

```python
from fastapi_shield.validation import unique_items

# Create a validator that ensures a list has unique items
no_duplicates = unique_items()
```

#### `contains(item: Any)`

Validates that a collection contains the specified item.

```python
from fastapi_shield.validation import contains

# Create a validator that ensures a list contains 'admin'
has_admin = contains('admin')
```

### Datetime Validators

```python
from fastapi_shield.validation import (
    min_date,
    max_date,
    date_range,
    is_past,
    is_future
)
```

#### `min_date(min_dt: datetime)`

Validates that a datetime is at least the specified datetime.

```python
from fastapi_shield.validation import min_date
from fastapi_shield import shield
from typing import NewType
from datetime import datetime

# Create a validator that ensures a date is at least 2023-01-01
min_2023 = min_date(datetime(2023, 1, 1))

# Create a shielded type
BirthDate = NewType("BirthDate", datetime)
validated_birth_date = shield(
    BirthDate,
    validators=[min_2023]
)

# Use in an endpoint
@app.post("/users/")
async def create_user(birth_date: validated_birth_date):
    # birth_date is guaranteed to be at least 2023-01-01
    return {"message": "User created"}
```

#### `max_date(max_dt: datetime)`

Validates that a datetime does not exceed the specified datetime.

```python
from fastapi_shield.validation import max_date
from datetime import datetime

# Create a validator that ensures a date is at most today
today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
not_future = max_date(today)
```

#### `date_range(min_dt: datetime, max_dt: datetime)`

Validates that a datetime is within the specified range.

```python
from fastapi_shield.validation import date_range
from datetime import datetime, timedelta

# Create a validator that ensures a date is within the last year
today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
one_year_ago = today - timedelta(days=365)
last_year = date_range(one_year_ago, today)
```

#### `is_past()`

Validates that a datetime is in the past.

```python
from fastapi_shield.validation import is_past

# Create a validator that ensures a date is in the past
past_date = is_past()
```

#### `is_future()`

Validates that a datetime is in the future.

```python
from fastapi_shield.validation import is_future

# Create a validator that ensures a date is in the future
future_date = is_future()
```

## Combining Validators

Validators can be combined to create more complex validation logic:

```python
from fastapi_shield.validation import min_length, max_length, pattern
from fastapi_shield import shield
from typing import NewType

# Create multiple validators
username_min_length = min_length(3)
username_max_length = max_length(20)
username_pattern = pattern(r'^[a-zA-Z0-9_]+$')

# Create a shielded type with multiple validators
Username = NewType("Username", str)
validated_username = shield(
    Username,
    validators=[
        username_min_length,
        username_max_length,
        username_pattern
    ]
)

# Use in an endpoint
@app.post("/users/")
async def create_user(username: validated_username):
    # username is guaranteed to:
    # - be at least 3 characters
    # - be at most 20 characters
    # - contain only alphanumeric characters and underscores
    return {"message": "User created"}
```

## Custom Validators

You can create custom validators for specialized validation logic:

```python
from fastapi_shield import shield
from typing import NewType

# Create a custom validator
def validate_password_strength(value: str) -> str:
    """Validate that a password is strong."""
    has_upper = any(c.isupper() for c in value)
    has_lower = any(c.islower() for c in value)
    has_digit = any(c.isdigit() for c in value)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?/" for c in value)
    
    if not (has_upper and has_lower and has_digit and has_special):
        raise ValueError(
            "Password must contain uppercase, lowercase, "
            "digit, and special characters"
        )
    
    return value

# Create a shielded type with the custom validator
Password = NewType("Password", str)
strong_password = shield(
    Password,
    validators=[
        min_length(8),
        validate_password_strength
    ]
)

# Use in an endpoint
@app.post("/users/")
async def create_user(password: strong_password):
    # password is guaranteed to be strong
    return {"message": "User created"}
```

## Validator Factories

You can create factory functions that produce validators with specific configurations:

```python
from fastapi_shield import shield
from typing import NewType, Callable, Any

# Create a validator factory
def enum_validator(allowed_values: set) -> Callable[[Any], Any]:
    """Create a validator that ensures a value is in the allowed set."""
    def validate(value: Any) -> Any:
        if value not in allowed_values:
            allowed_str = ", ".join(str(v) for v in allowed_values)
            raise ValueError(f"Value must be one of: {allowed_str}")
        return value
    return validate

# Create a shielded type with the factory-generated validator
Role = NewType("Role", str)
allowed_roles = {"admin", "user", "guest"}
validated_role = shield(
    Role,
    validators=[enum_validator(allowed_roles)]
)

# Use in an endpoint
@app.post("/users/")
async def create_user(role: validated_role):
    # role is guaranteed to be one of: admin, user, guest
    return {"message": "User created"}
```

## Integration with Pydantic

FastAPI Shield validators can be used alongside Pydantic validators:

```python
from fastapi_shield import shield
from fastapi_shield.validation import min_length, pattern
from typing import NewType
from pydantic import BaseModel, validator

# Create a shielded type
Username = NewType("Username", str)
validated_username = shield(
    Username,
    validators=[
        min_length(3),
        pattern(r'^[a-zA-Z0-9_]+$')
    ]
)

# Use in a Pydantic model
class User(BaseModel):
    username: validated_username
    email: str
    
    # Additional Pydantic validation
    @validator("email")
    def validate_email(cls, v):
        if "@" not in v:
            raise ValueError("Invalid email format")
        return v

# Use in an endpoint
@app.post("/users/")
async def create_user(user: User):
    # user.username is guaranteed to:
    # - be at least 3 characters
    # - contain only alphanumeric characters and underscores
    # user.email is guaranteed to contain @
    return {"message": "User created"}
```

## Best Practices

1. **Reuse Validators**: Create reusable validators for common validation patterns
2. **Compose Validators**: Combine multiple validators for complex validation logic
3. **Clear Error Messages**: Provide clear error messages in custom validators
4. **Validation Ordering**: Consider the order of validators for efficiency
5. **Type Safety**: Use `NewType` to create distinct types for your shields
6. **Document Validators**: Document the behavior of your validators
7. **Fail Fast**: Put the most restrictive validators first to fail fast 