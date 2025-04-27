# Type Wrapping

FastAPI Shield provides powerful type wrapping capabilities to enhance type safety and readability in your shields.

## Understanding Type Wrapping

Type wrapping allows you to create type-safe shields that clearly communicate their intent through Python's type system. This approach leverages Python's typing system and FastAPI's powerful dependency injection to create secure, maintainable code.

## Using Type Hints with Shields

When creating shields, it's recommended to use appropriate type hints to make your code more readable and to enable better IDE support:

```python
from typing import Optional
from fastapi import Header, HTTPException
from fastapi_shield import shield

@shield(name="Typed Auth Shield")
def typed_auth_shield(api_token: Optional[str] = Header(default=None)) -> Optional[str]:
    """
    A typed authentication shield.
    
    Args:
        api_token: The API token from the header
        
    Returns:
        The validated token if valid, None otherwise
    """
    if api_token in ("admin_token", "user_token"):
        return api_token
    return None
```

## Generic Shield Functions

You can create more flexible shields using generics:

```python
from typing import TypeVar, Generic, Optional, Any
from fastapi import Depends
from fastapi_shield import shield

T = TypeVar('T')

class GenericShield(Generic[T]):
    def __init__(self, validator: callable):
        self.validator = validator
        
    def __call__(self, value: T) -> Optional[T]:
        return self.validator(value)

def create_validation_shield(validator: callable):
    """Create a shield that uses the provided validator function"""
    
    @shield
    def validation_shield(value: Any = Depends()):
        shield_instance = GenericShield(validator)
        result = shield_instance(value)
        return result
        
    return validation_shield

# Example usage
def is_positive_number(value: int) -> Optional[int]:
    return value if value > 0 else None

positive_number_shield = create_validation_shield(is_positive_number)
```

## Type Wrapping with ShieldedDepends

The `ShieldedDepends` mechanism also supports proper type hinting:

```python
from typing import Dict, Any, Optional
from fastapi import Header
from fastapi_shield import shield, ShieldedDepends

def get_user_from_token(token: str = Header()) -> Dict[str, Any]:
    """Get user data from a token"""
    users = {
        "token1": {"id": 1, "role": "admin"},
        "token2": {"id": 2, "role": "user"}
    }
    return users.get(token, {})

@shield
def role_shield(role: str, user: Dict[str, Any] = ShieldedDepends(get_user_from_token)) -> Optional[Dict[str, Any]]:
    """Shield that checks if the user has the required role"""
    if user.get("role") == role:
        return user
    return None
```

## Custom Type Classes

For more complex scenarios, you can create custom type classes:

```python
from typing import Optional, Dict, Any
from pydantic import BaseModel
from fastapi import Header
from fastapi_shield import shield

class User(BaseModel):
    id: int
    username: str
    role: str
    permissions: list[str]

class AuthResult(BaseModel):
    user: User
    token: str
    
@shield
def advanced_auth_shield(api_token: str = Header()) -> Optional[AuthResult]:
    """Advanced authentication shield that returns a structured auth result"""
    user_data = {
        "admin_token": {
            "id": 1,
            "username": "admin",
            "role": "admin",
            "permissions": ["read", "write", "delete"]
        },
        "user_token": {
            "id": 2,
            "username": "user",
            "role": "user",
            "permissions": ["read"]
        }
    }
    
    if api_token in user_data:
        return AuthResult(
            user=User(**user_data[api_token]),
            token=api_token
        )
    return None
```

## Advantages of Type Wrapping

Using proper type wrapping with FastAPI Shield offers several advantages:

1. **Type Safety**: IDE and linter tools can detect type mismatches
2. **Self-Documenting Code**: Types communicate intent clearly
3. **Better Autocomplete**: IDEs can provide better suggestions
4. **Easier Refactoring**: Changing types will highlight places that need changes
5. **Improved Documentation**: Generated API documentation will be more accurate 