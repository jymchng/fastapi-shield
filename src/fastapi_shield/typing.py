"""Type definitions and type variables for FastAPI Shield.

This module contains type definitions used throughout the FastAPI Shield library
to provide better type safety and documentation.
"""

from typing import Any, Callable, TypeVar

U = TypeVar("U", bound=Callable[..., Any])
"""Generic type variable for shield function signatures.

This type variable is used to preserve the type signature of shield functions
when they are wrapped by the Shield decorator, enabling proper type checking
and IDE support.

Examples:
    ```python
    def my_shield_func(request: Request) -> Optional[User]:
        # Shield logic here
        pass
    
    # U will be bound to the type of my_shield_func
    shield_instance: Shield[U] = Shield(my_shield_func)
    ```
"""

EndPointFunc = Callable[..., Any]
"""Type alias for FastAPI endpoint functions.

Represents any callable that can serve as a FastAPI endpoint function.
This includes both synchronous and asynchronous functions with arbitrary
parameters and return types.

Examples:
    ```python
    # Both of these match EndPointFunc
    async def async_endpoint(user_id: int) -> dict:
        return {"user_id": user_id}
    
    def sync_endpoint() -> str:
        return "Hello World"
    ```
"""
