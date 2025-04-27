# NewType API Reference

This page documents the API for FastAPI Shield's `NewType` functionality, which enhances type safety in your API endpoints.

## Shield

The main decorator that transforms a function into a shield.

```python
@overload
def shield(
    func: Callable[..., Optional[T]],
    *,
    name: Optional[str] = None,
    auto_error: bool = True,
    exception_to_raise_if_fail: Optional[HTTPException] = None,
    default_response_to_return_if_fail: Optional[Response] = None,
) -> Shield[T]: ...

@overload
def shield(
    *,
    name: Optional[str] = None,
    auto_error: bool = True,
    exception_to_raise_if_fail: Optional[HTTPException] = None,
    default_response_to_return_if_fail: Optional[Response] = None,
) -> Callable[[Callable[..., Optional[T]]], Shield[T]]: ...
```

### Parameters

- `func` - The function to transform into a shield
- `name` - A name for the shield (used in error messages)
- `auto_error` - Whether to automatically raise an exception when the shield blocks a request
- `exception_to_raise_if_fail` - A custom exception to raise when the shield blocks a request
- `default_response_to_return_if_fail` - A custom response to return when the shield blocks a request and `auto_error` is `False`

### Return Value

Returns a `Shield` instance that can be used as a decorator for FastAPI route handlers.

### Example

```python
from fastapi import HTTPException, status
from fastapi_shield import shield

@shield(
    name="API Key Shield",
    auto_error=True,
    exception_to_raise_if_fail=HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API key"
    )
)
def api_key_shield(api_key: str):
    if api_key == "valid_key":
        return {"authenticated": True}
    return None
```

## Shield Class

The `Shield` class that wraps shield functions.

```python
class Shield(Generic[U]):
    def __init__(
        self,
        shield_func: U,
        *,
        name: Optional[str] = None,
        auto_error: bool = True,
        exception_to_raise_if_fail: Optional[HTTPException] = None,
        default_response_to_return_if_fail: Optional[Response] = None,
    ):
        ...

    def __call__(self, endpoint: EndPointFunc) -> EndPointFunc:
        ...
```

### Parameters

- `shield_func` - The function that performs the shield's validation logic
- `name` - A name for the shield (used in error messages)
- `auto_error` - Whether to automatically raise an exception when the shield blocks a request
- `exception_to_raise_if_fail` - A custom exception to raise when the shield blocks a request
- `default_response_to_return_if_fail` - A custom response to return when the shield blocks a request and `auto_error` is `False`

### Methods

- `__call__(endpoint)` - Applies the shield to an endpoint function

## ShieldedDepends

A special dependency class that is only resolved if the shield allows the request to proceed.

```python
def ShieldedDepends(
    shielded_dependency: Optional[Callable[..., Any]] = None,
    *,
    auto_error: bool = True,
    scopes: Optional[Sequence[str]] = None,
    use_cache: bool = True,
) -> Any:
    ...
```

### Parameters

- `shielded_dependency` - The dependency to be shielded
- `auto_error` - Whether to automatically raise an exception when the dependency cannot be resolved
- `scopes` - OAuth2 scopes required by the dependency
- `use_cache` - Whether to cache the dependency resolution

### Return Value

Returns a `ShieldDepends` instance that can be used as a dependency in FastAPI route handlers.

### Example

```python
from fastapi import Depends, Header
from fastapi_shield import shield, ShieldedDepends

def get_user_from_token(api_token: str = Header()):
    # In a real app, you would decode and validate the token
    if api_token == "valid_token":
        return {"user_id": 123, "roles": ["admin"]}
    return None

@shield
def admin_shield(user = ShieldedDepends(get_user_from_token)):
    if user and "admin" in user.get("roles", []):
        return user
    return None
```

## ShieldDepends

The underlying implementation of `ShieldedDepends`.

```python
class ShieldDepends(Generic[U], Security):
    def __init__(
        self,
        shielded_dependency: Optional[U] = None,
        *,
        auto_error: bool = True,
        scopes: Optional[Sequence[str]] = None,
        use_cache: bool = True,
    ):
        ...

    async def __call__(self, *args, **kwargs):
        ...

    async def resolve_dependencies(self, request: Request, path_format: str):
        ...

    @asynccontextmanager
    async def _as_unblocked(self):
        ...
```

### Parameters

- `shielded_dependency` - The dependency to be shielded
- `auto_error` - Whether to automatically raise an exception when the dependency cannot be resolved
- `scopes` - OAuth2 scopes required by the dependency
- `use_cache` - Whether to cache the dependency resolution

### Methods

- `__call__(*args, **kwargs)` - Calls the shielded dependency if unblocked, otherwise returns self
- `resolve_dependencies(request, path_format)` - Resolves the dependencies for the shielded dependency
- `_as_unblocked()` - Context manager that temporarily unblocks the shield

## Type Annotations

FastAPI Shield uses the following type annotations for better type safety:

```python
# Type for endpoint functions
EndPointFunc = TypeVar("EndPointFunc", bound=Callable[..., Any])

# Type for shield functions
U = TypeVar("U", bound=Optional[Callable[..., Any]])

# Type for shield return values
T = TypeVar("T")
```

These type annotations help ensure that shields and dependencies are used correctly, providing better IDE support and catch potential type errors at compile time.

## Utility Functions

FastAPI Shield provides several utility functions that are used internally:

```python
async def get_solved_dependencies(
    request: Request,
    path_format: str,
    endpoint: Callable,
    dependency_cache: Dict[Tuple[Callable, str], Any],
) -> Dict[str, Any]:
    ...

def prepend_request_to_signature_params_of_function(
    func: Callable, func_params: Dict[str, Parameter]
) -> Dict[str, Parameter]:
    ...

def merge_dedup_seq_params(
    primary_p: Sequence[Parameter], secondary_p: Sequence[Parameter]
) -> Tuple[List[Parameter], Dict[str, Parameter]]:
    ...

def rearrange_params(
    params: Sequence[Parameter],
) -> Tuple[List[Parameter], Dict[str, Parameter]]:
    ...
```

These functions handle dependency resolution, parameter manipulation, and other internal tasks required for FastAPI Shield to work correctly with FastAPI's dependency injection system.

## Usage Notes

- When a shield returns `None`, the request is blocked, and an error response is generated based on the shield's configuration
- When a shield returns any value other than `None`, the request is allowed to proceed, and the returned value is passed to `ShieldedDepends` instances
- Shield functions can be synchronous or asynchronous
- Shield functions can accept any parameters that FastAPI's dependency injection system supports
- `ShieldedDepends` dependencies are only resolved if all shields in the chain have allowed the request to proceed
- Shields are evaluated in order from top to bottom (outermost decorator to innermost) 