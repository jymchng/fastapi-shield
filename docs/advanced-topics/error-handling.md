# Advanced Error Handling

This guide covers advanced error handling techniques for FastAPI Shield, allowing you to create robust APIs that gracefully handle exceptions and provide meaningful error responses.

## Custom Exception Classes

Create custom exception classes for different error scenarios:

```python
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi_shield import shield, ShieldedDepends
from typing import Optional, Dict, Any

class ShieldValidationError(Exception):
    def __init__(
        self, 
        status_code: int = 400, 
        detail: str = "Validation error", 
        field: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        self.status_code = status_code
        self.detail = detail
        self.field = field
        self.metadata = metadata or {}
        super().__init__(self.detail)

class AuthenticationError(Exception):
    def __init__(self, detail: str = "Authentication failed"):
        self.status_code = 401
        self.detail = detail
        super().__init__(self.detail)

class PermissionDeniedError(Exception):
    def __init__(self, detail: str = "Permission denied"):
        self.status_code = 403
        self.detail = detail
        super().__init__(self.detail)

class ResourceNotFoundError(Exception):
    def __init__(self, resource_type: str, resource_id: Any):
        self.status_code = 404
        self.detail = f"{resource_type} with id {resource_id} not found"
        self.resource_type = resource_type
        self.resource_id = resource_id
        super().__init__(self.detail)
```

## Global Exception Handlers

Register global exception handlers to transform your custom exceptions into appropriate responses:

```python
app = FastAPI()

@app.exception_handler(ShieldValidationError)
async def validation_exception_handler(request: Request, exc: ShieldValidationError):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "detail": exc.detail,
            "field": exc.field,
            **exc.metadata
        },
    )

@app.exception_handler(AuthenticationError)
async def authentication_exception_handler(request: Request, exc: AuthenticationError):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )

@app.exception_handler(PermissionDeniedError)
async def permission_exception_handler(request: Request, exc: PermissionDeniedError):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )

@app.exception_handler(ResourceNotFoundError)
async def not_found_exception_handler(request: Request, exc: ResourceNotFoundError):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "detail": exc.detail,
            "resource_type": exc.resource_type,
            "resource_id": exc.resource_id
        },
    )
```

## Exception-Aware Shields

Create shields that use your custom exceptions for better error handling:

```python
@shield(name="ValidateUser")
def validate_user(user_id: int):
    # Simulate database lookup
    if user_id <= 0:
        raise ShieldValidationError(
            detail="User ID must be positive",
            field="user_id",
            metadata={"received_value": user_id}
        )
    
    # Simulate user not found
    if user_id > 1000:
        raise ResourceNotFoundError("User", user_id)
    
    return {"id": user_id, "name": f"User {user_id}"}

@shield(name="RequireAdmin")
def require_admin(user: dict = ShieldedDepends(validate_user)):
    # Check if user has admin role
    if user.get("role") != "admin":
        raise PermissionDeniedError(f"User {user['id']} is not an admin")
    return user

@app.get("/admin/{user_id}")
@require_admin
async def admin_endpoint(user_id: int):
    return {"message": "Admin access granted"}
```

## Error Handling with Shield Pipelines

Create reusable error handling components for shield pipelines:

```python
from typing import Callable, Any, Type, Dict, Optional
from functools import wraps

def with_error_handling(
    shield_func: Callable,
    exceptions_map: Dict[Type[Exception], Callable[[Exception], Exception]] = None
):
    """
    Wraps a shield function with error handling logic
    """
    exceptions_map = exceptions_map or {}
    
    @wraps(shield_func)
    def wrapper(*args, **kwargs):
        try:
            return shield_func(*args, **kwargs)
        except Exception as e:
            # Check if we have a mapping for this exception type
            for exc_type, handler in exceptions_map.items():
                if isinstance(e, exc_type):
                    # Transform the exception
                    raise handler(e)
            # Re-raise if no handler found
            raise
    
    return wrapper

# Example usage
@shield(name="ValidateItemWithErrorHandling")
def validate_item_with_handling(item_id: int):
    return with_error_handling(
        validate_item,
        {
            ValueError: lambda e: ShieldValidationError(detail=str(e), field="item_id"),
            KeyError: lambda e: ResourceNotFoundError("Item", str(e))
        }
    )(item_id)

def validate_item(item_id: int):
    if item_id <= 0:
        raise ValueError("Item ID must be positive")
    
    # Simulate item lookup
    if item_id > 100:
        raise KeyError(item_id)
        
    return {"id": item_id, "name": f"Item {item_id}"}
```

## Context-Aware Error Handling

Create shields that provide context for error handling:

```python
from contextvars import ContextVar
from typing import Dict, Any, Optional

# Context variable to store request context
request_context: ContextVar[Dict[str, Any]] = ContextVar("request_context", default={})

@shield(name="SetRequestContext")
def set_request_context(request: Request):
    # Store relevant information from the request
    context = {
        "path": request.url.path,
        "method": request.method,
        "client_ip": request.client.host if request.client else None,
        "request_id": request.headers.get("X-Request-ID", "unknown"),
        "user_agent": request.headers.get("User-Agent", "unknown"),
    }
    token = request_context.set(context)
    return context

# Exception handler that uses the context
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    # Get the current context
    context = request_context.get()
    
    # Log the error with context
    logger.error(
        f"Error handling request: {exc}",
        extra={
            "exception": type(exc).__name__,
            "message": str(exc),
            **context
        }
    )
    
    # Return appropriate response based on exception type
    if isinstance(exc, HTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
        )
    
    # For unhandled exceptions, return 500 with request ID for troubleshooting
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error",
            "request_id": context.get("request_id", "unknown")
        },
    )

# Apply the context middleware to all endpoints
@app.middleware("http")
async def add_request_context(request: Request, call_next):
    # Set the context
    context = set_request_context(request)
    
    try:
        # Process the request
        response = await call_next(request)
        return response
    except Exception as e:
        # Let the exception handler deal with it
        raise
    finally:
        # Clean up
        request_context.set({})
```

## Validation Chains with Custom Error Accumulation

Create shields that accumulate multiple validation errors:

```python
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, ValidationError

class ValidationResult(BaseModel):
    valid: bool
    errors: List[Dict[str, Any]] = []

@shield(name="ValidateMultiple")
def validate_multiple(data: Dict[str, Any]):
    result = ValidationResult(valid=True)
    
    # Validate field 1
    if "field1" not in data:
        result.valid = False
        result.errors.append({
            "field": "field1",
            "error": "Field is required"
        })
    elif not isinstance(data["field1"], str):
        result.valid = False
        result.errors.append({
            "field": "field1",
            "error": "Must be a string",
            "value": data["field1"]
        })
    
    # Validate field 2
    if "field2" not in data:
        result.valid = False
        result.errors.append({
            "field": "field2",
            "error": "Field is required"
        })
    elif not isinstance(data["field2"], int) or data["field2"] <= 0:
        result.valid = False
        result.errors.append({
            "field": "field2",
            "error": "Must be a positive integer",
            "value": data.get("field2")
        })
    
    # If validation failed, raise an error with all validation issues
    if not result.valid:
        raise ShieldValidationError(
            detail="Multiple validation errors",
            metadata={"errors": result.errors}
        )
    
    return data
```

## Hierarchical Error Handling

Implement hierarchical error handling with shield dependencies:

```python
@shield(name="ValidateItemParent")
def validate_item_parent(parent_id: int):
    if parent_id <= 0:
        raise ShieldValidationError(detail="Parent ID must be positive", field="parent_id")
    
    # Simulate parent lookup
    if parent_id > 100:
        raise ResourceNotFoundError("Parent", parent_id)
    
    return {"id": parent_id, "name": f"Parent {parent_id}"}

@shield(name="ValidateItemChild")
def validate_item_child(child_id: int, parent: dict = ShieldedDepends(validate_item_parent)):
    # Parent validation errors will bubble up automatically
    
    if child_id <= 0:
        raise ShieldValidationError(detail="Child ID must be positive", field="child_id")
    
    # Validate that child belongs to parent
    if child_id > 10:  # Simplified check
        raise ShieldValidationError(
            detail=f"Child {child_id} does not belong to parent {parent['id']}",
            field="child_id",
            metadata={"parent_id": parent["id"]}
        )
    
    return {"id": child_id, "parent_id": parent["id"], "name": f"Child {child_id}"}

@app.get("/parents/{parent_id}/children/{child_id}")
@validate_item_child
async def get_child_item(parent_id: int, child_id: int):
    return {"message": "Child item found", "child_id": child_id, "parent_id": parent_id}
```

## Recoverable Errors

Create shields that can recover from certain errors:

```python
@shield(name="TryConvertToInt")
def try_convert_to_int(value: str):
    try:
        return int(value)
    except ValueError:
        # Instead of failing, return a default value
        return 0

@shield(name="FallbackShield")
def fallback_shield(primary_param: Optional[str] = None, fallback_param: Optional[str] = None):
    if primary_param is not None:
        try:
            # Try to use the primary parameter
            return process_parameter(primary_param)
        except Exception as e:
            # Log the error but don't fail
            logger.warning(f"Failed to process primary parameter: {e}")
    
    # Fall back to the secondary parameter
    if fallback_param is not None:
        return process_parameter(fallback_param)
    
    # If all else fails, use a default
    return {"status": "default", "value": "default_value"}

def process_parameter(param: str):
    # Implementation
    return {"status": "processed", "value": param}
```

## Transaction Rollback Pattern

Implement transaction-like behavior with shields:

```python
from contextlib import contextmanager
from typing import Generator, Any, Optional

@contextmanager
def transaction_context() -> Generator[Dict[str, Any], None, None]:
    """Context manager to simulate a transaction"""
    # Initialize transaction state
    state = {"committed": False, "resources": []}
    
    try:
        # Yield the state for operations
        yield state
        # Mark as successfully committed if we get here
        state["committed"] = True
    finally:
        # Clean up resources if not committed
        if not state["committed"]:
            for cleanup_func in state["resources"]:
                try:
                    cleanup_func()
                except Exception as e:
                    # Log but don't re-raise
                    logger.error(f"Error during transaction cleanup: {e}")

@shield(name="TransactionalOperation")
def transactional_operation(item_id: int):
    with transaction_context() as tx:
        # Simulate resource allocation
        resource = allocate_resource(item_id)
        
        # Register cleanup function
        def cleanup():
            deallocate_resource(resource)
        
        tx["resources"].append(cleanup)
        
        # Perform operation that might fail
        if item_id > 100:
            raise ValueError("Operation failed")
        
        # Success - don't roll back
        return {"id": item_id, "resource": resource}

def allocate_resource(item_id: int) -> str:
    # Simulate resource allocation
    return f"resource_{item_id}"

def deallocate_resource(resource: str):
    # Simulate resource cleanup
    logger.info(f"Deallocated {resource}")
```

## Error Boundary Pattern

Implement error boundaries to isolate failures:

```python
from typing import Callable, Any, Optional, Dict, List, Type

def error_boundary(
    shield_func: Callable,
    fallback_value: Any = None,
    catch_exceptions: List[Type[Exception]] = None,
    error_callback: Optional[Callable[[Exception], None]] = None
):
    """
    Creates an error boundary around a shield function
    """
    catch_exceptions = catch_exceptions or [Exception]
    
    @wraps(shield_func)
    def wrapper(*args, **kwargs):
        try:
            return shield_func(*args, **kwargs)
        except Exception as e:
            # Check if we should catch this exception
            if not any(isinstance(e, exc_type) for exc_type in catch_exceptions):
                raise
            
            # Call the error callback if provided
            if error_callback:
                error_callback(e)
            
            # Return the fallback value
            return fallback_value
    
    return wrapper

# Example usage
@shield(name="UserProfile")
def get_user_profile(user_id: int):
    # Wrap the potentially failing operation in an error boundary
    profile = error_boundary(
        fetch_user_profile,
        fallback_value={"id": user_id, "name": "Unknown", "is_default": True},
        catch_exceptions=[ResourceNotFoundError, ConnectionError],
        error_callback=lambda e: logger.warning(f"Error fetching profile for user {user_id}: {e}")
    )(user_id)
    
    return profile

def fetch_user_profile(user_id: int):
    # This might raise various exceptions
    if user_id <= 0:
        raise ValueError("Invalid user ID")
    if user_id > 1000:
        raise ResourceNotFoundError("User", user_id)
    if user_id == 999:
        raise ConnectionError("Database connection failed")
    
    return {"id": user_id, "name": f"User {user_id}", "email": f"user{user_id}@example.com"}
```

## Pluggable Error Handling Framework

Create a flexible error handling framework:

```python
from typing import Dict, Type, Callable, Any, List, Optional
from pydantic import BaseModel

# Define a registry for error handlers
error_handlers: Dict[Type[Exception], List[Callable]] = {}

def register_error_handler(exception_type: Type[Exception], handler: Callable):
    """Register a handler for a specific exception type"""
    if exception_type not in error_handlers:
        error_handlers[exception_type] = []
    error_handlers[exception_type].append(handler)

def handle_exception(exc: Exception) -> Optional[Any]:
    """
    Process an exception through all registered handlers
    Returns a response if handled, or None if not handled
    """
    for exc_type, handlers in error_handlers.items():
        if isinstance(exc, exc_type):
            for handler in handlers:
                result = handler(exc)
                if result is not None:
                    return result
    return None

# Example error handlers
def log_validation_errors(exc: ShieldValidationError):
    logger.warning(
        f"Validation error: {exc.detail}",
        extra={"field": exc.field, **exc.metadata}
    )
    # Not returning anything means we don't handle the response

def convert_not_found_to_response(exc: ResourceNotFoundError):
    # Return a customized response
    return JSONResponse(
        status_code=404,
        content={
            "error": "not_found",
            "message": exc.detail,
            "resource": {
                "type": exc.resource_type,
                "id": exc.resource_id
            }
        }
    )

# Register the handlers
register_error_handler(ShieldValidationError, log_validation_errors)
register_error_handler(ResourceNotFoundError, convert_not_found_to_response)

# Use in a middleware
@app.middleware("http")
async def error_handling_middleware(request: Request, call_next):
    try:
        return await call_next(request)
    except Exception as exc:
        # Try to handle the exception
        response = handle_exception(exc)
        if response is not None:
            return response
        
        # If not handled, re-raise
        raise
```

## Structured Error Responses

Create consistent error response formats:

```python
from enum import Enum
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List, Union

class ErrorCode(str, Enum):
    VALIDATION_ERROR = "validation_error"
    NOT_FOUND = "not_found"
    PERMISSION_DENIED = "permission_denied"
    AUTHENTICATION_FAILED = "authentication_failed"
    INVALID_REQUEST = "invalid_request"
    INTERNAL_ERROR = "internal_error"

class ErrorDetail(BaseModel):
    code: ErrorCode
    message: str
    target: Optional[str] = None
    details: Optional[List["ErrorDetail"]] = None
    metadata: Optional[Dict[str, Any]] = None

class ErrorResponse(BaseModel):
    error: ErrorDetail
    request_id: Optional[str] = None
    
    class Config:
        schema_extra = {
            "example": {
                "error": {
                    "code": "validation_error",
                    "message": "Validation failed",
                    "target": "email",
                    "details": [
                        {
                            "code": "validation_error",
                            "message": "Email must be a valid email address",
                            "target": "email"
                        }
                    ]
                },
                "request_id": "req-12345"
            }
        }

# Use the structured error response in exception handlers
@app.exception_handler(ShieldValidationError)
async def structured_validation_exception_handler(request: Request, exc: ShieldValidationError):
    detail = ErrorDetail(
        code=ErrorCode.VALIDATION_ERROR,
        message=exc.detail,
        target=exc.field,
        metadata=exc.metadata
    )
    
    response = ErrorResponse(
        error=detail,
        request_id=request.headers.get("X-Request-ID")
    )
    
    return JSONResponse(
        status_code=exc.status_code,
        content=response.dict(exclude_none=True)
    )
```

## Error Translation for Internationalization

Implement error message translation:

```python
from typing import Dict, Optional, Callable
import gettext

# Simplified i18n setup
translations: Dict[str, gettext.GNUTranslations] = {}

def load_translations():
    # Load translations for different languages
    for lang in ["en", "es", "fr"]:
        translations[lang] = gettext.translation(
            "messages", 
            localedir="./locales", 
            languages=[lang],
            fallback=True
        )

# Translation function
def translate(message: str, lang: str = "en") -> str:
    if lang not in translations:
        return message
    
    return translations[lang].gettext(message)

@shield(name="LocalizedErrorHandler")
def localized_error_handler(request: Request):
    # Get preferred language from headers
    accept_language = request.headers.get("Accept-Language", "en")
    lang = accept_language.split(",")[0].strip().split("-")[0]
    
    # Store the language preference for use in exception handlers
    request.state.lang = lang
    
    return {"language": lang}

# Exception handler with i18n support
@app.exception_handler(ShieldValidationError)
async def i18n_validation_exception_handler(request: Request, exc: ShieldValidationError):
    # Get language preference
    lang = getattr(request.state, "lang", "en")
    
    # Translate the error message
    translated_message = translate(exc.detail, lang)
    
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "detail": translated_message,
            "field": exc.field,
            **exc.metadata
        },
    )
```

## Best Practices for Error Handling in FastAPI Shield

1. **Use custom exception classes** that extend from Python's built-in exceptions to create domain-specific errors.

2. **Create global exception handlers** for consistent error responses across your API.

3. **Include contextual information** in your error responses to help clients understand and fix the issue.

4. **Avoid exposing sensitive information** in error messages, especially for production environments.

5. **Layer your error handling** to allow both broad catches and specific handling.

6. **Use appropriate HTTP status codes** based on the type of error.

7. **Consider internationalization** for user-facing error messages.

8. **Include request identifiers** in error responses to help with troubleshooting.

9. **Log detailed error information** server-side while keeping client responses concise.

10. **Implement graceful degradation** with fallbacks for non-critical errors.

These advanced error handling techniques will help you build more robust APIs that gracefully handle exceptions and provide users with helpful, actionable error messages. 