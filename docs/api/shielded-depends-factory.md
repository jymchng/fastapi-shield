# ShieldedDepends Function

The `ShieldedDepends` function is a factory for creating `ShieldDepends` instances, providing a clean interface for dependency injection with shield integration.

## Overview

`ShieldedDepends` is the recommended way to create shield-aware dependencies. It provides a convenient interface similar to FastAPI's `Depends()`, but with the added capability of receiving data from shield validation.

## Function Reference

::: fastapi_shield.shield.ShieldedDepends
    options:
      show_root_heading: false
      show_source: false
      heading_level: 3
      docstring_style: google
      docstring_options:
        ignore_init_summary: false

## Basic Usage

### Simple Dependency

```python
from fastapi import FastAPI, Request
from fastapi_shield import shield, ShieldedDepends

app = FastAPI()

@shield
def auth_shield(request: Request) -> dict | None:
    """Validate authentication and return user data."""
    token = request.headers.get("Authorization")
    if validate_token(token):
        return {"user_id": 123, "username": "john_doe"}
    return None

def get_current_user(user_data: dict) -> dict:
    """Transform shield data into user object."""
    return {
        "id": user_data["user_id"],
        "username": user_data["username"],
        "is_authenticated": True
    }

@app.get("/profile")
@auth_shield
def get_profile(user: dict = ShieldedDepends(get_current_user)):
    return {"profile": user}
```

### With Database Integration

```python
from sqlalchemy.orm import Session
from fastapi import Depends

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_user_from_db(
    user_data: dict,  # Shield data
    db: Session = Depends(get_db)  # Regular dependency
) -> User:
    """Fetch user from database using shield data."""
    user_id = user_data["user_id"]
    return db.query(User).filter(User.id == user_id).first()

@app.get("/profile")
@auth_shield
def get_profile(user: User = ShieldedDepends(get_user_from_db)):
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email
    }
```

## Configuration Options

### Auto Error Handling

```python
# Default: raises exceptions on error
user_dep = ShieldedDepends(get_current_user)

# Custom: returns default responses instead of raising exceptions
user_dep_no_error = ShieldedDepends(
    get_current_user,
    auto_error=False
)

@app.get("/profile")
@auth_shield
def get_profile(user: User = user_dep_no_error):
    if isinstance(user, ShieldDepends):  # Validation failed
        return {"error": "Authentication required"}
    return {"profile": user.to_dict()}
```

### OAuth2 Scopes

```python
def get_admin_user(user_data: dict, db: Session = Depends(get_db)) -> User:
    """Get user with admin privileges."""
    user = db.query(User).filter(User.id == user_data["user_id"]).first()
    if not user or not user.is_admin:
        raise HTTPException(403, "Admin privileges required")
    return user

# Dependency with OAuth2 scopes
admin_user_dep = ShieldedDepends(
    get_admin_user,
    scopes=["admin", "write"]
)

@app.get("/admin/users")
@auth_shield
def list_users(admin: User = admin_user_dep):
    return {"users": get_all_users()}
```

### Caching

```python
def expensive_user_computation(
    user_data: dict,
    db: Session = Depends(get_db),
    cache: Redis = Depends(get_redis)
) -> dict:
    """Expensive computation with caching."""
    user_id = user_data["user_id"]
    
    # This result will be cached by FastAPI
    result = perform_expensive_computation(user_id, db)
    return result

# Enable caching for expensive operations
cached_user_dep = ShieldedDepends(
    expensive_user_computation,
    use_cache=True  # Default is True
)

@app.get("/expensive-operation")
@auth_shield
def expensive_endpoint(result: dict = cached_user_dep):
    return {"result": result}
```

## Advanced Patterns

### Multiple Shield Dependencies

```python
@shield
def auth_shield(request: Request) -> dict | None:
    # Authentication logic
    return {"user_id": 123, "role": "user"}

@shield  
def permission_shield(request: Request) -> dict | None:
    # Permission logic
    return {"permissions": ["read", "write"]}

def get_auth_context(auth_data: dict) -> dict:
    return {"user_id": auth_data["user_id"], "role": auth_data["role"]}

def get_permission_context(permission_data: dict) -> dict:
    return {"permissions": permission_data["permissions"]}

@app.get("/protected-resource")
@auth_shield
@permission_shield
def protected_endpoint(
    auth: dict = ShieldedDepends(get_auth_context),
    perms: dict = ShieldedDepends(get_permission_context)
):
    return {
        "message": "Access granted",
        "user": auth,
        "permissions": perms
    }
```

### Conditional Dependencies

```python
def get_user_or_anonymous(
    # No first parameter = optional shield data
    request: Request,
    db: Session = Depends(get_db)
) -> dict:
    """Dependency that works with or without authentication."""
    # This will receive shield data if available, or work without it
    return {"user": None, "is_anonymous": True}

def get_authenticated_user(
    user_data: dict,  # Required shield data
    db: Session = Depends(get_db)
) -> User:
    """Dependency that requires authentication."""
    return db.query(User).filter(User.id == user_data["user_id"]).first()

# Optional authentication
flexible_dep = ShieldedDepends(get_user_or_anonymous)

# Required authentication  
required_dep = ShieldedDepends(get_authenticated_user)

@app.get("/flexible")
@auth_shield  # May succeed or fail
def flexible_endpoint(context: dict = flexible_dep):
    return context

@app.get("/required")
@auth_shield  # Must succeed
def required_endpoint(user: User = required_dep):
    return {"user": user.username}
```

### Error Handling Patterns

```python
def robust_user_dependency(
    user_data: dict,
    db: Session = Depends(get_db)
) -> User:
    """User dependency with comprehensive error handling."""
    try:
        user_id = user_data.get("user_id")
        if not user_id:
            raise HTTPException(400, "User ID not found in shield data")
        
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(404, f"User {user_id} not found")
        
        if not user.is_active:
            raise HTTPException(403, "User account is disabled")
        
        return user
    
    except Exception as e:
        # Log error for debugging
        logger.error(f"Error in user dependency: {e}")
        raise

robust_user_dep = ShieldedDepends(robust_user_dependency)
```

### Factory Pattern

```python
def create_user_dependency(user_type: str):
    """Factory for creating type-specific user dependencies."""
    
    def get_typed_user(
        user_data: dict,
        db: Session = Depends(get_db)
    ) -> User:
        user = db.query(User).filter(User.id == user_data["user_id"]).first()
        if user.type != user_type:
            raise HTTPException(403, f"User must be of type {user_type}")
        return user
    
    return ShieldedDepends(get_typed_user)

# Create specific dependencies
admin_user_dep = create_user_dependency("admin")
regular_user_dep = create_user_dependency("regular")

@app.get("/admin/dashboard")
@auth_shield
def admin_dashboard(admin: User = admin_user_dep):
    return {"dashboard": "admin_data"}

@app.get("/user/profile")
@auth_shield
def user_profile(user: User = regular_user_dep):
    return {"profile": user.to_dict()}
```

## Performance Optimization

### Connection Pooling

```python
@lru_cache()
def get_database_pool():
    """Cached database connection pool."""
    return create_connection_pool()

def optimized_user_dependency(
    user_data: dict,
    pool = Depends(get_database_pool)
) -> User:
    """Optimized user lookup with connection pooling."""
    with pool.get_connection() as conn:
        return fetch_user_optimized(conn, user_data["user_id"])

optimized_user_dep = ShieldedDepends(
    optimized_user_dependency,
    use_cache=True  # Cache the result
)
```

### Batch Operations

```python
def batch_user_dependency(
    user_data: dict,
    db: Session = Depends(get_db)
) -> dict:
    """Fetch multiple related objects in a single query."""
    user_id = user_data["user_id"]
    
    # Batch fetch user, profile, and permissions
    result = db.execute(
        """
        SELECT u.*, p.*, perm.*
        FROM users u
        LEFT JOIN profiles p ON u.id = p.user_id
        LEFT JOIN permissions perm ON u.id = perm.user_id
        WHERE u.id = :user_id
        """,
        {"user_id": user_id}
    ).fetchone()
    
    return {
        "user": result.user_data,
        "profile": result.profile_data,
        "permissions": result.permission_data
    }

batch_dep = ShieldedDepends(batch_user_dependency, use_cache=True)
```

## Integration Examples

### With Pydantic Models

```python
from pydantic import BaseModel

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    is_active: bool

def get_user_response(
    user_data: dict,
    db: Session = Depends(get_db)
) -> UserResponse:
    """Return Pydantic model for type safety."""
    user = db.query(User).filter(User.id == user_data["user_id"]).first()
    return UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        is_active=user.is_active
    )

typed_user_dep = ShieldedDepends(get_user_response)

@app.get("/profile", response_model=dict)
@auth_shield
def get_profile(user: UserResponse = typed_user_dep):
    return {"profile": user.model_dump()}
```

### With Background Tasks

```python
from fastapi import BackgroundTasks

def user_with_background_tasks(
    user_data: dict,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
) -> User:
    """User dependency that schedules background tasks."""
    user = db.query(User).filter(User.id == user_data["user_id"]).first()
    
    # Schedule background task to update last login
    background_tasks.add_task(update_last_login, user.id)
    
    return user

task_user_dep = ShieldedDepends(user_with_background_tasks)
```

## Best Practices

1. **Type Annotations** - Always use proper type hints for better IDE support
2. **Error Handling** - Handle all possible error scenarios gracefully
3. **Performance** - Use caching for expensive operations
4. **Security** - Validate all data received from shields
5. **Documentation** - Document what shield data the dependency expects
6. **Testing** - Write comprehensive tests for dependency functions

## See Also

- [ShieldDepends Class](shield-depends.md) - The underlying class
- [Dependency Injection Guide](../advanced-topics/dependency-injection.md) - Advanced patterns
- [Authentication Patterns](../user-guide/authentication-patterns.md) - Common use cases 