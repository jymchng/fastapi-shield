# ShieldDepends Class

The `ShieldDepends` class enables shield-validated data to be injected into FastAPI endpoints as dependencies, providing seamless integration with FastAPI's dependency injection system.

## Overview

`ShieldDepends` is a dependency wrapper that integrates shields with FastAPI's dependency injection. It allows endpoints to receive shield-validated data through the standard dependency injection mechanism, making it easy to access authenticated user data, validated permissions, or any other shield-processed information.

## Class Reference

::: fastapi_shield.shield.ShieldDepends
    options:
      members:
        - __init__
        - first_param
        - rest_params
        - __call__
        - __bool__
        - __signature__
        - resolve_dependencies
        - _as_unblocked
      show_root_heading: false
      show_source: false
      heading_level: 3
      show_bases: true
      show_inheritance_diagram: false
      merge_init_into_class: false
      docstring_style: google
      docstring_options:
        ignore_init_summary: false
      filters:
        - "!^_"
        - "^__init__$"
        - "^first_param$"
        - "^rest_params$"
        - "^__call__$"
        - "^__bool__$"
        - "^__signature__$"
        - "^resolve_dependencies$"
        - "^_as_unblocked$"

## Lifecycle

The `ShieldDepends` lifecycle follows these stages:

1. **Initialization** - Created as blocked (`unblocked=False`)
2. **Shield Validation** - Shield runs and validates request
3. **Dependency Resolution** - Dependencies are resolved using FastAPI's DI
4. **Unblocking** - Temporarily unblocked for function execution
5. **Execution** - Dependency function called with shield data
6. **Re-blocking** - Automatically re-blocked for security

## Usage Examples

### Basic Authentication Dependency

```python
from fastapi import FastAPI, Request, Depends
from fastapi_shield import shield, ShieldDepends

app = FastAPI()

@shield
def auth_shield(request: Request) -> dict | None:
    """Validate JWT token and return user data."""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user_data = validate_jwt_token(token)
    if user_data:
        return {"user_id": user_data["sub"], "username": user_data["username"]}
    return None

def get_current_user(user_data: dict) -> dict:
    """Convert shield data to user object."""
    return {
        "id": user_data["user_id"],
        "username": user_data["username"],
        "is_authenticated": True
    }

@app.get("/profile")
@auth_shield
def get_profile(current_user: dict = ShieldDepends(get_current_user)):
    return {"profile": current_user}
```

### Database Integration

```python
from sqlalchemy.orm import Session

def get_db() -> Session:
    """Get database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_user_from_db(
    user_data: dict,  # Receives shield data
    db: Session = Depends(get_db)  # Regular dependency
) -> User:
    """Get user object from database using shield data."""
    user_id = user_data["user_id"]
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "User not found")
    return user

@app.get("/profile")
@auth_shield
def get_profile(user: User = ShieldDepends(get_user_from_db)):
    return {"username": user.username, "email": user.email}
```

### Complex Dependencies with Multiple Shields

```python
@shield
def auth_shield(request: Request) -> dict | None:
    """Authentication shield."""
    # Auth logic
    return {"user_id": 123, "role": "admin"}

@shield  
def permission_shield(request: Request) -> dict | None:
    """Permission check shield."""
    # Permission logic
    return {"permissions": ["read", "write", "admin"]}

def get_user_with_permissions(
    auth_data: dict,  # From auth_shield
    db: Session = Depends(get_db)
) -> dict:
    """Get user with authentication data."""
    return {"user": get_user(auth_data["user_id"]), "role": auth_data["role"]}

def get_permission_context(
    permission_data: dict,  # From permission_shield
    cache: Redis = Depends(get_redis)
) -> dict:
    """Get permission context."""
    return {"permissions": permission_data["permissions"]}

@app.get("/admin/data")
@auth_shield
@permission_shield  
def get_admin_data(
    user_context: dict = ShieldDepends(get_user_with_permissions),
    perm_context: dict = ShieldDepends(get_permission_context)
):
    return {
        "user": user_context,
        "permissions": perm_context,
        "data": "sensitive admin data"
    }
```

### Optional Shield Data

```python
def optional_user_dependency(
    # No first parameter means shield data is optional
    db: Session = Depends(get_db),
    cache: Redis = Depends(get_redis)
) -> dict:
    """Dependency that works with or without shield data."""
    return {"anonymous": True, "db": db, "cache": cache}

@app.get("/public-or-private")
@auth_shield  # May pass or fail
def flexible_endpoint(
    context: dict = ShieldDepends(optional_user_dependency)
):
    if context.get("anonymous"):
        return {"message": "Public access", "user": None}
    else:
        return {"message": "Authenticated access", "user": context.get("user")}
```

### Custom Error Handling

```python
def get_user_with_error_handling(
    user_data: dict,
    db: Session = Depends(get_db)
) -> User:
    """Get user with custom error handling."""
    try:
        user_id = user_data["user_id"]
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(404, f"User {user_id} not found")
        return user
    except KeyError:
        raise HTTPException(400, "Invalid user data from shield")

# Use with auto_error=False for custom responses
user_dep = ShieldDepends(get_user_with_error_handling, auto_error=False)

@app.get("/profile")
@auth_shield
def get_profile(user: User = user_dep):
    return {"profile": user.to_dict()}
```

## Integration Patterns

### With OAuth2 Scopes

```python
from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_user_with_scopes(
    token_data: dict,
    db: Session = Depends(get_db)
) -> User:
    """Get user with OAuth2 scope validation."""
    user = get_user_by_id(db, token_data["user_id"])
    # Scope validation can be done here or in the shield
    return user

# ShieldDepends with OAuth2 scopes
admin_user_dep = ShieldDepends(
    get_user_with_scopes,
    scopes=["admin"]
)

@app.get("/admin/users")
@auth_shield
def get_all_users(admin: User = admin_user_dep):
    return {"users": get_all_users_from_db()}
```

### Caching Integration

```python
def get_cached_user(
    user_data: dict,
    cache: Redis = Depends(get_redis),
    db: Session = Depends(get_db)
) -> User:
    """Get user with caching."""
    user_id = user_data["user_id"]
    
    # Try cache first
    cached_user = cache.get(f"user:{user_id}")
    if cached_user:
        return User.parse_raw(cached_user)
    
    # Fallback to database
    user = db.query(User).filter(User.id == user_id).first()
    if user:
        cache.setex(f"user:{user_id}", 300, user.json())  # 5 min cache
    return user

# Use caching with ShieldDepends
cached_user_dep = ShieldDepends(get_cached_user, use_cache=True)
```

## Security Considerations

- **Always start blocked**: `ShieldDepends` instances start in a blocked state for security
- **Automatic re-blocking**: After execution, dependencies are automatically re-blocked
- **Shield validation required**: Dependencies only execute after successful shield validation
- **Error propagation**: Validation errors are properly propagated to FastAPI's error handling

## Performance Tips

- Use `use_cache=True` for expensive dependency calculations
- Keep dependency functions lightweight
- Use async dependencies for I/O operations
- Consider connection pooling for database dependencies

## See Also

- [Shield Class](shield.md) - The main shield decorator
- [ShieldedDepends Factory](shielded-depends-factory.md) - Convenient factory function
- [Dependency Injection Guide](../advanced-topics/dependency-injection.md) - Advanced patterns 