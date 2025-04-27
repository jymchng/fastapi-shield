# Troubleshooting

This guide provides solutions to common issues you might encounter when using FastAPI Shield.

## Common Shield Errors

### Shield Not Applied

**Symptom:** Your endpoint doesn't seem to be validating or transforming input despite having a shield applied.

**Solution:** Ensure you're applying shields properly as decorators:

```python
from fastapi import FastAPI
from fastapi_shield import shield, ShieldedDepends

app = FastAPI()

# Define the shield
@shield(name="ValidatePositiveID")
def validate_positive_id(id: int):
    if id <= 0:
        raise ValueError("ID must be positive")
    return id

# INCORRECT: Not using the shield
@app.get("/items/{item_id}")
async def get_item_wrong(item_id: int):
    return {"item_id": item_id}

# CORRECT: Using the shield as a decorator
@app.get("/items/{item_id}")
@validate_positive_id
async def get_item_correct(item_id: int):
    return {"item_id": item_id}
```

### Shield Dependency Not Injected

**Symptom:** Your shield is defined but not being injected properly into your endpoint.

**Solution:** Make sure you're using `ShieldedDepends` correctly:

```python
from fastapi import FastAPI, Depends
from fastapi_shield import shield, ShieldedDepends
from typing import Annotated

app = FastAPI()

@shield(name="GetCurrentUser")
def get_current_user(user_id: int = 0):
    # Simulate database lookup
    return {"id": user_id, "name": f"User {user_id}"}

# INCORRECT: Using Depends instead of ShieldedDepends
@app.get("/user/wrong")
async def get_user_wrong(user: dict = Depends(get_current_user)):
    return user

# CORRECT: Using ShieldedDepends
@app.get("/user/correct")
async def get_user_correct(user: dict = ShieldedDepends(get_current_user)):
    return user

# ALSO CORRECT: Using Annotated syntax (Python 3.9+)
@app.get("/user/annotated")
async def get_user_annotated(user: Annotated[dict, ShieldedDepends(get_current_user)]):
    return user
```

### Multiple Shield Composition Issues

**Symptom:** When combining multiple shields, they don't work as expected or in the right order.

**Solution:** Apply shields in the correct order, from innermost to outermost processing:

```python
from fastapi import FastAPI
from fastapi_shield import shield, ShieldedDepends

app = FastAPI()

@shield(name="ValidateID")
def validate_id(id: int):
    if id <= 0:
        raise ValueError("ID must be positive")
    return id

@shield(name="LogAccess")
def log_access(id: int):
    print(f"Accessing resource with ID: {id}")
    return id

# CORRECT: Order of decorators matters - innermost executes first
@app.get("/items/{item_id}")
@log_access     # Executes second
@validate_id    # Executes first
async def get_item(item_id: int):
    return {"item_id": item_id}
```

## Path Parameter Issues

### Path Parameter Type Conversion

**Symptom:** Your shield is raising errors because path parameters have incorrect types.

**Solution:** Remember that FastAPI handles path parameter type conversion before your shield runs:

```python
from fastapi import FastAPI, Path
from fastapi_shield import shield, ShieldedDepends

app = FastAPI()

@shield(name="ValidateID")
def validate_id(id: int):
    # By the time this executes, id is already converted to int by FastAPI
    print(f"ID type in shield: {type(id)}")
    if id <= 0:
        raise ValueError("ID must be positive")
    return id

# Use additional validation with Path if needed
@app.get("/items/{item_id}")
@validate_id
async def get_item(item_id: int = Path(..., gt=0)):
    return {"item_id": item_id}
```

### Missing Path Parameters

**Symptom:** Your shield can't access expected path parameters.

**Solution:** Make sure your shield function's parameter names match the path parameters exactly:

```python
from fastapi import FastAPI
from fastapi_shield import shield, ShieldedDepends

app = FastAPI()

# INCORRECT: Parameter name doesn't match path parameter
@shield(name="ValidateID")
def validate_wrong_param(user_id: int):  # Path has item_id but shield expects user_id
    if user_id <= 0:
        raise ValueError("ID must be positive")
    return user_id

# CORRECT: Parameter name matches path parameter
@shield(name="ValidateID")
def validate_correct_param(item_id: int):  # Name matches path parameter
    if item_id <= 0:
        raise ValueError("ID must be positive")
    return item_id

@app.get("/items/{item_id}")
@validate_correct_param
async def get_item(item_id: int):
    return {"item_id": item_id}
```

## Query Parameter Issues

### Optional Query Parameters

**Symptom:** Your shield raises errors when optional query parameters are not provided.

**Solution:** Use default values for optional parameters in your shield:

```python
from fastapi import FastAPI, Query
from fastapi_shield import shield, ShieldedDepends
from typing import Optional

app = FastAPI()

# CORRECT: Handle optional query parameter
@shield(name="ValidateLimit")
def validate_limit(limit: Optional[int] = None):
    if limit is not None and limit <= 0:
        raise ValueError("Limit must be positive")
    return limit or 10  # Default to 10 if not provided

@app.get("/items")
@validate_limit
async def list_items(limit: Optional[int] = None):
    # limit will be validated by the shield
    return {"limit": limit}
```

## Request Body Issues

### Complex Model Validation

**Symptom:** Your shield can't access nested fields in a Pydantic model or can't modify the model.

**Solution:** For complex models, consider using multiple shields or create a shield that returns a modified model:

```python
from fastapi import FastAPI
from fastapi_shield import shield, ShieldedDepends
from pydantic import BaseModel

class Item(BaseModel):
    name: str
    description: str = ""
    price: float
    tax: float = 0.0

app = FastAPI()

@shield(name="ProcessItem")
def process_item(item: Item):
    # Calculate total price with tax
    total_price = item.price + item.tax
    # Return a new model with the calculated total
    return Item(
        name=item.name,
        description=item.description,
        price=total_price,
        tax=0.0  # Tax already included in price
    )

@app.post("/items/")
@process_item
async def create_item(item: Item):
    return {"item": item}
```

## Authentication and Authorization Issues

### Shield Not Receiving Auth Headers

**Symptom:** Your authentication shield can't access the authorization header.

**Solution:** Use FastAPI's Request object to access headers:

```python
from fastapi import FastAPI, Request, HTTPException
from fastapi_shield import shield, ShieldedDepends

app = FastAPI()

@shield(name="ValidateToken")
def validate_token(request: Request):
    token = request.headers.get("Authorization")
    if not token or not token.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid token")
    
    # Strip "Bearer " prefix
    token = token[7:]
    
    # Validate token (replace with your actual validation logic)
    if token != "valid_token":
        raise HTTPException(status_code=401, detail="Invalid token")
    
    # Return user data or token payload
    return {"user_id": 123, "role": "admin"}

@app.get("/protected")
@validate_token
async def protected_route(user_data: dict):
    return {"message": "Access granted", "user": user_data}
```

### Role-Based Access Control Problems

**Symptom:** Role-based access control (RBAC) shields not working properly.

**Solution:** Ensure your authentication shield passes role information to the authorization shield:

```python
from fastapi import FastAPI, HTTPException, Depends
from fastapi_shield import shield, ShieldedDepends
from typing import List, Dict, Annotated

app = FastAPI()

# Authentication shield
@shield(name="Authenticate")
def authenticate(api_key: str = ""):
    if not api_key:
        raise HTTPException(status_code=401, detail="API key required")
    
    # In a real app, validate the API key against a database
    if api_key != "valid_key":
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    # Return user data including roles
    return {"user_id": 123, "roles": ["admin", "editor"]}

# Authorization shield
@shield(name="RequireRoles")
def require_roles(required_roles: List[str], user: Dict = ShieldedDepends(authenticate)):
    user_roles = set(user.get("roles", []))
    
    if not any(role in user_roles for role in required_roles):
        raise HTTPException(
            status_code=403,
            detail=f"Access denied. Required roles: {required_roles}"
        )
    
    return user

# Create specific role requirement shields
@shield(name="RequireAdmin")
def require_admin(user: Dict = ShieldedDepends(require_roles, required_roles=["admin"])):
    return user

@shield(name="RequireEditor")
def require_editor(user: Dict = ShieldedDepends(require_roles, required_roles=["editor"])):
    return user

# Admin-only endpoint
@app.get("/admin")
@require_admin
async def admin_route(user: dict):
    return {"message": "Admin access granted", "user": user}

# Editor-only endpoint
@app.get("/editor")
@require_editor
async def editor_route(user: dict):
    return {"message": "Editor access granted", "user": user}

# Requires either admin or editor
@app.get("/content")
@require_roles
async def content_route(
    user: Annotated[dict, ShieldedDepends(require_roles, required_roles=["admin", "editor"])]
):
    return {"message": "Content access granted", "user": user}
```

## Type Conversion Issues

### NewType Conversion Errors

**Symptom:** Your custom type shields are not converting values correctly.

**Solution:** Ensure your shield returns the exact type expected:

```python
from fastapi import FastAPI
from fastapi_shield import shield, ShieldedDepends
from typing import NewType, Dict, Any
from pydantic import BaseModel
import json

# Custom types
UserId = NewType("UserId", int)
UserData = NewType("UserData", Dict[str, Any])

app = FastAPI()

class User(BaseModel):
    id: UserId
    name: str
    age: int

@shield(name="ConvertToUserId")
def convert_to_user_id(id: int) -> UserId:
    if id <= 0:
        raise ValueError("User ID must be positive")
    # Explicitly cast to UserId
    return UserId(id)

@shield(name="FetchUserData")
def fetch_user_data(user_id: UserId) -> UserData:
    # Simulate database lookup
    user_data = {"id": user_id, "name": f"User {user_id}", "age": 30}
    # Explicitly cast to UserData
    return UserData(user_data)

@app.get("/users/{id}", response_model=User)
@fetch_user_data
@convert_to_user_id
async def get_user(id: int) -> User:
    # user_data will be of type UserData
    user_data = fetch_user_data(convert_to_user_id(id))
    return User(**user_data)
```

## Asynchronous Shields

### Mixing Async and Sync Shields

**Symptom:** Issues when mixing async and sync shields in the same endpoint.

**Solution:** Be consistent with async usage and use `await` properly:

```python
from fastapi import FastAPI
from fastapi_shield import shield, ShieldedDepends
import asyncio

app = FastAPI()

# Synchronous shield
@shield(name="ValidateSync")
def validate_sync(id: int):
    if id <= 0:
        raise ValueError("ID must be positive")
    return id

# Asynchronous shield
@shield(name="ValidateAsync")
async def validate_async(id: int):
    # Simulate async operation
    await asyncio.sleep(0.1)
    if id <= 0:
        raise ValueError("ID must be positive")
    return id

# CORRECT: Using both async and sync shields
@app.get("/items/{item_id}")
@validate_async
@validate_sync
async def get_item(item_id: int):
    return {"item_id": item_id}
```

### Async Dependency Chain

**Symptom:** Issues with complex chains of async dependencies.

**Solution:** Be careful with dependency order and await correctly:

```python
from fastapi import FastAPI, Depends
from fastapi_shield import shield, ShieldedDepends
import asyncio
from typing import Annotated

app = FastAPI()

@shield(name="AsyncDep1")
async def async_dep_1():
    await asyncio.sleep(0.1)
    return {"step": "dep1"}

@shield(name="AsyncDep2")
async def async_dep_2(dep1_result: dict = ShieldedDepends(async_dep_1)):
    await asyncio.sleep(0.1)
    result = dep1_result.copy()
    result.update({"step": "dep2"})
    return result

@shield(name="AsyncDep3")
async def async_dep_3(dep2_result: dict = ShieldedDepends(async_dep_2)):
    await asyncio.sleep(0.1)
    result = dep2_result.copy()
    result.update({"step": "dep3"})
    return result

@app.get("/async-chain")
async def async_chain(
    result: Annotated[dict, ShieldedDepends(async_dep_3)]
):
    return result
```

## Performance Issues

### Slow Shield Execution

**Symptom:** Endpoints with shields are significantly slower than expected.

**Solution:** Optimize your shields and consider caching for expensive operations:

```python
from fastapi import FastAPI, Depends
from fastapi_shield import shield, ShieldedDepends
import time
from functools import lru_cache

app = FastAPI()

# SLOW: Expensive operation on every request
@shield(name="SlowShield")
def slow_shield(id: int):
    # Simulate expensive operation
    time.sleep(1)  # Don't use time.sleep in production code
    return {"id": id, "computed": id * 100}

# BETTER: Using Python's lru_cache
@lru_cache(maxsize=100)
def cached_expensive_operation(id: int):
    # Simulate expensive operation
    time.sleep(1)  # Don't use time.sleep in production code
    return {"id": id, "computed": id * 100}

@shield(name="CachedShield")
def cached_shield(id: int):
    return cached_expensive_operation(id)

@app.get("/slow/{id}")
@slow_shield
async def slow_endpoint(id: int):
    return {"result": slow_shield(id)}

@app.get("/fast/{id}")
@cached_shield
async def fast_endpoint(id: int):
    return {"result": cached_shield(id)}
```

### Memory Leaks

**Symptom:** Application memory usage grows over time with shields.

**Solution:** Be careful with how you store data in shields and avoid global state:

```python
from fastapi import FastAPI, Depends
from fastapi_shield import shield, ShieldedDepends
import weakref

app = FastAPI()

# BAD: Global cache that can grow indefinitely
BAD_CACHE = {}

@shield(name="LeakyShield")
def leaky_shield(key: str):
    # This will grow indefinitely
    if key not in BAD_CACHE:
        BAD_CACHE[key] = f"Computed value for {key}"
    return BAD_CACHE[key]

# BETTER: Size-limited cache
from functools import lru_cache

@lru_cache(maxsize=100)
def limited_cache_func(key: str):
    return f"Computed value for {key}"

@shield(name="BetterShield")
def better_shield(key: str):
    return limited_cache_func(key)

@app.get("/leaky/{key}")
@leaky_shield
async def leaky_endpoint(key: str):
    return {"value": leaky_shield(key)}

@app.get("/better/{key}")
@better_shield
async def better_endpoint(key: str):
    return {"value": better_shield(key)}
```

## Integration with Other Libraries

### Pydantic Integration

**Symptom:** Issues integrating shield validation with Pydantic models.

**Solution:** Use shields that work with and return Pydantic models:

```python
from fastapi import FastAPI
from fastapi_shield import shield, ShieldedDepends
from pydantic import BaseModel, validator, Field

class Item(BaseModel):
    name: str
    price: float
    tax: float = 0.0
    
    @validator("price")
    def price_must_be_positive(cls, v):
        if v <= 0:
            raise ValueError("Price must be positive")
        return v

app = FastAPI()

@shield(name="EnrichItem")
def enrich_item(item: Item):
    # Calculate total with tax
    total = item.price * (1 + item.tax)
    
    # Create a new Item with updated data
    return Item(
        name=item.name,
        price=item.price,
        tax=item.tax,
        # You can add computed fields if your model supports them
    )

@app.post("/items/")
@enrich_item
async def create_item(item: Item):
    return {"item": item, "total_price": item.price * (1 + item.tax)}
```

### SQLAlchemy Integration

**Symptom:** Issues integrating shields with SQLAlchemy ORM.

**Solution:** Use shields with database dependencies:

```python
from fastapi import FastAPI, Depends, HTTPException
from fastapi_shield import shield, ShieldedDepends
from sqlalchemy.orm import Session
from typing import Annotated

# Assume these are defined elsewhere
from .database import SessionLocal, engine
from .models import User as DBUser
from .schemas import User, UserCreate

app = FastAPI()

# Database dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@shield(name="ValidateUserExists")
def validate_user_exists(user_id: int, db: Session = Depends(get_db)):
    user = db.query(DBUser).filter(DBUser.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@app.get("/users/{user_id}", response_model=User)
async def read_user(
    user: Annotated[DBUser, ShieldedDepends(validate_user_exists)]
):
    return user

@shield(name="CreateUser")
def create_user(user_data: UserCreate, db: Session = Depends(get_db)):
    db_user = DBUser(**user_data.dict())
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/users/", response_model=User)
async def create_user_endpoint(
    user: Annotated[DBUser, ShieldedDepends(create_user)]
):
    return user
```

## Debugging Tips

### Shield Tracing

To debug shield execution, add logging:

```python
import logging
from fastapi import FastAPI
from fastapi_shield import shield, ShieldedDepends

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("shield_debug")

app = FastAPI()

@shield(name="DebugShield")
def debug_shield(value: str):
    logger.debug(f"DebugShield called with value: {value}")
    result = value.upper()
    logger.debug(f"DebugShield returning: {result}")
    return result

@app.get("/debug/{value}")
@debug_shield
async def debug_endpoint(value: str):
    return {"original": value, "transformed": debug_shield(value)}
```

### Checking Shield Registration

To verify your shields are properly registered:

```python
from fastapi import FastAPI
from fastapi_shield import shield, ShieldedDepends

app = FastAPI()

# Define shields
@shield(name="Shield1")
def shield1(value: str):
    return value.upper()

@shield(name="Shield2")
def shield2(value: str):
    return value.lower()

# Add a route to inspect registered shields
@app.get("/shields")
async def list_shields():
    # This is a simplified example - actual implementation depends on how
    # FastAPI Shield tracks registered shields internally
    from fastapi_shield import _get_registered_shields  # Hypothetical function
    
    shields = _get_registered_shields()
    return {"registered_shields": shields}
```

## Advanced Troubleshooting

### Shield Dependency Cycles

**Symptom:** Circular dependencies between shields causing errors or infinite recursion.

**Solution:** Restructure your dependencies to avoid cycles:

```python
from fastapi import FastAPI, Depends
from fastapi_shield import shield, ShieldedDepends

app = FastAPI()

# BAD: Circular dependency
@shield(name="ShieldA")
def shield_a(value: str, dep_b: str = ShieldedDepends("shield_b")):
    return f"A({value}, {dep_b})"

@shield(name="ShieldB")
def shield_b(value: str, dep_a: str = ShieldedDepends("shield_a")):
    return f"B({value}, {dep_a})"  # This creates a circular dependency!

# BETTER: Proper hierarchy
@shield(name="BaseShield")
def base_shield(value: str):
    return f"Base({value})"

@shield(name="DerivedShield1")
def derived_shield1(value: str, base: str = ShieldedDepends(base_shield)):
    return f"Derived1({value}, {base})"

@shield(name="DerivedShield2")
def derived_shield2(value: str, base: str = ShieldedDepends(base_shield)):
    return f"Derived2({value}, {base})"

@app.get("/good/{value}")
@derived_shield1
async def good_endpoint(value: str):
    return {"result": derived_shield1(value)}
```

### Error Handling in Shields

**Symptom:** Errors in shields not being properly handled or propagated.

**Solution:** Use proper error handling within shields:

```python
from fastapi import FastAPI, HTTPException, Request
from fastapi_shield import shield, ShieldedDepends
from fastapi.responses import JSONResponse

app = FastAPI()

class ShieldError(Exception):
    def __init__(self, code: int, message: str):
        self.code = code
        self.message = message
        super().__init__(self.message)

@app.exception_handler(ShieldError)
async def shield_error_handler(request: Request, exc: ShieldError):
    return JSONResponse(
        status_code=exc.code,
        content={"shield_error": exc.message},
    )

@shield(name="ErrorHandlingShield")
def error_handling_shield(value: str):
    try:
        # Simulate an error
        if value == "error":
            raise ValueError("Simulation of an internal error")
        
        # Process normally
        return value.upper()
    except ValueError as e:
        # Convert to a ShieldError with appropriate status code
        raise ShieldError(code=400, message=str(e))

@app.get("/handle-error/{value}")
@error_handling_shield
async def handle_error_endpoint(value: str):
    return {"result": error_handling_shield(value)}
```

## Common Error Messages

Here are some common error messages you might encounter with FastAPI Shield and their solutions:

### "Shield not defined in the dependency injection system"

This typically means you've used a `ShieldedDepends` with a shield that isn't properly registered:

```python
# Make sure shields are properly decorated with @shield
@shield(name="MyShield")  # Ensure this decorator is present
def my_shield(value: str):
    return value
```

### "Multiple shields returned different values for the same parameter"

This can happen when multiple shields modify the same parameter and return different values:

```python
# Shield order matters - the innermost shield runs first
@app.get("/items/{item_id}")
@shield2  # Executes second and receives the output of shield1
@shield1  # Executes first and receives the raw item_id
async def get_item(item_id: int):
    return {"item_id": item_id}
```

### "Shield dependency not found"

This typically occurs when trying to use `ShieldedDepends` with a function that isn't a shield:

```python
# Make sure to convert regular functions to shields
def regular_function(value: str):  # Not a shield
    return value

@shield(name="ConvertedToShield")  # Now it's a shield
def shield_function(value: str):
    return value

# Use ShieldedDepends with shield functions only
@app.get("/items/{item_id}")
async def get_item(
    value: str = ShieldedDepends(shield_function)  # This is correct
    # value: str = ShieldedDepends(regular_function)  # This would cause the error
):
    return {"value": value}
``` 