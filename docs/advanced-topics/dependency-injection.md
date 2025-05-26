# Dependency Injection with FastAPI Shield

FastAPI Shield integrates seamlessly with FastAPI's dependency injection system, extending its capabilities with type-based validation and transformation. This guide explores advanced dependency injection patterns using FastAPI Shield.

## Basic Dependency Injection

FastAPI's built-in dependency injection system allows you to declare dependencies that will be provided to your endpoint functions:

```python
from fastapi import FastAPI, Depends, HTTPException
from typing import Annotated

app = FastAPI()

def get_query_parameter(q: str = None):
    if q:
        return q
    return "Default value"

@app.get("/items/")
def read_items(query_param: Annotated[str, Depends(get_query_parameter)]):
    return {"query_param": query_param}
```

FastAPI Shield enhances this system by adding type-based validation and transformation:

```python
from fastapi import FastAPI, Depends, HTTPException
from typing import NewType, Annotated
from fastapi_shield import shield, ShieldedDepends

app = FastAPI()

# Define a sanitized query type
SanitizedQuery = NewType("SanitizedQuery", str)

# Create a shield to sanitize and validate the query
@shield(name="Sanitize Query")
def sanitize_query(q: str = None) -> SanitizedQuery:
    if q is None:
        return SanitizedQuery("Default value")
    
    # Remove any potentially dangerous characters
    sanitized = q.strip().replace(";", "")
    
    # Validate length
    if len(sanitized) > 100:
        raise HTTPException(status_code=400, detail="Query too long")
    
    return SanitizedQuery(sanitized)

@app.get("/items/")
@sanitize_query
def read_items(q: SanitizedQuery = ShieldedDepends(sanitize_query)):
    return {"query": q}
```

## Composite Dependencies

You can create complex dependency chains with FastAPI Shield:

```python
from fastapi import FastAPI, Depends, HTTPException
from typing import NewType, Annotated, Dict, Optional
from pydantic import BaseModel
from fastapi_shield import shield, ShieldedDepends
import time

app = FastAPI()

# Define models and types
class UserContext(BaseModel):
    user_id: Optional[str] = None
    is_authenticated: bool = False
    last_active: float = 0

AuthenticatedContext = NewType("AuthenticatedContext", UserContext)
RateLimitedContext = NewType("RateLimitedContext", AuthenticatedContext)

# Base context provider
@shield(name="Base Context")
def get_base_context() -> UserContext:
    # In a real app, this might come from a request object
    # or be populated based on a token or session
    return UserContext(
        last_active=time.time()
    )

# Authentication shield
@shield(name="Authenticate Context")
def authenticate_context(context: UserContext = ShieldedDepends(get_base_context)) -> AuthenticatedContext:
    # In a real app, check authentication from a token or session
    if context.user_id is None:
        # Mock authentication - normally you'd validate a token
        context.user_id = "user123"
        context.is_authenticated = True
    
    if not context.is_authenticated:
        raise HTTPException(
            status_code=401,
            detail="Authentication required"
        )
    
    return AuthenticatedContext(context)

# Rate limiting shield
@shield(name="Rate Limit Context")
def rate_limit_context(context: AuthenticatedContext = ShieldedDepends(authenticate_context)) -> RateLimitedContext:
    # Simple in-memory rate limiting (use Redis in production)
    user_id = context.user_id
    current_time = time.time()
    
    # In a real app, check against a rate limit store
    # Here we just pass through
    
    return RateLimitedContext(context)

# Use the full dependency chain
@app.get("/protected-resource")
@get_base_context
@authenticate_context
@rate_limit_context
async def get_protected_resource(context: RateLimitedContext = ShieldedDepends(rate_limit_context)):
    return {
        "user_id": context.user_id,
        "authenticated": context.is_authenticated,
        "last_active": context.last_active
    }
```

## Dependency Injection with Shields

FastAPI Shield provides the `ShieldedDepends` class that combines Depends with shield functionality:

```python
from fastapi import FastAPI, Query
from typing import NewType, Annotated, Optional
from fastapi_shield import shield, ShieldedDepends

app = FastAPI()

# Define a validated page type
ValidatedPage = NewType("ValidatedPage", int)
ValidatedLimit = NewType("ValidatedLimit", int)

# Shields for pagination parameters
@shield(name="Validate Page")
def validate_page(page: int = Query(1)) -> ValidatedPage:
    if page < 1:
        page = 1
    return ValidatedPage(page)

@shield(name="Validate Limit")
def validate_limit(limit: int = Query(10)) -> ValidatedLimit:
    if limit < 1:
        limit = 1
    if limit > 100:
        limit = 100
    return ValidatedLimit(limit)

# Use shields on endpoints
@app.get("/items")
@validate_page
@validate_limit
def get_items(
    page: ValidatedPage = ShieldedDepends(validate_page),
    limit: ValidatedLimit = ShieldedDepends(validate_limit)
):
    # Calculate pagination
    skip = (page - 1) * limit
    
    # Get items with pagination
    return {
        "pagination": {"skip": skip, "limit": limit},
        "items": [{"id": i} for i in range(skip, skip + limit)]
    }
```

## Scoped Dependencies with ShieldDepends

FastAPI Shield provides `ShieldedDepends` for creating scoped dependencies:

```python
from fastapi import FastAPI, Depends, HTTPException
from typing import NewType, Annotated, List, Dict, Optional
from pydantic import BaseModel
from fastapi_shield import shield, ShieldedDepends
import time

app = FastAPI()

# Models
class User(BaseModel):
    user_id: str
    username: str
    is_admin: bool = False
    scopes: List[str] = []

# Types
AuthenticatedUser = NewType("AuthenticatedUser", User)
AdminUser = NewType("AdminUser", AuthenticatedUser)

# Mock user database
USERS = {
    "user1": User(user_id="user1", username="Regular User", scopes=["read:items"]),
    "admin1": User(user_id="admin1", username="Admin User", is_admin=True, 
                   scopes=["read:items", "write:items", "admin:panel"])
}

# Base authentication shield
@shield(name="Authenticate")
def authenticate(user_id: str) -> AuthenticatedUser:
    if user_id not in USERS:
        raise HTTPException(status_code=401, detail="User not authenticated")
    return AuthenticatedUser(USERS[user_id])

# Admin check shield
@shield(name="Ensure Admin")
def ensure_admin(user: AuthenticatedUser = ShieldedDepends(lambda user: user)) -> AdminUser:
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    return AdminUser(user)

# Scope check shield
@shield(name="Check Scope")
def check_scope(
    user: AuthenticatedUser = ShieldedDepends(authenticate), 
    required_scope: str = "read:items"
) -> AuthenticatedUser:
    if required_scope not in user.scopes:
        raise HTTPException(
            status_code=403, 
            detail=f"Missing required scope: {required_scope}"
        )
    return user

# Use shields on endpoints
@app.get("/admin-panel")
@authenticate
@ensure_admin
def admin_panel(user_id: str = "admin1", admin: AdminUser = ShieldedDepends(ensure_admin)):
    return {"message": f"Welcome to the admin panel, {admin.username}"}

@app.get("/items")
@authenticate
@check_scope
def read_items(user_id: str = "user1", user: AuthenticatedUser = ShieldedDepends(check_scope)):
    return {"message": f"Reading items for {user.username}", "items": [{"id": 1, "name": "Item 1"}]}

# Create a factory function for a shield with specific scope
def require_scope(scope_name: str):
    """Create a shield that checks for a specific scope"""
    
    @shield(name=f"Require {scope_name} Scope")
    def scope_shield(
        user: AuthenticatedUser = ShieldedDepends(authenticate), 
    ) -> AuthenticatedUser:
        if scope_name not in user.scopes:
            raise HTTPException(
                status_code=403, 
                detail=f"Missing required scope: {scope_name}"
            )
        return user
        
    return scope_shield

write_items_shield = require_scope("write:items")

@app.post("/items")
@authenticate
@write_items_shield
def create_item(
    item: dict, 
    user_id: str = "admin1",
    user: AuthenticatedUser = ShieldedDepends(write_items_shield)
):
    return {"message": f"Creating item for {user.username}", "item": item}
```

## Contextual Dependency Injection

FastAPI Shield allows you to create context-aware dependencies:

```python
from fastapi import FastAPI, Depends, HTTPException, Request
from typing import NewType, Annotated, Dict, Optional, Callable
from pydantic import BaseModel
from fastapi_shield import shield, ShieldedDepends
import time
from datetime import datetime

app = FastAPI()

# Context model
class RequestContext(BaseModel):
    request_id: str
    timestamp: float
    user_id: Optional[str] = None
    is_admin: bool = False
    
# Create a context dependency
@shield(name="Get Request Context")
async def get_request_context(request: Request) -> RequestContext:
    # In a real app, extract from request headers, auth tokens, etc.
    return RequestContext(
        request_id=f"req_{int(time.time())}",
        timestamp=time.time(),
        user_id=request.headers.get("X-User-Id"),
        is_admin=request.headers.get("X-Is-Admin") == "true"
    )

# Create a logger that depends on context
def get_logger(context: RequestContext = ShieldedDepends(get_request_context)):
    def log(level: str, message: str):
        timestamp = datetime.fromtimestamp(context.timestamp).isoformat()
        print(f"[{timestamp}] [{level}] [{context.request_id}] {message}")
    
    return log

# Use context in endpoint
@app.get("/items/{item_id}")
@get_request_context
async def get_item(
    item_id: int,
    context: RequestContext = ShieldedDepends(get_request_context),
    logger: Callable = Depends(get_logger)
):
    logger("INFO", f"Retrieving item {item_id}")
    
    # Check permissions
    if item_id > 100 and not context.is_admin:
        logger("ERROR", f"User {context.user_id} attempted to access restricted item {item_id}")
        raise HTTPException(status_code=403, detail="Access denied")
    
    logger("INFO", f"Successfully retrieved item {item_id}")
    
    return {
        "item_id": item_id,
        "name": f"Item {item_id}",
        "request_id": context.request_id,
        "user_id": context.user_id
    }
```

## Database Dependency Injection

Integrate FastAPI Shield with database connections:

```python
from fastapi import FastAPI, Depends, HTTPException
from typing import NewType, Annotated, List, Dict, Generator
from pydantic import BaseModel
from fastapi_shield import shield, ShieldedDepends
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

app = FastAPI()

# Database setup
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Database model
class ItemDB(Base):
    __tablename__ = "items"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    description = Column(String)

# Pydantic model
class Item(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    
    class Config:
        orm_mode = True

# Create the database tables
Base.metadata.create_all(bind=engine)

# Define a validated database session type
ValidatedDBSession = NewType("ValidatedDBSession", Session)

# Shield to provide and validate database session
@shield(name="Database Connection")
def get_db() -> ValidatedDBSession:
    db = SessionLocal()
    try:
        # Test database connection
        db.execute("SELECT 1")
        return ValidatedDBSession(db)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Database connection error: {str(e)}"
        )

# Use the database session in endpoints
@app.get("/items/", response_model=List[Item])
@get_db
def read_items(
    skip: int = 0, 
    limit: int = 100, 
    db: ValidatedDBSession = ShieldedDepends(get_db)
):
    items = db.query(ItemDB).offset(skip).limit(limit).all()
    return items

@app.get("/items/{item_id}", response_model=Item)
@get_db
def read_item(
    item_id: int, 
    db: ValidatedDBSession = ShieldedDepends(get_db)
):
    item = db.query(ItemDB).filter(ItemDB.id == item_id).first()
    if item is None:
        raise HTTPException(status_code=404, detail="Item not found")
    return item
```

## Async Dependency Injection

FastAPI Shield works seamlessly with async dependencies:

```python
from fastapi import FastAPI, Depends, HTTPException
from typing import NewType, Annotated, List, Dict, Optional
from pydantic import BaseModel
from fastapi_shield import shield, ShieldedDepends
import httpx
import asyncio

app = FastAPI()

# External API data model
class ExternalAPIData(BaseModel):
    api_id: str
    data: Dict[str, any]
    timestamp: float

# Define a validated API data type
ValidatedAPIData = NewType("ValidatedAPIData", ExternalAPIData)

# Shield to fetch and validate external API data
@shield(name="External API Data")
async def get_external_api_data(api_id: str) -> ValidatedAPIData:
    # In a real app, fetch from an external API
    async with httpx.AsyncClient() as client:
        try:
            # Simulated external API call
            await asyncio.sleep(0.1)  # Simulate network delay
            
            # Normally you would do:
            # response = await client.get(f"https://api.example.com/data/{api_id}")
            # response.raise_for_status()
            # data = response.json()
            
            # Simulated response
            data = {
                "value": 42,
                "name": f"Resource {api_id}",
                "status": "active"
            }
            
            return ValidatedAPIData(
                ExternalAPIData(
                    api_id=api_id,
                    data=data,
                    timestamp=asyncio.get_event_loop().time()
                )
            )
        except httpx.HTTPError as e:
            raise HTTPException(
                status_code=502,
                detail=f"Error fetching external API data: {str(e)}"
            )

# Cache for API responses
cache = {}

@shield(name="Cached API Data")
async def get_cached_api_data(
    api_id: str,
    max_age: int = 60
) -> ValidatedAPIData:
    current_time = asyncio.get_event_loop().time()
    
    # Check cache
    if api_id in cache:
        if current_time - cache[api_id].timestamp < max_age:
            return cache[api_id]
    
    # Get fresh data using the shield
    data = await get_external_api_data(api_id)
    
    # Update cache
    cache[api_id] = data
    
    return data

# Use the async shield in an endpoint
@app.get("/external-data/{api_id}")
@get_cached_api_data
async def read_external_data(
    api_id: str, 
    data: ValidatedAPIData = ShieldedDepends(get_cached_api_data)
):
    return {
        "api_id": data.api_id,
        "data": data.data,
        "cached_at": data.timestamp
    }
```

## Conditional Dependencies

FastAPI Shield allows you to create dependencies that execute conditionally:

```python
from fastapi import FastAPI, Depends, HTTPException, Query
from typing import NewType, Annotated, Optional, Callable
from pydantic import BaseModel
from fastapi_shield import shield, ShieldedDepends

app = FastAPI()

# Define feature flag types
FeatureFlags = NewType("FeatureFlags", dict)

# Shield to get feature flags
@shield(name="Feature Flags")
def get_feature_flags(user_id: Optional[str] = None) -> FeatureFlags:
    # In a real app, fetch from a feature flag service or database
    flags = {
        "new_ui": True,
        "advanced_search": False,
        "beta_features": user_id in ["beta_tester1", "admin"]
    }
    return FeatureFlags(flags)

# Factory function to create feature requirement shields
def feature_required(feature_name: str):
    @shield(name=f"Require {feature_name}")
    def feature_shield(flags: FeatureFlags = ShieldedDepends(get_feature_flags)):
        if not flags.get(feature_name, False):
            raise HTTPException(
                status_code=403,
                detail=f"Feature '{feature_name}' is not enabled for your account"
            )
        return True
    return feature_shield

# Create shield instances for specific features
advanced_search_shield = feature_required("advanced_search")
beta_features_shield = feature_required("beta_features")

# Use conditional shields in endpoints
@app.get("/advanced-search")
@get_feature_flags
@advanced_search_shield
def advanced_search(
    query: str,
    user_id: Optional[str] = None,
    _: bool = ShieldedDepends(advanced_search_shield)
):
    return {"results": f"Advanced search results for: {query}"}

@app.get("/beta-features")
@get_feature_flags
@beta_features_shield
def beta_features(
    user_id: str = Query(...),  # Required for the feature flag check
    _: bool = ShieldedDepends(beta_features_shield)
):
    return {"message": "Welcome to beta features", "user_id": user_id}
```

## Best Practices for Dependency Injection

When using dependency injection with FastAPI Shield, consider these best practices:

1. **Apply as Decorators**: Use shields as decorators on the routes that require them.

2. **Consistent Parameter Names**: Keep parameter names consistent between your shield function and endpoint function.

3. **Use ShieldedDepends**: Use `ShieldedDepends` rather than direct function calls when composing shields.

4. **Shield Factory Functions**: Create shield factory functions that return parametrized shields.

5. **Provide Names**: Always give your shields descriptive names for better debugging and logging.

6. **Shield Composition**: Apply multiple shields to a route as multiple decorators, not by calling them directly.

7. **Dependency Hierarchy**: Design a clear hierarchy of dependencies to avoid circular dependencies.

8. **Error Handling**: Provide clear error messages when dependencies fail to resolve.

9. **Scoped Cleanup**: For resources like database connections, ensure proper cleanup.

10. **Type Safety**: Use `NewType` to create explicit types for your dependencies.

By following these patterns and best practices, you can create a modular, maintainable, and type-safe application architecture with FastAPI Shield. 