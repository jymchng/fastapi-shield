# Authorization Examples

This page provides practical examples of implementing various authorization patterns with FastAPI Shield.

## Role-Based Access Control (RBAC)

RBAC restricts system access based on the roles assigned to users.

```python
from typing import Dict, List, NewType, Optional
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from fastapi_shield import shield, ShieldedDepends

app = FastAPI()

# Define types for authorization
UserId = NewType("UserId", int)
Role = NewType("Role", str)
Permission = NewType("Permission", str)

# Mock database
USERS_DB: Dict[UserId, Dict] = {
    UserId(1): {"roles": ["user"]},
    UserId(2): {"roles": ["user", "admin"]},
    UserId(3): {"roles": ["user", "moderator"]},
}

ROLES_PERMISSIONS: Dict[Role, List[Permission]] = {
    "user": [Permission("read:own")],
    "moderator": [Permission("read:own"), Permission("read:any"), Permission("update:any")],
    "admin": [Permission("read:own"), Permission("read:any"), Permission("update:any"), Permission("delete:any")]
}

class User(BaseModel):
    id: UserId
    roles: List[Role]

# Extract user ID from token
@shield
def validate_user_id(user_id: str) -> UserId:
    try:
        uid = int(user_id)
        if uid not in USERS_DB:
            raise ValueError("User not found")
        return UserId(uid)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid user ID")

# Get user with roles from database
@shield
def get_user(user_id: UserId = ShieldedDepends(lambda user_id: user_id)) -> User:
    user_data = USERS_DB.get(user_id, {})
    return User(id=user_id, roles=[Role(r) for r in user_data.get("roles", [])])

# Check if user has the required role
@shield
def has_role(required_role: Role, user: User = ShieldedDepends(lambda user_id: user_id)) -> User:
    if required_role not in user.roles:
        raise HTTPException(
            status_code=403, 
            detail=f"User does not have the required role: {required_role}"
        )
    return user

# Check if user has the required permission
@shield
def has_permission(required_permission: Permission, user: User = ShieldedDepends(get_user)) -> User:
    user_permissions = []
    for role in user.roles:
        user_permissions.extend(ROLES_PERMISSIONS.get(role, []))
    
    if required_permission not in user_permissions:
        raise HTTPException(
            status_code=403, 
            detail=f"User does not have the required permission: {required_permission}"
        )
    return user

# Routes with role-based authorization
@app.get("/admin-panel")
def admin_panel(user: User = ShieldedDepends(has_role, role=Role("admin"))):
    return {"message": "Welcome to the admin panel", "user_id": user.id}

@app.get("/moderator-tools")
def moderator_tools(user: User = ShieldedDepends(has_role, role=Role("moderator"))):
    return {"message": "Welcome to the moderator tools", "user_id": user.id}

# Routes with permission-based authorization
@app.delete("/items/{item_id}")
def delete_item(
    item_id: int, 
    user: User = ShieldedDepends(has_permission, required_permission=Permission("delete:any"))
):
    return {"message": f"Item {item_id} deleted", "user_id": user.id}

@app.get("/items/{item_id}")
def read_item(
    item_id: int, 
    user: User = ShieldedDepends(has_permission, required_permission=Permission("read:any"))
):
    return {"message": f"Item {item_id} details", "user_id": user.id}
```

## Attribute-Based Access Control (ABAC)

ABAC evaluates access decisions based on attributes of users, resources, actions, and environment.

```python
from typing import Dict, List, NewType, Optional, Set
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from fastapi_shield import shield, ShieldedDepends
from datetime import datetime, time

app = FastAPI()

# Define types
UserId = NewType("UserId", int)
ResourceId = NewType("ResourceId", int)
Department = NewType("Department", str)

# Mock database
USERS_DB: Dict[UserId, Dict] = {
    UserId(1): {"departments": ["marketing"], "clearance_level": 1},
    UserId(2): {"departments": ["engineering"], "clearance_level": 2},
    UserId(3): {"departments": ["engineering", "product"], "clearance_level": 3},
}

RESOURCES_DB: Dict[ResourceId, Dict] = {
    ResourceId(1): {"name": "Marketing Plan", "owner_department": "marketing", "required_clearance": 1},
    ResourceId(2): {"name": "Product Roadmap", "owner_department": "product", "required_clearance": 2},
    ResourceId(3): {"name": "Security Audit", "owner_department": "engineering", "required_clearance": 3},
}

# Models
class User(BaseModel):
    id: UserId
    departments: List[Department]
    clearance_level: int

class Resource(BaseModel):
    id: ResourceId
    name: str
    owner_department: Department
    required_clearance: int

# Shield functions
@shield
def get_user(user_id: str) -> User:
    try:
        uid = UserId(int(user_id))
        if uid not in USERS_DB:
            raise ValueError()
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid user ID")
    
    user_data = USERS_DB[uid]
    return User(
        id=uid,
        departments=[Department(d) for d in user_data.get("departments", [])],
        clearance_level=user_data.get("clearance_level", 0)
    )

@shield
def get_resource(resource_id: int) -> Resource:
    rid = ResourceId(resource_id)
    if rid not in RESOURCES_DB:
        raise HTTPException(status_code=404, detail="Resource not found")
    
    resource_data = RESOURCES_DB[rid]
    return Resource(
        id=rid,
        name=resource_data["name"],
        owner_department=Department(resource_data["owner_department"]),
        required_clearance=resource_data["required_clearance"]
    )

@shield
def check_access(
    user: User = ShieldedDepends(get_user),
    resource: Resource = ShieldedDepends(get_resource),
) -> bool:
    # Check if user is in the same department
    department_access = resource.owner_department in user.departments
    
    # Check if user has sufficient clearance
    clearance_access = user.clearance_level >= resource.required_clearance
    
    # Check if it's business hours (9 AM to 5 PM)
    current_hour = datetime.now().hour
    time_access = 9 <= current_hour <= 17
    
    if not (department_access and clearance_access and time_access):
        raise HTTPException(status_code=403, detail="Access denied")
    
    return True

# Routes with ABAC
@app.get("/resources/{resource_id}")
def access_resource(
    resource_id: int,
    user_id: str,
    access_granted: bool = ShieldedDepends(check_access)
):
    resource = RESOURCES_DB[ResourceId(resource_id)]
    return {
        "message": f"Access granted to {resource['name']}",
        "resource_id": resource_id
    }
```

## Context-Based Authorization

This example demonstrates dynamic authorization based on context:

```python
from typing import Dict, List, NewType, Optional
from fastapi import FastAPI, Depends, HTTPException, Request
from pydantic import BaseModel
from fastapi_shield import shield, ShieldedDepends
import time

app = FastAPI()

# Define types
UserId = NewType("UserId", int)
ResourceId = NewType("ResourceId", int)

# Mock user/resource databases
USERS_DB = {
    UserId(1): {"rate_limit": 10, "ip_whitelist": ["192.168.1.1", "10.0.0.1"]},
    UserId(2): {"rate_limit": 20, "ip_whitelist": ["192.168.1.2"]},
}

# Rate limiting tracking
request_history: Dict[UserId, List[float]] = {}

# Models
class User(BaseModel):
    id: UserId
    rate_limit: int
    ip_whitelist: List[str]

# Shield functions
@shield
def get_user(user_id: str) -> User:
    try:
        uid = UserId(int(user_id))
        if uid not in USERS_DB:
            raise ValueError()
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid user ID")
    
    user_data = USERS_DB[uid]
    return User(
        id=uid,
        rate_limit=user_data.get("rate_limit", 0),
        ip_whitelist=user_data.get("ip_whitelist", [])
    )

@shield
def check_ip_whitelist(request: Request, user: User = ShieldedDepends(get_user)) -> bool:
    client_ip = request.client.host if request.client else None
    
    if not client_ip or client_ip not in user.ip_whitelist:
        raise HTTPException(
            status_code=403, 
            detail="Access denied: IP not in whitelist"
        )
    return True

@shield
def check_rate_limit(user: User = ShieldedDepends(get_user)) -> bool:
    current_time = time.time()
    user_requests = request_history.get(user.id, [])
    
    # Filter to requests in the past minute
    recent_requests = [t for t in user_requests if current_time - t < 60]
    
    # Update history
    request_history[user.id] = recent_requests + [current_time]
    
    if len(recent_requests) >= user.rate_limit:
        raise HTTPException(
            status_code=429, 
            detail=f"Rate limit exceeded: {user.rate_limit} requests per minute"
        )
    return True

# Protected endpoint with context-based authorization
@app.get("/api/data")
def get_data(
    request: Request,
    user_id: str,
    ip_check: bool = ShieldedDepends(check_ip_whitelist),
    rate_check: bool = ShieldedDepends(check_rate_limit)
):
    return {
        "message": "Data access granted",
        "timestamp": time.time()
    }
```

## Best Practices for Authorization

1. **Principle of Least Privilege**: Grant only the permissions necessary for users to perform their tasks.

2. **Defense in Depth**: Implement multiple layers of authorization checks.

3. **Clear Separation**: Separate authentication from authorization logic.

4. **Central Authorization Service**: Use a centralized authorization service for consistent policy enforcement.

5. **Audit Logging**: Log all authorization decisions and access attempts.

6. **Regular Review**: Periodically review and update authorization policies.

7. **Fail Secure**: Default to denial if authorization checks fail.

8. **Testing**: Write comprehensive tests for authorization logic.

9. **Documentation**: Clearly document all authorization requirements and policies.

10. **Shield Composition**: Compose multiple shields to create complex authorization rules. 