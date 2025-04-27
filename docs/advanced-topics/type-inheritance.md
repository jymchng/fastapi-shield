# Type Inheritance

FastAPI Shield supports advanced type inheritance patterns, allowing you to create reusable and maintainable shield hierarchies.

## Base Shield Types

Creating base shield types that can be extended:

```python
from fastapi import FastAPI, Header, HTTPException, status, Request
from fastapi_shield import shield, ShieldedDepends
from typing import TypeVar, Generic, Optional, Dict, Any, Callable, List
from abc import ABC, abstractmethod

app = FastAPI()

# Type variables for generic shields
T = TypeVar('T')
U = TypeVar('U')

# Base shield class
class BaseShield(Generic[T, U], ABC):
    """
    Abstract base class for shields with common functionality
    
    Type parameters:
    T - The input type that the shield validates
    U - The output type that the shield returns
    """
    def __init__(self, name: str = None, auto_error: bool = True):
        self.name = name or self.__class__.__name__
        self.auto_error = auto_error
        
    @abstractmethod
    async def validate(self, input_value: T) -> Optional[U]:
        """
        Validate the input and return a value if valid, None otherwise
        
        This method must be implemented by subclasses.
        """
        pass
        
    def __call__(self):
        """Create a shield function from this shield class"""
        
        @shield(name=self.name, auto_error=self.auto_error)
        async def shield_func(request_data: T = Depends()):
            return await self.validate(request_data)
            
        return shield_func

# Concrete shield implementations
class ApiKeyShield(BaseShield[str, Dict[str, Any]]):
    """Shield that validates API keys"""
    
    def __init__(
        self, 
        valid_keys: List[str], 
        name: str = "API Key Shield", 
        auto_error: bool = True
    ):
        super().__init__(name, auto_error)
        self.valid_keys = valid_keys
    
    async def validate(self, api_key: str) -> Optional[Dict[str, Any]]:
        """Validate that the API key is in the list of valid keys"""
        if api_key in self.valid_keys:
            return {"key": api_key, "valid": True}
        return None

class RoleShield(BaseShield[Dict[str, Any], Dict[str, Any]]):
    """Shield that validates user roles"""
    
    def __init__(
        self, 
        required_roles: List[str], 
        name: str = None, 
        auto_error: bool = True
    ):
        name = name or f"Role Shield ({', '.join(required_roles)})"
        super().__init__(name, auto_error)
        self.required_roles = required_roles
    
    async def validate(self, user_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Validate that the user has one of the required roles"""
        user_roles = user_data.get("roles", [])
        if any(role in self.required_roles for role in user_roles):
            return user_data
        return None

class IpAddressShield(BaseShield[Request, Dict[str, Any]]):
    """Shield that validates client IP addresses"""
    
    def __init__(
        self, 
        allowed_ips: List[str], 
        name: str = "IP Shield", 
        auto_error: bool = True
    ):
        super().__init__(name, auto_error)
        self.allowed_ips = allowed_ips
    
    async def validate(self, request: Request) -> Optional[Dict[str, Any]]:
        """Validate that the client IP is in the list of allowed IPs"""
        client_ip = request.client.host
        if client_ip in self.allowed_ips:
            return {"client_ip": client_ip, "allowed": True}
        return None

# Create shield instances
api_key_shield = ApiKeyShield(
    valid_keys=["key1", "key2", "key3"],
    name="Production API Key Shield"
)

admin_shield = RoleShield(
    required_roles=["admin"],
    auto_error=True
)

internal_ip_shield = IpAddressShield(
    allowed_ips=["127.0.0.1", "::1", "192.168.1.100"],
    name="Internal Network Shield"
)

# Apply shields to endpoints
@app.get("/api/data")
@api_key_shield()
async def get_data(api_data: Dict[str, Any] = ShieldedDepends(api_key_shield())):
    return {
        "message": "API data access granted",
        "key_info": api_data
    }

@app.get("/admin/panel")
@api_key_shield()
@admin_shield()
async def admin_panel(
    user_data: Dict[str, Any] = ShieldedDepends(admin_shield())
):
    return {
        "message": "Admin panel access granted",
        "user_roles": user_data.get("roles", [])
    }

@app.get("/internal/metrics")
@internal_ip_shield()
async def internal_metrics(
    ip_data: Dict[str, Any] = ShieldedDepends(internal_ip_shield())
):
    return {
        "message": "Internal metrics access granted",
        "client_ip": ip_data["client_ip"]
    }
```

## Shield Factory Pattern with Inheritance

Using factory patterns with shield inheritance:

```python
from fastapi import FastAPI, Header, HTTPException, status, Request, Depends
from fastapi_shield import shield, ShieldedDepends
from typing import TypeVar, Generic, Optional, Dict, Any, Callable, List, Type
from pydantic import BaseModel

app = FastAPI()

# Generic models
T = TypeVar('T', bound=BaseModel)

class User(BaseModel):
    id: int
    username: str
    roles: List[str] = []
    permissions: List[str] = []

class AuthResult(BaseModel):
    user: User
    token: str
    authenticated: bool = True

# Shield factory base class
class ShieldFactory(Generic[T]):
    """Base factory class for creating shields"""
    
    def __init__(self, model_class: Type[T]):
        self.model_class = model_class
    
    def create_shield(self, name: str, validator_func: Callable[[T], bool]):
        """
        Create a shield that validates instances of the model class
        
        Args:
            name: Name of the shield
            validator_func: Function that validates the model instance
            
        Returns:
            A shield function
        """
        
        @shield(name=name)
        def model_shield(model_instance: T = Depends()):
            """Shield that validates a model instance"""
            if validator_func(model_instance):
                return model_instance
            return None
            
        return model_shield

# Create factories for different model types
user_shield_factory = ShieldFactory(User)
auth_shield_factory = ShieldFactory(AuthResult)

# Create shield validators
def has_admin_role(user: User) -> bool:
    """Check if user has admin role"""
    return "admin" in user.roles

def has_permission(permission: str):
    """Create a validator function that checks for a specific permission"""
    def validator(user: User) -> bool:
        return permission in user.permissions
    return validator

def is_authenticated(auth_result: AuthResult) -> bool:
    """Check if authentication result is valid"""
    return auth_result.authenticated

# Create shields using the factories
admin_user_shield = user_shield_factory.create_shield(
    name="Admin User Shield",
    validator_func=has_admin_role
)

content_manager_shield = user_shield_factory.create_shield(
    name="Content Manager Shield",
    validator_func=has_permission("manage_content")
)

authenticated_shield = auth_shield_factory.create_shield(
    name="Authentication Shield",
    validator_func=is_authenticated
)

# Framework for creating hierarchical shields
class ShieldHierarchy:
    """Class for creating hierarchies of shields"""
    
    def __init__(self, shields: List[Callable] = None):
        self.shields = shields or []
    
    def add_shield(self, shield_func: Callable) -> 'ShieldHierarchy':
        """Add a shield to the hierarchy"""
        self.shields.append(shield_func)
        return self
    
    def apply(self, endpoint_func: Callable) -> Callable:
        """Apply all shields in the hierarchy to an endpoint function"""
        result = endpoint_func
        for shield_func in reversed(self.shields):
            result = shield_func(result)
        return result

# Create shield hierarchies
admin_hierarchy = ShieldHierarchy([
    authenticated_shield,
    admin_user_shield
])

content_hierarchy = ShieldHierarchy([
    authenticated_shield,
    content_manager_shield
])

# Apply shield hierarchies to endpoints
@app.get("/admin/dashboard")
@admin_hierarchy.apply
async def admin_dashboard(
    user: User = ShieldedDepends(admin_user_shield)
):
    return {
        "message": f"Welcome to admin dashboard, {user.username}",
        "roles": user.roles
    }

@app.get("/content/manage")
@content_hierarchy.apply
async def content_management(
    user: User = ShieldedDepends(content_manager_shield)
):
    return {
        "message": f"Welcome to content management, {user.username}",
        "permissions": user.permissions
    }
```

## Composite Shield Pattern

Using the composite pattern for shield composition:

```python
from fastapi import FastAPI, Request, Header, HTTPException, status
from fastapi_shield import shield, ShieldedDepends
from typing import List, Dict, Any, Optional, Callable, Union
from abc import ABC, abstractmethod

app = FastAPI()

# Shield component interface
class ShieldComponent(ABC):
    """Abstract base class for shield components"""
    
    @abstractmethod
    async def check(self, context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Check if the request should be allowed
        
        Args:
            context: Dictionary containing request context
            
        Returns:
            Updated context if allowed, None otherwise
        """
        pass
    
    @abstractmethod
    def create_shield(self, name: str = None) -> Callable:
        """Create a FastAPI Shield function from this component"""
        pass

# Leaf shield component
class SimpleShield(ShieldComponent):
    """Simple shield component that performs a single check"""
    
    def __init__(self, check_func: Callable[[Dict[str, Any]], bool], name: str = None):
        self.check_func = check_func
        self.name = name or "SimpleShield"
    
    async def check(self, context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Perform the check"""
        if self.check_func(context):
            return context
        return None
    
    def create_shield(self, name: str = None) -> Callable:
        """Create a FastAPI Shield function"""
        shield_name = name or self.name
        
        @shield(name=shield_name)
        async def shield_func(request: Request, api_key: str = Header(None)):
            """Shield function created from a SimpleShield"""
            # Initialize context with request info
            context = {
                "request": request,
                "api_key": api_key,
                "client_ip": request.client.host,
                "method": request.method,
                "path": request.url.path
            }
            
            return await self.check(context)
            
        return shield_func

# Composite shield component
class CompositeShield(ShieldComponent):
    """Composite shield that combines multiple shields"""
    
    def __init__(self, components: List[ShieldComponent], name: str = None, require_all: bool = True):
        self.components = components
        self.name = name or "CompositeShield"
        self.require_all = require_all  # If True, all shields must pass; if False, any shield can pass
    
    async def check(self, context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check all component shields"""
        if self.require_all:
            # All shields must pass
            updated_context = context.copy()
            for component in self.components:
                result = await component.check(updated_context)
                if result is None:
                    return None
                updated_context.update(result)
            return updated_context
        else:
            # Any shield can pass
            for component in self.components:
                result = await component.check(context)
                if result is not None:
                    return result
            return None
    
    def create_shield(self, name: str = None) -> Callable:
        """Create a FastAPI Shield function"""
        shield_name = name or self.name
        
        @shield(name=shield_name)
        async def shield_func(request: Request, api_key: str = Header(None)):
            """Shield function created from a CompositeShield"""
            # Initialize context with request info
            context = {
                "request": request,
                "api_key": api_key,
                "client_ip": request.client.host,
                "method": request.method,
                "path": request.url.path
            }
            
            return await self.check(context)
            
        return shield_func
    
    def add_component(self, component: ShieldComponent) -> 'CompositeShield':
        """Add a component to this composite shield"""
        self.components.append(component)
        return self

# Create simple shield components
api_key_check = SimpleShield(
    check_func=lambda ctx: ctx.get("api_key") in ["key1", "key2", "key3"],
    name="API Key Check"
)

internal_ip_check = SimpleShield(
    check_func=lambda ctx: ctx.get("client_ip") in ["127.0.0.1", "::1"],
    name="Internal IP Check"
)

get_method_check = SimpleShield(
    check_func=lambda ctx: ctx.get("method") == "GET",
    name="GET Method Check"
)

# Create composite shields
internal_api_shield = CompositeShield(
    components=[api_key_check, internal_ip_check],
    name="Internal API Shield",
    require_all=True
)

read_only_shield = CompositeShield(
    components=[api_key_check, get_method_check],
    name="Read-Only Shield",
    require_all=True
)

any_auth_shield = CompositeShield(
    components=[api_key_check, internal_ip_check],
    name="Any Auth Shield",
    require_all=False
)

# Apply shields to endpoints
@app.get("/internal/api")
@internal_api_shield.create_shield()
async def internal_api(context: Dict[str, Any] = ShieldedDepends(internal_api_shield.create_shield())):
    return {
        "message": "Internal API access granted",
        "client_ip": context.get("client_ip"),
        "api_key": context.get("api_key")
    }

@app.get("/data/read")
@read_only_shield.create_shield()
async def read_data(context: Dict[str, Any] = ShieldedDepends(read_only_shield.create_shield())):
    return {
        "message": "Read-only access granted",
        "method": context.get("method")
    }

@app.get("/flexible/access")
@any_auth_shield.create_shield()
async def flexible_access(context: Dict[str, Any] = ShieldedDepends(any_auth_shield.create_shield())):
    return {
        "message": "Flexible access granted",
        "auth_method": "API Key" if context.get("api_key") else "Internal IP"
    }
```

These advanced type inheritance patterns provide powerful tools for creating flexible, reusable shield components that can be composed and extended to meet complex security requirements. 