# Advanced Method Interception

FastAPI Shield provides powerful method interception capabilities that allow you to modify, validate, or enhance request processing in sophisticated ways. This guide explores advanced method interception techniques using FastAPI Shield.

## Transformer Pattern

The transformer pattern allows you to process and modify the request context through a series of transformers.

```python
from fastapi import FastAPI, Depends, HTTPException, Header, Request
from typing import NewType, Annotated, Optional, List, Dict, Any
from pydantic import BaseModel
from fastapi_shield import shield, ShieldedDepends
import time
import jwt
from abc import ABC, abstractmethod

app = FastAPI()

# Define a model to hold the request context
class RequestContext(BaseModel):
    request: Any  # FastAPI Request
    path: str
    method: str
    client_ip: str
    headers: Dict[str, str]
    params: Dict[str, Any] = {}
    user_id: Optional[str] = None
    roles: List[str] = []
    claims: Dict[str, Any] = {}
    is_authenticated: bool = False
    start_time: float = 0.0
    
    class Config:
        arbitrary_types_allowed = True

# Create a transformed context type
TransformedContext = NewType("TransformedContext", RequestContext)

# Base transformer class
class RequestTransformer(ABC):
    @abstractmethod
    def transform(self, context: RequestContext) -> TransformedContext:
        pass
        
    def __call__(self, context: RequestContext) -> TransformedContext:
        return self.transform(context)

# Specific transformer implementations
class LoggingTransformer(RequestTransformer):
    def transform(self, context: RequestContext) -> TransformedContext:
        context.start_time = time.time()
        print(f"Request started: {context.method} {context.path} from {context.client_ip}")
        return TransformedContext(context)

class HeaderNormalizationTransformer(RequestTransformer):
    def transform(self, context: RequestContext) -> TransformedContext:
        # Normalize header keys to lowercase
        context.headers = {k.lower(): v for k, v in context.headers.items()}
        return TransformedContext(context)

class AuthenticationTransformer(RequestTransformer):
    def __init__(self, secret_key: str, algorithm: str = "HS256"):
        self.secret_key = secret_key
        self.algorithm = algorithm
        
    def transform(self, context: RequestContext) -> TransformedContext:
        # Check for Authorization header
        auth_header = context.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            return TransformedContext(context)
            
        token = auth_header[7:]  # Remove "Bearer " prefix
        
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            context.is_authenticated = True
            context.user_id = payload.get("sub")
            context.claims = payload
            
            # Extract roles if they exist in the token
            if "roles" in payload and isinstance(payload["roles"], list):
                context.roles = payload["roles"]
                
        except jwt.PyJWTError:
            # Token invalid, keep default unauthenticated state
            pass
            
        return TransformedContext(context)

class UserDataTransformer(RequestTransformer):
    def transform(self, context: RequestContext) -> TransformedContext:
        if context.is_authenticated and context.user_id:
            # Here you would typically load additional user data
            # from your database or another service
            
            # Simulated user data
            if context.user_id == "admin":
                context.roles.append("admin")
                
        return TransformedContext(context)

class RoleCheckTransformer(RequestTransformer):
    def __init__(self, required_roles: List[str]):
        self.required_roles = required_roles
        
    def transform(self, context: RequestContext) -> TransformedContext:
        if not self.required_roles:
            return TransformedContext(context)
            
        if not context.is_authenticated:
            raise HTTPException(
                status_code=401,
                detail="Authentication required",
                headers={"WWW-Authenticate": "Bearer"}
            )
            
        for role in self.required_roles:
            if role not in context.roles:
                raise HTTPException(
                    status_code=403,
                    detail=f"Required role missing: {role}"
                )
                
        return TransformedContext(context)

# Transformer pipeline
class TransformerPipeline:
    def __init__(self, transformers: List[RequestTransformer]):
        self.transformers = transformers
        
    def process(self, context: RequestContext) -> TransformedContext:
        current_context = context
        for transformer in self.transformers:
            current_context = transformer.transform(current_context)
        return TransformedContext(current_context)

# Shield to create and transform the request context
@shield(name="Request Context Transformer")
async def transform_request(request: Request) -> TransformedContext:
    # Create initial context
    headers = {k: v for k, v in request.headers.items()}
    context = RequestContext(
        request=request,
        path=request.url.path,
        method=request.method,
        client_ip=request.client.host,
        headers=headers
    )
    
    # Create transformer pipeline
    pipeline = TransformerPipeline([
        LoggingTransformer(),
        HeaderNormalizationTransformer(),
        AuthenticationTransformer(secret_key="your-secret-key"),
        UserDataTransformer()
    ])
    
    # Process through pipeline
    return pipeline.process(context)

# Admin-only shield using role checking
@shield(
    name="Admin Required",
    exception_to_raise_if_fail=HTTPException(
        status_code=403,
        detail="Admin access required"
    )
)
def admin_required(context: TransformedContext = ShieldedDepends(transform_request)) -> TransformedContext:
    if not context.is_authenticated:
        return None
        
    if "admin" not in context.roles:
        return None
        
    return context

# Example endpoints
@app.get("/api/public")
@transform_request
async def public_endpoint(context: TransformedContext = ShieldedDepends(transform_request)):
    return {
        "message": "This is a public endpoint",
        "authenticated": context.is_authenticated,
        "user_id": context.user_id if context.is_authenticated else None
    }

@app.get("/api/protected")
@transform_request
async def protected_endpoint(context: TransformedContext = ShieldedDepends(transform_request)):
    if not context.is_authenticated:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"}
        )
        
    return {
        "message": "This is a protected endpoint",
        "user_id": context.user_id,
        "roles": context.roles
    }

@app.get("/api/admin")
@transform_request
@admin_required
async def admin_endpoint(context: TransformedContext = ShieldedDepends(admin_required)):
    return {
        "message": "This is an admin endpoint",
        "user_id": context.user_id,
        "roles": context.roles,
        "all_claims": context.claims
    }
```

## Aspect-Oriented Programming with FastAPI Shield

Aspect-Oriented Programming (AOP) is a programming paradigm that aims to increase modularity by allowing the separation of cross-cutting concerns. FastAPI Shield can implement AOP concepts to handle concerns like logging, security, and performance monitoring.

```python
from fastapi import FastAPI, Depends, HTTPException, Request, Response
from typing import NewType, Annotated, Optional, List, Dict, Any, Callable, Type, TypeVar, Generic
from pydantic import BaseModel
from fastapi_shield import shield, ShieldedDepends
import time
import traceback
import functools

app = FastAPI()

# Define a type variable for generic typing
T = TypeVar('T')

# Base Aspect class
class Aspect(Generic[T]):
    def pre_process(self, request: Request, *args, **kwargs) -> Dict[str, Any]:
        """Process before the function execution"""
        return {}
        
    def post_process(self, request: Request, response: Any, context: Dict[str, Any]) -> Any:
        """Process after the function execution"""
        return response
        
    def handle_exception(self, request: Request, exc: Exception, context: Dict[str, Any]) -> Any:
        """Handle exceptions raised during execution"""
        raise exc

# Concrete aspect implementations
class LoggingAspect(Aspect):
    def pre_process(self, request: Request, *args, **kwargs) -> Dict[str, Any]:
        return {"start_time": time.time(), "path": request.url.path, "method": request.method}
        
    def post_process(self, request: Request, response: Any, context: Dict[str, Any]) -> Any:
        duration = time.time() - context["start_time"]
        print(f"Request completed: {context['method']} {context['path']} - {duration:.3f}s")
        return response
        
    def handle_exception(self, request: Request, exc: Exception, context: Dict[str, Any]) -> Any:
        duration = time.time() - context["start_time"]
        print(f"Error in request: {context['method']} {context['path']} - {duration:.3f}s")
        print(f"Exception: {type(exc).__name__}: {str(exc)}")
        raise exc

class SecurityAspect(Aspect):
    def __init__(self, require_auth: bool = True):
        self.require_auth = require_auth
        
    def pre_process(self, request: Request, *args, **kwargs) -> Dict[str, Any]:
        # Here you'd implement your authentication logic
        auth_header = request.headers.get("Authorization", "")
        is_authenticated = auth_header.startswith("Bearer ")
        
        if self.require_auth and not is_authenticated:
            raise HTTPException(
                status_code=401,
                detail="Authentication required",
                headers={"WWW-Authenticate": "Bearer"}
            )
            
        return {"is_authenticated": is_authenticated}

class PerformanceAspect(Aspect):
    def __init__(self, slow_threshold: float = 1.0):
        self.slow_threshold = slow_threshold
        
    def pre_process(self, request: Request, *args, **kwargs) -> Dict[str, Any]:
        return {"start_time": time.time()}
        
    def post_process(self, request: Request, response: Any, context: Dict[str, Any]) -> Any:
        duration = time.time() - context["start_time"]
        if duration > self.slow_threshold:
            print(f"SLOW REQUEST: {request.method} {request.url.path} took {duration:.3f}s")
            # In a real app, you might log this to monitoring
        return response

# Factory function to create AOP shields
def create_aop_shield(*aspects: Aspect) -> Type:
    """Create a shield that applies the given aspects to the endpoint"""
    
    @shield(name="AOP Shield")
    async def aop_shield(request: Request) -> Request:
        # AOP context dictionary to share data between aspects
        context = {}
        
        # Run pre-processing for all aspects
        for aspect in aspects:
            try:
                aspect_context = aspect.pre_process(request)
                context.update(aspect_context)
            except Exception as e:
                # If an aspect raises an exception, let it handle it
                return aspect.handle_exception(request, e, context)
        
        return request
    
    return aop_shield

# Decorator for applying aspects to an endpoint
def with_aspects(*aspects: Aspect):
    """Decorator to apply aspects to an endpoint"""
    
    def decorator(func: Callable):
        # Create the shield from aspects
        aop_shield = create_aop_shield(*aspects)
        
        @functools.wraps(func)
        async def wrapper(request: Request = ShieldedDepends(aop_shield), *args, **kwargs):
            # Create context for aspects
            context = {}
            
            # Pre-processing (already done by the shield)
            # But we can add additional details here if needed
            
            try:
                # Call the original function
                response = await func(request, *args, **kwargs)
                
                # Post-processing
                for aspect in aspects:
                    response = aspect.post_process(request, response, context)
                    
                return response
            except Exception as e:
                # Exception handling
                for aspect in aspects:
                    try:
                        # Let each aspect handle the exception
                        return aspect.handle_exception(request, e, context)
                    except Exception:
                        # If the aspect re-raises, continue to the next aspect
                        continue
                
                # If no aspect handled the exception, re-raise it
                raise
        
        return wrapper
    
    return decorator

# Example of using aspects with FastAPI endpoints
@app.get("/api/simple")
@with_aspects(LoggingAspect(), PerformanceAspect(slow_threshold=0.2))
async def simple_endpoint(request: Request):
    # Simulate some processing time
    time.sleep(0.1)
    return {"message": "This is a simple endpoint"}

@app.get("/api/secured")
@with_aspects(SecurityAspect(), LoggingAspect(), PerformanceAspect())
async def secured_endpoint(request: Request):
    return {"message": "This is a secured endpoint"}

@app.get("/api/error")
@with_aspects(LoggingAspect(), PerformanceAspect())
async def error_endpoint(request: Request):
    # Deliberately cause an error
    raise ValueError("This is a test error")
```

## Advanced Method Interception with Context Managers

For more complex scenarios, you can use context managers with FastAPI Shield to implement advanced method interception.

```python
from fastapi import FastAPI, Depends, HTTPException, Request
from typing import NewType, Annotated, Optional, List, Dict, Any, Callable, AsyncContextManager
from fastapi_shield import shield, ShieldedDepends
from contextlib import asynccontextmanager
import time
import traceback

app = FastAPI()

# Context manager for monitoring endpoint execution
@asynccontextmanager
async def endpoint_monitor(request: Request):
    start_time = time.time()
    path = request.url.path
    method = request.method
    
    print(f"Starting request: {method} {path}")
    
    # Setup complete, yield control back to the endpoint
    try:
        yield
        # If we get here, the endpoint completed successfully
        duration = time.time() - start_time
        print(f"Request completed successfully: {method} {path} - {duration:.3f}s")
    except Exception as e:
        # If an exception occurs, log it
        duration = time.time() - start_time
        print(f"Error in request: {method} {path} - {duration:.3f}s")
        print(f"Exception: {type(e).__name__}: {str(e)}")
        print(traceback.format_exc())
        # Re-raise the exception
        raise

# A shield that leverages the context manager
@shield(name="Monitored Request")
async def monitor_request(request: Request) -> Request:
    # The context manager will be used in the endpoint itself
    return request

# Type annotation for a monitored request
MonitoredRequest = NewType("MonitoredRequest", Request)

# Example endpoint using the context manager
@app.get("/api/monitored")
@monitor_request
async def monitored_endpoint(request: MonitoredRequest = ShieldedDepends(monitor_request)):
    async with endpoint_monitor(request):
        # Simulated processing
        time.sleep(0.2)
        
        # Return the response
        return {"message": "This is a monitored endpoint"}

# Example of error handling with context manager
@app.get("/api/monitored-error")
@monitor_request
async def monitored_error_endpoint(request: MonitoredRequest = ShieldedDepends(monitor_request)):
    async with endpoint_monitor(request):
        # Simulate an error
        time.sleep(0.1)
        raise ValueError("This is a test error in a monitored endpoint")
```

FastAPI Shield's method interception capabilities provide a powerful toolkit for creating robust, maintainable, and secure applications. By leveraging these advanced patterns, you can implement sophisticated cross-cutting concerns while keeping your code clean and modular. 