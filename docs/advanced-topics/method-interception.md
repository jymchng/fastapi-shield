# Method Interception

This section covers advanced method interception techniques using FastAPI Shield. Method interception allows you to modify, validate, or enhance request processing in sophisticated ways.

## Request Transformation Pipeline

Creating a pipeline of shields that progressively transform request data:

```python
from fastapi import FastAPI, Request, Response, Depends, HTTPException, status
from fastapi_shield import shield, ShieldedDepends
from typing import Dict, Any, List, Optional, Callable
from pydantic import BaseModel
import json
import time

app = FastAPI()

# Request context model
class RequestContext(BaseModel):
    path: str
    method: str
    client_ip: str
    timestamp: float
    headers: Dict[str, str]
    query_params: Dict[str, str]
    processed_by: List[str] = []
    transformed_data: Dict[str, Any] = {}
    
    class Config:
        arbitrary_types_allowed = True

# Base transformer interface
class RequestTransformer:
    """Base class for request transformers"""
    
    def __init__(self, name: str):
        self.name = name
    
    async def transform(self, context: RequestContext) -> RequestContext:
        """
        Transform the request context
        
        Args:
            context: The current request context
            
        Returns:
            The transformed context
        """
        # Mark this transformer as having processed the request
        context.processed_by.append(self.name)
        return context
    
    def create_shield(self) -> Callable:
        """Create a shield function from this transformer"""
        
        @shield(name=self.name)
        async def transformer_shield(request: Request) -> Optional[RequestContext]:
            """Shield that applies the transformer"""
            # Create initial context from request
            headers = dict(request.headers)
            query_params = dict(request.query_params)
            
            context = RequestContext(
                path=request.url.path,
                method=request.method,
                client_ip=request.client.host,
                timestamp=time.time(),
                headers=headers,
                query_params=query_params
            )
            
            # Apply the transformation
            return await self.transform(context)
            
        return transformer_shield

# Concrete transformers
class LoggingTransformer(RequestTransformer):
    """Transformer that logs request information"""
    
    def __init__(self, name: str = "LoggingTransformer"):
        super().__init__(name)
    
    async def transform(self, context: RequestContext) -> RequestContext:
        """Log request information"""
        context = await super().transform(context)
        
        # In a real app, you would log to a file or database
        print(f"Request to {context.path} from {context.client_ip} at {context.timestamp}")
        
        return context

class HeaderNormalizationTransformer(RequestTransformer):
    """Transformer that normalizes header names"""
    
    def __init__(self, name: str = "HeaderNormalizationTransformer"):
        super().__init__(name)
    
    async def transform(self, context: RequestContext) -> RequestContext:
        """Normalize header names to lowercase with underscores"""
        context = await super().transform(context)
        
        # Create normalized headers
        normalized_headers = {}
        for key, value in context.headers.items():
            normalized_key = key.lower().replace('-', '_')
            normalized_headers[normalized_key] = value
        
        # Store both original and normalized headers
        context.transformed_data["original_headers"] = context.headers.copy()
        context.headers = normalized_headers
        
        return context

class AuthenticationTransformer(RequestTransformer):
    """Transformer that extracts and validates authentication information"""
    
    def __init__(self, name: str = "AuthenticationTransformer"):
        super().__init__(name)
    
    async def transform(self, context: RequestContext) -> RequestContext:
        """Extract and validate authentication information"""
        context = await super().transform(context)
        
        # Check for API key in headers or query parameters
        api_key = context.headers.get("x_api_key") or context.query_params.get("api_key")
        
        if not api_key:
            # No API key found
            return None
        
        # In a real app, you would validate the API key
        valid_keys = ["key1", "key2", "key3"]
        if api_key not in valid_keys:
            return None
        
        # Store authentication information
        context.transformed_data["auth"] = {
            "authenticated": True,
            "api_key": api_key,
            "auth_time": time.time()
        }
        
        return context

class UserDataTransformer(RequestTransformer):
    """Transformer that loads user data based on authentication"""
    
    def __init__(self, name: str = "UserDataTransformer"):
        super().__init__(name)
    
    async def transform(self, context: RequestContext) -> RequestContext:
        """Load user data based on authentication"""
        context = await super().transform(context)
        
        # Check if authenticated
        auth_data = context.transformed_data.get("auth")
        if not auth_data or not auth_data.get("authenticated"):
            return None
        
        # In a real app, you would load user data from a database
        api_key = auth_data.get("api_key")
        user_data = {
            "key1": {"user_id": 1, "username": "admin", "role": "admin"},
            "key2": {"user_id": 2, "username": "editor", "role": "editor"},
            "key3": {"user_id": 3, "username": "user", "role": "user"}
        }.get(api_key)
        
        if not user_data:
            return None
        
        # Store user data
        context.transformed_data["user"] = user_data
        
        return context

class RoleCheckTransformer(RequestTransformer):
    """Transformer that checks if the user has a required role"""
    
    def __init__(self, required_role: str, name: str = None):
        name = name or f"RoleCheckTransformer({required_role})"
        super().__init__(name)
        self.required_role = required_role
    
    async def transform(self, context: RequestContext) -> RequestContext:
        """Check if the user has the required role"""
        context = await super().transform(context)
        
        # Check if user data is available
        user_data = context.transformed_data.get("user")
        if not user_data:
            return None
        
        # Check if user has the required role
        user_role = user_data.get("role")
        if user_role != self.required_role and user_role != "admin":
            return None
        
        return context

# Create transformer instances
logging_transformer = LoggingTransformer()
header_normalization_transformer = HeaderNormalizationTransformer()
authentication_transformer = AuthenticationTransformer()
user_data_transformer = UserDataTransformer()
admin_role_transformer = RoleCheckTransformer("admin")
editor_role_transformer = RoleCheckTransformer("editor")

# Create a transformer pipeline
class TransformerPipeline:
    """Pipeline of transformers that are applied in sequence"""
    
    def __init__(self, transformers: List[RequestTransformer], name: str = "TransformerPipeline"):
        self.transformers = transformers
        self.name = name
    
    def create_shield(self) -> Callable:
        """Create a shield function from this pipeline"""
        
        @shield(name=self.name)
        async def pipeline_shield(request: Request) -> Optional[RequestContext]:
            """Shield that applies all transformers in the pipeline"""
            # Create initial context from request
            headers = dict(request.headers)
            query_params = dict(request.query_params)
            
            context = RequestContext(
                path=request.url.path,
                method=request.method,
                client_ip=request.client.host,
                timestamp=time.time(),
                headers=headers,
                query_params=query_params
            )
            
            # Apply each transformer in sequence
            for transformer in self.transformers:
                context = await transformer.transform(context)
                if context is None:
                    return None
            
            return context
            
        return pipeline_shield

# Create pipelines for different endpoint types
base_pipeline = TransformerPipeline(
    transformers=[logging_transformer, header_normalization_transformer],
    name="BasePipeline"
)

auth_pipeline = TransformerPipeline(
    transformers=[
        logging_transformer,
        header_normalization_transformer,
        authentication_transformer,
        user_data_transformer
    ],
    name="AuthPipeline"
)

admin_pipeline = TransformerPipeline(
    transformers=[
        logging_transformer,
        header_normalization_transformer,
        authentication_transformer,
        user_data_transformer,
        admin_role_transformer
    ],
    name="AdminPipeline"
)

editor_pipeline = TransformerPipeline(
    transformers=[
        logging_transformer,
        header_normalization_transformer,
        authentication_transformer,
        user_data_transformer,
        editor_role_transformer
    ],
    name="EditorPipeline"
)

# Apply pipelines to endpoints
@app.get("/public")
@base_pipeline.create_shield()
async def public_endpoint(context: RequestContext = ShieldedDepends(base_pipeline.create_shield())):
    """Public endpoint that doesn't require authentication"""
    return {
        "message": "Public endpoint",
        "processed_by": context.processed_by,
        "client_ip": context.client_ip
    }

@app.get("/authenticated")
@auth_pipeline.create_shield()
async def authenticated_endpoint(context: RequestContext = ShieldedDepends(auth_pipeline.create_shield())):
    """Authenticated endpoint that requires a valid API key"""
    user_data = context.transformed_data.get("user", {})
    return {
        "message": f"Welcome, {user_data.get('username')}",
        "user_id": user_data.get("user_id"),
        "role": user_data.get("role")
    }

@app.get("/admin")
@admin_pipeline.create_shield()
async def admin_endpoint(context: RequestContext = ShieldedDepends(admin_pipeline.create_shield())):
    """Admin endpoint that requires admin role"""
    user_data = context.transformed_data.get("user", {})
    return {
        "message": f"Admin panel accessed by {user_data.get('username')}",
        "user_id": user_data.get("user_id")
    }

@app.get("/editor")
@editor_pipeline.create_shield()
async def editor_endpoint(context: RequestContext = ShieldedDepends(editor_pipeline.create_shield())):
    """Editor endpoint that requires editor or admin role"""
    user_data = context.transformed_data.get("user", {})
    return {
        "message": f"Editor panel accessed by {user_data.get('username')}",
        "user_id": user_data.get("user_id")
    }
```

## Aspect-Oriented Programming with Shields

Using FastAPI Shield to implement Aspect-Oriented Programming patterns:

```python
from fastapi import FastAPI, Header, HTTPException, status, Request, Response
from fastapi_shield import shield, ShieldedDepends
from typing import Dict, Any, List, Optional, Callable, Union, TypeVar, Type
from pydantic import BaseModel
import time
import json
import logging
from functools import wraps

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("aspect_oriented_api")

app = FastAPI()

# Type variable for method return types
T = TypeVar('T')

# Aspect base class
class Aspect:
    """
    Base class for aspects in AOP pattern
    
    Aspects provide cross-cutting concerns like logging, security, etc.
    """
    
    async def before(self, request: Request, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Code to execute before the endpoint handler
        
        Args:
            request: The FastAPI request
            context: Context data passed between aspects
            
        Returns:
            Updated context
        """
        return context or {}
    
    async def after(self, request: Request, response: Response, context: Dict[str, Any] = None) -> Response:
        """
        Code to execute after the endpoint handler
        
        Args:
            request: The FastAPI request
            response: The response from the endpoint handler
            context: Context data from before phase
            
        Returns:
            Potentially modified response
        """
        return response
    
    async def around(
        self, 
        request: Request, 
        handler: Callable[..., T], 
        context: Dict[str, Any] = None
    ) -> Union[T, Response]:
        """
        Code to execute around the endpoint handler (can short-circuit)
        
        Args:
            request: The FastAPI request
            handler: The endpoint handler function
            context: Context data from before phase
            
        Returns:
            Result from handler or a custom response (short-circuit)
        """
        # Execute the handler
        return await handler()
    
    async def after_exception(
        self, 
        request: Request, 
        exception: Exception, 
        context: Dict[str, Any] = None
    ) -> Optional[Response]:
        """
        Code to execute when the endpoint handler raises an exception
        
        Args:
            request: The FastAPI request
            exception: The exception raised
            context: Context data from before phase
            
        Returns:
            Optional response to return instead of raising the exception
        """
        # By default, return None to let the exception propagate
        return None

# Concrete aspects
class LoggingAspect(Aspect):
    """Aspect that logs requests and responses"""
    
    async def before(self, request: Request, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Log request information"""
        context = await super().before(request, context)
        
        # Add request start time to context
        context["start_time"] = time.time()
        context["request_id"] = context.get("request_id", str(time.time()))
        
        # Log request information
        logger.info(
            f"Request {context['request_id']}: {request.method} {request.url.path} "
            f"from {request.client.host}"
        )
        
        return context
    
    async def after(self, request: Request, response: Response, context: Dict[str, Any] = None) -> Response:
        """Log response information"""
        # Calculate request duration
        start_time = context.get("start_time", 0)
        duration = time.time() - start_time
        
        # Log response information
        logger.info(
            f"Response {context.get('request_id', '')}: {response.status_code} "
            f"completed in {duration:.4f}s"
        )
        
        # Add timing header to response
        response.headers["X-Response-Time"] = f"{duration:.4f}"
        
        return response
    
    async def after_exception(self, request: Request, exception: Exception, context: Dict[str, Any] = None) -> Optional[Response]:
        """Log exception information"""
        # Log exception
        logger.error(
            f"Exception {context.get('request_id', '')}: {type(exception).__name__} - {str(exception)}"
        )
        
        # Let the exception propagate
        return None

class SecurityAspect(Aspect):
    """Aspect that handles authentication and authorization"""
    
    def __init__(self, required_role: str = None):
        self.required_role = required_role
    
    async def before(self, request: Request, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Authenticate the request and check permissions"""
        context = await super().before(request, context)
        
        # Extract API key from header
        api_key = request.headers.get("x-api-key")
        if not api_key:
            context["auth_error"] = "Missing API key"
            return context
        
        # In a real app, you would validate the API key against a database
        # This is simplified for the example
        user_data = {
            "key1": {"user_id": 1, "role": "admin", "username": "admin"},
            "key2": {"user_id": 2, "role": "editor", "username": "editor"},
            "key3": {"user_id": 3, "role": "user", "username": "user1"}
        }.get(api_key)
        
        if not user_data:
            context["auth_error"] = "Invalid API key"
            return context
        
        # Check role if required
        if self.required_role and user_data.get("role") != self.required_role and user_data.get("role") != "admin":
            context["auth_error"] = f"Requires role: {self.required_role}"
            return context
        
        # Add user data to context
        context["user"] = user_data
        
        return context
    
    async def around(self, request: Request, handler: Callable[..., T], context: Dict[str, Any] = None) -> Union[T, Response]:
        """Short-circuit if authentication failed"""
        # Check for authentication error
        auth_error = context.get("auth_error")
        if auth_error:
            # Return 401 Unauthorized response
            error_response = Response(
                content=json.dumps({"detail": auth_error}),
                status_code=status.HTTP_401_UNAUTHORIZED,
                media_type="application/json"
            )
            return error_response
        
        # Proceed with handler
        return await handler()

class PerformanceAspect(Aspect):
    """Aspect that monitors and enforces performance constraints"""
    
    def __init__(self, timeout_seconds: float = 5.0):
        self.timeout_seconds = timeout_seconds
    
    async def before(self, request: Request, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Initialize performance monitoring"""
        context = await super().before(request, context)
        
        # Add start time to context
        context["perf_start_time"] = time.time()
        
        return context
    
    async def after(self, request: Request, response: Response, context: Dict[str, Any] = None) -> Response:
        """Add performance headers to response"""
        # Calculate request duration
        start_time = context.get("perf_start_time", 0)
        duration = time.time() - start_time
        
        # Add performance headers
        response.headers["X-Processing-Time"] = f"{duration:.4f}"
        
        # Log slow requests
        if duration > self.timeout_seconds:
            logger.warning(
                f"Slow request {context.get('request_id', '')}: {request.method} {request.url.path} "
                f"took {duration:.4f}s (timeout: {self.timeout_seconds}s)"
            )
        
        return response

# Factory for creating aspect-oriented shields
def create_aop_shield(*aspects: Aspect):
    """
    Create a shield that applies multiple aspects to an endpoint
    
    Args:
        *aspects: One or more aspects to apply
        
    Returns:
        A shield function
    """
    
    @shield(name="AOPShield")
    async def aop_shield(request: Request) -> Dict[str, Any]:
        """Shield that applies aspects to an endpoint"""
        # Initialize context
        context = {}
        
        # Apply before phase for all aspects
        for aspect in aspects:
            context = await aspect.before(request, context)
        
        # Return context for use in endpoint
        return context
    
    return aop_shield

# Decorator for applying aspects to an endpoint
def with_aspects(*aspects: Aspect):
    """
    Decorator that applies aspects to an endpoint
    
    Args:
        *aspects: One or more aspects to apply
        
    Returns:
        A decorator function
    """
    
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(request: Request, context: Dict[str, Any] = ShieldedDepends(create_aop_shield(*aspects))):
            try:
                # Apply around phase for all aspects (in reverse order)
                handler = func
                for aspect in reversed(aspects):
                    # Create a closure around the current handler
                    current_handler = handler
                    
                    # Create new handler that applies the aspect
                    async def aspect_handler():
                        return await aspect.around(request, current_handler, context)
                    
                    handler = aspect_handler
                
                # Execute the wrapped handler
                result = await handler()
                
                # Convert result to Response if needed
                response = result if isinstance(result, Response) else Response(
                    content=json.dumps(result),
                    media_type="application/json"
                )
                
                # Apply after phase for all aspects (in original order)
                for aspect in aspects:
                    response = await aspect.after(request, response, context)
                
                return response
            except Exception as e:
                # Apply after_exception phase for all aspects (in original order)
                for aspect in aspects:
                    custom_response = await aspect.after_exception(request, e, context)
                    if custom_response:
                        return custom_response
                
                # Re-raise the exception if no aspect handled it
                raise
        
        return wrapper
    
    return decorator

# Create aspect instances
logging_aspect = LoggingAspect()
auth_aspect = SecurityAspect()
admin_aspect = SecurityAspect(required_role="admin")
editor_aspect = SecurityAspect(required_role="editor")
performance_aspect = PerformanceAspect(timeout_seconds=1.0)

# Apply aspects to endpoints
@app.get("/aop/public")
@with_aspects(logging_aspect, performance_aspect)
async def aop_public(request: Request, context: Dict[str, Any]):
    """Public endpoint with logging and performance monitoring"""
    # Simulate some work
    time.sleep(0.1)
    
    return {
        "message": "Public endpoint",
        "request_id": context.get("request_id")
    }

@app.get("/aop/authenticated")
@with_aspects(logging_aspect, auth_aspect, performance_aspect)
async def aop_authenticated(request: Request, context: Dict[str, Any]):
    """Authenticated endpoint"""
    # Get user data from context
    user = context.get("user", {})
    
    return {
        "message": f"Hello, {user.get('username')}",
        "user_id": user.get("user_id"),
        "role": user.get("role")
    }

@app.get("/aop/admin")
@with_aspects(logging_aspect, admin_aspect, performance_aspect)
async def aop_admin(request: Request, context: Dict[str, Any]):
    """Admin-only endpoint"""
    # Get user data from context
    user = context.get("user", {})
    
    # Simulate complex operation
    time.sleep(0.5)
    
    return {
        "message": f"Admin area accessed by {user.get('username')}",
        "user_id": user.get("user_id")
    }

@app.get("/aop/slow")
@with_aspects(logging_aspect, auth_aspect, performance_aspect)
async def aop_slow(request: Request, context: Dict[str, Any]):
    """Endpoint that deliberately exceeds the performance timeout"""
    # Simulate slow operation
    time.sleep(2.0)
    
    return {
        "message": "Slow operation completed",
        "user": context.get("user", {}).get("username")
    }
```

These advanced method interception techniques demonstrate how FastAPI Shield can be used to implement sophisticated request processing patterns such as transformation pipelines and aspect-oriented programming. 