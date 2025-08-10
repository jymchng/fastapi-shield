"""Shield Middleware Bridge for FastAPI Shield.

This module provides seamless integration between FastAPI Shield and middleware systems,
including ASGI middleware, Starlette middleware, and custom middleware patterns.
It allows shields to be deployed as middleware components for maximum flexibility.
"""

import asyncio
import inspect
import logging
import time
import warnings
from abc import ABC, abstractmethod
from collections import defaultdict
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urlparse

from fastapi import HTTPException, Request, Response
from fastapi.dependencies.utils import is_coroutine_callable
from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from fastapi_shield.shield import Shield

logger = logging.getLogger(__name__)


class MiddlewareType(str, Enum):
    """Types of middleware integration."""
    ASGI = "asgi"
    STARLETTE = "starlette"
    FASTAPI = "fastapi"
    CUSTOM = "custom"


class ShieldPosition(str, Enum):
    """Position of shield middleware in the stack."""
    FIRST = "first"
    BEFORE_ROUTING = "before_routing"
    AFTER_ROUTING = "after_routing"
    BEFORE_AUTH = "before_auth"
    AFTER_AUTH = "after_auth"
    LAST = "last"
    CUSTOM = "custom"


class ProcessingPhase(str, Enum):
    """Request processing phases."""
    REQUEST_START = "request_start"
    REQUEST_HEADERS = "request_headers"
    REQUEST_BODY = "request_body"
    ROUTING = "routing"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    ENDPOINT_EXECUTION = "endpoint_execution"
    RESPONSE_HEADERS = "response_headers"
    RESPONSE_BODY = "response_body"
    RESPONSE_END = "response_end"


@dataclass
class MiddlewareConfig:
    """Configuration for shield middleware integration."""
    
    # Basic settings
    shield: Shield
    name: str = "shield_middleware"
    position: ShieldPosition = ShieldPosition.BEFORE_ROUTING
    enabled: bool = True
    
    # Processing settings
    process_phases: Set[ProcessingPhase] = field(
        default_factory=lambda: {ProcessingPhase.REQUEST_START}
    )
    ignore_paths: Set[str] = field(default_factory=set)
    include_paths: Optional[Set[str]] = None
    methods: Optional[Set[str]] = None
    
    # Performance settings
    timeout_seconds: float = 30.0
    max_body_size: int = 10 * 1024 * 1024  # 10MB
    enable_caching: bool = True
    cache_ttl_seconds: int = 300  # 5 minutes
    
    # Error handling
    auto_error: bool = True
    error_response_type: str = "json"  # json, plain, html
    custom_error_handler: Optional[Callable[[Exception, Request], Response]] = None
    
    # Compatibility settings
    preserve_original_headers: bool = True
    pass_through_on_error: bool = False
    enable_debug_headers: bool = False


@dataclass
class MiddlewareMetrics:
    """Metrics for middleware performance monitoring."""
    total_requests: int = 0
    blocked_requests: int = 0
    allowed_requests: int = 0
    error_count: int = 0
    avg_processing_time_ms: float = 0.0
    max_processing_time_ms: float = 0.0
    processing_times: List[float] = field(default_factory=list)
    phase_metrics: Dict[ProcessingPhase, Dict[str, float]] = field(
        default_factory=lambda: defaultdict(lambda: {"count": 0, "total_time": 0.0})
    )


class ShieldMiddlewareCache:
    """High-performance cache for shield middleware results."""
    
    def __init__(self, max_size: int = 10000, ttl_seconds: int = 300):
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self._cache: Dict[str, Tuple[Any, float]] = {}
        self._access_times: Dict[str, float] = {}
        
    def get(self, key: str) -> Optional[Any]:
        """Get cached result."""
        if key not in self._cache:
            return None
            
        value, expiry_time = self._cache[key]
        current_time = time.time()
        
        if current_time > expiry_time:
            self._cache.pop(key, None)
            self._access_times.pop(key, None)
            return None
            
        self._access_times[key] = current_time
        return value
    
    def set(self, key: str, value: Any) -> None:
        """Set cached result."""
        current_time = time.time()
        expiry_time = current_time + self.ttl_seconds
        
        # Clean up expired entries if cache is full
        if len(self._cache) >= self.max_size:
            self._cleanup_expired()
            
            # If still full, remove oldest entries
            if len(self._cache) >= self.max_size:
                self._cleanup_oldest()
        
        self._cache[key] = (value, expiry_time)
        self._access_times[key] = current_time
    
    def _cleanup_expired(self) -> None:
        """Remove expired cache entries."""
        current_time = time.time()
        expired_keys = []
        
        for key, (_, expiry_time) in list(self._cache.items()):
            if current_time > expiry_time:
                expired_keys.append(key)
        
        for key in expired_keys:
            self._cache.pop(key, None)
            self._access_times.pop(key, None)
    
    def _cleanup_oldest(self) -> None:
        """Remove oldest cache entries."""
        if not self._access_times:
            return
            
        # Remove 25% of oldest entries
        remove_count = max(1, len(self._access_times) // 4)
        oldest_keys = sorted(self._access_times.items(), key=lambda x: x[1])[:remove_count]
        
        for key, _ in oldest_keys:
            self._cache.pop(key, None)
            self._access_times.pop(key, None)
    
    def clear(self) -> None:
        """Clear all cached data."""
        self._cache.clear()
        self._access_times.clear()


class MiddlewareContext:
    """Context for shield middleware processing."""
    
    def __init__(self, config: MiddlewareConfig):
        self.config = config
        self.start_time = time.time()
        self.processing_phases: List[ProcessingPhase] = []
        self.shield_results: Dict[str, Any] = {}
        self.errors: List[Exception] = []
        self.metadata: Dict[str, Any] = {}
    
    def add_phase(self, phase: ProcessingPhase) -> None:
        """Record processing phase."""
        self.processing_phases.append(phase)
    
    def set_result(self, shield_name: str, result: Any) -> None:
        """Set shield processing result."""
        self.shield_results[shield_name] = result
    
    def add_error(self, error: Exception) -> None:
        """Add processing error."""
        self.errors.append(error)
    
    def get_processing_time_ms(self) -> float:
        """Get total processing time in milliseconds."""
        return (time.time() - self.start_time) * 1000


class ShieldMiddlewareBridge(ABC):
    """Abstract base class for shield middleware bridges."""
    
    def __init__(self, config: MiddlewareConfig):
        self.config = config
        self.metrics = MiddlewareMetrics()
        self.cache = ShieldMiddlewareCache(
            ttl_seconds=config.cache_ttl_seconds
        ) if config.enable_caching else None
        self._enabled = config.enabled
    
    @abstractmethod
    async def process_request(self, context: MiddlewareContext, 
                            request: Request) -> Optional[Response]:
        """Process incoming request with shield."""
        pass
    
    @abstractmethod
    async def process_response(self, context: MiddlewareContext,
                             request: Request, response: Response) -> Response:
        """Process outgoing response."""
        pass
    
    def should_process_request(self, request: Request) -> bool:
        """Determine if request should be processed by shield."""
        if not self._enabled:
            return False
        
        path = request.url.path
        
        # Check ignored paths first
        if path in self.config.ignore_paths:
            return False
        
        # Check included paths - if specified, path must be in the list or start with one of the paths
        if self.config.include_paths:
            path_match = False
            for include_path in self.config.include_paths:
                if path == include_path or path.startswith(include_path + "/") or path.startswith(include_path):
                    path_match = True
                    break
            if not path_match:
                return False
        
        # Check HTTP methods
        if self.config.methods and request.method not in self.config.methods:
            return False
        
        return True
    
    def create_cache_key(self, request: Request) -> str:
        """Create cache key for request."""
        key_parts = [
            request.method,
            request.url.path,
            str(request.url.query),
        ]
        
        # Include relevant headers
        auth_header = request.headers.get("authorization", "")
        if auth_header:
            # Hash the auth header for security
            import hashlib
            auth_hash = hashlib.sha256(auth_header.encode()).hexdigest()[:16]
            key_parts.append(auth_hash)
        
        return "|".join(key_parts)
    
    async def execute_shield(self, request: Request, 
                           context: MiddlewareContext) -> Optional[Any]:
        """Execute shield with proper error handling."""
        try:
            # Check cache first
            if self.cache:
                cache_key = self.create_cache_key(request)
                cached_result = self.cache.get(cache_key)
                if cached_result is not None:
                    context.set_result(self.config.name, cached_result)
                    return cached_result
            
            # Execute shield
            shield_func = self.config.shield._guard_func
            
            # Prepare shield arguments
            shield_args = self._prepare_shield_args(request, shield_func)
            
            # Execute based on shield type
            if self.config.shield._guard_func_is_async:
                result = await shield_func(**shield_args)
            else:
                # Run sync shield in thread pool to avoid blocking
                import concurrent.futures
                loop = asyncio.get_event_loop()
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    result = await loop.run_in_executor(
                        executor, lambda: shield_func(**shield_args)
                    )
            
            # Cache result if enabled
            if self.cache and result is not None:
                self.cache.set(cache_key, result)
            
            context.set_result(self.config.name, result)
            return result
            
        except asyncio.TimeoutError:
            error = HTTPException(
                status_code=408, 
                detail=f"Shield {self.config.name} timeout"
            )
            context.add_error(error)
            if self.config.auto_error and not self.config.pass_through_on_error:
                raise error
            return None
            
        except Exception as e:
            context.add_error(e)
            # Re-raise the exception so caller can handle it based on pass_through_on_error
            raise e
    
    def _prepare_shield_args(self, request: Request, shield_func: Callable) -> Dict[str, Any]:
        """Prepare arguments for shield function."""
        sig = inspect.signature(shield_func)
        args = {}
        
        for param_name, param in sig.parameters.items():
            if param_name == "request":
                args["request"] = request
            elif param_name in ["req", "http_request"]:
                args[param_name] = request
            # Add more parameter mappings as needed
        
        return args
    
    def create_error_response(self, error: Exception, request: Request) -> Response:
        """Create error response for failed shield."""
        if self.config.custom_error_handler:
            try:
                return self.config.custom_error_handler(error, request)
            except Exception as e:
                logger.error(f"Custom error handler failed: {e}")
        
        # Default error responses
        if isinstance(error, HTTPException):
            status_code = error.status_code
            detail = error.detail
        else:
            status_code = 500
            detail = f"Shield {self.config.name} failed"
        
        if self.config.error_response_type == "json":
            return JSONResponse(
                status_code=status_code,
                content={"error": detail, "shield": self.config.name}
            )
        else:
            return PlainTextResponse(
                status_code=status_code,
                content=detail
            )
    
    def update_metrics(self, context: MiddlewareContext, blocked: bool) -> None:
        """Update middleware metrics."""
        processing_time = context.get_processing_time_ms()
        
        self.metrics.total_requests += 1
        if blocked:
            self.metrics.blocked_requests += 1
        else:
            self.metrics.allowed_requests += 1
        
        # Update processing time metrics
        self.metrics.processing_times.append(processing_time)
        if len(self.metrics.processing_times) > 1000:
            self.metrics.processing_times = self.metrics.processing_times[-500:]
        
        if processing_time > self.metrics.max_processing_time_ms:
            self.metrics.max_processing_time_ms = processing_time
        
        # Calculate rolling average
        recent_times = self.metrics.processing_times[-100:]
        self.metrics.avg_processing_time_ms = sum(recent_times) / len(recent_times)
        
        # Update phase metrics
        for phase in context.processing_phases:
            phase_data = self.metrics.phase_metrics[phase]
            phase_data["count"] += 1
            phase_data["total_time"] += processing_time
        
        if context.errors:
            self.metrics.error_count += 1


class ASGIShieldMiddleware(ShieldMiddlewareBridge):
    """ASGI middleware implementation for shields."""
    
    def __init__(self, app: ASGIApp, config: MiddlewareConfig):
        super().__init__(config)
        self.app = app
    
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """ASGI application entry point."""
        if scope["type"] != "http":
            # Pass through non-HTTP requests
            await self.app(scope, receive, send)
            return
        
        # Create request object from ASGI scope
        request = Request(scope, receive)
        
        if not self.should_process_request(request):
            await self.app(scope, receive, send)
            return
        
        context = MiddlewareContext(self.config)
        context.add_phase(ProcessingPhase.REQUEST_START)
        
        try:
            # Process request with shield
            error_response = await self.process_request(context, request)
            
            if error_response is not None:
                # Shield blocked the request
                self.update_metrics(context, blocked=True)
                await error_response(scope, receive, send)
                return
            
            # Shield allowed the request - continue processing
            context.add_phase(ProcessingPhase.ENDPOINT_EXECUTION)
            
            # Capture response for post-processing
            response_started = False
            response_body = b""
            
            async def capture_send(message: Message) -> None:
                nonlocal response_started, response_body
                
                if message["type"] == "http.response.start":
                    response_started = True
                    # Add debug headers if enabled
                    if self.config.enable_debug_headers:
                        headers = list(message.get("headers", []))
                        headers.append(
                            (b"x-shield-processed", f"{self.config.name}".encode())
                        )
                        headers.append(
                            (b"x-shield-time", f"{context.get_processing_time_ms():.2f}ms".encode())
                        )
                        message["headers"] = headers
                    
                    await send(message)
                    
                elif message["type"] == "http.response.body":
                    if self.config.preserve_original_headers:
                        response_body += message.get("body", b"")
                    await send(message)
                else:
                    await send(message)
            
            # Execute downstream application
            await self.app(scope, receive, capture_send)
            
            # Post-process response
            context.add_phase(ProcessingPhase.RESPONSE_END)
            self.update_metrics(context, blocked=False)
            
        except Exception as e:
            context.add_error(e)
            self.update_metrics(context, blocked=True)
            
            if not self.config.pass_through_on_error:
                error_response = self.create_error_response(e, request)
                await error_response(scope, receive, send)
            else:
                # Pass through to original app
                await self.app(scope, receive, send)
    
    async def process_request(self, context: MiddlewareContext, 
                            request: Request) -> Optional[Response]:
        """Process request with shield - ASGI implementation."""
        context.add_phase(ProcessingPhase.AUTHENTICATION)
        
        # Execute shield with timeout
        try:
            result = await asyncio.wait_for(
                self.execute_shield(request, context),
                timeout=self.config.timeout_seconds
            )
            
            if result is None:
                # Shield blocked the request
                if isinstance(self.config.shield._exception_to_raise_if_fail, HTTPException):
                    return self.create_error_response(
                        self.config.shield._exception_to_raise_if_fail, 
                        request
                    )
                else:
                    return self.create_error_response(
                        HTTPException(status_code=403, detail="Access denied"),
                        request
                    )
            
            # Shield allowed the request
            return None
            
        except asyncio.TimeoutError:
            return self.create_error_response(
                HTTPException(status_code=408, detail="Request timeout"),
                request
            )
    
    async def process_response(self, context: MiddlewareContext,
                             request: Request, response: Response) -> Response:
        """Process response - ASGI implementation."""
        context.add_phase(ProcessingPhase.RESPONSE_HEADERS)
        
        if self.config.enable_debug_headers:
            response.headers["x-shield-processed"] = self.config.name
            response.headers["x-shield-time"] = f"{context.get_processing_time_ms():.2f}ms"
        
        return response


class StarletteShieldMiddleware(BaseHTTPMiddleware, ShieldMiddlewareBridge):
    """Starlette middleware implementation for shields."""
    
    def __init__(self, app, config: MiddlewareConfig):
        BaseHTTPMiddleware.__init__(self, app)
        ShieldMiddlewareBridge.__init__(self, config)
    
    async def dispatch(self, request: Request, call_next) -> Response:
        """Starlette middleware dispatch method."""
        if not self.should_process_request(request):
            return await call_next(request)
        
        context = MiddlewareContext(self.config)
        context.add_phase(ProcessingPhase.REQUEST_START)
        
        try:
            # Process request with shield
            error_response = await self.process_request(context, request)
            
            if error_response is not None:
                # Shield blocked the request
                self.update_metrics(context, blocked=True)
                return error_response
            
            # Shield allowed the request - continue processing
            context.add_phase(ProcessingPhase.ENDPOINT_EXECUTION)
            response = await call_next(request)
            
            # Post-process response
            response = await self.process_response(context, request, response)
            context.add_phase(ProcessingPhase.RESPONSE_END)
            
            self.update_metrics(context, blocked=False)
            return response
            
        except Exception as e:
            context.add_error(e)
            self.update_metrics(context, blocked=True)
            
            if self.config.pass_through_on_error:
                try:
                    # Shield failed, but pass through to app anyway
                    context.add_phase(ProcessingPhase.ENDPOINT_EXECUTION)
                    response = await call_next(request)
                    context.add_phase(ProcessingPhase.RESPONSE_END)
                    return response
                except Exception:
                    # If call_next also fails, return error response
                    return self.create_error_response(e, request)
            else:
                return self.create_error_response(e, request)
    
    async def process_request(self, context: MiddlewareContext,
                            request: Request) -> Optional[Response]:
        """Process request with shield - Starlette implementation."""
        context.add_phase(ProcessingPhase.AUTHENTICATION)
        
        try:
            result = await asyncio.wait_for(
                self.execute_shield(request, context),
                timeout=self.config.timeout_seconds
            )
            
            if result is None:
                # Shield blocked the request
                return self.create_error_response(
                    HTTPException(status_code=403, detail="Shield blocked request"),
                    request
                )
            
            # Shield allowed the request
            return None
            
        except asyncio.TimeoutError:
            if self.config.pass_through_on_error:
                return None  # Let request pass through
            return self.create_error_response(
                HTTPException(status_code=408, detail="Shield timeout"),
                request
            )
        except Exception as e:
            context.add_error(e)
            if self.config.pass_through_on_error:
                return None  # Let request pass through
            return self.create_error_response(e, request)
    
    async def process_response(self, context: MiddlewareContext,
                             request: Request, response: Response) -> Response:
        """Process response - Starlette implementation."""
        context.add_phase(ProcessingPhase.RESPONSE_HEADERS)
        
        if self.config.enable_debug_headers:
            response.headers["x-shield-processed"] = self.config.name
            response.headers["x-shield-time"] = f"{context.get_processing_time_ms():.2f}ms"
        
        return response


class MiddlewareChainOptimizer:
    """Optimizer for shield middleware chains."""
    
    def __init__(self):
        self.middleware_stack: List[ShieldMiddlewareBridge] = []
        self.optimization_enabled = True
        self._cache_keys: Dict[str, Set[str]] = defaultdict(set)
    
    def add_middleware(self, middleware: ShieldMiddlewareBridge) -> None:
        """Add middleware to the optimization chain."""
        self.middleware_stack.append(middleware)
        
        # Analyze middleware for optimization opportunities
        if self.optimization_enabled:
            self._analyze_middleware(middleware)
    
    def _analyze_middleware(self, middleware: ShieldMiddlewareBridge) -> None:
        """Analyze middleware for optimization opportunities."""
        config = middleware.config
        
        # Track cache key patterns
        if config.enable_caching:
            shield_name = config.name
            if config.include_paths:
                self._cache_keys[shield_name].update(config.include_paths)
            
            # Identify overlapping cache patterns
            for existing_name, existing_paths in self._cache_keys.items():
                if existing_name != shield_name:
                    overlap = self._cache_keys[shield_name].intersection(existing_paths)
                    if overlap:
                        logger.info(
                            f"Cache optimization opportunity: {shield_name} and "
                            f"{existing_name} have overlapping paths: {overlap}"
                        )
    
    async def process_request_chain(self, request: Request) -> Optional[Response]:
        """Process request through optimized middleware chain."""
        if not self.middleware_stack:
            return None
        
        # Execute middleware in order
        for middleware in self.middleware_stack:
            if not middleware.should_process_request(request):
                continue
            
            context = MiddlewareContext(middleware.config)
            error_response = await middleware.process_request(context, request)
            
            if error_response is not None:
                # Middleware blocked the request
                return error_response
        
        # All middleware allowed the request
        return None
    
    def get_chain_metrics(self) -> Dict[str, Any]:
        """Get metrics for the entire middleware chain."""
        total_metrics = {
            "total_middleware": len(self.middleware_stack),
            "total_requests": 0,
            "total_blocked": 0,
            "total_allowed": 0,
            "avg_processing_time_ms": 0.0,
            "middleware_metrics": {}
        }
        
        all_processing_times = []
        
        for middleware in self.middleware_stack:
            metrics = middleware.metrics
            total_metrics["total_requests"] += metrics.total_requests
            total_metrics["total_blocked"] += metrics.blocked_requests
            total_metrics["total_allowed"] += metrics.allowed_requests
            all_processing_times.extend(metrics.processing_times)
            
            total_metrics["middleware_metrics"][middleware.config.name] = {
                "requests": metrics.total_requests,
                "blocked": metrics.blocked_requests,
                "allowed": metrics.allowed_requests,
                "avg_time_ms": metrics.avg_processing_time_ms,
                "max_time_ms": metrics.max_processing_time_ms,
                "error_count": metrics.error_count
            }
        
        if all_processing_times:
            total_metrics["avg_processing_time_ms"] = sum(all_processing_times) / len(all_processing_times)
        
        return total_metrics


# Factory functions for creating middleware

def create_asgi_shield_middleware(shield: Shield, **kwargs) -> ASGIShieldMiddleware:
    """Create ASGI middleware from a shield.
    
    Args:
        shield: The shield to wrap as middleware
        **kwargs: Additional configuration options
    
    Returns:
        ASGIShieldMiddleware: ASGI middleware instance
    """
    config = MiddlewareConfig(shield=shield, **kwargs)
    
    def middleware_factory(app: ASGIApp) -> ASGIShieldMiddleware:
        return ASGIShieldMiddleware(app, config)
    
    return middleware_factory


def create_starlette_shield_middleware(shield: Shield, **kwargs) -> StarletteShieldMiddleware:
    """Create Starlette middleware from a shield.
    
    Args:
        shield: The shield to wrap as middleware
        **kwargs: Additional configuration options
    
    Returns:
        StarletteShieldMiddleware: Starlette middleware class
    """
    config = MiddlewareConfig(shield=shield, **kwargs)
    
    class ConfiguredMiddleware(StarletteShieldMiddleware):
        def __init__(self, app):
            super().__init__(app, config)
    
    return ConfiguredMiddleware


def shield_to_middleware(shield: Shield, middleware_type: MiddlewareType = MiddlewareType.STARLETTE,
                        **config_kwargs) -> Union[ASGIShieldMiddleware, StarletteShieldMiddleware]:
    """Convert a shield to middleware.
    
    Args:
        shield: The shield to convert
        middleware_type: Type of middleware to create
        **config_kwargs: Configuration options
    
    Returns:
        Middleware instance or factory
    """
    if middleware_type == MiddlewareType.ASGI:
        return create_asgi_shield_middleware(shield, **config_kwargs)
    elif middleware_type == MiddlewareType.STARLETTE:
        return create_starlette_shield_middleware(shield, **config_kwargs)
    else:
        raise ValueError(f"Unsupported middleware type: {middleware_type}")


def create_middleware_chain(*shields: Shield, middleware_type: MiddlewareType = MiddlewareType.STARLETTE,
                          **config_kwargs) -> List[Union[ASGIShieldMiddleware, StarletteShieldMiddleware]]:
    """Create a chain of shield middleware.
    
    Args:
        *shields: Shields to convert to middleware
        middleware_type: Type of middleware to create
        **config_kwargs: Configuration options applied to all shields
    
    Returns:
        List of middleware instances
    """
    middleware_list = []
    
    for shield in shields:
        middleware = shield_to_middleware(
            shield, 
            middleware_type=middleware_type,
            **config_kwargs
        )
        middleware_list.append(middleware)
    
    return middleware_list


# Integration helpers

class MiddlewareIntegrator:
    """Helper for integrating shield middleware with applications."""
    
    @staticmethod
    def integrate_with_fastapi(app, shields: List[Shield], **config_kwargs) -> None:
        """Integrate shields as middleware with FastAPI app.
        
        Args:
            app: FastAPI application instance
            shields: List of shields to add as middleware
            **config_kwargs: Configuration options
        """
        for shield in reversed(shields):  # Add in reverse order for correct execution order
            middleware_class = create_starlette_shield_middleware(shield, **config_kwargs)
            app.add_middleware(middleware_class)
    
    @staticmethod
    def integrate_with_starlette(app: Starlette, shields: List[Shield], **config_kwargs) -> None:
        """Integrate shields as middleware with Starlette app.
        
        Args:
            app: Starlette application instance
            shields: List of shields to add as middleware
            **config_kwargs: Configuration options
        """
        for shield in reversed(shields):  # Add in reverse order for correct execution order
            middleware_class = create_starlette_shield_middleware(shield, **config_kwargs)
            app.add_middleware(middleware_class)
    
    @staticmethod
    def integrate_with_asgi_app(app: ASGIApp, shields: List[Shield], **config_kwargs) -> ASGIApp:
        """Integrate shields as middleware with any ASGI app.
        
        Args:
            app: ASGI application instance
            shields: List of shields to add as middleware
            **config_kwargs: Configuration options
        
        Returns:
            Wrapped ASGI application
        """
        wrapped_app = app
        
        for shield in reversed(shields):  # Apply in reverse order
            middleware_factory = create_asgi_shield_middleware(shield, **config_kwargs)
            wrapped_app = middleware_factory(wrapped_app)
        
        return wrapped_app


# Backwards compatibility aliases
ASGIMiddleware = ASGIShieldMiddleware
StarletteMiddleware = StarletteShieldMiddleware