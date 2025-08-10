"""CORS security shield for FastAPI Shield.

This module provides advanced CORS (Cross-Origin Resource Sharing) security
functionality with per-endpoint control, dynamic policies based on authentication,
and granular security controls for sensitive endpoints.
"""

import re
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Pattern, Set, Union

from fastapi import HTTPException, Request, Response, status
from pydantic import BaseModel

from fastapi_shield.shield import Shield, shield


class CORSPolicy(str, Enum):
    """Predefined CORS policy types."""
    STRICT = "strict"          # Very restrictive, specific origins only
    MODERATE = "moderate"      # Reasonable restrictions with some flexibility
    PERMISSIVE = "permissive"  # More open for development/public APIs
    CUSTOM = "custom"          # Custom configuration


class CORSConfig(BaseModel):
    """CORS configuration for a shield."""
    
    # Origins configuration
    allowed_origins: Optional[Set[str]] = None  # Specific allowed origins
    allowed_origin_patterns: Optional[List[Union[str, Pattern]]] = None  # Regex patterns for origins
    allow_credentials: bool = False
    
    # Methods and headers
    allowed_methods: Set[str] = {"GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"}
    allowed_headers: Set[str] = {"Accept", "Accept-Language", "Content-Language", "Content-Type"}
    exposed_headers: Set[str] = set()
    
    # Preflight configuration
    max_age: Optional[int] = 86400  # 24 hours
    
    # Dynamic configuration
    dynamic_origins_func: Optional[Callable[[Request], Set[str]]] = None
    auth_required_for_origins: bool = False
    authenticated_user_origins: Optional[Set[str]] = None
    
    # Security options
    strict_mode: bool = False
    block_null_origin: bool = True
    block_file_origins: bool = True
    require_origin_header: bool = True
    
    model_config = {"arbitrary_types_allowed": True}


class CORSSecurityShield:
    """Advanced CORS security shield with per-endpoint control."""
    
    # Predefined secure configurations
    STRICT_CONFIG = CORSConfig(
        allowed_origins=None,  # Must be explicitly configured
        allow_credentials=False,
        allowed_methods={"GET", "POST"},
        allowed_headers={"Accept", "Content-Type"},
        strict_mode=False,  # Will be set to True when origins are configured
        block_null_origin=True,
        block_file_origins=True,
        require_origin_header=True,
    )
    
    MODERATE_CONFIG = CORSConfig(
        allowed_origins=None,  # Must be configured
        allow_credentials=True,
        allowed_methods={"GET", "POST", "PUT", "DELETE", "OPTIONS"},
        allowed_headers={"Accept", "Accept-Language", "Content-Language", "Content-Type", "Authorization"},
        exposed_headers={"X-Total-Count", "X-Page-Count"},
        strict_mode=False,
        block_null_origin=True,
        block_file_origins=True,
        require_origin_header=True,
    )
    
    PERMISSIVE_CONFIG = CORSConfig(
        allowed_origins={"*"},
        allow_credentials=False,  # Cannot be True with wildcard origins
        allowed_methods={"GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"},
        allowed_headers={"*"},
        strict_mode=False,
        block_null_origin=False,
        block_file_origins=False,
        require_origin_header=False,
    )
    
    def __init__(
        self,
        config: Union[CORSConfig, CORSPolicy] = CORSPolicy.MODERATE,
        allowed_origins: Optional[Union[List[str], Set[str]]] = None,
        allowed_origin_patterns: Optional[List[Union[str, Pattern]]] = None,
        allow_credentials: Optional[bool] = None,
        allowed_methods: Optional[Union[List[str], Set[str]]] = None,
        allowed_headers: Optional[Union[List[str], Set[str]]] = None,
        exposed_headers: Optional[Union[List[str], Set[str]]] = None,
        max_age: Optional[int] = None,
        dynamic_origins_func: Optional[Callable[[Request], Set[str]]] = None,
        strict_mode: Optional[bool] = None,
    ):
        """Initialize CORS security shield.
        
        Args:
            config: Predefined policy or custom CORSConfig
            allowed_origins: List of allowed origin URLs
            allowed_origin_patterns: Regex patterns for dynamic origin matching
            allow_credentials: Whether to allow credentials in CORS requests
            allowed_methods: HTTP methods to allow
            allowed_headers: Headers to allow
            exposed_headers: Headers to expose to the client
            max_age: Max age for preflight cache
            dynamic_origins_func: Function to dynamically determine allowed origins
            strict_mode: Enable strict security mode
        """
        # Start with base configuration
        if isinstance(config, CORSPolicy):
            if config == CORSPolicy.STRICT:
                self.config = self.STRICT_CONFIG.model_copy()
            elif config == CORSPolicy.MODERATE:
                self.config = self.MODERATE_CONFIG.model_copy()
            elif config == CORSPolicy.PERMISSIVE:
                self.config = self.PERMISSIVE_CONFIG.model_copy()
            else:
                self.config = CORSConfig()
        else:
            self.config = config
        
        # Override with explicit parameters
        if allowed_origins is not None:
            self.config.allowed_origins = set(allowed_origins)
        if allowed_origin_patterns is not None:
            # Compile regex patterns
            compiled_patterns = []
            for pattern in allowed_origin_patterns:
                if isinstance(pattern, str):
                    compiled_patterns.append(re.compile(pattern))
                else:
                    compiled_patterns.append(pattern)
            self.config.allowed_origin_patterns = compiled_patterns
        if allow_credentials is not None:
            self.config.allow_credentials = allow_credentials
        if allowed_methods is not None:
            self.config.allowed_methods = set(allowed_methods)
        if allowed_headers is not None:
            self.config.allowed_headers = set(allowed_headers)
        if exposed_headers is not None:
            self.config.exposed_headers = set(exposed_headers)
        if max_age is not None:
            self.config.max_age = max_age
        if dynamic_origins_func is not None:
            self.config.dynamic_origins_func = dynamic_origins_func
        if strict_mode is not None:
            self.config.strict_mode = strict_mode
        
        # Validate configuration
        self._validate_config()
    
    def _validate_config(self) -> None:
        """Validate CORS configuration for security issues."""
        # Cannot allow credentials with wildcard origins
        if self.config.allow_credentials and self.config.allowed_origins:
            if "*" in self.config.allowed_origins:
                raise ValueError(
                    "Cannot allow credentials with wildcard origins. "
                    "This is a security violation per CORS specification."
                )
        
        # Warn about permissive configurations in strict mode
        if self.config.strict_mode:
            if self.config.allowed_origins and "*" in self.config.allowed_origins:
                raise ValueError("Wildcard origins not allowed in strict mode")
            
            if (not self.config.allowed_origins or len(self.config.allowed_origins) == 0) and \
               (not self.config.allowed_origin_patterns or len(self.config.allowed_origin_patterns) == 0):
                raise ValueError("Strict mode requires explicit origin configuration")
    
    def _get_request_origin(self, request: Request) -> Optional[str]:
        """Get the origin from the request."""
        return request.headers.get("origin")
    
    def _is_origin_allowed(self, request: Request, origin: str) -> bool:
        """Check if an origin is allowed for this request."""
        # Check for security violations first
        if self.config.block_null_origin and origin.lower() == "null":
            return False
        
        if self.config.block_file_origins and origin.startswith("file://"):
            return False
        
        # Check dynamic origins first (highest priority)
        if self.config.dynamic_origins_func:
            try:
                dynamic_origins = self.config.dynamic_origins_func(request)
                if origin in dynamic_origins:
                    return True
            except Exception:
                # If dynamic function fails, fall back to static configuration
                pass
        
        # Check static allowed origins
        if self.config.allowed_origins:
            if "*" in self.config.allowed_origins:
                return True
            if origin in self.config.allowed_origins:
                return True
        
        # Check pattern-based origins
        if self.config.allowed_origin_patterns:
            for pattern in self.config.allowed_origin_patterns:
                if pattern.match(origin):
                    return True
        
        # Check authenticated user origins
        if self.config.authenticated_user_origins:
            # This would typically check if the user is authenticated
            # For now, we'll assume authentication is handled by other shields
            if hasattr(request, '_user_authenticated') and request._user_authenticated:
                if origin in self.config.authenticated_user_origins:
                    return True
        
        return False
    
    def _handle_preflight_request(self, request: Request) -> Response:
        """Handle CORS preflight (OPTIONS) request."""
        origin = self._get_request_origin(request)
        
        # Check if origin is required and missing
        if self.config.require_origin_header and not origin:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Origin header is required for CORS requests"
            )
        
        # Check if origin is allowed
        if origin and not self._is_origin_allowed(request, origin):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Origin not allowed by CORS policy"
            )
        
        # Get requested method and headers
        requested_method = request.headers.get("access-control-request-method")
        requested_headers = request.headers.get("access-control-request-headers", "")
        
        # Validate requested method
        if requested_method and requested_method not in self.config.allowed_methods:
            raise HTTPException(
                status_code=status.HTTP_405_METHOD_NOT_ALLOWED,
                detail=f"Method {requested_method} not allowed by CORS policy"
            )
        
        # Validate requested headers
        if requested_headers:
            requested_headers_list = [h.strip().lower() for h in requested_headers.split(",")]
            allowed_headers_lower = {h.lower() for h in self.config.allowed_headers}
            
            if "*" not in self.config.allowed_headers:
                for header in requested_headers_list:
                    if header and header not in allowed_headers_lower:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Header {header} not allowed by CORS policy"
                        )
        
        # Build preflight response
        headers = {}
        
        if origin:
            headers["Access-Control-Allow-Origin"] = origin
        
        if self.config.allow_credentials:
            headers["Access-Control-Allow-Credentials"] = "true"
        
        if self.config.allowed_methods:
            headers["Access-Control-Allow-Methods"] = ", ".join(self.config.allowed_methods)
        
        if self.config.allowed_headers and "*" not in self.config.allowed_headers:
            headers["Access-Control-Allow-Headers"] = ", ".join(self.config.allowed_headers)
        elif requested_headers:
            headers["Access-Control-Allow-Headers"] = requested_headers
        
        if self.config.max_age is not None:
            headers["Access-Control-Max-Age"] = str(self.config.max_age)
        
        return Response(
            status_code=status.HTTP_200_OK,
            headers=headers,
            content=""
        )
    
    def _add_cors_headers(self, request: Request, response: Response) -> Response:
        """Add CORS headers to actual response."""
        origin = self._get_request_origin(request)
        
        # Check if origin is required and missing
        if self.config.require_origin_header and not origin:
            if self.config.strict_mode:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Origin header is required for CORS requests"
                )
            return response
        
        # Check if origin is allowed
        if origin and not self._is_origin_allowed(request, origin):
            if self.config.strict_mode:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Origin not allowed by CORS policy"
                )
            return response
        
        # Add CORS headers to response
        if self.config.allowed_origins and "*" in self.config.allowed_origins:
            response.headers["Access-Control-Allow-Origin"] = "*"
        elif origin:
            response.headers["Access-Control-Allow-Origin"] = origin
        
        if self.config.allow_credentials:
            response.headers["Access-Control-Allow-Credentials"] = "true"
        
        if self.config.exposed_headers:
            response.headers["Access-Control-Expose-Headers"] = ", ".join(self.config.exposed_headers)
        
        # Add Vary header for security
        vary_headers = []
        existing_vary = response.headers.get("Vary", "")
        if existing_vary:
            vary_headers.extend([h.strip() for h in existing_vary.split(",")])
        
        if "Origin" not in vary_headers:
            vary_headers.append("Origin")
        
        response.headers["Vary"] = ", ".join(vary_headers)
        
        return response
    
    def create_shield(self, name: str = "CORS") -> Shield:
        """Create a shield instance for CORS security."""
        
        async def cors_shield(request: Request) -> Optional[Dict[str, Any]]:
            """CORS security shield function."""
            try:
                # Handle preflight requests (OPTIONS)
                if request.method == "OPTIONS":
                    # Check if this is a preflight request
                    if request.headers.get("access-control-request-method"):
                        preflight_response = self._handle_preflight_request(request)
                        # Store the response to be returned by the shield system
                        request._cors_preflight_response = preflight_response
                        return {"preflight_handled": True, "response": preflight_response}
                
                # For actual requests, validate CORS and prepare headers
                origin = self._get_request_origin(request)
                
                # Perform CORS validation
                if self.config.require_origin_header and not origin:
                    if self.config.strict_mode:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Origin header is required for CORS requests"
                        )
                
                if origin and not self._is_origin_allowed(request, origin):
                    if self.config.strict_mode:
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail="Origin not allowed by CORS policy"
                        )
                
                return {
                    "cors_validated": True,
                    "origin": origin,
                    "allowed": origin is None or self._is_origin_allowed(request, origin),
                }
                
            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"CORS validation error: {str(e)}"
                )
        
        return shield(
            cors_shield,
            name=name,
            auto_error=True,
        )


# Convenience functions for common CORS scenarios
def cors_shield(
    policy: Union[CORSPolicy, CORSConfig] = CORSPolicy.MODERATE,
    allowed_origins: Optional[List[str]] = None,
    allowed_origin_patterns: Optional[List[str]] = None,
    allow_credentials: bool = False,
    allowed_methods: Optional[List[str]] = None,
    allowed_headers: Optional[List[str]] = None,
    exposed_headers: Optional[List[str]] = None,
    max_age: Optional[int] = None,
    strict_mode: bool = False,
    name: str = "CORS",
) -> Shield:
    """Create a CORS security shield with specified configuration.
    
    Args:
        policy: Predefined policy or custom configuration
        allowed_origins: List of allowed origin URLs
        allowed_origin_patterns: Regex patterns for origin matching
        allow_credentials: Whether to allow credentials
        allowed_methods: HTTP methods to allow
        allowed_headers: Headers to allow
        exposed_headers: Headers to expose
        max_age: Preflight cache max age
        strict_mode: Enable strict security mode
        name: Shield name
        
    Returns:
        Shield: Configured CORS security shield
        
    Examples:
        ```python
        # Strict CORS for sensitive endpoints
        @app.post("/api/admin/users")
        @cors_shield(
            policy=CORSPolicy.STRICT,
            allowed_origins=["https://admin.example.com"],
            allow_credentials=True,
            strict_mode=True
        )
        def create_user():
            return {"status": "created"}
        
        # Moderate CORS for API endpoints
        @app.get("/api/data")
        @cors_shield(
            allowed_origins=["https://app.example.com", "https://mobile.example.com"],
            allow_credentials=True,
            exposed_headers=["X-Total-Count"]
        )
        def get_data():
            return {"data": []}
        
        # Pattern-based origins
        @app.get("/api/public")
        @cors_shield(
            allowed_origin_patterns=[r"https://.*\\.example\\.com", r"https://.*\\.trusted\\.org"],
            allowed_methods=["GET", "POST"]
        )
        def public_api():
            return {"status": "ok"}
        ```
    """
    cors_shield_instance = CORSSecurityShield(
        config=policy,
        allowed_origins=allowed_origins,
        allowed_origin_patterns=allowed_origin_patterns,
        allow_credentials=allow_credentials,
        allowed_methods=allowed_methods,
        allowed_headers=allowed_headers,
        exposed_headers=exposed_headers,
        max_age=max_age,
        strict_mode=strict_mode,
    )
    return cors_shield_instance.create_shield(name=name)


def strict_cors_shield(
    allowed_origins: List[str],
    allow_credentials: bool = True,
    allowed_methods: Optional[List[str]] = None,
    name: str = "StrictCORS",
) -> Shield:
    """Create a strict CORS shield for sensitive endpoints.
    
    Args:
        allowed_origins: Explicitly allowed origin URLs
        allow_credentials: Whether to allow credentials (default True)
        allowed_methods: Allowed HTTP methods (defaults to GET, POST only)
        name: Shield name
        
    Returns:
        Shield: Strict CORS security shield
    """
    return cors_shield(
        policy=CORSPolicy.STRICT,
        allowed_origins=allowed_origins,
        allow_credentials=allow_credentials,
        allowed_methods=allowed_methods or ["GET", "POST"],
        strict_mode=True,
        name=name,
    )


def public_cors_shield(
    allowed_methods: Optional[List[str]] = None,
    exposed_headers: Optional[List[str]] = None,
    name: str = "PublicCORS",
) -> Shield:
    """Create a permissive CORS shield for public APIs.
    
    Args:
        allowed_methods: HTTP methods to allow
        exposed_headers: Headers to expose to clients
        name: Shield name
        
    Returns:
        Shield: Permissive CORS security shield
    """
    return cors_shield(
        policy=CORSPolicy.PERMISSIVE,
        allowed_methods=allowed_methods,
        exposed_headers=exposed_headers,
        name=name,
    )


def dynamic_cors_shield(
    origins_func: Callable[[Request], Set[str]],
    allow_credentials: bool = True,
    allowed_methods: Optional[List[str]] = None,
    strict_mode: bool = False,
    name: str = "DynamicCORS",
) -> Shield:
    """Create a CORS shield with dynamic origin validation.
    
    Args:
        origins_func: Function that returns allowed origins based on request
        allow_credentials: Whether to allow credentials
        allowed_methods: HTTP methods to allow
        strict_mode: Enable strict security mode
        name: Shield name
        
    Returns:
        Shield: Dynamic CORS security shield
        
    Examples:
        ```python
        def get_user_allowed_origins(request: Request) -> Set[str]:
            # Get user from request (from auth shield)
            user = getattr(request, 'user', None)
            if user and user.is_admin:
                return {"https://admin.example.com", "https://staging.example.com"}
            elif user:
                return {"https://app.example.com"}
            return {"https://public.example.com"}
        
        @app.get("/api/user-data")
        @dynamic_cors_shield(get_user_allowed_origins)
        def get_user_data():
            return {"data": "user-specific"}
        ```
    """
    config = CORSConfig(
        dynamic_origins_func=origins_func,
        allow_credentials=allow_credentials,
        allowed_methods=set(allowed_methods) if allowed_methods else {"GET", "POST", "PUT", "DELETE", "OPTIONS"},
        strict_mode=strict_mode,
    )
    
    cors_shield_instance = CORSSecurityShield(config=config)
    return cors_shield_instance.create_shield(name=name)


def authenticated_cors_shield(
    public_origins: List[str],
    authenticated_origins: List[str],
    allow_credentials: bool = True,
    name: str = "AuthCORS",
) -> Shield:
    """Create a CORS shield with different origins for authenticated users.
    
    Args:
        public_origins: Origins allowed for unauthenticated requests
        authenticated_origins: Additional origins allowed for authenticated users
        allow_credentials: Whether to allow credentials
        name: Shield name
        
    Returns:
        Shield: Authentication-aware CORS shield
    """
    config = CORSConfig(
        allowed_origins=set(public_origins),
        authenticated_user_origins=set(authenticated_origins),
        allow_credentials=allow_credentials,
        auth_required_for_origins=True,
    )
    
    cors_shield_instance = CORSSecurityShield(config=config)
    return cors_shield_instance.create_shield(name=name)