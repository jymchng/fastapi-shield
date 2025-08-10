"""Cache control shield for FastAPI Shield.

This module provides HTTP caching control with security-focused policies,
ETag generation, conditional requests, and authentication-aware caching
for FastAPI applications.
"""

import hashlib
import time
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Union

from fastapi import HTTPException, Request, Response, status
from pydantic import BaseModel

from fastapi_shield.shield import Shield, shield


class CachePolicy(str, Enum):
    """Predefined cache policy types."""
    NO_CACHE = "no_cache"          # Never cache, always revalidate
    PRIVATE = "private"            # Cache only in browser, not proxies
    PUBLIC = "public"              # Cache everywhere
    SENSITIVE = "sensitive"        # Extra restrictive for sensitive data
    STATIC = "static"              # Long-term caching for static assets
    DYNAMIC = "dynamic"            # Short-term caching for dynamic content


class CacheDirective(str, Enum):
    """Cache-Control directive types."""
    NO_CACHE = "no-cache"
    NO_STORE = "no-store" 
    MUST_REVALIDATE = "must-revalidate"
    PROXY_REVALIDATE = "proxy-revalidate"
    PRIVATE = "private"
    PUBLIC = "public"
    MAX_AGE = "max-age"
    S_MAXAGE = "s-maxage"
    IMMUTABLE = "immutable"
    NO_TRANSFORM = "no-transform"


class CacheConfig(BaseModel):
    """Cache control configuration."""
    
    # Cache policy
    policy: Optional[CachePolicy] = None
    
    # Cache-Control directives
    directives: Dict[CacheDirective, Optional[Union[int, str, bool]]] = {}
    
    # Timing configuration
    max_age: Optional[int] = None          # Browser cache time (seconds)
    s_max_age: Optional[int] = None        # Proxy cache time (seconds) 
    expires_delta: Optional[timedelta] = None  # Expires header offset
    
    # ETag configuration
    enable_etag: bool = False
    etag_algorithm: str = "md5"           # Algorithm for ETag generation
    weak_etag: bool = False               # Use weak ETags
    
    # Last-Modified configuration
    enable_last_modified: bool = False
    
    # Conditional request configuration
    handle_conditional: bool = True       # Handle If-None-Match, If-Modified-Since
    
    # Security options
    no_cache_sensitive: bool = True       # Force no-cache for authenticated requests
    vary_headers: Optional[List[str]] = None  # Headers to include in Vary
    
    # Dynamic configuration
    cache_condition_func: Optional[Callable[[Request, Response], bool]] = None
    max_age_func: Optional[Callable[[Request, Response], Optional[int]]] = None
    
    model_config = {"arbitrary_types_allowed": True}


class CacheControlShield:
    """HTTP cache control shield with security-focused policies."""
    
    # Predefined secure cache configurations
    NO_CACHE_CONFIG = CacheConfig(
        policy=CachePolicy.NO_CACHE,
        directives={
            CacheDirective.NO_CACHE: True,
            CacheDirective.NO_STORE: True,
            CacheDirective.MUST_REVALIDATE: True,
        },
        vary_headers=["Authorization", "Cookie"],
        enable_etag=False,
        handle_conditional=False,
    )
    
    SENSITIVE_CONFIG = CacheConfig(
        policy=CachePolicy.SENSITIVE,
        directives={
            CacheDirective.PRIVATE: True,
            CacheDirective.NO_CACHE: True,
            CacheDirective.MUST_REVALIDATE: True,
        },
        max_age=0,
        vary_headers=["Authorization", "Cookie", "User-Agent"],
        enable_etag=True,
        weak_etag=True,
        handle_conditional=True,
        no_cache_sensitive=True,
    )
    
    PRIVATE_CONFIG = CacheConfig(
        policy=CachePolicy.PRIVATE,
        directives={
            CacheDirective.PRIVATE: True,
            CacheDirective.MUST_REVALIDATE: True,
        },
        max_age=300,  # 5 minutes
        vary_headers=["Authorization"],
        enable_etag=True,
        enable_last_modified=True,
        handle_conditional=True,
    )
    
    PUBLIC_CONFIG = CacheConfig(
        policy=CachePolicy.PUBLIC,
        directives={
            CacheDirective.PUBLIC: True,
        },
        max_age=3600,  # 1 hour
        s_max_age=7200,  # 2 hours for proxies
        enable_etag=True,
        enable_last_modified=True,
        handle_conditional=True,
        vary_headers=["Accept-Encoding"],
    )
    
    STATIC_CONFIG = CacheConfig(
        policy=CachePolicy.STATIC,
        directives={
            CacheDirective.PUBLIC: True,
            CacheDirective.IMMUTABLE: True,
            CacheDirective.NO_TRANSFORM: True,
        },
        max_age=31536000,  # 1 year
        s_max_age=31536000,
        enable_etag=True,
        enable_last_modified=True,
        handle_conditional=True,
        vary_headers=["Accept-Encoding"],
    )
    
    DYNAMIC_CONFIG = CacheConfig(
        policy=CachePolicy.DYNAMIC,
        directives={
            CacheDirective.PRIVATE: True,
            CacheDirective.MUST_REVALIDATE: True,
        },
        max_age=60,  # 1 minute
        enable_etag=True,
        enable_last_modified=True,
        handle_conditional=True,
        vary_headers=["Authorization", "Accept-Encoding"],
    )
    
    def __init__(
        self,
        config: Union[CacheConfig, CachePolicy] = CachePolicy.PRIVATE,
        max_age: Optional[int] = None,
        s_max_age: Optional[int] = None,
        enable_etag: Optional[bool] = None,
        enable_last_modified: Optional[bool] = None,
        handle_conditional: Optional[bool] = None,
        vary_headers: Optional[List[str]] = None,
        no_cache_sensitive: Optional[bool] = None,
        cache_condition_func: Optional[Callable[[Request, Response], bool]] = None,
        max_age_func: Optional[Callable[[Request, Response], Optional[int]]] = None,
    ):
        """Initialize cache control shield.
        
        Args:
            config: Predefined policy or custom CacheConfig
            max_age: Browser cache time in seconds
            s_max_age: Proxy cache time in seconds
            enable_etag: Enable ETag generation
            enable_last_modified: Enable Last-Modified header
            handle_conditional: Handle conditional requests
            vary_headers: Headers to include in Vary
            no_cache_sensitive: Force no-cache for authenticated requests
            cache_condition_func: Function to determine if response should be cached
            max_age_func: Function to dynamically determine max-age
        """
        # Start with base configuration
        if isinstance(config, CachePolicy):
            if config == CachePolicy.NO_CACHE:
                self.config = self.NO_CACHE_CONFIG.model_copy()
            elif config == CachePolicy.SENSITIVE:
                self.config = self.SENSITIVE_CONFIG.model_copy()
            elif config == CachePolicy.PRIVATE:
                self.config = self.PRIVATE_CONFIG.model_copy()
            elif config == CachePolicy.PUBLIC:
                self.config = self.PUBLIC_CONFIG.model_copy()
            elif config == CachePolicy.STATIC:
                self.config = self.STATIC_CONFIG.model_copy()
            elif config == CachePolicy.DYNAMIC:
                self.config = self.DYNAMIC_CONFIG.model_copy()
            else:
                self.config = CacheConfig()
        else:
            self.config = config
        
        # Override with explicit parameters
        if max_age is not None:
            self.config.max_age = max_age
            if CacheDirective.MAX_AGE not in self.config.directives:
                self.config.directives[CacheDirective.MAX_AGE] = max_age
        
        if s_max_age is not None:
            self.config.s_max_age = s_max_age
            self.config.directives[CacheDirective.S_MAXAGE] = s_max_age
        
        if enable_etag is not None:
            self.config.enable_etag = enable_etag
        
        if enable_last_modified is not None:
            self.config.enable_last_modified = enable_last_modified
        
        if handle_conditional is not None:
            self.config.handle_conditional = handle_conditional
        
        if vary_headers is not None:
            self.config.vary_headers = vary_headers
        
        if no_cache_sensitive is not None:
            self.config.no_cache_sensitive = no_cache_sensitive
        
        if cache_condition_func is not None:
            self.config.cache_condition_func = cache_condition_func
        
        if max_age_func is not None:
            self.config.max_age_func = max_age_func
        
        # Store original response for ETag generation
        self._response_cache: Dict[str, tuple] = {}
    
    def _is_authenticated_request(self, request: Request) -> bool:
        """Check if request is authenticated (has auth headers or session)."""
        # Check for common authentication indicators
        auth_headers = [
            "authorization",
            "x-auth-token", 
            "x-api-key",
            "cookie",
        ]
        
        for header in auth_headers:
            if request.headers.get(header):
                return True
        
        # Check for authentication markers set by other shields
        if hasattr(request, '_user_authenticated') and request._user_authenticated:
            return True
        
        if hasattr(request, 'user') and request.user:
            return True
        
        return False
    
    def _should_cache_response(self, request: Request, response: Response) -> bool:
        """Determine if response should be cached based on configuration."""
        # Check custom cache condition function
        if self.config.cache_condition_func:
            try:
                return self.config.cache_condition_func(request, response)
            except Exception:
                return False
        
        # Don't cache error responses by default
        if response.status_code >= 400:
            return False
        
        # Check no-cache for sensitive requests
        if self.config.no_cache_sensitive and self._is_authenticated_request(request):
            return False
        
        # Default: cache successful responses
        return 200 <= response.status_code < 300
    
    def _generate_etag(self, content: bytes, weak: bool = False) -> str:
        """Generate ETag for response content."""
        if self.config.etag_algorithm == "md5":
            hash_obj = hashlib.md5(content)
        elif self.config.etag_algorithm == "sha1":
            hash_obj = hashlib.sha1(content)
        elif self.config.etag_algorithm == "sha256":
            hash_obj = hashlib.sha256(content)
        else:
            # Fallback to MD5
            hash_obj = hashlib.md5(content)
        
        etag = hash_obj.hexdigest()[:16]  # First 16 chars for brevity
        
        # Weak ETags are prefixed with W/
        if weak:
            return f'W/"{etag}"'
        else:
            return f'"{etag}"'
    
    def _get_last_modified(self, request: Request, response: Response) -> Optional[str]:
        """Get Last-Modified timestamp for response."""
        # Check if already set in response
        if "last-modified" in response.headers:
            return response.headers["last-modified"]
        
        # For now, use current time - in real implementation, this would
        # typically come from database timestamps, file modification times, etc.
        now = datetime.now(timezone.utc)
        return now.strftime("%a, %d %b %Y %H:%M:%S GMT")
    
    def _parse_http_date(self, date_str: str) -> Optional[datetime]:
        """Parse HTTP date string to datetime."""
        formats = [
            "%a, %d %b %Y %H:%M:%S GMT",  # RFC 822
            "%A, %d-%b-%y %H:%M:%S GMT",  # RFC 850
            "%a %b %d %H:%M:%S %Y",       # ANSI C asctime()
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        
        return None
    
    def _check_if_none_match(self, request: Request, etag: str) -> bool:
        """Check If-None-Match header against ETag."""
        if_none_match = request.headers.get("if-none-match")
        if not if_none_match:
            return False
        
        # Handle multiple ETags and wildcards
        etags = [tag.strip() for tag in if_none_match.split(",")]
        
        # Check for wildcard
        if "*" in etags:
            return True
        
        # Check if our ETag matches any of the listed ETags
        return etag in etags
    
    def _check_if_modified_since(self, request: Request, last_modified: str) -> bool:
        """Check If-Modified-Since header against Last-Modified."""
        if_modified_since = request.headers.get("if-modified-since")
        if not if_modified_since:
            return True  # Assume modified if no header
        
        # Parse both dates
        ims_date = self._parse_http_date(if_modified_since)
        lm_date = self._parse_http_date(last_modified)
        
        if not ims_date or not lm_date:
            return True  # Assume modified if parsing fails
        
        # Return True if modified since the given date
        return lm_date > ims_date
    
    def _handle_conditional_request(self, request: Request, etag: Optional[str], last_modified: Optional[str]) -> Optional[Response]:
        """Handle conditional requests and return 304 if not modified."""
        if not self.config.handle_conditional:
            return None
        
        # Check If-None-Match (ETag-based)
        if etag and self._check_if_none_match(request, etag):
            # ETag matches, content hasn't changed
            return Response(status_code=status.HTTP_304_NOT_MODIFIED)
        
        # Check If-Modified-Since (date-based)
        if last_modified and not self._check_if_modified_since(request, last_modified):
            # Content hasn't been modified since the given date
            return Response(status_code=status.HTTP_304_NOT_MODIFIED)
        
        return None
    
    def _build_cache_control_header(self, request: Request, response: Response) -> str:
        """Build Cache-Control header value."""
        directives = []
        
        # Get dynamic max-age if function is provided
        dynamic_max_age = None
        if self.config.max_age_func:
            try:
                dynamic_max_age = self.config.max_age_func(request, response)
            except Exception:
                pass
        
        # Process each directive
        for directive, value in self.config.directives.items():
            if value is True:
                directives.append(directive.value)
            elif value is not False and value is not None:
                if directive == CacheDirective.MAX_AGE:
                    # Use dynamic max-age if available
                    max_age_value = dynamic_max_age if dynamic_max_age is not None else value
                    if max_age_value is not None:
                        directives.append(f"{directive.value}={max_age_value}")
                else:
                    directives.append(f"{directive.value}={value}")
        
        # Add max-age if set in config but not in directives
        if self.config.max_age is not None and CacheDirective.MAX_AGE not in self.config.directives:
            max_age_value = dynamic_max_age if dynamic_max_age is not None else self.config.max_age
            directives.append(f"max-age={max_age_value}")
        
        # Add s-maxage if set
        if self.config.s_max_age is not None:
            directives.append(f"s-maxage={self.config.s_max_age}")
        
        return ", ".join(directives)
    
    def _add_cache_headers(self, request: Request, response: Response, response_content: bytes) -> Response:
        """Add cache-related headers to response."""
        # Check if we should cache this response
        if not self._should_cache_response(request, response):
            # Force no-cache for non-cacheable responses
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
            return response
        
        # Generate ETag if enabled
        etag = None
        if self.config.enable_etag and response_content:
            etag = self._generate_etag(response_content, self.config.weak_etag)
            response.headers["ETag"] = etag
        
        # Add Last-Modified if enabled
        last_modified = None
        if self.config.enable_last_modified:
            last_modified = self._get_last_modified(request, response)
            if last_modified:
                response.headers["Last-Modified"] = last_modified
        
        # Handle conditional requests
        if self.config.handle_conditional:
            conditional_response = self._handle_conditional_request(request, etag, last_modified)
            if conditional_response:
                # Copy cache headers to 304 response
                if etag:
                    conditional_response.headers["ETag"] = etag
                if last_modified:
                    conditional_response.headers["Last-Modified"] = last_modified
                
                return conditional_response
        
        # Build Cache-Control header
        cache_control = self._build_cache_control_header(request, response)
        if cache_control:
            response.headers["Cache-Control"] = cache_control
        
        # Add Expires header if configured
        if self.config.expires_delta:
            expires = datetime.now(timezone.utc) + self.config.expires_delta
            response.headers["Expires"] = expires.strftime("%a, %d %b %Y %H:%M:%S GMT")
        
        # Add Vary header
        if self.config.vary_headers:
            existing_vary = response.headers.get("Vary", "")
            vary_headers = list(self.config.vary_headers)
            
            if existing_vary:
                existing = [h.strip() for h in existing_vary.split(",")]
                vary_headers.extend(h for h in existing if h not in vary_headers)
            
            response.headers["Vary"] = ", ".join(vary_headers)
        
        return response
    
    def create_shield(self, name: str = "CacheControl") -> Shield:
        """Create a shield instance for cache control."""
        
        async def cache_control_shield(request: Request) -> Optional[Dict[str, Any]]:
            """Cache control shield function."""
            try:
                # Store request info for later processing
                return {
                    "cache_shield_active": True,
                    "cache_policy": self.config.policy.value if self.config.policy else "custom",
                    "is_authenticated": self._is_authenticated_request(request),
                }
                
            except Exception as e:
                # Return error info but don't block request
                return {
                    "cache_shield_error": str(e),
                    "cache_shield_active": False,
                }
        
        return shield(
            cache_control_shield,
            name=name,
            auto_error=False,  # Don't auto-raise errors
        )


# Convenience functions for common cache control scenarios
def cache_control_shield(
    policy: Union[CachePolicy, CacheConfig] = CachePolicy.PRIVATE,
    max_age: Optional[int] = None,
    s_max_age: Optional[int] = None,
    enable_etag: bool = True,
    enable_last_modified: bool = True,
    handle_conditional: bool = True,
    vary_headers: Optional[List[str]] = None,
    no_cache_sensitive: bool = True,
    name: str = "CacheControl",
) -> Shield:
    """Create a cache control shield with specified configuration.
    
    Args:
        policy: Predefined policy or custom configuration
        max_age: Browser cache time in seconds
        s_max_age: Proxy cache time in seconds
        enable_etag: Enable ETag generation and validation
        enable_last_modified: Enable Last-Modified header
        handle_conditional: Handle conditional requests (304 responses)
        vary_headers: Headers to include in Vary
        no_cache_sensitive: Force no-cache for authenticated requests
        name: Shield name
        
    Returns:
        Shield: Configured cache control shield
        
    Examples:
        ```python
        # No cache for sensitive admin endpoints
        @app.get("/admin/users")
        @cache_control_shield(policy=CachePolicy.NO_CACHE)
        def admin_users():
            return {"users": []}
        
        # Private cache for user data
        @app.get("/api/user/profile")
        @cache_control_shield(
            policy=CachePolicy.PRIVATE,
            max_age=300,
            enable_etag=True
        )
        def user_profile():
            return {"profile": {}}
        
        # Public cache for static content
        @app.get("/api/public/data")
        @cache_control_shield(
            policy=CachePolicy.PUBLIC,
            max_age=3600,
            s_max_age=7200
        )
        def public_data():
            return {"data": []}
        
        # Long-term cache for static assets
        @app.get("/assets/{filename}")
        @cache_control_shield(
            policy=CachePolicy.STATIC,
            max_age=31536000,  # 1 year
            vary_headers=["Accept-Encoding"]
        )
        def serve_asset(filename: str):
            return FileResponse(f"assets/{filename}")
        ```
    """
    cache_shield = CacheControlShield(
        config=policy,
        max_age=max_age,
        s_max_age=s_max_age,
        enable_etag=enable_etag,
        enable_last_modified=enable_last_modified,
        handle_conditional=handle_conditional,
        vary_headers=vary_headers,
        no_cache_sensitive=no_cache_sensitive,
    )
    return cache_shield.create_shield(name=name)


def no_cache_shield(
    vary_headers: Optional[List[str]] = None,
    name: str = "NoCache",
) -> Shield:
    """Create a no-cache shield for sensitive endpoints.
    
    Args:
        vary_headers: Headers to include in Vary (default: Authorization, Cookie)
        name: Shield name
        
    Returns:
        Shield: No-cache shield
    """
    return cache_control_shield(
        policy=CachePolicy.NO_CACHE,
        vary_headers=vary_headers or ["Authorization", "Cookie"],
        name=name,
    )


def private_cache_shield(
    max_age: int = 300,
    enable_etag: bool = True,
    enable_last_modified: bool = True,
    name: str = "PrivateCache",
) -> Shield:
    """Create a private cache shield for user-specific data.
    
    Args:
        max_age: Cache time in seconds (default: 5 minutes)
        enable_etag: Enable ETag generation
        enable_last_modified: Enable Last-Modified header
        name: Shield name
        
    Returns:
        Shield: Private cache shield
    """
    return cache_control_shield(
        policy=CachePolicy.PRIVATE,
        max_age=max_age,
        enable_etag=enable_etag,
        enable_last_modified=enable_last_modified,
        vary_headers=["Authorization"],
        name=name,
    )


def public_cache_shield(
    max_age: int = 3600,
    s_max_age: Optional[int] = None,
    enable_etag: bool = True,
    enable_last_modified: bool = True,
    vary_headers: Optional[List[str]] = None,
    name: str = "PublicCache",
) -> Shield:
    """Create a public cache shield for shared data.
    
    Args:
        max_age: Browser cache time in seconds (default: 1 hour)
        s_max_age: Proxy cache time in seconds
        enable_etag: Enable ETag generation
        enable_last_modified: Enable Last-Modified header
        vary_headers: Headers to include in Vary
        name: Shield name
        
    Returns:
        Shield: Public cache shield
    """
    return cache_control_shield(
        policy=CachePolicy.PUBLIC,
        max_age=max_age,
        s_max_age=s_max_age,
        enable_etag=enable_etag,
        enable_last_modified=enable_last_modified,
        vary_headers=vary_headers or ["Accept-Encoding"],
        no_cache_sensitive=False,  # Allow caching even for authenticated requests
        name=name,
    )


def static_cache_shield(
    max_age: int = 31536000,  # 1 year
    immutable: bool = True,
    vary_headers: Optional[List[str]] = None,
    name: str = "StaticCache",
) -> Shield:
    """Create a static cache shield for long-term asset caching.
    
    Args:
        max_age: Cache time in seconds (default: 1 year)
        immutable: Mark content as immutable
        vary_headers: Headers to include in Vary
        name: Shield name
        
    Returns:
        Shield: Static cache shield
    """
    config = CacheConfig(
        policy=CachePolicy.STATIC,
        directives={
            CacheDirective.PUBLIC: True,
            CacheDirective.IMMUTABLE: immutable,
            CacheDirective.NO_TRANSFORM: True,
        },
        max_age=max_age,
        s_max_age=max_age,
        enable_etag=True,
        enable_last_modified=True,
        handle_conditional=True,
        vary_headers=vary_headers or ["Accept-Encoding"],
        no_cache_sensitive=False,
    )
    
    cache_shield = CacheControlShield(config=config)
    return cache_shield.create_shield(name=name)


def dynamic_cache_shield(
    cache_condition_func: Callable[[Request, Response], bool],
    max_age_func: Optional[Callable[[Request, Response], Optional[int]]] = None,
    enable_etag: bool = True,
    vary_headers: Optional[List[str]] = None,
    name: str = "DynamicCache",
) -> Shield:
    """Create a cache shield with dynamic caching logic.
    
    Args:
        cache_condition_func: Function to determine if response should be cached
        max_age_func: Function to dynamically determine max-age
        enable_etag: Enable ETag generation
        vary_headers: Headers to include in Vary
        name: Shield name
        
    Returns:
        Shield: Dynamic cache shield
        
    Examples:
        ```python
        def should_cache(request: Request, response: Response) -> bool:
            # Only cache successful responses for non-admin users
            return (
                response.status_code == 200 and
                not request.url.path.startswith("/admin")
            )
        
        def get_max_age(request: Request, response: Response) -> Optional[int]:
            # Shorter cache for frequently changing data
            if "volatile" in request.url.path:
                return 60  # 1 minute
            else:
                return 300  # 5 minutes
        
        @app.get("/api/data/{item_id}")
        @dynamic_cache_shield(
            cache_condition_func=should_cache,
            max_age_func=get_max_age
        )
        def get_data(item_id: str):
            return {"data": f"item-{item_id}"}
        ```
    """
    config = CacheConfig(
        policy=CachePolicy.DYNAMIC,
        directives={
            CacheDirective.PRIVATE: True,
            CacheDirective.MUST_REVALIDATE: True,
        },
        enable_etag=enable_etag,
        enable_last_modified=True,
        handle_conditional=True,
        vary_headers=vary_headers or ["Authorization", "Accept-Encoding"],
        cache_condition_func=cache_condition_func,
        max_age_func=max_age_func,
    )
    
    cache_shield = CacheControlShield(config=config)
    return cache_shield.create_shield(name=name)


def conditional_cache_shield(
    authenticated_policy: CachePolicy = CachePolicy.PRIVATE,
    unauthenticated_policy: CachePolicy = CachePolicy.PUBLIC,
    authenticated_max_age: int = 300,
    unauthenticated_max_age: int = 3600,
    name: str = "ConditionalCache",
) -> Shield:
    """Create a cache shield with different policies for authenticated vs unauthenticated requests.
    
    Args:
        authenticated_policy: Cache policy for authenticated users
        unauthenticated_policy: Cache policy for unauthenticated users
        authenticated_max_age: Cache time for authenticated users
        unauthenticated_max_age: Cache time for unauthenticated users
        name: Shield name
        
    Returns:
        Shield: Conditional cache shield
    """
    def cache_condition(request: Request, response: Response) -> bool:
        # Always allow caching, but policy will determine specifics
        return 200 <= response.status_code < 300
    
    def get_max_age(request: Request, response: Response) -> Optional[int]:
        # Check for authentication indicators
        auth_headers = ["authorization", "x-auth-token", "x-api-key", "cookie"]
        is_authenticated = any(request.headers.get(h) for h in auth_headers)
        
        return authenticated_max_age if is_authenticated else unauthenticated_max_age
    
    # Use the unauthenticated policy as base and adjust dynamically
    config = CacheConfig(
        policy=unauthenticated_policy,
        directives={
            CacheDirective.PUBLIC: True,
            CacheDirective.MUST_REVALIDATE: True,
        },
        enable_etag=True,
        enable_last_modified=True,
        handle_conditional=True,
        vary_headers=["Authorization", "Accept-Encoding"],
        cache_condition_func=cache_condition,
        max_age_func=get_max_age,
    )
    
    cache_shield = CacheControlShield(config=config)
    return cache_shield.create_shield(name=name)