"""FastAPI Shield - Protect your FastAPI endpoints with ease.

FastAPI Shield provides a powerful decorator-based system for intercepting and validating
requests before they reach your FastAPI endpoints. It enables you to create reusable
'shields' that can validate authentication, authorization, rate limiting, input sanitization,
and more.

Key Components:
    - Shield: The main decorator class for creating request interceptors
    - ShieldedDepends: Dependency injection wrapper for shield-aware dependencies
    - shield: Factory function for creating Shield instances

Usage:
    ```python
    from fastapi_shield import Shield, ShieldedDepends, shield

    # Create a shield using the decorator
    @shield
    def auth_shield(request: Request):
        # Your validation logic here
        return validated_data_or_none

    # Apply shield to endpoint
    @app.get("/protected")
    @auth_shield
    def protected_endpoint():
        return {"message": "Access granted"}
    ```

For more information, visit: https://github.com/jymchng/fastapi-shield
"""

from fastapi_shield.shield import Shield, ShieldedDepends, shield
from fastapi_shield.rate_limit import (
    RateLimitShield,
    RateLimitAlgorithm,
    RateLimitBackend,
    MemoryRateLimitBackend,
    rate_limit,
    per_ip_rate_limit,
    per_user_rate_limit,
)
from fastapi_shield.input_validation import (
    InputValidationShield,
    ValidationRule,
    SanitizationType,
    ValidationType,
    InputSanitizer,
    InputValidator,
    input_validation_shield,
    create_xss_protection_shield,
    create_sql_injection_protection_shield,
    create_email_validation_shield,
    create_length_validation_shield,
)
from fastapi_shield.cors_security import (
    CORSSecurityShield,
    CORSConfig,
    CORSPolicy,
    cors_shield,
    strict_cors_shield,
    public_cors_shield,
    dynamic_cors_shield,
    authenticated_cors_shield,
)
from fastapi_shield.ip_geolocation import (
    IPGeolocationShield,
    IPRule,
    IPAction,
    IPRuleType,
    GeoLocation,
    GeolocationProvider,
    MockGeolocationProvider,
    IPApiGeolocationProvider,
    MaxMindGeolocationProvider,
    ip_geolocation_shield,
    country_blocking_shield,
    ip_whitelist_shield,
    proxy_detection_shield,
)
from fastapi_shield.cache_control import (
    CacheControlShield,
    CacheConfig,
    CachePolicy,
    CacheDirective,
    cache_control_shield,
    no_cache_shield,
    private_cache_shield,
    public_cache_shield,
    static_cache_shield,
    dynamic_cache_shield,
    conditional_cache_shield,
)

__version__ = "0.1.1"

__all__ = [
    "Shield", 
    "ShieldedDepends", 
    "shield",
    "RateLimitShield",
    "RateLimitAlgorithm",
    "RateLimitBackend",
    "MemoryRateLimitBackend",
    "rate_limit",
    "per_ip_rate_limit",
    "per_user_rate_limit",
    "InputValidationShield",
    "ValidationRule",
    "SanitizationType",
    "ValidationType",
    "InputSanitizer",
    "InputValidator",
    "input_validation_shield",
    "create_xss_protection_shield",
    "create_sql_injection_protection_shield",
    "create_email_validation_shield",
    "create_length_validation_shield",
    "CORSSecurityShield",
    "CORSConfig",
    "CORSPolicy",
    "cors_shield",
    "strict_cors_shield",
    "public_cors_shield",
    "dynamic_cors_shield",
    "authenticated_cors_shield",
    "IPGeolocationShield",
    "IPRule",
    "IPAction",
    "IPRuleType",
    "GeoLocation",
    "GeolocationProvider",
    "MockGeolocationProvider",
    "IPApiGeolocationProvider",
    "MaxMindGeolocationProvider",
    "ip_geolocation_shield",
    "country_blocking_shield",
    "ip_whitelist_shield",
    "proxy_detection_shield",
    "CacheControlShield",
    "CacheConfig",
    "CachePolicy",
    "CacheDirective",
    "cache_control_shield",
    "no_cache_shield",
    "private_cache_shield",
    "public_cache_shield",
    "static_cache_shield",
    "dynamic_cache_shield",
    "conditional_cache_shield",
]
