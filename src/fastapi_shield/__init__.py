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

__version__ = "0.1.4"

__all__ = ["Shield", "ShieldedDepends", "shield"]
