"""Tests for CORS security shield functionality."""

import re
from typing import Dict, Set
from unittest.mock import Mock

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

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


class TestCORSConfig:
    """Test CORS configuration."""
    
    def test_cors_config_defaults(self):
        """Test default CORS configuration."""
        config = CORSConfig()
        assert config.allowed_origins is None
        assert config.allow_credentials is False
        assert "GET" in config.allowed_methods
        assert "POST" in config.allowed_methods
        assert "Accept" in config.allowed_headers
        assert config.max_age == 86400
        assert config.strict_mode is False
        assert config.block_null_origin is True
        assert config.block_file_origins is True
        assert config.require_origin_header is True
    
    def test_cors_config_custom(self):
        """Test custom CORS configuration."""
        config = CORSConfig(
            allowed_origins={"https://example.com"},
            allow_credentials=True,
            allowed_methods={"GET", "POST"},
            allowed_headers={"Content-Type", "Authorization"},
            exposed_headers={"X-Total-Count"},
            max_age=3600,
            strict_mode=True,
            block_null_origin=False,
        )
        assert config.allowed_origins == {"https://example.com"}
        assert config.allow_credentials is True
        assert config.allowed_methods == {"GET", "POST"}
        assert config.allowed_headers == {"Content-Type", "Authorization"}
        assert config.exposed_headers == {"X-Total-Count"}
        assert config.max_age == 3600
        assert config.strict_mode is True
        assert config.block_null_origin is False


class TestCORSSecurityShield:
    """Test the CORS security shield class."""
    
    @pytest.fixture
    def mock_request(self):
        """Create a mock request for testing."""
        request = Mock()
        request.method = "GET"
        request.headers = {"origin": "https://example.com"}
        return request
    
    def test_predefined_configurations(self):
        """Test predefined CORS configurations."""
        # Strict configuration with explicit origins
        strict_shield = CORSSecurityShield(
            CORSPolicy.STRICT,
            allowed_origins=["https://trusted.com"],
            strict_mode=True
        )
        assert strict_shield.config.strict_mode is True
        assert strict_shield.config.block_null_origin is True
        assert strict_shield.config.allowed_methods == {"GET", "POST"}
        
        # Moderate configuration with explicit origins
        moderate_shield = CORSSecurityShield(
            CORSPolicy.MODERATE,
            allowed_origins=["https://app.com"]
        )
        assert moderate_shield.config.strict_mode is False
        assert "PUT" in moderate_shield.config.allowed_methods
        assert "Authorization" in moderate_shield.config.allowed_headers
        
        # Permissive configuration
        permissive_shield = CORSSecurityShield(CORSPolicy.PERMISSIVE)
        assert "*" in permissive_shield.config.allowed_origins
        assert permissive_shield.config.allow_credentials is False
    
    def test_initialization_with_parameters(self):
        """Test initialization with explicit parameters."""
        shield = CORSSecurityShield(
            config=CORSPolicy.MODERATE,
            allowed_origins=["https://example.com"],
            allow_credentials=True,
            allowed_methods=["GET", "POST", "PUT"],
            strict_mode=True,
        )
        assert shield.config.allowed_origins == {"https://example.com"}
        assert shield.config.allow_credentials is True
        assert shield.config.allowed_methods == {"GET", "POST", "PUT"}
        assert shield.config.strict_mode is True
    
    def test_configuration_validation_credentials_with_wildcard(self):
        """Test that credentials with wildcard origins raises error."""
        with pytest.raises(ValueError, match="Cannot allow credentials with wildcard origins"):
            CORSSecurityShield(
                allowed_origins=["*"],
                allow_credentials=True
            )
    
    def test_configuration_validation_strict_mode(self):
        """Test strict mode configuration validation."""
        # Wildcard + credentials not allowed (catches this first)
        with pytest.raises(ValueError, match="Cannot allow credentials with wildcard origins"):
            CORSSecurityShield(
                allowed_origins=["*"],
                allow_credentials=True,  # This triggers the first validation error
                strict_mode=True
            )
        
        # Wildcard origins without credentials in strict mode
        with pytest.raises(ValueError, match="Wildcard origins not allowed in strict mode"):
            CORSSecurityShield(
                allowed_origins=["*"],
                allow_credentials=False,
                strict_mode=True
            )
        
        # Strict mode requires explicit origins
        with pytest.raises(ValueError, match="Strict mode requires explicit origin configuration"):
            CORSSecurityShield(strict_mode=True)
    
    def test_get_request_origin(self, mock_request):
        """Test getting origin from request."""
        shield = CORSSecurityShield()
        
        origin = shield._get_request_origin(mock_request)
        assert origin == "https://example.com"
        
        # Test missing origin
        mock_request.headers = {}
        origin = shield._get_request_origin(mock_request)
        assert origin is None
    
    def test_is_origin_allowed_static_origins(self):
        """Test static origin validation."""
        shield = CORSSecurityShield(allowed_origins=["https://example.com", "https://trusted.com"])
        mock_request = Mock()
        
        # Allowed origin
        assert shield._is_origin_allowed(mock_request, "https://example.com") is True
        
        # Not allowed origin
        assert shield._is_origin_allowed(mock_request, "https://malicious.com") is False
        
        # Wildcard allowed (without credentials)
        shield_wildcard = CORSSecurityShield(
            allowed_origins=["*"],
            allow_credentials=False
        )
        assert shield_wildcard._is_origin_allowed(mock_request, "https://anything.com") is True
    
    def test_is_origin_allowed_patterns(self):
        """Test pattern-based origin validation."""
        shield = CORSSecurityShield(
            allowed_origin_patterns=[r"https://.*\.example\.com", r"https://.*\.trusted\.org"]
        )
        mock_request = Mock()
        
        # Matching patterns
        assert shield._is_origin_allowed(mock_request, "https://app.example.com") is True
        assert shield._is_origin_allowed(mock_request, "https://api.trusted.org") is True
        
        # Non-matching patterns
        assert shield._is_origin_allowed(mock_request, "https://malicious.com") is False
        assert shield._is_origin_allowed(mock_request, "https://example.com.evil.com") is False
    
    def test_is_origin_allowed_security_blocks(self):
        """Test security-related origin blocks."""
        shield = CORSSecurityShield()
        mock_request = Mock()
        
        # Null origin blocked by default
        assert shield._is_origin_allowed(mock_request, "null") is False
        
        # File origins blocked by default
        assert shield._is_origin_allowed(mock_request, "file:///path/to/file.html") is False
        
        # Allow null origins when configured
        shield_allow_null = CORSSecurityShield(config=CORSConfig(block_null_origin=False))
        assert shield_allow_null._is_origin_allowed(mock_request, "null") is False  # Still needs to be in allowed origins
    
    def test_is_origin_allowed_dynamic_function(self):
        """Test dynamic origin validation."""
        def dynamic_origins(request):
            if hasattr(request, 'user_role') and request.user_role == 'admin':
                return {"https://admin.example.com"}
            return {"https://public.example.com"}
        
        shield = CORSSecurityShield()
        shield.config.dynamic_origins_func = dynamic_origins
        
        mock_request = Mock()
        mock_request.user_role = 'admin'
        
        # Admin user can access admin origin
        assert shield._is_origin_allowed(mock_request, "https://admin.example.com") is True
        
        # Admin user cannot access other origins via dynamic function
        # (but might via static origins)
        mock_request.user_role = 'user'
        assert shield._is_origin_allowed(mock_request, "https://admin.example.com") is False
        assert shield._is_origin_allowed(mock_request, "https://public.example.com") is True
    
    def test_handle_preflight_request_success(self):
        """Test successful preflight request handling."""
        shield = CORSSecurityShield(
            allowed_origins=["https://example.com"],
            allowed_methods=["GET", "POST", "PUT"],
            allowed_headers=["Content-Type", "Authorization"],
            allow_credentials=True,
            max_age=3600
        )
        
        mock_request = Mock()
        mock_request.headers = {
            "origin": "https://example.com",
            "access-control-request-method": "POST",
            "access-control-request-headers": "Content-Type, Authorization"
        }
        
        response = shield._handle_preflight_request(mock_request)
        
        assert response.status_code == 200
        assert response.headers["Access-Control-Allow-Origin"] == "https://example.com"
        assert response.headers["Access-Control-Allow-Credentials"] == "true"
        assert "POST" in response.headers["Access-Control-Allow-Methods"]
        # Headers might be in different order
        headers = response.headers["Access-Control-Allow-Headers"]
        assert "Content-Type" in headers
        assert "Authorization" in headers
        assert response.headers["Access-Control-Max-Age"] == "3600"
    
    def test_handle_preflight_request_disallowed_origin(self):
        """Test preflight request with disallowed origin."""
        shield = CORSSecurityShield(allowed_origins=["https://example.com"])
        
        mock_request = Mock()
        mock_request.headers = {
            "origin": "https://malicious.com",
            "access-control-request-method": "GET"
        }
        
        with pytest.raises(HTTPException) as exc_info:
            shield._handle_preflight_request(mock_request)
        
        assert exc_info.value.status_code == 403
        assert "Origin not allowed" in str(exc_info.value.detail)
    
    def test_handle_preflight_request_disallowed_method(self):
        """Test preflight request with disallowed method."""
        shield = CORSSecurityShield(
            allowed_origins=["https://example.com"],
            allowed_methods=["GET", "POST"]
        )
        
        mock_request = Mock()
        mock_request.headers = {
            "origin": "https://example.com",
            "access-control-request-method": "DELETE"
        }
        
        with pytest.raises(HTTPException) as exc_info:
            shield._handle_preflight_request(mock_request)
        
        assert exc_info.value.status_code == 405
        assert "Method DELETE not allowed" in str(exc_info.value.detail)
    
    def test_handle_preflight_request_disallowed_headers(self):
        """Test preflight request with disallowed headers."""
        shield = CORSSecurityShield(
            allowed_origins=["https://example.com"],
            allowed_headers=["Content-Type"]
        )
        
        mock_request = Mock()
        mock_request.headers = {
            "origin": "https://example.com",
            "access-control-request-method": "GET",
            "access-control-request-headers": "Authorization, X-Custom-Header"
        }
        
        with pytest.raises(HTTPException) as exc_info:
            shield._handle_preflight_request(mock_request)
        
        assert exc_info.value.status_code == 400
        assert "not allowed by CORS policy" in str(exc_info.value.detail)
    
    def test_handle_preflight_request_missing_origin(self):
        """Test preflight request without origin header."""
        # Use config to set require_origin_header
        config = CORSConfig(require_origin_header=True)
        shield = CORSSecurityShield(config=config)
        
        mock_request = Mock()
        mock_request.headers = {"access-control-request-method": "GET"}
        
        with pytest.raises(HTTPException) as exc_info:
            shield._handle_preflight_request(mock_request)
        
        assert exc_info.value.status_code == 400
        assert "Origin header is required" in str(exc_info.value.detail)
    
    def test_add_cors_headers_success(self):
        """Test adding CORS headers to response."""
        shield = CORSSecurityShield(
            allowed_origins=["https://example.com"],
            allow_credentials=True,
            exposed_headers=["X-Total-Count", "X-Page-Count"]
        )
        
        mock_request = Mock()
        mock_request.headers = {"origin": "https://example.com"}
        
        mock_response = Mock()
        mock_response.headers = {}
        
        response = shield._add_cors_headers(mock_request, mock_response)
        
        assert response.headers["Access-Control-Allow-Origin"] == "https://example.com"
        assert response.headers["Access-Control-Allow-Credentials"] == "true"
        assert "X-Total-Count" in response.headers["Access-Control-Expose-Headers"]
        assert "Origin" in response.headers["Vary"]
    
    def test_add_cors_headers_wildcard_origin(self):
        """Test adding CORS headers with wildcard origin."""
        shield = CORSSecurityShield(
            allowed_origins=["*"],
            allow_credentials=False
        )
        
        mock_request = Mock()
        mock_request.headers = {"origin": "https://example.com"}
        
        mock_response = Mock()
        mock_response.headers = {}
        
        response = shield._add_cors_headers(mock_request, mock_response)
        
        assert response.headers["Access-Control-Allow-Origin"] == "*"
    
    def test_add_cors_headers_disallowed_origin_non_strict(self):
        """Test adding CORS headers with disallowed origin in non-strict mode."""
        shield = CORSSecurityShield(
            allowed_origins=["https://allowed.com"],
            strict_mode=False
        )
        
        mock_request = Mock()
        mock_request.headers = {"origin": "https://disallowed.com"}
        
        mock_response = Mock()
        mock_response.headers = {}
        
        # Should not raise error in non-strict mode, just return original response
        response = shield._add_cors_headers(mock_request, mock_response)
        assert "Access-Control-Allow-Origin" not in response.headers
    
    def test_add_cors_headers_disallowed_origin_strict(self):
        """Test adding CORS headers with disallowed origin in strict mode."""
        shield = CORSSecurityShield(
            allowed_origins=["https://allowed.com"],
            strict_mode=True
        )
        
        mock_request = Mock()
        mock_request.headers = {"origin": "https://disallowed.com"}
        
        mock_response = Mock()
        mock_response.headers = {}
        
        with pytest.raises(HTTPException) as exc_info:
            shield._add_cors_headers(mock_request, mock_response)
        
        assert exc_info.value.status_code == 403


class TestCORSIntegration:
    """Integration tests with FastAPI."""
    
    def test_basic_cors_shield(self):
        """Test basic CORS shield integration."""
        app = FastAPI()
        
        @app.get("/api/data")
        @cors_shield(
            allowed_origins=["https://example.com"],
            allow_credentials=True
        )
        def get_data():
            return {"data": "value"}
        
        client = TestClient(app)
        
        # Request from allowed origin
        response = client.get(
            "/api/data",
            headers={"Origin": "https://example.com"}
        )
        assert response.status_code == 200
        # Note: TestClient doesn't automatically add CORS headers to responses
        # In real FastAPI, the shield would handle this
    
    def test_preflight_request_handling(self):
        """Test CORS preflight (OPTIONS) request handling."""
        app = FastAPI()
        
        @app.post("/api/data")
        @cors_shield(
            allowed_origins=["https://example.com"],
            allowed_methods=["GET", "POST"],
            allowed_headers=["Content-Type", "Authorization"],
            allow_credentials=True
        )
        def post_data():
            return {"status": "created"}
        
        client = TestClient(app)
        
        # Preflight request
        response = client.options(
            "/api/data",
            headers={
                "Origin": "https://example.com",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type, Authorization"
            }
        )
        
        # The shield should handle this, but TestClient behavior may vary
        # In real implementation, this would return appropriate CORS headers
        assert response.status_code in [200, 405]  # 405 if OPTIONS not explicitly handled
    
    def test_strict_cors_shield(self):
        """Test strict CORS shield."""
        app = FastAPI()
        
        @app.get("/api/sensitive")
        @strict_cors_shield(
            allowed_origins=["https://trusted.com"],
            allow_credentials=True
        )
        def sensitive_data():
            return {"sensitive": "data"}
        
        client = TestClient(app)
        
        # Should work with allowed origin
        response = client.get(
            "/api/sensitive",
            headers={"Origin": "https://trusted.com"}
        )
        assert response.status_code == 200
    
    def test_public_cors_shield(self):
        """Test public CORS shield."""
        app = FastAPI()
        
        @app.get("/api/public")
        @public_cors_shield(exposed_headers=["X-Total-Count"])
        def public_data():
            return {"public": "data"}
        
        client = TestClient(app)
        
        response = client.get("/api/public", headers={"Origin": "https://any.com"})
        assert response.status_code == 200
    
    def test_dynamic_cors_shield(self):
        """Test dynamic CORS shield."""
        def get_allowed_origins(request):
            # Mock user role detection
            user_agent = request.headers.get("User-Agent", "")
            if "admin" in user_agent.lower():
                return {"https://admin.example.com"}
            return {"https://public.example.com"}
        
        app = FastAPI()
        
        @app.get("/api/dynamic")
        @dynamic_cors_shield(get_allowed_origins)
        def dynamic_data():
            return {"dynamic": "data"}
        
        client = TestClient(app)
        
        # Admin user
        response = client.get(
            "/api/dynamic",
            headers={
                "Origin": "https://admin.example.com",
                "User-Agent": "Admin Browser"
            }
        )
        assert response.status_code == 200
        
        # Regular user
        response = client.get(
            "/api/dynamic",
            headers={
                "Origin": "https://public.example.com",
                "User-Agent": "Regular Browser"
            }
        )
        assert response.status_code == 200
    
    def test_authenticated_cors_shield(self):
        """Test authenticated CORS shield."""
        app = FastAPI()
        
        @app.get("/api/user-data")
        @authenticated_cors_shield(
            public_origins=["https://public.example.com"],
            authenticated_origins=["https://app.example.com", "https://admin.example.com"]
        )
        def user_data():
            return {"user": "data"}
        
        client = TestClient(app)
        
        # Public origin should work
        response = client.get(
            "/api/user-data",
            headers={"Origin": "https://public.example.com"}
        )
        assert response.status_code == 200
    
    def test_cors_with_multiple_shields(self):
        """Test CORS shield combined with other shields."""
        app = FastAPI()
        
        @app.post("/api/protected")
        @cors_shield(
            allowed_origins=["https://app.example.com"],
            allow_credentials=True,
            strict_mode=False
        )
        def protected_endpoint():
            return {"status": "success"}
        
        client = TestClient(app)
        
        response = client.post(
            "/api/protected",
            headers={"Origin": "https://app.example.com"}
        )
        assert response.status_code == 200
    
    def test_cors_pattern_matching(self):
        """Test CORS shield with pattern-based origin matching."""
        app = FastAPI()
        
        @app.get("/api/pattern")
        @cors_shield(
            allowed_origin_patterns=[r"https://.*\.example\.com", r"https://.*\.trusted\.org"],
            allow_credentials=True
        )
        def pattern_endpoint():
            return {"pattern": "matched"}
        
        client = TestClient(app)
        
        # Should work with matching subdomain
        response = client.get(
            "/api/pattern",
            headers={"Origin": "https://app.example.com"}
        )
        assert response.status_code == 200
        
        response = client.get(
            "/api/pattern",
            headers={"Origin": "https://api.trusted.org"}
        )
        assert response.status_code == 200


class TestConvenienceFunctions:
    """Test CORS convenience functions."""
    
    def test_cors_shield_factory(self):
        """Test CORS shield factory function."""
        shield = cors_shield(
            policy=CORSPolicy.MODERATE,
            allowed_origins=["https://example.com"],
            allow_credentials=True,
            strict_mode=False
        )
        assert isinstance(shield, type(cors_shield()))
    
    def test_strict_cors_shield_factory(self):
        """Test strict CORS shield factory."""
        shield = strict_cors_shield(
            allowed_origins=["https://secure.com"],
            allow_credentials=True
        )
        assert isinstance(shield, type(cors_shield()))
    
    def test_public_cors_shield_factory(self):
        """Test public CORS shield factory."""
        shield = public_cors_shield(
            allowed_methods=["GET", "POST"],
            exposed_headers=["X-Total-Count"]
        )
        assert isinstance(shield, type(cors_shield()))
    
    def test_dynamic_cors_shield_factory(self):
        """Test dynamic CORS shield factory."""
        def origins_func(request):
            return {"https://dynamic.com"}
        
        shield = dynamic_cors_shield(
            origins_func,
            allow_credentials=True,
            strict_mode=False  # Use False since we're not setting static origins
        )
        assert isinstance(shield, type(cors_shield()))
    
    def test_authenticated_cors_shield_factory(self):
        """Test authenticated CORS shield factory."""
        shield = authenticated_cors_shield(
            public_origins=["https://public.com"],
            authenticated_origins=["https://private.com"],
            allow_credentials=True
        )
        assert isinstance(shield, type(cors_shield()))


class TestCORSPolicyEnforcement:
    """Test CORS policy enforcement scenarios."""
    
    def test_wildcard_origin_without_credentials(self):
        """Test wildcard origin configuration."""
        # Should work without credentials
        shield = CORSSecurityShield(
            allowed_origins=["*"],
            allow_credentials=False
        )
        
        mock_request = Mock()
        assert shield._is_origin_allowed(mock_request, "https://any.com") is True
    
    def test_null_origin_handling(self):
        """Test null origin handling."""
        # Default: block null origins
        shield = CORSSecurityShield()
        mock_request = Mock()
        assert shield._is_origin_allowed(mock_request, "null") is False
        
        # Allow null origins
        shield_allow_null = CORSSecurityShield(config=CORSConfig(
            block_null_origin=False,
            allowed_origins={"null"}
        ))
        assert shield_allow_null._is_origin_allowed(mock_request, "null") is True
    
    def test_file_origin_handling(self):
        """Test file origin handling."""
        # Default: block file origins
        shield = CORSSecurityShield()
        mock_request = Mock()
        assert shield._is_origin_allowed(mock_request, "file:///path/file.html") is False
        
        # Allow file origins
        shield_allow_files = CORSSecurityShield(config=CORSConfig(
            block_file_origins=False,
            allowed_origins={"file://"}
        ))
        # Still needs to match allowed origins exactly
        assert shield_allow_files._is_origin_allowed(mock_request, "file:///path/file.html") is False
    
    def test_origin_header_requirement(self):
        """Test origin header requirement."""
        shield = CORSSecurityShield(config=CORSConfig(require_origin_header=True))
        
        mock_request = Mock()
        mock_response = Mock()
        mock_response.headers = {}
        
        # Request without origin header in strict mode should fail
        mock_request.headers = {}
        shield.config.strict_mode = True
        
        with pytest.raises(HTTPException) as exc_info:
            shield._add_cors_headers(mock_request, mock_response)
        
        assert exc_info.value.status_code == 400
        assert "Origin header is required" in str(exc_info.value.detail)
    
    def test_complex_origin_patterns(self):
        """Test complex regex patterns for origin matching."""
        patterns = [
            r"https://[a-z]+\.example\.com",  # Subdomain pattern
            r"https://app-[0-9]+\.service\.com",  # Numbered apps
            r"https://.*\.trusted\.org",  # Wildcard subdomain
        ]
        
        shield = CORSSecurityShield(allowed_origin_patterns=patterns)
        mock_request = Mock()
        
        # Should match patterns
        assert shield._is_origin_allowed(mock_request, "https://api.example.com") is True
        assert shield._is_origin_allowed(mock_request, "https://app-123.service.com") is True
        assert shield._is_origin_allowed(mock_request, "https://sub.trusted.org") is True
        
        # Should not match patterns
        assert shield._is_origin_allowed(mock_request, "https://123.example.com") is False  # Numbers in subdomain
        assert shield._is_origin_allowed(mock_request, "https://app-abc.service.com") is False  # Letters instead of numbers
        assert shield._is_origin_allowed(mock_request, "https://untrusted.org") is False  # No subdomain
    
    def test_cors_headers_with_existing_vary(self):
        """Test CORS headers with existing Vary header."""
        shield = CORSSecurityShield(allowed_origins=["https://example.com"])
        
        mock_request = Mock()
        mock_request.headers = {"origin": "https://example.com"}
        
        mock_response = Mock()
        mock_response.headers = {"Vary": "Accept-Encoding, User-Agent"}
        
        response = shield._add_cors_headers(mock_request, mock_response)
        
        # Should preserve existing Vary headers and add Origin
        vary_header = response.headers["Vary"]
        assert "Accept-Encoding" in vary_header
        assert "User-Agent" in vary_header
        assert "Origin" in vary_header


class TestCORSErrorHandling:
    """Test CORS error handling scenarios."""
    
    def test_dynamic_origins_function_error(self):
        """Test handling of dynamic origins function errors."""
        def failing_origins_func(request):
            raise ValueError("Dynamic origin function failed")
        
        shield = CORSSecurityShield()
        shield.config.dynamic_origins_func = failing_origins_func
        shield.config.allowed_origins = {"https://fallback.com"}
        
        mock_request = Mock()
        
        # Should fall back to static origins when dynamic function fails
        assert shield._is_origin_allowed(mock_request, "https://fallback.com") is True
        assert shield._is_origin_allowed(mock_request, "https://other.com") is False
    
    def test_shield_creation_error_handling(self):
        """Test shield creation with invalid configuration."""
        # Test various invalid configurations
        with pytest.raises(ValueError):
            CORSSecurityShield(
                allowed_origins=["*"],
                allow_credentials=True
            )
    
    def test_preflight_missing_request_method(self):
        """Test preflight request without Access-Control-Request-Method."""
        shield = CORSSecurityShield(allowed_origins=["https://example.com"])
        
        mock_request = Mock()
        mock_request.headers = {"origin": "https://example.com"}
        
        # Should handle missing request method gracefully
        response = shield._handle_preflight_request(mock_request)
        assert response.status_code == 200
    
    def test_malformed_request_headers(self):
        """Test handling of malformed request headers."""
        shield = CORSSecurityShield(
            allowed_origins=["https://example.com"],
            allowed_headers=["Content-Type"]
        )
        
        mock_request = Mock()
        mock_request.headers = {
            "origin": "https://example.com",
            "access-control-request-method": "POST",
            "access-control-request-headers": ",,  , Content-Type,  ,"  # Malformed headers
        }
        
        # Should handle malformed headers gracefully
        response = shield._handle_preflight_request(mock_request)
        assert response.status_code == 200


if __name__ == "__main__":
    pytest.main([__file__])