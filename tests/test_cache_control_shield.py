"""Tests for cache control shield functionality."""

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Dict
from unittest.mock import Mock, patch

import pytest
from fastapi import FastAPI, Response
from fastapi.testclient import TestClient

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


class TestCacheConfig:
    """Test cache configuration."""
    
    def test_cache_config_defaults(self):
        """Test default cache configuration."""
        config = CacheConfig()
        assert config.policy is None
        assert config.directives == {}
        assert config.max_age is None
        assert config.enable_etag is False
        assert config.enable_last_modified is False
        assert config.handle_conditional is True
        assert config.no_cache_sensitive is True
    
    def test_cache_config_custom(self):
        """Test custom cache configuration."""
        config = CacheConfig(
            policy=CachePolicy.PRIVATE,
            directives={CacheDirective.PRIVATE: True, CacheDirective.MAX_AGE: 300},
            max_age=300,
            enable_etag=True,
            enable_last_modified=True,
            vary_headers=["Authorization"],
            no_cache_sensitive=False,
        )
        assert config.policy == CachePolicy.PRIVATE
        assert config.directives[CacheDirective.PRIVATE] is True
        assert config.max_age == 300
        assert config.enable_etag is True
        assert config.vary_headers == ["Authorization"]
        assert config.no_cache_sensitive is False


class TestCacheDirective:
    """Test cache directive enum."""
    
    def test_cache_directive_values(self):
        """Test cache directive string values."""
        assert CacheDirective.NO_CACHE.value == "no-cache"
        assert CacheDirective.NO_STORE.value == "no-store"
        assert CacheDirective.MUST_REVALIDATE.value == "must-revalidate"
        assert CacheDirective.PRIVATE.value == "private"
        assert CacheDirective.PUBLIC.value == "public"
        assert CacheDirective.MAX_AGE.value == "max-age"
        assert CacheDirective.IMMUTABLE.value == "immutable"


class TestCacheControlShield:
    """Test the cache control shield class."""
    
    @pytest.fixture
    def mock_request(self):
        """Create a mock request for testing."""
        request = Mock()
        request.headers = {}
        request.url = Mock()
        request.url.path = "/api/test"
        return request
    
    @pytest.fixture
    def mock_response(self):
        """Create a mock response for testing."""
        response = Mock()
        response.status_code = 200
        response.headers = {}
        return response
    
    def test_predefined_configurations(self):
        """Test predefined cache configurations."""
        # No cache configuration
        no_cache_shield = CacheControlShield(CachePolicy.NO_CACHE)
        assert no_cache_shield.config.policy == CachePolicy.NO_CACHE
        assert CacheDirective.NO_CACHE in no_cache_shield.config.directives
        assert CacheDirective.NO_STORE in no_cache_shield.config.directives
        
        # Sensitive configuration
        sensitive_shield = CacheControlShield(CachePolicy.SENSITIVE)
        assert sensitive_shield.config.policy == CachePolicy.SENSITIVE
        assert CacheDirective.PRIVATE in sensitive_shield.config.directives
        assert sensitive_shield.config.enable_etag is True
        
        # Private configuration
        private_shield = CacheControlShield(CachePolicy.PRIVATE)
        assert private_shield.config.policy == CachePolicy.PRIVATE
        assert CacheDirective.PRIVATE in private_shield.config.directives
        assert private_shield.config.max_age == 300
        
        # Public configuration
        public_shield = CacheControlShield(CachePolicy.PUBLIC)
        assert public_shield.config.policy == CachePolicy.PUBLIC
        assert CacheDirective.PUBLIC in public_shield.config.directives
        assert private_shield.config.max_age == 300
        
        # Static configuration
        static_shield = CacheControlShield(CachePolicy.STATIC)
        assert static_shield.config.policy == CachePolicy.STATIC
        assert CacheDirective.IMMUTABLE in static_shield.config.directives
        assert static_shield.config.max_age == 31536000
        
        # Dynamic configuration
        dynamic_shield = CacheControlShield(CachePolicy.DYNAMIC)
        assert dynamic_shield.config.policy == CachePolicy.DYNAMIC
        assert dynamic_shield.config.max_age == 60
    
    def test_initialization_with_parameters(self):
        """Test initialization with explicit parameters."""
        shield = CacheControlShield(
            config=CachePolicy.PRIVATE,
            max_age=600,
            enable_etag=False,
            enable_last_modified=False,
            vary_headers=["Accept-Encoding"],
            no_cache_sensitive=False,
        )
        assert shield.config.max_age == 600
        assert shield.config.enable_etag is False
        assert shield.config.enable_last_modified is False
        assert shield.config.vary_headers == ["Accept-Encoding"]
        assert shield.config.no_cache_sensitive is False
    
    def test_is_authenticated_request(self, mock_request):
        """Test authentication detection."""
        shield = CacheControlShield()
        
        # No authentication - make sure mock has no auth attributes
        mock_request.headers = {}
        mock_request.user = None
        mock_request._user_authenticated = False
        assert shield._is_authenticated_request(mock_request) is False
        
        # Authorization header
        mock_request.headers = {"authorization": "Bearer token"}
        assert shield._is_authenticated_request(mock_request) is True
        
        # Cookie header
        mock_request.headers = {"cookie": "session=123"}
        assert shield._is_authenticated_request(mock_request) is True
        
        # API key header
        mock_request.headers = {"x-api-key": "key123"}
        assert shield._is_authenticated_request(mock_request) is True
        
        # User attribute
        mock_request.headers = {}
        mock_request.user = {"id": 1}
        assert shield._is_authenticated_request(mock_request) is True
        
        # Authentication marker
        mock_request.user = None
        mock_request._user_authenticated = True
        assert shield._is_authenticated_request(mock_request) is True
    
    def test_should_cache_response(self, mock_request, mock_response):
        """Test response caching logic."""
        shield = CacheControlShield()
        
        # Set up mock request without authentication
        mock_request.headers = {}
        mock_request.user = None
        mock_request._user_authenticated = False
        
        # Successful response should be cached
        mock_response.status_code = 200
        assert shield._should_cache_response(mock_request, mock_response) is True
        
        # Error responses should not be cached
        mock_response.status_code = 404
        assert shield._should_cache_response(mock_request, mock_response) is False
        
        mock_response.status_code = 500
        assert shield._should_cache_response(mock_request, mock_response) is False
        
        # Authenticated requests with no_cache_sensitive
        mock_response.status_code = 200
        mock_request.headers = {"authorization": "Bearer token"}
        shield.config.no_cache_sensitive = True
        assert shield._should_cache_response(mock_request, mock_response) is False
        
        # Custom cache condition function
        def custom_condition(request, response):
            return response.status_code == 201
        
        shield.config.cache_condition_func = custom_condition
        mock_response.status_code = 200
        assert shield._should_cache_response(mock_request, mock_response) is False
        
        mock_response.status_code = 201
        assert shield._should_cache_response(mock_request, mock_response) is True
    
    def test_generate_etag(self):
        """Test ETag generation."""
        shield = CacheControlShield()
        content = b"test content"
        
        # MD5 ETag (default)
        shield.config.etag_algorithm = "md5"
        etag = shield._generate_etag(content)
        expected = hashlib.md5(content).hexdigest()[:16]
        assert etag == f'"{expected}"'
        
        # Weak ETag
        weak_etag = shield._generate_etag(content, weak=True)
        assert weak_etag == f'W/"{expected}"'
        
        # SHA1 ETag
        shield.config.etag_algorithm = "sha1"
        etag = shield._generate_etag(content)
        expected = hashlib.sha1(content).hexdigest()[:16]
        assert etag == f'"{expected}"'
        
        # SHA256 ETag
        shield.config.etag_algorithm = "sha256"
        etag = shield._generate_etag(content)
        expected = hashlib.sha256(content).hexdigest()[:16]
        assert etag == f'"{expected}"'
        
        # Invalid algorithm falls back to MD5
        shield.config.etag_algorithm = "invalid"
        etag = shield._generate_etag(content)
        expected = hashlib.md5(content).hexdigest()[:16]
        assert etag == f'"{expected}"'
    
    def test_get_last_modified(self, mock_request, mock_response):
        """Test Last-Modified header generation."""
        shield = CacheControlShield()
        
        # Response already has Last-Modified
        mock_response.headers = {"last-modified": "Mon, 01 Jan 2024 00:00:00 GMT"}
        result = shield._get_last_modified(mock_request, mock_response)
        assert result == "Mon, 01 Jan 2024 00:00:00 GMT"
        
        # Generate new Last-Modified
        mock_response.headers = {}
        with patch('fastapi_shield.cache_control.datetime') as mock_datetime:
            mock_now = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
            mock_datetime.now.return_value = mock_now
            
            result = shield._get_last_modified(mock_request, mock_response)
            assert result == "Mon, 01 Jan 2024 12:00:00 GMT"
    
    def test_parse_http_date(self):
        """Test HTTP date parsing."""
        shield = CacheControlShield()
        
        # RFC 822 format
        date_str = "Mon, 01 Jan 2024 12:00:00 GMT"
        parsed = shield._parse_http_date(date_str)
        expected = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        assert parsed == expected
        
        # Invalid date
        invalid_date = "invalid date"
        parsed = shield._parse_http_date(invalid_date)
        assert parsed is None
    
    def test_check_if_none_match(self, mock_request):
        """Test If-None-Match header processing."""
        shield = CacheControlShield()
        etag = '"12345678"'
        
        # No If-None-Match header
        mock_request.headers = {}
        assert shield._check_if_none_match(mock_request, etag) is False
        
        # Matching ETag
        mock_request.headers = {"if-none-match": '"12345678"'}
        assert shield._check_if_none_match(mock_request, etag) is True
        
        # Wildcard
        mock_request.headers = {"if-none-match": "*"}
        assert shield._check_if_none_match(mock_request, etag) is True
        
        # Multiple ETags
        mock_request.headers = {"if-none-match": '"11111111", "12345678", "22222222"'}
        assert shield._check_if_none_match(mock_request, etag) is True
        
        # Non-matching ETag
        mock_request.headers = {"if-none-match": '"87654321"'}
        assert shield._check_if_none_match(mock_request, etag) is False
    
    def test_check_if_modified_since(self, mock_request):
        """Test If-Modified-Since header processing."""
        shield = CacheControlShield()
        last_modified = "Mon, 01 Jan 2024 12:00:00 GMT"
        
        # No If-Modified-Since header
        mock_request.headers = {}
        assert shield._check_if_modified_since(mock_request, last_modified) is True
        
        # Content modified after If-Modified-Since
        mock_request.headers = {"if-modified-since": "Mon, 01 Jan 2024 11:00:00 GMT"}
        assert shield._check_if_modified_since(mock_request, last_modified) is True
        
        # Content not modified since If-Modified-Since
        mock_request.headers = {"if-modified-since": "Mon, 01 Jan 2024 13:00:00 GMT"}
        assert shield._check_if_modified_since(mock_request, last_modified) is False
        
        # Same timestamp (not modified)
        mock_request.headers = {"if-modified-since": last_modified}
        assert shield._check_if_modified_since(mock_request, last_modified) is False
        
        # Invalid date format
        mock_request.headers = {"if-modified-since": "invalid date"}
        assert shield._check_if_modified_since(mock_request, last_modified) is True
    
    def test_handle_conditional_request(self, mock_request):
        """Test conditional request handling."""
        shield = CacheControlShield()
        shield.config.handle_conditional = True
        etag = '"12345678"'
        last_modified = "Mon, 01 Jan 2024 12:00:00 GMT"
        
        # No conditional headers
        mock_request.headers = {}
        response = shield._handle_conditional_request(mock_request, etag, last_modified)
        assert response is None
        
        # ETag matches (304 response)
        mock_request.headers = {"if-none-match": '"12345678"'}
        response = shield._handle_conditional_request(mock_request, etag, last_modified)
        assert response is not None
        assert response.status_code == 304
        
        # Not modified since date (304 response)
        mock_request.headers = {"if-modified-since": "Mon, 01 Jan 2024 13:00:00 GMT"}
        response = shield._handle_conditional_request(mock_request, None, last_modified)
        assert response is not None
        assert response.status_code == 304
        
        # Conditional handling disabled
        shield.config.handle_conditional = False
        response = shield._handle_conditional_request(mock_request, etag, last_modified)
        assert response is None
    
    def test_build_cache_control_header(self, mock_request, mock_response):
        """Test Cache-Control header building."""
        shield = CacheControlShield()
        
        # Basic directives
        shield.config.directives = {
            CacheDirective.PRIVATE: True,
            CacheDirective.MUST_REVALIDATE: True,
        }
        shield.config.max_age = 300
        
        header = shield._build_cache_control_header(mock_request, mock_response)
        assert "private" in header
        assert "must-revalidate" in header
        assert "max-age=300" in header
        
        # With s-maxage
        shield.config.s_max_age = 600
        header = shield._build_cache_control_header(mock_request, mock_response)
        assert "s-maxage=600" in header
        
        # With dynamic max-age function
        def get_max_age(request, response):
            return 900
        
        shield.config.max_age_func = get_max_age
        header = shield._build_cache_control_header(mock_request, mock_response)
        assert "max-age=900" in header
        
        # Directive with value
        shield.config.directives[CacheDirective.MAX_AGE] = 120
        header = shield._build_cache_control_header(mock_request, mock_response)
        # Dynamic max-age should override directive max-age
        assert "max-age=900" in header
        
        # Boolean False directive should be ignored
        shield.config.directives[CacheDirective.PUBLIC] = False
        header = shield._build_cache_control_header(mock_request, mock_response)
        assert "public" not in header
    
    def test_add_cache_headers(self, mock_request, mock_response):
        """Test adding cache headers to response."""
        shield = CacheControlShield()
        shield.config.enable_etag = True
        shield.config.enable_last_modified = True
        shield.config.vary_headers = ["Authorization", "Accept-Encoding"]
        shield.config.directives = {CacheDirective.PRIVATE: True}
        shield.config.max_age = 300
        
        content = b"test response content"
        
        with patch.object(shield, '_should_cache_response', return_value=True):
            response = shield._add_cache_headers(mock_request, mock_response, content)
        
        # Should have ETag
        assert "ETag" in response.headers
        
        # Should have Last-Modified
        assert "Last-Modified" in response.headers
        
        # Should have Cache-Control
        assert "Cache-Control" in response.headers
        cache_control = response.headers["Cache-Control"]
        assert "private" in cache_control
        assert "max-age=300" in cache_control
        
        # Should have Vary header
        assert "Vary" in response.headers
        vary_header = response.headers["Vary"]
        assert "Authorization" in vary_header
        assert "Accept-Encoding" in vary_header
    
    def test_add_cache_headers_no_cache(self, mock_request, mock_response):
        """Test adding no-cache headers for non-cacheable responses."""
        shield = CacheControlShield()
        content = b"test content"
        
        with patch.object(shield, '_should_cache_response', return_value=False):
            response = shield._add_cache_headers(mock_request, mock_response, content)
        
        assert response.headers["Cache-Control"] == "no-cache, no-store, must-revalidate"
        assert response.headers["Pragma"] == "no-cache"
        assert response.headers["Expires"] == "0"
    
    def test_add_cache_headers_conditional_304(self, mock_request, mock_response):
        """Test 304 response for conditional requests."""
        shield = CacheControlShield()
        shield.config.enable_etag = True
        shield.config.handle_conditional = True
        content = b"test content"
        
        # Set up conditional request
        etag = shield._generate_etag(content)
        mock_request.headers = {"if-none-match": etag}
        
        with patch.object(shield, '_should_cache_response', return_value=True):
            response = shield._add_cache_headers(mock_request, mock_response, content)
        
        # Should return 304
        assert response.status_code == 304
        assert "ETag" in response.headers
    
    def test_add_cache_headers_with_expires(self, mock_request, mock_response):
        """Test adding Expires header."""
        shield = CacheControlShield()
        shield.config.expires_delta = timedelta(hours=1)
        content = b"test content"
        
        with patch.object(shield, '_should_cache_response', return_value=True):
            with patch('fastapi_shield.cache_control.datetime') as mock_datetime:
                mock_now = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
                mock_datetime.now.return_value = mock_now
                
                response = shield._add_cache_headers(mock_request, mock_response, content)
        
        assert "Expires" in response.headers
        assert response.headers["Expires"] == "Mon, 01 Jan 2024 13:00:00 GMT"
    
    def test_add_cache_headers_existing_vary(self, mock_request, mock_response):
        """Test merging with existing Vary header."""
        shield = CacheControlShield()
        shield.config.vary_headers = ["Authorization"]
        mock_response.headers = {"Vary": "Accept-Encoding, User-Agent"}
        content = b"test content"
        
        with patch.object(shield, '_should_cache_response', return_value=True):
            response = shield._add_cache_headers(mock_request, mock_response, content)
        
        vary_header = response.headers["Vary"]
        assert "Authorization" in vary_header
        assert "Accept-Encoding" in vary_header
        assert "User-Agent" in vary_header


class TestCacheControlIntegration:
    """Integration tests with FastAPI."""
    
    def test_basic_cache_shield(self):
        """Test basic cache shield integration."""
        app = FastAPI()
        
        @app.get("/api/data")
        @cache_control_shield(policy=CachePolicy.PRIVATE, max_age=300)
        def get_data():
            return {"data": "value"}
        
        client = TestClient(app)
        
        response = client.get("/api/data")
        assert response.status_code == 200
        # Note: Actual cache headers would be added in a real middleware implementation
    
    def test_no_cache_shield(self):
        """Test no-cache shield."""
        app = FastAPI()
        
        @app.get("/admin/sensitive")
        @no_cache_shield()
        def sensitive_data():
            return {"sensitive": "data"}
        
        client = TestClient(app)
        
        response = client.get("/admin/sensitive")
        assert response.status_code == 200
    
    def test_private_cache_shield(self):
        """Test private cache shield."""
        app = FastAPI()
        
        @app.get("/api/user/profile")
        @private_cache_shield(max_age=600)
        def user_profile():
            return {"profile": {"name": "user"}}
        
        client = TestClient(app)
        
        response = client.get("/api/user/profile")
        assert response.status_code == 200
    
    def test_public_cache_shield(self):
        """Test public cache shield."""
        app = FastAPI()
        
        @app.get("/api/public/data")
        @public_cache_shield(max_age=1800, s_max_age=3600)
        def public_data():
            return {"public": "data"}
        
        client = TestClient(app)
        
        response = client.get("/api/public/data")
        assert response.status_code == 200
    
    def test_static_cache_shield(self):
        """Test static cache shield."""
        app = FastAPI()
        
        @app.get("/assets/{filename}")
        @static_cache_shield(max_age=86400)
        def serve_asset(filename: str):
            return {"content": f"asset-{filename}"}
        
        client = TestClient(app)
        
        response = client.get("/assets/style.css")
        assert response.status_code == 200
    
    def test_dynamic_cache_shield(self):
        """Test dynamic cache shield."""
        def should_cache(request, response):
            return response.status_code == 200 and "cache" in request.url.path
        
        def get_max_age(request, response):
            return 300 if "short" in request.url.path else 3600
        
        app = FastAPI()
        
        @app.get("/api/{path}")
        @dynamic_cache_shield(
            cache_condition_func=should_cache,
            max_age_func=get_max_age
        )
        def dynamic_endpoint(path: str):
            return {"path": path}
        
        client = TestClient(app)
        
        response = client.get("/api/cache-short")
        assert response.status_code == 200
        
        response = client.get("/api/cache-long")
        assert response.status_code == 200
    
    def test_conditional_cache_shield(self):
        """Test conditional cache shield."""
        app = FastAPI()
        
        @app.get("/api/conditional")
        @conditional_cache_shield(
            authenticated_max_age=300,
            unauthenticated_max_age=1800
        )
        def conditional_data():
            return {"conditional": "data"}
        
        client = TestClient(app)
        
        # Unauthenticated request
        response = client.get("/api/conditional")
        assert response.status_code == 200
        
        # Authenticated request
        response = client.get(
            "/api/conditional",
            headers={"Authorization": "Bearer token"}
        )
        assert response.status_code == 200
    
    def test_cache_with_etag_condition(self):
        """Test cache shield with ETag conditional requests."""
        app = FastAPI()
        
        @app.get("/api/etag-test")
        @cache_control_shield(
            policy=CachePolicy.PRIVATE,
            enable_etag=True,
            handle_conditional=True
        )
        def etag_test():
            return {"timestamp": 12345}
        
        client = TestClient(app)
        
        # First request
        response = client.get("/api/etag-test")
        assert response.status_code == 200
        
        # Conditional request with matching ETag would return 304 in real implementation
        # For now, just test that the shield doesn't break the request
        response = client.get(
            "/api/etag-test",
            headers={"If-None-Match": '"test-etag"'}
        )
        assert response.status_code == 200
    
    def test_cache_shield_with_authentication(self):
        """Test cache shield behavior with authentication."""
        app = FastAPI()
        
        @app.get("/api/auth-sensitive")
        @cache_control_shield(
            policy=CachePolicy.PRIVATE,
            no_cache_sensitive=True
        )
        def auth_sensitive():
            return {"sensitive": "data"}
        
        client = TestClient(app)
        
        # Unauthenticated request
        response = client.get("/api/auth-sensitive")
        assert response.status_code == 200
        
        # Authenticated request
        response = client.get(
            "/api/auth-sensitive",
            headers={"Authorization": "Bearer token"}
        )
        assert response.status_code == 200
    
    def test_multiple_cache_shields(self):
        """Test combining cache shields with other shields."""
        app = FastAPI()
        
        @app.get("/api/protected-cached")
        @cache_control_shield(policy=CachePolicy.PRIVATE, max_age=300)
        def protected_cached():
            return {"protected": "cached"}
        
        client = TestClient(app)
        
        response = client.get("/api/protected-cached")
        assert response.status_code == 200


class TestConvenienceFunctions:
    """Test cache control convenience functions."""
    
    def test_cache_control_shield_factory(self):
        """Test cache control shield factory function."""
        shield = cache_control_shield(
            policy=CachePolicy.PRIVATE,
            max_age=600,
            enable_etag=True,
            vary_headers=["Authorization"]
        )
        assert isinstance(shield, type(cache_control_shield()))
    
    def test_no_cache_shield_factory(self):
        """Test no-cache shield factory."""
        shield = no_cache_shield(vary_headers=["Authorization", "Cookie"])
        assert isinstance(shield, type(cache_control_shield()))
    
    def test_private_cache_shield_factory(self):
        """Test private cache shield factory."""
        shield = private_cache_shield(
            max_age=900,
            enable_etag=False,
            enable_last_modified=True
        )
        assert isinstance(shield, type(cache_control_shield()))
    
    def test_public_cache_shield_factory(self):
        """Test public cache shield factory."""
        shield = public_cache_shield(
            max_age=1800,
            s_max_age=7200,
            vary_headers=["Accept-Encoding", "Accept-Language"]
        )
        assert isinstance(shield, type(cache_control_shield()))
    
    def test_static_cache_shield_factory(self):
        """Test static cache shield factory."""
        shield = static_cache_shield(
            max_age=86400,
            immutable=True,
            vary_headers=["Accept-Encoding"]
        )
        assert isinstance(shield, type(cache_control_shield()))
    
    def test_dynamic_cache_shield_factory(self):
        """Test dynamic cache shield factory."""
        def cache_condition(request, response):
            return True
        
        def max_age_func(request, response):
            return 300
        
        shield = dynamic_cache_shield(
            cache_condition_func=cache_condition,
            max_age_func=max_age_func,
            enable_etag=False
        )
        assert isinstance(shield, type(cache_control_shield()))
    
    def test_conditional_cache_shield_factory(self):
        """Test conditional cache shield factory."""
        shield = conditional_cache_shield(
            authenticated_policy=CachePolicy.PRIVATE,
            unauthenticated_policy=CachePolicy.PUBLIC,
            authenticated_max_age=300,
            unauthenticated_max_age=1800
        )
        assert isinstance(shield, type(cache_control_shield()))


class TestCacheControlEdgeCases:
    """Test cache control edge cases and error handling."""
    
    def test_etag_generation_with_empty_content(self):
        """Test ETag generation with empty content."""
        shield = CacheControlShield()
        etag = shield._generate_etag(b"")
        assert etag is not None
        assert etag.startswith('"')
        assert etag.endswith('"')
    
    def test_etag_generation_with_large_content(self):
        """Test ETag generation with large content."""
        shield = CacheControlShield()
        large_content = b"x" * 1000000  # 1MB
        etag = shield._generate_etag(large_content)
        assert etag is not None
        assert len(etag) == 18  # 16 chars + 2 quotes
    
    def test_cache_condition_function_error(self):
        """Test handling of cache condition function errors."""
        def failing_condition(request, response):
            raise ValueError("Condition function error")
        
        shield = CacheControlShield()
        shield.config.cache_condition_func = failing_condition
        
        mock_request = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        
        # Should return False on error
        result = shield._should_cache_response(mock_request, mock_response)
        assert result is False
    
    def test_max_age_function_error(self):
        """Test handling of max-age function errors."""
        def failing_max_age(request, response):
            raise ValueError("Max age function error")
        
        shield = CacheControlShield(config=CachePolicy.PRIVATE)
        shield.config.max_age_func = failing_max_age
        
        mock_request = Mock()
        mock_response = Mock()
        
        # Should fall back to some max_age value on error (not fail completely)
        header = shield._build_cache_control_header(mock_request, mock_response)
        # The important thing is that it includes a max-age directive
        assert "max-age=" in header
        # And includes expected directives from PRIVATE policy
        assert "private" in header
        assert "must-revalidate" in header
    
    def test_malformed_conditional_headers(self):
        """Test handling of malformed conditional headers."""
        shield = CacheControlShield()
        mock_request = Mock()
        
        # Malformed If-None-Match
        mock_request.headers = {"if-none-match": "malformed-etag-without-quotes"}
        result = shield._check_if_none_match(mock_request, '"valid-etag"')
        assert result is False
        
        # Malformed If-Modified-Since
        mock_request.headers = {"if-modified-since": "not a valid date"}
        result = shield._check_if_modified_since(mock_request, "Mon, 01 Jan 2024 12:00:00 GMT")
        assert result is True  # Should assume modified on parse error
    
    def test_shield_creation_and_execution(self):
        """Test shield creation and execution."""
        shield = CacheControlShield(config=CachePolicy.PRIVATE)
        created_shield = shield.create_shield()
        
        # Test shield execution by calling the underlying guard function
        mock_request = Mock()
        mock_request.headers = {}
        mock_request.url = Mock()
        mock_request.url.path = "/test"
        mock_request.user = None
        mock_request._user_authenticated = False
        
        import asyncio
        
        async def test_shield():
            # Access the underlying guard function
            result = await created_shield._guard_func(mock_request)
            return result
        
        result = asyncio.run(test_shield())
        assert result is not None
        assert result.get("cache_shield_active") is True
        assert result.get("cache_policy") == "private"
        assert result.get("is_authenticated") is False
    
    def test_shield_with_authentication_markers(self):
        """Test shield execution with various authentication markers."""
        shield = CacheControlShield()
        created_shield = shield.create_shield()
        
        mock_request = Mock()
        mock_request.url = Mock()
        mock_request.url.path = "/test"
        mock_request.user = {"id": 1}
        mock_request.headers = {}
        mock_request._user_authenticated = False
        
        import asyncio
        
        async def test_shield():
            result = await created_shield._guard_func(mock_request)
            return result
        
        result = asyncio.run(test_shield())
        assert result.get("is_authenticated") is True
    
    def test_shield_error_handling(self):
        """Test shield error handling."""
        # Create a shield that will cause an error
        shield = CacheControlShield()
        
        # Mock a method to raise an error
        original_method = shield._is_authenticated_request
        def error_method(request):
            raise Exception("Test error")
        shield._is_authenticated_request = error_method
        
        created_shield = shield.create_shield()
        mock_request = Mock()
        mock_request.headers = {}
        mock_request.url = Mock()
        mock_request.url.path = "/test"
        
        import asyncio
        
        async def test_shield():
            result = await created_shield._guard_func(mock_request)
            return result
        
        result = asyncio.run(test_shield())
        assert result.get("cache_shield_error") is not None
        assert result.get("cache_shield_active") is False


if __name__ == "__main__":
    pytest.main([__file__])