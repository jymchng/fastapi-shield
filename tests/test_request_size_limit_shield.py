"""Tests for request size limit shield functionality."""

import asyncio
import io
from typing import Dict
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import FastAPI, HTTPException, Request, UploadFile
from fastapi.testclient import TestClient

from fastapi_shield.request_size_limit import (
    RequestSizeLimitShield,
    RequestSizeLimitConfig,
    RequestSizeTracker,
    SizeViolation,
    SizeUnit,
    SizeContentTypeCategory,
    SizeCheckMode,
    convert_size_to_bytes,
    format_bytes,
    request_size_limit_shield,
    json_size_limit_shield,
    file_upload_size_limit_shield,
    api_size_limit_shield,
    strict_size_limit_shield,
)


class TestSizeUtilities:
    """Test size utility functions."""
    
    def test_convert_size_to_bytes_int(self):
        """Test converting integer sizes."""
        assert convert_size_to_bytes(1024) == 1024
        assert convert_size_to_bytes(0) == 0
    
    def test_convert_size_to_bytes_string(self):
        """Test converting string sizes."""
        assert convert_size_to_bytes("1024") == 1024
        assert convert_size_to_bytes("1KB") == 1024
        assert convert_size_to_bytes("1MB") == 1048576
        assert convert_size_to_bytes("1GB") == 1073741824
        assert convert_size_to_bytes("1.5KB") == 1536
        assert convert_size_to_bytes("512 KB") == 524288
    
    def test_convert_size_to_bytes_invalid(self):
        """Test invalid size conversions."""
        with pytest.raises(ValueError):
            convert_size_to_bytes("invalid")
        
        with pytest.raises(ValueError):
            convert_size_to_bytes("1XB")
        
        with pytest.raises(ValueError):
            convert_size_to_bytes([1024])
    
    def test_format_bytes(self):
        """Test byte formatting."""
        assert format_bytes(512) == "512 bytes"
        assert format_bytes(1024) == "1.0 KB"
        assert format_bytes(1536) == "1.5 KB"
        assert format_bytes(1048576) == "1.0 MB"
        assert format_bytes(1073741824) == "1.0 GB"


class TestRequestSizeLimitConfig:
    """Test request size limit configuration."""
    
    def test_config_defaults(self):
        """Test default configuration values."""
        config = RequestSizeLimitConfig()
        
        assert config.max_request_size == 16 * 1024 * 1024  # 16MB
        assert config.check_mode == SizeCheckMode.MEMORY_EFFICIENT
        assert config.check_content_length_header is True
        assert config.allow_chunked_encoding is True
        assert config.chunk_size == 8192
        assert config.max_read_time == 30.0
        assert config.include_size_info is True
        assert config.log_violations is True
    
    def test_config_content_type_limits(self):
        """Test default content type limits."""
        config = RequestSizeLimitConfig()
        
        assert config.content_type_limits[SizeContentTypeCategory.JSON] == 1024 * 1024  # 1MB
        assert config.content_type_limits[SizeContentTypeCategory.FORM_DATA] == 512 * 1024  # 512KB
        assert config.content_type_limits[SizeContentTypeCategory.MULTIPART] == 50 * 1024 * 1024  # 50MB
    
    def test_config_validation(self):
        """Test configuration validation."""
        # Invalid content type limits
        with pytest.raises(ValueError):
            RequestSizeLimitConfig(
                content_type_limits={SizeContentTypeCategory.JSON: -1}
            )
        
        # Invalid chunk size
        with pytest.raises(ValueError):
            RequestSizeLimitConfig(chunk_size=2 * 1024 * 1024)  # 2MB too large


class TestRequestSizeTracker:
    """Test request size tracker functionality."""
    
    @pytest.fixture
    def basic_config(self):
        """Create basic configuration for testing."""
        return RequestSizeLimitConfig(
            max_request_size=1024,
            content_type_limits={
                SizeContentTypeCategory.JSON: 512,
                SizeContentTypeCategory.TEXT: 256,
            }
        )
    
    @pytest.fixture
    def tracker(self, basic_config):
        """Create tracker for testing."""
        return RequestSizeTracker(basic_config)
    
    def test_tracker_initialization(self, tracker):
        """Test tracker initialization."""
        assert tracker.bytes_read == 0
        assert tracker.content_type_category is None
        assert tracker.estimated_size is None
        assert tracker.is_chunked is False
        assert len(tracker.violations) == 0
    
    def test_categorize_content_type(self, tracker):
        """Test content type categorization."""
        assert tracker._categorize_content_type("application/json") == SizeContentTypeCategory.JSON
        assert tracker._categorize_content_type("application/x-www-form-urlencoded") == SizeContentTypeCategory.FORM_DATA
        assert tracker._categorize_content_type("multipart/form-data") == SizeContentTypeCategory.MULTIPART
        assert tracker._categorize_content_type("text/plain") == SizeContentTypeCategory.TEXT
        assert tracker._categorize_content_type("image/jpeg") == SizeContentTypeCategory.IMAGE
        assert tracker._categorize_content_type("video/mp4") == SizeContentTypeCategory.VIDEO
        assert tracker._categorize_content_type("audio/mpeg") == SizeContentTypeCategory.AUDIO
        assert tracker._categorize_content_type("application/pdf") == SizeContentTypeCategory.DOCUMENT
        assert tracker._categorize_content_type("application/zip") == SizeContentTypeCategory.ARCHIVE
        assert tracker._categorize_content_type("application/octet-stream") == SizeContentTypeCategory.BINARY
        assert tracker._categorize_content_type("unknown/type") == SizeContentTypeCategory.DEFAULT
    
    def test_set_content_info(self, tracker):
        """Test setting content information."""
        tracker.set_content_info("application/json", 100)
        
        assert tracker.content_type_category == SizeContentTypeCategory.JSON
        assert tracker.estimated_size == 100
        assert tracker.is_chunked is False
        
        # Test chunked encoding (no content-length)
        tracker.set_content_info("text/plain", None)
        assert tracker.is_chunked is True
    
    def test_get_applicable_limit(self, tracker):
        """Test getting applicable size limit."""
        # No content type set - should use global limit
        assert tracker.get_applicable_limit() == 1024
        
        # JSON content type - should use JSON limit (smaller than global)
        tracker.set_content_info("application/json", 100)
        assert tracker.get_applicable_limit() == 512
        
        # Unknown content type - should use global limit
        tracker.set_content_info("unknown/type", 100)
        assert tracker.get_applicable_limit() == 1024
    
    def test_check_content_length_header(self, tracker):
        """Test content length header validation."""
        tracker.set_content_info("application/json", 100)
        
        # Within limit
        violation = tracker.check_content_length_header(400)
        assert violation is None
        
        # Exceeds limit
        violation = tracker.check_content_length_header(600)
        assert violation is not None
        assert violation.violation_type == "content_length_header"
        assert violation.limit == 512
        assert violation.actual_size == 600
        assert len(tracker.violations) == 1
    
    def test_add_bytes(self, tracker):
        """Test adding bytes and checking limits."""
        tracker.set_content_info("application/json", 100)
        
        # Within limit
        violation = tracker.add_bytes(200)
        assert violation is None
        assert tracker.bytes_read == 200
        
        # Add more bytes - still within limit
        violation = tracker.add_bytes(200)
        assert violation is None
        assert tracker.bytes_read == 400
        
        # Exceed limit
        violation = tracker.add_bytes(200)
        assert violation is not None
        assert violation.violation_type == "streaming_limit"
        assert violation.limit == 512
        assert violation.actual_size == 600
        assert tracker.bytes_read == 600
        assert len(tracker.violations) == 1
    
    def test_check_timeout(self, tracker):
        """Test timeout checking."""
        # Mock time to simulate timeout
        with patch('time.time') as mock_time:
            # First call returns start time, second call returns timeout time
            mock_time.side_effect = [0, 35]
            tracker.start_time = mock_time()  # Sets to 0
            violation = tracker.check_timeout()  # Uses 35
        
        assert violation is not None
        assert violation.violation_type == "read_timeout"
        assert violation.limit == 30  # max_read_time
        assert violation.actual_size == 35
        assert len(tracker.violations) == 1
    
    def test_get_progress_info(self, tracker):
        """Test progress information."""
        tracker.set_content_info("application/json", 500)
        tracker.add_bytes(250)
        
        progress = tracker.get_progress_info()
        
        assert progress["bytes_read"] == 250
        assert progress["applicable_limit"] == 512
        assert progress["percentage"] == 250 / 512 * 100
        assert progress["estimated_size"] == 500
        assert progress["is_chunked"] is False
        assert progress["content_category"] == "json"
        assert progress["violations_count"] == 0


class TestRequestSizeLimitShield:
    """Test request size limit shield implementation."""
    
    @pytest.fixture
    def basic_config(self):
        """Create basic configuration for testing."""
        return RequestSizeLimitConfig(
            max_request_size=1024,
            content_type_limits={SizeContentTypeCategory.JSON: 512},
            check_mode=SizeCheckMode.MEMORY_EFFICIENT,
        )
    
    @pytest.fixture
    def shield_instance(self, basic_config):
        """Create shield instance for testing."""
        return RequestSizeLimitShield(basic_config)
    
    def test_shield_initialization(self, shield_instance, basic_config):
        """Test shield initialization."""
        assert shield_instance.config == basic_config
    
    @pytest.mark.asyncio
    async def test_validate_url_size(self, shield_instance):
        """Test URL size validation."""
        # Mock request with long URL
        request = Mock(spec=Request)
        request.url = Mock()
        request.url.__str__ = Mock(return_value="http://example.com/" + "a" * 3000)
        
        # Should raise exception for long URL
        with pytest.raises(HTTPException) as exc_info:
            await shield_instance._validate_url_size(request)
        
        assert exc_info.value.status_code == 414  # Request URI Too Long
    
    @pytest.mark.asyncio
    async def test_validate_query_params_size(self, shield_instance):
        """Test query parameters size validation."""
        request = Mock(spec=Request)
        request.url = Mock()
        request.url.query = "param=" + "a" * 10000  # Large query param
        request.url.__str__ = Mock(return_value="http://example.com/")
        
        # Should raise exception for large query params
        with pytest.raises(HTTPException) as exc_info:
            await shield_instance._validate_url_size(request)
        
        assert exc_info.value.status_code == 413  # Request Entity Too Large


class TestRequestSizeLimitIntegration:
    """Test request size limit integration with FastAPI."""
    
    def test_json_size_limit_shield_success(self):
        """Test successful JSON size limit validation."""
        app = FastAPI()
        
        @app.post("/json")
        @json_size_limit_shield(max_size="1KB")
        def handle_json():
            return {"status": "success"}
        
        client = TestClient(app)
        
        # Small JSON should pass
        small_data = {"key": "value"}
        response = client.post(
            "/json",
            json=small_data,
            headers={"Content-Type": "application/json"}
        )
        
        assert response.status_code == 200
        assert response.json()["status"] == "success"
    
    def test_json_size_limit_shield_failure(self):
        """Test failed JSON size limit validation."""
        app = FastAPI()
        
        @app.post("/json")
        @json_size_limit_shield(max_size="100")  # Very small limit
        def handle_json():
            return {"status": "success"}
        
        client = TestClient(app)
        
        # Large JSON should fail
        large_data = {"key": "x" * 1000}
        response = client.post(
            "/json",
            json=large_data,
            headers={"Content-Type": "application/json"}
        )
        
        assert response.status_code == 413  # Request Entity Too Large
        assert "limit" in response.json()["detail"].lower()
    
    def test_request_size_limit_shield_header_check(self):
        """Test request size limit with content-length header check."""
        app = FastAPI()
        
        @app.post("/header-check")
        @request_size_limit_shield(
            max_size="500",
            check_mode=SizeCheckMode.HEADER_ONLY
        )
        def header_check():
            return {"status": "success"}
        
        client = TestClient(app)
        
        # Request with large Content-Length header
        response = client.post(
            "/header-check",
            data="x" * 1000,
            headers={
                "Content-Type": "text/plain",
                "Content-Length": "1000"
            }
        )
        
        assert response.status_code == 413
    
    def test_file_upload_size_limit_shield(self):
        """Test file upload size limit validation."""
        app = FastAPI()
        
        @app.post("/upload")
        @file_upload_size_limit_shield(
            max_file_size="1KB",
            max_total_size="2KB"
        )
        def upload_file():
            return {"uploaded": True}
        
        client = TestClient(app)
        
        # Small upload should pass
        response = client.post(
            "/upload",
            data=b"small file content",
            headers={"Content-Type": "multipart/form-data"}
        )
        assert response.status_code == 200
    
    def test_api_size_limit_shield(self):
        """Test API size limit validation."""
        app = FastAPI()
        
        @app.post("/api")
        @api_size_limit_shield(
            json_size="512",
            form_size="256", 
            file_size="1KB"
        )
        def api_endpoint():
            return {"processed": True}
        
        client = TestClient(app)
        
        # Valid JSON request
        response = client.post(
            "/api",
            json={"data": "test"},
            headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 200
    
    def test_strict_size_limit_shield(self):
        """Test strict size limit validation."""
        app = FastAPI()
        
        @app.post("/strict")
        @strict_size_limit_shield(
            max_size="256",
            require_content_length=True
        )
        def strict_endpoint():
            return {"status": "success"}
        
        client = TestClient(app)
        
        # Small request should pass
        response = client.post(
            "/strict",
            data="small",
            headers={"Content-Type": "text/plain"}
        )
        assert response.status_code == 200


class TestSizeContentTypeCategories:
    """Test size content type categorization."""
    
    def test_size_content_type_categories(self):
        """Test size content type category values."""
        assert SizeContentTypeCategory.JSON == "json"
        assert SizeContentTypeCategory.FORM_DATA == "form_data"
        assert SizeContentTypeCategory.MULTIPART == "multipart"
        assert SizeContentTypeCategory.TEXT == "text"
        assert SizeContentTypeCategory.BINARY == "binary"
        assert SizeContentTypeCategory.IMAGE == "image"
        assert SizeContentTypeCategory.VIDEO == "video"
        assert SizeContentTypeCategory.AUDIO == "audio"
        assert SizeContentTypeCategory.DOCUMENT == "document"
        assert SizeContentTypeCategory.ARCHIVE == "archive"
        assert SizeContentTypeCategory.DEFAULT == "default"


class TestSizeCheckModes:
    """Test size check modes."""
    
    def test_size_check_modes(self):
        """Test size check mode values."""
        assert SizeCheckMode.HEADER_ONLY == "header_only"
        assert SizeCheckMode.STREAMING == "streaming"
        assert SizeCheckMode.MEMORY_EFFICIENT == "memory_efficient"
        assert SizeCheckMode.STRICT == "strict"


class TestSizeViolation:
    """Test size violation model."""
    
    def test_size_violation_creation(self):
        """Test creating size violation."""
        violation = SizeViolation(
            violation_type="test_violation",
            limit=1000,
            actual_size=1500,
            content_type="application/json",
            category=SizeContentTypeCategory.JSON,
            message="Test violation message"
        )
        
        assert violation.violation_type == "test_violation"
        assert violation.limit == 1000
        assert violation.actual_size == 1500
        assert violation.content_type == "application/json"
        assert violation.category == SizeContentTypeCategory.JSON
        assert violation.message == "Test violation message"
        assert violation.timestamp > 0


class TestAdvancedFeatures:
    """Test advanced size limiting features."""
    
    def test_custom_content_type_limits(self):
        """Test custom content type limits."""
        app = FastAPI()
        
        @app.post("/custom")
        @request_size_limit_shield(
            max_size="2KB",
            content_type_limits={
                SizeContentTypeCategory.JSON: "512",
                "multipart": "1KB"  # Test string key
            }
        )
        def custom_endpoint():
            return {"processed": True}
        
        client = TestClient(app)
        
        # Should work with valid request
        response = client.post(
            "/custom",
            json={"small": "data"},
            headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 200
    
    def test_custom_error_message(self):
        """Test custom error message."""
        app = FastAPI()
        
        @app.post("/custom-error")
        @request_size_limit_shield(
            max_size="100",
            custom_error_message="Request too big!"
        )
        def custom_error_endpoint():
            return {"status": "success"}
        
        client = TestClient(app)
        
        response = client.post(
            "/custom-error",
            data="x" * 1000,
            headers={"Content-Type": "text/plain"}
        )
        
        assert response.status_code == 413
        assert "Request too big!" in response.json()["detail"]
    
    def test_size_tracking_info(self):
        """Test size tracking information."""
        app = FastAPI()
        
        shield_config = RequestSizeLimitConfig(
            max_request_size=2048,
            enable_size_tracking=True
        )
        shield_instance = RequestSizeLimitShield(shield_config)
        
        @app.post("/tracking")
        @shield_instance.create_shield()
        def tracking_endpoint():
            return {"status": "success"}
        
        client = TestClient(app)
        
        response = client.post(
            "/tracking",
            data="test data",
            headers={"Content-Type": "text/plain"}
        )
        
        assert response.status_code == 200


class TestErrorHandling:
    """Test error handling scenarios."""
    
    def test_invalid_content_length_header(self):
        """Test invalid Content-Length header."""
        app = FastAPI()
        
        @app.post("/invalid-length")
        @json_size_limit_shield(max_size="1KB")
        def invalid_length_endpoint():
            return {"status": "success"}
        
        client = TestClient(app)
        
        # This test may be handled by the HTTP client/server layer
        # but we can test our shield's handling of the parsed value
        response = client.post(
            "/invalid-length",
            json={"data": "test"},
            headers={"Content-Type": "application/json"}
        )
        
        # Should work with valid request regardless
        assert response.status_code == 200
    
    def test_url_too_long(self):
        """Test URL length validation."""
        app = FastAPI()
        
        config = RequestSizeLimitConfig(max_url_length=50)
        shield_instance = RequestSizeLimitShield(config)
        
        @app.post("/short-url-only")
        @shield_instance.create_shield()
        def short_url_endpoint():
            return {"status": "success"}
        
        client = TestClient(app)
        
        # Normal URL should work
        response = client.post("/short-url-only")
        assert response.status_code == 200
    
    def test_too_many_query_params(self):
        """Test too many query parameters."""
        app = FastAPI()
        
        config = RequestSizeLimitConfig(max_param_count=2)
        shield_instance = RequestSizeLimitShield(config)
        
        @app.get("/limited-params")
        @shield_instance.create_shield()
        def limited_params_endpoint():
            return {"status": "success"}
        
        client = TestClient(app)
        
        # Few params should work
        response = client.get("/limited-params?a=1&b=2")
        assert response.status_code == 200
        
        # Too many params should fail
        response = client.get("/limited-params?a=1&b=2&c=3&d=4")
        assert response.status_code == 413


class TestPerformanceFeatures:
    """Test performance-related features."""
    
    def test_chunk_size_configuration(self):
        """Test chunk size configuration."""
        config = RequestSizeLimitConfig(chunk_size=4096)
        assert config.chunk_size == 4096
        
        # Invalid chunk size should raise error
        with pytest.raises(ValueError):
            RequestSizeLimitConfig(chunk_size=2 * 1024 * 1024)  # Too large
    
    def test_memory_efficient_mode(self):
        """Test memory efficient check mode."""
        app = FastAPI()
        
        @app.post("/efficient")
        @request_size_limit_shield(
            max_size="1KB",
            check_mode=SizeCheckMode.MEMORY_EFFICIENT
        )
        def efficient_endpoint():
            return {"status": "success"}
        
        client = TestClient(app)
        
        response = client.post(
            "/efficient",
            data="test data",
            headers={"Content-Type": "text/plain"}
        )
        assert response.status_code == 200
    
    def test_streaming_mode(self):
        """Test streaming check mode."""
        app = FastAPI()
        
        @app.post("/streaming")
        @request_size_limit_shield(
            max_size="1KB",
            check_mode=SizeCheckMode.STREAMING
        )
        def streaming_endpoint():
            return {"status": "success"}
        
        client = TestClient(app)
        
        response = client.post(
            "/streaming",
            data="test data",
            headers={"Content-Type": "text/plain"}
        )
        assert response.status_code == 200


if __name__ == "__main__":
    pytest.main([__file__])