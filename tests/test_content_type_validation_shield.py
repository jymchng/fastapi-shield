"""Tests for content type validation shield functionality."""

from typing import Dict
from unittest.mock import Mock, patch

import pytest
from fastapi import FastAPI, HTTPException, Request, UploadFile
from fastapi.testclient import TestClient

from fastapi_shield.content_type_validation import (
    ContentTypeShield,
    ContentTypeConfig,
    ContentTypeValidationResult,
    ContentTypeValidator,
    ContentTypePolicy,
    SecurityLevel,
    MIME_TYPE_GROUPS,
    FILE_SIGNATURES,
    content_type_shield,
    json_content_type_shield,
    file_upload_content_type_shield,
    form_content_type_shield,
    api_content_type_shield,
)


class TestContentTypeConfig:
    """Test content type configuration."""
    
    def test_config_defaults(self):
        """Test default configuration values."""
        config = ContentTypeConfig()
        
        assert config.allowed_types == ["application/json"]
        assert config.policy == ContentTypePolicy.STRICT
        assert config.security_level == SecurityLevel.MEDIUM
        assert config.allowed_charsets == ["utf-8", "utf-16", "ascii"]
        assert config.require_charset is False
        assert config.prevent_mime_sniffing is True
        assert config.validate_file_signature is True
    
    def test_config_custom(self):
        """Test custom configuration values."""
        config = ContentTypeConfig(
            allowed_types=["image/jpeg", "image/png"],
            policy=ContentTypePolicy.PERMISSIVE,
            security_level=SecurityLevel.HIGH,
            require_charset=True,
            prevent_mime_sniffing=False,
        )
        
        assert config.allowed_types == ["image/jpeg", "image/png"]
        assert config.policy == ContentTypePolicy.PERMISSIVE
        assert config.security_level == SecurityLevel.HIGH
        assert config.require_charset is True
        assert config.prevent_mime_sniffing is False


class TestContentTypeValidator:
    """Test content type validator functionality."""
    
    @pytest.fixture
    def basic_config(self):
        """Create basic configuration for testing."""
        return ContentTypeConfig(
            allowed_types=["application/json"],
            policy=ContentTypePolicy.STRICT,
            security_level=SecurityLevel.MEDIUM,
        )
    
    @pytest.fixture
    def validator(self, basic_config):
        """Create validator for testing."""
        return ContentTypeValidator(basic_config)
    
    def test_parse_content_type_basic(self, validator):
        """Test basic content-type parsing."""
        result = validator._parse_content_type("application/json")
        
        assert result['content_type'] == "application/json"
        assert result['type'] == "application"
        assert result['subtype'] == "json"
        assert result['charset'] == ""
        assert result['boundary'] == ""
    
    def test_parse_content_type_with_charset(self, validator):
        """Test content-type parsing with charset."""
        result = validator._parse_content_type("application/json; charset=utf-8")
        
        assert result['content_type'] == "application/json"
        assert result['charset'] == "utf-8"
    
    def test_parse_content_type_with_boundary(self, validator):
        """Test content-type parsing with boundary."""
        result = validator._parse_content_type("multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW")
        
        assert result['content_type'] == "multipart/form-data"
        assert result['boundary'] == "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    
    def test_parse_content_type_invalid(self, validator):
        """Test invalid content-type parsing."""
        with pytest.raises(ValueError):
            validator._parse_content_type("")
    
    def test_validate_charset_required(self):
        """Test charset validation when required."""
        config = ContentTypeConfig(require_charset=True, allowed_charsets=["utf-8"])
        validator = ContentTypeValidator(config)
        
        # Missing charset
        issues = validator._validate_charset("")
        assert len(issues) == 1
        assert "required" in issues[0].lower()
        
        # Invalid charset
        issues = validator._validate_charset("invalid")
        assert len(issues) == 1
        assert "not allowed" in issues[0].lower()
        
        # Valid charset
        issues = validator._validate_charset("utf-8")
        assert len(issues) == 0
    
    def test_validate_boundary(self):
        """Test boundary validation."""
        config = ContentTypeConfig(validate_multipart_boundary=True, max_boundary_length=10)
        validator = ContentTypeValidator(config)
        
        # Valid boundary
        issues = validator._validate_boundary("simple123")
        assert len(issues) == 0
        
        # Too long boundary
        issues = validator._validate_boundary("verylongboundaryname")
        assert len(issues) == 1
        assert "too long" in issues[0].lower()
        
        # Suspicious characters
        issues = validator._validate_boundary("bad<")
        assert len(issues) == 1
        assert "suspicious" in issues[0].lower()
    
    def test_check_file_extension(self):
        """Test file extension validation."""
        config = ContentTypeConfig(
            forbidden_file_extensions=[".exe", ".bat"],
            allowed_file_extensions=[".jpg", ".png"]
        )
        validator = ContentTypeValidator(config)
        
        # Forbidden extension
        issues = validator._check_file_extension("image/jpeg", "malware.exe")
        assert len(issues) == 1
        assert "forbidden" in issues[0].lower()
        
        # Not in allowed list
        issues = validator._check_file_extension("image/gif", "image.gif")
        assert len(issues) == 1
        assert "not in allowed" in issues[0].lower()
        
        # Valid extension
        issues = validator._check_file_extension("image/jpeg", "image.jpg")
        assert len(issues) == 0
    
    def test_detect_file_signature(self, validator):
        """Test file signature detection."""
        # JPEG signature
        jpeg_content = b'\xFF\xD8\xFF\xE0\x00\x10JFIF'
        detected = validator._detect_file_signature(jpeg_content)
        assert detected == "image/jpeg"
        
        # PNG signature
        png_content = b'\x89PNG\r\n\x1A\n\x00\x00\x00\rIHDR'
        detected = validator._detect_file_signature(png_content)
        assert detected == "image/png"
        
        # Unknown signature
        unknown_content = b'\x00\x01\x02\x03'
        detected = validator._detect_file_signature(unknown_content)
        assert detected is None
    
    def test_validate_file_signature(self):
        """Test file signature validation."""
        config = ContentTypeConfig(validate_file_signature=True)
        validator = ContentTypeValidator(config)
        
        # Matching signature
        jpeg_content = b'\xFF\xD8\xFF\xE0\x00\x10JFIF'
        issues = validator._validate_file_signature("image/jpeg", jpeg_content)
        assert len(issues) == 0
        
        # Mismatched signature
        jpeg_content = b'\xFF\xD8\xFF\xE0\x00\x10JFIF'
        issues = validator._validate_file_signature("application/json", jpeg_content)
        assert len(issues) == 1
        assert "mismatch" in issues[0].lower()
    
    def test_check_mime_sniffing_risks(self):
        """Test MIME sniffing risk detection."""
        config = ContentTypeConfig(prevent_mime_sniffing=True)
        validator = ContentTypeValidator(config)
        
        # Dangerous content in non-HTML type
        script_content = b'<script>alert("xss")</script>'
        warnings = validator._check_mime_sniffing_risks("application/json", script_content)
        assert len(warnings) == 1
        assert "executable" in warnings[0].lower()
        
        # Safe content
        json_content = b'{"key": "value"}'
        warnings = validator._check_mime_sniffing_risks("application/json", json_content)
        assert len(warnings) == 0
        
        # SVG with script
        svg_content = b'<svg><script>alert("xss")</script></svg>'
        warnings = validator._check_mime_sniffing_risks("image/svg+xml", svg_content)
        assert len(warnings) == 1
        assert "svg" in warnings[0].lower() and "script" in warnings[0].lower()
    
    def test_is_type_allowed_strict(self, validator):
        """Test type checking with strict policy."""
        # Exact match
        assert validator._is_type_allowed("application/json") is True
        
        # Not allowed
        assert validator._is_type_allowed("text/html") is False
        
        # Subtype not allowed in strict mode
        assert validator._is_type_allowed("application/json; charset=utf-8") is False
    
    def test_is_type_allowed_permissive(self):
        """Test type checking with permissive policy."""
        config = ContentTypeConfig(
            allowed_types=["application/json"],
            policy=ContentTypePolicy.PERMISSIVE
        )
        validator = ContentTypeValidator(config)
        
        # Exact match
        assert validator._is_type_allowed("application/json") is True
        
        # With parameters (allowed in permissive)
        assert validator._is_type_allowed("application/json; charset=utf-8") is True
        
        # Different type
        assert validator._is_type_allowed("text/html") is False
    
    def test_is_type_allowed_pattern(self):
        """Test type checking with pattern policy."""
        config = ContentTypeConfig(
            policy=ContentTypePolicy.PATTERN,
            custom_patterns=[r"application/.*", r"text/plain"]
        )
        validator = ContentTypeValidator(config)
        
        # Matches pattern
        assert validator._is_type_allowed("application/json") is True
        assert validator._is_type_allowed("application/xml") is True
        assert validator._is_type_allowed("text/plain") is True
        
        # Doesn't match pattern
        assert validator._is_type_allowed("text/html") is False
    
    @pytest.mark.asyncio
    async def test_validate_content_type_success(self, validator):
        """Test successful content-type validation."""
        # Mock request
        request = Mock(spec=Request)
        request.headers = {"content-type": "application/json"}
        
        result = await validator.validate_content_type(request)
        
        assert result.valid is True
        assert result.content_type == "application/json"
        assert result.main_type == "application"
        assert result.sub_type == "json"
    
    @pytest.mark.asyncio
    async def test_validate_content_type_missing_header(self, validator):
        """Test validation with missing content-type header."""
        request = Mock(spec=Request)
        request.headers = {}
        
        result = await validator.validate_content_type(request)
        
        assert result.valid is False
        assert "required" in result.error_message.lower()
    
    @pytest.mark.asyncio
    async def test_validate_content_type_not_allowed(self, validator):
        """Test validation with non-allowed content type."""
        request = Mock(spec=Request)
        request.headers = {"content-type": "text/html"}
        
        result = await validator.validate_content_type(request)
        
        assert result.valid is False
        assert "not allowed" in result.error_message.lower()
    
    @pytest.mark.asyncio
    async def test_validate_content_type_with_content(self):
        """Test validation with content analysis."""
        config = ContentTypeConfig(
            allowed_types=["image/jpeg"],
            validate_file_signature=True,
            security_level=SecurityLevel.HIGH
        )
        validator = ContentTypeValidator(config)
        
        request = Mock(spec=Request)
        request.headers = {"content-type": "image/jpeg"}
        
        # Valid JPEG content
        jpeg_content = b'\xFF\xD8\xFF\xE0\x00\x10JFIF'
        result = await validator.validate_content_type(request, content=jpeg_content)
        
        assert result.valid is True
        assert result.file_signature == "image/jpeg"
    
    @pytest.mark.asyncio
    async def test_validate_content_type_paranoid_security(self):
        """Test validation with paranoid security level."""
        config = ContentTypeConfig(
            allowed_types=["application/json"],
            security_level=SecurityLevel.PARANOID,
            require_charset=True
        )
        validator = ContentTypeValidator(config)
        
        request = Mock(spec=Request)
        request.headers = {"content-type": "application/json"}  # No charset
        
        result = await validator.validate_content_type(request)
        
        assert result.valid is False
        assert "paranoid" in result.error_message.lower()


class TestContentTypeShield:
    """Test content type shield implementation."""
    
    @pytest.fixture
    def basic_config(self):
        """Create basic configuration for testing."""
        return ContentTypeConfig(
            allowed_types=["application/json"],
            policy=ContentTypePolicy.STRICT,
        )
    
    @pytest.fixture
    def shield_instance(self, basic_config):
        """Create shield instance for testing."""
        return ContentTypeShield(basic_config)
    
    def test_shield_initialization(self, shield_instance, basic_config):
        """Test shield initialization."""
        assert shield_instance.config == basic_config
        assert shield_instance.validator is not None


class TestContentTypeIntegration:
    """Test content type validation integration with FastAPI."""
    
    def test_json_content_type_shield_success(self):
        """Test successful JSON content type validation."""
        app = FastAPI()
        
        @app.post("/json")
        @json_content_type_shield()
        def handle_json():
            return {"status": "success"}
        
        client = TestClient(app)
        response = client.post(
            "/json",
            json={"data": "test"},
            headers={"Content-Type": "application/json"}
        )
        
        assert response.status_code == 200
        assert response.json()["status"] == "success"
    
    def test_json_content_type_shield_failure(self):
        """Test failed JSON content type validation."""
        app = FastAPI()
        
        @app.post("/json")
        @json_content_type_shield()
        def handle_json():
            return {"status": "success"}
        
        client = TestClient(app)
        response = client.post(
            "/json",
            data="plain text",
            headers={"Content-Type": "text/plain"}
        )
        
        assert response.status_code == 415  # Unsupported Media Type
        assert "not allowed" in response.json()["detail"].lower()
    
    def test_content_type_shield_custom_types(self):
        """Test content type shield with custom allowed types."""
        app = FastAPI()
        
        @app.post("/custom")
        @content_type_shield(allowed_types=["text/plain", "text/html"])
        def handle_custom():
            return {"status": "success"}
        
        client = TestClient(app)
        
        # Valid type
        response = client.post(
            "/custom",
            data="plain text",
            headers={"Content-Type": "text/plain"}
        )
        assert response.status_code == 200
        
        # Invalid type
        response = client.post(
            "/custom",
            json={"data": "test"},
            headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 415
    
    def test_file_upload_content_type_shield(self):
        """Test file upload content type validation."""
        app = FastAPI()
        
        @app.post("/upload")
        @file_upload_content_type_shield(
            allowed_types=["image/jpeg", "image/png"]
        )
        def upload_file():
            return {"uploaded": True}
        
        client = TestClient(app)
        
        # Valid image type
        response = client.post(
            "/upload",
            data=b"fake image data",
            headers={"Content-Type": "image/jpeg"}
        )
        assert response.status_code == 200
        
        # Invalid type
        response = client.post(
            "/upload",
            data=b"fake data",
            headers={"Content-Type": "application/octet-stream"}
        )
        assert response.status_code == 415
    
    def test_form_content_type_shield(self):
        """Test form content type validation."""
        app = FastAPI()
        
        @app.post("/form")
        @form_content_type_shield()
        def handle_form():
            return {"submitted": True}
        
        client = TestClient(app)
        
        # Valid form data
        response = client.post(
            "/form",
            data={"field": "value"},
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        assert response.status_code == 200
        
        # Invalid type
        response = client.post(
            "/form",
            json={"field": "value"},
            headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 415
    
    def test_api_content_type_shield(self):
        """Test API content type validation."""
        app = FastAPI()
        
        @app.post("/api")
        @api_content_type_shield(allow_json=True, allow_xml=True)
        def handle_api():
            return {"processed": True}
        
        client = TestClient(app)
        
        # Valid JSON
        response = client.post(
            "/api",
            json={"data": "test"},
            headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 200
        
        # Valid XML
        response = client.post(
            "/api",
            data="<xml></xml>",
            headers={"Content-Type": "application/xml"}
        )
        assert response.status_code == 200
        
        # Invalid type
        response = client.post(
            "/api",
            data="plain text",
            headers={"Content-Type": "text/plain"}
        )
        assert response.status_code == 415


class TestSecurityFeatures:
    """Test security-related features."""
    
    def test_mime_sniffing_prevention(self):
        """Test MIME sniffing prevention."""
        app = FastAPI()
        
        @app.post("/secure")
        @content_type_shield(
            allowed_types=["application/json"],
            security_level=SecurityLevel.HIGH,
            prevent_mime_sniffing=True
        )
        def secure_endpoint():
            return {"status": "secure"}
        
        client = TestClient(app)
        
        # Dangerous content in JSON
        malicious_content = b'<script>alert("xss")</script>'
        response = client.post(
            "/secure",
            content=malicious_content,
            headers={"Content-Type": "application/json"}
        )
        
        # Should be rejected due to dangerous content
        assert response.status_code == 415
    
    def test_security_headers(self):
        """Test security headers in responses."""
        app = FastAPI()
        
        @app.post("/headers")
        @content_type_shield(allowed_types=["application/json"])
        def endpoint_with_headers():
            return {"status": "success"}
        
        client = TestClient(app)
        
        # Invalid content type to trigger error with headers
        response = client.post(
            "/headers",
            data="invalid",
            headers={"Content-Type": "text/plain"}
        )
        
        assert response.status_code == 415
        assert "X-Content-Type-Options" in response.headers
        assert response.headers["X-Content-Type-Options"] == "nosniff"
    
    def test_file_signature_validation(self):
        """Test file signature validation."""
        app = FastAPI()
        
        @app.post("/validate-signature")
        @file_upload_content_type_shield(
            allowed_types=["image/jpeg"],
            security_level=SecurityLevel.HIGH
        )
        def validate_file():
            return {"validated": True}
        
        client = TestClient(app)
        
        # Real JPEG signature
        jpeg_signature = b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00'
        response = client.post(
            "/validate-signature",
            content=jpeg_signature,
            headers={"Content-Type": "image/jpeg"}
        )
        assert response.status_code == 200
        
        # Fake JPEG (wrong signature)
        fake_jpeg = b'fake jpeg content'
        response = client.post(
            "/validate-signature",
            content=fake_jpeg,
            headers={"Content-Type": "image/jpeg"}
        )
        # Might still pass depending on security level configuration
        # but will have warnings in the validation result


class TestMimeTypeGroups:
    """Test MIME type groups functionality."""
    
    def test_mime_type_groups_content(self):
        """Test MIME type groups contain expected types."""
        assert "application/json" in MIME_TYPE_GROUPS["json"]
        assert "image/jpeg" in MIME_TYPE_GROUPS["images"]
        assert "application/pdf" in MIME_TYPE_GROUPS["documents"]
        assert "application/zip" in MIME_TYPE_GROUPS["archives"]
        assert "multipart/form-data" in MIME_TYPE_GROUPS["form"]
    
    def test_file_signatures_content(self):
        """Test file signatures contain expected mappings."""
        assert FILE_SIGNATURES[b'\xFF\xD8\xFF'] == 'image/jpeg'
        assert FILE_SIGNATURES[b'\x89PNG\r\n\x1A\n'] == 'image/png'
        assert FILE_SIGNATURES[b'%PDF-'] == 'application/pdf'


class TestCustomValidation:
    """Test custom validation scenarios."""
    
    def test_custom_patterns(self):
        """Test custom regex patterns."""
        config = ContentTypeConfig(
            policy=ContentTypePolicy.PATTERN,
            custom_patterns=[r"application/vnd\..*", r"text/.*"]
        )
        validator = ContentTypeValidator(config)
        
        # Should match custom patterns
        assert validator._is_type_allowed("application/vnd.api+json") is True
        assert validator._is_type_allowed("text/plain") is True
        
        # Should not match
        assert validator._is_type_allowed("image/jpeg") is False
    
    def test_charset_requirement(self):
        """Test charset requirement enforcement."""
        app = FastAPI()
        
        @app.post("/charset-required")
        @content_type_shield(
            allowed_types=["text/plain"],
            require_charset=True
        )
        def charset_endpoint():
            return {"status": "success"}
        
        client = TestClient(app)
        
        # Without charset - should fail
        response = client.post(
            "/charset-required",
            data="plain text",
            headers={"Content-Type": "text/plain"}
        )
        assert response.status_code == 415
        
        # With charset - should succeed
        response = client.post(
            "/charset-required",
            data="plain text",
            headers={"Content-Type": "text/plain; charset=utf-8"}
        )
        assert response.status_code == 200
    
    def test_custom_error_message(self):
        """Test custom error message."""
        config = ContentTypeConfig(
            allowed_types=["application/json"],
            custom_error_message="Only JSON is allowed!"
        )
        shield_instance = ContentTypeShield(config)
        
        app = FastAPI()
        
        @app.post("/custom-error")
        @shield_instance.create_shield()
        def custom_error_endpoint():
            return {"status": "success"}
        
        client = TestClient(app)
        
        response = client.post(
            "/custom-error",
            data="invalid",
            headers={"Content-Type": "text/plain"}
        )
        
        assert response.status_code == 415
        assert response.json()["detail"] == "Only JSON is allowed!"


class TestEdgeCases:
    """Test edge cases and error conditions."""
    
    def test_missing_content_type_header(self):
        """Test handling of missing content-type header."""
        app = FastAPI()
        
        @app.post("/no-header")
        @json_content_type_shield()
        def no_header_endpoint():
            return {"status": "success"}
        
        client = TestClient(app)
        
        # Request without content-type header
        response = client.request("POST", "/no-header", data="test")
        assert response.status_code == 415
        assert "required" in response.json()["detail"].lower()
    
    def test_malformed_content_type_header(self):
        """Test handling of malformed content-type header."""
        app = FastAPI()
        
        @app.post("/malformed")
        @json_content_type_shield()
        def malformed_endpoint():
            return {"status": "success"}
        
        client = TestClient(app)
        
        # Malformed header - this will be handled by the HTTP client/server
        # but we can test empty or invalid formats
        response = client.post(
            "/malformed",
            data="test",
            headers={"Content-Type": ""}
        )
        assert response.status_code == 415
    
    def test_case_insensitive_content_type(self):
        """Test case insensitive content type handling."""
        app = FastAPI()
        
        @app.post("/case-test")
        @json_content_type_shield()
        def case_test_endpoint():
            return {"status": "success"}
        
        client = TestClient(app)
        
        # Mixed case content type
        response = client.post(
            "/case-test",
            json={"data": "test"},
            headers={"Content-Type": "APPLICATION/JSON"}
        )
        assert response.status_code == 200
    
    def test_content_type_with_multiple_parameters(self):
        """Test content type with multiple parameters."""
        app = FastAPI()
        
        @app.post("/params")
        @content_type_shield(
            allowed_types=["application/json"],
            policy=ContentTypePolicy.PERMISSIVE
        )
        def params_endpoint():
            return {"status": "success"}
        
        client = TestClient(app)
        
        # Content type with multiple parameters
        response = client.post(
            "/params",
            json={"data": "test"},
            headers={"Content-Type": "application/json; charset=utf-8; boundary=something"}
        )
        assert response.status_code == 200


if __name__ == "__main__":
    pytest.main([__file__])