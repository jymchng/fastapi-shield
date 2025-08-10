"""Comprehensive tests for response postprocessing functionality.

This module contains extensive tests for all response postprocessing components
including header manipulation, body transformation, content filtering,
compression, security headers, and the overall postprocessing framework.
"""

import gzip
import json
import pytest
import re
import zlib
from typing import Dict, Any
from unittest.mock import Mock, patch, AsyncMock

from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.testclient import TestClient
from starlette.responses import StreamingResponse

from fastapi_shield.response_postprocessing import (
    ResponsePostprocessor,
    HeaderProcessor,
    SecurityHeaderProcessor,
    BodyTransformer,
    ContentFilter,
    CompressionProcessor,
    PostprocessingShield,
    PostprocessingAction,
    PostprocessingResult,
    SecurityHeaderConfig,
    CompressionConfig,
    CompressionMethod,
    FilterRule,
    postprocessing_shield,
    create_security_headers_processor,
    create_compression_processor,
    create_content_filter,
)


class TestResponsePostprocessor:
    """Test the abstract ResponsePostprocessor base class."""
    
    def test_init(self):
        """Test postprocessor initialization."""
        class TestProcessor(ResponsePostprocessor):
            async def process(self, request, response, context):
                return PostprocessingResult(action=PostprocessingAction.CONTINUE)
        
        processor = TestProcessor("test", enabled=False)
        assert processor.name == "test"
        assert processor.enabled is False
    
    def test_is_applicable_enabled(self):
        """Test is_applicable method when enabled."""
        class TestProcessor(ResponsePostprocessor):
            async def process(self, request, response, context):
                return PostprocessingResult(action=PostprocessingAction.CONTINUE)
        
        processor = TestProcessor("test", enabled=True)
        request = Mock(spec=Request)
        response = Mock(spec=Response)
        
        assert processor.is_applicable(request, response) is True
    
    def test_is_applicable_disabled(self):
        """Test is_applicable method when disabled."""
        class TestProcessor(ResponsePostprocessor):
            async def process(self, request, response, context):
                return PostprocessingResult(action=PostprocessingAction.CONTINUE)
        
        processor = TestProcessor("test", enabled=False)
        request = Mock(spec=Request)
        response = Mock(spec=Response)
        
        assert processor.is_applicable(request, response) is False


class TestHeaderProcessor:
    """Test header manipulation functionality."""
    
    def test_init(self):
        """Test header processor initialization."""
        add_headers = {"X-Custom": "value"}
        remove_headers = ["X-Unwanted"]
        modify_headers = {"X-Modify": lambda x: x.upper()}
        
        processor = HeaderProcessor(
            add_headers=add_headers,
            remove_headers=remove_headers,
            modify_headers=modify_headers
        )
        
        assert processor.add_headers == add_headers
        assert processor.remove_headers == remove_headers
        assert processor.modify_headers == modify_headers
    
    @pytest.mark.asyncio
    async def test_process_disabled(self):
        """Test processing when disabled."""
        processor = HeaderProcessor(enabled=False)
        request = Mock(spec=Request)
        response = Mock(spec=Response)
        response.headers = {"Content-Type": "application/json"}
        
        result = await processor.process(request, response, {})
        
        assert result.action == PostprocessingAction.CONTINUE
        assert result.headers is None
    
    @pytest.mark.asyncio
    async def test_process_add_headers(self):
        """Test adding headers."""
        processor = HeaderProcessor(add_headers={"X-Custom": "test", "X-Another": "value"})
        request = Mock(spec=Request)
        response = Mock(spec=Response)
        response.headers = {"Content-Type": "application/json"}
        
        result = await processor.process(request, response, {})
        
        assert result.action == PostprocessingAction.TRANSFORM
        assert result.headers["X-Custom"] == "test"
        assert result.headers["X-Another"] == "value"
        assert result.headers["Content-Type"] == "application/json"
    
    @pytest.mark.asyncio
    async def test_process_remove_headers(self):
        """Test removing headers."""
        processor = HeaderProcessor(remove_headers=["X-Unwanted", "X-Another"])
        request = Mock(spec=Request)
        response = Mock(spec=Response)
        response.headers = {
            "Content-Type": "application/json",
            "X-Unwanted": "remove-me",
            "X-Another": "also-remove",
            "X-Keep": "keep-me"
        }
        
        result = await processor.process(request, response, {})
        
        assert result.action == PostprocessingAction.TRANSFORM
        assert "x-unwanted" not in result.headers
        assert "x-another" not in result.headers
        assert result.headers["X-Keep"] == "keep-me"
        assert result.headers["Content-Type"] == "application/json"
    
    @pytest.mark.asyncio
    async def test_process_modify_headers(self):
        """Test modifying headers."""
        modify_headers = {
            "content-type": lambda x: x.replace("json", "modified"),
            "x-custom": lambda x: x.upper()
        }
        processor = HeaderProcessor(modify_headers=modify_headers)
        request = Mock(spec=Request)
        response = Mock(spec=Response)
        response.headers = {
            "Content-Type": "application/json",
            "X-Custom": "lowercase",
            "X-Other": "unchanged"
        }
        
        result = await processor.process(request, response, {})
        
        assert result.action == PostprocessingAction.TRANSFORM
        assert result.headers["content-type"] == "application/modified"
        assert result.headers["x-custom"] == "LOWERCASE"
        assert result.headers["X-Other"] == "unchanged"
    
    @pytest.mark.asyncio
    async def test_process_combined_operations(self):
        """Test combined header operations."""
        processor = HeaderProcessor(
            add_headers={"X-New": "added"},
            remove_headers=["X-Remove"],
            modify_headers={"X-Modify": lambda x: x.upper()}
        )
        request = Mock(spec=Request)
        response = Mock(spec=Response)
        response.headers = {
            "Content-Type": "application/json",
            "X-Remove": "will-be-removed",
            "X-Modify": "will-be-uppercase"
        }
        
        result = await processor.process(request, response, {})
        
        assert result.action == PostprocessingAction.TRANSFORM
        assert result.headers["X-New"] == "added"
        assert "x-remove" not in result.headers
        assert result.headers["x-modify"] == "WILL-BE-UPPERCASE"


class TestSecurityHeaderProcessor:
    """Test security header injection functionality."""
    
    def test_init_default_config(self):
        """Test initialization with default configuration."""
        processor = SecurityHeaderProcessor()
        assert processor.config is not None
        assert processor.config.hsts_max_age == 31536000
        assert processor.config.frame_options == "DENY"
    
    def test_init_custom_config(self):
        """Test initialization with custom configuration."""
        config = SecurityHeaderConfig(
            csp_policy="default-src 'self'",
            hsts_max_age=3600,
            frame_options="SAMEORIGIN"
        )
        processor = SecurityHeaderProcessor(config=config)
        assert processor.config.csp_policy == "default-src 'self'"
        assert processor.config.hsts_max_age == 3600
        assert processor.config.frame_options == "SAMEORIGIN"
    
    @pytest.mark.asyncio
    async def test_process_disabled(self):
        """Test processing when disabled."""
        processor = SecurityHeaderProcessor(enabled=False)
        request = Mock(spec=Request)
        response = Mock(spec=Response)
        response.headers = {}
        
        result = await processor.process(request, response, {})
        
        assert result.action == PostprocessingAction.CONTINUE
    
    @pytest.mark.asyncio
    async def test_process_default_headers(self):
        """Test processing with default security headers."""
        processor = SecurityHeaderProcessor()
        request = Mock(spec=Request)
        response = Mock(spec=Response)
        response.headers = {}
        
        result = await processor.process(request, response, {})
        
        assert result.action == PostprocessingAction.TRANSFORM
        assert "Strict-Transport-Security" in result.headers
        assert "max-age=31536000" in result.headers["Strict-Transport-Security"]
        assert "includeSubDomains" in result.headers["Strict-Transport-Security"]
        assert result.headers["X-Frame-Options"] == "DENY"
        assert result.headers["X-Content-Type-Options"] == "nosniff"
        assert result.headers["X-XSS-Protection"] == "1; mode=block"
        assert result.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    
    @pytest.mark.asyncio
    async def test_process_csp_header(self):
        """Test Content Security Policy header."""
        config = SecurityHeaderConfig(csp_policy="default-src 'self'; script-src 'unsafe-inline'")
        processor = SecurityHeaderProcessor(config=config)
        request = Mock(spec=Request)
        response = Mock(spec=Response)
        response.headers = {}
        
        result = await processor.process(request, response, {})
        
        assert result.action == PostprocessingAction.TRANSFORM
        assert result.headers["Content-Security-Policy"] == "default-src 'self'; script-src 'unsafe-inline'"
    
    @pytest.mark.asyncio
    async def test_process_csp_report_only(self):
        """Test Content Security Policy report-only mode."""
        config = SecurityHeaderConfig(
            csp_policy="default-src 'self'",
            csp_report_only=True
        )
        processor = SecurityHeaderProcessor(config=config)
        request = Mock(spec=Request)
        response = Mock(spec=Response)
        response.headers = {}
        
        result = await processor.process(request, response, {})
        
        assert result.action == PostprocessingAction.TRANSFORM
        assert "Content-Security-Policy-Report-Only" in result.headers
        assert result.headers["Content-Security-Policy-Report-Only"] == "default-src 'self'"
    
    @pytest.mark.asyncio
    async def test_process_hsts_configurations(self):
        """Test various HSTS configurations."""
        # Basic HSTS
        config = SecurityHeaderConfig(
            hsts_max_age=7776000,
            hsts_include_subdomains=False,
            hsts_preload=False
        )
        processor = SecurityHeaderProcessor(config=config)
        request = Mock(spec=Request)
        response = Mock(spec=Response)
        response.headers = {}
        
        result = await processor.process(request, response, {})
        assert result.headers["Strict-Transport-Security"] == "max-age=7776000"
        
        # HSTS with subdomains and preload
        config = SecurityHeaderConfig(
            hsts_max_age=31536000,
            hsts_include_subdomains=True,
            hsts_preload=True
        )
        processor = SecurityHeaderProcessor(config=config)
        result = await processor.process(request, response, {})
        expected = "max-age=31536000; includeSubDomains; preload"
        assert result.headers["Strict-Transport-Security"] == expected
    
    @pytest.mark.asyncio
    async def test_process_custom_headers(self):
        """Test custom headers injection."""
        config = SecurityHeaderConfig(
            custom_headers={
                "X-Custom-Security": "enabled",
                "X-API-Version": "v1.0"
            }
        )
        processor = SecurityHeaderProcessor(config=config)
        request = Mock(spec=Request)
        response = Mock(spec=Response)
        response.headers = {}
        
        result = await processor.process(request, response, {})
        
        assert result.action == PostprocessingAction.TRANSFORM
        assert result.headers["X-Custom-Security"] == "enabled"
        assert result.headers["X-API-Version"] == "v1.0"
    
    @pytest.mark.asyncio
    async def test_process_permissions_policy(self):
        """Test Permissions Policy header."""
        config = SecurityHeaderConfig(
            permissions_policy="geolocation=(), microphone=(), camera=()"
        )
        processor = SecurityHeaderProcessor(config=config)
        request = Mock(spec=Request)
        response = Mock(spec=Response)
        response.headers = {}
        
        result = await processor.process(request, response, {})
        
        assert result.action == PostprocessingAction.TRANSFORM
        assert result.headers["Permissions-Policy"] == "geolocation=(), microphone=(), camera=()"


class TestBodyTransformer:
    """Test response body transformation functionality."""
    
    def test_init(self):
        """Test body transformer initialization."""
        transformers = {"application/json": lambda x: x}
        json_transformers = [lambda x: x]
        
        processor = BodyTransformer(
            transformers=transformers,
            json_transformers=json_transformers
        )
        
        assert processor.transformers == transformers
        assert processor.json_transformers == json_transformers
    
    @pytest.mark.asyncio
    async def test_process_disabled(self):
        """Test processing when disabled."""
        processor = BodyTransformer(enabled=False)
        request = Mock(spec=Request)
        response = Mock(spec=Response)
        response.headers = {"content-type": "application/json"}
        response.body = '{"test": "data"}'
        
        result = await processor.process(request, response, {})
        
        assert result.action == PostprocessingAction.CONTINUE
    
    @pytest.mark.asyncio
    async def test_process_no_body_attribute(self):
        """Test processing response without body attribute."""
        processor = BodyTransformer()
        request = Mock(spec=Request)
        response = Mock(spec=Response)
        response.headers = {"content-type": "application/json"}
        # No body attribute
        
        result = await processor.process(request, response, {})
        
        assert result.action == PostprocessingAction.CONTINUE
    
    @pytest.mark.asyncio
    async def test_process_json_transformation(self):
        """Test JSON body transformation."""
        def json_transform(data):
            data["transformed"] = True
            return data
        
        def content_transform(data):
            data["content_transformed"] = True
            return data
        
        processor = BodyTransformer(
            transformers={"application/json": content_transform},
            json_transformers=[json_transform]
        )
        
        request = Mock(spec=Request)
        response = Mock(spec=Response)
        response.headers = {"content-type": "application/json; charset=utf-8"}
        response.body = '{"original": "data"}'
        
        result = await processor.process(request, response, {})
        
        assert result.action == PostprocessingAction.TRANSFORM
        transformed_data = json.loads(result.body)
        assert transformed_data["original"] == "data"
        assert transformed_data["transformed"] is True
        assert transformed_data["content_transformed"] is True
    
    @pytest.mark.asyncio
    async def test_process_json_bytes_body(self):
        """Test JSON transformation with bytes body."""
        def json_transform(data):
            data["from_bytes"] = True
            return data
        
        processor = BodyTransformer(json_transformers=[json_transform])
        
        request = Mock(spec=Request)
        response = Mock(spec=Response)
        response.headers = {"content-type": "application/json"}
        response.body = b'{"original": "data"}'
        
        result = await processor.process(request, response, {})
        
        assert result.action == PostprocessingAction.TRANSFORM
        transformed_data = json.loads(result.body)
        assert transformed_data["original"] == "data"
        assert transformed_data["from_bytes"] is True
    
    @pytest.mark.asyncio
    async def test_process_text_transformation(self):
        """Test text content transformation."""
        def text_transform(content):
            return content.upper()
        
        processor = BodyTransformer(
            transformers={"text/plain": text_transform}
        )
        
        request = Mock(spec=Request)
        response = Mock(spec=Response)
        response.headers = {"content-type": "text/plain"}
        response.body = "hello world"
        
        result = await processor.process(request, response, {})
        
        assert result.action == PostprocessingAction.TRANSFORM
        assert result.body == "HELLO WORLD"
    
    @pytest.mark.asyncio
    async def test_process_transformation_error(self):
        """Test handling of transformation errors."""
        def failing_transform(data):
            raise ValueError("Transformation failed")
        
        processor = BodyTransformer(
            transformers={"application/json": failing_transform}
        )
        
        request = Mock(spec=Request)
        response = Mock(spec=Response)
        response.headers = {"content-type": "application/json"}
        response.body = '{"test": "data"}'
        
        result = await processor.process(request, response, {})
        
        assert result.action == PostprocessingAction.CONTINUE
        assert "Transformation failed" in result.reason
    
    @pytest.mark.asyncio
    async def test_process_unsupported_content_type(self):
        """Test processing unsupported content type."""
        processor = BodyTransformer(
            transformers={"application/json": lambda x: x}
        )
        
        request = Mock(spec=Request)
        response = Mock(spec=Response)
        response.headers = {"content-type": "text/html"}
        response.body = "<html>test</html>"
        
        result = await processor.process(request, response, {})
        
        assert result.action == PostprocessingAction.CONTINUE


class TestContentFilter:
    """Test content filtering and sanitization functionality."""
    
    def test_init(self):
        """Test content filter initialization."""
        filter_rules = [FilterRule(pattern=r"test", replacement="filtered")]
        blocked_patterns = [r"blocked"]
        
        processor = ContentFilter(
            filter_rules=filter_rules,
            blocked_patterns=blocked_patterns,
            sanitize_html=True
        )
        
        assert len(processor.filter_rules) == 1
        assert len(processor.blocked_patterns) == 1
        assert processor.sanitize_html is True
    
    @pytest.mark.asyncio
    async def test_process_disabled(self):
        """Test processing when disabled."""
        processor = ContentFilter(enabled=False)
        request = Mock(spec=Request)
        response = Mock(spec=Response)
        response.headers = {"content-type": "text/html"}
        response.body = "<script>alert('xss')</script>"
        
        result = await processor.process(request, response, {})
        
        assert result.action == PostprocessingAction.CONTINUE
    
    @pytest.mark.asyncio
    async def test_process_blocked_pattern(self):
        """Test blocking content with blocked patterns."""
        processor = ContentFilter(
            blocked_patterns=[r"malicious.*content", r"script.*alert"]
        )
        
        request = Mock(spec=Request)
        response = Mock(spec=Response)
        response.headers = {"content-type": "text/html"}
        response.body = "This contains script alert('xss') which is blocked"
        
        result = await processor.process(request, response, {})
        
        assert result.action == PostprocessingAction.BLOCK
        assert "Content blocked by pattern" in result.reason
    
    @pytest.mark.asyncio
    async def test_process_filter_rules(self):
        """Test content filtering with filter rules."""
        filter_rules = [
            FilterRule(
                pattern=r"badword",
                replacement="***",
                content_types={"text/plain", "text/html"}
            ),
            FilterRule(
                pattern=r"email@example\.com",
                replacement="[EMAIL_REDACTED]",
                content_types={"text/plain"}
            )
        ]
        
        processor = ContentFilter(filter_rules=filter_rules)
        
        request = Mock(spec=Request)
        response = Mock(spec=Response)
        response.headers = {"content-type": "text/plain"}
        response.body = "This badword and email@example.com should be filtered"
        
        result = await processor.process(request, response, {})
        
        assert result.action == PostprocessingAction.TRANSFORM
        assert "***" in result.body
        assert "[EMAIL_REDACTED]" in result.body
        assert "badword" not in result.body
        assert "email@example.com" not in result.body
    
    @pytest.mark.asyncio
    async def test_process_html_sanitization(self):
        """Test HTML sanitization."""
        processor = ContentFilter(sanitize_html=True)
        
        request = Mock(spec=Request)
        response = Mock(spec=Response)
        response.headers = {"content-type": "text/html"}
        response.body = """
        <html>
            <body>
                <p>Safe content</p>
                <script>alert('xss')</script>
                <iframe src="malicious.com"></iframe>
                <object data="malicious.swf"></object>
                <embed src="malicious.swf">
                <div onclick="malicious()">Click me</div>
                <a href="javascript:alert('xss')">Link</a>
            </body>
        </html>
        """
        
        result = await processor.process(request, response, {})
        
        assert result.action == PostprocessingAction.TRANSFORM
        assert "Safe content" in result.body
        assert "<script>" not in result.body
        assert "<iframe>" not in result.body
        assert "<object>" not in result.body
        assert "<embed>" not in result.body
        assert "onclick=" not in result.body
        assert "javascript:" not in result.body
    
    @pytest.mark.asyncio
    async def test_process_content_type_filtering(self):
        """Test filtering based on content type."""
        filter_rules = [
            FilterRule(
                pattern=r"filter-me",
                replacement="filtered",
                content_types={"text/html"}  # Only apply to HTML
            )
        ]
        
        processor = ContentFilter(filter_rules=filter_rules)
        
        # Test with matching content type
        request = Mock(spec=Request)
        response = Mock(spec=Response)
        response.headers = {"content-type": "text/html"}
        response.body = "This filter-me should be filtered"
        
        result = await processor.process(request, response, {})
        assert result.action == PostprocessingAction.TRANSFORM
        assert "filtered" in result.body
        
        # Test with non-matching content type
        response.headers = {"content-type": "text/plain"}
        response.body = "This filter-me should NOT be filtered"
        
        result = await processor.process(request, response, {})
        assert result.action == PostprocessingAction.CONTINUE
    
    @pytest.mark.asyncio
    async def test_process_no_body_attribute(self):
        """Test processing response without body attribute."""
        processor = ContentFilter()
        request = Mock(spec=Request)
        response = Mock(spec=Response)
        response.headers = {"content-type": "text/html"}
        # No body attribute
        
        result = await processor.process(request, response, {})
        
        assert result.action == PostprocessingAction.CONTINUE
    
    @pytest.mark.asyncio
    async def test_process_bytes_body(self):
        """Test processing bytes body."""
        processor = ContentFilter(
            filter_rules=[FilterRule(pattern=r"test", replacement="filtered")]
        )
        
        request = Mock(spec=Request)
        response = Mock(spec=Response)
        response.headers = {"content-type": "text/plain"}
        response.body = b"This is a test message"
        
        result = await processor.process(request, response, {})
        
        assert result.action == PostprocessingAction.TRANSFORM
        assert "filtered" in result.body
        assert "test" not in result.body


class TestCompressionProcessor:
    """Test response compression functionality."""
    
    def test_init(self):
        """Test compression processor initialization."""
        config = CompressionConfig(
            method=CompressionMethod.DEFLATE,
            min_size=2048,
            level=9
        )
        processor = CompressionProcessor(config=config)
        
        assert processor.config.method == CompressionMethod.DEFLATE
        assert processor.config.min_size == 2048
        assert processor.config.level == 9
    
    def test_is_applicable_disabled(self):
        """Test applicability when disabled."""
        processor = CompressionProcessor(enabled=False)
        request = Mock(spec=Request)
        request.headers = {"accept-encoding": "gzip"}
        response = Mock(spec=Response)
        response.headers = {"content-type": "text/plain"}
        
        assert processor.is_applicable(request, response) is False
    
    def test_is_applicable_no_accept_encoding(self):
        """Test applicability when client doesn't accept compression."""
        processor = CompressionProcessor()
        request = Mock(spec=Request)
        request.headers = {"accept-encoding": "identity"}
        response = Mock(spec=Response)
        response.headers = {"content-type": "text/plain"}
        
        assert processor.is_applicable(request, response) is False
    
    def test_is_applicable_unsupported_content_type(self):
        """Test applicability with unsupported content type."""
        config = CompressionConfig(content_types={"text/plain"})
        processor = CompressionProcessor(config=config)
        request = Mock(spec=Request)
        request.headers = {"accept-encoding": "gzip"}
        response = Mock(spec=Response)
        response.headers = {"content-type": "image/png"}
        
        assert processor.is_applicable(request, response) is False
    
    def test_is_applicable_already_compressed(self):
        """Test applicability when response is already compressed."""
        processor = CompressionProcessor()
        request = Mock(spec=Request)
        request.headers = {"accept-encoding": "gzip"}
        response = Mock(spec=Response)
        response.headers = {
            "content-type": "text/plain",
            "content-encoding": "gzip"
        }
        
        assert processor.is_applicable(request, response) is False
    
    def test_is_applicable_valid(self):
        """Test applicability with valid conditions."""
        processor = CompressionProcessor()
        request = Mock(spec=Request)
        request.headers = {"accept-encoding": "gzip, deflate"}
        response = Mock(spec=Response)
        response.headers = {"content-type": "text/plain"}
        
        assert processor.is_applicable(request, response) is True
    
    @pytest.mark.asyncio
    async def test_process_not_applicable(self):
        """Test processing when not applicable."""
        processor = CompressionProcessor()
        request = Mock(spec=Request)
        request.headers = {"accept-encoding": "identity"}
        response = Mock(spec=Response)
        response.headers = {"content-type": "text/plain"}
        
        result = await processor.process(request, response, {})
        
        assert result.action == PostprocessingAction.CONTINUE
    
    @pytest.mark.asyncio
    async def test_process_no_body_attribute(self):
        """Test processing response without body attribute."""
        processor = CompressionProcessor()
        request = Mock(spec=Request)
        request.headers = {"accept-encoding": "gzip"}
        response = Mock(spec=Response)
        response.headers = {"content-type": "text/plain"}
        # No body attribute
        
        result = await processor.process(request, response, {})
        
        assert result.action == PostprocessingAction.CONTINUE
    
    @pytest.mark.asyncio
    async def test_process_small_content(self):
        """Test processing content smaller than minimum size."""
        config = CompressionConfig(min_size=1000)
        processor = CompressionProcessor(config=config)
        
        request = Mock(spec=Request)
        request.headers = {"accept-encoding": "gzip"}
        response = Mock(spec=Response)
        response.headers = {"content-type": "text/plain"}
        response.body = "small"
        
        result = await processor.process(request, response, {})
        
        assert result.action == PostprocessingAction.CONTINUE
    
    @pytest.mark.asyncio
    async def test_process_gzip_compression(self):
        """Test GZIP compression."""
        config = CompressionConfig(method=CompressionMethod.GZIP, min_size=10)
        processor = CompressionProcessor(config=config)
        
        content = "This is a test content that should be compressed with GZIP"
        
        request = Mock(spec=Request)
        request.headers = {"accept-encoding": "gzip"}
        response = Mock(spec=Response)
        response.headers = {"content-type": "text/plain"}
        response.body = content
        
        result = await processor.process(request, response, {})
        
        assert result.action == PostprocessingAction.TRANSFORM
        assert result.headers["content-encoding"] == "gzip"
        assert result.headers["content-length"] == str(len(result.body))
        
        # Verify compression worked
        decompressed = gzip.decompress(result.body).decode()
        assert decompressed == content
    
    @pytest.mark.asyncio
    async def test_process_deflate_compression(self):
        """Test DEFLATE compression."""
        config = CompressionConfig(method=CompressionMethod.DEFLATE, min_size=10)
        processor = CompressionProcessor(config=config)
        
        content = "This is a test content that should be compressed with DEFLATE"
        
        request = Mock(spec=Request)
        request.headers = {"accept-encoding": "deflate"}
        response = Mock(spec=Response)
        response.headers = {"content-type": "text/plain"}
        response.body = content
        
        result = await processor.process(request, response, {})
        
        assert result.action == PostprocessingAction.TRANSFORM
        assert result.headers["content-encoding"] == "deflate"
        assert result.headers["content-length"] == str(len(result.body))
        
        # Verify compression worked
        decompressed = zlib.decompress(result.body).decode()
        assert decompressed == content
    
    @pytest.mark.asyncio
    async def test_process_string_body(self):
        """Test compression with string body."""
        config = CompressionConfig(min_size=10)
        processor = CompressionProcessor(config=config)
        
        content = "This is a string body that should be compressed"
        
        request = Mock(spec=Request)
        request.headers = {"accept-encoding": "gzip"}
        response = Mock(spec=Response)
        response.headers = {"content-type": "text/plain"}
        response.body = content
        
        result = await processor.process(request, response, {})
        
        assert result.action == PostprocessingAction.TRANSFORM
        assert result.headers["content-encoding"] == "gzip"
        
        # Verify compression worked
        decompressed = gzip.decompress(result.body).decode()
        assert decompressed == content
    
    @pytest.mark.asyncio
    async def test_process_compression_error(self):
        """Test handling compression errors."""
        config = CompressionConfig(min_size=10)  # Lower minimum size to ensure compression is attempted
        processor = CompressionProcessor(config=config)
        
        request = Mock(spec=Request)
        request.headers = {"accept-encoding": "gzip"}
        response = Mock(spec=Response)
        response.headers = {"content-type": "text/plain"}
        response.body = "This is a test content that should trigger compression error and is long enough"
        
        with patch('fastapi_shield.response_postprocessing.gzip.compress', side_effect=Exception("Compression failed")):
            result = await processor.process(request, response, {})
        
        assert result.action == PostprocessingAction.CONTINUE
        assert result.reason is not None
        assert "Compression failed" in result.reason


class TestPostprocessingShield:
    """Test the PostprocessingShield class."""
    
    def test_init(self):
        """Test postprocessing shield initialization."""
        def dummy_shield(request: Request):
            return {"user": "test"}
        
        processors = [HeaderProcessor()]
        shield = PostprocessingShield(dummy_shield, postprocessors=processors)
        
        assert len(shield.postprocessors) == 1
        assert isinstance(shield.postprocessors[0], HeaderProcessor)
    
    def test_add_postprocessor(self):
        """Test adding postprocessor."""
        def dummy_shield(request: Request):
            return {"user": "test"}
        
        shield = PostprocessingShield(dummy_shield)
        processor = HeaderProcessor(name="test")
        
        shield.add_postprocessor(processor)
        
        assert len(shield.postprocessors) == 1
        assert shield.postprocessors[0] == processor
    
    def test_remove_postprocessor(self):
        """Test removing postprocessor."""
        def dummy_shield(request: Request):
            return {"user": "test"}
        
        processors = [
            HeaderProcessor(name="header1"),
            SecurityHeaderProcessor(name="security"),
            HeaderProcessor(name="header2")
        ]
        shield = PostprocessingShield(dummy_shield, postprocessors=processors)
        
        # Remove existing processor
        result = shield.remove_postprocessor("security")
        assert result is True
        assert len(shield.postprocessors) == 2
        assert all(p.name != "security" for p in shield.postprocessors)
        
        # Try to remove non-existing processor
        result = shield.remove_postprocessor("nonexistent")
        assert result is False
        assert len(shield.postprocessors) == 2
    
    @pytest.mark.asyncio
    async def test_apply_postprocessors_continue(self):
        """Test applying postprocessors that continue."""
        processor = Mock(spec=ResponsePostprocessor)
        processor.process.return_value = PostprocessingResult(action=PostprocessingAction.CONTINUE)
        
        def dummy_shield(request: Request):
            return {"user": "test"}
        
        shield = PostprocessingShield(dummy_shield, postprocessors=[processor])
        
        request = Mock(spec=Request)
        response = Mock(spec=Response)
        context = {}
        
        result = await shield._apply_postprocessors(request, response, context)
        
        assert result == response
        processor.process.assert_called_once_with(request, response, context)
    
    @pytest.mark.asyncio
    async def test_apply_postprocessors_block(self):
        """Test applying postprocessors that block."""
        processor = Mock(spec=ResponsePostprocessor)
        processor.process.return_value = PostprocessingResult(
            action=PostprocessingAction.BLOCK,
            reason="Content blocked"
        )
        
        def dummy_shield(request: Request):
            return {"user": "test"}
        
        shield = PostprocessingShield(dummy_shield, postprocessors=[processor])
        
        request = Mock(spec=Request)
        response = Mock(spec=Response)
        context = {}
        
        result = await shield._apply_postprocessors(request, response, context)
        
        assert isinstance(result, JSONResponse)
        assert result.status_code == 403
    
    @pytest.mark.asyncio
    async def test_apply_postprocessors_replace(self):
        """Test applying postprocessors that replace response."""
        new_response = JSONResponse({"message": "replaced"})
        processor = Mock(spec=ResponsePostprocessor)
        processor.process.return_value = PostprocessingResult(
            action=PostprocessingAction.REPLACE,
            response=new_response
        )
        
        def dummy_shield(request: Request):
            return {"user": "test"}
        
        shield = PostprocessingShield(dummy_shield, postprocessors=[processor])
        
        request = Mock(spec=Request)
        response = Mock(spec=Response)
        context = {}
        
        result = await shield._apply_postprocessors(request, response, context)
        
        assert result == new_response
    
    @pytest.mark.asyncio
    async def test_apply_postprocessors_transform_headers(self):
        """Test applying postprocessors that transform headers."""
        processor = Mock(spec=ResponsePostprocessor)
        processor.process.return_value = PostprocessingResult(
            action=PostprocessingAction.TRANSFORM,
            headers={"X-Custom": "test"}
        )
        
        def dummy_shield(request: Request):
            return {"user": "test"}
        
        shield = PostprocessingShield(dummy_shield, postprocessors=[processor])
        
        request = Mock(spec=Request)
        response = Mock(spec=Response)
        response.status_code = 200
        response.body = "test content"
        response.headers = {"Content-Type": "text/plain"}
        context = {}
        
        result = await shield._apply_postprocessors(request, response, context)
        
        assert isinstance(result, Response)
        assert result.headers["X-Custom"] == "test"
        assert result.status_code == 200
    
    @pytest.mark.asyncio
    async def test_apply_postprocessors_transform_body(self):
        """Test applying postprocessors that transform body."""
        processor = Mock(spec=ResponsePostprocessor)
        processor.process.return_value = PostprocessingResult(
            action=PostprocessingAction.TRANSFORM,
            body="transformed content"
        )
        
        def dummy_shield(request: Request):
            return {"user": "test"}
        
        shield = PostprocessingShield(dummy_shield, postprocessors=[processor])
        
        request = Mock(spec=Request)
        response = Mock(spec=Response)
        response.status_code = 200
        response.body = "original content"
        response.headers = {"Content-Type": "text/plain"}
        context = {}
        
        result = await shield._apply_postprocessors(request, response, context)
        
        assert isinstance(result, Response)
        assert result.body == b"transformed content"
    
    @pytest.mark.asyncio
    async def test_apply_postprocessors_exception_handling(self):
        """Test handling exceptions in postprocessors."""
        processor1 = Mock(spec=ResponsePostprocessor)
        processor1.process.side_effect = Exception("Processor 1 failed")
        
        processor2 = Mock(spec=ResponsePostprocessor)
        processor2.process.return_value = PostprocessingResult(
            action=PostprocessingAction.TRANSFORM,
            headers={"X-Success": "true"}
        )
        
        def dummy_shield(request: Request):
            return {"user": "test"}
        
        shield = PostprocessingShield(dummy_shield, postprocessors=[processor1, processor2])
        
        request = Mock(spec=Request)
        response = Mock(spec=Response)
        response.status_code = 200
        response.body = "test content"
        response.headers = {"Content-Type": "text/plain"}
        context = {}
        
        result = await shield._apply_postprocessors(request, response, context)
        
        # Should continue despite processor1 failing
        assert isinstance(result, Response)
        assert result.headers["X-Success"] == "true"
    
    @pytest.mark.asyncio
    async def test_apply_postprocessors_chaining(self):
        """Test chaining multiple postprocessors."""
        processor1 = Mock(spec=ResponsePostprocessor)
        processor1.process.return_value = PostprocessingResult(
            action=PostprocessingAction.TRANSFORM,
            headers={"X-First": "processor1"}
        )
        
        processor2 = Mock(spec=ResponsePostprocessor)
        processor2.process.return_value = PostprocessingResult(
            action=PostprocessingAction.TRANSFORM,
            body="transformed by processor2"
        )
        
        def dummy_shield(request: Request):
            return {"user": "test"}
        
        shield = PostprocessingShield(dummy_shield, postprocessors=[processor1, processor2])
        
        request = Mock(spec=Request)
        response = Mock(spec=Response)
        response.status_code = 200
        response.body = "original content"
        response.headers = {"Content-Type": "text/plain"}
        context = {}
        
        result = await shield._apply_postprocessors(request, response, context)
        
        assert isinstance(result, Response)
        assert result.headers["X-First"] == "processor1"
        assert result.body == b"transformed by processor2"


class TestPostprocessingShieldIntegration:
    """Test postprocessing shield integration with FastAPI."""
    
    @pytest.fixture
    def app(self):
        """Create test FastAPI app."""
        app = FastAPI()
        return app
    
    @pytest.fixture
    def client(self, app):
        """Create test client."""
        return TestClient(app)
    
    def test_postprocessing_shield_decorator(self, app, client):
        """Test postprocessing shield as decorator."""
        @postprocessing_shield
        def auth_shield(request: Request):
            return {"user_id": 123}
        
        @app.get("/test")
        @auth_shield
        def test_endpoint():
            return {"message": "success"}
        
        response = client.get("/test")
        assert response.status_code == 200
        assert response.json() == {"message": "success"}
    
    def test_postprocessing_shield_with_processors(self, app, client):
        """Test postprocessing shield with processors."""
        security_processor = create_security_headers_processor(
            csp_policy="default-src 'self'",
            custom_headers={"X-API-Version": "1.0"}
        )
        
        @postprocessing_shield(postprocessors=[security_processor])
        def auth_shield(request: Request):
            return {"user_id": 123}
        
        @app.get("/test")
        @auth_shield
        def test_endpoint():
            return {"message": "success"}
        
        response = client.get("/test")
        assert response.status_code == 200
        assert response.headers["Content-Security-Policy"] == "default-src 'self'"
        assert response.headers["X-API-Version"] == "1.0"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert "Strict-Transport-Security" in response.headers


class TestConvenienceFunctions:
    """Test convenience functions for creating postprocessors."""
    
    def test_create_security_headers_processor(self):
        """Test creating security headers processor."""
        processor = create_security_headers_processor(
            csp_policy="default-src 'self'",
            hsts_max_age=7200,
            custom_headers={"X-Custom": "value"}
        )
        
        assert isinstance(processor, SecurityHeaderProcessor)
        assert processor.config.csp_policy == "default-src 'self'"
        assert processor.config.hsts_max_age == 7200
        assert processor.config.custom_headers["X-Custom"] == "value"
    
    def test_create_compression_processor(self):
        """Test creating compression processor."""
        processor = create_compression_processor(
            method=CompressionMethod.DEFLATE,
            min_size=2048,
            level=9
        )
        
        assert isinstance(processor, CompressionProcessor)
        assert processor.config.method == CompressionMethod.DEFLATE
        assert processor.config.min_size == 2048
        assert processor.config.level == 9
    
    def test_create_content_filter(self):
        """Test creating content filter."""
        processor = create_content_filter(
            blocked_patterns=["malicious"],
            sanitize_html=False
        )
        
        assert isinstance(processor, ContentFilter)
        assert len(processor.blocked_patterns) == 1
        assert processor.sanitize_html is False


class TestPostprocessingResult:
    """Test PostprocessingResult dataclass."""
    
    def test_init_default(self):
        """Test default initialization."""
        result = PostprocessingResult(action=PostprocessingAction.CONTINUE)
        
        assert result.action == PostprocessingAction.CONTINUE
        assert result.response is None
        assert result.headers is None
        assert result.body is None
        assert result.reason is None
    
    def test_init_full(self):
        """Test full initialization."""
        response = Mock(spec=Response)
        headers = {"X-Test": "value"}
        body = "test body"
        reason = "test reason"
        
        result = PostprocessingResult(
            action=PostprocessingAction.TRANSFORM,
            response=response,
            headers=headers,
            body=body,
            reason=reason
        )
        
        assert result.action == PostprocessingAction.TRANSFORM
        assert result.response == response
        assert result.headers == headers
        assert result.body == body
        assert result.reason == reason


class TestFilterRule:
    """Test FilterRule dataclass."""
    
    def test_init_default(self):
        """Test default initialization."""
        rule = FilterRule(pattern="test")
        
        assert rule.pattern == "test"
        assert rule.replacement == ""
        assert rule.flags == 0
        assert "text/html" in rule.content_types
        assert "text/plain" in rule.content_types
    
    def test_init_custom(self):
        """Test custom initialization."""
        pattern = re.compile(r"test", re.IGNORECASE)
        content_types = {"application/json"}
        
        rule = FilterRule(
            pattern=pattern,
            replacement="replaced",
            flags=re.MULTILINE,
            content_types=content_types
        )
        
        assert rule.pattern == pattern
        assert rule.replacement == "replaced"
        assert rule.flags == re.MULTILINE
        assert rule.content_types == content_types


class TestSecurityHeaderConfig:
    """Test SecurityHeaderConfig dataclass."""
    
    def test_init_default(self):
        """Test default initialization."""
        config = SecurityHeaderConfig()
        
        assert config.csp_policy is None
        assert config.csp_report_only is False
        assert config.hsts_max_age == 31536000
        assert config.hsts_include_subdomains is True
        assert config.hsts_preload is False
        assert config.frame_options == "DENY"
        assert config.content_type_options == "nosniff"
        assert config.xss_protection == "1; mode=block"
        assert config.referrer_policy == "strict-origin-when-cross-origin"
        assert config.permissions_policy is None
        assert config.custom_headers == {}
    
    def test_init_custom(self):
        """Test custom initialization."""
        custom_headers = {"X-Custom": "value"}
        
        config = SecurityHeaderConfig(
            csp_policy="default-src 'self'",
            csp_report_only=True,
            hsts_max_age=7200,
            hsts_include_subdomains=False,
            hsts_preload=True,
            frame_options="SAMEORIGIN",
            content_type_options="",
            xss_protection="0",
            referrer_policy="no-referrer",
            permissions_policy="geolocation=()",
            custom_headers=custom_headers
        )
        
        assert config.csp_policy == "default-src 'self'"
        assert config.csp_report_only is True
        assert config.hsts_max_age == 7200
        assert config.hsts_include_subdomains is False
        assert config.hsts_preload is True
        assert config.frame_options == "SAMEORIGIN"
        assert config.content_type_options == ""
        assert config.xss_protection == "0"
        assert config.referrer_policy == "no-referrer"
        assert config.permissions_policy == "geolocation=()"
        assert config.custom_headers == custom_headers


class TestCompressionConfig:
    """Test CompressionConfig dataclass."""
    
    def test_init_default(self):
        """Test default initialization."""
        config = CompressionConfig()
        
        assert config.method == CompressionMethod.GZIP
        assert config.min_size == 1024
        assert config.level == 6
        assert "text/plain" in config.content_types
        assert "application/json" in config.content_types
    
    def test_init_custom(self):
        """Test custom initialization."""
        content_types = {"text/plain", "text/css"}
        
        config = CompressionConfig(
            method=CompressionMethod.DEFLATE,
            min_size=2048,
            level=9,
            content_types=content_types
        )
        
        assert config.method == CompressionMethod.DEFLATE
        assert config.min_size == 2048
        assert config.level == 9
        assert config.content_types == content_types