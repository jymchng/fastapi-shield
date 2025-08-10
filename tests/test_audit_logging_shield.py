"""Tests for audit logging shield functionality."""

import json
import logging
import tempfile
import time
from datetime import datetime, timezone
from typing import Dict, List
from unittest.mock import Mock, patch

import pytest
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient

from fastapi_shield.audit_logging import (
    AuditLoggingShield,
    AuditLogConfig,
    LogEntry,
    LogLevel,
    LogFormat,
    SensitiveDataMask,
    AuditLogger,
    PythonAuditLogger,
    StructlogAuditLogger,
    FileAuditLogger,
    audit_logging_shield,
    sensitive_audit_shield,
    compliance_audit_shield,
    error_audit_shield,
    performance_audit_shield,
    debug_audit_shield,
)


class MockAuditLogger(AuditLogger):
    """Mock audit logger for testing."""
    
    def __init__(self):
        self.entries: List[tuple] = []
        self.flushed = False
        self.closed = False
    
    def log(self, entry: LogEntry, level: LogLevel = LogLevel.INFO) -> None:
        """Log an audit entry."""
        self.entries.append((entry, level))
    
    def flush(self) -> None:
        """Flush any buffered log entries."""
        self.flushed = True
    
    def close(self) -> None:
        """Close the logger and cleanup resources."""
        self.closed = True


class TestAuditLogConfig:
    """Test audit log configuration."""
    
    def test_audit_log_config_defaults(self):
        """Test default audit log configuration."""
        config = AuditLogConfig()
        assert config.enabled is True
        assert config.log_level == LogLevel.INFO
        assert config.log_format == LogFormat.JSON
        assert config.log_requests is True
        assert config.log_responses is True
        assert config.log_headers is True
        assert config.log_body is False
        assert config.mask_sensitive_data is True
        assert config.masking_strategy == SensitiveDataMask.PARTIAL
        assert config.async_logging is True
    
    def test_audit_log_config_custom(self):
        """Test custom audit log configuration."""
        config = AuditLogConfig(
            enabled=False,
            log_level=LogLevel.DEBUG,
            log_format=LogFormat.CEF,
            log_requests=False,
            log_responses=False,
            log_headers=False,
            log_body=True,
            mask_sensitive_data=False,
            masking_strategy=SensitiveDataMask.FULL,
            async_logging=False,
        )
        assert config.enabled is False
        assert config.log_level == LogLevel.DEBUG
        assert config.log_format == LogFormat.CEF
        assert config.log_requests is False
        assert config.log_body is True
        assert config.mask_sensitive_data is False
        assert config.async_logging is False


class TestLogEntry:
    """Test log entry model."""
    
    def test_log_entry_creation(self):
        """Test creating log entry."""
        now = datetime.now(timezone.utc)
        entry = LogEntry(
            timestamp=now,
            correlation_id="test-123",
            method="GET",
            url="https://example.com/api/test",
            path="/api/test",
            request_time=now,
            status_code=200,
            duration_ms=150.5,
            client_ip="192.168.1.1",
            user_agent="Mozilla/5.0",
            authenticated=True,
        )
        
        assert entry.correlation_id == "test-123"
        assert entry.method == "GET"
        assert entry.path == "/api/test"
        assert entry.status_code == 200
        assert entry.duration_ms == 150.5
        assert entry.authenticated is True
    
    def test_log_entry_serialization(self):
        """Test log entry JSON serialization."""
        now = datetime.now(timezone.utc)
        entry = LogEntry(
            timestamp=now,
            correlation_id="test-123",
            method="POST",
            url="https://example.com/api/users",
            path="/api/users",
            request_time=now,
            status_code=201,
        )
        
        json_str = entry.model_dump_json(exclude_none=True)
        data = json.loads(json_str)
        
        assert data["correlation_id"] == "test-123"
        assert data["method"] == "POST"
        assert data["status_code"] == 201
        assert "query_params" not in data  # Excluded because None


class TestPythonAuditLogger:
    """Test Python standard logging audit logger."""
    
    def test_python_logger_initialization(self):
        """Test Python logger initialization."""
        logger = PythonAuditLogger("test.audit", LogFormat.JSON)
        assert logger.logger.name == "test.audit"
        assert logger.format_type == LogFormat.JSON
    
    def test_python_logger_json_logging(self):
        """Test JSON logging."""
        logger = PythonAuditLogger("test.audit", LogFormat.JSON)
        
        now = datetime.now(timezone.utc)
        entry = LogEntry(
            timestamp=now,
            correlation_id="test-123",
            method="GET",
            url="https://example.com/test",
            path="/test",
            request_time=now,
        )
        
        with patch.object(logger.logger, 'log') as mock_log:
            logger.log(entry, LogLevel.INFO)
            mock_log.assert_called_once()
            args, kwargs = mock_log.call_args
            assert args[0] == logging.INFO
            # Should be JSON string
            assert '"correlation_id":"test-123"' in args[1]
    
    def test_python_logger_text_logging(self):
        """Test text format logging."""
        logger = PythonAuditLogger("test.audit", LogFormat.SYSLOG)
        
        now = datetime.now(timezone.utc)
        entry = LogEntry(
            timestamp=now,
            correlation_id="test-123",
            method="GET",
            url="https://example.com/test",
            path="/test",
            request_time=now,
            status_code=200,
            duration_ms=100.0,
            client_ip="192.168.1.1",
        )
        
        with patch.object(logger.logger, 'log') as mock_log:
            logger.log(entry, LogLevel.INFO)
            mock_log.assert_called_once()
            args, kwargs = mock_log.call_args
            # Should be formatted string
            assert "GET /test - 200 - 100.00ms - 192.168.1.1" == args[1]


class TestFileAuditLogger:
    """Test file-based audit logger."""
    
    def test_file_logger_initialization(self):
        """Test file logger initialization."""
        with tempfile.NamedTemporaryFile() as tmp:
            logger = FileAuditLogger(tmp.name, LogFormat.JSON)
            assert logger.file_path == tmp.name
            assert logger.format_type == LogFormat.JSON
            logger.close()
    
    def test_file_logger_logging(self):
        """Test file logging."""
        with tempfile.NamedTemporaryFile(mode='w+') as tmp:
            logger = FileAuditLogger(tmp.name, LogFormat.JSON)
            
            now = datetime.now(timezone.utc)
            entry = LogEntry(
                timestamp=now,
                correlation_id="test-123",
                method="POST",
                url="https://example.com/api/test",
                path="/api/test",
                request_time=now,
            )
            
            logger.log(entry, LogLevel.INFO)
            logger.flush()
            logger.close()
            
            # Read log file
            tmp.seek(0)
            content = tmp.read()
            assert '"correlation_id":"test-123"' in content
            assert '"method":"POST"' in content


class TestAuditLoggingShield:
    """Test the audit logging shield class."""
    
    @pytest.fixture
    def mock_request(self):
        """Create a mock request for testing."""
        request = Mock()
        request.method = "GET"
        request.url = Mock()
        request.url.path = "/api/test"
        request.url.query = "param=value"
        request.url.__str__ = Mock(return_value="https://example.com/api/test?param=value")
        request.headers = {
            "user-agent": "Mozilla/5.0",
            "authorization": "Bearer token123",
            "x-api-key": "key123"
        }
        request.query_params = {"param": "value", "secret": "password123"}
        request.path_params = {"id": "123"}
        request.client = Mock()
        request.client.host = "192.168.1.1"
        request.state = Mock()
        # Set up user with no permissions by default
        request.user = None
        return request
    
    @pytest.fixture
    def mock_response(self):
        """Create a mock response for testing."""
        response = Mock()
        response.status_code = 200
        response.headers = {"content-type": "application/json", "content-length": "100"}
        return response
    
    def test_shield_initialization_defaults(self):
        """Test shield initialization with defaults."""
        mock_logger = MockAuditLogger()
        shield = AuditLoggingShield(logger=mock_logger)
        
        assert shield.config.enabled is True
        assert shield.config.log_level == LogLevel.INFO
        assert shield.config.mask_sensitive_data is True
        assert shield.logger is mock_logger
    
    def test_shield_initialization_custom(self):
        """Test shield initialization with custom configuration."""
        config = AuditLogConfig(
            enabled=False,
            log_level=LogLevel.DEBUG,
            mask_sensitive_data=False,
            log_body=True,
        )
        mock_logger = MockAuditLogger()
        
        shield = AuditLoggingShield(config=config, logger=mock_logger)
        
        assert shield.config.enabled is False
        assert shield.config.log_level == LogLevel.DEBUG
        assert shield.config.mask_sensitive_data is False
        assert shield.config.log_body is True
    
    def test_generate_correlation_id(self, mock_request):
        """Test correlation ID generation."""
        shield = AuditLoggingShield()
        
        # Test extracting existing correlation ID
        mock_request.headers = {"x-correlation-id": "existing-123"}
        correlation_id = shield._generate_correlation_id(mock_request)
        assert correlation_id == "existing-123"
        
        # Test generating new correlation ID
        mock_request.headers = {}
        correlation_id = shield._generate_correlation_id(mock_request)
        assert len(correlation_id) == 36  # UUID4 format
    
    def test_extract_client_ip(self, mock_request):
        """Test client IP extraction."""
        shield = AuditLoggingShield()
        
        # Test direct client IP
        ip = shield._extract_client_ip(mock_request)
        assert ip == "192.168.1.1"
        
        # Test X-Forwarded-For header
        mock_request.headers = {"x-forwarded-for": "203.0.113.1, 198.51.100.1"}
        ip = shield._extract_client_ip(mock_request)
        assert ip == "203.0.113.1"
        
        # Test X-Real-IP header
        mock_request.headers = {"x-real-ip": "203.0.113.2"}
        ip = shield._extract_client_ip(mock_request)
        assert ip == "203.0.113.2"
    
    def test_mask_sensitive_data(self):
        """Test sensitive data masking."""
        shield = AuditLoggingShield()
        
        # Test partial masking (default)
        masked = shield._mask_sensitive_data("password123", "password")
        assert masked == "pa***3"
        
        # Test full masking
        shield.config.masking_strategy = SensitiveDataMask.FULL
        masked = shield._mask_sensitive_data("secret", "secret")
        assert masked == "***"
        
        # Test hash masking
        shield.config.masking_strategy = SensitiveDataMask.HASH
        masked = shield._mask_sensitive_data("token123", "token")
        assert masked.startswith("sha256:")
        assert len(masked) > 10
        
        # Test no masking
        shield.config.masking_strategy = SensitiveDataMask.NONE
        masked = shield._mask_sensitive_data("data", "field")
        assert masked == "data"
    
    def test_should_mask_field(self):
        """Test field masking detection."""
        shield = AuditLoggingShield()
        
        # Test header masking
        assert shield._should_mask_field("authorization", "header") is True
        assert shield._should_mask_field("content-type", "header") is False
        
        # Test query parameter masking
        assert shield._should_mask_field("password", "query") is True
        assert shield._should_mask_field("search", "query") is False
        
        # Test body field masking
        assert shield._should_mask_field("secret", "body") is True
        assert shield._should_mask_field("name", "body") is False
    
    def test_mask_dict_data(self):
        """Test dictionary data masking."""
        shield = AuditLoggingShield()
        
        data = {
            "username": "john",
            "password": "secret123",
            "token": "abc123",
            "metadata": {
                "api_key": "key123",
                "description": "test"
            }
        }
        
        masked = shield._mask_dict_data(data, "body")
        
        assert masked["username"] == "john"  # Not sensitive
        assert masked["password"] == "se***3"  # Masked
        assert masked["token"] == "ab***3"    # Masked
        assert masked["metadata"]["api_key"] == "ke***3"  # Nested masking
        assert masked["metadata"]["description"] == "test"  # Not sensitive
    
    def test_should_log_request(self, mock_request, mock_response):
        """Test request logging decisions."""
        shield = AuditLoggingShield()
        
        # Test enabled logging
        assert shield._should_log_request(mock_request, mock_response) is True
        
        # Test disabled logging
        shield.config.enabled = False
        assert shield._should_log_request(mock_request, mock_response) is False
        
        # Test error-only logging
        shield.config.enabled = True
        shield.config.log_errors_only = True
        mock_response.status_code = 200
        assert shield._should_log_request(mock_request, mock_response) is False
        
        mock_response.status_code = 404
        assert shield._should_log_request(mock_request, mock_response) is True
        
        # Test status code filters
        shield.config.log_errors_only = False
        shield.config.include_status_codes = {200, 201}
        mock_response.status_code = 200
        assert shield._should_log_request(mock_request, mock_response) is True
        
        mock_response.status_code = 404
        assert shield._should_log_request(mock_request, mock_response) is False
        
        # Test exclude status codes
        shield.config.include_status_codes = None
        shield.config.exclude_status_codes = {404, 500}
        mock_response.status_code = 404
        assert shield._should_log_request(mock_request, mock_response) is False
        
        mock_response.status_code = 200
        assert shield._should_log_request(mock_request, mock_response) is True
    
    def test_extract_request_data(self, mock_request):
        """Test request data extraction."""
        shield = AuditLoggingShield()
        
        data = shield._extract_request_data(mock_request)
        
        assert data["method"] == "GET"
        assert data["url"] == "https://example.com/api/test?param=value"
        assert data["path"] == "/api/test"
        assert "headers" in data
        assert data["headers"]["authorization"] == "Be***3"  # Masked
        assert "query_params" in data
        assert data["query_params"]["secret"] == "pa***3"    # Masked
        assert data["path_params"] == {"id": "123"}
        assert data["client_ip"] == "192.168.1.1"
        assert data["user_agent"] == "Mozilla/5.0"
    
    def test_extract_response_data(self, mock_response):
        """Test response data extraction."""
        shield = AuditLoggingShield()
        
        data = shield._extract_response_data(mock_response)
        
        assert data["status_code"] == 200
        assert "response_headers" in data
        assert data["response_headers"]["content-type"] == "application/json"
        assert data["response_size"] == 100
    
    def test_extract_user_context(self, mock_request):
        """Test user context extraction."""
        shield = AuditLoggingShield()
        
        # Test with authorization header
        context = shield._extract_user_context(mock_request)
        assert context["authenticated"] is True
        
        # Test with user object
        mock_request.headers = {}
        mock_request.user = Mock()
        mock_request.user.id = 123
        mock_request.user.permissions = ["read", "write"]
        
        context = shield._extract_user_context(mock_request)
        assert context["authenticated"] is True
        assert context["user_id"] == "123"
        assert context["permissions"] == ["read", "write"]
        
        # Test with user ID header
        mock_request.user = None
        mock_request.headers = {"x-user-id": "456"}
        
        context = shield._extract_user_context(mock_request)
        assert context["authenticated"] is True
        assert context["user_id"] == "456"
    
    def test_create_log_entry(self, mock_request, mock_response):
        """Test log entry creation."""
        mock_logger = MockAuditLogger()
        shield = AuditLoggingShield(logger=mock_logger)
        
        start_time = time.time() - 0.1  # 100ms ago
        
        entry = shield._create_log_entry(mock_request, mock_response, start_time)
        
        assert entry.correlation_id is not None
        assert entry.method == "GET"
        assert entry.path == "/api/test"
        assert entry.status_code == 200
        assert entry.client_ip == "192.168.1.1"
        assert entry.duration_ms is not None
        assert entry.duration_ms > 50  # Should be around 100ms
        assert entry.authenticated is True
    
    def test_create_log_entry_with_error(self, mock_request):
        """Test log entry creation with error."""
        mock_logger = MockAuditLogger()
        shield = AuditLoggingShield(logger=mock_logger)
        shield.config.include_stack_trace = True
        
        error = ValueError("Test error")
        entry = shield._create_log_entry(mock_request, error=error)
        
        assert entry.error_message == "Test error"
        assert entry.stack_trace is not None
        assert "ValueError" in entry.stack_trace
    
    def test_log_entry_async(self, mock_request):
        """Test asynchronous logging."""
        mock_logger = MockAuditLogger()
        shield = AuditLoggingShield(logger=mock_logger)
        shield.config.async_logging = True
        shield.config.buffer_size = 2
        
        entry = shield._create_log_entry(mock_request)
        
        # First entry should be buffered
        shield._log_entry(entry, LogLevel.INFO)
        assert len(shield._log_buffer) == 1
        assert len(mock_logger.entries) == 0
        
        # Second entry should flush buffer
        shield._log_entry(entry, LogLevel.INFO)
        assert len(shield._log_buffer) == 0
        assert len(mock_logger.entries) == 2
    
    def test_log_entry_sync(self, mock_request):
        """Test synchronous logging."""
        mock_logger = MockAuditLogger()
        shield = AuditLoggingShield(logger=mock_logger)
        shield.config.async_logging = False
        
        entry = shield._create_log_entry(mock_request)
        
        shield._log_entry(entry, LogLevel.INFO)
        assert len(shield._log_buffer) == 0
        assert len(mock_logger.entries) == 1
    
    def test_log_response(self, mock_request, mock_response):
        """Test response logging."""
        mock_logger = MockAuditLogger()
        shield = AuditLoggingShield(logger=mock_logger)
        shield.config.async_logging = False
        
        # Set up request state
        mock_request.state.audit_start_time = time.time() - 0.1
        
        shield.log_response(mock_request, mock_response)
        
        assert len(mock_logger.entries) == 1
        entry, level = mock_logger.entries[0]
        
        assert entry.method == "GET"
        assert entry.status_code == 200
        assert level == LogLevel.INFO
    
    def test_log_response_error_status(self, mock_request, mock_response):
        """Test response logging with error status codes."""
        mock_logger = MockAuditLogger()
        shield = AuditLoggingShield(logger=mock_logger)
        shield.config.async_logging = False
        
        # Set up request state
        mock_request.state.audit_start_time = time.time() - 0.1
        
        # Test 400 status
        mock_response.status_code = 400
        shield.log_response(mock_request, mock_response)
        entry, level = mock_logger.entries[0]
        assert level == LogLevel.WARNING
        
        # Test 500 status
        mock_response.status_code = 500
        shield.log_response(mock_request, mock_response)
        entry, level = mock_logger.entries[1]
        assert level == LogLevel.ERROR
    
    def test_flush_and_close(self):
        """Test flushing and closing logger."""
        mock_logger = MockAuditLogger()
        shield = AuditLoggingShield(logger=mock_logger)
        shield.config.async_logging = False  # Ensure sync logging for test
        
        shield.flush()
        assert mock_logger.flushed is True
        
        shield.close()
        assert mock_logger.closed is True


class TestAuditLoggingIntegration:
    """Integration tests with FastAPI."""
    
    def test_basic_audit_logging_shield(self):
        """Test basic audit logging shield integration."""
        mock_logger = MockAuditLogger()
        
        app = FastAPI()
        
        @app.get("/api/test")
        @audit_logging_shield(logger=mock_logger)
        def test_endpoint():
            return {"message": "test"}
        
        client = TestClient(app)
        
        response = client.get("/api/test")
        assert response.status_code == 200
        # Note: Actual logging would happen in middleware, not in the shield decorator
    
    def test_sensitive_audit_shield(self):
        """Test sensitive data audit shield."""
        mock_logger = MockAuditLogger()
        
        app = FastAPI()
        
        @app.post("/api/login")
        @sensitive_audit_shield(logger=mock_logger)
        def login_endpoint():
            return {"token": "abc123"}
        
        client = TestClient(app)
        
        response = client.post("/api/login", json={"username": "user", "password": "pass"})
        assert response.status_code == 200
    
    def test_compliance_audit_shield(self):
        """Test compliance audit shield."""
        with tempfile.NamedTemporaryFile() as tmp:
            app = FastAPI()
            
            @app.get("/api/compliance")
            @compliance_audit_shield(file_path=tmp.name)
            def compliance_endpoint():
                return {"data": "compliance"}
            
            client = TestClient(app)
            
            response = client.get("/api/compliance")
            assert response.status_code == 200
    
    def test_error_audit_shield(self):
        """Test error-only audit shield."""
        mock_logger = MockAuditLogger()
        
        app = FastAPI()
        
        @app.get("/api/error")
        @error_audit_shield(logger=mock_logger)
        def error_endpoint():
            return {"error": "test"}
        
        client = TestClient(app)
        
        response = client.get("/api/error")
        assert response.status_code == 200
    
    def test_performance_audit_shield(self):
        """Test performance audit shield."""
        mock_logger = MockAuditLogger()
        
        app = FastAPI()
        
        @app.get("/api/performance")
        @performance_audit_shield(threshold_ms=100.0, logger=mock_logger)
        def performance_endpoint():
            return {"performance": "test"}
        
        client = TestClient(app)
        
        response = client.get("/api/performance")
        assert response.status_code == 200
    
    def test_debug_audit_shield(self):
        """Test debug audit shield."""
        mock_logger = MockAuditLogger()
        
        app = FastAPI()
        
        @app.get("/api/debug")
        @debug_audit_shield(logger=mock_logger)
        def debug_endpoint():
            return {"debug": "test"}
        
        client = TestClient(app)
        
        response = client.get("/api/debug")
        assert response.status_code == 200


class TestConvenienceFunctions:
    """Test audit logging convenience functions."""
    
    def test_audit_logging_shield_factory(self):
        """Test audit logging shield factory function."""
        mock_logger = MockAuditLogger()
        
        shield = audit_logging_shield(
            log_level=LogLevel.DEBUG,
            log_requests=True,
            log_responses=True,
            log_headers=False,
            logger=mock_logger
        )
        assert isinstance(shield, type(audit_logging_shield()))
    
    def test_sensitive_audit_shield_factory(self):
        """Test sensitive audit shield factory."""
        mock_logger = MockAuditLogger()
        
        shield = sensitive_audit_shield(
            masking_strategy=SensitiveDataMask.HASH,
            logger=mock_logger
        )
        assert isinstance(shield, type(audit_logging_shield()))
    
    def test_compliance_audit_shield_factory(self):
        """Test compliance audit shield factory."""
        with tempfile.NamedTemporaryFile() as tmp:
            shield = compliance_audit_shield(
                file_path=tmp.name,
                log_format=LogFormat.JSON
            )
            assert isinstance(shield, type(audit_logging_shield()))
    
    def test_error_audit_shield_factory(self):
        """Test error audit shield factory."""
        mock_logger = MockAuditLogger()
        
        shield = error_audit_shield(logger=mock_logger)
        assert isinstance(shield, type(audit_logging_shield()))
    
    def test_performance_audit_shield_factory(self):
        """Test performance audit shield factory."""
        mock_logger = MockAuditLogger()
        
        shield = performance_audit_shield(
            threshold_ms=500.0,
            logger=mock_logger
        )
        assert isinstance(shield, type(audit_logging_shield()))
    
    def test_debug_audit_shield_factory(self):
        """Test debug audit shield factory."""
        mock_logger = MockAuditLogger()
        
        shield = debug_audit_shield(logger=mock_logger)
        assert isinstance(shield, type(audit_logging_shield()))


class TestSensitiveDataPatterns:
    """Test sensitive data pattern detection."""
    
    def test_password_pattern(self):
        """Test password pattern detection."""
        shield = AuditLoggingShield()
        
        text = 'password="secret123" and token="abc456"'
        masked = shield._mask_text_data(text)
        
        # Should mask the sensitive values
        assert "secret123" not in masked
        assert "abc456" not in masked
        assert 'password=' in masked
        assert 'token=' in masked
    
    def test_credit_card_pattern(self):
        """Test credit card pattern detection."""
        shield = AuditLoggingShield()
        
        text = "Credit card: 4532-1234-5678-9012"
        masked = shield._mask_text_data(text)
        
        # Should mask the credit card number
        assert "4532-1234-5678-9012" not in masked
    
    def test_ssn_pattern(self):
        """Test SSN pattern detection."""
        shield = AuditLoggingShield()
        
        text = "SSN: 123-45-6789"
        masked = shield._mask_text_data(text)
        
        # Should mask the SSN
        assert "123-45-6789" not in masked


class TestLoggerImplementations:
    """Test different logger implementations."""
    
    def test_structlog_logger(self):
        """Test structlog logger (if available)."""
        try:
            # Try to create structlog logger
            logger = StructlogAuditLogger()
            
            now = datetime.now(timezone.utc)
            entry = LogEntry(
                timestamp=now,
                correlation_id="test-123",
                method="GET",
                url="https://example.com/test",
                path="/test",
                request_time=now,
            )
            
            # Should not raise exception
            logger.log(entry, LogLevel.INFO)
            logger.flush()
            logger.close()
            
        except ImportError:
            # structlog not available, skip test
            pytest.skip("structlog not available")
    
    def test_file_logger_rotation(self):
        """Test file logger with rotation."""
        with tempfile.NamedTemporaryFile() as tmp:
            logger = FileAuditLogger(
                tmp.name,
                LogFormat.JSON,
                max_size=1024,  # Small size for testing
                backup_count=2
            )
            
            now = datetime.now(timezone.utc)
            entry = LogEntry(
                timestamp=now,
                correlation_id="test-123",
                method="GET",
                url="https://example.com/test",
                path="/test",
                request_time=now,
            )
            
            # Log multiple entries to trigger rotation
            for i in range(100):
                entry.correlation_id = f"test-{i}"
                logger.log(entry, LogLevel.INFO)
            
            logger.flush()
            logger.close()


class TestErrorHandling:
    """Test error handling scenarios."""
    
    def test_shield_error_handling(self):
        """Test shield error handling."""
        # Create a logger that raises an error
        class FailingLogger(AuditLogger):
            def log(self, entry, level):
                raise Exception("Logging error")
            
            def flush(self):
                pass
            
            def close(self):
                pass
        
        shield = AuditLoggingShield(logger=FailingLogger())
        created_shield = shield.create_shield()
        
        mock_request = Mock()
        mock_request.method = "GET"
        mock_request.url = Mock()
        mock_request.url.path = "/test"
        mock_request.headers = {}
        mock_request.state = Mock()
        
        import asyncio
        
        async def test_shield():
            result = await created_shield._guard_func(mock_request)
            return result
        
        result = asyncio.run(test_shield())
        
        # Should handle error gracefully (but logging errors are currently not caught in shield creation)
        # The shield will still be active even if logging fails
        assert result.get("audit_logging_active") is True
    
    def test_custom_fields_extractor_error(self):
        """Test custom fields extractor error handling."""
        def failing_extractor(request):
            raise Exception("Extractor error")
        
        shield = AuditLoggingShield(custom_fields_extractor=failing_extractor)
        
        # Create mock request
        mock_request = Mock()
        mock_request.method = "GET"
        mock_request.url = Mock()
        mock_request.url.path = "/test"
        mock_request.url.query = ""
        mock_request.url.__str__ = Mock(return_value="https://example.com/test")
        mock_request.headers = {}
        mock_request.query_params = {}
        mock_request.path_params = {}
        mock_request.client = Mock()
        mock_request.client.host = "127.0.0.1"
        mock_request.user = None
        
        # Should not raise error
        entry = shield._create_log_entry(mock_request)
        assert entry.custom_fields is None
    
    def test_logger_close_error(self):
        """Test logger close error handling."""
        class FailingCloseLogger(AuditLogger):
            def log(self, entry, level):
                pass
            
            def flush(self):
                pass
            
            def close(self):
                raise Exception("Close error")
        
        shield = AuditLoggingShield(logger=FailingCloseLogger())
        
        # Should not raise error
        shield.close()


if __name__ == "__main__":
    pytest.main([__file__])