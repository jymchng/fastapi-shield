"""Comprehensive tests for the enhanced error handling system."""

import asyncio
import json
import pytest
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any
from unittest.mock import Mock, patch, AsyncMock

from fastapi import HTTPException
from fastapi.responses import JSONResponse

from fastapi_shield.error_handling import (
    ErrorSeverity, ErrorCategory, RecoveryStrategy, ErrorContext, ErrorDetails,
    ShieldError, AuthenticationError, AuthorizationError, ValidationError,
    ConfigurationError, TimeoutError, ResourceExhaustionError, DependencyFailureError,
    RetryConfig, ErrorRecoveryManager, CircuitBreaker, ErrorLogger,
    ErrorHandlingMiddleware, enhanced_shield_decorator, error_context, debug_mode,
    get_error_recovery_manager, get_error_logger, log_shield_error,
    raise_authentication_error, raise_authorization_error, raise_validation_error,
    raise_configuration_error, raise_timeout_error,
    with_error_handling, with_retry, with_fallback, with_circuit_breaker,
    _error_context, _debug_mode
)
from tests.mocks.error_handling_mocks import (
    MockRequest, MockResponse, MockShieldError, MockErrorRecoveryManager,
    MockCircuitBreaker, MockErrorLogger, MockFailingFunction, MockAsyncFailingFunction,
    MockMiddleware, MockShield, create_mock_error_context, create_mock_error_details,
    create_mock_retry_config
)


class TestErrorContext:
    """Test ErrorContext class."""
    
    def test_error_context_creation(self):
        """Test creating error context."""
        context = ErrorContext(
            shield_name="TestShield",
            endpoint_path="/api/test",
            method="POST",
            user_id="user123"
        )
        
        assert context.shield_name == "TestShield"
        assert context.endpoint_path == "/api/test"
        assert context.method == "POST"
        assert context.user_id == "user123"
        assert isinstance(context.request_id, str)
        assert isinstance(context.timestamp, datetime)
    
    def test_error_context_serialization(self):
        """Test error context serialization."""
        context = create_mock_error_context(
            shield_name="TestShield",
            endpoint_path="/api/test",
            method="GET",
            user_id="user456"
        )
        
        data = context.to_dict()
        
        assert data["shield_name"] == "TestShield"
        assert data["endpoint_path"] == "/api/test"
        assert data["method"] == "GET"
        assert data["user_id"] == "user456"
        assert "request_id" in data
        assert "timestamp" in data


class TestErrorDetails:
    """Test ErrorDetails class."""
    
    def test_error_details_creation(self):
        """Test creating error details."""
        context = create_mock_error_context()
        details = ErrorDetails(
            error_id="error-123",
            error_type="TestError",
            message="Test error message",
            severity=ErrorSeverity.HIGH,
            category=ErrorCategory.VALIDATION,
            recovery_strategy=RecoveryStrategy.RETRY,
            context=context,
            suggested_actions=["Check input", "Retry request"]
        )
        
        assert details.error_id == "error-123"
        assert details.error_type == "TestError"
        assert details.message == "Test error message"
        assert details.severity == ErrorSeverity.HIGH
        assert details.category == ErrorCategory.VALIDATION
        assert details.recovery_strategy == RecoveryStrategy.RETRY
        assert details.context == context
        assert "Check input" in details.suggested_actions
    
    def test_error_details_serialization(self):
        """Test error details serialization."""
        details = create_mock_error_details(
            error_type="SerializationTest",
            message="Serialization test message",
            severity=ErrorSeverity.CRITICAL
        )
        
        data = details.to_dict()
        
        assert data["error_type"] == "SerializationTest"
        assert data["message"] == "Serialization test message"
        assert data["severity"] == "critical"
        assert "context" in data
        assert "timestamp" in data["context"]


class TestShieldError:
    """Test ShieldError and its subclasses."""
    
    def test_shield_error_creation(self):
        """Test creating Shield error."""
        error = ShieldError(
            message="Test error",
            severity=ErrorSeverity.HIGH,
            category=ErrorCategory.AUTHENTICATION,
            recovery_strategy=RecoveryStrategy.RETRY,
            debug_info={"key": "value"},
            suggested_actions=["Action 1", "Action 2"]
        )
        
        assert error.message == "Test error"
        assert error.severity == ErrorSeverity.HIGH
        assert error.category == ErrorCategory.AUTHENTICATION
        assert error.recovery_strategy == RecoveryStrategy.RETRY
        assert error.debug_info["key"] == "value"
        assert "Action 1" in error.suggested_actions
        assert isinstance(error.error_id, str)
        assert isinstance(error.timestamp, datetime)
    
    def test_authentication_error(self):
        """Test AuthenticationError."""
        error = AuthenticationError("Invalid credentials")
        
        assert error.message == "Invalid credentials"
        assert error.category == ErrorCategory.AUTHENTICATION
        assert error.http_status_code == 401
        assert error.severity == ErrorSeverity.HIGH
        assert "Check credentials" in error.suggested_actions
    
    def test_authorization_error(self):
        """Test AuthorizationError."""
        error = AuthorizationError("Insufficient permissions")
        
        assert error.message == "Insufficient permissions"
        assert error.category == ErrorCategory.AUTHORIZATION
        assert error.http_status_code == 403
        assert error.severity == ErrorSeverity.HIGH
    
    def test_validation_error(self):
        """Test ValidationError."""
        error = ValidationError("Invalid input format")
        
        assert error.message == "Invalid input format"
        assert error.category == ErrorCategory.VALIDATION
        assert error.http_status_code == 400
        assert error.severity == ErrorSeverity.MEDIUM
    
    def test_configuration_error(self):
        """Test ConfigurationError."""
        error = ConfigurationError("Missing required config")
        
        assert error.message == "Missing required config"
        assert error.category == ErrorCategory.CONFIGURATION
        assert error.http_status_code == 500
        assert error.severity == ErrorSeverity.HIGH
    
    def test_timeout_error(self):
        """Test TimeoutError."""
        error = TimeoutError("Operation timed out")
        
        assert error.message == "Operation timed out"
        assert error.category == ErrorCategory.TIMEOUT
        assert error.http_status_code == 408
        assert error.recovery_strategy == RecoveryStrategy.RETRY
    
    def test_resource_exhaustion_error(self):
        """Test ResourceExhaustionError."""
        error = ResourceExhaustionError("Rate limit exceeded")
        
        assert error.message == "Rate limit exceeded"
        assert error.category == ErrorCategory.RESOURCE_EXHAUSTION
        assert error.http_status_code == 429
        assert error.severity == ErrorSeverity.CRITICAL
        assert error.recovery_strategy == RecoveryStrategy.CIRCUIT_BREAKER
    
    def test_dependency_failure_error(self):
        """Test DependencyFailureError."""
        error = DependencyFailureError("Database unavailable")
        
        assert error.message == "Database unavailable"
        assert error.category == ErrorCategory.DEPENDENCY_FAILURE
        assert error.http_status_code == 503
        assert error.recovery_strategy == RecoveryStrategy.FALLBACK
    
    def test_error_user_message_generation(self):
        """Test user-friendly message generation."""
        auth_error = AuthenticationError()
        assert "Authentication failed" in auth_error.user_message
        
        authz_error = AuthorizationError()
        assert "permission" in authz_error.user_message.lower()
        
        validation_error = ValidationError()
        assert "invalid" in validation_error.user_message.lower()
    
    def test_error_to_http_response(self):
        """Test converting error to HTTP response."""
        error = ValidationError(
            "Invalid email format",
            debug_info={"field": "email", "value": "invalid-email"}
        )
        
        # Test without debug info
        response = error.to_http_response(include_debug_info=False)
        assert response.status_code == 400
        
        response_data = json.loads(response.body.decode())
        assert response_data["error"] is True
        assert response_data["error_id"] == error.error_id
        assert "debug_info" not in response_data
        
        # Test with debug info
        debug_response = error.to_http_response(include_debug_info=True)
        debug_data = json.loads(debug_response.body.decode())
        assert "debug_info" in debug_data
        assert debug_data["debug_info"]["field"] == "email"
    
    def test_error_details_extraction(self):
        """Test extracting error details."""
        error = MockShieldError(
            message="Mock error",
            severity=ErrorSeverity.CRITICAL,
            category=ErrorCategory.INTERNAL_ERROR
        )
        
        details = error.get_error_details()
        
        assert details.error_id == error.error_id
        assert details.message == error.message
        assert details.severity == error.severity
        assert details.category == error.category


class TestRetryConfig:
    """Test RetryConfig class."""
    
    def test_retry_config_creation(self):
        """Test creating retry configuration."""
        config = RetryConfig(
            max_attempts=5,
            initial_delay=2.0,
            max_delay=120.0,
            exponential_base=3.0,
            jitter=False
        )
        
        assert config.max_attempts == 5
        assert config.initial_delay == 2.0
        assert config.max_delay == 120.0
        assert config.exponential_base == 3.0
        assert config.jitter is False
    
    def test_delay_calculation(self):
        """Test retry delay calculation."""
        config = RetryConfig(
            initial_delay=1.0,
            exponential_base=2.0,
            max_delay=10.0,
            jitter=False
        )
        
        # Test exponential backoff
        assert config.calculate_delay(1) == 1.0  # 1.0 * 2^0
        assert config.calculate_delay(2) == 2.0  # 1.0 * 2^1
        assert config.calculate_delay(3) == 4.0  # 1.0 * 2^2
        assert config.calculate_delay(4) == 8.0  # 1.0 * 2^3
        
        # Test max delay cap
        assert config.calculate_delay(5) == 10.0  # Capped at max_delay
    
    def test_delay_calculation_with_jitter(self):
        """Test retry delay calculation with jitter."""
        config = RetryConfig(
            initial_delay=2.0,
            exponential_base=2.0,
            max_delay=20.0,
            jitter=True
        )
        
        # Test that jitter produces different values
        delays = [config.calculate_delay(2) for _ in range(10)]
        
        # All delays should be between base delay * 0.5 and base delay
        base_delay = 4.0  # 2.0 * 2^1
        assert all(base_delay * 0.5 <= delay <= base_delay for delay in delays)
        
        # Should have some variation
        assert len(set(delays)) > 1


class TestCircuitBreaker:
    """Test CircuitBreaker class."""
    
    def test_circuit_breaker_creation(self):
        """Test creating circuit breaker."""
        cb = CircuitBreaker(
            name="test-breaker",
            failure_threshold=3,
            recovery_timeout=30.0
        )
        
        assert cb.name == "test-breaker"
        assert cb.failure_threshold == 3
        assert cb.recovery_timeout == 30.0
        assert cb.failure_count == 0
        assert cb.state == "closed"
    
    def test_circuit_breaker_failure_tracking(self):
        """Test circuit breaker failure tracking."""
        cb = CircuitBreaker(name="test-cb", failure_threshold=2)
        
        # Initially closed
        assert not cb.is_open()
        assert cb.state == "closed"
        
        # Record first failure
        cb.record_failure()
        assert cb.failure_count == 1
        assert not cb.is_open()
        
        # Record second failure - should open circuit
        cb.record_failure()
        assert cb.failure_count == 2
        assert cb.is_open()
        assert cb.state == "open"
    
    def test_circuit_breaker_success_recovery(self):
        """Test circuit breaker recovery on success."""
        cb = CircuitBreaker(name="test-cb2", failure_threshold=2)
        
        # Trigger circuit to open
        cb.record_failure()
        cb.record_failure()
        assert cb.is_open()
        
        # Record success should close circuit
        cb.record_success()
        assert not cb.is_open()
        assert cb.failure_count == 0
        assert cb.state == "closed"
    
    def test_circuit_breaker_timeout_recovery(self):
        """Test circuit breaker timeout recovery."""
        cb = CircuitBreaker(name="test-cb3", failure_threshold=1, recovery_timeout=0.1)  # 100ms timeout
        
        # Trigger circuit to open
        cb.record_failure()
        assert cb.is_open()
        
        # Wait for recovery timeout
        time.sleep(0.2)
        
        # Should transition to half-open
        assert not cb.is_open()
        assert cb.state == "half_open"
    
    def test_circuit_breaker_state_info(self):
        """Test circuit breaker state information."""
        cb = CircuitBreaker(name="test", failure_threshold=5)
        cb.record_failure()
        cb.record_failure()
        
        state = cb.get_state()
        
        assert state["name"] == "test"
        assert state["failure_count"] == 2
        assert state["failure_threshold"] == 5
        assert state["state"] == "closed"
        assert "last_failure_time" in state


class TestErrorRecoveryManager:
    """Test ErrorRecoveryManager class."""
    
    @pytest.fixture
    def recovery_manager(self):
        """Create error recovery manager."""
        return ErrorRecoveryManager()
    
    def test_recovery_manager_initialization(self, recovery_manager):
        """Test recovery manager initialization."""
        assert len(recovery_manager.circuit_breakers) == 0
        assert len(recovery_manager.fallback_handlers) == 0
        assert len(recovery_manager.retry_configs) == 0
    
    def test_fallback_registration(self, recovery_manager):
        """Test fallback handler registration."""
        def fallback_handler():
            return "fallback result"
        
        recovery_manager.register_fallback("test-key", fallback_handler)
        
        assert "test-key" in recovery_manager.fallback_handlers
        assert recovery_manager.fallback_handlers["test-key"] == fallback_handler
    
    def test_retry_config_registration(self, recovery_manager):
        """Test retry config registration."""
        config = create_mock_retry_config(max_attempts=5)
        
        recovery_manager.register_retry_config("test-key", config)
        
        assert "test-key" in recovery_manager.retry_configs
        assert recovery_manager.retry_configs["test-key"] == config
    
    def test_circuit_breaker_creation(self, recovery_manager):
        """Test circuit breaker creation."""
        cb1 = recovery_manager.get_circuit_breaker("test-breaker")
        cb2 = recovery_manager.get_circuit_breaker("test-breaker")
        
        # Should return the same instance
        assert cb1 is cb2
        assert cb1.name == "test-breaker"
        assert "test-breaker" in recovery_manager.circuit_breakers
    
    @pytest.mark.asyncio
    async def test_simple_execution(self, recovery_manager):
        """Test simple execution without recovery."""
        mock_func = MockAsyncFailingFunction()
        
        result = await recovery_manager.execute_with_recovery(
            "test-key",
            mock_func,
            recovery_strategy=RecoveryStrategy.NONE
        )
        
        assert "Async success" in result
        assert mock_func.call_count == 1
    
    @pytest.mark.asyncio
    async def test_retry_execution(self, recovery_manager):
        """Test execution with retry strategy."""
        # Configure retry
        retry_config = create_mock_retry_config(max_attempts=3)
        recovery_manager.register_retry_config("test-retry", retry_config)
        
        # Function that fails twice then succeeds
        call_count = 0
        
        async def failing_then_success(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 3:  # Fail first two attempts
                raise TimeoutError(f"Mock timeout on attempt {call_count}")
            else:
                return f"Async success on attempt {call_count}"
        
        result = await recovery_manager.execute_with_recovery(
            "test-retry",
            failing_then_success,
            recovery_strategy=RecoveryStrategy.RETRY
        )
        
        assert "Async success" in result
        assert call_count == 3  # Should have retried
    
    @pytest.mark.asyncio
    async def test_fallback_execution(self, recovery_manager):
        """Test execution with fallback strategy."""
        # Register fallback
        async def fallback_handler(*args, **kwargs):
            return "fallback result"
        
        recovery_manager.register_fallback("test-fallback", fallback_handler)
        
        # Failing function
        mock_func = MockAsyncFailingFunction(should_fail=True)
        
        result = await recovery_manager.execute_with_recovery(
            "test-fallback",
            mock_func,
            recovery_strategy=RecoveryStrategy.FALLBACK
        )
        
        assert result == "fallback result"
        assert mock_func.call_count == 1  # Original function called once
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_execution(self, recovery_manager):
        """Test execution with circuit breaker strategy."""
        mock_func = MockAsyncFailingFunction(should_fail=True)
        
        # First call should fail and record failure
        with pytest.raises(Exception):
            await recovery_manager.execute_with_recovery(
                "test-circuit",
                mock_func,
                recovery_strategy=RecoveryStrategy.CIRCUIT_BREAKER
            )
        
        cb = recovery_manager.get_circuit_breaker("test-circuit")
        assert cb.failure_count == 1
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_open_state(self, recovery_manager):
        """Test circuit breaker in open state."""
        cb = recovery_manager.get_circuit_breaker("test-circuit")
        
        # Manually open circuit breaker
        cb.failure_count = cb.failure_threshold
        cb.state = "open"
        cb.last_failure_time = time.time()
        
        mock_func = MockAsyncFailingFunction()
        
        # Should raise ResourceExhaustionError when circuit is open
        with pytest.raises(ResourceExhaustionError, match="Circuit breaker"):
            await recovery_manager.execute_with_recovery(
                "test-circuit",
                mock_func,
                recovery_strategy=RecoveryStrategy.CIRCUIT_BREAKER
            )
        
        assert mock_func.call_count == 0  # Function should not be called


class TestErrorLogger:
    """Test ErrorLogger class."""
    
    @pytest.fixture
    def error_logger(self):
        """Create error logger."""
        return ErrorLogger("test_logger")
    
    def test_error_logger_initialization(self, error_logger):
        """Test error logger initialization."""
        assert error_logger.logger.name == "test_logger"
        assert len(error_logger.error_counts) == 0
        assert len(error_logger.error_history) == 0
        assert error_logger.max_history_size == 1000
    
    def test_shield_error_logging(self, error_logger):
        """Test logging Shield errors."""
        error = MockShieldError(
            message="Test error for logging",
            severity=ErrorSeverity.HIGH,
            category=ErrorCategory.VALIDATION
        )
        
        error_logger.log_error(error)
        
        assert error.error_type in error_logger.error_counts
        assert error_logger.error_counts[error.error_type] == 1
        assert len(error_logger.error_history) == 1
        assert error_logger.error_history[0].message == "Test error for logging"
    
    def test_generic_exception_logging(self, error_logger):
        """Test logging generic exceptions."""
        error = ValueError("Generic error")
        context = {"key": "value"}
        
        error_logger.log_error(error, context=context)
        
        assert "ValueError" in error_logger.error_counts
        assert error_logger.error_counts["ValueError"] == 1
        assert len(error_logger.error_history) == 1
        
        logged_error = error_logger.error_history[0]
        assert logged_error.error_type == "ValueError"
        assert logged_error.message == "Generic error"
        assert logged_error.context.custom_attributes == context
    
    def test_error_statistics(self, error_logger):
        """Test error statistics generation."""
        # Log multiple errors
        errors = [
            MockShieldError(message="Error 1"),
            MockShieldError(message="Error 2"),
            ValidationError("Validation error"),
            ValidationError("Another validation error"),
            TimeoutError("Timeout error")
        ]
        
        for error in errors:
            error_logger.log_error(error)
        
        stats = error_logger.get_error_statistics()
        
        assert stats["total_errors"] == 5
        assert "MockShieldError" in stats["error_counts_by_type"]
        assert stats["error_counts_by_type"]["MockShieldError"] == 2
        assert stats["error_counts_by_type"]["ValidationError"] == 2
        assert stats["error_counts_by_type"]["TimeoutError"] == 1
        
        # Check most common errors
        most_common = stats["most_common_errors"]
        assert len(most_common) <= 5
        # Should be sorted by count (descending)
        if len(most_common) > 1:
            assert most_common[0][1] >= most_common[1][1]
    
    def test_history_size_limit(self, error_logger):
        """Test error history size limit."""
        error_logger.max_history_size = 3
        
        # Log more errors than the limit
        for i in range(5):
            error_logger.log_error(MockShieldError(message=f"Error {i}"))
        
        # Should only keep the last 3 errors
        assert len(error_logger.error_history) == 3
        assert error_logger.error_history[0].message == "Error 2"
        assert error_logger.error_history[1].message == "Error 3"
        assert error_logger.error_history[2].message == "Error 4"


class TestErrorHandlingMiddleware:
    """Test ErrorHandlingMiddleware class."""
    
    @pytest.fixture
    def middleware(self):
        """Create error handling middleware."""
        app = Mock()
        return ErrorHandlingMiddleware(app, debug_mode=True)
    
    @pytest.mark.asyncio
    async def test_successful_request(self, middleware):
        """Test middleware with successful request."""
        request = MockRequest(method="GET", url_path="/test")
        
        async def call_next(req):
            return MockResponse(status_code=200, content="Success")
        
        response = await middleware.dispatch(request, call_next)
        
        assert response.status_code == 200
        assert response.content == "Success"
    
    @pytest.mark.asyncio
    async def test_shield_error_handling(self, middleware):
        """Test middleware handling Shield errors."""
        request = MockRequest(method="POST", url_path="/test")
        
        async def call_next(req):
            raise ValidationError("Invalid data format")
        
        response = await middleware.dispatch(request, call_next)
        
        assert isinstance(response, JSONResponse)
        assert response.status_code == 400
        
        response_data = json.loads(response.body.decode())
        assert response_data["error"] is True
        assert "Invalid data format" not in response_data["message"]  # User message
        assert "debug_info" in response_data  # Debug mode enabled
    
    @pytest.mark.asyncio
    async def test_http_exception_conversion(self, middleware):
        """Test middleware converting HTTPException to ShieldError."""
        request = MockRequest(method="GET", url_path="/test")
        
        async def call_next(req):
            raise HTTPException(status_code=404, detail="Not found")
        
        response = await middleware.dispatch(request, call_next)
        
        assert isinstance(response, JSONResponse)
        assert response.status_code == 404
        
        response_data = json.loads(response.body.decode())
        assert response_data["error"] is True
        assert response_data["category"] == "user_error"
    
    @pytest.mark.asyncio
    async def test_unexpected_exception_handling(self, middleware):
        """Test middleware handling unexpected exceptions."""
        request = MockRequest(method="DELETE", url_path="/test")
        
        async def call_next(req):
            raise RuntimeError("Unexpected error")
        
        response = await middleware.dispatch(request, call_next)
        
        assert isinstance(response, JSONResponse)
        assert response.status_code == 500
        
        response_data = json.loads(response.body.decode())
        assert response_data["error"] is True
        assert response_data["category"] == "internal_error"
        assert "debug_info" in response_data
        assert response_data["debug_info"]["original_error"] == "Unexpected error"
    
    @pytest.mark.asyncio
    async def test_debug_mode_disabled(self):
        """Test middleware with debug mode disabled."""
        app = Mock()
        middleware = ErrorHandlingMiddleware(app, debug_mode=False)
        request = MockRequest(method="GET", url_path="/test")
        
        async def call_next(req):
            raise ValidationError("Validation failed")
        
        response = await middleware.dispatch(request, call_next)
        response_data = json.loads(response.body.decode())
        
        # Debug info should not be included
        assert "debug_info" not in response_data
        assert "internal_message" not in response_data


class TestEnhancedShieldDecorator:
    """Test enhanced shield decorator."""
    
    @pytest.mark.asyncio
    async def test_decorator_success(self):
        """Test decorator with successful shield execution."""
        @enhanced_shield_decorator
        async def test_shield(request):
            return {"status": "success", "data": "test"}
        
        request = MockRequest()
        result = await test_shield(request)
        
        assert result["status"] == "success"
        assert result["data"] == "test"
    
    @pytest.mark.asyncio
    async def test_decorator_shield_error_passthrough(self):
        """Test decorator passing through Shield errors."""
        @enhanced_shield_decorator
        async def test_shield(request):
            raise ValidationError("Shield validation failed")
        
        request = MockRequest()
        
        with pytest.raises(ValidationError, match="Shield validation failed"):
            await test_shield(request)
    
    @pytest.mark.asyncio
    async def test_decorator_generic_exception_conversion(self):
        """Test decorator converting generic exceptions."""
        @enhanced_shield_decorator
        async def test_shield(request):
            raise ValueError("Generic error")
        
        request = MockRequest()
        
        with pytest.raises(ShieldError) as exc_info:
            await test_shield(request)
        
        error = exc_info.value
        assert "test_shield" in error.message
        assert "Generic error" in error.message
        assert error.category == ErrorCategory.INTERNAL_ERROR
        assert error.debug_info["shield_name"] == "test_shield"
    
    @pytest.mark.asyncio
    async def test_decorator_with_recovery_manager(self):
        """Test decorator with error recovery manager."""
        recovery_manager = MockErrorRecoveryManager()
        
        @enhanced_shield_decorator
        async def test_shield(request):
            return {"shield": "test", "status": "success"}
        
        request = MockRequest()
        result = await test_shield(request)
        
        assert result["shield"] == "test"
        assert result["status"] == "success"


class TestContextManagers:
    """Test error handling context managers."""
    
    def test_error_context_manager(self):
        """Test error_context context manager."""
        # Initial context should be empty
        initial_context = _error_context.get({})
        
        with error_context(shield_name="TestShield", user_id="user123"):
            current_context = _error_context.get({})
            assert current_context["shield_name"] == "TestShield"
            assert current_context["user_id"] == "user123"
        
        # Context should be restored after exiting
        final_context = _error_context.get({})
        assert final_context == initial_context
    
    def test_debug_mode_context_manager(self):
        """Test debug_mode context manager."""
        # Initial debug mode should be False
        initial_debug = _debug_mode.get(False)
        assert initial_debug is False
        
        with debug_mode(True):
            current_debug = _debug_mode.get(False)
            assert current_debug is True
        
        # Debug mode should be restored
        final_debug = _debug_mode.get(False)
        assert final_debug is False
    
    def test_nested_context_managers(self):
        """Test nested context managers."""
        with error_context(shield_name="OuterShield"):
            outer_context = _error_context.get({})
            assert outer_context["shield_name"] == "OuterShield"
            
            with error_context(user_id="user456", method="POST"):
                inner_context = _error_context.get({})
                assert inner_context["shield_name"] == "OuterShield"  # Inherited
                assert inner_context["user_id"] == "user456"
                assert inner_context["method"] == "POST"
            
            # Should restore to outer context
            restored_context = _error_context.get({})
            assert restored_context["shield_name"] == "OuterShield"
            assert "user_id" not in restored_context


class TestConvenienceFunctions:
    """Test convenience functions."""
    
    def test_global_instances(self):
        """Test global instance access."""
        recovery_manager = get_error_recovery_manager()
        error_logger = get_error_logger()
        
        assert isinstance(recovery_manager, ErrorRecoveryManager)
        assert isinstance(error_logger, ErrorLogger)
        
        # Should return the same instances
        assert get_error_recovery_manager() is recovery_manager
        assert get_error_logger() is error_logger
    
    def test_log_shield_error_function(self):
        """Test log_shield_error convenience function."""
        error = MockShieldError("Test error for global logging")
        
        # This should not raise an exception
        log_shield_error(error, context={"key": "value"})
        
        # Check that it was logged (would need to check the global logger)
        global_logger = get_error_logger()
        assert len(global_logger.error_history) > 0
    
    def test_raise_error_functions(self):
        """Test raise_*_error convenience functions."""
        with pytest.raises(AuthenticationError, match="Auth failed"):
            raise_authentication_error("Auth failed")
        
        with pytest.raises(AuthorizationError, match="Access denied"):
            raise_authorization_error("Access denied")
        
        with pytest.raises(ValidationError, match="Invalid input"):
            raise_validation_error("Invalid input")
        
        with pytest.raises(ConfigurationError, match="Config missing"):
            raise_configuration_error("Config missing")
        
        with pytest.raises(TimeoutError, match="Timed out"):
            raise_timeout_error("Timed out")


class TestErrorHandlingDecorators:
    """Test error handling decorators."""
    
    @pytest.mark.asyncio
    async def test_with_error_handling_decorator(self):
        """Test with_error_handling decorator."""
        @with_error_handling(recovery_strategy=RecoveryStrategy.NONE)
        async def test_function():
            return "success"
        
        result = await test_function()
        assert result == "success"
    
    @pytest.mark.asyncio
    async def test_with_retry_decorator(self):
        """Test with_retry decorator."""
        call_count = 0
        
        @with_retry(max_attempts=3, initial_delay=0.01)
        async def test_function():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise TimeoutError("Timeout")
            return "success after retries"
        
        result = await test_function()
        assert result == "success after retries"
        assert call_count == 3
    
    @pytest.mark.asyncio
    async def test_with_fallback_decorator(self):
        """Test with_fallback decorator."""
        async def fallback_handler():
            return "fallback result"
        
        @with_fallback(fallback_handler)
        async def test_function():
            raise RuntimeError("Primary function failed")
        
        result = await test_function()
        assert result == "fallback result"
    
    @pytest.mark.asyncio
    async def test_with_circuit_breaker_decorator(self):
        """Test with_circuit_breaker decorator."""
        @with_circuit_breaker()
        async def test_function():
            return "circuit breaker success"
        
        result = await test_function()
        assert result == "circuit breaker success"


class TestErrorHandlingIntegration:
    """Integration tests for error handling system."""
    
    @pytest.mark.asyncio
    async def test_end_to_end_error_flow(self):
        """Test complete error handling flow."""
        # Set up error context
        with error_context(
            shield_name="IntegrationTestShield",
            endpoint_path="/api/integration",
            method="POST",
            user_id="user789"
        ), debug_mode(True):
            
            # Create a shield that will fail
            shield = MockShield(name="IntegrationShield", should_fail=True)
            shield.exception_type = ValidationError
            
            # Enhanced shield with error handling
            @enhanced_shield_decorator
            async def enhanced_shield(request):
                return await shield(request)
            
            request = MockRequest(method="POST", url_path="/api/integration")
            
            # Should raise ValidationError
            with pytest.raises(ValidationError):
                await enhanced_shield(request)
            
            # Check that context was properly set
            current_context = _error_context.get({})
            # The decorator overrides the shield_name with the function name
            assert current_context["shield_name"] == "enhanced_shield"
            assert current_context["user_id"] == "user789"
    
    @pytest.mark.asyncio
    async def test_middleware_integration(self):
        """Test middleware integration with error recovery."""
        app = Mock()
        middleware = ErrorHandlingMiddleware(app, debug_mode=True)
        
        # Mock a shield that uses retry strategy
        call_count = 0
        
        async def failing_then_success_app(request):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise TimeoutError("Temporary failure")
            return MockResponse(status_code=200, content="Success after retries")
        
        request = MockRequest(method="GET", url_path="/test-retry")
        
        # First attempt - should handle error
        response = await middleware.dispatch(request, lambda r: failing_then_success_app(r))
        
        # Should get error response
        assert isinstance(response, JSONResponse)
        assert response.status_code == 408
    
    @pytest.mark.asyncio
    async def test_comprehensive_error_recovery(self):
        """Test comprehensive error recovery scenarios."""
        recovery_manager = ErrorRecoveryManager()
        
        # Configure retry
        retry_config = RetryConfig(
            max_attempts=3,
            initial_delay=0.01,
            retry_on_exceptions=(TimeoutError, DependencyFailureError)
        )
        recovery_manager.register_retry_config("test-service", retry_config)
        
        # Configure fallback
        async def fallback_service():
            return "fallback data"
        
        recovery_manager.register_fallback("test-service", fallback_service)
        
        # Test function that fails with retryable error
        attempt_count = 0
        
        async def unreliable_service():
            nonlocal attempt_count
            attempt_count += 1
            if attempt_count < 3:
                raise TimeoutError("Service timeout")
            return "service data"
        
        # Should succeed after retries
        result = await recovery_manager.execute_with_recovery(
            "test-service",
            unreliable_service,
            recovery_strategy=RecoveryStrategy.RETRY
        )
        
        assert result == "service data"
        assert attempt_count == 3
        
        # Test with non-retryable error - should use fallback
        async def failing_service():
            raise RuntimeError("Non-retryable error")
        
        result = await recovery_manager.execute_with_recovery(
            "test-service", 
            failing_service,
            recovery_strategy=RecoveryStrategy.FALLBACK
        )
        
        assert result == "fallback data"
    
    def test_error_logging_integration(self):
        """Test error logging integration."""
        error_logger = ErrorLogger("integration_test")
        
        # Log various types of errors
        errors = [
            AuthenticationError("Invalid token"),
            ValidationError("Bad input", debug_info={"field": "email"}),
            ResourceExhaustionError("Rate limit exceeded"),
            ConfigurationError("Missing API key")
        ]
        
        for error in errors:
            error_logger.log_error(error)
        
        # Check statistics
        stats = error_logger.get_error_statistics()
        assert stats["total_errors"] == 4
        assert len(stats["error_counts_by_type"]) == 4
        
        # Check most common errors
        most_common = stats["most_common_errors"]
        assert len(most_common) == 4
        
        # All should have count of 1
        for error_type, count in most_common:
            assert count == 1