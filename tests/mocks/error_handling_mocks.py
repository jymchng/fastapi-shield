"""Mock classes for error handling testing."""

import asyncio
import time
import uuid
from typing import Any, Dict, List, Optional, Callable, Type
from unittest.mock import Mock, AsyncMock
from datetime import datetime

from fastapi import Request, Response
from fastapi_shield.error_handling import (
    ErrorContext, ErrorDetails, ShieldError, ErrorSeverity, ErrorCategory,
    RecoveryStrategy, RetryConfig, ErrorRecoveryManager, CircuitBreaker,
    ErrorLogger
)


class MockRequest:
    """Mock FastAPI request for testing."""
    
    def __init__(
        self,
        method: str = "GET",
        url_path: str = "/test",
        headers: Optional[Dict[str, str]] = None,
        query_params: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None
    ):
        self.method = method
        self.url = Mock()
        self.url.path = url_path
        self.headers = headers or {}
        self.query_params = query_params or {}
        self._body = body or b""
    
    async def body(self) -> bytes:
        """Get request body."""
        return self._body
    
    async def json(self) -> Any:
        """Get request JSON."""
        import json
        return json.loads(self._body.decode())


class MockResponse:
    """Mock FastAPI response for testing."""
    
    def __init__(
        self,
        status_code: int = 200,
        headers: Optional[Dict[str, str]] = None,
        content: Any = None
    ):
        self.status_code = status_code
        self.headers = headers or {}
        self.content = content


class MockShieldError(ShieldError):
    """Mock Shield error for testing."""
    
    def __init__(
        self,
        message: str = "Test error",
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        category: ErrorCategory = ErrorCategory.INTERNAL_ERROR,
        recovery_strategy: RecoveryStrategy = RecoveryStrategy.NONE,
        **kwargs
    ):
        super().__init__(
            message=message,
            severity=severity,
            category=category,
            recovery_strategy=recovery_strategy,
            **kwargs
        )
    
    @property
    def error_type(self):
        """Get error type for testing."""
        return self.__class__.__name__


class MockErrorRecoveryManager:
    """Mock error recovery manager for testing."""
    
    def __init__(self):
        self.circuit_breakers: Dict[str, MockCircuitBreaker] = {}
        self.fallback_handlers: Dict[str, Callable] = {}
        self.retry_configs: Dict[str, RetryConfig] = {}
        self.execution_history: List[Dict[str, Any]] = []
        self.should_fail = False
        self.fail_with_exception: Optional[Type[Exception]] = None
    
    def register_fallback(self, key: str, handler: Callable):
        """Register fallback handler."""
        self.fallback_handlers[key] = handler
    
    def register_retry_config(self, key: str, config: RetryConfig):
        """Register retry configuration."""
        self.retry_configs[key] = config
    
    def get_circuit_breaker(self, key: str) -> 'MockCircuitBreaker':
        """Get or create mock circuit breaker."""
        if key not in self.circuit_breakers:
            self.circuit_breakers[key] = MockCircuitBreaker(name=key)
        return self.circuit_breakers[key]
    
    def set_should_fail(self, should_fail: bool, exception_type: Optional[Type[Exception]] = None):
        """Configure whether execution should fail."""
        self.should_fail = should_fail
        self.fail_with_exception = exception_type
    
    async def execute_with_recovery(
        self,
        key: str,
        func: Callable,
        *args,
        recovery_strategy: RecoveryStrategy = RecoveryStrategy.NONE,
        **kwargs
    ) -> Any:
        """Mock execute with recovery."""
        execution_record = {
            "key": key,
            "strategy": recovery_strategy,
            "timestamp": datetime.now(),
            "args": args,
            "kwargs": kwargs
        }
        self.execution_history.append(execution_record)
        
        if self.should_fail and self.fail_with_exception:
            raise self.fail_with_exception("Mock execution failure")
        
        # Simulate different recovery strategies
        if recovery_strategy == RecoveryStrategy.RETRY:
            return await self._mock_retry_execution(key, func, *args, **kwargs)
        elif recovery_strategy == RecoveryStrategy.FALLBACK:
            return await self._mock_fallback_execution(key, func, *args, **kwargs)
        elif recovery_strategy == RecoveryStrategy.CIRCUIT_BREAKER:
            return await self._mock_circuit_breaker_execution(key, func, *args, **kwargs)
        else:
            if asyncio.iscoroutinefunction(func):
                return await func(*args, **kwargs)
            else:
                return func(*args, **kwargs)
    
    async def _mock_retry_execution(self, key: str, func: Callable, *args, **kwargs):
        """Mock retry execution."""
        config = self.retry_configs.get(key, RetryConfig())
        
        for attempt in range(config.max_attempts):
            try:
                if asyncio.iscoroutinefunction(func):
                    return await func(*args, **kwargs)
                else:
                    return func(*args, **kwargs)
            except Exception as e:
                if attempt < config.max_attempts - 1:
                    await asyncio.sleep(0.01)  # Small delay for testing
                else:
                    raise
    
    async def _mock_fallback_execution(self, key: str, func: Callable, *args, **kwargs):
        """Mock fallback execution."""
        try:
            if asyncio.iscoroutinefunction(func):
                return await func(*args, **kwargs)
            else:
                return func(*args, **kwargs)
        except Exception:
            fallback = self.fallback_handlers.get(key)
            if fallback:
                if asyncio.iscoroutinefunction(fallback):
                    return await fallback(*args, **kwargs)
                else:
                    return fallback(*args, **kwargs)
            else:
                raise
    
    async def _mock_circuit_breaker_execution(self, key: str, func: Callable, *args, **kwargs):
        """Mock circuit breaker execution."""
        circuit_breaker = self.get_circuit_breaker(key)
        
        if circuit_breaker.is_open():
            from fastapi_shield.error_handling import ResourceExhaustionError
            raise ResourceExhaustionError(f"Circuit breaker {key} is open")
        
        try:
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)
            circuit_breaker.record_success()
            return result
        except Exception as e:
            circuit_breaker.record_failure()
            raise


class MockCircuitBreaker:
    """Mock circuit breaker for testing."""
    
    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0
    ):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time: Optional[float] = None
        self.state = "closed"  # closed, open, half_open
        self.force_open = False  # For testing
    
    def set_force_open(self, force_open: bool):
        """Force circuit breaker state for testing."""
        self.force_open = force_open
        if force_open:
            self.state = "open"
        else:
            self.state = "closed"
            self.failure_count = 0
    
    def is_open(self) -> bool:
        """Check if circuit breaker is open."""
        if self.force_open:
            return True
        
        if self.state == "open":
            if (self.last_failure_time and 
                time.time() - self.last_failure_time > self.recovery_timeout):
                self.state = "half_open"
                return False
            return True
        return False
    
    def record_success(self):
        """Record successful execution."""
        self.failure_count = 0
        self.state = "closed"
    
    def record_failure(self):
        """Record failed execution."""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.failure_count >= self.failure_threshold:
            self.state = "open"
    
    def get_state(self) -> Dict[str, Any]:
        """Get circuit breaker state."""
        return {
            "name": self.name,
            "state": self.state,
            "failure_count": self.failure_count,
            "failure_threshold": self.failure_threshold,
            "last_failure_time": self.last_failure_time,
            "recovery_timeout": self.recovery_timeout,
            "force_open": self.force_open
        }


class MockErrorLogger:
    """Mock error logger for testing."""
    
    def __init__(self):
        self.logged_errors: List[ErrorDetails] = []
        self.error_counts: Dict[str, int] = {}
        self.log_calls: List[Dict[str, Any]] = []
    
    def log_error(
        self,
        error: Exception,
        context: Optional[Dict[str, Any]] = None,
        extra_fields: Optional[Dict[str, Any]] = None
    ):
        """Mock log error."""
        log_entry = {
            "error": error,
            "context": context,
            "extra_fields": extra_fields,
            "timestamp": datetime.now()
        }
        self.log_calls.append(log_entry)
        
        if isinstance(error, ShieldError):
            error_details = error.get_error_details()
            self.logged_errors.append(error_details)
            
            error_type = error_details.error_type
            self.error_counts[error_type] = self.error_counts.get(error_type, 0) + 1
    
    def get_error_statistics(self) -> Dict[str, Any]:
        """Get mock error statistics."""
        total_errors = sum(self.error_counts.values())
        return {
            "total_errors": total_errors,
            "error_counts_by_type": dict(self.error_counts),
            "recent_errors_count": len(self.logged_errors),
            "most_common_errors": sorted(
                self.error_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]
        }
    
    def clear_history(self):
        """Clear logged error history."""
        self.logged_errors.clear()
        self.error_counts.clear()
        self.log_calls.clear()


class MockFailingFunction:
    """Mock function that can be configured to fail."""
    
    def __init__(self, should_fail: bool = False, exception_type: Type[Exception] = Exception):
        self.should_fail = should_fail
        self.exception_type = exception_type
        self.call_count = 0
        self.success_count = 0
        self.failure_count = 0
        self.call_history: List[Dict[str, Any]] = []
    
    def __call__(self, *args, **kwargs):
        """Mock function call."""
        self.call_count += 1
        call_record = {
            "attempt": self.call_count,
            "args": args,
            "kwargs": kwargs,
            "timestamp": datetime.now()
        }
        self.call_history.append(call_record)
        
        if self.should_fail:
            self.failure_count += 1
            raise self.exception_type(f"Mock failure on attempt {self.call_count}")
        else:
            self.success_count += 1
            return f"Success on attempt {self.call_count}"
    
    def set_should_fail(self, should_fail: bool):
        """Configure failure behavior."""
        self.should_fail = should_fail
    
    def reset_counters(self):
        """Reset call counters."""
        self.call_count = 0
        self.success_count = 0
        self.failure_count = 0
        self.call_history.clear()


class MockAsyncFailingFunction:
    """Mock async function that can be configured to fail."""
    
    def __init__(self, should_fail: bool = False, exception_type: Type[Exception] = Exception):
        self.should_fail = should_fail
        self.exception_type = exception_type
        self.call_count = 0
        self.success_count = 0
        self.failure_count = 0
        self.call_history: List[Dict[str, Any]] = []
    
    async def __call__(self, *args, **kwargs):
        """Mock async function call."""
        self.call_count += 1
        call_record = {
            "attempt": self.call_count,
            "args": args,
            "kwargs": kwargs,
            "timestamp": datetime.now()
        }
        self.call_history.append(call_record)
        
        if self.should_fail:
            self.failure_count += 1
            raise self.exception_type(f"Mock async failure on attempt {self.call_count}")
        else:
            self.success_count += 1
            return f"Async success on attempt {self.call_count}"
    
    def set_should_fail(self, should_fail: bool):
        """Configure failure behavior."""
        self.should_fail = should_fail
    
    def reset_counters(self):
        """Reset call counters."""
        self.call_count = 0
        self.success_count = 0
        self.failure_count = 0
        self.call_history.clear()


def create_mock_error_context(
    request_id: Optional[str] = None,
    shield_name: Optional[str] = None,
    endpoint_path: Optional[str] = None,
    method: Optional[str] = None,
    **kwargs
) -> ErrorContext:
    """Create mock error context for testing."""
    return ErrorContext(
        request_id=request_id or str(uuid.uuid4()),
        shield_name=shield_name,
        endpoint_path=endpoint_path,
        method=method,
        **kwargs
    )


def create_mock_error_details(
    error_id: Optional[str] = None,
    error_type: str = "MockError",
    message: str = "Mock error message",
    severity: ErrorSeverity = ErrorSeverity.MEDIUM,
    category: ErrorCategory = ErrorCategory.INTERNAL_ERROR,
    recovery_strategy: RecoveryStrategy = RecoveryStrategy.NONE,
    context: Optional[ErrorContext] = None,
    **kwargs
) -> ErrorDetails:
    """Create mock error details for testing."""
    return ErrorDetails(
        error_id=error_id or str(uuid.uuid4()),
        error_type=error_type,
        message=message,
        severity=severity,
        category=category,
        recovery_strategy=recovery_strategy,
        context=context or create_mock_error_context(),
        **kwargs
    )


def create_mock_retry_config(
    max_attempts: int = 3,
    initial_delay: float = 0.1,  # Short delay for testing
    max_delay: float = 1.0,
    exponential_base: float = 2.0,
    jitter: bool = False,  # Disable jitter for predictable testing
    retry_on_exceptions: Optional[tuple] = None
) -> RetryConfig:
    """Create mock retry configuration for testing."""
    if retry_on_exceptions is None:
        from fastapi_shield.error_handling import TimeoutError, DependencyFailureError
        retry_on_exceptions = (TimeoutError, DependencyFailureError)
    
    return RetryConfig(
        max_attempts=max_attempts,
        initial_delay=initial_delay,
        max_delay=max_delay,
        exponential_base=exponential_base,
        jitter=jitter,
        retry_on_exceptions=retry_on_exceptions
    )


class MockMiddleware:
    """Mock middleware for testing error handling middleware."""
    
    def __init__(self):
        self.call_count = 0
        self.requests_processed: List[Dict[str, Any]] = []
        self.responses_generated: List[Dict[str, Any]] = []
        self.errors_handled: List[Dict[str, Any]] = []
    
    async def __call__(self, request: MockRequest, call_next):
        """Mock middleware call."""
        self.call_count += 1
        request_record = {
            "method": request.method,
            "path": request.url.path,
            "timestamp": datetime.now()
        }
        self.requests_processed.append(request_record)
        
        try:
            response = await call_next(request)
            response_record = {
                "status_code": getattr(response, 'status_code', 200),
                "timestamp": datetime.now()
            }
            self.responses_generated.append(response_record)
            return response
        except Exception as e:
            error_record = {
                "error_type": e.__class__.__name__,
                "message": str(e),
                "timestamp": datetime.now()
            }
            self.errors_handled.append(error_record)
            raise
    
    def reset_counters(self):
        """Reset middleware counters."""
        self.call_count = 0
        self.requests_processed.clear()
        self.responses_generated.clear()
        self.errors_handled.clear()


class MockShield:
    """Mock shield for testing error handling."""
    
    def __init__(
        self,
        name: str = "MockShield",
        should_fail: bool = False,
        exception_type: Type[Exception] = Exception
    ):
        self.name = name
        self.should_fail = should_fail
        self.exception_type = exception_type
        self.execution_count = 0
        self.execution_history: List[Dict[str, Any]] = []
    
    async def __call__(self, request, *args, **kwargs):
        """Mock shield execution."""
        self.execution_count += 1
        execution_record = {
            "execution": self.execution_count,
            "request_path": getattr(request, 'url', {}).get('path', '/'),
            "timestamp": datetime.now(),
            "args": args,
            "kwargs": kwargs
        }
        self.execution_history.append(execution_record)
        
        if self.should_fail:
            raise self.exception_type(f"Mock shield {self.name} failure")
        
        return {"shield": self.name, "status": "success", "execution": self.execution_count}
    
    def set_should_fail(self, should_fail: bool):
        """Configure shield failure behavior."""
        self.should_fail = should_fail
    
    def reset_counters(self):
        """Reset execution counters."""
        self.execution_count = 0
        self.execution_history.clear()