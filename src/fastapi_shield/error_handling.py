"""Enhanced error handling system for FastAPI Shield.

This module provides comprehensive error handling capabilities including
detailed error messages, debugging information, recovery mechanisms,
structured logging, and error analytics.
"""

import asyncio
import contextvars
import inspect
import json
import logging
import traceback
import uuid
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from functools import wraps
from pathlib import Path
from typing import (
    Any, Dict, List, Optional, Tuple, Union, Callable, Type,
    Awaitable, TypeVar, Generic
)
import sys
import threading
import time
import weakref

from fastapi import Request, Response, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from fastapi_shield.shield import Shield

# Context variables for error tracking
_error_context: contextvars.ContextVar[Dict[str, Any]] = contextvars.ContextVar(
    'error_context', default={}
)
_debug_mode: contextvars.ContextVar[bool] = contextvars.ContextVar(
    'debug_mode', default=False
)

T = TypeVar('T')
F = TypeVar('F', bound=Callable[..., Any])

logger = logging.getLogger(__name__)


class ErrorSeverity(str, Enum):
    """Error severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ErrorCategory(str, Enum):
    """Error categories for classification."""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    VALIDATION = "validation"
    CONFIGURATION = "configuration"
    NETWORK = "network"
    TIMEOUT = "timeout"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    DEPENDENCY_FAILURE = "dependency_failure"
    INTERNAL_ERROR = "internal_error"
    USER_ERROR = "user_error"
    SYSTEM_ERROR = "system_error"


class RecoveryStrategy(str, Enum):
    """Error recovery strategies."""
    NONE = "none"
    RETRY = "retry"
    FALLBACK = "fallback"
    CIRCUIT_BREAKER = "circuit_breaker"
    GRACEFUL_DEGRADATION = "graceful_degradation"
    FAIL_FAST = "fail_fast"
    IGNORE = "ignore"


@dataclass
class ErrorContext:
    """Context information for error tracking."""
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    shield_name: Optional[str] = None
    endpoint_path: Optional[str] = None
    method: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    correlation_id: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    execution_context: Dict[str, Any] = field(default_factory=dict)
    custom_attributes: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "request_id": self.request_id,
            "shield_name": self.shield_name,
            "endpoint_path": self.endpoint_path,
            "method": self.method,
            "user_id": self.user_id,
            "session_id": self.session_id,
            "correlation_id": self.correlation_id,
            "timestamp": self.timestamp.isoformat() if isinstance(self.timestamp, datetime) else self.timestamp,
            "execution_context": self.execution_context,
            "custom_attributes": self.custom_attributes
        }


@dataclass
class ErrorDetails:
    """Detailed error information."""
    error_id: str
    error_type: str
    message: str
    severity: ErrorSeverity
    category: ErrorCategory
    recovery_strategy: RecoveryStrategy
    context: ErrorContext
    stack_trace: Optional[str] = None
    debug_info: Optional[Dict[str, Any]] = None
    suggested_actions: List[str] = field(default_factory=list)
    related_errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "error_id": self.error_id,
            "error_type": self.error_type,
            "message": self.message,
            "severity": self.severity.value,
            "category": self.category.value,
            "recovery_strategy": self.recovery_strategy.value,
            "context": self.context.to_dict(),
            "stack_trace": self.stack_trace,
            "debug_info": self.debug_info,
            "suggested_actions": self.suggested_actions,
            "related_errors": self.related_errors,
            "metadata": self.metadata
        }


class ShieldError(Exception):
    """Enhanced base exception class for Shield errors."""
    
    def __init__(
        self,
        message: str,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        category: ErrorCategory = ErrorCategory.INTERNAL_ERROR,
        recovery_strategy: RecoveryStrategy = RecoveryStrategy.NONE,
        debug_info: Optional[Dict[str, Any]] = None,
        suggested_actions: Optional[List[str]] = None,
        http_status_code: int = 500,
        user_message: Optional[str] = None,
        **kwargs
    ):
        super().__init__(message)
        self.error_id = str(uuid.uuid4())
        self.message = message
        self.severity = severity
        self.category = category
        self.recovery_strategy = recovery_strategy
        self.debug_info = debug_info or {}
        self.suggested_actions = suggested_actions or []
        self.http_status_code = http_status_code
        self.user_message = user_message or self._generate_user_message()
        self.metadata = kwargs
        self.context = self._get_current_context()
        self.timestamp = datetime.now()
        
        # Capture stack trace
        self.stack_trace = traceback.format_exc() if sys.exc_info()[0] else None
    
    def _get_current_context(self) -> ErrorContext:
        """Get current error context."""
        context_data = _error_context.get({})
        # Handle timestamp conversion
        if 'timestamp' in context_data and isinstance(context_data['timestamp'], str):
            try:
                timestamp = datetime.fromisoformat(context_data['timestamp'])
            except ValueError:
                timestamp = datetime.now()
            context_data = {**context_data, 'timestamp': timestamp}
        return ErrorContext(**context_data)
    
    def _generate_user_message(self) -> str:
        """Generate user-friendly message."""
        if self.category == ErrorCategory.AUTHENTICATION:
            return "Authentication failed. Please check your credentials."
        elif self.category == ErrorCategory.AUTHORIZATION:
            return "You don't have permission to access this resource."
        elif self.category == ErrorCategory.VALIDATION:
            return "The provided data is invalid. Please check your input."
        elif self.category == ErrorCategory.TIMEOUT:
            return "The request timed out. Please try again."
        elif self.category == ErrorCategory.NETWORK:
            return "Network error occurred. Please check your connection."
        elif self.category == ErrorCategory.RESOURCE_EXHAUSTION:
            return "System resources are temporarily unavailable. Please try again later."
        else:
            return "An error occurred while processing your request."
    
    def get_error_details(self) -> ErrorDetails:
        """Get detailed error information."""
        return ErrorDetails(
            error_id=self.error_id,
            error_type=self.__class__.__name__,
            message=self.message,
            severity=self.severity,
            category=self.category,
            recovery_strategy=self.recovery_strategy,
            context=self.context,
            stack_trace=self.stack_trace,
            debug_info=self.debug_info,
            suggested_actions=self.suggested_actions,
            metadata=self.metadata
        )
    
    def to_http_response(self, include_debug_info: bool = False) -> JSONResponse:
        """Convert to HTTP response."""
        response_data = {
            "error": True,
            "error_id": self.error_id,
            "message": self.user_message,
            "category": self.category.value,
            "timestamp": self.timestamp.isoformat()
        }
        
        if include_debug_info:
            response_data.update({
                "debug_info": self.debug_info,
                "suggested_actions": self.suggested_actions,
                "internal_message": self.message,
                "context": self.context.to_dict()
            })
        
        return JSONResponse(
            status_code=self.http_status_code,
            content=response_data
        )


class AuthenticationError(ShieldError):
    """Authentication-related errors."""
    
    def __init__(self, message: str = "Authentication failed", **kwargs):
        super().__init__(
            message=message,
            category=ErrorCategory.AUTHENTICATION,
            http_status_code=401,
            severity=ErrorSeverity.HIGH,
            suggested_actions=["Check credentials", "Verify token validity"],
            **kwargs
        )


class AuthorizationError(ShieldError):
    """Authorization-related errors."""
    
    def __init__(self, message: str = "Access denied", **kwargs):
        super().__init__(
            message=message,
            category=ErrorCategory.AUTHORIZATION,
            http_status_code=403,
            severity=ErrorSeverity.HIGH,
            suggested_actions=["Check permissions", "Contact administrator"],
            **kwargs
        )


class ValidationError(ShieldError):
    """Validation-related errors."""
    
    def __init__(self, message: str = "Validation failed", **kwargs):
        super().__init__(
            message=message,
            category=ErrorCategory.VALIDATION,
            http_status_code=400,
            severity=ErrorSeverity.MEDIUM,
            suggested_actions=["Check input format", "Validate required fields"],
            **kwargs
        )


class ConfigurationError(ShieldError):
    """Configuration-related errors."""
    
    def __init__(self, message: str = "Configuration error", **kwargs):
        super().__init__(
            message=message,
            category=ErrorCategory.CONFIGURATION,
            http_status_code=500,
            severity=ErrorSeverity.HIGH,
            suggested_actions=["Check configuration", "Verify environment variables"],
            **kwargs
        )


class TimeoutError(ShieldError):
    """Timeout-related errors."""
    
    def __init__(self, message: str = "Request timeout", **kwargs):
        super().__init__(
            message=message,
            category=ErrorCategory.TIMEOUT,
            http_status_code=408,
            severity=ErrorSeverity.MEDIUM,
            recovery_strategy=RecoveryStrategy.RETRY,
            suggested_actions=["Retry request", "Check network connectivity"],
            **kwargs
        )


class ResourceExhaustionError(ShieldError):
    """Resource exhaustion errors."""
    
    def __init__(self, message: str = "Resources exhausted", **kwargs):
        super().__init__(
            message=message,
            category=ErrorCategory.RESOURCE_EXHAUSTION,
            http_status_code=429,
            severity=ErrorSeverity.CRITICAL,
            recovery_strategy=RecoveryStrategy.CIRCUIT_BREAKER,
            suggested_actions=["Wait and retry", "Reduce load"],
            **kwargs
        )


class DependencyFailureError(ShieldError):
    """Dependency failure errors."""
    
    def __init__(self, message: str = "Dependency failure", **kwargs):
        super().__init__(
            message=message,
            category=ErrorCategory.DEPENDENCY_FAILURE,
            http_status_code=503,
            severity=ErrorSeverity.HIGH,
            recovery_strategy=RecoveryStrategy.FALLBACK,
            suggested_actions=["Check dependencies", "Use fallback mechanism"],
            **kwargs
        )


@dataclass
class RetryConfig:
    """Configuration for retry mechanisms."""
    max_attempts: int = 3
    initial_delay: float = 1.0
    max_delay: float = 60.0
    exponential_base: float = 2.0
    jitter: bool = True
    retry_on_exceptions: Tuple[Type[Exception], ...] = (TimeoutError, DependencyFailureError)
    
    def calculate_delay(self, attempt: int) -> float:
        """Calculate delay for retry attempt."""
        delay = self.initial_delay * (self.exponential_base ** (attempt - 1))
        delay = min(delay, self.max_delay)
        
        if self.jitter:
            import random
            delay *= (0.5 + random.random() * 0.5)
        
        return delay


class ErrorRecoveryManager:
    """Manager for error recovery strategies."""
    
    def __init__(self):
        self.circuit_breakers: Dict[str, 'CircuitBreaker'] = {}
        self.fallback_handlers: Dict[str, Callable] = {}
        self.retry_configs: Dict[str, RetryConfig] = {}
        self._lock = threading.RLock()
    
    def register_fallback(self, key: str, handler: Callable):
        """Register a fallback handler."""
        with self._lock:
            self.fallback_handlers[key] = handler
    
    def register_retry_config(self, key: str, config: RetryConfig):
        """Register retry configuration."""
        with self._lock:
            self.retry_configs[key] = config
    
    def get_circuit_breaker(self, key: str) -> 'CircuitBreaker':
        """Get or create circuit breaker."""
        with self._lock:
            if key not in self.circuit_breakers:
                self.circuit_breakers[key] = CircuitBreaker(name=key)
            return self.circuit_breakers[key]
    
    async def execute_with_recovery(
        self,
        key: str,
        func: Callable,
        *args,
        recovery_strategy: RecoveryStrategy = RecoveryStrategy.NONE,
        **kwargs
    ) -> Any:
        """Execute function with recovery strategy."""
        if recovery_strategy == RecoveryStrategy.RETRY:
            return await self._execute_with_retry(key, func, *args, **kwargs)
        elif recovery_strategy == RecoveryStrategy.FALLBACK:
            return await self._execute_with_fallback(key, func, *args, **kwargs)
        elif recovery_strategy == RecoveryStrategy.CIRCUIT_BREAKER:
            return await self._execute_with_circuit_breaker(key, func, *args, **kwargs)
        else:
            return await self._execute_simple(func, *args, **kwargs)
    
    async def _execute_simple(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function without recovery."""
        if asyncio.iscoroutinefunction(func):
            return await func(*args, **kwargs)
        elif hasattr(func, '__call__') and asyncio.iscoroutinefunction(func.__call__):
            return await func(*args, **kwargs)
        else:
            result = func(*args, **kwargs)
            if asyncio.iscoroutine(result):
                return await result
            return result
    
    async def _execute_with_retry(self, key: str, func: Callable, *args, **kwargs) -> Any:
        """Execute function with retry logic."""
        config = self.retry_configs.get(key, RetryConfig())
        last_exception = None
        
        for attempt in range(1, config.max_attempts + 1):
            try:
                return await self._execute_simple(func, *args, **kwargs)
            except Exception as e:
                last_exception = e
                
                # Check if we should retry this exception
                if not isinstance(e, config.retry_on_exceptions):
                    raise
                
                # Don't delay on the last attempt
                if attempt < config.max_attempts:
                    delay = config.calculate_delay(attempt)
                    await asyncio.sleep(delay)
                    
                    logger.warning(
                        f"Retry attempt {attempt}/{config.max_attempts} for {key} "
                        f"after {delay:.2f}s delay: {e}"
                    )
        
        # All attempts failed
        if last_exception:
            raise last_exception
    
    async def _execute_with_fallback(self, key: str, func: Callable, *args, **kwargs) -> Any:
        """Execute function with fallback."""
        try:
            return await self._execute_simple(func, *args, **kwargs)
        except Exception as e:
            fallback_handler = self.fallback_handlers.get(key)
            if fallback_handler:
                logger.warning(f"Using fallback for {key}: {e}")
                return await self._execute_simple(fallback_handler, *args, **kwargs)
            else:
                raise
    
    async def _execute_with_circuit_breaker(self, key: str, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker."""
        circuit_breaker = self.get_circuit_breaker(key)
        
        if circuit_breaker.is_open():
            raise ResourceExhaustionError(
                f"Circuit breaker {key} is open",
                debug_info={"circuit_breaker_state": circuit_breaker.get_state()}
            )
        
        try:
            result = await self._execute_simple(func, *args, **kwargs)
            circuit_breaker.record_success()
            return result
        except Exception as e:
            circuit_breaker.record_failure()
            raise


class CircuitBreaker:
    """Circuit breaker implementation for error handling."""
    
    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        expected_exception: Type[Exception] = Exception
    ):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        
        self.failure_count = 0
        self.last_failure_time: Optional[float] = None
        self.state = "closed"  # closed, open, half_open
        self._lock = threading.Lock()
    
    def is_open(self) -> bool:
        """Check if circuit breaker is open."""
        with self._lock:
            if self.state == "open":
                # Check if recovery timeout has passed
                if (self.last_failure_time and 
                    time.time() - self.last_failure_time > self.recovery_timeout):
                    self.state = "half_open"
                    return False
                return True
            return False
    
    def record_success(self):
        """Record successful execution."""
        with self._lock:
            self.failure_count = 0
            self.state = "closed"
    
    def record_failure(self):
        """Record failed execution."""
        with self._lock:
            self.failure_count += 1
            self.last_failure_time = time.time()
            
            if self.failure_count >= self.failure_threshold:
                self.state = "open"
    
    def get_state(self) -> Dict[str, Any]:
        """Get current circuit breaker state."""
        return {
            "name": self.name,
            "state": self.state,
            "failure_count": self.failure_count,
            "failure_threshold": self.failure_threshold,
            "last_failure_time": self.last_failure_time,
            "recovery_timeout": self.recovery_timeout
        }


class ErrorLogger:
    """Enhanced error logging with structured format."""
    
    def __init__(self, logger_name: str = __name__):
        self.logger = logging.getLogger(logger_name)
        self.error_counts: Dict[str, int] = {}
        self.error_history: List[ErrorDetails] = []
        self._lock = threading.Lock()
        self.max_history_size = 1000
    
    def log_error(
        self,
        error: Union[ShieldError, Exception],
        context: Optional[Dict[str, Any]] = None,
        extra_fields: Optional[Dict[str, Any]] = None
    ):
        """Log error with structured format."""
        if isinstance(error, ShieldError):
            error_details = error.get_error_details()
        else:
            error_details = self._create_error_details_from_exception(error, context)
        
        # Add extra fields
        if extra_fields:
            error_details.metadata.update(extra_fields)
        
        # Log with appropriate level
        log_level = self._get_log_level(error_details.severity)
        log_data = error_details.to_dict()
        
        self.logger.log(
            log_level,
            f"Shield Error: {error_details.message}",
            extra={"error_details": log_data}
        )
        
        # Track error statistics
        with self._lock:
            error_type = error_details.error_type
            self.error_counts[error_type] = self.error_counts.get(error_type, 0) + 1
            
            # Keep error history
            self.error_history.append(error_details)
            if len(self.error_history) > self.max_history_size:
                self.error_history = self.error_history[-self.max_history_size:]
    
    def _create_error_details_from_exception(
        self,
        error: Exception,
        context: Optional[Dict[str, Any]] = None
    ) -> ErrorDetails:
        """Create error details from generic exception."""
        error_context = ErrorContext()
        if context:
            error_context.custom_attributes.update(context)
        
        return ErrorDetails(
            error_id=str(uuid.uuid4()),
            error_type=error.__class__.__name__,
            message=str(error),
            severity=ErrorSeverity.MEDIUM,
            category=ErrorCategory.INTERNAL_ERROR,
            recovery_strategy=RecoveryStrategy.NONE,
            context=error_context,
            stack_trace=traceback.format_exc(),
            debug_info={"exception_args": getattr(error, 'args', [])}
        )
    
    def _get_log_level(self, severity: ErrorSeverity) -> int:
        """Map severity to log level."""
        mapping = {
            ErrorSeverity.CRITICAL: logging.CRITICAL,
            ErrorSeverity.HIGH: logging.ERROR,
            ErrorSeverity.MEDIUM: logging.WARNING,
            ErrorSeverity.LOW: logging.INFO,
            ErrorSeverity.INFO: logging.INFO
        }
        return mapping.get(severity, logging.WARNING)
    
    def get_error_statistics(self) -> Dict[str, Any]:
        """Get error statistics."""
        with self._lock:
            total_errors = sum(self.error_counts.values())
            recent_errors = []
            for err in self.error_history[-100:]:
                try:
                    if isinstance(err.context.timestamp, datetime):
                        timestamp = err.context.timestamp
                    else:
                        timestamp = datetime.fromisoformat(str(err.context.timestamp).replace('Z', '+00:00').replace('+00:00', ''))
                    
                    if (datetime.now() - timestamp).total_seconds() < 3600:
                        recent_errors.append(err)
                except (ValueError, AttributeError, TypeError):
                    # Skip errors with invalid timestamps
                    continue
            
            return {
                "total_errors": total_errors,
                "error_counts_by_type": dict(self.error_counts),
                "recent_errors_count": len(recent_errors),
                "most_common_errors": sorted(
                    self.error_counts.items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:5]
            }


class ErrorHandlingMiddleware(BaseHTTPMiddleware):
    """Middleware for handling Shield errors."""
    
    def __init__(self, app, debug_mode: bool = False, include_stack_traces: bool = False):
        super().__init__(app)
        self.debug_mode = debug_mode
        self.include_stack_traces = include_stack_traces
        self.error_logger = ErrorLogger()
    
    async def dispatch(self, request: Request, call_next):
        """Process request with error handling."""
        # Set error context
        context_dict = {
            "endpoint_path": request.url.path,
            "method": request.method,
            "request_id": request.headers.get('X-Request-ID', str(uuid.uuid4())),
            "timestamp": datetime.now().isoformat()
        }
        
        _error_context.set(context_dict)
        _debug_mode.set(self.debug_mode)
        
        try:
            response = await call_next(request)
            return response
        except ShieldError as e:
            self.error_logger.log_error(e)
            return e.to_http_response(include_debug_info=self.debug_mode)
        except HTTPException as e:
            # Convert HTTPException to ShieldError for consistent handling
            shield_error = ShieldError(
                message=e.detail,
                http_status_code=e.status_code,
                category=ErrorCategory.USER_ERROR,
                severity=ErrorSeverity.MEDIUM
            )
            self.error_logger.log_error(shield_error)
            return shield_error.to_http_response(include_debug_info=self.debug_mode)
        except Exception as e:
            # Handle unexpected errors
            shield_error = ShieldError(
                message="Internal server error",
                category=ErrorCategory.INTERNAL_ERROR,
                severity=ErrorSeverity.CRITICAL,
                debug_info={"original_error": str(e)},
                http_status_code=500
            )
            self.error_logger.log_error(shield_error)
            return shield_error.to_http_response(include_debug_info=self.debug_mode)


def enhanced_shield_decorator(
    original_shield_func: Callable,
    error_recovery_manager: Optional[ErrorRecoveryManager] = None,
    retry_config: Optional[RetryConfig] = None,
    fallback_handler: Optional[Callable] = None
):
    """Decorator to enhance shield functions with error handling."""
    
    @wraps(original_shield_func)
    async def wrapper(*args, **kwargs):
        shield_name = getattr(original_shield_func, '__name__', 'unknown_shield')
        
        # Update error context
        current_context = _error_context.get({})
        current_context['shield_name'] = shield_name
        _error_context.set(current_context)
        
        try:
            # Use error recovery if available
            if error_recovery_manager:
                return await error_recovery_manager.execute_with_recovery(
                    shield_name,
                    original_shield_func,
                    *args,
                    **kwargs
                )
            else:
                if asyncio.iscoroutinefunction(original_shield_func):
                    return await original_shield_func(*args, **kwargs)
                else:
                    return original_shield_func(*args, **kwargs)
        
        except ShieldError:
            # Re-raise Shield errors as-is
            raise
        except Exception as e:
            # Convert generic exceptions to ShieldError
            raise ShieldError(
                message=f"Shield '{shield_name}' execution failed: {str(e)}",
                category=ErrorCategory.INTERNAL_ERROR,
                severity=ErrorSeverity.HIGH,
                debug_info={
                    "shield_name": shield_name,
                    "original_error": str(e),
                    "original_error_type": e.__class__.__name__
                }
            )
    
    return wrapper


# Context managers for error handling
@contextmanager
def error_context(**kwargs):
    """Context manager to set error context."""
    current_context = _error_context.get({})
    new_context = {**current_context, **kwargs}
    token = _error_context.set(new_context)
    try:
        yield
    finally:
        _error_context.reset(token)


@contextmanager
def debug_mode(enabled: bool = True):
    """Context manager to enable/disable debug mode."""
    token = _debug_mode.set(enabled)
    try:
        yield
    finally:
        _debug_mode.reset(token)


# Global instances
_global_error_recovery_manager = ErrorRecoveryManager()
_global_error_logger = ErrorLogger()


def get_error_recovery_manager() -> ErrorRecoveryManager:
    """Get global error recovery manager."""
    return _global_error_recovery_manager


def get_error_logger() -> ErrorLogger:
    """Get global error logger."""
    return _global_error_logger


def log_shield_error(
    error: Union[ShieldError, Exception],
    context: Optional[Dict[str, Any]] = None,
    **kwargs
):
    """Log shield error with global logger."""
    _global_error_logger.log_error(error, context, kwargs)


# Convenience functions for common error scenarios
def raise_authentication_error(message: str = "Authentication failed", **kwargs):
    """Raise authentication error."""
    raise AuthenticationError(message, **kwargs)


def raise_authorization_error(message: str = "Access denied", **kwargs):
    """Raise authorization error."""
    raise AuthorizationError(message, **kwargs)


def raise_validation_error(message: str = "Validation failed", **kwargs):
    """Raise validation error."""
    raise ValidationError(message, **kwargs)


def raise_configuration_error(message: str = "Configuration error", **kwargs):
    """Raise configuration error."""
    raise ConfigurationError(message, **kwargs)


def raise_timeout_error(message: str = "Request timeout", **kwargs):
    """Raise timeout error."""
    raise TimeoutError(message, **kwargs)


# Decorators for common error handling patterns
def with_error_handling(
    recovery_strategy: RecoveryStrategy = RecoveryStrategy.NONE,
    retry_config: Optional[RetryConfig] = None,
    fallback_handler: Optional[Callable] = None
):
    """Decorator to add error handling to functions."""
    def decorator(func: F) -> F:
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            if retry_config:
                _global_error_recovery_manager.register_retry_config(
                    func.__name__, retry_config
                )
            
            if fallback_handler:
                _global_error_recovery_manager.register_fallback(
                    func.__name__, fallback_handler
                )
            
            return await _global_error_recovery_manager.execute_with_recovery(
                func.__name__,
                func,
                *args,
                recovery_strategy=recovery_strategy,
                **kwargs
            )
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            # For sync functions, convert to async for consistency
            async def async_func():
                return func(*args, **kwargs)
            
            return asyncio.run(async_wrapper())
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


def with_retry(
    max_attempts: int = 3,
    initial_delay: float = 1.0,
    max_delay: float = 60.0,
    exponential_base: float = 2.0,
    retry_on_exceptions: Tuple[Type[Exception], ...] = (TimeoutError, DependencyFailureError)
):
    """Decorator to add retry logic."""
    retry_config = RetryConfig(
        max_attempts=max_attempts,
        initial_delay=initial_delay,
        max_delay=max_delay,
        exponential_base=exponential_base,
        retry_on_exceptions=retry_on_exceptions
    )
    return with_error_handling(
        recovery_strategy=RecoveryStrategy.RETRY,
        retry_config=retry_config
    )


def with_fallback(fallback_handler: Callable):
    """Decorator to add fallback logic."""
    return with_error_handling(
        recovery_strategy=RecoveryStrategy.FALLBACK,
        fallback_handler=fallback_handler
    )


def with_circuit_breaker():
    """Decorator to add circuit breaker logic."""
    return with_error_handling(
        recovery_strategy=RecoveryStrategy.CIRCUIT_BREAKER
    )