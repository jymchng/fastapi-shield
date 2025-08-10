"""Circuit breaker shield for FastAPI Shield.

This module provides circuit breaker pattern implementation to prevent cascading
failures by temporarily blocking requests when downstream services are failing.
It supports configurable failure thresholds, recovery mechanisms, and comprehensive
monitoring integration.
"""

import asyncio
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from enum import Enum
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Union
import logging
from dataclasses import dataclass, field

from fastapi import HTTPException, Request, status
from pydantic import BaseModel

from fastapi_shield.shield import Shield, shield


logger = logging.getLogger(__name__)


class CircuitState(str, Enum):
    """Circuit breaker states."""
    CLOSED = "closed"      # Normal operation, requests flow through
    OPEN = "open"         # Circuit breaker trips, requests fail fast
    HALF_OPEN = "half_open"  # Testing state, limited requests allowed


class CircuitBreakerConfig(BaseModel):
    """Configuration for circuit breaker."""
    
    # Failure tracking
    failure_threshold: int = 5  # Number of failures before opening
    success_threshold: int = 2  # Successes needed in half-open to close
    recovery_timeout: float = 60.0  # Seconds before trying half-open
    request_timeout: float = 30.0  # Timeout for individual requests
    
    # Sliding window configuration
    sliding_window_size: int = 100  # Number of recent requests to track
    failure_rate_threshold: float = 0.5  # Failure rate to open circuit (0.0-1.0)
    minimum_requests: int = 10  # Minimum requests before evaluating failure rate
    
    # Half-open state configuration
    half_open_max_requests: int = 5  # Max requests allowed in half-open state
    
    # Exponential backoff
    enable_exponential_backoff: bool = True
    backoff_multiplier: float = 2.0
    max_backoff_time: float = 300.0  # 5 minutes max
    
    # Monitoring and alerting
    enable_monitoring: bool = True
    alert_on_state_change: bool = True
    
    # Custom error handling
    exceptions_to_ignore: List[str] = field(default_factory=list)  # Exception types to not count as failures
    exceptions_to_count: List[str] = field(default_factory=list)   # Only these exceptions count as failures
    
    model_config = {"arbitrary_types_allowed": True}


@dataclass
class CircuitMetrics:
    """Circuit breaker metrics and statistics."""
    
    # Current state
    state: CircuitState = CircuitState.CLOSED
    last_state_change: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Request tracking
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    rejected_requests: int = 0  # Requests rejected due to open circuit
    
    # Timing
    last_failure_time: Optional[datetime] = None
    last_success_time: Optional[datetime] = None
    next_attempt_time: Optional[datetime] = None
    
    # Performance
    average_response_time: float = 0.0
    slowest_response_time: float = 0.0
    fastest_response_time: float = float('inf')
    
    # Half-open state tracking
    half_open_requests: int = 0
    half_open_successes: int = 0
    half_open_failures: int = 0
    
    # Sliding window for failure rate calculation
    recent_requests: List[bool] = field(default_factory=list)  # True for success, False for failure
    
    @property
    def failure_rate(self) -> float:
        """Calculate current failure rate."""
        if not self.recent_requests:
            return 0.0
        failures = sum(1 for success in self.recent_requests if not success)
        return failures / len(self.recent_requests)
    
    @property
    def success_rate(self) -> float:
        """Calculate current success rate."""
        return 1.0 - self.failure_rate
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary for monitoring."""
        return {
            "state": self.state.value,
            "last_state_change": self.last_state_change.isoformat(),
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "rejected_requests": self.rejected_requests,
            "failure_rate": self.failure_rate,
            "success_rate": self.success_rate,
            "average_response_time": self.average_response_time,
            "slowest_response_time": self.slowest_response_time,
            "fastest_response_time": self.fastest_response_time if self.fastest_response_time != float('inf') else 0,
            "half_open_requests": self.half_open_requests,
            "half_open_successes": self.half_open_successes,
            "half_open_failures": self.half_open_failures,
            "last_failure_time": self.last_failure_time.isoformat() if self.last_failure_time else None,
            "last_success_time": self.last_success_time.isoformat() if self.last_success_time else None,
            "next_attempt_time": self.next_attempt_time.isoformat() if self.next_attempt_time else None,
        }


class HealthChecker(ABC):
    """Abstract base class for health checking."""
    
    @abstractmethod
    async def check_health(self) -> bool:
        """Check if the service is healthy."""
        pass


class HTTPHealthChecker(HealthChecker):
    """HTTP-based health checker."""
    
    def __init__(self, health_url: str, timeout: float = 5.0, expected_status: int = 200):
        self.health_url = health_url
        self.timeout = timeout
        self.expected_status = expected_status
    
    async def check_health(self) -> bool:
        """Check health via HTTP endpoint."""
        try:
            import httpx
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(self.health_url)
                return response.status_code == self.expected_status
        except Exception as e:
            logger.warning(f"Health check failed: {e}")
            return False


class CallbackHealthChecker(HealthChecker):
    """Custom callback-based health checker."""
    
    def __init__(self, health_callback: Callable[[], bool]):
        self.health_callback = health_callback
    
    async def check_health(self) -> bool:
        """Check health via custom callback."""
        try:
            if asyncio.iscoroutinefunction(self.health_callback):
                return await self.health_callback()
            else:
                return self.health_callback()
        except Exception as e:
            logger.warning(f"Health check callback failed: {e}")
            return False


class CircuitBreakerMonitor(ABC):
    """Abstract base class for circuit breaker monitoring."""
    
    @abstractmethod
    async def on_state_change(
        self, 
        old_state: CircuitState, 
        new_state: CircuitState, 
        metrics: CircuitMetrics,
        circuit_name: str
    ) -> None:
        """Called when circuit breaker state changes."""
        pass
    
    @abstractmethod
    async def on_metrics_update(self, metrics: CircuitMetrics, circuit_name: str) -> None:
        """Called when metrics are updated."""
        pass


class LoggingMonitor(CircuitBreakerMonitor):
    """Logging-based circuit breaker monitor."""
    
    def __init__(self, logger_name: str = __name__):
        self.logger = logging.getLogger(logger_name)
    
    async def on_state_change(
        self, 
        old_state: CircuitState, 
        new_state: CircuitState, 
        metrics: CircuitMetrics,
        circuit_name: str
    ) -> None:
        """Log state changes."""
        self.logger.warning(
            f"Circuit breaker '{circuit_name}' state changed: {old_state.value} -> {new_state.value}. "
            f"Failure rate: {metrics.failure_rate:.2%}, Total requests: {metrics.total_requests}"
        )
    
    async def on_metrics_update(self, metrics: CircuitMetrics, circuit_name: str) -> None:
        """Log metrics updates (debug level)."""
        self.logger.debug(
            f"Circuit breaker '{circuit_name}' metrics: "
            f"State: {metrics.state.value}, "
            f"Failure rate: {metrics.failure_rate:.2%}, "
            f"Total requests: {metrics.total_requests}"
        )


class MetricsCollectorMonitor(CircuitBreakerMonitor):
    """Monitor that collects metrics for external systems."""
    
    def __init__(self):
        self.metrics_data: Dict[str, Dict[str, Any]] = {}
        self.state_changes: List[Dict[str, Any]] = []
    
    async def on_state_change(
        self, 
        old_state: CircuitState, 
        new_state: CircuitState, 
        metrics: CircuitMetrics,
        circuit_name: str
    ) -> None:
        """Collect state change events."""
        self.state_changes.append({
            "circuit_name": circuit_name,
            "old_state": old_state.value,
            "new_state": new_state.value,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "failure_rate": metrics.failure_rate,
            "total_requests": metrics.total_requests,
        })
        
        # Keep only last 100 state changes
        if len(self.state_changes) > 100:
            self.state_changes = self.state_changes[-100:]
    
    async def on_metrics_update(self, metrics: CircuitMetrics, circuit_name: str) -> None:
        """Store latest metrics."""
        self.metrics_data[circuit_name] = metrics.to_dict()
    
    def get_metrics(self, circuit_name: str) -> Optional[Dict[str, Any]]:
        """Get metrics for a specific circuit."""
        return self.metrics_data.get(circuit_name)
    
    def get_all_metrics(self) -> Dict[str, Dict[str, Any]]:
        """Get all circuit metrics."""
        return self.metrics_data.copy()
    
    def get_state_changes(self, circuit_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get state change history."""
        if circuit_name:
            return [sc for sc in self.state_changes if sc["circuit_name"] == circuit_name]
        return self.state_changes.copy()


class CircuitBreakerShield:
    """Circuit breaker implementation for FastAPI shields."""
    
    def __init__(
        self,
        name: str,
        config: CircuitBreakerConfig,
        health_checker: Optional[HealthChecker] = None,
        monitors: Optional[List[CircuitBreakerMonitor]] = None,
    ):
        """Initialize circuit breaker shield.
        
        Args:
            name: Circuit breaker name for identification
            config: Circuit breaker configuration
            health_checker: Optional health checker for recovery
            monitors: Optional monitors for state changes and metrics
        """
        self.name = name
        self.config = config
        self.health_checker = health_checker
        self.monitors = monitors or []
        
        self.metrics = CircuitMetrics()
        self._lock = asyncio.Lock()
        self._failure_count = 0
        self._last_failure_time: Optional[float] = None
        
        # Add default logging monitor if monitoring is enabled
        if config.enable_monitoring and not any(isinstance(m, LoggingMonitor) for m in self.monitors):
            self.monitors.append(LoggingMonitor())
    
    async def _notify_monitors_state_change(self, old_state: CircuitState, new_state: CircuitState) -> None:
        """Notify all monitors of state change."""
        for monitor in self.monitors:
            try:
                await monitor.on_state_change(old_state, new_state, self.metrics, self.name)
            except Exception as e:
                logger.error(f"Monitor notification failed: {e}")
    
    async def _notify_monitors_metrics_update(self) -> None:
        """Notify all monitors of metrics update."""
        for monitor in self.monitors:
            try:
                await monitor.on_metrics_update(self.metrics, self.name)
            except Exception as e:
                logger.error(f"Monitor metrics update failed: {e}")
    
    async def _change_state(self, new_state: CircuitState) -> None:
        """Change circuit state and notify monitors."""
        old_state = self.metrics.state
        if old_state != new_state:
            self.metrics.state = new_state
            self.metrics.last_state_change = datetime.now(timezone.utc)
            
            if self.config.alert_on_state_change:
                await self._notify_monitors_state_change(old_state, new_state)
    
    def _should_ignore_exception(self, exception: Exception) -> bool:
        """Check if exception should be ignored for failure counting."""
        exception_name = exception.__class__.__name__
        
        # If specific exceptions to count are configured, only count those
        if self.config.exceptions_to_count:
            return exception_name not in self.config.exceptions_to_count
        
        # If exceptions to ignore are configured, ignore those
        if self.config.exceptions_to_ignore:
            return exception_name in self.config.exceptions_to_ignore
        
        return False
    
    def _calculate_backoff_time(self) -> float:
        """Calculate exponential backoff time."""
        if not self.config.enable_exponential_backoff:
            return self.config.recovery_timeout
        
        base_time = self.config.recovery_timeout
        backoff_time = base_time * (self.config.backoff_multiplier ** self._failure_count)
        return min(backoff_time, self.config.max_backoff_time)
    
    def _update_sliding_window(self, success: bool) -> None:
        """Update sliding window for failure rate calculation."""
        self.metrics.recent_requests.append(success)
        
        # Maintain sliding window size
        if len(self.metrics.recent_requests) > self.config.sliding_window_size:
            self.metrics.recent_requests.pop(0)
    
    def _should_trip_circuit(self) -> bool:
        """Check if circuit should be tripped based on failure rate."""
        # Need minimum requests before evaluating
        if len(self.metrics.recent_requests) < self.config.minimum_requests:
            return False
        
        # Check failure rate threshold
        return self.metrics.failure_rate >= self.config.failure_rate_threshold
    
    async def _can_attempt_request(self) -> bool:
        """Check if request can be attempted based on current state."""
        current_time = time.time()
        
        if self.metrics.state == CircuitState.CLOSED:
            return True
        
        elif self.metrics.state == CircuitState.OPEN:
            # Check if recovery timeout has passed
            if self.metrics.next_attempt_time and current_time >= self.metrics.next_attempt_time.timestamp():
                # Check health if health checker is available
                if self.health_checker:
                    try:
                        is_healthy = await self.health_checker.check_health()
                        if is_healthy:
                            await self._change_state(CircuitState.HALF_OPEN)
                            self.metrics.half_open_requests = 0
                            self.metrics.half_open_successes = 0
                            self.metrics.half_open_failures = 0
                            return True
                        else:
                            # Health check failed, extend timeout
                            backoff_time = self._calculate_backoff_time()
                            self.metrics.next_attempt_time = datetime.fromtimestamp(
                                current_time + backoff_time, tz=timezone.utc
                            )
                            return False
                    except Exception as e:
                        logger.warning(f"Health check failed: {e}")
                        return False
                else:
                    # No health checker, transition to half-open
                    await self._change_state(CircuitState.HALF_OPEN)
                    self.metrics.half_open_requests = 0
                    self.metrics.half_open_successes = 0
                    self.metrics.half_open_failures = 0
                    return True
            return False
        
        elif self.metrics.state == CircuitState.HALF_OPEN:
            # Allow limited requests in half-open state
            return self.metrics.half_open_requests < self.config.half_open_max_requests
        
        return False
    
    async def _record_success(self, response_time: float) -> None:
        """Record successful request."""
        async with self._lock:
            self.metrics.total_requests += 1
            self.metrics.successful_requests += 1
            self.metrics.last_success_time = datetime.now(timezone.utc)
            
            # Update response time metrics
            if response_time < self.metrics.fastest_response_time:
                self.metrics.fastest_response_time = response_time
            if response_time > self.metrics.slowest_response_time:
                self.metrics.slowest_response_time = response_time
            
            # Update average response time
            total_responses = self.metrics.successful_requests + self.metrics.failed_requests
            self.metrics.average_response_time = (
                (self.metrics.average_response_time * (total_responses - 1) + response_time) / total_responses
            )
            
            self._update_sliding_window(True)
            
            if self.metrics.state == CircuitState.HALF_OPEN:
                self.metrics.half_open_successes += 1
                
                # Check if we should close the circuit
                if self.metrics.half_open_successes >= self.config.success_threshold:
                    await self._change_state(CircuitState.CLOSED)
                    self._failure_count = 0
                    self.metrics.next_attempt_time = None
            
            await self._notify_monitors_metrics_update()
    
    async def _record_failure(self, exception: Optional[Exception] = None) -> None:
        """Record failed request."""
        async with self._lock:
            # Check if we should ignore this exception
            if exception and self._should_ignore_exception(exception):
                return
            
            self.metrics.total_requests += 1
            self.metrics.failed_requests += 1
            self.metrics.last_failure_time = datetime.now(timezone.utc)
            self._failure_count += 1
            self._last_failure_time = time.time()
            
            self._update_sliding_window(False)
            
            if self.metrics.state == CircuitState.CLOSED:
                # Check if we should open the circuit
                if self._should_trip_circuit():
                    await self._change_state(CircuitState.OPEN)
                    backoff_time = self._calculate_backoff_time()
                    self.metrics.next_attempt_time = datetime.fromtimestamp(
                        time.time() + backoff_time, tz=timezone.utc
                    )
            
            elif self.metrics.state == CircuitState.HALF_OPEN:
                self.metrics.half_open_failures += 1
                # Any failure in half-open state opens the circuit
                await self._change_state(CircuitState.OPEN)
                backoff_time = self._calculate_backoff_time()
                self.metrics.next_attempt_time = datetime.fromtimestamp(
                    time.time() + backoff_time, tz=timezone.utc
                )
            
            await self._notify_monitors_metrics_update()
    
    async def _record_rejection(self) -> None:
        """Record rejected request."""
        async with self._lock:
            self.metrics.rejected_requests += 1
            await self._notify_monitors_metrics_update()
    
    async def execute_request(self, request_func: Callable[[], Any]) -> Any:
        """Execute a request through the circuit breaker."""
        # Check if request can be attempted
        can_attempt = await self._can_attempt_request()
        
        if not can_attempt:
            await self._record_rejection()
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Circuit breaker '{self.name}' is {self.metrics.state.value}. Service temporarily unavailable."
            )
        
        # Track half-open requests
        if self.metrics.state == CircuitState.HALF_OPEN:
            async with self._lock:
                self.metrics.half_open_requests += 1
        
        # Execute the request with timeout
        start_time = time.time()
        try:
            if asyncio.iscoroutinefunction(request_func):
                result = await asyncio.wait_for(
                    request_func(), 
                    timeout=self.config.request_timeout
                )
            else:
                result = request_func()
            
            response_time = time.time() - start_time
            await self._record_success(response_time)
            return result
        
        except asyncio.TimeoutError:
            await self._record_failure(TimeoutError(f"Request timeout after {self.config.request_timeout}s"))
            raise HTTPException(
                status_code=status.HTTP_408_REQUEST_TIMEOUT,
                detail=f"Request timeout after {self.config.request_timeout}s"
            )
        
        except Exception as e:
            await self._record_failure(e)
            raise
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get current circuit breaker metrics."""
        return self.metrics.to_dict()
    
    async def reset(self) -> None:
        """Reset circuit breaker to closed state."""
        async with self._lock:
            old_state = self.metrics.state
            self.metrics = CircuitMetrics()
            self._failure_count = 0
            self._last_failure_time = None
            await self._change_state(CircuitState.CLOSED)
            
            logger.info(f"Circuit breaker '{self.name}' has been manually reset")
    
    async def force_open(self) -> None:
        """Force circuit breaker to open state."""
        async with self._lock:
            await self._change_state(CircuitState.OPEN)
            self.metrics.next_attempt_time = datetime.fromtimestamp(
                time.time() + self.config.recovery_timeout, tz=timezone.utc
            )
            
            logger.info(f"Circuit breaker '{self.name}' has been forced open")
    
    def create_shield(self, endpoint_func: Callable) -> Shield:
        """Create a shield that uses this circuit breaker.
        
        Args:
            endpoint_func: The endpoint function to protect with circuit breaker
            
        Returns:
            Shield instance with circuit breaker protection
        """
        
        async def circuit_breaker_shield(request: Request) -> Dict[str, Any]:
            """Circuit breaker shield function."""
            
            async def execute_endpoint():
                """Execute the original endpoint function."""
                # For endpoint functions, we don't pass the request as they have their own parameters
                if asyncio.iscoroutinefunction(endpoint_func):
                    return await endpoint_func()
                else:
                    return endpoint_func()
            
            # Execute through circuit breaker
            result = await self.execute_request(execute_endpoint)
            
            return {
                "circuit_breaker_name": self.name,
                "circuit_state": self.metrics.state.value,
                "circuit_metrics": self.get_metrics(),
                "shield_result": result,
            }
        
        return shield(
            circuit_breaker_shield,
            name=f"CircuitBreaker_{self.name}",
            auto_error=True,
        )


# Global registry for circuit breakers
_circuit_breaker_registry: Dict[str, CircuitBreakerShield] = {}


def get_circuit_breaker(name: str) -> Optional[CircuitBreakerShield]:
    """Get circuit breaker by name from global registry."""
    return _circuit_breaker_registry.get(name)


def register_circuit_breaker(circuit_breaker: CircuitBreakerShield) -> None:
    """Register circuit breaker in global registry."""
    _circuit_breaker_registry[circuit_breaker.name] = circuit_breaker


def get_all_circuit_breakers() -> Dict[str, CircuitBreakerShield]:
    """Get all registered circuit breakers."""
    return _circuit_breaker_registry.copy()


def circuit_breaker_shield(
    name: str,
    failure_threshold: int = 5,
    success_threshold: int = 2,
    recovery_timeout: float = 60.0,
    request_timeout: float = 30.0,
    failure_rate_threshold: float = 0.5,
    sliding_window_size: int = 100,
    minimum_requests: int = 10,
    enable_exponential_backoff: bool = True,
    health_checker: Optional[HealthChecker] = None,
    monitors: Optional[List[CircuitBreakerMonitor]] = None,
) -> Callable:
    """Create a circuit breaker shield decorator.
    
    Args:
        name: Circuit breaker name
        failure_threshold: Number of failures before opening
        success_threshold: Successes needed in half-open to close
        recovery_timeout: Seconds before trying half-open
        request_timeout: Timeout for individual requests
        failure_rate_threshold: Failure rate to open circuit (0.0-1.0)
        sliding_window_size: Number of recent requests to track
        minimum_requests: Minimum requests before evaluating failure rate
        enable_exponential_backoff: Enable exponential backoff
        health_checker: Optional health checker
        monitors: Optional monitors for state changes
        
    Returns:
        Circuit breaker shield decorator
        
    Examples:
        ```python
        # Basic circuit breaker
        @app.get("/api/data")
        @circuit_breaker_shield(name="api_data", failure_threshold=3)
        def get_data():
            return {"data": "value"}
        
        # Circuit breaker with health check
        health_checker = HTTPHealthChecker("http://service/health")
        
        @app.get("/api/service")
        @circuit_breaker_shield(
            name="external_service",
            failure_threshold=5,
            recovery_timeout=30.0,
            health_checker=health_checker
        )
        def call_external_service():
            return {"result": "success"}
        
        # Circuit breaker with monitoring
        monitor = MetricsCollectorMonitor()
        
        @app.post("/api/process")
        @circuit_breaker_shield(
            name="data_processor",
            failure_rate_threshold=0.3,
            monitors=[monitor]
        )
        def process_data(data: dict):
            return {"processed": True}
        ```
    """
    
    # Create circuit breaker configuration
    config = CircuitBreakerConfig(
        failure_threshold=failure_threshold,
        success_threshold=success_threshold,
        recovery_timeout=recovery_timeout,
        request_timeout=request_timeout,
        failure_rate_threshold=failure_rate_threshold,
        sliding_window_size=sliding_window_size,
        minimum_requests=minimum_requests,
        enable_exponential_backoff=enable_exponential_backoff,
    )
    
    # Create circuit breaker instance
    circuit_breaker = CircuitBreakerShield(
        name=name,
        config=config,
        health_checker=health_checker,
        monitors=monitors or [],
    )
    
    # Register circuit breaker
    register_circuit_breaker(circuit_breaker)
    
    def decorator(func: Callable) -> Callable:
        if asyncio.iscoroutinefunction(func):
            @wraps(func)
            async def async_wrapper(*args, **kwargs):
                async def execute_func():
                    return await func(*args, **kwargs)
                
                return await circuit_breaker.execute_request(execute_func)
            
            return async_wrapper
        else:
            @wraps(func)
            async def sync_wrapper(*args, **kwargs):
                def execute_func():
                    return func(*args, **kwargs)
                
                return await circuit_breaker.execute_request(execute_func)
            
            return sync_wrapper
    
    return decorator


def database_circuit_breaker_shield(
    name: str = "database",
    failure_threshold: int = 3,
    recovery_timeout: float = 30.0,
    request_timeout: float = 10.0,
) -> Callable:
    """Create a circuit breaker shield optimized for database operations.
    
    Args:
        name: Circuit breaker name
        failure_threshold: Number of failures before opening
        recovery_timeout: Seconds before trying half-open
        request_timeout: Timeout for individual requests
        
    Returns:
        Database-optimized circuit breaker shield
        
    Examples:
        ```python
        @app.get("/users/{user_id}")
        @database_circuit_breaker_shield(name="user_db")
        def get_user(user_id: int):
            return db.get_user(user_id)
        ```
    """
    return circuit_breaker_shield(
        name=name,
        failure_threshold=failure_threshold,
        success_threshold=1,  # Single success closes circuit for DB
        recovery_timeout=recovery_timeout,
        request_timeout=request_timeout,
        failure_rate_threshold=0.6,  # Higher threshold for DB operations
        sliding_window_size=50,
        minimum_requests=5,
        enable_exponential_backoff=True,
    )


def external_service_circuit_breaker_shield(
    name: str = "external_service",
    health_url: Optional[str] = None,
    failure_threshold: int = 5,
    recovery_timeout: float = 60.0,
    request_timeout: float = 30.0,
) -> Callable:
    """Create a circuit breaker shield optimized for external service calls.
    
    Args:
        name: Circuit breaker name
        health_url: Health check URL for the external service
        failure_threshold: Number of failures before opening
        recovery_timeout: Seconds before trying half-open
        request_timeout: Timeout for individual requests
        
    Returns:
        External service-optimized circuit breaker shield
        
    Examples:
        ```python
        @app.get("/external-data")
        @external_service_circuit_breaker_shield(
            name="payment_service",
            health_url="https://api.payment.com/health"
        )
        def get_payment_data():
            return call_payment_api()
        ```
    """
    health_checker = None
    if health_url:
        health_checker = HTTPHealthChecker(health_url)
    
    return circuit_breaker_shield(
        name=name,
        failure_threshold=failure_threshold,
        success_threshold=2,
        recovery_timeout=recovery_timeout,
        request_timeout=request_timeout,
        failure_rate_threshold=0.5,
        sliding_window_size=100,
        minimum_requests=10,
        enable_exponential_backoff=True,
        health_checker=health_checker,
    )


def high_availability_circuit_breaker_shield(
    name: str = "high_availability",
    failure_threshold: int = 10,
    recovery_timeout: float = 120.0,
) -> Callable:
    """Create a circuit breaker shield optimized for high availability scenarios.
    
    Args:
        name: Circuit breaker name
        failure_threshold: Number of failures before opening
        recovery_timeout: Seconds before trying half-open
        
    Returns:
        High availability-optimized circuit breaker shield
        
    Examples:
        ```python
        @app.get("/critical-service")
        @high_availability_circuit_breaker_shield(name="critical_ops")
        def critical_operation():
            return perform_critical_task()
        ```
    """
    return circuit_breaker_shield(
        name=name,
        failure_threshold=failure_threshold,
        success_threshold=3,  # Need more successes to be confident
        recovery_timeout=recovery_timeout,
        request_timeout=60.0,  # Longer timeout for critical operations
        failure_rate_threshold=0.3,  # Lower threshold for critical services
        sliding_window_size=200,  # Larger window for better statistics
        minimum_requests=20,
        enable_exponential_backoff=True,
    )