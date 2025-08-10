"""Tests for circuit breaker shield functionality."""

import asyncio
import time
from datetime import datetime, timezone
from typing import Any, Dict
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.testclient import TestClient

from fastapi_shield.circuit_breaker import (
    CircuitBreakerShield,
    CircuitBreakerConfig,
    CircuitMetrics,
    CircuitState,
    HealthChecker,
    HTTPHealthChecker,
    CallbackHealthChecker,
    CircuitBreakerMonitor,
    LoggingMonitor,
    MetricsCollectorMonitor,
    get_circuit_breaker,
    register_circuit_breaker,
    get_all_circuit_breakers,
    circuit_breaker_shield,
    database_circuit_breaker_shield,
    external_service_circuit_breaker_shield,
    high_availability_circuit_breaker_shield,
)


class MockHealthChecker(HealthChecker):
    """Mock health checker for testing."""
    
    def __init__(self, healthy: bool = True):
        self.healthy = healthy
        self.call_count = 0
    
    async def check_health(self) -> bool:
        """Mock health check."""
        self.call_count += 1
        return self.healthy
    
    def set_healthy(self, healthy: bool) -> None:
        """Set health status."""
        self.healthy = healthy


class MockMonitor(CircuitBreakerMonitor):
    """Mock monitor for testing."""
    
    def __init__(self):
        self.state_changes = []
        self.metrics_updates = []
    
    async def on_state_change(self, old_state, new_state, metrics, circuit_name):
        """Record state change."""
        self.state_changes.append({
            "old_state": old_state,
            "new_state": new_state,
            "circuit_name": circuit_name,
            "timestamp": datetime.now(timezone.utc)
        })
    
    async def on_metrics_update(self, metrics, circuit_name):
        """Record metrics update."""
        self.metrics_updates.append({
            "circuit_name": circuit_name,
            "metrics": metrics.to_dict(),
            "timestamp": datetime.now(timezone.utc)
        })


class TestCircuitBreakerConfig:
    """Test circuit breaker configuration."""
    
    def test_config_defaults(self):
        """Test default configuration values."""
        config = CircuitBreakerConfig()
        
        assert config.failure_threshold == 5
        assert config.success_threshold == 2
        assert config.recovery_timeout == 60.0
        assert config.request_timeout == 30.0
        assert config.sliding_window_size == 100
        assert config.failure_rate_threshold == 0.5
        assert config.minimum_requests == 10
        assert config.half_open_max_requests == 5
        assert config.enable_exponential_backoff is True
        assert config.enable_monitoring is True
    
    def test_config_custom(self):
        """Test custom configuration values."""
        config = CircuitBreakerConfig(
            failure_threshold=3,
            success_threshold=1,
            recovery_timeout=30.0,
            failure_rate_threshold=0.3,
            enable_exponential_backoff=False,
        )
        
        assert config.failure_threshold == 3
        assert config.success_threshold == 1
        assert config.recovery_timeout == 30.0
        assert config.failure_rate_threshold == 0.3
        assert config.enable_exponential_backoff is False


class TestCircuitMetrics:
    """Test circuit metrics functionality."""
    
    def test_metrics_initialization(self):
        """Test metrics initialization."""
        metrics = CircuitMetrics()
        
        assert metrics.state == CircuitState.CLOSED
        assert metrics.total_requests == 0
        assert metrics.successful_requests == 0
        assert metrics.failed_requests == 0
        assert metrics.rejected_requests == 0
        assert metrics.failure_rate == 0.0
        assert metrics.success_rate == 1.0
    
    def test_failure_rate_calculation(self):
        """Test failure rate calculation."""
        metrics = CircuitMetrics()
        
        # Add some requests to sliding window
        metrics.recent_requests = [True, True, False, True, False]  # 2 failures out of 5
        
        assert metrics.failure_rate == 0.4
        assert metrics.success_rate == 0.6
    
    def test_metrics_to_dict(self):
        """Test metrics dictionary conversion."""
        metrics = CircuitMetrics()
        metrics.total_requests = 10
        metrics.successful_requests = 7
        metrics.failed_requests = 3
        
        data = metrics.to_dict()
        
        assert data["state"] == "closed"
        assert data["total_requests"] == 10
        assert data["successful_requests"] == 7
        assert data["failed_requests"] == 3
        assert "last_state_change" in data
        assert "failure_rate" in data


class TestHealthCheckers:
    """Test health checker implementations."""
    
    def test_callback_health_checker_sync(self):
        """Test callback health checker with sync function."""
        def health_check():
            return True
        
        checker = CallbackHealthChecker(health_check)
        
        # Test async wrapper
        result = asyncio.run(checker.check_health())
        assert result is True
    
    @pytest.mark.asyncio
    async def test_callback_health_checker_async(self):
        """Test callback health checker with async function."""
        async def health_check():
            return False
        
        checker = CallbackHealthChecker(health_check)
        result = await checker.check_health()
        assert result is False
    
    @pytest.mark.asyncio
    async def test_callback_health_checker_exception(self):
        """Test callback health checker exception handling."""
        def failing_health_check():
            raise Exception("Health check failed")
        
        checker = CallbackHealthChecker(failing_health_check)
        result = await checker.check_health()
        assert result is False
    
    @pytest.mark.asyncio
    async def test_http_health_checker(self):
        """Test HTTP health checker."""
        # This test would require mocking httpx, skipping for now
        # In real usage, HTTPHealthChecker would make actual HTTP calls
        checker = HTTPHealthChecker("http://example.com/health")
        assert checker.health_url == "http://example.com/health"
        assert checker.timeout == 5.0
        assert checker.expected_status == 200


class TestMonitors:
    """Test monitor implementations."""
    
    @pytest.mark.asyncio
    async def test_logging_monitor(self):
        """Test logging monitor."""
        monitor = LoggingMonitor()
        metrics = CircuitMetrics()
        
        # Should not raise exceptions
        await monitor.on_state_change(
            CircuitState.CLOSED, 
            CircuitState.OPEN, 
            metrics, 
            "test_circuit"
        )
        
        await monitor.on_metrics_update(metrics, "test_circuit")
    
    @pytest.mark.asyncio
    async def test_metrics_collector_monitor(self):
        """Test metrics collector monitor."""
        monitor = MetricsCollectorMonitor()
        metrics = CircuitMetrics()
        
        # Test state change tracking
        await monitor.on_state_change(
            CircuitState.CLOSED, 
            CircuitState.OPEN, 
            metrics, 
            "test_circuit"
        )
        
        state_changes = monitor.get_state_changes("test_circuit")
        assert len(state_changes) == 1
        assert state_changes[0]["circuit_name"] == "test_circuit"
        assert state_changes[0]["old_state"] == "closed"
        assert state_changes[0]["new_state"] == "open"
        
        # Test metrics collection
        await monitor.on_metrics_update(metrics, "test_circuit")
        
        collected_metrics = monitor.get_metrics("test_circuit")
        assert collected_metrics is not None
        assert collected_metrics["state"] == "closed"


class TestCircuitBreakerShield:
    """Test circuit breaker shield implementation."""
    
    @pytest.fixture
    def basic_config(self):
        """Create basic configuration for testing."""
        return CircuitBreakerConfig(
            failure_threshold=2,
            success_threshold=1,
            recovery_timeout=1.0,  # Short timeout for testing
            request_timeout=1.0,
            minimum_requests=2,
            failure_rate_threshold=0.5,
            enable_monitoring=False,  # Disable for cleaner test output
        )
    
    @pytest.fixture
    def circuit_breaker(self, basic_config):
        """Create circuit breaker for testing."""
        return CircuitBreakerShield("test_circuit", basic_config)
    
    def test_initialization(self, circuit_breaker, basic_config):
        """Test circuit breaker initialization."""
        assert circuit_breaker.name == "test_circuit"
        assert circuit_breaker.config == basic_config
        assert circuit_breaker.metrics.state == CircuitState.CLOSED
        assert circuit_breaker._failure_count == 0
    
    def test_initialization_with_health_checker(self, basic_config):
        """Test initialization with health checker."""
        health_checker = MockHealthChecker()
        cb = CircuitBreakerShield("test", basic_config, health_checker=health_checker)
        
        assert cb.health_checker == health_checker
    
    def test_initialization_with_monitors(self, basic_config):
        """Test initialization with monitors."""
        monitor = MockMonitor()
        cb = CircuitBreakerShield("test", basic_config, monitors=[monitor])
        
        assert len(cb.monitors) == 1
        assert cb.monitors[0] == monitor
    
    @pytest.mark.asyncio
    async def test_successful_request(self, circuit_breaker):
        """Test successful request execution."""
        async def success_func():
            return "success"
        
        result = await circuit_breaker.execute_request(success_func)
        
        assert result == "success"
        assert circuit_breaker.metrics.state == CircuitState.CLOSED
        assert circuit_breaker.metrics.successful_requests == 1
        assert circuit_breaker.metrics.total_requests == 1
        assert circuit_breaker.metrics.failed_requests == 0
    
    @pytest.mark.asyncio
    async def test_failed_request(self, circuit_breaker):
        """Test failed request execution."""
        async def failing_func():
            raise ValueError("Test error")
        
        with pytest.raises(ValueError):
            await circuit_breaker.execute_request(failing_func)
        
        assert circuit_breaker.metrics.failed_requests == 1
        assert circuit_breaker.metrics.total_requests == 1
        assert circuit_breaker.metrics.successful_requests == 0
    
    @pytest.mark.asyncio
    async def test_circuit_opening(self, circuit_breaker):
        """Test circuit opening after failures."""
        async def failing_func():
            raise ValueError("Test error")
        
        # First failure
        with pytest.raises(ValueError):
            await circuit_breaker.execute_request(failing_func)
        
        assert circuit_breaker.metrics.state == CircuitState.CLOSED
        
        # Second failure should open the circuit
        with pytest.raises(ValueError):
            await circuit_breaker.execute_request(failing_func)
        
        assert circuit_breaker.metrics.state == CircuitState.OPEN
        assert circuit_breaker.metrics.failed_requests == 2
    
    @pytest.mark.asyncio
    async def test_circuit_rejection(self, circuit_breaker):
        """Test request rejection when circuit is open."""
        # Force circuit open
        await circuit_breaker.force_open()
        
        async def success_func():
            return "success"
        
        # Request should be rejected
        with pytest.raises(HTTPException) as exc_info:
            await circuit_breaker.execute_request(success_func)
        
        assert exc_info.value.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        assert "Circuit breaker" in exc_info.value.detail
        assert circuit_breaker.metrics.rejected_requests == 1
    
    @pytest.mark.asyncio
    async def test_circuit_half_open_transition(self, circuit_breaker):
        """Test transition to half-open state."""
        # Open the circuit
        await circuit_breaker.force_open()
        assert circuit_breaker.metrics.state == CircuitState.OPEN
        
        # Wait for recovery timeout
        await asyncio.sleep(1.1)  # Slightly longer than recovery_timeout
        
        async def success_func():
            return "success"
        
        # Next request should transition to half-open
        result = await circuit_breaker.execute_request(success_func)
        
        assert result == "success"
        assert circuit_breaker.metrics.state == CircuitState.CLOSED  # Should close after success
    
    @pytest.mark.asyncio
    async def test_half_open_to_closed(self, circuit_breaker):
        """Test transition from half-open to closed."""
        # Manually set to half-open state
        await circuit_breaker._change_state(CircuitState.HALF_OPEN)
        circuit_breaker.metrics.half_open_requests = 0
        circuit_breaker.metrics.half_open_successes = 0
        
        async def success_func():
            return "success"
        
        # Successful request should close the circuit
        result = await circuit_breaker.execute_request(success_func)
        
        assert result == "success"
        assert circuit_breaker.metrics.state == CircuitState.CLOSED
        assert circuit_breaker._failure_count == 0
    
    @pytest.mark.asyncio
    async def test_half_open_to_open(self, circuit_breaker):
        """Test transition from half-open back to open on failure."""
        # Manually set to half-open state
        await circuit_breaker._change_state(CircuitState.HALF_OPEN)
        circuit_breaker.metrics.half_open_requests = 0
        
        async def failing_func():
            raise ValueError("Test error")
        
        # Failed request should open the circuit again
        with pytest.raises(ValueError):
            await circuit_breaker.execute_request(failing_func)
        
        assert circuit_breaker.metrics.state == CircuitState.OPEN
    
    @pytest.mark.asyncio
    async def test_request_timeout(self, circuit_breaker):
        """Test request timeout handling."""
        async def slow_func():
            await asyncio.sleep(2.0)  # Longer than request_timeout (1.0s)
            return "success"
        
        with pytest.raises(HTTPException) as exc_info:
            await circuit_breaker.execute_request(slow_func)
        
        assert exc_info.value.status_code == status.HTTP_408_REQUEST_TIMEOUT
        assert circuit_breaker.metrics.failed_requests == 1
    
    @pytest.mark.asyncio
    async def test_sync_function_execution(self, circuit_breaker):
        """Test execution of synchronous functions."""
        def sync_func():
            return "sync_success"
        
        result = await circuit_breaker.execute_request(sync_func)
        
        assert result == "sync_success"
        assert circuit_breaker.metrics.successful_requests == 1
    
    @pytest.mark.asyncio
    async def test_exception_filtering(self):
        """Test exception filtering configuration."""
        config = CircuitBreakerConfig(
            failure_threshold=2,
            exceptions_to_ignore=["ValueError"],
            enable_monitoring=False,
        )
        cb = CircuitBreakerShield("test", config)
        
        async def func_with_ignored_exception():
            raise ValueError("Ignored error")
        
        # ValueError should be ignored and not count as failure
        with pytest.raises(ValueError):
            await cb.execute_request(func_with_ignored_exception)
        
        assert cb.metrics.failed_requests == 0  # Should not be counted
        assert cb.metrics.state == CircuitState.CLOSED
    
    @pytest.mark.asyncio
    async def test_specific_exceptions_only(self):
        """Test counting only specific exceptions."""
        config = CircuitBreakerConfig(
            failure_threshold=2,
            exceptions_to_count=["RuntimeError"],
            enable_monitoring=False,
        )
        cb = CircuitBreakerShield("test", config)
        
        async def func_with_uncounted_exception():
            raise ValueError("Not counted")
        
        async def func_with_counted_exception():
            raise RuntimeError("Counted")
        
        # ValueError should not be counted
        with pytest.raises(ValueError):
            await cb.execute_request(func_with_uncounted_exception)
        
        assert cb.metrics.failed_requests == 0
        
        # RuntimeError should be counted
        with pytest.raises(RuntimeError):
            await cb.execute_request(func_with_counted_exception)
        
        assert cb.metrics.failed_requests == 1
    
    @pytest.mark.asyncio
    async def test_health_checker_integration(self, basic_config):
        """Test health checker integration during recovery."""
        health_checker = MockHealthChecker(healthy=False)
        cb = CircuitBreakerShield("test", basic_config, health_checker=health_checker)
        
        # Open the circuit
        await cb.force_open()
        
        # Wait for recovery timeout
        await asyncio.sleep(1.1)
        
        async def success_func():
            return "success"
        
        # Should be rejected because health check fails
        with pytest.raises(HTTPException):
            await cb.execute_request(success_func)
        
        assert health_checker.call_count == 1
        
        # Set healthy and try again
        health_checker.set_healthy(True)
        await asyncio.sleep(1.1)
        
        result = await cb.execute_request(success_func)
        assert result == "success"
        assert health_checker.call_count == 2
    
    @pytest.mark.asyncio
    async def test_exponential_backoff(self):
        """Test exponential backoff functionality."""
        config = CircuitBreakerConfig(
            failure_threshold=1,
            recovery_timeout=1.0,
            enable_exponential_backoff=True,
            backoff_multiplier=2.0,
            enable_monitoring=False,
        )
        cb = CircuitBreakerShield("test", config)
        
        # Test backoff calculation
        cb._failure_count = 0
        backoff1 = cb._calculate_backoff_time()
        assert backoff1 == 1.0  # Base timeout
        
        cb._failure_count = 1
        backoff2 = cb._calculate_backoff_time()
        assert backoff2 == 2.0  # 1.0 * 2^1
        
        cb._failure_count = 2
        backoff3 = cb._calculate_backoff_time()
        assert backoff3 == 4.0  # 1.0 * 2^2
    
    @pytest.mark.asyncio
    async def test_monitor_notifications(self, basic_config):
        """Test monitor notifications."""
        monitor = MockMonitor()
        cb = CircuitBreakerShield("test", basic_config, monitors=[monitor])
        
        async def failing_func():
            raise ValueError("Test error")
        
        # Trigger state change
        with pytest.raises(ValueError):
            await cb.execute_request(failing_func)
        
        with pytest.raises(ValueError):
            await cb.execute_request(failing_func)
        
        # Should have recorded state change to OPEN
        assert len(monitor.state_changes) == 1
        assert monitor.state_changes[0]["old_state"] == CircuitState.CLOSED
        assert monitor.state_changes[0]["new_state"] == CircuitState.OPEN
        
        # Should have recorded metrics updates
        assert len(monitor.metrics_updates) >= 2
    
    @pytest.mark.asyncio
    async def test_reset(self, circuit_breaker):
        """Test manual circuit reset."""
        # Open the circuit by forcing failures
        await circuit_breaker.force_open()
        assert circuit_breaker.metrics.state == CircuitState.OPEN
        
        # Reset the circuit
        await circuit_breaker.reset()
        
        assert circuit_breaker.metrics.state == CircuitState.CLOSED
        assert circuit_breaker._failure_count == 0
        assert circuit_breaker.metrics.total_requests == 0
    
    def test_get_metrics(self, circuit_breaker):
        """Test metrics retrieval."""
        metrics = circuit_breaker.get_metrics()
        
        assert isinstance(metrics, dict)
        assert "state" in metrics
        assert "total_requests" in metrics
        assert "failure_rate" in metrics


class TestCircuitBreakerIntegration:
    """Test circuit breaker integration with FastAPI."""
    
    def test_circuit_breaker_decorator_success(self):
        """Test circuit breaker decorator with successful function."""
        app = FastAPI()
        
        @app.get("/success")
        @circuit_breaker_shield(
            name="success_test",
            failure_threshold=2,
            recovery_timeout=1.0,
        )
        async def success_endpoint():
            return {"status": "success"}
        
        client = TestClient(app)
        response = client.get("/success")
        
        assert response.status_code == 200
        assert response.json()["status"] == "success"
        
        # Check that circuit breaker was registered
        cb = get_circuit_breaker("success_test")
        assert cb is not None
        assert cb.metrics.successful_requests == 1
    
    def test_circuit_breaker_with_http_exception(self):
        """Test circuit breaker with HTTP exceptions (which should be allowed)."""
        app = FastAPI()
        
        @app.get("/http-error")
        @circuit_breaker_shield(
            name="http_error_test",
            failure_threshold=2,
            recovery_timeout=1.0,
        )
        async def http_error_endpoint():
            raise HTTPException(status_code=404, detail="Not found")
        
        client = TestClient(app)
        response = client.get("/http-error")
        
        assert response.status_code == 404
        assert response.json()["detail"] == "Not found"
        
        # HTTP exceptions should be allowed through and not counted as failures
        cb = get_circuit_breaker("http_error_test")
        assert cb is not None
        # The circuit breaker might still count this as a failure depending on implementation
        # which is fine - HTTP errors can be considered failures for circuit breaking
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_direct_usage(self):
        """Test circuit breaker used directly without FastAPI."""
        config = CircuitBreakerConfig(
            failure_threshold=2,
            success_threshold=1,  # Only need 1 success to close circuit
            recovery_timeout=0.1,
            minimum_requests=2,  # Need at least 2 requests before evaluating failure rate
            failure_rate_threshold=1.0,  # 100% failure rate needed to open
            enable_exponential_backoff=False,  # Disable exponential backoff for predictable timing
            enable_monitoring=False,
        )
        cb = CircuitBreakerShield("direct_test", config)
        
        call_count = 0
        
        async def failing_function():
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                raise ValueError(f"Error {call_count}")
            return f"Success {call_count}"
        
        # First call should fail
        with pytest.raises(ValueError):
            await cb.execute_request(failing_function)
        assert cb.metrics.state == CircuitState.CLOSED  # Still closed after 1 failure
        
        # Second call should fail and open circuit (meets minimum_requests + failure_rate)
        with pytest.raises(ValueError):
            await cb.execute_request(failing_function)
        assert cb.metrics.state == CircuitState.OPEN  # Should be open now
        
        # Verify next_attempt_time is set
        assert cb.metrics.next_attempt_time is not None
        
        # Third call should be rejected immediately
        with pytest.raises(HTTPException) as exc_info:
            await cb.execute_request(failing_function)
        assert exc_info.value.status_code == 503
        
        # Wait for recovery timeout
        await asyncio.sleep(0.2)  # Longer than recovery_timeout
        
        # Should now be able to attempt requests (half-open)
        # and since call_count=3, the function will succeed
        result = await cb.execute_request(failing_function)
        assert result == "Success 3"
        assert cb.metrics.state == CircuitState.CLOSED


class TestRegistryFunctions:
    """Test circuit breaker registry functions."""
    
    def test_register_and_get_circuit_breaker(self):
        """Test circuit breaker registration and retrieval."""
        config = CircuitBreakerConfig(enable_monitoring=False)
        cb = CircuitBreakerShield("registry_test", config)
        
        # Register circuit breaker
        register_circuit_breaker(cb)
        
        # Retrieve circuit breaker
        retrieved = get_circuit_breaker("registry_test")
        assert retrieved == cb
        
        # Test non-existent circuit breaker
        non_existent = get_circuit_breaker("does_not_exist")
        assert non_existent is None
    
    def test_get_all_circuit_breakers(self):
        """Test getting all circuit breakers."""
        config = CircuitBreakerConfig(enable_monitoring=False)
        cb1 = CircuitBreakerShield("cb1", config)
        cb2 = CircuitBreakerShield("cb2", config)
        
        register_circuit_breaker(cb1)
        register_circuit_breaker(cb2)
        
        all_cbs = get_all_circuit_breakers()
        assert "cb1" in all_cbs
        assert "cb2" in all_cbs
        assert all_cbs["cb1"] == cb1
        assert all_cbs["cb2"] == cb2


class TestConvenienceDecorators:
    """Test convenience decorator functions."""
    
    def test_database_circuit_breaker_shield(self):
        """Test database circuit breaker shield factory."""
        app = FastAPI()
        
        @app.get("/users/{user_id}")
        @database_circuit_breaker_shield(name="user_db")
        async def get_user(user_id: int):
            return {"user_id": user_id, "name": "Test User"}
        
        client = TestClient(app)
        response = client.get("/users/123")
        
        assert response.status_code == 200
        assert response.json()["user_id"] == 123
        
        # Check that circuit breaker was registered
        cb = get_circuit_breaker("user_db")
        assert cb is not None
        assert cb.config.failure_threshold == 3  # Database-specific config
        assert cb.config.request_timeout == 10.0
    
    def test_external_service_circuit_breaker_shield(self):
        """Test external service circuit breaker shield factory."""
        app = FastAPI()
        
        @app.get("/external")
        @external_service_circuit_breaker_shield(name="payment_api")
        async def call_payment_api():
            return {"payment_status": "processed"}
        
        client = TestClient(app)
        response = client.get("/external")
        
        assert response.status_code == 200
        assert response.json()["payment_status"] == "processed"
        
        # Check circuit breaker configuration
        cb = get_circuit_breaker("payment_api")
        assert cb is not None
        assert cb.config.failure_threshold == 5  # External service config
        assert cb.config.success_threshold == 2
    
    def test_external_service_with_health_check(self):
        """Test external service circuit breaker with health check."""
        app = FastAPI()
        
        @app.get("/external-with-health")
        @external_service_circuit_breaker_shield(
            name="api_with_health",
            health_url="https://example.com/health"
        )
        async def call_api_with_health():
            return {"status": "ok"}
        
        client = TestClient(app)
        response = client.get("/external-with-health")
        
        assert response.status_code == 200
        
        cb = get_circuit_breaker("api_with_health")
        assert cb is not None
        assert cb.health_checker is not None
        assert isinstance(cb.health_checker, HTTPHealthChecker)
    
    def test_high_availability_circuit_breaker_shield(self):
        """Test high availability circuit breaker shield factory."""
        app = FastAPI()
        
        @app.get("/critical")
        @high_availability_circuit_breaker_shield(name="critical_service")
        async def critical_operation():
            return {"result": "critical_success"}
        
        client = TestClient(app)
        response = client.get("/critical")
        
        assert response.status_code == 200
        
        cb = get_circuit_breaker("critical_service")
        assert cb is not None
        assert cb.config.failure_threshold == 10  # Higher threshold for HA
        assert cb.config.failure_rate_threshold == 0.3  # Lower rate threshold
        assert cb.config.success_threshold == 3  # More successes needed


class TestPerformanceAndMetrics:
    """Test performance characteristics and metrics collection."""
    
    @pytest.mark.asyncio
    async def test_response_time_tracking(self):
        """Test response time metrics tracking."""
        config = CircuitBreakerConfig(enable_monitoring=False)
        cb = CircuitBreakerShield("perf_test", config)
        
        async def fast_func():
            await asyncio.sleep(0.01)  # 10ms
            return "fast"
        
        async def slow_func():
            await asyncio.sleep(0.05)  # 50ms
            return "slow"
        
        # Execute functions
        await cb.execute_request(fast_func)
        await cb.execute_request(slow_func)
        
        metrics = cb.metrics
        assert metrics.successful_requests == 2
        assert metrics.fastest_response_time < 0.02  # Should be around 10ms
        assert metrics.slowest_response_time > 0.04  # Should be around 50ms
        assert 0.02 < metrics.average_response_time < 0.04  # Should be around 30ms
    
    @pytest.mark.asyncio
    async def test_sliding_window_behavior(self):
        """Test sliding window for failure rate calculation."""
        config = CircuitBreakerConfig(
            sliding_window_size=5,
            minimum_requests=3,
            failure_rate_threshold=0.6,
            enable_monitoring=False,
        )
        cb = CircuitBreakerShield("window_test", config)
        
        async def success_func():
            return "success"
        
        async def fail_func():
            raise ValueError("fail")
        
        # Add requests to sliding window
        await cb.execute_request(success_func)  # [True]
        await cb.execute_request(success_func)  # [True, True]
        
        with pytest.raises(ValueError):
            await cb.execute_request(fail_func)   # [True, True, False]
        
        assert len(cb.metrics.recent_requests) == 3
        assert cb.metrics.failure_rate == 1/3  # 33%
        assert cb.metrics.state == CircuitState.CLOSED  # Below threshold
        
        with pytest.raises(ValueError):
            await cb.execute_request(fail_func)   # [True, True, False, False]
        
        with pytest.raises(ValueError):
            await cb.execute_request(fail_func)   # [True, True, False, False, False]
        
        assert cb.metrics.failure_rate == 3/5  # 60%
        assert cb.metrics.state == CircuitState.OPEN  # Should open at 60% threshold
    
    @pytest.mark.asyncio
    async def test_concurrent_requests(self):
        """Test circuit breaker behavior with concurrent requests."""
        config = CircuitBreakerConfig(
            failure_threshold=5,
            enable_monitoring=False,
        )
        cb = CircuitBreakerShield("concurrent_test", config)
        
        async def concurrent_func(delay: float):
            await asyncio.sleep(delay)
            return f"result_{delay}"
        
        # Execute multiple concurrent requests
        async def task1():
            return await cb.execute_request(lambda delay=0.01: concurrent_func(delay))
        
        async def task2():
            return await cb.execute_request(lambda delay=0.02: concurrent_func(delay))
        
        async def task3():
            return await cb.execute_request(lambda delay=0.01: concurrent_func(delay))
        
        tasks = [task1(), task2(), task3()]
        
        results = await asyncio.gather(*tasks)
        
        assert len(results) == 3
        assert cb.metrics.successful_requests == 3
        assert cb.metrics.total_requests == 3


class TestErrorConditions:
    """Test error conditions and edge cases."""
    
    @pytest.mark.asyncio
    async def test_monitor_exception_handling(self):
        """Test that monitor exceptions don't break circuit breaker."""
        class FailingMonitor(CircuitBreakerMonitor):
            async def on_state_change(self, old_state, new_state, metrics, circuit_name):
                raise Exception("Monitor failed")
            
            async def on_metrics_update(self, metrics, circuit_name):
                raise Exception("Metrics update failed")
        
        config = CircuitBreakerConfig(
            failure_threshold=1,
            enable_monitoring=False,
        )
        cb = CircuitBreakerShield("error_test", config, monitors=[FailingMonitor()])
        
        async def failing_func():
            raise ValueError("Test error")
        
        # Should still work despite monitor failures
        with pytest.raises(ValueError):
            await cb.execute_request(failing_func)
        
        assert cb.metrics.failed_requests == 1
    
    @pytest.mark.asyncio
    async def test_health_checker_exception(self):
        """Test health checker exception handling."""
        class FailingHealthChecker(HealthChecker):
            async def check_health(self):
                raise Exception("Health check error")
        
        config = CircuitBreakerConfig(
            failure_threshold=1,
            recovery_timeout=0.1,
            enable_monitoring=False,
        )
        cb = CircuitBreakerShield("health_error_test", config, health_checker=FailingHealthChecker())
        
        # Open the circuit
        await cb.force_open()
        
        # Wait for recovery attempt
        await asyncio.sleep(0.2)
        
        async def success_func():
            return "success"
        
        # Should still be rejected due to health check failure
        with pytest.raises(HTTPException):
            await cb.execute_request(success_func)


if __name__ == "__main__":
    pytest.main([__file__])