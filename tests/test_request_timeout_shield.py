"""Comprehensive tests for request timeout shield."""

import pytest
import asyncio
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import Mock, patch, AsyncMock
from fastapi import FastAPI, Request, HTTPException
from fastapi.testclient import TestClient

from fastapi_shield.request_timeout import (
    RequestTimeoutShield,
    RequestTimeoutConfig,
    TimeoutConfiguration,
    ActiveRequest,
    TimeoutMetrics,
    TimeoutNotifier,
    LoggingTimeoutNotifier,
    MetricsTimeoutNotifier,
    WebhookTimeoutNotifier,
    TimeoutException,
    TimeoutTrigger,
    TimeoutAction,
    TimeoutGranularity,
    request_timeout_shield,
    endpoint_timeout_shield,
    method_timeout_shield,
    idle_timeout_shield,
    processing_timeout_shield,
    graceful_timeout_shield,
    comprehensive_timeout_shield,
)

from tests.mocks.request_timeout_mocks import (
    MockTimeoutNotifier,
    MockRequest,
    SlowTask,
    TimeoutTestHelper,
    MockMetricsCollector,
    TimeoutScenarioSimulator,
    ConcurrencyTestHelper,
    PerformanceTestHelper,
    EdgeCaseTestHelper,
)


class TestTimeoutConfiguration:
    """Test timeout configuration functionality."""
    
    def test_timeout_configuration_creation(self):
        """Test basic timeout configuration creation."""
        config = TimeoutConfiguration(
            timeout_seconds=30.0,
            trigger=TimeoutTrigger.REQUEST_DURATION,
            action=TimeoutAction.TERMINATE
        )
        
        assert config.timeout_seconds == 30.0
        assert config.trigger == TimeoutTrigger.REQUEST_DURATION
        assert config.action == TimeoutAction.TERMINATE
        assert config.priority == 0
        assert config.endpoint_pattern is None
        assert config.http_methods is None
    
    def test_timeout_configuration_with_patterns(self):
        """Test timeout configuration with endpoint and method patterns."""
        config = TimeoutConfiguration(
            timeout_seconds=60.0,
            endpoint_pattern=r"/api/upload/.*",
            http_methods=["POST", "PUT"],
            priority=1,
            custom_message="Upload timeout exceeded"
        )
        
        assert config.endpoint_pattern == r"/api/upload/.*"
        assert config.http_methods == ["POST", "PUT"]
        assert config.priority == 1
        assert config.custom_message == "Upload timeout exceeded"
    
    def test_timeout_configuration_matching(self):
        """Test request matching logic."""
        config = TimeoutConfiguration(
            timeout_seconds=30.0,
            endpoint_pattern=r"/api/.*",
            http_methods=["GET", "POST"]
        )
        
        request = MockRequest(path="/api/users", method="GET")
        assert config.matches_request(request, "/api/users", "GET", "127.0.0.1") is True
        
        request = MockRequest(path="/api/users", method="DELETE")
        assert config.matches_request(request, "/api/users", "DELETE", "127.0.0.1") is False
        
        request = MockRequest(path="/public/info", method="GET")
        assert config.matches_request(request, "/public/info", "GET", "127.0.0.1") is False
    
    def test_timeout_configuration_client_patterns(self):
        """Test client pattern matching."""
        config = TimeoutConfiguration(
            timeout_seconds=30.0,
            client_patterns=[r"192\.168\..*", r"10\.0\..*"]
        )
        
        assert config.matches_request(None, "/test", "GET", "192.168.1.1") is True
        assert config.matches_request(None, "/test", "GET", "10.0.0.100") is True
        assert config.matches_request(None, "/test", "GET", "172.16.1.1") is False
        assert config.matches_request(None, "/test", "GET", "127.0.0.1") is False


class TestTimeoutMetrics:
    """Test timeout metrics collection."""
    
    def test_metrics_initialization(self):
        """Test metrics initialization."""
        metrics = TimeoutMetrics()
        
        assert metrics.total_requests == 0
        assert metrics.timed_out_requests == 0
        assert metrics.average_duration == 0.0
        assert metrics.max_duration == 0.0
        assert metrics.min_duration == float('inf')
        assert len(metrics.timeout_by_trigger) == 0
        assert len(metrics.timeout_by_endpoint) == 0
        assert len(metrics.recent_timeouts) == 0
    
    def test_metrics_record_successful_request(self):
        """Test recording successful requests."""
        metrics = TimeoutMetrics()
        
        metrics.record_request(2.5, "/api/test", False)
        
        assert metrics.total_requests == 1
        assert metrics.timed_out_requests == 0
        assert metrics.average_duration == 2.5
        assert metrics.max_duration == 2.5
        assert metrics.min_duration == 2.5
        assert metrics.get_timeout_rate() == 0.0
    
    def test_metrics_record_timed_out_request(self):
        """Test recording timed out requests."""
        metrics = TimeoutMetrics()
        
        metrics.record_request(10.0, "/api/slow", True, TimeoutTrigger.REQUEST_DURATION)
        
        assert metrics.total_requests == 1
        assert metrics.timed_out_requests == 1
        assert metrics.average_duration == 10.0
        assert metrics.get_timeout_rate() == 100.0
        assert metrics.timeout_by_trigger[TimeoutTrigger.REQUEST_DURATION] == 1
        assert metrics.timeout_by_endpoint["/api/slow"] == 1
        assert len(metrics.recent_timeouts) == 1
    
    def test_metrics_multiple_requests(self):
        """Test metrics with multiple requests."""
        metrics = TimeoutMetrics()
        
        # Record multiple requests
        metrics.record_request(1.0, "/api/fast", False)
        metrics.record_request(5.0, "/api/medium", False)
        metrics.record_request(15.0, "/api/slow", True, TimeoutTrigger.REQUEST_DURATION)
        metrics.record_request(2.0, "/api/fast", False)
        
        assert metrics.total_requests == 4
        assert metrics.timed_out_requests == 1
        assert metrics.average_duration == 5.75  # (1+5+15+2)/4
        assert metrics.max_duration == 15.0
        assert metrics.min_duration == 1.0
        assert metrics.get_timeout_rate() == 25.0
    
    def test_metrics_to_dict(self):
        """Test metrics serialization."""
        metrics = TimeoutMetrics()
        metrics.record_request(3.0, "/test", True, TimeoutTrigger.IDLE_TIME)
        
        metrics_dict = metrics.to_dict()
        
        expected_keys = {
            'total_requests', 'timed_out_requests', 'timeout_rate_percent',
            'average_duration', 'max_duration', 'min_duration',
            'timeout_by_trigger', 'timeout_by_endpoint', 'recent_timeouts_count'
        }
        
        assert set(metrics_dict.keys()) == expected_keys
        assert metrics_dict['total_requests'] == 1
        assert metrics_dict['timeout_rate_percent'] == 100.0


class TestActiveRequest:
    """Test active request functionality."""
    
    def test_active_request_creation(self):
        """Test active request creation."""
        request = MockRequest()
        timeout_config = TimeoutTestHelper.create_timeout_config()
        
        active_request = ActiveRequest(
            request_id="test-123",
            request=request,
            endpoint="/test",
            method="GET",
            client_id="127.0.0.1",
            start_time=time.time(),
            last_activity_time=time.time(),
            timeout_config=timeout_config
        )
        
        assert active_request.request_id == "test-123"
        assert active_request.endpoint == "/test"
        assert active_request.method == "GET"
        assert active_request.client_id == "127.0.0.1"
        assert active_request.processing_start_time is None
        assert active_request.warning_sent is False
    
    def test_active_request_duration_calculation(self):
        """Test duration calculations."""
        start_time = time.time() - 5.0  # 5 seconds ago
        
        active_request = TimeoutTestHelper.create_active_request(
            start_time_offset=5.0
        )
        
        duration = active_request.get_duration()
        assert 4.9 <= duration <= 5.1  # Allow small timing variations
    
    def test_active_request_idle_time_calculation(self):
        """Test idle time calculations."""
        current_time = time.time()
        active_request = TimeoutTestHelper.create_active_request()
        
        # Simulate 2 seconds of idle time
        active_request.last_activity_time = current_time - 2.0
        
        idle_time = active_request.get_idle_time()
        assert 1.9 <= idle_time <= 2.1  # Allow small timing variations
    
    def test_active_request_processing_time(self):
        """Test processing time calculations."""
        active_request = TimeoutTestHelper.create_active_request()
        
        # No processing started yet
        assert active_request.get_processing_time() == 0.0
        
        # Start processing
        processing_start = time.time() - 1.5
        active_request.processing_start_time = processing_start
        
        processing_time = active_request.get_processing_time()
        assert 1.4 <= processing_time <= 1.6
    
    def test_active_request_timeout_detection(self):
        """Test timeout detection logic."""
        # Request that should timeout
        expired_request = TimeoutTestHelper.create_expired_request(
            timeout_seconds=5.0,
            expired_by=1.0
        )
        
        should_timeout, trigger = expired_request.should_timeout()
        assert should_timeout is True
        assert trigger == TimeoutTrigger.REQUEST_DURATION
        
        # Request that should not timeout
        active_request = TimeoutTestHelper.create_active_request(
            timeout_seconds=10.0
        )
        
        should_timeout, trigger = active_request.should_timeout()
        assert should_timeout is False
    
    def test_active_request_warning_detection(self):
        """Test warning detection logic."""
        warning_request = TimeoutTestHelper.create_warning_request(
            timeout_seconds=10.0,
            warning_threshold=7.0,
            current_duration=8.0
        )
        
        assert warning_request.should_warn() is True
        
        # Mark warning as sent
        warning_request.warning_sent = True
        assert warning_request.should_warn() is False
    
    def test_active_request_activity_updates(self):
        """Test activity timestamp updates."""
        active_request = TimeoutTestHelper.create_active_request()
        
        original_time = active_request.last_activity_time
        
        # Wait a bit and update activity
        time.sleep(0.1)
        active_request.update_activity()
        
        assert active_request.last_activity_time > original_time
    
    def test_active_request_processing_lifecycle(self):
        """Test request processing lifecycle."""
        active_request = TimeoutTestHelper.create_active_request()
        
        # Start processing
        active_request.start_processing()
        
        assert active_request.processing_start_time is not None
        assert active_request.get_processing_time() >= 0


class TestTimeoutNotifiers:
    """Test timeout notification handlers."""
    
    def test_logging_notifier_creation(self):
        """Test logging notifier creation."""
        notifier = LoggingTimeoutNotifier()
        assert notifier.logger is not None
        
        # Test with custom logger
        custom_logger = Mock()
        notifier = LoggingTimeoutNotifier(custom_logger)
        assert notifier.logger == custom_logger
    
    @pytest.mark.asyncio
    async def test_logging_notifier_timeout(self):
        """Test logging notifier timeout handling."""
        logger = Mock()
        notifier = LoggingTimeoutNotifier(logger)
        
        active_request = TimeoutTestHelper.create_active_request()
        
        await notifier.notify_timeout(active_request, TimeoutTrigger.REQUEST_DURATION)
        
        logger.warning.assert_called_once()
        call_args = logger.warning.call_args[0][0]
        assert "Request timeout" in call_args
        assert active_request.endpoint in call_args
    
    @pytest.mark.asyncio
    async def test_logging_notifier_warning(self):
        """Test logging notifier warning handling."""
        logger = Mock()
        notifier = LoggingTimeoutNotifier(logger)
        
        active_request = TimeoutTestHelper.create_active_request()
        
        await notifier.notify_warning(active_request)
        
        logger.info.assert_called_once()
        call_args = logger.info.call_args[0][0]
        assert "approaching timeout" in call_args
    
    def test_metrics_notifier_creation(self):
        """Test metrics notifier creation."""
        collector = MockMetricsCollector()
        notifier = MetricsTimeoutNotifier(collector.collect_metric)
        
        assert notifier.metrics_callback is not None
    
    @pytest.mark.asyncio
    async def test_metrics_notifier_timeout(self):
        """Test metrics notifier timeout handling."""
        collector = MockMetricsCollector()
        notifier = MetricsTimeoutNotifier(collector.collect_metric)
        
        active_request = TimeoutTestHelper.create_active_request()
        
        await notifier.notify_timeout(active_request, TimeoutTrigger.IDLE_TIME)
        
        assert collector.call_count == 1
        timeout_events = collector.get_timeout_events()
        assert len(timeout_events) == 1
        assert timeout_events[0]['event'] == 'timeout'
        assert timeout_events[0]['trigger'] == 'idle_time'
    
    @pytest.mark.asyncio
    async def test_metrics_notifier_warning(self):
        """Test metrics notifier warning handling."""
        collector = MockMetricsCollector()
        notifier = MetricsTimeoutNotifier(collector.collect_metric)
        
        active_request = TimeoutTestHelper.create_active_request()
        
        await notifier.notify_warning(active_request)
        
        warning_events = collector.get_warning_events()
        assert len(warning_events) == 1
        assert warning_events[0]['event'] == 'timeout_warning'
    
    def test_webhook_notifier_creation(self):
        """Test webhook notifier creation."""
        notifier = WebhookTimeoutNotifier("https://example.com/webhook")
        
        assert notifier.webhook_url == "https://example.com/webhook"
        assert notifier.timeout == 5
    
    @pytest.mark.asyncio
    async def test_webhook_notifier_without_httpx(self):
        """Test webhook notifier when httpx is not available."""
        notifier = WebhookTimeoutNotifier("https://example.com/webhook")
        notifier._client = None  # Simulate httpx not available
        
        active_request = TimeoutTestHelper.create_active_request()
        
        # Should not raise exception
        await notifier.notify_timeout(active_request, TimeoutTrigger.REQUEST_DURATION)
        await notifier.notify_warning(active_request)
    
    @pytest.mark.asyncio
    async def test_mock_timeout_notifier(self):
        """Test mock timeout notifier functionality."""
        notifier = MockTimeoutNotifier()
        active_request = TimeoutTestHelper.create_active_request()
        
        # Test timeout notification
        await notifier.notify_timeout(active_request, TimeoutTrigger.REQUEST_DURATION)
        assert len(notifier.timeout_notifications) == 1
        
        # Test warning notification
        await notifier.notify_warning(active_request)
        assert len(notifier.warning_notifications) == 1
        
        # Test failure scenarios
        notifier.should_fail_timeout = True
        with pytest.raises(Exception, match="Mock timeout notification failure"):
            await notifier.notify_timeout(active_request, TimeoutTrigger.REQUEST_DURATION)


class TestRequestTimeoutConfig:
    """Test request timeout configuration."""
    
    def test_config_defaults(self):
        """Test default configuration values."""
        config = RequestTimeoutConfig()
        
        assert config.default_timeout_seconds == 30.0
        assert config.check_interval_seconds == 1.0
        assert config.enable_metrics is True
        assert config.enable_warnings is True
        assert config.granularity == TimeoutGranularity.ENDPOINT
        assert len(config.timeout_configurations) == 0
        assert len(config.notifiers) == 1  # Default logging notifier
        assert config.max_concurrent_requests is None
        assert config.graceful_shutdown_timeout == 5.0
    
    def test_config_custom_values(self):
        """Test configuration with custom values."""
        timeout_configs = [
            TimeoutTestHelper.create_timeout_config(timeout_seconds=60.0)
        ]
        
        notifiers = [MockTimeoutNotifier()]
        
        config = RequestTimeoutConfig(
            default_timeout_seconds=45.0,
            check_interval_seconds=0.5,
            enable_metrics=False,
            timeout_configurations=timeout_configs,
            notifiers=notifiers,
            max_concurrent_requests=100,
            graceful_shutdown_timeout=10.0
        )
        
        assert config.default_timeout_seconds == 45.0
        assert config.check_interval_seconds == 0.5
        assert config.enable_metrics is False
        assert len(config.timeout_configurations) == 1
        assert len(config.notifiers) == 1
        assert config.max_concurrent_requests == 100
        assert config.graceful_shutdown_timeout == 10.0
    
    def test_config_with_extractors(self):
        """Test configuration with custom extractors."""
        def custom_client_extractor(request):
            return request.headers.get("X-Client-ID", "unknown")
        
        def custom_endpoint_extractor(request):
            return f"{request.method}:{request.url.path}"
        
        config = RequestTimeoutConfig(
            client_id_extractor=custom_client_extractor,
            endpoint_extractor=custom_endpoint_extractor
        )
        
        assert config.client_id_extractor is not None
        assert config.endpoint_extractor is not None


class TestRequestTimeoutShield:
    """Test request timeout shield functionality."""
    
    @pytest.fixture
    def basic_config(self):
        """Create basic timeout configuration for testing."""
        return RequestTimeoutConfig(
            default_timeout_seconds=5.0,
            check_interval_seconds=0.1,
            notifiers=[MockTimeoutNotifier()]
        )
    
    @pytest.fixture
    def shield(self, basic_config):
        """Create timeout shield for testing."""
        return RequestTimeoutShield(basic_config)
    
    def test_shield_creation(self, shield):
        """Test timeout shield creation."""
        assert isinstance(shield, RequestTimeoutShield)
        assert len(shield.active_requests) == 0
        assert isinstance(shield.metrics, TimeoutMetrics)
        # Monitor task starts when shield is first used, not during creation
        assert shield._initialized is False
    
    def test_shield_client_id_extraction(self, shield):
        """Test client ID extraction."""
        # Test with X-Forwarded-For header
        request = MockRequest(headers={"X-Forwarded-For": "192.168.1.1, 10.0.0.1"})
        client_id = shield._get_client_id(request)
        assert client_id == "192.168.1.1"
        
        # Test with X-Real-IP header
        request = MockRequest(headers={"X-Real-IP": "172.16.1.1"})
        client_id = shield._get_client_id(request)
        assert client_id == "172.16.1.1"
        
        # Test with client.host
        request = MockRequest(client_host="127.0.0.1")
        client_id = shield._get_client_id(request)
        assert client_id == "127.0.0.1"
    
    def test_shield_endpoint_extraction(self, shield):
        """Test endpoint extraction."""
        request = MockRequest(path="/api/users/123")
        endpoint = shield._get_endpoint(request)
        assert endpoint == "/api/users/123"
    
    def test_shield_request_id_extraction(self, shield):
        """Test request ID extraction."""
        # Test with existing request ID header
        request = MockRequest(headers={"X-Request-ID": "existing-123"})
        request_id = shield._get_request_id(request)
        assert request_id == "existing-123"
        
        # Test with generated request ID
        request = MockRequest()
        request_id = shield._get_request_id(request)
        assert len(request_id) > 0
        assert request_id != shield._get_request_id(MockRequest())  # Should be unique
    
    def test_shield_timeout_config_finding(self, shield):
        """Test timeout configuration selection."""
        # Add specific configuration
        api_config = TimeoutConfiguration(
            timeout_seconds=60.0,
            endpoint_pattern=r"/api/.*",
            priority=1
        )
        shield.config.timeout_configurations.append(api_config)
        shield.config.timeout_configurations.sort(key=lambda x: x.priority, reverse=True)
        
        # Test matching configuration
        request = MockRequest(path="/api/users")
        config = shield._find_timeout_config(request, "/api/users", "GET", "127.0.0.1")
        assert config.timeout_seconds == 60.0
        
        # Test default configuration
        request = MockRequest(path="/public/info")
        config = shield._find_timeout_config(request, "/public/info", "GET", "127.0.0.1")
        assert config.timeout_seconds == shield.config.default_timeout_seconds
    
    @pytest.mark.asyncio
    async def test_shield_function_basic(self, shield):
        """Test basic shield function execution."""
        request = MockRequest(path="/test")
        
        result = await shield._shield_function(request)
        
        assert result is not None
        assert "request_timeout" in result
        timeout_info = result["request_timeout"]
        assert "request_id" in timeout_info
        assert timeout_info["endpoint"] == "/test"
        assert timeout_info["timeout_seconds"] == 5.0
        
        # Should have added to active requests
        assert len(shield.active_requests) == 1
    
    @pytest.mark.asyncio
    async def test_shield_function_concurrent_limit(self):
        """Test concurrent request limit enforcement."""
        config = RequestTimeoutConfig(
            max_concurrent_requests=2,
            notifiers=[MockTimeoutNotifier()]
        )
        shield = RequestTimeoutShield(config)
        
        # Add requests up to limit
        await shield._shield_function(MockRequest(path="/test1"))
        await shield._shield_function(MockRequest(path="/test2"))
        
        # Third request should be rejected
        with pytest.raises(HTTPException) as exc_info:
            await shield._shield_function(MockRequest(path="/test3"))
        
        assert exc_info.value.status_code == 503
        assert "too_many_requests" in exc_info.value.detail["error"]
    
    @pytest.mark.asyncio
    async def test_shield_timeout_detection(self, shield):
        """Test timeout detection and handling."""
        # Create a request that will timeout quickly
        request = MockRequest(path="/test")
        result = await shield._shield_function(request)
        request_id = result["request_timeout"]["request_id"]
        
        # Manually expire the request
        active_request = shield.active_requests[request_id]
        active_request.start_time = time.time() - 10.0  # 10 seconds ago
        
        # Wait for timeout monitor to detect it
        await asyncio.sleep(0.2)
        
        # Request should be removed from active requests
        assert request_id not in shield.active_requests
        
        # Notifier should have been called
        notifier = shield.config.notifiers[0]
        assert len(notifier.timeout_notifications) == 1
    
    @pytest.mark.asyncio
    async def test_shield_warning_detection(self, shield):
        """Test timeout warning detection."""
        # Configure shield with warning threshold
        warning_config = TimeoutConfiguration(
            timeout_seconds=10.0,
            warning_threshold=7.0,
            priority=1
        )
        shield.config.timeout_configurations.append(warning_config)
        shield.config.timeout_configurations.sort(key=lambda x: x.priority, reverse=True)
        
        # Create request
        request = MockRequest(path="/test")
        result = await shield._shield_function(request)
        request_id = result["request_timeout"]["request_id"]
        
        # Set request to warning threshold
        active_request = shield.active_requests[request_id]
        active_request.start_time = time.time() - 8.0  # Should trigger warning
        
        # Wait for monitor to detect warning
        await asyncio.sleep(0.2)
        
        # Warning should have been sent
        notifier = shield.config.notifiers[0]
        assert len(notifier.warning_notifications) == 1
        assert active_request.warning_sent is True
    
    @pytest.mark.asyncio
    async def test_shield_request_completion(self, shield):
        """Test request completion handling."""
        request = MockRequest(path="/test")
        result = await shield._shield_function(request)
        request_id = result["request_timeout"]["request_id"]
        
        # Complete the request
        await shield.complete_request(request_id)
        
        # Should be removed from active requests
        assert request_id not in shield.active_requests
        
        # Should be recorded in metrics
        assert shield.metrics.total_requests == 1
        assert shield.metrics.timed_out_requests == 0
    
    def test_shield_metrics_collection(self, shield):
        """Test metrics collection."""
        metrics = shield.get_metrics()
        
        expected_keys = {
            'total_requests', 'timed_out_requests', 'timeout_rate_percent',
            'average_duration', 'max_duration', 'min_duration',
            'timeout_by_trigger', 'timeout_by_endpoint', 'recent_timeouts_count',
            'active_requests', 'max_concurrent_requests', 'monitor_running',
            'configurations_count', 'initialized'
        }
        
        assert set(metrics.keys()) == expected_keys
        assert metrics['active_requests'] == 0
        assert metrics['monitor_running'] is False  # Not initialized yet
    
    def test_shield_active_requests_info(self, shield):
        """Test active requests information retrieval."""
        # Initially empty
        active_info = shield.get_active_requests()
        assert len(active_info) == 0
        
        # Add a request manually for testing
        active_request = TimeoutTestHelper.create_active_request()
        shield.active_requests[active_request.request_id] = active_request
        
        active_info = shield.get_active_requests()
        assert len(active_info) == 1
        assert active_request.request_id in active_info
        
        request_info = active_info[active_request.request_id]
        assert request_info['endpoint'] == active_request.endpoint
        assert request_info['method'] == active_request.method
        assert 'duration' in request_info
        assert 'idle_time' in request_info
    
    @pytest.mark.asyncio
    async def test_shield_shutdown(self, shield):
        """Test shield shutdown process."""
        # Add some active requests
        await shield._shield_function(MockRequest(path="/test1"))
        await shield._shield_function(MockRequest(path="/test2"))
        
        assert len(shield.active_requests) == 2
        assert shield._monitor_task is not None
        assert not shield._monitor_task.done()
        
        # Shutdown
        await shield.shutdown()
        
        # Should clean up everything
        assert len(shield.active_requests) == 0
        assert shield._shutdown_event.is_set()
        assert shield._monitor_task.done()


class TestTimeoutTriggers:
    """Test different timeout trigger types."""
    
    @pytest.mark.asyncio
    async def test_request_duration_trigger(self):
        """Test request duration timeout trigger."""
        active_request = TimeoutTestHelper.create_active_request(
            timeout_seconds=2.0,
            trigger=TimeoutTrigger.REQUEST_DURATION,
            start_time_offset=3.0  # Started 3 seconds ago
        )
        
        should_timeout, trigger = active_request.should_timeout()
        assert should_timeout is True
        assert trigger == TimeoutTrigger.REQUEST_DURATION
    
    @pytest.mark.asyncio
    async def test_idle_time_trigger(self):
        """Test idle time timeout trigger."""
        active_request = TimeoutTestHelper.create_active_request(
            timeout_seconds=2.0,
            trigger=TimeoutTrigger.IDLE_TIME
        )
        
        # Set last activity to 3 seconds ago
        active_request.last_activity_time = time.time() - 3.0
        
        should_timeout, trigger = active_request.should_timeout()
        assert should_timeout is True
        assert trigger == TimeoutTrigger.IDLE_TIME
    
    @pytest.mark.asyncio
    async def test_processing_time_trigger(self):
        """Test processing time timeout trigger."""
        active_request = TimeoutTestHelper.create_active_request(
            timeout_seconds=2.0,
            trigger=TimeoutTrigger.PROCESSING_TIME
        )
        
        # Set processing start to 3 seconds ago
        active_request.processing_start_time = time.time() - 3.0
        
        should_timeout, trigger = active_request.should_timeout()
        assert should_timeout is True
        assert trigger == TimeoutTrigger.PROCESSING_TIME


class TestTimeoutActions:
    """Test different timeout actions."""
    
    @pytest.mark.asyncio
    async def test_terminate_action(self):
        """Test terminate action."""
        config = RequestTimeoutConfig(
            default_timeout_seconds=0.1,
            check_interval_seconds=0.05,
            timeout_configurations=[
                TimeoutConfiguration(
                    timeout_seconds=0.1,
                    action=TimeoutAction.TERMINATE,
                    priority=1
                )
            ],
            notifiers=[MockTimeoutNotifier()]
        )
        
        shield = RequestTimeoutShield(config)
        
        # Create request that will timeout
        request = MockRequest(path="/test")
        await shield._shield_function(request)
        
        # Wait for timeout
        await asyncio.sleep(0.2)
        
        # Request should be terminated and removed
        assert len(shield.active_requests) == 0
        
        notifier = shield.config.notifiers[0]
        assert len(notifier.timeout_notifications) == 1
    
    @pytest.mark.asyncio
    async def test_graceful_stop_action(self):
        """Test graceful stop action."""
        config = RequestTimeoutConfig(
            default_timeout_seconds=0.1,
            check_interval_seconds=0.05,
            graceful_shutdown_timeout=0.1,
            timeout_configurations=[
                TimeoutConfiguration(
                    timeout_seconds=0.1,
                    action=TimeoutAction.GRACEFUL_STOP,
                    priority=1
                )
            ],
            notifiers=[MockTimeoutNotifier()]
        )
        
        shield = RequestTimeoutShield(config)
        
        # Create request with mock task
        request = MockRequest(path="/test")
        result = await shield._shield_function(request)
        request_id = result["request_timeout"]["request_id"]
        
        # Add a mock task to the active request
        active_request = shield.active_requests[request_id]
        active_request.task = asyncio.create_task(asyncio.sleep(1.0))
        
        # Wait for timeout and graceful stop
        await asyncio.sleep(0.3)
        
        # Task should be cancelled (graceful stop -> force cancel after timeout)
        assert active_request.task.cancelled() or active_request.task.done()


class TestConvenienceFunctions:
    """Test convenience functions for creating timeout shields."""
    
    def test_request_timeout_shield(self):
        """Test basic request timeout shield creation."""
        shield = request_timeout_shield(
            timeout_seconds=60.0,
            check_interval=2.0,
            enable_metrics=False
        )
        
        assert isinstance(shield, RequestTimeoutShield)
        assert shield.config.default_timeout_seconds == 60.0
        assert shield.config.check_interval_seconds == 2.0
        assert shield.config.enable_metrics is False
    
    def test_endpoint_timeout_shield(self):
        """Test endpoint-specific timeout shield creation."""
        endpoint_timeouts = {
            r"/api/upload/.*": 120.0,
            r"/api/search/.*": 30.0
        }
        
        shield = endpoint_timeout_shield(
            endpoint_timeouts=endpoint_timeouts,
            default_timeout=45.0
        )
        
        assert shield.config.default_timeout_seconds == 45.0
        assert len(shield.config.timeout_configurations) == 2
        
        # Test configuration matching
        upload_config = None
        for config in shield.config.timeout_configurations:
            if config.endpoint_pattern == r"/api/upload/.*":
                upload_config = config
                break
        
        assert upload_config is not None
        assert upload_config.timeout_seconds == 120.0
    
    def test_method_timeout_shield(self):
        """Test HTTP method timeout shield creation."""
        method_timeouts = {
            "POST": 60.0,
            "PUT": 90.0,
            "DELETE": 30.0
        }
        
        shield = method_timeout_shield(
            method_timeouts=method_timeouts,
            default_timeout=45.0
        )
        
        assert len(shield.config.timeout_configurations) == 3
        
        # Find POST configuration
        post_config = None
        for config in shield.config.timeout_configurations:
            if config.http_methods == ["POST"]:
                post_config = config
                break
        
        assert post_config is not None
        assert post_config.timeout_seconds == 60.0
    
    def test_idle_timeout_shield(self):
        """Test idle timeout shield creation."""
        shield = idle_timeout_shield(
            idle_timeout_seconds=15.0,
            check_interval=0.25
        )
        
        assert shield.config.default_timeout_seconds == 15.0
        assert shield.config.check_interval_seconds == 0.25
        assert len(shield.config.timeout_configurations) == 1
        
        config = shield.config.timeout_configurations[0]
        assert config.trigger == TimeoutTrigger.IDLE_TIME
        assert config.timeout_seconds == 15.0
    
    def test_processing_timeout_shield(self):
        """Test processing timeout shield creation."""
        shield = processing_timeout_shield(
            processing_timeout_seconds=20.0,
            warning_threshold_seconds=15.0
        )
        
        assert len(shield.config.timeout_configurations) == 1
        
        config = shield.config.timeout_configurations[0]
        assert config.trigger == TimeoutTrigger.PROCESSING_TIME
        assert config.timeout_seconds == 20.0
        assert config.warning_threshold == 15.0
    
    def test_graceful_timeout_shield(self):
        """Test graceful timeout shield creation."""
        shield = graceful_timeout_shield(
            timeout_seconds=40.0,
            graceful_shutdown_timeout=8.0,
            custom_message="Request taking too long"
        )
        
        assert shield.config.graceful_shutdown_timeout == 8.0
        assert len(shield.config.timeout_configurations) == 1
        
        config = shield.config.timeout_configurations[0]
        assert config.action == TimeoutAction.GRACEFUL_STOP
        assert config.custom_message == "Request taking too long"
    
    def test_comprehensive_timeout_shield(self):
        """Test comprehensive timeout shield creation."""
        shield = comprehensive_timeout_shield(
            default_timeout=30.0,
            endpoint_timeouts={"/api/upload": 120.0},
            method_timeouts={"POST": 60.0},
            idle_timeout=10.0,
            processing_timeout=45.0,
            max_concurrent_requests=100
        )
        
        assert shield.config.default_timeout_seconds == 30.0
        assert shield.config.max_concurrent_requests == 100
        assert len(shield.config.timeout_configurations) == 4  # endpoint, method, idle, processing
        
        # Should include logging notifier by default
        assert len(shield.config.notifiers) >= 1
        assert any(isinstance(n, LoggingTimeoutNotifier) for n in shield.config.notifiers)


class TestPerformanceAndScaling:
    """Test performance and scalability aspects."""
    
    @pytest.mark.asyncio
    async def test_concurrent_request_handling(self):
        """Test handling multiple concurrent requests."""
        config = RequestTimeoutConfig(
            default_timeout_seconds=5.0,
            check_interval_seconds=0.1,
            max_concurrent_requests=50,
            notifiers=[MockTimeoutNotifier()]
        )
        
        shield = RequestTimeoutShield(config)
        
        # Create multiple concurrent requests
        request_count = 20
        requests = []
        
        for i in range(request_count):
            request = MockRequest(path=f"/test/{i}")
            result = await shield._shield_function(request)
            requests.append(result)
        
        # All requests should be tracked
        assert len(shield.active_requests) == request_count
        
        # Complete all requests
        for result in requests:
            request_id = result["request_timeout"]["request_id"]
            await shield.complete_request(request_id)
        
        # All should be completed
        assert len(shield.active_requests) == 0
        assert shield.metrics.total_requests == request_count
    
    @pytest.mark.asyncio
    async def test_timeout_monitoring_performance(self):
        """Test performance of timeout monitoring."""
        # Create shield with many active requests
        config = RequestTimeoutConfig(
            default_timeout_seconds=60.0,  # Long timeout to avoid actual timeouts
            check_interval_seconds=0.1,
            notifiers=[]  # No notifiers to reduce overhead
        )
        
        shield = RequestTimeoutShield(config)
        
        # Add many active requests
        request_count = 100
        for i in range(request_count):
            active_request = TimeoutTestHelper.create_active_request(
                request_id=f"perf-test-{i}",
                timeout_seconds=60.0
            )
            shield.active_requests[active_request.request_id] = active_request
        
        # Measure timeout checking performance
        start_time = time.time()
        
        # Run several timeout checks
        for _ in range(10):
            await shield._check_timeouts()
        
        end_time = time.time()
        
        # Performance should be reasonable
        total_time = end_time - start_time
        checks_per_request = total_time / (request_count * 10)
        
        # Should be able to check timeouts very quickly
        assert checks_per_request < 0.001  # Less than 1ms per request per check
    
    @pytest.mark.asyncio
    async def test_memory_usage_with_many_requests(self):
        """Test memory usage with many concurrent requests."""
        config = RequestTimeoutConfig(
            default_timeout_seconds=30.0,
            notifiers=[MockTimeoutNotifier()]
        )
        
        shield = RequestTimeoutShield(config)
        
        # Create many requests and complete them
        for batch in range(10):
            # Create batch of requests
            batch_requests = []
            for i in range(50):
                request = MockRequest(path=f"/batch/{batch}/item/{i}")
                result = await shield._shield_function(request)
                batch_requests.append(result["request_timeout"]["request_id"])
            
            # Complete the batch
            for request_id in batch_requests:
                await shield.complete_request(request_id)
            
            # Should not accumulate active requests
            assert len(shield.active_requests) == 0
        
        # Should have processed all requests
        assert shield.metrics.total_requests == 500
    
    def test_metrics_performance(self):
        """Test metrics collection performance."""
        metrics = TimeoutMetrics()
        
        # Record many requests quickly
        start_time = time.time()
        
        for i in range(1000):
            duration = (i % 10) + 1.0
            endpoint = f"/api/endpoint-{i % 20}"
            timed_out = i % 10 == 0  # Every 10th request times out
            trigger = TimeoutTrigger.REQUEST_DURATION if timed_out else None
            
            metrics.record_request(duration, endpoint, timed_out, trigger)
        
        end_time = time.time()
        
        # Should complete quickly
        total_time = end_time - start_time
        assert total_time < 1.0  # Should complete in less than 1 second
        
        # Verify metrics are correct
        assert metrics.total_requests == 1000
        assert metrics.timed_out_requests == 100
        assert metrics.get_timeout_rate() == 10.0


class TestEdgeCasesAndErrorHandling:
    """Test edge cases and error handling."""
    
    @pytest.mark.asyncio
    async def test_notification_failures(self):
        """Test handling of notification failures."""
        failing_notifier = MockTimeoutNotifier()
        config = RequestTimeoutConfig(
            default_timeout_seconds=0.1,
            check_interval_seconds=0.05,
            notifiers=[failing_notifier]
        )
        
        shield = RequestTimeoutShield(config)
        
        # Configure notifier to fail
        failing_notifier.should_fail_timeout = True
        
        # Create request that will timeout
        request = MockRequest(path="/test")
        await shield._shield_function(request)
        
        # Wait for timeout (should not crash despite notification failure)
        await asyncio.sleep(0.2)
        
        # Shield should continue operating
        assert shield._monitor_task is not None
        assert not shield._monitor_task.done()
    
    def test_invalid_regex_patterns(self):
        """Test handling of invalid regex patterns."""
        # Invalid regex should not crash configuration creation
        config = TimeoutConfiguration(
            timeout_seconds=30.0,
            endpoint_pattern="[invalid"  # Invalid regex
        )
        
        request = MockRequest(path="/test")
        
        # Should handle gracefully (return False for invalid regex)
        result = config.matches_request(request, "/test", "GET", "127.0.0.1")
        assert result is False  # Invalid regex should not match
    
    def test_extreme_timeout_values(self):
        """Test handling of extreme timeout values."""
        edge_cases = [
            0.0,      # Zero timeout
            -1.0,     # Negative timeout
            float('inf'),  # Infinite timeout
            1e-6,     # Very small timeout
            1e6,      # Very large timeout
        ]
        
        for timeout_value in edge_cases:
            config = TimeoutConfiguration(timeout_seconds=timeout_value)
            
            # Should not crash during creation
            assert config.timeout_seconds == timeout_value
    
    @pytest.mark.asyncio
    async def test_concurrent_modification_safety(self):
        """Test safety of concurrent modifications to active requests."""
        config = RequestTimeoutConfig(
            default_timeout_seconds=5.0,
            notifiers=[MockTimeoutNotifier()]
        )
        
        shield = RequestTimeoutShield(config)
        
        # Add requests concurrently
        async def add_request(i):
            request = MockRequest(path=f"/test/{i}")
            return await shield._shield_function(request)
        
        # Add and remove requests concurrently
        async def remove_request(request_id):
            await asyncio.sleep(0.1)  # Small delay
            await shield.complete_request(request_id)
        
        # Create tasks for adding and removing requests
        add_tasks = [add_request(i) for i in range(10)]
        results = await asyncio.gather(*add_tasks)
        
        # Start removal tasks
        remove_tasks = [
            remove_request(result["request_timeout"]["request_id"])
            for result in results
        ]
        
        # Wait for removals to complete
        await asyncio.gather(*remove_tasks)
        
        # Should complete without errors
        assert len(shield.active_requests) == 0
    
    def test_zero_check_interval(self):
        """Test handling of zero check interval."""
        config = RequestTimeoutConfig(
            check_interval_seconds=0.0,
            notifiers=[MockTimeoutNotifier()]
        )
        
        # Should not crash during shield creation
        shield = RequestTimeoutShield(config)
        assert shield.config.check_interval_seconds == 0.0
    
    @pytest.mark.asyncio
    async def test_shield_with_disabled_tracking(self):
        """Test shield with request tracking disabled."""
        config = RequestTimeoutConfig(
            enable_request_tracking=False,
            notifiers=[MockTimeoutNotifier()]
        )
        
        shield = RequestTimeoutShield(config)
        
        request = MockRequest(path="/test")
        result = await shield._shield_function(request)
        
        # Should return None when tracking is disabled
        assert result is None
        assert len(shield.active_requests) == 0
    
    def test_malformed_request_objects(self):
        """Test handling of malformed request objects."""
        config = RequestTimeoutConfig(notifiers=[MockTimeoutNotifier()])
        shield = RequestTimeoutShield(config)
        
        # Request without client
        request = MockRequest()
        request.client = None
        
        client_id = shield._get_client_id(request)
        assert client_id == "unknown"
        
        # Request with missing headers
        request = MockRequest()
        request.headers = None
        
        # Should not crash
        request_id = shield._get_request_id(request)
        assert len(request_id) > 0


class TestIntegrationScenarios:
    """Test integration scenarios with FastAPI."""
    
    @pytest.mark.asyncio
    async def test_fastapi_integration(self):
        """Test integration with FastAPI application."""
        app = FastAPI()
        
        timeout_shield = request_timeout_shield(
            timeout_seconds=5.0,
            enable_metrics=True
        )
        
        @app.get("/test")
        async def test_endpoint(request: Request):
            result = await timeout_shield._shield_function(request)
            return {"message": "success", "timeout_info": result}
        
        client = TestClient(app)
        
        response = client.get("/test")
        
        assert response.status_code == 200
        data = response.json()
        assert "timeout_info" in data
        assert "request_timeout" in data["timeout_info"]
    
    @pytest.mark.asyncio
    async def test_mixed_timeout_scenarios(self):
        """Test complex scenario with mixed timeout configurations."""
        simulator = TimeoutScenarioSimulator()
        
        # Create mixed workload
        fast_requests, slow_requests = simulator.simulate_mixed_workload(
            fast_requests=5,
            slow_requests=3,
            fast_timeout=2.0,
            slow_timeout=10.0
        )
        
        # Simulate time passing
        await asyncio.sleep(0.1)
        
        # Check timeout status
        timed_out, warnings = simulator.check_timeouts()
        
        # Initially, no timeouts expected
        assert len(timed_out) == 0
        
        # Complete some requests
        for i, request in enumerate(fast_requests[:2]):
            simulator.complete_request(request.request_id)
        
        # Get statistics
        stats = simulator.get_statistics()
        assert stats['completed_requests'] == 2
        assert stats['active_requests'] == len(fast_requests) + len(slow_requests) - 2  # Remaining active requests


# Run specific test groups if this file is executed directly
if __name__ == "__main__":
    pytest.main([__file__, "-v"])