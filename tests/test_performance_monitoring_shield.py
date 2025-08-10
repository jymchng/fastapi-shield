"""Comprehensive tests for Performance Monitoring Shield functionality."""

import asyncio
import json
import time
import threading
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch, MagicMock

import pytest
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient

from fastapi_shield.performance_monitoring import (
    PerformanceMonitoringShield,
    PerformanceMonitoringConfig,
    MonitoringServiceProvider,
    PrometheusProvider,
    DataDogProvider,
    NewRelicProvider,
    CustomProvider,
    MetricsStorage,
    ResourceMonitor,
    AlertManager,
    AlertThreshold,
    Alert,
    PerformanceMetric,
    ResourceUsage,
    MonitoringService,
    AlertSeverity,
    MetricType,
    performance_monitoring_shield,
    prometheus_performance_shield,
    datadog_performance_shield,
    newrelic_performance_shield,
    multi_provider_performance_shield,
)
from tests.mocks.performance_monitoring_mocks import (
    MockMonitoringProvider,
    MockPrometheusProvider,
    MockDataDogProvider,
    MockNewRelicProvider,
    MockCustomProvider,
    MockMetricsStorage,
    MockResourceMonitor,
    MockAlertManager,
    create_mock_performance_metric,
    create_mock_resource_usage,
    create_mock_alert_threshold,
    create_mock_alert,
    LoadTestHelper,
    TimingHelper,
    ValidationHelper,
)


def create_mock_request(
    method: str = "GET",
    path: str = "/api/test",
    headers: dict = None,
    user_id: str = "test_user"
) -> Mock:
    """Create a mock FastAPI Request object."""
    request = Mock(spec=Request)
    request.method = method
    request.url = Mock()
    request.url.path = path
    request.headers = headers or {}
    request.state = Mock()
    
    # Add user identification header
    if user_id:
        request.headers["x-user-id"] = user_id
    
    if "host" not in request.headers:
        request.headers["host"] = "localhost"
    
    return request


def create_mock_response(
    status_code: int = 200,
    body: bytes = b'{"message": "success"}'
) -> Mock:
    """Create a mock FastAPI Response object."""
    response = Mock(spec=Response)
    response.status_code = status_code
    response.body = body
    return response


class TestPerformanceMetric:
    """Test PerformanceMetric data structure."""
    
    def test_performance_metric_creation(self):
        """Test creating performance metric with all parameters."""
        metric = PerformanceMetric(
            name="test_metric",
            value=123.45,
            metric_type=MetricType.HISTOGRAM,
            labels={"endpoint": "/test", "method": "GET"},
            unit="ms"
        )
        
        assert metric.name == "test_metric"
        assert metric.value == 123.45
        assert metric.metric_type == MetricType.HISTOGRAM
        assert metric.labels["endpoint"] == "/test"
        assert metric.labels["method"] == "GET"
        assert metric.unit == "ms"
        assert isinstance(metric.timestamp, datetime)
    
    def test_performance_metric_defaults(self):
        """Test performance metric with default values."""
        metric = PerformanceMetric(
            name="simple_metric",
            value=50.0,
            metric_type=MetricType.GAUGE
        )
        
        assert metric.name == "simple_metric"
        assert metric.value == 50.0
        assert metric.metric_type == MetricType.GAUGE
        assert metric.labels == {}
        assert metric.unit == "ms"
        assert isinstance(metric.timestamp, datetime)


class TestResourceUsage:
    """Test ResourceUsage data structure."""
    
    def test_resource_usage_creation(self):
        """Test creating resource usage with all parameters."""
        usage = ResourceUsage(
            cpu_percent=75.5,
            memory_percent=80.0,
            memory_used_mb=2048.0,
            disk_io_read_mb=100.0,
            disk_io_write_mb=50.0,
            network_sent_mb=25.0,
            network_recv_mb=30.0
        )
        
        assert usage.cpu_percent == 75.5
        assert usage.memory_percent == 80.0
        assert usage.memory_used_mb == 2048.0
        assert usage.disk_io_read_mb == 100.0
        assert usage.disk_io_write_mb == 50.0
        assert usage.network_sent_mb == 25.0
        assert usage.network_recv_mb == 30.0
        assert isinstance(usage.timestamp, datetime)


class TestAlertThreshold:
    """Test AlertThreshold data structure."""
    
    def test_alert_threshold_creation(self):
        """Test creating alert threshold with all parameters."""
        threshold = AlertThreshold(
            metric_name="response_time",
            threshold_value=1000.0,
            comparison="greater_than",
            severity=AlertSeverity.HIGH,
            window_seconds=300,
            consecutive_breaches=3,
            enabled=True
        )
        
        assert threshold.metric_name == "response_time"
        assert threshold.threshold_value == 1000.0
        assert threshold.comparison == "greater_than"
        assert threshold.severity == AlertSeverity.HIGH
        assert threshold.window_seconds == 300
        assert threshold.consecutive_breaches == 3
        assert threshold.enabled is True
    
    def test_alert_threshold_defaults(self):
        """Test alert threshold with default values."""
        threshold = AlertThreshold(
            metric_name="test_metric",
            threshold_value=500.0,
            comparison="less_than",
            severity=AlertSeverity.MEDIUM
        )
        
        assert threshold.metric_name == "test_metric"
        assert threshold.threshold_value == 500.0
        assert threshold.comparison == "less_than"
        assert threshold.severity == AlertSeverity.MEDIUM
        assert threshold.window_seconds == 300
        assert threshold.consecutive_breaches == 3
        assert threshold.enabled is True


class TestAlert:
    """Test Alert data structure."""
    
    def test_alert_creation(self):
        """Test creating alert with all parameters."""
        threshold = create_mock_alert_threshold()
        first_breach = datetime.utcnow() - timedelta(minutes=5)
        last_breach = datetime.utcnow()
        
        alert = Alert(
            id="test_alert_123",
            threshold=threshold,
            current_value=1500.0,
            breach_count=3,
            first_breach_time=first_breach,
            last_breach_time=last_breach,
            resolved=False
        )
        
        assert alert.id == "test_alert_123"
        assert alert.threshold == threshold
        assert alert.current_value == 1500.0
        assert alert.breach_count == 3
        assert alert.first_breach_time == first_breach
        assert alert.last_breach_time == last_breach
        assert alert.resolved is False
        assert alert.resolved_time is None
    
    def test_alert_resolved(self):
        """Test resolved alert."""
        alert = create_mock_alert(resolved=True)
        
        assert alert.resolved is True
        assert alert.resolved_time is not None
        assert isinstance(alert.resolved_time, datetime)


class TestMetricsStorage:
    """Test MetricsStorage functionality."""
    
    def test_storage_creation(self):
        """Test creating metrics storage."""
        storage = MetricsStorage(retention_hours=48, max_metrics_per_endpoint=5000)
        assert storage.retention_hours == 48
        assert storage.max_metrics_per_endpoint == 5000
    
    def test_add_and_get_metric(self):
        """Test adding and retrieving metrics."""
        storage = MetricsStorage()
        metric = create_mock_performance_metric("test_metric", 100.0)
        
        storage.add_metric("/test", metric)
        
        metrics = storage.get_metrics("/test")
        assert len(metrics) == 1
        assert metrics[0] == metric
    
    def test_add_and_get_resource_usage(self):
        """Test adding and retrieving resource usage."""
        storage = MetricsStorage()
        usage = create_mock_resource_usage(cpu_percent=75.0)
        
        storage.add_resource_usage(usage)
        
        usage_data = storage.get_resource_usage()
        assert len(usage_data) == 1
        assert usage_data[0] == usage
    
    def test_get_metrics_with_time_range(self):
        """Test getting metrics within time range."""
        storage = MetricsStorage()
        
        # Add metrics with different timestamps
        old_time = datetime.utcnow() - timedelta(hours=2)
        new_time = datetime.utcnow()
        
        old_metric = create_mock_performance_metric("old_metric", 50.0)
        old_metric.timestamp = old_time
        
        new_metric = create_mock_performance_metric("new_metric", 100.0)
        new_metric.timestamp = new_time
        
        storage.add_metric("/test", old_metric)
        storage.add_metric("/test", new_metric)
        
        # Get metrics from last hour
        start_time = datetime.utcnow() - timedelta(hours=1)
        recent_metrics = storage.get_metrics("/test", start_time=start_time)
        
        assert len(recent_metrics) == 1
        assert recent_metrics[0].name == "new_metric"
    
    def test_get_statistics(self):
        """Test getting metric statistics."""
        storage = MetricsStorage()
        
        # Add multiple metrics with same name
        values = [100.0, 150.0, 200.0, 250.0, 300.0]
        for value in values:
            metric = create_mock_performance_metric("response_time", value)
            storage.add_metric("/test", metric)
        
        stats = storage.get_statistics("/test", "response_time", window_minutes=60)
        
        assert stats["count"] == 5
        assert stats["min"] == 100.0
        assert stats["max"] == 300.0
        assert stats["mean"] == 200.0
        assert stats["median"] == 200.0
        assert stats["p95"] == 250.0  # 95th percentile of [100,150,200,250,300] is 250
        assert stats["p99"] == 250.0  # 99th percentile with only 5 values is also 250
        assert stats["stddev"] > 0
    
    def test_get_statistics_empty(self):
        """Test getting statistics with no data."""
        storage = MetricsStorage()
        
        stats = storage.get_statistics("/test", "nonexistent_metric")
        
        assert stats["count"] == 0
    
    def test_metrics_max_limit(self):
        """Test metrics maximum limit per endpoint."""
        storage = MetricsStorage(max_metrics_per_endpoint=3)
        
        # Add more metrics than the limit
        for i in range(5):
            metric = create_mock_performance_metric(f"metric_{i}", i * 10)
            storage.add_metric("/test", metric)
        
        metrics = storage.get_metrics("/test")
        
        # Should only keep the maximum number
        assert len(metrics) <= 3


class TestResourceMonitor:
    """Test ResourceMonitor functionality."""
    
    def test_resource_monitor_creation(self):
        """Test creating resource monitor."""
        monitor = ResourceMonitor(collection_interval=60)
        assert monitor.collection_interval == 60
    
    def test_add_callback(self):
        """Test adding callback to resource monitor."""
        monitor = ResourceMonitor()
        callback_called = []
        
        def test_callback(usage):
            callback_called.append(usage)
        
        monitor.add_callback(test_callback)
        
        # Simulate callback execution
        usage = create_mock_resource_usage()
        for callback in monitor._callbacks:
            callback(usage)
        
        assert len(callback_called) == 1
        assert callback_called[0] == usage
    
    def test_start_stop_monitoring(self):
        """Test starting and stopping resource monitoring."""
        monitor = ResourceMonitor(collection_interval=1)  # Short interval for testing
        
        assert not monitor._running
        
        monitor.start()
        assert monitor._running
        
        monitor.stop()
        assert not monitor._running
    
    def test_collect_resource_usage(self):
        """Test collecting resource usage."""
        from fastapi_shield.performance_monitoring import PSUTIL_AVAILABLE
        
        monitor = ResourceMonitor()
        usage = monitor._collect_resource_usage()
        
        # When psutil is not available, should return zero values
        if not PSUTIL_AVAILABLE:
            assert usage.cpu_percent == 0.0
            assert usage.memory_percent == 0.0
            assert usage.memory_used_mb == 0.0
            assert usage.disk_io_read_mb == 0.0
            assert usage.disk_io_write_mb == 0.0
            assert usage.network_sent_mb == 0.0
            assert usage.network_recv_mb == 0.0
        else:
            # When psutil is available, values should be non-negative
            assert usage.cpu_percent >= 0.0
            assert usage.memory_percent >= 0.0
            assert usage.memory_used_mb >= 0.0
            assert usage.disk_io_read_mb >= 0.0
            assert usage.disk_io_write_mb >= 0.0
            assert usage.network_sent_mb >= 0.0
            assert usage.network_recv_mb >= 0.0


class TestAlertManager:
    """Test AlertManager functionality."""
    
    def test_alert_manager_creation(self):
        """Test creating alert manager."""
        manager = AlertManager()
        assert len(manager.thresholds) == 0
        assert len(manager.active_alerts) == 0
        assert len(manager.alert_history) == 0
    
    def test_add_remove_threshold(self):
        """Test adding and removing thresholds."""
        manager = AlertManager()
        threshold = create_mock_alert_threshold("test_metric")
        
        manager.add_threshold(threshold)
        assert "test_metric" in manager.thresholds
        assert manager.thresholds["test_metric"] == threshold
        
        manager.remove_threshold("test_metric")
        assert "test_metric" not in manager.thresholds
    
    def test_check_thresholds_breach(self):
        """Test checking thresholds with breach."""
        manager = AlertManager()
        
        # Add threshold: response_time > 1000ms
        threshold = AlertThreshold(
            metric_name="response_time",
            threshold_value=1000.0,
            comparison="greater_than",
            severity=AlertSeverity.HIGH,
            consecutive_breaches=1  # Immediate alert
        )
        manager.add_threshold(threshold)
        
        # Create metric that breaches threshold
        metric = create_mock_performance_metric("response_time", 1500.0)
        
        alerts = manager.check_thresholds([metric])
        
        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.threshold.metric_name == "response_time"
        assert alert.current_value == 1500.0
        assert not alert.resolved
    
    def test_check_thresholds_no_breach(self):
        """Test checking thresholds without breach."""
        manager = AlertManager()
        
        threshold = create_mock_alert_threshold("response_time", 1000.0)
        manager.add_threshold(threshold)
        
        # Create metric that doesn't breach threshold
        metric = create_mock_performance_metric("response_time", 500.0)
        
        alerts = manager.check_thresholds([metric])
        
        assert len(alerts) == 0
    
    def test_check_thresholds_resolve_alert(self):
        """Test resolving alerts when threshold is no longer breached."""
        manager = AlertManager()
        
        threshold = AlertThreshold(
            metric_name="response_time",
            threshold_value=1000.0,
            comparison="greater_than",
            severity=AlertSeverity.HIGH,
            consecutive_breaches=1
        )
        manager.add_threshold(threshold)
        
        # First: breach threshold
        breach_metric = create_mock_performance_metric("response_time", 1500.0)
        alerts = manager.check_thresholds([breach_metric])
        
        assert len(alerts) == 1
        assert not alerts[0].resolved
        assert "response_time" in manager.active_alerts
        
        # Then: no longer breach threshold
        normal_metric = create_mock_performance_metric("response_time", 500.0)
        alerts = manager.check_thresholds([normal_metric])
        
        assert len(alerts) == 1
        assert alerts[0].resolved
        assert "response_time" not in manager.active_alerts
        assert len(manager.alert_history) == 1
    
    def test_get_active_alerts(self):
        """Test getting active alerts."""
        manager = AlertManager()
        alert = create_mock_alert("test_metric")
        
        manager.active_alerts["test_metric"] = alert
        
        active_alerts = manager.get_active_alerts()
        assert len(active_alerts) == 1
        assert active_alerts[0] == alert
    
    def test_get_alert_history(self):
        """Test getting alert history."""
        manager = AlertManager()
        
        # Add alert to history
        old_alert = create_mock_alert("old_metric", resolved=True)
        old_alert.first_breach_time = datetime.utcnow() - timedelta(hours=2)
        
        recent_alert = create_mock_alert("recent_metric", resolved=True)
        recent_alert.first_breach_time = datetime.utcnow() - timedelta(minutes=30)
        
        manager.alert_history = [old_alert, recent_alert]
        
        # Get history for last 1 hour
        recent_history = manager.get_alert_history(hours=1)
        
        assert len(recent_history) == 1
        assert recent_history[0] == recent_alert
    
    def test_threshold_breach_comparison_types(self):
        """Test different threshold comparison types."""
        manager = AlertManager()
        
        # Test "less_than" comparison
        threshold = AlertThreshold(
            metric_name="memory_available",
            threshold_value=1000.0,
            comparison="less_than",
            severity=AlertSeverity.CRITICAL,
            consecutive_breaches=1
        )
        
        # Breach: memory_available < 1000
        breach_value = manager._check_threshold_breach(500.0, threshold)
        assert breach_value is True
        
        # No breach: memory_available >= 1000
        no_breach_value = manager._check_threshold_breach(1500.0, threshold)
        assert no_breach_value is False
        
        # Test "equal_to" comparison
        threshold.comparison = "equal_to"
        threshold.threshold_value = 100.0
        
        equal_value = manager._check_threshold_breach(100.0, threshold)
        assert equal_value is True
        
        not_equal_value = manager._check_threshold_breach(99.0, threshold)
        assert not_equal_value is False


class TestMonitoringProviders:
    """Test monitoring service providers."""
    
    def test_mock_provider_default_behavior(self):
        """Test mock provider with default settings."""
        provider = MockMonitoringProvider()
        
        # Test metric sending
        metric = create_mock_performance_metric()
        result = asyncio.run(provider.send_metric(metric))
        
        assert result is True
        assert len(provider.sent_metrics) == 1
        assert provider.metric_call_count == 1
        
        # Test alert sending
        alert = create_mock_alert()
        result = asyncio.run(provider.send_alert(alert))
        
        assert result is True
        assert len(provider.sent_alerts) == 1
        assert provider.alert_call_count == 1
        
        # Test health check
        result = asyncio.run(provider.health_check())
        assert result is True
        assert provider.health_check_call_count == 1
    
    @pytest.mark.asyncio
    async def test_mock_provider_failure_mode(self):
        """Test mock provider in failure mode."""
        provider = MockMonitoringProvider(
            send_metric_success=False,
            send_alert_success=False,
            health_status=False
        )
        
        metric = create_mock_performance_metric()
        result = await provider.send_metric(metric)
        assert result is False
        assert len(provider.sent_metrics) == 0
        
        alert = create_mock_alert()
        result = await provider.send_alert(alert)
        assert result is False
        assert len(provider.sent_alerts) == 0
        
        result = await provider.health_check()
        assert result is False
    
    @pytest.mark.asyncio
    async def test_mock_provider_exception_handling(self):
        """Test mock provider exception handling."""
        provider = MockMonitoringProvider(should_raise_exception=True)
        
        with pytest.raises(Exception, match="Mock metric sending exception"):
            await provider.send_metric(create_mock_performance_metric())
        
        with pytest.raises(Exception, match="Mock alert sending exception"):
            await provider.send_alert(create_mock_alert())
        
        with pytest.raises(Exception, match="Mock health check exception"):
            await provider.health_check()
    
    @pytest.mark.asyncio
    async def test_mock_provider_tracking(self):
        """Test mock provider tracking capabilities."""
        provider = MockMonitoringProvider()
        
        # Send different metrics
        metric1 = create_mock_performance_metric("metric1", 100.0)
        metric2 = create_mock_performance_metric("metric2", 200.0)
        
        await provider.send_metric(metric1)
        await provider.send_metric(metric2)
        
        # Test tracking methods
        assert len(provider.get_metrics_by_name("metric1")) == 1
        assert len(provider.get_metrics_by_name("metric2")) == 1
        assert len(provider.get_metrics_by_name("nonexistent")) == 0
        
        # Test label filtering
        test_metrics = provider.get_metrics_by_labels({"endpoint": "/test"})
        assert len(test_metrics) == 2  # Both have default test endpoint label
    
    def test_prometheus_provider_creation(self):
        """Test Prometheus provider creation."""
        provider = PrometheusProvider(
            pushgateway_url="http://localhost:9091",
            job_name="test-job",
            basic_auth=("user", "pass")
        )
        
        assert provider.pushgateway_url == "http://localhost:9091"
        assert provider.job_name == "test-job"
        assert provider.basic_auth == ("user", "pass")
    
    @pytest.mark.asyncio
    @patch('httpx.AsyncClient.post')
    async def test_prometheus_send_metric_success(self, mock_post):
        """Test successful Prometheus metric sending."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response
        
        provider = PrometheusProvider("http://localhost:9091")
        metric = create_mock_performance_metric("test_metric", 123.45)
        
        result = await provider.send_metric(metric)
        
        assert result is True
        mock_post.assert_called_once()
        
        # Verify the call arguments contain Prometheus format
        call_args = mock_post.call_args
        assert "test_metric" in call_args.kwargs["content"]
        assert "123.45" in call_args.kwargs["content"]
    
    @pytest.mark.asyncio
    @patch('httpx.AsyncClient.post')
    async def test_prometheus_send_metric_failure(self, mock_post):
        """Test failed Prometheus metric sending."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_post.return_value = mock_response
        
        provider = PrometheusProvider("http://localhost:9091")
        metric = create_mock_performance_metric()
        
        result = await provider.send_metric(metric)
        
        assert result is False
    
    def test_datadog_provider_creation(self):
        """Test DataDog provider creation."""
        provider = DataDogProvider(
            api_key="test_api_key",
            app_key="test_app_key",
            api_url="https://api.datadoghq.eu"
        )
        
        assert provider.api_key == "test_api_key"
        assert provider.app_key == "test_app_key"
        assert provider.api_url == "https://api.datadoghq.eu"
    
    @pytest.mark.asyncio
    @patch('httpx.AsyncClient.post')
    async def test_datadog_send_metric_success(self, mock_post):
        """Test successful DataDog metric sending."""
        mock_response = Mock()
        mock_response.status_code = 202
        mock_post.return_value = mock_response
        
        provider = DataDogProvider("api_key", "app_key")
        metric = create_mock_performance_metric("datadog.test.metric", 456.78)
        
        result = await provider.send_metric(metric)
        
        assert result is True
        mock_post.assert_called_once()
        
        # Verify the call includes DataDog format
        call_args = mock_post.call_args
        json_data = call_args.kwargs["json"]
        assert "series" in json_data
        assert len(json_data["series"]) == 1
        assert json_data["series"][0]["metric"] == "datadog.test.metric"
    
    def test_newrelic_provider_creation(self):
        """Test New Relic provider creation."""
        provider = NewRelicProvider(
            license_key="test_license",
            account_id="123456"
        )
        
        assert provider.license_key == "test_license"
        assert provider.account_id == "123456"
    
    @pytest.mark.asyncio
    @patch('httpx.AsyncClient.post')
    async def test_newrelic_send_metric_success(self, mock_post):
        """Test successful New Relic metric sending."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response
        
        provider = NewRelicProvider("license_key", "account_id")
        metric = create_mock_performance_metric("newrelic.test.metric", 789.12)
        
        result = await provider.send_metric(metric)
        
        assert result is True
        mock_post.assert_called_once()
        
        # Verify New Relic format
        call_args = mock_post.call_args
        json_data = call_args.kwargs["json"]
        assert isinstance(json_data, list)
        assert len(json_data) == 1
        assert "metrics" in json_data[0]
    
    @pytest.mark.asyncio
    async def test_custom_provider_sync_callback(self):
        """Test custom provider with synchronous callback."""
        metrics_received = []
        
        def metric_callback(metric):
            metrics_received.append(metric)
            return True
        
        provider = CustomProvider(metric_callback=metric_callback)
        metric = create_mock_performance_metric()
        
        result = await provider.send_metric(metric)
        
        assert result is True
        assert len(metrics_received) == 1
        assert metrics_received[0] == metric
    
    @pytest.mark.asyncio
    async def test_custom_provider_async_callback(self):
        """Test custom provider with asynchronous callback."""
        alerts_received = []
        
        async def alert_callback(alert):
            await asyncio.sleep(0.01)  # Simulate async work
            alerts_received.append(alert)
            return True
        
        provider = CustomProvider(
            metric_callback=lambda m: True,
            alert_callback=alert_callback
        )
        alert = create_mock_alert()
        
        result = await provider.send_alert(alert)
        
        assert result is True
        assert len(alerts_received) == 1
        assert alerts_received[0] == alert
    
    @pytest.mark.asyncio
    async def test_custom_provider_callback_exception(self):
        """Test custom provider callback exception handling."""
        def failing_callback(metric):
            raise ValueError("Callback failed")
        
        provider = CustomProvider(metric_callback=failing_callback)
        metric = create_mock_performance_metric()
        
        result = await provider.send_metric(metric)
        
        assert result is False


class TestPerformanceMonitoringConfig:
    """Test PerformanceMonitoringConfig."""
    
    def test_config_creation_with_defaults(self):
        """Test config creation with default values."""
        providers = [MockMonitoringProvider()]
        config = PerformanceMonitoringConfig(providers=providers)
        
        assert config.providers == providers
        assert config.thresholds == []
        assert config.collect_resource_usage is True
        assert config.resource_collection_interval == 30
        assert config.metrics_retention_hours == 24
        assert config.send_metrics_async is True
        assert config.exclude_endpoints == []
    
    def test_config_creation_with_custom_values(self):
        """Test config creation with custom values."""
        providers = [MockMonitoringProvider()]
        thresholds = [create_mock_alert_threshold()]
        
        config = PerformanceMonitoringConfig(
            providers=providers,
            thresholds=thresholds,
            collect_resource_usage=False,
            resource_collection_interval=60,
            metrics_retention_hours=48,
            send_metrics_async=False,
            exclude_endpoints=["/health", "/metrics"],
            include_request_body_size=False,
            include_response_body_size=False,
            track_user_metrics=False
        )
        
        assert config.providers == providers
        assert config.thresholds == thresholds
        assert config.collect_resource_usage is False
        assert config.resource_collection_interval == 60
        assert config.metrics_retention_hours == 48
        assert config.send_metrics_async is False
        assert config.exclude_endpoints == ["/health", "/metrics"]
        assert config.include_request_body_size is False
        assert config.include_response_body_size is False
        assert config.track_user_metrics is False


class TestPerformanceMonitoringShield:
    """Test PerformanceMonitoringShield functionality."""
    
    def test_shield_creation(self):
        """Test creating performance monitoring shield."""
        provider = MockMonitoringProvider()
        config = PerformanceMonitoringConfig(providers=[provider])
        shield = PerformanceMonitoringShield(config)
        
        assert shield.config == config
        assert isinstance(shield.storage, MetricsStorage)
        assert isinstance(shield.alert_manager, AlertManager)
        assert isinstance(shield.resource_monitor, ResourceMonitor)
    
    def test_shield_creation_with_thresholds(self):
        """Test creating shield with alert thresholds."""
        provider = MockMonitoringProvider()
        threshold = create_mock_alert_threshold()
        config = PerformanceMonitoringConfig(
            providers=[provider],
            thresholds=[threshold]
        )
        shield = PerformanceMonitoringShield(config)
        
        assert len(shield.alert_manager.thresholds) == 1
        assert "test_metric" in shield.alert_manager.thresholds
    
    @pytest.mark.asyncio
    async def test_shield_function_basic_operation(self):
        """Test basic shield function operation."""
        provider = MockMonitoringProvider()
        config = PerformanceMonitoringConfig(providers=[provider])
        shield = PerformanceMonitoringShield(config)
        
        request = create_mock_request()
        
        result = await shield._shield_function(request)
        
        assert result is not None
        assert "performance_monitoring" in result
        
        perf_data = result["performance_monitoring"]
        assert "start_time" in perf_data
        assert perf_data["endpoint"] == "/api/test"
        assert perf_data["method"] == "GET"
        assert "labels" in perf_data
    
    @pytest.mark.asyncio
    async def test_shield_function_excluded_endpoint(self):
        """Test shield function with excluded endpoint."""
        provider = MockMonitoringProvider()
        config = PerformanceMonitoringConfig(
            providers=[provider],
            exclude_endpoints=["/health", "/metrics"]
        )
        shield = PerformanceMonitoringShield(config)
        
        request = create_mock_request(path="/health")
        
        result = await shield._shield_function(request)
        
        # Should return None for excluded endpoints
        assert result is None
    
    def test_extract_labels_default(self):
        """Test default label extraction."""
        provider = MockMonitoringProvider()
        config = PerformanceMonitoringConfig(providers=[provider])
        shield = PerformanceMonitoringShield(config)
        
        request = create_mock_request(
            method="POST",
            path="/api/users",
            user_id="user123"
        )
        
        labels = shield._extract_labels(request)
        
        assert labels["method"] == "POST"
        assert labels["endpoint"] == "/api/users"
        assert labels["host"] == "localhost"
        assert labels["user_id"] == "user123"
    
    def test_extract_labels_custom(self):
        """Test custom label extraction."""
        provider = MockMonitoringProvider()
        
        def extract_version(request):
            return request.headers.get("api-version", "v1")
        
        config = PerformanceMonitoringConfig(
            providers=[provider],
            custom_labels={"version": extract_version}
        )
        shield = PerformanceMonitoringShield(config)
        
        request = create_mock_request()
        request.headers["api-version"] = "v2"
        
        labels = shield._extract_labels(request)
        
        assert labels["version"] == "v2"
    
    def test_extract_labels_anonymous_user(self):
        """Test label extraction with anonymous user."""
        provider = MockMonitoringProvider()
        config = PerformanceMonitoringConfig(providers=[provider])
        shield = PerformanceMonitoringShield(config)
        
        request = create_mock_request(user_id=None)
        request.headers = {"host": "example.com"}
        
        labels = shield._extract_labels(request)
        
        assert labels["user_id"] == "anonymous"
        assert labels["host"] == "example.com"
    
    @pytest.mark.asyncio
    async def test_record_response_metrics(self):
        """Test recording response metrics."""
        provider = MockMonitoringProvider()
        config = PerformanceMonitoringConfig(
            providers=[provider],
            send_metrics_async=False  # Immediate sending for testing
        )
        shield = PerformanceMonitoringShield(config)
        
        # Set up request state (normally done by shield function)
        request = create_mock_request(path="/test")
        request.state.performance_start_time = time.time() - 0.1  # 100ms ago
        request.state.performance_start_memory = 1024 * 1024 * 1024  # 1GB
        request.state.performance_labels = {"endpoint": "/test", "method": "GET"}
        request.state.performance_request_body_size = 512
        
        response = create_mock_response(status_code=200)
        
        await shield.record_response_metrics(request, response)
        
        # Verify metrics were stored locally
        metrics = shield.storage.get_metrics("/test")
        assert len(metrics) > 0
        
        # Find response time metric
        response_time_metrics = [m for m in metrics if m.name == "http_request_duration_ms"]
        assert len(response_time_metrics) == 1
        assert response_time_metrics[0].value >= 100  # At least 100ms
        
        # Verify metrics were sent to provider
        assert provider.metric_call_count > 0
        assert len(provider.sent_metrics) > 0
    
    @pytest.mark.asyncio
    async def test_record_response_metrics_with_alert(self):
        """Test recording response metrics that trigger alerts."""
        provider = MockMonitoringProvider()
        
        # Set up threshold that will be breached
        threshold = AlertThreshold(
            metric_name="http_request_duration_ms",
            threshold_value=50.0,
            comparison="greater_than",
            severity=AlertSeverity.HIGH,
            consecutive_breaches=1
        )
        
        config = PerformanceMonitoringConfig(
            providers=[provider],
            thresholds=[threshold],
            send_metrics_async=False
        )
        shield = PerformanceMonitoringShield(config)
        
        # Set up request with slow response time
        request = create_mock_request()
        request.state.performance_start_time = time.time() - 0.2  # 200ms ago (breaches 50ms threshold)
        request.state.performance_start_memory = 0
        request.state.performance_labels = {"endpoint": "/test", "method": "GET"}
        request.state.performance_request_body_size = 0
        
        response = create_mock_response()
        
        await shield.record_response_metrics(request, response)
        
        # Verify alert was generated
        active_alerts = shield.alert_manager.get_active_alerts()
        assert len(active_alerts) == 1
        
        alert = active_alerts[0]
        assert alert.threshold.metric_name == "http_request_duration_ms"
        assert alert.current_value >= 200  # Response time was ~200ms
        
        # Verify alert was sent to provider
        assert len(provider.sent_alerts) == 1
    
    @pytest.mark.asyncio
    async def test_get_metrics(self):
        """Test getting metrics from shield."""
        provider = MockMonitoringProvider()
        config = PerformanceMonitoringConfig(providers=[provider])
        shield = PerformanceMonitoringShield(config)
        
        # Add some test metrics
        metric1 = create_mock_performance_metric("metric1", 100.0)
        metric2 = create_mock_performance_metric("metric2", 200.0)
        shield.storage.add_metric("/test", metric1)
        shield.storage.add_metric("/test", metric2)
        
        metrics = shield.get_metrics("/test")
        
        assert len(metrics) == 2
        assert metric1 in metrics
        assert metric2 in metrics
    
    @pytest.mark.asyncio
    async def test_get_statistics(self):
        """Test getting statistics from shield."""
        provider = MockMonitoringProvider()
        config = PerformanceMonitoringConfig(providers=[provider])
        shield = PerformanceMonitoringShield(config)
        
        # Add test metrics
        values = [100.0, 200.0, 300.0]
        for value in values:
            metric = create_mock_performance_metric("response_time", value)
            shield.storage.add_metric("/test", metric)
        
        stats = shield.get_statistics("/test", "response_time")
        
        assert stats["count"] == 3
        assert stats["min"] == 100.0
        assert stats["max"] == 300.0
        assert stats["mean"] == 200.0
    
    def test_add_remove_threshold(self):
        """Test adding and removing thresholds from shield."""
        provider = MockMonitoringProvider()
        config = PerformanceMonitoringConfig(providers=[provider])
        shield = PerformanceMonitoringShield(config)
        
        threshold = create_mock_alert_threshold("new_metric")
        
        shield.add_threshold(threshold)
        assert "new_metric" in shield.alert_manager.thresholds
        
        shield.remove_threshold("new_metric")
        assert "new_metric" not in shield.alert_manager.thresholds


class TestConvenienceFunctions:
    """Test convenience functions for creating shields."""
    
    def test_performance_monitoring_shield_creation(self):
        """Test generic performance monitoring shield creation."""
        providers = [MockMonitoringProvider()]
        thresholds = [create_mock_alert_threshold()]
        
        shield = performance_monitoring_shield(
            providers=providers,
            thresholds=thresholds,
            collect_resource_usage=False,
            metrics_retention_hours=48,
            send_metrics_async=False
        )
        
        assert isinstance(shield, PerformanceMonitoringShield)
        assert shield.config.providers == providers
        assert shield.config.thresholds == thresholds
        assert shield.config.collect_resource_usage is False
        assert shield.config.metrics_retention_hours == 48
        assert shield.config.send_metrics_async is False
    
    def test_prometheus_performance_shield_creation(self):
        """Test Prometheus performance shield creation."""
        shield = prometheus_performance_shield(
            pushgateway_url="http://localhost:9091",
            job_name="test-job",
            basic_auth=("user", "pass")
        )
        
        assert isinstance(shield, PerformanceMonitoringShield)
        assert len(shield.config.providers) == 1
        assert isinstance(shield.config.providers[0], PrometheusProvider)
        assert shield.config.providers[0].pushgateway_url == "http://localhost:9091"
        assert shield.config.providers[0].job_name == "test-job"
        assert shield.config.providers[0].basic_auth == ("user", "pass")
    
    def test_datadog_performance_shield_creation(self):
        """Test DataDog performance shield creation."""
        shield = datadog_performance_shield(
            api_key="test_api_key",
            app_key="test_app_key",
            api_url="https://api.datadoghq.eu"
        )
        
        assert isinstance(shield, PerformanceMonitoringShield)
        assert len(shield.config.providers) == 1
        assert isinstance(shield.config.providers[0], DataDogProvider)
        assert shield.config.providers[0].api_key == "test_api_key"
        assert shield.config.providers[0].app_key == "test_app_key"
        assert shield.config.providers[0].api_url == "https://api.datadoghq.eu"
    
    def test_newrelic_performance_shield_creation(self):
        """Test New Relic performance shield creation."""
        shield = newrelic_performance_shield(
            license_key="test_license",
            account_id="123456"
        )
        
        assert isinstance(shield, PerformanceMonitoringShield)
        assert len(shield.config.providers) == 1
        assert isinstance(shield.config.providers[0], NewRelicProvider)
        assert shield.config.providers[0].license_key == "test_license"
        assert shield.config.providers[0].account_id == "123456"
    
    def test_multi_provider_performance_shield_creation(self):
        """Test multi-provider performance shield creation."""
        shield = multi_provider_performance_shield(
            prometheus_config={
                "pushgateway_url": "http://localhost:9091",
                "job_name": "multi-test"
            },
            datadog_config={
                "api_key": "dd_key",
                "app_key": "dd_app_key"
            },
            newrelic_config={
                "license_key": "nr_license",
                "account_id": "nr_account"
            }
        )
        
        assert isinstance(shield, PerformanceMonitoringShield)
        assert len(shield.config.providers) == 3
        
        # Check provider types
        provider_types = [type(p).__name__ for p in shield.config.providers]
        assert "PrometheusProvider" in provider_types
        assert "DataDogProvider" in provider_types
        assert "NewRelicProvider" in provider_types
    
    def test_multi_provider_shield_empty_config_error(self):
        """Test multi-provider shield with no providers raises error."""
        with pytest.raises(ValueError, match="At least one monitoring provider must be configured"):
            multi_provider_performance_shield()


class TestIntegration:
    """Integration tests with FastAPI."""
    
    def test_performance_monitoring_integration(self):
        """Test performance monitoring integration with FastAPI."""
        app = FastAPI()
        
        provider = MockMonitoringProvider()
        shield = performance_monitoring_shield(
            providers=[provider],
            send_metrics_async=False  # Immediate sending for testing
        )
        
        @app.get("/api/test")
        @shield
        def test_endpoint():
            return {"message": "success"}
        
        client = TestClient(app)
        
        response = client.get("/api/test", headers={"x-user-id": "test_user"})
        
        assert response.status_code == 200
        assert response.json() == {"message": "success"}
        
        # Verify metrics were collected (need to manually trigger response recording)
        # Note: In real FastAPI, this would be done by middleware
    
    def test_performance_monitoring_with_middleware_simulation(self):
        """Test performance monitoring with simulated middleware behavior."""
        provider = MockMonitoringProvider()
        shield = performance_monitoring_shield(
            providers=[provider],
            send_metrics_async=False
        )
        
        async def simulate_request_response():
            # Simulate request processing
            request = create_mock_request(path="/api/users", method="POST")
            
            # Shield function (before endpoint)
            shield_result = await shield._shield_function(request)
            assert shield_result is not None
            
            # Simulate endpoint processing time
            await asyncio.sleep(0.05)  # 50ms
            
            # Simulate response
            response = create_mock_response(status_code=201)
            
            # Record response metrics (after endpoint)
            await shield.record_response_metrics(request, response)
            
            return response
        
        # Run simulation
        response = asyncio.run(simulate_request_response())
        
        assert response.status_code == 201
        
        # Verify metrics were sent
        assert provider.metric_call_count > 0
        
        # Check specific metrics
        duration_metrics = provider.get_metrics_by_name("http_request_duration_ms")
        assert len(duration_metrics) == 1
        assert duration_metrics[0].value >= 50  # At least 50ms
        
        counter_metrics = provider.get_metrics_by_name("http_requests_total")
        assert len(counter_metrics) == 1
        assert counter_metrics[0].value == 1


class TestAdvancedFeatures:
    """Test advanced performance monitoring features."""
    
    @pytest.mark.asyncio
    async def test_concurrent_metric_collection(self):
        """Test concurrent metric collection."""
        provider = MockMonitoringProvider()
        config = PerformanceMonitoringConfig(
            providers=[provider],
            send_metrics_async=False
        )
        shield = PerformanceMonitoringShield(config)
        
        # Create multiple concurrent requests
        async def process_request(request_id):
            request = create_mock_request(path=f"/api/request_{request_id}")
            
            # Start shield processing
            await shield._shield_function(request)
            
            # Simulate some processing time
            await asyncio.sleep(0.01)
            
            # Record response
            response = create_mock_response()
            await shield.record_response_metrics(request, response)
            
            return request_id
        
        # Process 10 concurrent requests
        tasks = [process_request(i) for i in range(10)]
        results = await asyncio.gather(*tasks)
        
        assert len(results) == 10
        
        # Verify all metrics were collected
        total_metrics_sent = provider.metric_call_count
        assert total_metrics_sent >= 10  # At least one metric per request
    
    @pytest.mark.asyncio
    async def test_batch_metric_sending(self):
        """Test batch metric sending functionality."""
        provider = MockMonitoringProvider(response_delay=0.01)  # Slow provider
        config = PerformanceMonitoringConfig(
            providers=[provider],
            send_metrics_async=True,
            batch_size=5,
            batch_timeout_seconds=1
        )
        shield = PerformanceMonitoringShield(config)
        
        # Add metrics to batch
        for i in range(3):
            metrics = [
                create_mock_performance_metric(f"metric_{i}_{j}", j * 10)
                for j in range(2)
            ]
            shield._add_to_batch(metrics)
        
        # Wait for batch processing
        await asyncio.sleep(0.1)
        
        # Check that batch was accumulated
        assert len(shield._metric_batch) == 6  # 3 * 2 metrics
    
    def test_resource_usage_tracking(self):
        """Test resource usage tracking."""
        provider = MockMonitoringProvider()
        config = PerformanceMonitoringConfig(
            providers=[provider],
            collect_resource_usage=False  # Disable automatic collection for testing
        )
        shield = PerformanceMonitoringShield(config)
        
        # Simulate resource usage data
        usage = create_mock_resource_usage(
            cpu_percent=85.0,
            memory_percent=70.0,
            memory_used_mb=4096.0
        )
        
        shield.storage.add_resource_usage(usage)
        
        # Retrieve resource usage data
        usage_data = shield.get_resource_usage()
        
        assert len(usage_data) == 1
        assert usage_data[0].cpu_percent == 85.0
        assert usage_data[0].memory_percent == 70.0
        assert usage_data[0].memory_used_mb == 4096.0
    
    @pytest.mark.asyncio
    async def test_alert_lifecycle(self):
        """Test complete alert lifecycle."""
        provider = MockMonitoringProvider()
        
        # Set up threshold
        threshold = AlertThreshold(
            metric_name="error_rate",
            threshold_value=5.0,  # 5% error rate
            comparison="greater_than",
            severity=AlertSeverity.CRITICAL,
            consecutive_breaches=1
        )
        
        config = PerformanceMonitoringConfig(
            providers=[provider],
            thresholds=[threshold],
            send_metrics_async=False
        )
        shield = PerformanceMonitoringShield(config)
        
        # 1. Trigger alert with high error rate
        high_error_metric = create_mock_performance_metric("error_rate", 10.0)
        alerts = shield.alert_manager.check_thresholds([high_error_metric])
        
        assert len(alerts) == 1
        alert = alerts[0]
        assert not alert.resolved
        assert alert.current_value == 10.0
        
        # Send alert
        await shield._send_alert(alert)
        assert len(provider.sent_alerts) == 1
        
        # 2. Resolve alert with normal error rate
        normal_error_metric = create_mock_performance_metric("error_rate", 2.0)
        alerts = shield.alert_manager.check_thresholds([normal_error_metric])
        
        assert len(alerts) == 1
        resolved_alert = alerts[0]
        assert resolved_alert.resolved
        assert resolved_alert.resolved_time is not None
        
        # Send resolved alert
        await shield._send_alert(resolved_alert)
        assert len(provider.sent_alerts) == 2  # Original + resolved
    
    def test_custom_labels_with_exception(self):
        """Test custom label extraction with exception handling."""
        provider = MockMonitoringProvider()
        
        def failing_extractor(request):
            raise ValueError("Extractor failed")
        
        config = PerformanceMonitoringConfig(
            providers=[provider],
            custom_labels={"custom_field": failing_extractor}
        )
        shield = PerformanceMonitoringShield(config)
        
        request = create_mock_request()
        labels = shield._extract_labels(request)
        
        # Should handle exception gracefully
        assert "custom_field" in labels
        assert labels["custom_field"] == "error"
    
    def test_metrics_storage_time_filtering(self):
        """Test metrics storage time-based filtering."""
        storage = MetricsStorage()
        
        # Add metrics with different timestamps
        now = datetime.utcnow()
        hour_ago = now - timedelta(hours=1)
        day_ago = now - timedelta(days=1)
        
        recent_metric = create_mock_performance_metric("recent", 100.0)
        recent_metric.timestamp = now
        
        hour_old_metric = create_mock_performance_metric("hour_old", 200.0)
        hour_old_metric.timestamp = hour_ago
        
        day_old_metric = create_mock_performance_metric("day_old", 300.0)
        day_old_metric.timestamp = day_ago
        
        storage.add_metric("/test", recent_metric)
        storage.add_metric("/test", hour_old_metric)
        storage.add_metric("/test", day_old_metric)
        
        # Get metrics from last 2 hours
        start_time = now - timedelta(hours=2)
        recent_metrics = storage.get_metrics("/test", start_time=start_time)
        
        assert len(recent_metrics) == 2
        metric_names = [m.name for m in recent_metrics]
        assert "recent" in metric_names
        assert "hour_old" in metric_names
        assert "day_old" not in metric_names
    
    @pytest.mark.asyncio
    async def test_provider_health_check_integration(self):
        """Test provider health check integration."""
        # Healthy provider
        healthy_provider = MockMonitoringProvider(health_status=True)
        
        # Unhealthy provider
        unhealthy_provider = MockMonitoringProvider(health_status=False)
        
        config = PerformanceMonitoringConfig(
            providers=[healthy_provider, unhealthy_provider]
        )
        shield = PerformanceMonitoringShield(config)
        
        # Check health of all providers
        health_checks = []
        for provider in shield.config.providers:
            health_status = await provider.health_check()
            health_checks.append(health_status)
        
        assert health_checks == [True, False]
        assert healthy_provider.health_check_call_count == 1
        assert unhealthy_provider.health_check_call_count == 1


class TestEdgeCases:
    """Test edge cases and boundary conditions."""
    
    @pytest.mark.asyncio
    async def test_missing_request_state(self):
        """Test behavior when request state is missing."""
        provider = MockMonitoringProvider()
        config = PerformanceMonitoringConfig(providers=[provider])
        shield = PerformanceMonitoringShield(config)
        
        # Create request without performance state attributes
        request = create_mock_request()
        # Delete the performance attributes from the mock state
        del request.state.performance_start_time
        
        response = create_mock_response()
        
        # Should handle gracefully without raising exception
        await shield.record_response_metrics(request, response)
        
        # No metrics should be recorded
        assert provider.metric_call_count == 0
    
    def test_empty_metrics_statistics(self):
        """Test statistics calculation with empty metrics."""
        storage = MetricsStorage()
        
        stats = storage.get_statistics("/nonexistent", "nonexistent_metric")
        
        assert stats["count"] == 0
        assert len(stats) == 1  # Only count should be present
    
    def test_single_metric_statistics(self):
        """Test statistics calculation with single metric."""
        storage = MetricsStorage()
        
        metric = create_mock_performance_metric("single_metric", 100.0)
        storage.add_metric("/test", metric)
        
        stats = storage.get_statistics("/test", "single_metric")
        
        assert stats["count"] == 1
        assert stats["min"] == 100.0
        assert stats["max"] == 100.0
        assert stats["mean"] == 100.0
        assert stats["median"] == 100.0
        assert stats["stddev"] == 0.0  # No variance with single value
    
    @pytest.mark.asyncio
    async def test_very_large_response_time(self):
        """Test handling of very large response times."""
        provider = MockMonitoringProvider()
        config = PerformanceMonitoringConfig(
            providers=[provider],
            send_metrics_async=False
        )
        shield = PerformanceMonitoringShield(config)
        
        request = create_mock_request()
        request.state.performance_start_time = time.time() - 30.0  # 30 seconds ago
        request.state.performance_start_memory = 0
        request.state.performance_labels = {"endpoint": "/test", "method": "GET"}
        request.state.performance_request_body_size = 0
        
        response = create_mock_response()
        
        await shield.record_response_metrics(request, response)
        
        # Find the response time metric
        duration_metrics = provider.get_metrics_by_name("http_request_duration_ms")
        assert len(duration_metrics) == 1
        
        # Should be approximately 30,000ms
        assert duration_metrics[0].value >= 29000
        assert duration_metrics[0].value <= 31000
    
    def test_unicode_in_labels(self):
        """Test handling of Unicode characters in labels."""
        provider = MockMonitoringProvider()
        config = PerformanceMonitoringConfig(providers=[provider])
        shield = PerformanceMonitoringShield(config)
        
        request = create_mock_request(path="/api/测试", user_id="用户123")
        request.headers["custom-field"] = "🚀 测试"
        
        labels = shield._extract_labels(request)
        
        assert labels["endpoint"] == "/api/测试"
        assert labels["user_id"] == "用户123"
        # Custom labels should handle Unicode properly
    
    @pytest.mark.asyncio
    async def test_zero_response_time(self):
        """Test handling of zero or negative response times."""
        provider = MockMonitoringProvider()
        config = PerformanceMonitoringConfig(
            providers=[provider],
            send_metrics_async=False
        )
        shield = PerformanceMonitoringShield(config)
        
        request = create_mock_request()
        # Set start time to future (should result in negative duration)
        request.state.performance_start_time = time.time() + 1.0
        request.state.performance_start_memory = 0
        request.state.performance_labels = {"endpoint": "/test", "method": "GET"}
        request.state.performance_request_body_size = 0
        
        response = create_mock_response()
        
        await shield.record_response_metrics(request, response)
        
        # Should handle negative duration gracefully
        duration_metrics = provider.get_metrics_by_name("http_request_duration_ms")
        assert len(duration_metrics) == 1
        # Value might be negative, but should not crash
    
    def test_alert_threshold_edge_values(self):
        """Test alert thresholds with edge values."""
        manager = AlertManager()
        
        # Test with very small values
        threshold = AlertThreshold(
            metric_name="small_metric",
            threshold_value=0.001,
            comparison="greater_than",
            severity=AlertSeverity.LOW,
            consecutive_breaches=1
        )
        manager.add_threshold(threshold)
        
        # Metric that barely breaches threshold
        barely_breach_metric = create_mock_performance_metric("small_metric", 0.0011)
        alerts = manager.check_thresholds([barely_breach_metric])
        
        assert len(alerts) == 1
        
        # Metric that barely doesn't breach threshold
        barely_safe_metric = create_mock_performance_metric("small_metric", 0.0009)
        alerts = manager.check_thresholds([barely_safe_metric])
        
        # Should resolve the alert
        assert len(alerts) == 1
        assert alerts[0].resolved is True


class TestPerformance:
    """Test performance-related aspects."""
    
    @pytest.mark.asyncio
    async def test_high_volume_metric_collection(self):
        """Test performance with high volume of metrics."""
        provider = MockMonitoringProvider()
        config = PerformanceMonitoringConfig(
            providers=[provider],
            send_metrics_async=True,  # Use async to not block on sending
            max_metrics_per_endpoint=1000
        )
        shield = PerformanceMonitoringShield(config)
        
        start_time = time.time()
        
        # Generate many metrics
        for i in range(500):
            metric = create_mock_performance_metric(f"metric_{i % 10}", i * 10)
            shield.storage.add_metric(f"/endpoint_{i % 5}", metric)
        
        end_time = time.time()
        
        # Should complete quickly (less than 1 second)
        assert end_time - start_time < 1.0
        
        # Verify metrics were stored
        total_metrics = 0
        for i in range(5):
            endpoint_metrics = shield.storage.get_metrics(f"/endpoint_{i}")
            total_metrics += len(endpoint_metrics)
        
        assert total_metrics == 500
    
    def test_concurrent_storage_access(self):
        """Test concurrent access to metrics storage."""
        storage = MetricsStorage()
        
        def add_metrics_worker(worker_id):
            for i in range(100):
                metric = create_mock_performance_metric(f"worker_{worker_id}_metric_{i}", i)
                storage.add_metric(f"/worker_{worker_id}", metric)
        
        # Start multiple threads adding metrics concurrently
        threads = []
        for worker_id in range(5):
            thread = threading.Thread(target=add_metrics_worker, args=(worker_id,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Verify all metrics were added correctly
        total_metrics = 0
        for worker_id in range(5):
            worker_metrics = storage.get_metrics(f"/worker_{worker_id}")
            total_metrics += len(worker_metrics)
        
        assert total_metrics == 500  # 5 workers * 100 metrics each
    
    @pytest.mark.asyncio
    async def test_memory_usage_tracking_accuracy(self):
        """Test memory usage tracking accuracy."""
        from fastapi_shield.performance_monitoring import PSUTIL_AVAILABLE
        
        provider = MockMonitoringProvider()
        config = PerformanceMonitoringConfig(
            providers=[provider],
            send_metrics_async=False
        )
        shield = PerformanceMonitoringShield(config)
        
        request = create_mock_request()
        request.state.performance_start_memory = 1024 * 1024 * 1024  # 1GB
        request.state.performance_start_time = time.time()
        request.state.performance_labels = {"endpoint": "/test", "method": "GET"}
        request.state.performance_request_body_size = 0
        
        response = create_mock_response()
        await shield.record_response_metrics(request, response)
        
        # Check memory usage metric
        memory_metrics = provider.get_metrics_by_name("http_request_memory_mb")
        assert len(memory_metrics) == 1
        
        # When psutil is not available, memory calculation will be 0 - start_memory
        if not PSUTIL_AVAILABLE:
            expected_memory_change = (0 - request.state.performance_start_memory) / (1024 * 1024)
            assert memory_metrics[0].value == expected_memory_change
        else:
            # When psutil is available, should have a realistic memory value
            assert isinstance(memory_metrics[0].value, float)