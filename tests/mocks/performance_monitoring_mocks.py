"""Mock classes and utilities for performance monitoring shield testing."""

import asyncio
import time
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Callable
from unittest.mock import Mock, AsyncMock

from fastapi_shield.performance_monitoring import (
    MonitoringServiceProvider,
    PerformanceMetric,
    ResourceUsage,
    Alert,
    AlertThreshold,
    MetricType,
    AlertSeverity,
    MonitoringService
)


class MockMonitoringProvider(MonitoringServiceProvider):
    """Mock monitoring service provider for testing."""
    
    def __init__(
        self,
        send_metric_success: bool = True,
        send_alert_success: bool = True,
        health_status: bool = True,
        response_delay: float = 0.0,
        should_raise_exception: bool = False
    ):
        self.send_metric_success = send_metric_success
        self.send_alert_success = send_alert_success
        self.health_status = health_status
        self.response_delay = response_delay
        self.should_raise_exception = should_raise_exception
        
        # Tracking
        self.sent_metrics: List[PerformanceMetric] = []
        self.sent_alerts: List[Alert] = []
        self.health_check_calls = []
        
        # Call counters
        self.metric_call_count = 0
        self.alert_call_count = 0
        self.health_check_call_count = 0
    
    async def send_metric(self, metric: PerformanceMetric) -> bool:
        """Mock metric sending."""
        self.metric_call_count += 1
        
        if self.response_delay > 0:
            await asyncio.sleep(self.response_delay)
        
        if self.should_raise_exception:
            raise Exception("Mock metric sending exception")
        
        if self.send_metric_success:
            self.sent_metrics.append(metric)
        
        return self.send_metric_success
    
    async def send_alert(self, alert: Alert) -> bool:
        """Mock alert sending."""
        self.alert_call_count += 1
        
        if self.response_delay > 0:
            await asyncio.sleep(self.response_delay)
        
        if self.should_raise_exception:
            raise Exception("Mock alert sending exception")
        
        if self.send_alert_success:
            self.sent_alerts.append(alert)
        
        return self.send_alert_success
    
    async def health_check(self) -> bool:
        """Mock health check."""
        self.health_check_call_count += 1
        self.health_check_calls.append(time.time())
        
        if self.response_delay > 0:
            await asyncio.sleep(self.response_delay)
        
        if self.should_raise_exception:
            raise Exception("Mock health check exception")
        
        return self.health_status
    
    def reset_tracking(self):
        """Reset call tracking."""
        self.sent_metrics = []
        self.sent_alerts = []
        self.health_check_calls = []
        self.metric_call_count = 0
        self.alert_call_count = 0
        self.health_check_call_count = 0
    
    def get_metrics_by_name(self, name: str) -> List[PerformanceMetric]:
        """Get metrics by name."""
        return [m for m in self.sent_metrics if m.name == name]
    
    def get_metrics_by_labels(self, labels: Dict[str, str]) -> List[PerformanceMetric]:
        """Get metrics by labels."""
        result = []
        for metric in self.sent_metrics:
            if all(metric.labels.get(k) == v for k, v in labels.items()):
                result.append(metric)
        return result
    
    def get_alerts_by_metric(self, metric_name: str) -> List[Alert]:
        """Get alerts by metric name."""
        return [a for a in self.sent_alerts if a.threshold.metric_name == metric_name]


class MockPrometheusProvider(MockMonitoringProvider):
    """Mock Prometheus provider."""
    
    def __init__(self, pushgateway_url: str = "http://localhost:9091", **kwargs):
        super().__init__(**kwargs)
        self.pushgateway_url = pushgateway_url
        self.job_name = kwargs.get('job_name', 'test-job')
        
    async def send_metric(self, metric: PerformanceMetric) -> bool:
        """Mock Prometheus metric sending with format validation."""
        result = await super().send_metric(metric)
        
        # Simulate Prometheus format validation
        if result and metric.name:
            # Check if metric name is valid Prometheus format
            if not metric.name.replace('_', '').replace('.', '').isalnum():
                return False
        
        return result


class MockDataDogProvider(MockMonitoringProvider):
    """Mock DataDog provider."""
    
    def __init__(self, api_key: str = "test_api_key", app_key: str = "test_app_key", **kwargs):
        super().__init__(**kwargs)
        self.api_key = api_key
        self.app_key = app_key
        self.api_url = kwargs.get('api_url', 'https://api.datadoghq.com')
    
    async def send_metric(self, metric: PerformanceMetric) -> bool:
        """Mock DataDog metric sending with tags validation."""
        result = await super().send_metric(metric)
        
        # Simulate DataDog tag validation
        if result:
            # Check tag format (key:value)
            for key, value in metric.labels.items():
                if ':' in key or ':' in str(value):
                    return False
        
        return result
    
    async def send_alert(self, alert: Alert) -> bool:
        """Mock DataDog alert sending as event."""
        result = await super().send_alert(alert)
        
        # DataDog sends alerts as events
        if result:
            # Simulate event creation
            pass
        
        return result


class MockNewRelicProvider(MockMonitoringProvider):
    """Mock New Relic provider."""
    
    def __init__(self, license_key: str = "test_license", account_id: str = "123456", **kwargs):
        super().__init__(**kwargs)
        self.license_key = license_key
        self.account_id = account_id
        self.api_url = kwargs.get('api_url', 'https://metric-api.newrelic.com')
    
    async def send_metric(self, metric: PerformanceMetric) -> bool:
        """Mock New Relic metric sending."""
        result = await super().send_metric(metric)
        
        # Simulate New Relic validation
        if result:
            # Check if timestamp is valid
            if metric.timestamp > datetime.utcnow() + timedelta(minutes=5):
                return False
        
        return result


class MockCustomProvider(MockMonitoringProvider):
    """Mock custom provider with callback functions."""
    
    def __init__(
        self,
        metric_callback: Optional[Callable] = None,
        alert_callback: Optional[Callable] = None,
        health_callback: Optional[Callable] = None,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.metric_callback = metric_callback
        self.alert_callback = alert_callback
        self.health_callback = health_callback
    
    async def send_metric(self, metric: PerformanceMetric) -> bool:
        """Use custom callback for metric sending."""
        if self.metric_callback:
            try:
                if asyncio.iscoroutinefunction(self.metric_callback):
                    result = await self.metric_callback(metric)
                else:
                    result = self.metric_callback(metric)
                
                if result:
                    self.sent_metrics.append(metric)
                
                return result
            except Exception:
                return False
        
        return await super().send_metric(metric)
    
    async def send_alert(self, alert: Alert) -> bool:
        """Use custom callback for alert sending."""
        if self.alert_callback:
            try:
                if asyncio.iscoroutinefunction(self.alert_callback):
                    result = await self.alert_callback(alert)
                else:
                    result = self.alert_callback(alert)
                
                if result:
                    self.sent_alerts.append(alert)
                
                return result
            except Exception:
                return False
        
        return await super().send_alert(alert)


class MockMetricsStorage:
    """Mock metrics storage for testing."""
    
    def __init__(self, retention_hours: int = 24, max_metrics_per_endpoint: int = 1000):
        self.retention_hours = retention_hours
        self.max_metrics_per_endpoint = max_metrics_per_endpoint
        self._metrics: Dict[str, List[PerformanceMetric]] = defaultdict(list)
        self._resource_usage: List[ResourceUsage] = []
        
        # Tracking
        self.add_metric_calls = []
        self.add_resource_usage_calls = []
        self.get_metrics_calls = []
        self.get_resource_usage_calls = []
        self.get_statistics_calls = []
    
    def add_metric(self, endpoint: str, metric: PerformanceMetric) -> None:
        """Mock add metric."""
        self.add_metric_calls.append({
            "endpoint": endpoint,
            "metric": metric,
            "timestamp": time.time()
        })
        
        self._metrics[endpoint].append(metric)
        
        # Simulate max limit
        if len(self._metrics[endpoint]) > self.max_metrics_per_endpoint:
            self._metrics[endpoint] = self._metrics[endpoint][-self.max_metrics_per_endpoint:]
    
    def add_resource_usage(self, usage: ResourceUsage) -> None:
        """Mock add resource usage."""
        self.add_resource_usage_calls.append({
            "usage": usage,
            "timestamp": time.time()
        })
        
        self._resource_usage.append(usage)
        
        # Simulate max limit
        if len(self._resource_usage) > self.max_metrics_per_endpoint:
            self._resource_usage = self._resource_usage[-self.max_metrics_per_endpoint:]
    
    def get_metrics(self, endpoint: str, start_time: Optional[datetime] = None,
                   end_time: Optional[datetime] = None) -> List[PerformanceMetric]:
        """Mock get metrics."""
        self.get_metrics_calls.append({
            "endpoint": endpoint,
            "start_time": start_time,
            "end_time": end_time,
            "timestamp": time.time()
        })
        
        metrics = self._metrics.get(endpoint, [])
        
        if start_time or end_time:
            filtered_metrics = []
            for metric in metrics:
                if start_time and metric.timestamp < start_time:
                    continue
                if end_time and metric.timestamp > end_time:
                    continue
                filtered_metrics.append(metric)
            return filtered_metrics
        
        return list(metrics)
    
    def get_resource_usage(self, start_time: Optional[datetime] = None,
                          end_time: Optional[datetime] = None) -> List[ResourceUsage]:
        """Mock get resource usage."""
        self.get_resource_usage_calls.append({
            "start_time": start_time,
            "end_time": end_time,
            "timestamp": time.time()
        })
        
        usage_data = self._resource_usage
        
        if start_time or end_time:
            filtered_data = []
            for usage in usage_data:
                if start_time and usage.timestamp < start_time:
                    continue
                if end_time and usage.timestamp > end_time:
                    continue
                filtered_data.append(usage)
            return filtered_data
        
        return list(usage_data)
    
    def get_statistics(self, endpoint: str, metric_name: str,
                      window_minutes: int = 60) -> Dict[str, float]:
        """Mock get statistics."""
        self.get_statistics_calls.append({
            "endpoint": endpoint,
            "metric_name": metric_name,
            "window_minutes": window_minutes,
            "timestamp": time.time()
        })
        
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(minutes=window_minutes)
        
        metrics = self.get_metrics(endpoint, start_time, end_time)
        values = [m.value for m in metrics if m.name == metric_name]
        
        if not values:
            return {"count": 0}
        
        import statistics
        return {
            "count": len(values),
            "min": min(values),
            "max": max(values),
            "mean": statistics.mean(values),
            "median": statistics.median(values),
            "p95": sorted(values)[int(0.95 * len(values))] if values else 0,
            "p99": sorted(values)[int(0.99 * len(values))] if values else 0,
            "stddev": statistics.stdev(values) if len(values) > 1 else 0.0
        }
    
    def reset_tracking(self):
        """Reset call tracking."""
        self.add_metric_calls = []
        self.add_resource_usage_calls = []
        self.get_metrics_calls = []
        self.get_resource_usage_calls = []
        self.get_statistics_calls = []


class MockResourceMonitor:
    """Mock resource monitor for testing."""
    
    def __init__(self, collection_interval: int = 30):
        self.collection_interval = collection_interval
        self._running = False
        self._callbacks: List[Callable[[ResourceUsage], None]] = []
        self.collected_usage: List[ResourceUsage] = []
        
        # Tracking
        self.start_calls = 0
        self.stop_calls = 0
        self.add_callback_calls = []
    
    def add_callback(self, callback: Callable[[ResourceUsage], None]) -> None:
        """Mock add callback."""
        self.add_callback_calls.append(callback)
        self._callbacks.append(callback)
    
    def start(self) -> None:
        """Mock start monitoring."""
        self.start_calls += 1
        self._running = True
    
    def stop(self) -> None:
        """Mock stop monitoring."""
        self.stop_calls += 1
        self._running = False
    
    def simulate_resource_collection(self, usage: ResourceUsage) -> None:
        """Simulate resource collection for testing."""
        self.collected_usage.append(usage)
        
        for callback in self._callbacks:
            try:
                callback(usage)
            except Exception:
                continue
    
    def is_running(self) -> bool:
        """Check if monitoring is running."""
        return self._running
    
    def reset_tracking(self):
        """Reset call tracking."""
        self.start_calls = 0
        self.stop_calls = 0
        self.add_callback_calls = []
        self.collected_usage = []


class MockAlertManager:
    """Mock alert manager for testing."""
    
    def __init__(self):
        self.thresholds: Dict[str, AlertThreshold] = {}
        self.active_alerts: Dict[str, Alert] = {}
        self.alert_history: List[Alert] = []
        
        # Tracking
        self.add_threshold_calls = []
        self.remove_threshold_calls = []
        self.check_thresholds_calls = []
        self.threshold_breaches = defaultdict(list)
    
    def add_threshold(self, threshold: AlertThreshold) -> None:
        """Mock add threshold."""
        self.add_threshold_calls.append(threshold)
        self.thresholds[threshold.metric_name] = threshold
    
    def remove_threshold(self, metric_name: str) -> None:
        """Mock remove threshold."""
        self.remove_threshold_calls.append(metric_name)
        self.thresholds.pop(metric_name, None)
    
    def check_thresholds(self, metrics: List[PerformanceMetric]) -> List[Alert]:
        """Mock threshold checking."""
        self.check_thresholds_calls.append({
            "metrics": metrics,
            "timestamp": time.time()
        })
        
        new_alerts = []
        current_time = datetime.utcnow()
        
        for metric in metrics:
            threshold = self.thresholds.get(metric.name)
            if not threshold or not threshold.enabled:
                continue
            
            breach_detected = self._check_threshold_breach(metric.value, threshold)
            
            if breach_detected:
                self.threshold_breaches[metric.name].append(current_time)
                
                # Create alert
                alert_id = f"{metric.name}_{int(current_time.timestamp())}"
                alert = Alert(
                    id=alert_id,
                    threshold=threshold,
                    current_value=metric.value,
                    breach_count=1,
                    first_breach_time=current_time,
                    last_breach_time=current_time
                )
                
                self.active_alerts[metric.name] = alert
                new_alerts.append(alert)
            else:
                # Resolve alert if exists
                if metric.name in self.active_alerts:
                    alert = self.active_alerts[metric.name]
                    alert.resolved = True
                    alert.resolved_time = current_time
                    self.alert_history.append(alert)
                    del self.active_alerts[metric.name]
                    new_alerts.append(alert)
        
        return new_alerts
    
    def get_active_alerts(self) -> List[Alert]:
        """Mock get active alerts."""
        return list(self.active_alerts.values())
    
    def get_alert_history(self, hours: int = 24) -> List[Alert]:
        """Mock get alert history."""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        return [
            alert for alert in self.alert_history
            if alert.first_breach_time >= cutoff_time
        ]
    
    def _check_threshold_breach(self, value: float, threshold: AlertThreshold) -> bool:
        """Check threshold breach."""
        if threshold.comparison == "greater_than":
            return value > threshold.threshold_value
        elif threshold.comparison == "less_than":
            return value < threshold.threshold_value
        elif threshold.comparison == "equal_to":
            return abs(value - threshold.threshold_value) < 0.001
        return False
    
    def simulate_alert(self, metric_name: str, current_value: float, 
                      severity: AlertSeverity = AlertSeverity.HIGH) -> Alert:
        """Simulate an alert for testing."""
        threshold = AlertThreshold(
            metric_name=metric_name,
            threshold_value=current_value - 1,
            comparison="greater_than",
            severity=severity
        )
        
        alert = Alert(
            id=f"test_{metric_name}_{int(time.time())}",
            threshold=threshold,
            current_value=current_value,
            breach_count=1,
            first_breach_time=datetime.utcnow(),
            last_breach_time=datetime.utcnow()
        )
        
        self.active_alerts[metric_name] = alert
        return alert
    
    def reset_tracking(self):
        """Reset call tracking."""
        self.add_threshold_calls = []
        self.remove_threshold_calls = []
        self.check_thresholds_calls = []
        self.threshold_breaches = defaultdict(list)


def create_mock_performance_metric(
    name: str = "test_metric",
    value: float = 100.0,
    metric_type: MetricType = MetricType.GAUGE,
    labels: Optional[Dict[str, str]] = None,
    unit: str = "ms"
) -> PerformanceMetric:
    """Create a mock performance metric."""
    return PerformanceMetric(
        name=name,
        value=value,
        metric_type=metric_type,
        labels=labels or {"endpoint": "/test", "method": "GET"},
        unit=unit
    )


def create_mock_resource_usage(
    cpu_percent: float = 50.0,
    memory_percent: float = 60.0,
    memory_used_mb: float = 1024.0,
    disk_io_read_mb: float = 10.0,
    disk_io_write_mb: float = 5.0,
    network_sent_mb: float = 2.0,
    network_recv_mb: float = 3.0
) -> ResourceUsage:
    """Create a mock resource usage object."""
    return ResourceUsage(
        cpu_percent=cpu_percent,
        memory_percent=memory_percent,
        memory_used_mb=memory_used_mb,
        disk_io_read_mb=disk_io_read_mb,
        disk_io_write_mb=disk_io_write_mb,
        network_sent_mb=network_sent_mb,
        network_recv_mb=network_recv_mb
    )


def create_mock_alert_threshold(
    metric_name: str = "test_metric",
    threshold_value: float = 1000.0,
    comparison: str = "greater_than",
    severity: AlertSeverity = AlertSeverity.HIGH,
    window_seconds: int = 300,
    consecutive_breaches: int = 3
) -> AlertThreshold:
    """Create a mock alert threshold."""
    return AlertThreshold(
        metric_name=metric_name,
        threshold_value=threshold_value,
        comparison=comparison,
        severity=severity,
        window_seconds=window_seconds,
        consecutive_breaches=consecutive_breaches
    )


def create_mock_alert(
    metric_name: str = "test_metric",
    current_value: float = 1500.0,
    severity: AlertSeverity = AlertSeverity.HIGH,
    resolved: bool = False
) -> Alert:
    """Create a mock alert."""
    threshold = create_mock_alert_threshold(
        metric_name=metric_name,
        severity=severity
    )
    
    current_time = datetime.utcnow()
    
    alert = Alert(
        id=f"test_alert_{int(current_time.timestamp())}",
        threshold=threshold,
        current_value=current_value,
        breach_count=3,
        first_breach_time=current_time - timedelta(minutes=5),
        last_breach_time=current_time,
        resolved=resolved
    )
    
    if resolved:
        alert.resolved_time = current_time
    
    return alert


class AsyncContextManager:
    """Helper for creating async context managers in tests."""
    
    def __init__(self, value):
        self.value = value
    
    async def __aenter__(self):
        return self.value
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


class LoadTestHelper:
    """Helper for load testing performance monitoring."""
    
    @staticmethod
    async def concurrent_requests(
        shield,
        request_mocks: List[Mock],
        concurrent_count: int = 10
    ) -> List[Dict[str, Any]]:
        """Perform concurrent requests and return results."""
        tasks = []
        
        for i in range(concurrent_count):
            request_mock = request_mocks[i % len(request_mocks)]
            task = asyncio.create_task(
                shield._shield_function(request_mock)
            )
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return [
            {
                "request_index": i,
                "result": result,
                "is_exception": isinstance(result, Exception)
            }
            for i, result in enumerate(results)
        ]
    
    @staticmethod
    def generate_test_metrics(
        count: int,
        endpoint: str = "/test",
        base_response_time: float = 100.0,
        response_time_variance: float = 50.0
    ) -> List[PerformanceMetric]:
        """Generate test metrics for load testing."""
        import random
        
        metrics = []
        for i in range(count):
            response_time = base_response_time + random.uniform(-response_time_variance, response_time_variance)
            metrics.append(create_mock_performance_metric(
                name="http_request_duration_ms",
                value=max(0, response_time),
                labels={
                    "endpoint": endpoint,
                    "method": "GET",
                    "status_code": "200"
                }
            ))
        
        return metrics


class TimingHelper:
    """Helper for testing timing-related functionality."""
    
    @staticmethod
    def mock_time_progression(seconds: float):
        """Mock time progression for testing."""
        original_time = time.time()
        
        def mock_time():
            return original_time + seconds
        
        return Mock(side_effect=mock_time)
    
    @staticmethod
    async def wait_for_condition(
        condition_func: Callable[[], bool],
        timeout_seconds: int = 5,
        check_interval: float = 0.1
    ) -> bool:
        """Wait for a condition to become true."""
        start_time = time.time()
        
        while time.time() - start_time < timeout_seconds:
            if condition_func():
                return True
            await asyncio.sleep(check_interval)
        
        return False


class ValidationHelper:
    """Helper for validating test results."""
    
    @staticmethod
    def assert_metric_properties(
        metric: PerformanceMetric,
        expected_name: Optional[str] = None,
        expected_type: Optional[MetricType] = None,
        expected_labels: Optional[Dict[str, str]] = None,
        min_value: Optional[float] = None,
        max_value: Optional[float] = None
    ):
        """Assert performance metric properties."""
        if expected_name:
            assert metric.name == expected_name
        
        if expected_type:
            assert metric.metric_type == expected_type
        
        if expected_labels:
            for key, value in expected_labels.items():
                assert key in metric.labels
                assert metric.labels[key] == value
        
        if min_value is not None:
            assert metric.value >= min_value
        
        if max_value is not None:
            assert metric.value <= max_value
        
        assert isinstance(metric.timestamp, datetime)
    
    @staticmethod
    def assert_alert_properties(
        alert: Alert,
        expected_metric_name: Optional[str] = None,
        expected_severity: Optional[AlertSeverity] = None,
        expected_resolved: Optional[bool] = None,
        min_breach_count: Optional[int] = None
    ):
        """Assert alert properties."""
        if expected_metric_name:
            assert alert.threshold.metric_name == expected_metric_name
        
        if expected_severity:
            assert alert.threshold.severity == expected_severity
        
        if expected_resolved is not None:
            assert alert.resolved == expected_resolved
        
        if min_breach_count is not None:
            assert alert.breach_count >= min_breach_count
        
        assert isinstance(alert.first_breach_time, datetime)
        assert isinstance(alert.last_breach_time, datetime)
        assert alert.first_breach_time <= alert.last_breach_time
    
    @staticmethod
    def assert_resource_usage_properties(
        usage: ResourceUsage,
        min_cpu: float = 0.0,
        max_cpu: float = 100.0,
        min_memory: float = 0.0,
        max_memory: float = 100.0
    ):
        """Assert resource usage properties."""
        assert min_cpu <= usage.cpu_percent <= max_cpu
        assert min_memory <= usage.memory_percent <= max_memory
        assert usage.memory_used_mb >= 0
        assert usage.disk_io_read_mb >= 0
        assert usage.disk_io_write_mb >= 0
        assert usage.network_sent_mb >= 0
        assert usage.network_recv_mb >= 0
        assert isinstance(usage.timestamp, datetime)