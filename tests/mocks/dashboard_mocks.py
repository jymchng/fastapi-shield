"""Mock classes and utilities for testing the Shield Metrics Dashboard system."""

import asyncio
import json
import sqlite3
import tempfile
import time
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, Callable, Set
from unittest.mock import Mock, AsyncMock, MagicMock
from fastapi import WebSocket
from fastapi.websockets import WebSocketState

from fastapi_shield.dashboard import (
    MetricStorage, Metric, MetricType, MetricValue, Alert, AlertRule, 
    AlertSeverity, AlertStatus, DashboardWebSocketManager
)


class MockMetricStorage(MetricStorage):
    """Mock metric storage for testing."""
    
    def __init__(self):
        self.metrics: Dict[str, Metric] = {}
        self.store_calls = 0
        self.get_calls = 0
        self.delete_calls = 0
        self.should_fail_store = False
        self.should_fail_get = False
        self.should_fail_delete = False
        self.store_delay = 0
        self.get_delay = 0
    
    async def store_metric(self, metric: Metric) -> bool:
        """Store a metric."""
        self.store_calls += 1
        
        if self.store_delay > 0:
            await asyncio.sleep(self.store_delay)
        
        if self.should_fail_store:
            return False
        
        self.metrics[metric.name] = metric
        return True
    
    async def get_metric(self, name: str) -> Optional[Metric]:
        """Get a metric by name."""
        self.get_calls += 1
        
        if self.get_delay > 0:
            await asyncio.sleep(self.get_delay)
        
        if self.should_fail_get:
            return None
        
        return self.metrics.get(name)
    
    async def get_all_metrics(self) -> List[Metric]:
        """Get all metrics."""
        return list(self.metrics.values())
    
    async def delete_metric(self, name: str) -> bool:
        """Delete a metric."""
        self.delete_calls += 1
        
        if self.should_fail_delete:
            return False
        
        if name in self.metrics:
            del self.metrics[name]
            return True
        return False
    
    async def get_metrics_by_labels(self, labels: Dict[str, str]) -> List[Metric]:
        """Get metrics by labels."""
        result = []
        for metric in self.metrics.values():
            # Simple label matching for testing
            for value in metric.values:
                if all(value.labels.get(k) == v for k, v in labels.items()):
                    result.append(metric)
                    break
        return result
    
    def reset_counters(self):
        """Reset call counters."""
        self.store_calls = 0
        self.get_calls = 0
        self.delete_calls = 0


class MockWebSocket:
    """Mock WebSocket for testing."""
    
    def __init__(self):
        self.state = WebSocketState.CONNECTING
        self.sent_messages: List[str] = []
        self.client_state = WebSocketState.CONNECTED
        self.should_fail_send = False
        self.should_fail_accept = False
        self.accept_calls = 0
        self.send_calls = 0
    
    async def accept(self):
        """Mock accept connection."""
        self.accept_calls += 1
        if self.should_fail_accept:
            raise Exception("Failed to accept connection")
        self.state = WebSocketState.CONNECTED
        self.client_state = WebSocketState.CONNECTED
    
    async def send_text(self, data: str):
        """Mock send text message."""
        self.send_calls += 1
        if self.should_fail_send:
            raise Exception("Failed to send message")
        self.sent_messages.append(data)
    
    async def receive_text(self) -> str:
        """Mock receive text message."""
        return json.dumps({"type": "ping"})
    
    def disconnect(self):
        """Mock disconnect."""
        self.state = WebSocketState.DISCONNECTED
        self.client_state = WebSocketState.DISCONNECTED


class MockUvicornServer:
    """Mock Uvicorn server for testing."""
    
    def __init__(self):
        self.serve_calls = 0
        self.should_fail_serve = False
        self.serve_delay = 0
    
    async def serve(self):
        """Mock serve."""
        self.serve_calls += 1
        
        if self.serve_delay > 0:
            await asyncio.sleep(self.serve_delay)
        
        if self.should_fail_serve:
            raise Exception("Server failed to start")


class DashboardTestScenarios:
    """Pre-built test scenarios for dashboard testing."""
    
    @staticmethod
    def create_sample_metrics() -> List[Metric]:
        """Create sample metrics for testing."""
        metrics = []
        
        # Counter metric
        counter_metric = Metric(
            name="requests_total",
            type=MetricType.COUNTER,
            description="Total number of requests",
            unit="requests"
        )
        
        # Add some sample values
        base_time = datetime.now(timezone.utc)
        for i in range(10):
            counter_metric.add_value(
                i * 10,
                labels={"method": "GET", "status": "200"},
            )
        
        metrics.append(counter_metric)
        
        # Gauge metric
        gauge_metric = Metric(
            name="cpu_usage",
            type=MetricType.GAUGE,
            description="CPU usage percentage",
            unit="%"
        )
        
        for i in range(10):
            gauge_metric.add_value(50 + i * 2, labels={"core": "0"})
        
        metrics.append(gauge_metric)
        
        # Histogram metric
        histogram_metric = Metric(
            name="request_duration",
            type=MetricType.HISTOGRAM,
            description="Request duration",
            unit="seconds"
        )
        
        for i in range(10):
            histogram_metric.add_value(0.1 + i * 0.05, labels={"endpoint": "/api/test"})
        
        metrics.append(histogram_metric)
        
        return metrics
    
    @staticmethod
    def create_sample_alert_rules() -> List[AlertRule]:
        """Create sample alert rules for testing."""
        rules = []
        
        # High CPU usage alert
        rules.append(AlertRule(
            id="cpu-high",
            name="High CPU Usage",
            metric_name="cpu_usage",
            condition="gt",
            threshold=80.0,
            duration=60,
            severity=AlertSeverity.WARNING,
            description="CPU usage is above 80%"
        ))
        
        # High error rate alert
        rules.append(AlertRule(
            id="error-rate-high",
            name="High Error Rate",
            metric_name="error_rate",
            condition="gt",
            threshold=5.0,
            duration=120,
            severity=AlertSeverity.ERROR,
            description="Error rate is above 5%"
        ))
        
        # Critical memory alert
        rules.append(AlertRule(
            id="memory-critical",
            name="Critical Memory Usage",
            metric_name="memory_usage",
            condition="gt",
            threshold=95.0,
            duration=30,
            severity=AlertSeverity.CRITICAL,
            description="Memory usage is critically high"
        ))
        
        return rules
    
    @staticmethod
    def create_sample_alerts() -> List[Alert]:
        """Create sample alerts for testing."""
        alerts = []
        
        # Active alert
        alerts.append(Alert(
            id="alert-1",
            rule_id="cpu-high",
            rule_name="High CPU Usage",
            metric_name="cpu_usage",
            metric_value=85.0,
            threshold=80.0,
            severity=AlertSeverity.WARNING,
            status=AlertStatus.ACTIVE,
            message="CPU usage is 85% (threshold: 80%)",
            labels={"core": "0"}
        ))
        
        # Resolved alert
        resolved_alert = Alert(
            id="alert-2",
            rule_id="error-rate-high",
            rule_name="High Error Rate",
            metric_name="error_rate",
            metric_value=6.0,
            threshold=5.0,
            severity=AlertSeverity.ERROR,
            status=AlertStatus.RESOLVED,
            message="Error rate is 6% (threshold: 5%)",
        )
        resolved_alert.resolve()
        alerts.append(resolved_alert)
        
        # Acknowledged alert
        ack_alert = Alert(
            id="alert-3",
            rule_id="memory-critical",
            rule_name="Critical Memory Usage",
            metric_name="memory_usage",
            metric_value=97.0,
            threshold=95.0,
            severity=AlertSeverity.CRITICAL,
            status=AlertStatus.ACKNOWLEDGED,
            message="Memory usage is 97% (threshold: 95%)"
        )
        ack_alert.acknowledge("testuser")
        alerts.append(ack_alert)
        
        return alerts
    
    @staticmethod
    def create_time_series_data(
        start_time: datetime,
        end_time: datetime,
        interval_seconds: int,
        base_value: float = 50.0,
        variance: float = 10.0
    ) -> List[MetricValue]:
        """Create time series data for testing."""
        import random
        
        values = []
        current_time = start_time
        
        while current_time <= end_time:
            value = base_value + random.uniform(-variance, variance)
            values.append(MetricValue(
                value=value,
                timestamp=current_time,
                labels={"source": "test"}
            ))
            current_time += timedelta(seconds=interval_seconds)
        
        return values
    
    @staticmethod
    def create_metric_with_labels() -> Metric:
        """Create a metric with various labels for testing."""
        metric = Metric(
            name="http_requests",
            type=MetricType.COUNTER,
            description="HTTP requests with labels"
        )
        
        # Add values with different label combinations
        labels_combinations = [
            {"method": "GET", "status": "200", "endpoint": "/api/users"},
            {"method": "POST", "status": "201", "endpoint": "/api/users"},
            {"method": "GET", "status": "404", "endpoint": "/api/users/123"},
            {"method": "PUT", "status": "200", "endpoint": "/api/users/123"},
            {"method": "DELETE", "status": "204", "endpoint": "/api/users/123"},
        ]
        
        for i, labels in enumerate(labels_combinations):
            metric.add_value(i * 5, labels)
        
        return metric


class AlertManagerTestHelper:
    """Helper for testing AlertManager functionality."""
    
    @staticmethod
    def create_mock_callback() -> Mock:
        """Create a mock alert callback."""
        callback = Mock()
        callback.side_effect = None  # No exception by default
        return callback
    
    @staticmethod
    def create_failing_callback() -> Mock:
        """Create a callback that always fails."""
        callback = Mock()
        callback.side_effect = Exception("Callback failed")
        return callback
    
    @staticmethod
    def simulate_alert_condition_met(
        metric: Metric,
        rule: AlertRule,
        duration_seconds: int = 0
    ):
        """Simulate an alert condition being met for a duration."""
        if duration_seconds > 0:
            # Add values that meet the condition over time
            start_time = datetime.now(timezone.utc) - timedelta(seconds=duration_seconds + 10)
            
            for i in range(duration_seconds + 20):
                timestamp = start_time + timedelta(seconds=i)
                # Create value that triggers the condition
                if rule.condition == "gt":
                    value = rule.threshold + 10
                elif rule.condition == "lt":
                    value = rule.threshold - 10
                elif rule.condition == "gte":
                    value = rule.threshold
                elif rule.condition == "lte":
                    value = rule.threshold
                elif rule.condition == "eq":
                    value = rule.threshold
                else:
                    value = rule.threshold + 10
                
                metric_value = MetricValue(value=value, timestamp=timestamp)
                metric.values.append(metric_value)
        else:
            # Just add a single triggering value
            if rule.condition == "gt":
                value = rule.threshold + 10
            elif rule.condition == "lt":
                value = rule.threshold - 10
            else:
                value = rule.threshold + 10
            
            metric.add_value(value)


class DashboardTestClient:
    """Test client for dashboard HTTP endpoints."""
    
    def __init__(self, app):
        from fastapi.testclient import TestClient
        self.client = TestClient(app)
    
    def get_metrics(self):
        """Get metrics endpoint."""
        return self.client.get("/api/metrics")
    
    def get_metric(self, metric_name: str, since: str = None):
        """Get specific metric endpoint."""
        url = f"/api/metrics/{metric_name}"
        if since:
            url += f"?since={since}"
        return self.client.get(url)
    
    def add_metric_value(self, metric_name: str, value: float, labels: dict = None):
        """Add metric value endpoint."""
        data = {"value": value}
        if labels:
            data["labels"] = labels
        return self.client.post(f"/api/metrics/{metric_name}", json=data)
    
    def get_alerts(self):
        """Get alerts endpoint."""
        return self.client.get("/api/alerts")
    
    def acknowledge_alert(self, alert_id: str):
        """Acknowledge alert endpoint."""
        return self.client.post(f"/api/alerts/{alert_id}/acknowledge")
    
    def silence_alert(self, alert_id: str):
        """Silence alert endpoint."""
        return self.client.post(f"/api/alerts/{alert_id}/silence")
    
    def get_alert_rules(self):
        """Get alert rules endpoint."""
        return self.client.get("/api/alert-rules")
    
    def create_alert_rule(self, rule_data: dict):
        """Create alert rule endpoint."""
        return self.client.post("/api/alert-rules", json=rule_data)
    
    def delete_alert_rule(self, rule_id: str):
        """Delete alert rule endpoint."""
        return self.client.delete(f"/api/alert-rules/{rule_id}")
    
    def get_chart_data(self, metric_name: str, chart_type: str = "line", time_range: str = "1h"):
        """Get chart data endpoint."""
        return self.client.get(f"/api/charts/{metric_name}?chart_type={chart_type}&time_range={time_range}")
    
    def get_dashboard_page(self):
        """Get main dashboard page."""
        return self.client.get("/")


class MetricsGeneratorHelper:
    """Helper for generating realistic metrics data."""
    
    @staticmethod
    def generate_cpu_metrics(duration_minutes: int = 60, interval_seconds: int = 10) -> Metric:
        """Generate realistic CPU usage metrics."""
        import random
        
        metric = Metric(
            name="cpu_usage_percent",
            type=MetricType.GAUGE,
            description="CPU usage percentage",
            unit="%"
        )
        
        start_time = datetime.now(timezone.utc) - timedelta(minutes=duration_minutes)
        current_time = start_time
        end_time = datetime.now(timezone.utc)
        
        base_cpu = 30.0
        
        while current_time <= end_time:
            # Simulate CPU usage with some realistic patterns
            time_factor = (current_time - start_time).total_seconds() / 3600  # Hours
            
            # Add daily pattern (higher usage during day)
            daily_pattern = 20 * (0.5 + 0.5 * math.sin(time_factor * 2 * math.pi / 24))
            
            # Add random variance
            noise = random.uniform(-5, 15)
            
            cpu_value = max(0, min(100, base_cpu + daily_pattern + noise))
            
            metric.values.append(MetricValue(
                value=cpu_value,
                timestamp=current_time,
                labels={"core": "all", "host": "test-server"}
            ))
            
            current_time += timedelta(seconds=interval_seconds)
        
        return metric
    
    @staticmethod
    def generate_request_metrics(duration_minutes: int = 60) -> List[Metric]:
        """Generate HTTP request metrics."""
        import random
        
        metrics = []
        
        # Request count metric
        requests_metric = Metric(
            name="http_requests_total",
            type=MetricType.COUNTER,
            description="Total HTTP requests"
        )
        
        # Response time metric
        response_time_metric = Metric(
            name="http_request_duration_seconds",
            type=MetricType.HISTOGRAM,
            description="HTTP request duration",
            unit="seconds"
        )
        
        start_time = datetime.now(timezone.utc) - timedelta(minutes=duration_minutes)
        current_time = start_time
        end_time = datetime.now(timezone.utc)
        
        request_count = 0
        
        while current_time <= end_time:
            # Generate requests for different endpoints
            endpoints = ["/api/users", "/api/orders", "/api/products", "/health"]
            methods = ["GET", "POST", "PUT", "DELETE"]
            status_codes = ["200", "201", "400", "404", "500"]
            
            # Simulate burst of requests
            requests_this_minute = random.randint(5, 50)
            
            for _ in range(requests_this_minute):
                endpoint = random.choice(endpoints)
                method = random.choice(methods)
                status = random.choices(
                    status_codes,
                    weights=[70, 10, 5, 10, 5]  # Mostly successful requests
                )[0]
                
                labels = {
                    "method": method,
                    "endpoint": endpoint,
                    "status": status
                }
                
                request_count += 1
                requests_metric.values.append(MetricValue(
                    value=request_count,
                    timestamp=current_time,
                    labels=labels
                ))
                
                # Response time varies by endpoint and status
                if status == "500":
                    response_time = random.uniform(1.0, 5.0)  # Errors are slower
                elif endpoint == "/health":
                    response_time = random.uniform(0.001, 0.01)  # Health check is fast
                else:
                    response_time = random.uniform(0.1, 1.0)  # Normal requests
                
                response_time_metric.values.append(MetricValue(
                    value=response_time,
                    timestamp=current_time,
                    labels=labels
                ))
            
            current_time += timedelta(minutes=1)
        
        metrics.extend([requests_metric, response_time_metric])
        return metrics
    
    @staticmethod
    def generate_memory_metrics(duration_minutes: int = 60) -> Metric:
        """Generate memory usage metrics."""
        import random
        
        metric = Metric(
            name="memory_usage_percent",
            type=MetricType.GAUGE,
            description="Memory usage percentage",
            unit="%"
        )
        
        start_time = datetime.now(timezone.utc) - timedelta(minutes=duration_minutes)
        current_time = start_time
        end_time = datetime.now(timezone.utc)
        
        base_memory = 60.0
        
        while current_time <= end_time:
            # Memory typically grows slowly then drops with GC
            time_factor = (current_time - start_time).total_seconds() / 60  # Minutes
            
            # Simulate memory growth and GC cycles
            gc_cycle = time_factor % 10  # 10-minute GC cycle
            if gc_cycle < 8:
                # Memory grows
                memory_growth = gc_cycle * 3
            else:
                # GC happens, memory drops
                memory_growth = (10 - gc_cycle) * 12
            
            noise = random.uniform(-2, 5)
            memory_value = max(0, min(100, base_memory + memory_growth + noise))
            
            metric.values.append(MetricValue(
                value=memory_value,
                timestamp=current_time,
                labels={"type": "heap", "host": "test-server"}
            ))
            
            current_time += timedelta(minutes=1)
        
        return metric


class TempDatabaseHelper:
    """Helper for creating temporary test databases."""
    
    def __init__(self):
        self.temp_file = None
        self.database_path = None
    
    def __enter__(self):
        """Create temporary database."""
        import tempfile
        
        self.temp_file = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        self.temp_file.close()
        self.database_path = self.temp_file.name
        return self.database_path
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Clean up temporary database."""
        if self.database_path and Path(self.database_path).exists():
            Path(self.database_path).unlink()


import math  # Add this for the metrics generator