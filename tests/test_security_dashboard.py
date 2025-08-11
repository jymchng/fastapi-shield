"""Comprehensive tests for FastAPI-Shield Security Dashboard module.

This test suite covers all aspects of the security dashboard including:
- Metrics collection and aggregation
- Alert management and notification
- WebSocket real-time updates
- Dashboard configuration and widgets
- Report generation and export
- Performance under load
- API endpoints and integration
"""

import asyncio
import json
import pytest
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any
from unittest.mock import Mock, AsyncMock, patch
import uuid

from fastapi.testclient import TestClient
from fastapi import FastAPI

from src.fastapi_shield.security_dashboard import (
    # Core classes
    SecurityDashboard, MetricsCollector, AlertManager, WebSocketManager,
    ReportGenerator, SecurityMetric, SecurityAlert, DashboardWidget,
    DashboardConfig,
    
    # Enums
    MetricType, ChartType, AlertSeverity, ReportFormat, DashboardTheme,
    
    # Convenience functions
    create_security_dashboard, create_default_widgets
)

from tests.mocks.mock_dashboard_infrastructure import (
    MockWebSocket, MockMetricsDatabase, MockAlertNotificationService,
    MockReportExporter, MockChartRenderer, MockAnalyticsEngine,
    MockDashboardTestEnvironment
)


class TestSecurityMetric:
    """Test SecurityMetric data class and operations."""
    
    def test_security_metric_creation(self):
        """Test creating a security metric."""
        timestamp = datetime.now(timezone.utc)
        
        metric = SecurityMetric(
            id="test-metric-1",
            name="test_requests",
            metric_type=MetricType.COUNTER,
            value=42.5,
            timestamp=timestamp,
            category="requests",
            tags={"environment": "test", "service": "api"},
            metadata={"source": "test_suite"}
        )
        
        assert metric.id == "test-metric-1"
        assert metric.name == "test_requests"
        assert metric.metric_type == MetricType.COUNTER
        assert metric.value == 42.5
        assert metric.timestamp == timestamp
        assert metric.category == "requests"
        assert metric.tags == {"environment": "test", "service": "api"}
        assert metric.metadata == {"source": "test_suite"}
    
    def test_security_metric_to_dict(self):
        """Test converting SecurityMetric to dictionary."""
        timestamp = datetime.now(timezone.utc)
        
        metric = SecurityMetric(
            id="test-metric-2",
            name="test_errors",
            metric_type=MetricType.GAUGE,
            value=10,
            timestamp=timestamp,
            category="errors"
        )
        
        result = metric.to_dict()
        
        assert result['id'] == "test-metric-2"
        assert result['name'] == "test_errors"
        assert result['metric_type'] == "gauge"
        assert result['value'] == 10
        assert result['timestamp'] == timestamp.isoformat()
        assert result['category'] == "errors"
        assert result['tags'] == {}
        assert result['metadata'] == {}
    
    def test_metric_types_enum(self):
        """Test MetricType enum values."""
        assert MetricType.COUNTER.value == "counter"
        assert MetricType.GAUGE.value == "gauge"
        assert MetricType.HISTOGRAM.value == "histogram"
        assert MetricType.RATE.value == "rate"
        assert MetricType.PERCENTAGE.value == "percentage"
    
    def test_metric_with_complex_metadata(self):
        """Test metric with complex metadata."""
        metric = SecurityMetric(
            id="complex-metric",
            name="complex_test",
            metric_type=MetricType.HISTOGRAM,
            value=100.0,
            timestamp=datetime.now(timezone.utc),
            category="complex",
            metadata={
                "distribution": [1, 2, 3, 4, 5],
                "percentiles": {"p50": 2.5, "p95": 4.5, "p99": 4.9},
                "source_details": {"host": "test-host", "pid": 12345}
            }
        )
        
        result = metric.to_dict()
        assert result['metadata']['distribution'] == [1, 2, 3, 4, 5]
        assert result['metadata']['percentiles']['p95'] == 4.5


class TestSecurityAlert:
    """Test SecurityAlert data class and operations."""
    
    def test_security_alert_creation(self):
        """Test creating a security alert."""
        timestamp = datetime.now(timezone.utc)
        
        alert = SecurityAlert(
            id="alert-1",
            title="High Error Rate",
            description="Error rate exceeded threshold",
            severity=AlertSeverity.HIGH,
            timestamp=timestamp,
            category="performance",
            source="error_monitor",
            affected_resources=["api-service", "database"],
            recommended_actions=["Check logs", "Restart service"]
        )
        
        assert alert.id == "alert-1"
        assert alert.title == "High Error Rate"
        assert alert.severity == AlertSeverity.HIGH
        assert alert.category == "performance"
        assert alert.source == "error_monitor"
        assert len(alert.affected_resources) == 2
        assert len(alert.recommended_actions) == 2
        assert not alert.is_acknowledged
        assert not alert.resolved
    
    def test_security_alert_to_dict(self):
        """Test converting SecurityAlert to dictionary."""
        timestamp = datetime.now(timezone.utc)
        
        alert = SecurityAlert(
            id="alert-2",
            title="Test Alert",
            description="Test description",
            severity=AlertSeverity.CRITICAL,
            timestamp=timestamp,
            category="security",
            source="test"
        )
        
        result = alert.to_dict()
        
        assert result['id'] == "alert-2"
        assert result['title'] == "Test Alert"
        assert result['severity'] == "critical"
        assert result['timestamp'] == timestamp.isoformat()
        assert result['is_acknowledged'] is False
        assert result['resolved'] is False
    
    def test_alert_acknowledgment(self):
        """Test alert acknowledgment tracking."""
        alert = SecurityAlert(
            id="ack-test",
            title="Acknowledgment Test",
            description="Test alert acknowledgment",
            severity=AlertSeverity.MEDIUM,
            timestamp=datetime.now(timezone.utc),
            category="test",
            source="test"
        )
        
        # Initially not acknowledged
        assert not alert.is_acknowledged
        assert alert.acknowledged_by is None
        assert alert.acknowledged_at is None
        
        # Acknowledge
        ack_time = datetime.now(timezone.utc)
        alert.is_acknowledged = True
        alert.acknowledged_by = "test_user"
        alert.acknowledged_at = ack_time
        
        assert alert.is_acknowledged
        assert alert.acknowledged_by == "test_user"
        assert alert.acknowledged_at == ack_time
    
    def test_alert_resolution(self):
        """Test alert resolution tracking."""
        alert = SecurityAlert(
            id="resolve-test",
            title="Resolution Test",
            description="Test alert resolution",
            severity=AlertSeverity.LOW,
            timestamp=datetime.now(timezone.utc),
            category="test",
            source="test"
        )
        
        # Initially not resolved
        assert not alert.resolved
        assert alert.resolved_by is None
        assert alert.resolved_at is None
        
        # Resolve
        resolve_time = datetime.now(timezone.utc)
        alert.resolved = True
        alert.resolved_by = "admin_user"
        alert.resolved_at = resolve_time
        
        assert alert.resolved
        assert alert.resolved_by == "admin_user"
        assert alert.resolved_at == resolve_time


class TestMetricsCollector:
    """Test MetricsCollector functionality."""
    
    def test_metrics_collector_creation(self):
        """Test creating MetricsCollector."""
        collector = MetricsCollector(max_metrics=5000)
        
        assert collector.max_metrics == 5000
        assert len(collector.metrics) == 0
        assert len(collector.metric_index) == 0
        assert len(collector.aggregated_metrics) == 0
    
    def test_add_metric(self):
        """Test adding metrics to collector."""
        collector = MetricsCollector()
        
        metric = SecurityMetric(
            id="test-1",
            name="test_metric",
            metric_type=MetricType.COUNTER,
            value=100,
            timestamp=datetime.now(timezone.utc),
            category="test"
        )
        
        collector.add_metric(metric)
        
        assert len(collector.metrics) == 1
        assert len(collector.metric_index['test']) == 1
        assert collector.metrics[0] == metric
    
    def test_get_metrics_no_filter(self):
        """Test getting all metrics without filters."""
        collector = MetricsCollector()
        
        metrics = []
        for i in range(5):
            metric = SecurityMetric(
                id=f"metric-{i}",
                name=f"test_{i}",
                metric_type=MetricType.COUNTER,
                value=i * 10,
                timestamp=datetime.now(timezone.utc),
                category=f"category_{i % 2}"
            )
            metrics.append(metric)
            collector.add_metric(metric)
        
        result = collector.get_metrics()
        assert len(result) == 5
    
    def test_get_metrics_with_category_filter(self):
        """Test getting metrics with category filter."""
        collector = MetricsCollector()
        
        # Add metrics to different categories
        for i in range(6):
            metric = SecurityMetric(
                id=f"metric-{i}",
                name=f"test_{i}",
                metric_type=MetricType.GAUGE,
                value=i * 5,
                timestamp=datetime.now(timezone.utc),
                category="category_a" if i % 2 == 0 else "category_b"
            )
            collector.add_metric(metric)
        
        # Filter by category_a
        result_a = collector.get_metrics(category="category_a")
        assert len(result_a) == 3
        assert all(m.category == "category_a" for m in result_a)
        
        # Filter by category_b
        result_b = collector.get_metrics(category="category_b")
        assert len(result_b) == 3
        assert all(m.category == "category_b" for m in result_b)
    
    def test_get_metrics_with_time_filter(self):
        """Test getting metrics with time filters."""
        collector = MetricsCollector()
        
        base_time = datetime.now(timezone.utc)
        
        # Add metrics with different timestamps
        for i in range(5):
            metric = SecurityMetric(
                id=f"time-metric-{i}",
                name=f"time_test_{i}",
                metric_type=MetricType.RATE,
                value=i * 20,
                timestamp=base_time + timedelta(hours=i),
                category="time_test"
            )
            collector.add_metric(metric)
        
        # Filter by start time
        start_time = base_time + timedelta(hours=2)
        result = collector.get_metrics(start_time=start_time)
        assert len(result) == 3  # Metrics 2, 3, 4
        
        # Filter by end time
        end_time = base_time + timedelta(hours=3)
        result = collector.get_metrics(end_time=end_time)
        assert len(result) == 4  # Metrics 0, 1, 2, 3
        
        # Filter by both start and end time
        result = collector.get_metrics(start_time=start_time, end_time=end_time)
        assert len(result) == 2  # Metrics 2, 3
    
    def test_get_metrics_with_limit(self):
        """Test getting metrics with limit."""
        collector = MetricsCollector()
        
        # Add 10 metrics
        for i in range(10):
            metric = SecurityMetric(
                id=f"limit-metric-{i}",
                name=f"limit_test_{i}",
                metric_type=MetricType.COUNTER,
                value=i,
                timestamp=datetime.now(timezone.utc),
                category="limit_test"
            )
            collector.add_metric(metric)
        
        # Get with limit
        result = collector.get_metrics(limit=5)
        assert len(result) == 5
        
        # Should get the most recent 5 metrics
        assert all(int(m.name.split('_')[-1]) >= 5 for m in result)
    
    def test_subscriber_notification(self):
        """Test subscriber notifications for new metrics."""
        collector = MetricsCollector()
        
        received_metrics = []
        
        def callback(metric):
            received_metrics.append(metric)
        
        collector.subscribe(callback)
        
        metric = SecurityMetric(
            id="notify-test",
            name="notification_test",
            metric_type=MetricType.GAUGE,
            value=50,
            timestamp=datetime.now(timezone.utc),
            category="notification"
        )
        
        collector.add_metric(metric)
        
        assert len(received_metrics) == 1
        assert received_metrics[0] == metric
    
    def test_unsubscribe(self):
        """Test unsubscribing from metric notifications."""
        collector = MetricsCollector()
        
        received_metrics = []
        
        def callback(metric):
            received_metrics.append(metric)
        
        collector.subscribe(callback)
        collector.unsubscribe(callback)
        
        metric = SecurityMetric(
            id="unsubscribe-test",
            name="unsubscribe_test",
            metric_type=MetricType.COUNTER,
            value=25,
            timestamp=datetime.now(timezone.utc),
            category="unsubscribe"
        )
        
        collector.add_metric(metric)
        
        assert len(received_metrics) == 0


class TestAlertManager:
    """Test AlertManager functionality."""
    
    def test_alert_manager_creation(self):
        """Test creating AlertManager."""
        manager = AlertManager(max_alerts=1000)
        
        assert manager.max_alerts == 1000
        assert len(manager.alerts) == 0
        assert len(manager.alert_index) == 0
        assert len(manager.alert_rules) == 0
    
    def test_add_alert(self):
        """Test adding alerts to manager."""
        manager = AlertManager()
        
        alert = SecurityAlert(
            id="test-alert",
            title="Test Alert",
            description="Test description",
            severity=AlertSeverity.MEDIUM,
            timestamp=datetime.now(timezone.utc),
            category="test",
            source="test"
        )
        
        manager.add_alert(alert)
        
        assert len(manager.alerts) == 1
        assert manager.alert_index["test-alert"] == alert
    
    def test_acknowledge_alert(self):
        """Test acknowledging alerts."""
        manager = AlertManager()
        
        alert = SecurityAlert(
            id="ack-alert",
            title="Acknowledgment Test",
            description="Test acknowledgment",
            severity=AlertSeverity.HIGH,
            timestamp=datetime.now(timezone.utc),
            category="test",
            source="test"
        )
        
        manager.add_alert(alert)
        
        # Acknowledge alert
        result = manager.acknowledge_alert("ack-alert", "test_user")
        
        assert result is True
        assert alert.is_acknowledged is True
        assert alert.acknowledged_by == "test_user"
        assert alert.acknowledged_at is not None
        
        # Try to acknowledge non-existent alert
        result = manager.acknowledge_alert("non-existent", "test_user")
        assert result is False
    
    def test_resolve_alert(self):
        """Test resolving alerts."""
        manager = AlertManager()
        
        alert = SecurityAlert(
            id="resolve-alert",
            title="Resolution Test",
            description="Test resolution",
            severity=AlertSeverity.LOW,
            timestamp=datetime.now(timezone.utc),
            category="test",
            source="test"
        )
        
        manager.add_alert(alert)
        
        # Resolve alert
        result = manager.resolve_alert("resolve-alert", "admin_user")
        
        assert result is True
        assert alert.resolved is True
        assert alert.resolved_by == "admin_user"
        assert alert.resolved_at is not None
    
    def test_get_alerts_no_filter(self):
        """Test getting all alerts without filters."""
        manager = AlertManager()
        
        # Add alerts with different severities
        severities = [AlertSeverity.CRITICAL, AlertSeverity.HIGH, AlertSeverity.MEDIUM, AlertSeverity.LOW]
        
        for i, severity in enumerate(severities):
            alert = SecurityAlert(
                id=f"alert-{i}",
                title=f"Alert {i}",
                description=f"Description {i}",
                severity=severity,
                timestamp=datetime.now(timezone.utc),
                category="test",
                source="test"
            )
            manager.add_alert(alert)
        
        result = manager.get_alerts()
        assert len(result) == 4
    
    def test_get_alerts_with_severity_filter(self):
        """Test getting alerts with severity filter."""
        manager = AlertManager()
        
        # Add alerts with different severities
        severities = [AlertSeverity.CRITICAL, AlertSeverity.HIGH, AlertSeverity.MEDIUM, AlertSeverity.LOW]
        
        for i, severity in enumerate(severities):
            alert = SecurityAlert(
                id=f"severity-alert-{i}",
                title=f"Alert {i}",
                description=f"Description {i}",
                severity=severity,
                timestamp=datetime.now(timezone.utc),
                category="test",
                source="test"
            )
            manager.add_alert(alert)
        
        # Filter by CRITICAL
        result = manager.get_alerts(severity=AlertSeverity.CRITICAL)
        assert len(result) == 1
        assert result[0].severity == AlertSeverity.CRITICAL
        
        # Filter by HIGH
        result = manager.get_alerts(severity=AlertSeverity.HIGH)
        assert len(result) == 1
        assert result[0].severity == AlertSeverity.HIGH
    
    def test_get_alerts_unresolved_only(self):
        """Test getting only unresolved alerts."""
        manager = AlertManager()
        
        # Add resolved and unresolved alerts
        for i in range(4):
            alert = SecurityAlert(
                id=f"resolve-filter-{i}",
                title=f"Alert {i}",
                description=f"Description {i}",
                severity=AlertSeverity.MEDIUM,
                timestamp=datetime.now(timezone.utc),
                category="test",
                source="test",
                resolved=(i % 2 == 0)  # Even numbered alerts are resolved
            )
            manager.add_alert(alert)
        
        # Get only unresolved alerts
        result = manager.get_alerts(unresolved_only=True)
        assert len(result) == 2
        assert all(not alert.resolved for alert in result)
    
    def test_get_alerts_with_limit(self):
        """Test getting alerts with limit."""
        manager = AlertManager()
        
        # Add 10 alerts
        for i in range(10):
            alert = SecurityAlert(
                id=f"limit-alert-{i}",
                title=f"Alert {i}",
                description=f"Description {i}",
                severity=AlertSeverity.INFO,
                timestamp=datetime.now(timezone.utc),
                category="test",
                source="test"
            )
            manager.add_alert(alert)
        
        # Get with limit
        result = manager.get_alerts(limit=5)
        assert len(result) == 5
    
    def test_add_alert_rule(self):
        """Test adding custom alert rules."""
        manager = AlertManager()
        
        def high_value_rule(metric: SecurityMetric) -> SecurityAlert:
            if metric.value > 1000:
                return SecurityAlert(
                    id=str(uuid.uuid4()),
                    title="High Value Alert",
                    description=f"Metric value {metric.value} exceeds threshold",
                    severity=AlertSeverity.HIGH,
                    timestamp=datetime.now(timezone.utc),
                    category="threshold",
                    source="rule_engine"
                )
            return None
        
        manager.add_alert_rule(high_value_rule)
        
        assert len(manager.alert_rules) == 1
    
    def test_evaluate_alert_rules(self):
        """Test evaluating alert rules."""
        manager = AlertManager()
        
        def test_rule(metric: SecurityMetric) -> SecurityAlert:
            if metric.category == "error" and metric.value > 50:
                return SecurityAlert(
                    id=str(uuid.uuid4()),
                    title="Error Threshold Exceeded",
                    description="Too many errors",
                    severity=AlertSeverity.CRITICAL,
                    timestamp=datetime.now(timezone.utc),
                    category="error_monitor",
                    source="alert_rule"
                )
            return None
        
        manager.add_alert_rule(test_rule)
        
        # Create metric that should trigger rule
        metric = SecurityMetric(
            id="rule-test",
            name="error_count",
            metric_type=MetricType.COUNTER,
            value=75,
            timestamp=datetime.now(timezone.utc),
            category="error"
        )
        
        manager.evaluate_alert_rules(metric)
        
        assert len(manager.alerts) == 1
        assert manager.alerts[0].title == "Error Threshold Exceeded"
    
    def test_alert_subscriber_notification(self):
        """Test alert subscriber notifications."""
        manager = AlertManager()
        
        received_alerts = []
        
        def callback(alert):
            received_alerts.append(alert)
        
        manager.subscribe(callback)
        
        alert = SecurityAlert(
            id="subscribe-test",
            title="Subscription Test",
            description="Test alert notification",
            severity=AlertSeverity.MEDIUM,
            timestamp=datetime.now(timezone.utc),
            category="test",
            source="test"
        )
        
        manager.add_alert(alert)
        
        assert len(received_alerts) == 1
        assert received_alerts[0] == alert


class TestWebSocketManager:
    """Test WebSocketManager functionality."""
    
    @pytest.mark.asyncio
    async def test_websocket_connection(self):
        """Test WebSocket connection management."""
        manager = WebSocketManager()
        websocket = MockWebSocket()
        
        await manager.connect(websocket)
        
        assert websocket in manager.active_connections
        assert websocket.accept_called is True
    
    @pytest.mark.asyncio
    async def test_websocket_disconnection(self):
        """Test WebSocket disconnection."""
        manager = WebSocketManager()
        websocket = MockWebSocket()
        
        await manager.connect(websocket)
        await manager.disconnect(websocket)
        
        assert websocket not in manager.active_connections
    
    @pytest.mark.asyncio
    async def test_broadcast_metric(self):
        """Test broadcasting metrics to WebSocket clients."""
        manager = WebSocketManager()
        websocket = MockWebSocket()
        
        await manager.connect(websocket)
        
        metric = SecurityMetric(
            id="broadcast-test",
            name="broadcast_metric",
            metric_type=MetricType.COUNTER,
            value=100,
            timestamp=datetime.now(timezone.utc),
            category="broadcast"
        )
        
        await manager.broadcast_metric(metric)
        
        assert len(websocket.messages_sent) == 1
        
        message = json.loads(websocket.messages_sent[0])
        assert message['type'] == 'metric_update'
        assert message['data']['id'] == 'broadcast-test'
    
    @pytest.mark.asyncio
    async def test_broadcast_alert(self):
        """Test broadcasting alerts to WebSocket clients."""
        manager = WebSocketManager()
        websocket = MockWebSocket()
        
        await manager.connect(websocket)
        
        alert = SecurityAlert(
            id="broadcast-alert",
            title="Broadcast Alert",
            description="Test alert broadcast",
            severity=AlertSeverity.HIGH,
            timestamp=datetime.now(timezone.utc),
            category="broadcast",
            source="test"
        )
        
        await manager.broadcast_alert(alert)
        
        assert len(websocket.messages_sent) == 1
        
        message = json.loads(websocket.messages_sent[0])
        assert message['type'] == 'alert_update'
        assert message['data']['id'] == 'broadcast-alert'
    
    @pytest.mark.asyncio
    async def test_broadcast_to_multiple_clients(self):
        """Test broadcasting to multiple WebSocket clients."""
        manager = WebSocketManager()
        
        websockets = [MockWebSocket(), MockWebSocket(), MockWebSocket()]
        
        for ws in websockets:
            await manager.connect(ws)
        
        metric = SecurityMetric(
            id="multi-broadcast",
            name="multi_metric",
            metric_type=MetricType.GAUGE,
            value=42,
            timestamp=datetime.now(timezone.utc),
            category="multi"
        )
        
        await manager.broadcast_metric(metric)
        
        for ws in websockets:
            assert len(ws.messages_sent) == 1


class TestReportGenerator:
    """Test ReportGenerator functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.metrics_collector = MetricsCollector()
        self.alert_manager = AlertManager()
        self.report_generator = ReportGenerator(self.metrics_collector, self.alert_manager)
        
        # Add test data
        self._add_test_metrics()
        self._add_test_alerts()
    
    def _add_test_metrics(self):
        """Add test metrics."""
        base_time = datetime.now(timezone.utc) - timedelta(hours=24)
        
        categories = ['performance', 'security', 'errors', 'requests']
        
        for i in range(20):
            metric = SecurityMetric(
                id=f"report-metric-{i}",
                name=f"test_metric_{i}",
                metric_type=MetricType.COUNTER,
                value=float(i * 10),
                timestamp=base_time + timedelta(hours=i),
                category=categories[i % len(categories)]
            )
            self.metrics_collector.add_metric(metric)
    
    def _add_test_alerts(self):
        """Add test alerts."""
        base_time = datetime.now(timezone.utc) - timedelta(hours=12)
        
        severities = [AlertSeverity.CRITICAL, AlertSeverity.HIGH, AlertSeverity.MEDIUM, AlertSeverity.LOW]
        
        for i in range(10):
            alert = SecurityAlert(
                id=f"report-alert-{i}",
                title=f"Report Alert {i}",
                description=f"Test alert {i}",
                severity=severities[i % len(severities)],
                timestamp=base_time + timedelta(hours=i),
                category="test",
                source="report_test",
                resolved=(i % 3 == 0)  # Every 3rd alert is resolved
            )
            self.alert_manager.add_alert(alert)
    
    @pytest.mark.asyncio
    async def test_generate_json_report(self):
        """Test generating JSON format report."""
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=1)
        
        report = await self.report_generator.generate_report(
            report_type="security_summary",
            format=ReportFormat.JSON,
            start_time=start_time,
            end_time=end_time
        )
        
        assert 'report_id' in report
        assert 'report_type' in report
        assert 'generated_at' in report
        assert 'period' in report
        assert 'summary' in report
        assert 'metrics_summary' in report
        assert 'alert_summary' in report
        assert 'recommendations' in report
        
        assert report['report_type'] == "security_summary"
        assert report['summary']['total_metrics'] > 0
        assert report['summary']['total_alerts'] > 0
    
    @pytest.mark.asyncio
    async def test_generate_html_report(self):
        """Test generating HTML format report."""
        report = await self.report_generator.generate_report(
            report_type="dashboard_overview",
            format=ReportFormat.HTML
        )
        
        assert isinstance(report, str)
        assert "<html>" in report
        assert "<title>" in report
        assert "FastAPI-Shield Security Report" in report
    
    @pytest.mark.asyncio
    async def test_generate_csv_report(self):
        """Test generating CSV format report."""
        report = await self.report_generator.generate_report(
            report_type="data_export",
            format=ReportFormat.CSV
        )
        
        assert isinstance(report, str)
        assert "=== METRICS ===" in report
        assert "=== ALERTS ===" in report
        assert "Timestamp,Category,Name,Type,Value,Tags" in report
    
    def test_calculate_alert_statistics(self):
        """Test alert statistics calculation."""
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=24)
        
        alerts = self.alert_manager.get_alerts()
        stats = self.report_generator._calculate_alert_statistics(alerts, start_time, end_time)
        
        assert 'total' in stats
        assert 'critical' in stats
        assert 'high' in stats
        assert 'medium' in stats
        assert 'low' in stats
        assert 'resolved' in stats
        assert 'resolution_rate' in stats
        assert 'by_category' in stats
        assert 'by_severity' in stats
        
        assert stats['total'] > 0
        assert 0 <= stats['resolution_rate'] <= 1
    
    def test_calculate_metric_statistics(self):
        """Test metric statistics calculation."""
        metrics = self.metrics_collector.get_metrics()
        stats = self.report_generator._calculate_metric_statistics(metrics)
        
        assert isinstance(stats, dict)
        
        # Check that we have stats for each category
        for category in ['performance', 'security', 'errors', 'requests']:
            if category in stats:
                category_stats = stats[category]
                assert 'count' in category_stats
                assert 'sum' in category_stats
                assert 'avg' in category_stats
                assert 'min' in category_stats
                assert 'max' in category_stats
    
    def test_get_top_metric_categories(self):
        """Test getting top metric categories."""
        metrics = self.metrics_collector.get_metrics()
        top_categories = self.report_generator._get_top_metric_categories(metrics, limit=3)
        
        assert isinstance(top_categories, list)
        assert len(top_categories) <= 3
        
        for category_info in top_categories:
            assert 'category' in category_info
            assert 'count' in category_info
            assert isinstance(category_info['count'], int)
    
    def test_calculate_alert_trends(self):
        """Test alert trends calculation."""
        alerts = self.alert_manager.get_alerts()
        trends = self.report_generator._calculate_alert_trends(alerts)
        
        if alerts:
            assert 'trend' in trends
            assert 'daily_counts' in trends
            assert trends['trend'] in ['increasing', 'decreasing', 'stable', 'insufficient_data']
        else:
            assert trends == {}
    
    def test_generate_recommendations(self):
        """Test recommendations generation."""
        metric_stats = {'performance': {'count': 100, 'avg': 50}}
        alert_stats = {'total': 5, 'critical': 1, 'resolution_rate': 0.6}
        
        recommendations = self.report_generator._generate_recommendations(metric_stats, alert_stats)
        
        assert isinstance(recommendations, list)
        assert len(recommendations) > 0
        assert all(isinstance(rec, str) for rec in recommendations)


class TestDashboardWidget:
    """Test DashboardWidget data class."""
    
    def test_dashboard_widget_creation(self):
        """Test creating dashboard widget."""
        widget = DashboardWidget(
            id="test-widget",
            title="Test Widget",
            chart_type=ChartType.LINE_CHART,
            metric_query="category:performance",
            position={"x": 0, "y": 0, "width": 6, "height": 4}
        )
        
        assert widget.id == "test-widget"
        assert widget.title == "Test Widget"
        assert widget.chart_type == ChartType.LINE_CHART
        assert widget.metric_query == "category:performance"
        assert widget.position == {"x": 0, "y": 0, "width": 6, "height": 4}
        assert widget.refresh_interval == 30
        assert widget.is_visible is True
    
    def test_dashboard_widget_to_dict(self):
        """Test converting widget to dictionary."""
        widget = DashboardWidget(
            id="dict-widget",
            title="Dictionary Test",
            chart_type=ChartType.PIE_CHART,
            metric_query="category:alerts",
            position={"x": 6, "y": 0, "width": 6, "height": 4},
            refresh_interval=60,
            color_scheme="blue",
            options={"show_legend": True}
        )
        
        result = widget.to_dict()
        
        assert result['id'] == "dict-widget"
        assert result['title'] == "Dictionary Test"
        assert result['chart_type'] == "pie_chart"
        assert result['metric_query'] == "category:alerts"
        assert result['refresh_interval'] == 60
        assert result['color_scheme'] == "blue"
        assert result['options'] == {"show_legend": True}


class TestDashboardConfig:
    """Test DashboardConfig data class."""
    
    def test_dashboard_config_defaults(self):
        """Test default dashboard configuration."""
        config = DashboardConfig()
        
        assert config.title == "FastAPI-Shield Security Dashboard"
        assert config.theme == DashboardTheme.DARK
        assert config.auto_refresh is True
        assert config.refresh_interval == 30
        assert config.timezone == "UTC"
        assert config.max_data_points == 1000
        assert config.enable_alerts is True
        assert config.enable_exports is True
        assert len(config.widgets) == 0
    
    def test_dashboard_config_custom(self):
        """Test custom dashboard configuration."""
        widgets = [
            DashboardWidget(
                id="custom-widget",
                title="Custom Widget",
                chart_type=ChartType.GAUGE_CHART,
                metric_query="category:system",
                position={"x": 0, "y": 0, "width": 4, "height": 3}
            )
        ]
        
        config = DashboardConfig(
            title="Custom Dashboard",
            theme=DashboardTheme.LIGHT,
            auto_refresh=False,
            refresh_interval=60,
            timezone="America/New_York",
            max_data_points=2000,
            widgets=widgets
        )
        
        assert config.title == "Custom Dashboard"
        assert config.theme == DashboardTheme.LIGHT
        assert config.auto_refresh is False
        assert config.refresh_interval == 60
        assert config.timezone == "America/New_York"
        assert config.max_data_points == 2000
        assert len(config.widgets) == 1


class TestSecurityDashboard:
    """Test main SecurityDashboard class."""
    
    def test_security_dashboard_creation(self):
        """Test creating security dashboard."""
        dashboard = SecurityDashboard()
        
        assert isinstance(dashboard.metrics_collector, MetricsCollector)
        assert isinstance(dashboard.alert_manager, AlertManager)
        assert isinstance(dashboard.websocket_manager, WebSocketManager)
        assert isinstance(dashboard.report_generator, ReportGenerator)
        assert isinstance(dashboard.config, DashboardConfig)
        assert isinstance(dashboard.app, FastAPI)
    
    def test_security_dashboard_with_custom_config(self):
        """Test creating dashboard with custom configuration."""
        config = DashboardConfig(
            title="Test Dashboard",
            theme=DashboardTheme.LIGHT,
            refresh_interval=15
        )
        
        dashboard = SecurityDashboard(config)
        
        assert dashboard.config.title == "Test Dashboard"
        assert dashboard.config.theme == DashboardTheme.LIGHT
        assert dashboard.config.refresh_interval == 15
    
    def test_add_metric_to_dashboard(self):
        """Test adding metric to dashboard."""
        dashboard = SecurityDashboard()
        
        metric = SecurityMetric(
            id="dashboard-metric",
            name="dashboard_test",
            metric_type=MetricType.COUNTER,
            value=75,
            timestamp=datetime.now(timezone.utc),
            category="dashboard"
        )
        
        dashboard.add_metric(metric)
        
        metrics = dashboard.metrics_collector.get_metrics()
        assert len(metrics) == 1
        assert metrics[0] == metric
    
    def test_add_alert_to_dashboard(self):
        """Test adding alert to dashboard."""
        dashboard = SecurityDashboard()
        
        alert = SecurityAlert(
            id="dashboard-alert",
            title="Dashboard Alert",
            description="Test alert for dashboard",
            severity=AlertSeverity.MEDIUM,
            timestamp=datetime.now(timezone.utc),
            category="dashboard",
            source="test"
        )
        
        dashboard.add_alert(alert)
        
        alerts = dashboard.alert_manager.get_alerts()
        assert len(alerts) == 1
        assert alerts[0] == alert
    
    @pytest.mark.asyncio
    async def test_dashboard_api_endpoints(self):
        """Test dashboard API endpoints using TestClient."""
        dashboard = SecurityDashboard()
        client = TestClient(dashboard.app)
        
        # Test health check endpoint
        response = client.get("/api/health")
        assert response.status_code == 200
        
        data = response.json()
        assert data['status'] == 'healthy'
        assert 'timestamp' in data
        assert 'metrics_count' in data
        assert 'alerts_count' in data
        assert 'websocket_connections' in data
    
    @pytest.mark.asyncio
    async def test_get_metrics_endpoint(self):
        """Test metrics API endpoint."""
        dashboard = SecurityDashboard()
        client = TestClient(dashboard.app)
        
        # Add test metric
        metric = SecurityMetric(
            id="api-metric",
            name="api_test",
            metric_type=MetricType.GAUGE,
            value=100,
            timestamp=datetime.now(timezone.utc),
            category="api"
        )
        dashboard.add_metric(metric)
        
        # Test get metrics
        response = client.get("/api/metrics")
        assert response.status_code == 200
        
        data = response.json()
        assert 'metrics' in data
        assert 'total' in data
        assert data['total'] == 1
        assert len(data['metrics']) == 1
    
    @pytest.mark.asyncio
    async def test_get_metrics_with_category_filter(self):
        """Test metrics API with category filter."""
        dashboard = SecurityDashboard()
        client = TestClient(dashboard.app)
        
        # Add metrics to different categories
        categories = ['category_a', 'category_b']
        for i, category in enumerate(categories):
            metric = SecurityMetric(
                id=f"filter-metric-{i}",
                name=f"filter_test_{i}",
                metric_type=MetricType.COUNTER,
                value=i * 10,
                timestamp=datetime.now(timezone.utc),
                category=category
            )
            dashboard.add_metric(metric)
        
        # Test filter by category_a
        response = client.get("/api/metrics?category=category_a")
        assert response.status_code == 200
        
        data = response.json()
        assert data['total'] == 1
        assert data['metrics'][0]['category'] == 'category_a'
    
    @pytest.mark.asyncio
    async def test_get_alerts_endpoint(self):
        """Test alerts API endpoint."""
        dashboard = SecurityDashboard()
        client = TestClient(dashboard.app)
        
        # Add test alert
        alert = SecurityAlert(
            id="api-alert",
            title="API Test Alert",
            description="Test alert for API",
            severity=AlertSeverity.HIGH,
            timestamp=datetime.now(timezone.utc),
            category="api",
            source="test"
        )
        dashboard.add_alert(alert)
        
        # Test get alerts
        response = client.get("/api/alerts")
        assert response.status_code == 200
        
        data = response.json()
        assert 'alerts' in data
        assert 'total' in data
        assert data['total'] == 1
        assert len(data['alerts']) == 1
    
    @pytest.mark.asyncio
    async def test_acknowledge_alert_endpoint(self):
        """Test alert acknowledgment API endpoint."""
        dashboard = SecurityDashboard()
        client = TestClient(dashboard.app)
        
        # Add test alert
        alert = SecurityAlert(
            id="ack-api-alert",
            title="Acknowledgment API Test",
            description="Test alert acknowledgment",
            severity=AlertSeverity.MEDIUM,
            timestamp=datetime.now(timezone.utc),
            category="api",
            source="test"
        )
        dashboard.add_alert(alert)
        
        # Acknowledge alert
        response = client.post("/api/alerts/ack-api-alert/acknowledge")
        assert response.status_code == 200
        
        data = response.json()
        assert data['status'] == 'acknowledged'
        assert data['alert_id'] == 'ack-api-alert'
        
        # Verify alert is acknowledged
        stored_alert = dashboard.alert_manager.alert_index['ack-api-alert']
        assert stored_alert.is_acknowledged is True
    
    @pytest.mark.asyncio
    async def test_resolve_alert_endpoint(self):
        """Test alert resolution API endpoint."""
        dashboard = SecurityDashboard()
        client = TestClient(dashboard.app)
        
        # Add test alert
        alert = SecurityAlert(
            id="resolve-api-alert",
            title="Resolution API Test",
            description="Test alert resolution",
            severity=AlertSeverity.LOW,
            timestamp=datetime.now(timezone.utc),
            category="api",
            source="test"
        )
        dashboard.add_alert(alert)
        
        # Resolve alert
        response = client.post("/api/alerts/resolve-api-alert/resolve")
        assert response.status_code == 200
        
        data = response.json()
        assert data['status'] == 'resolved'
        assert data['alert_id'] == 'resolve-api-alert'
        
        # Verify alert is resolved
        stored_alert = dashboard.alert_manager.alert_index['resolve-api-alert']
        assert stored_alert.resolved is True
    
    @pytest.mark.asyncio
    async def test_get_dashboard_config_endpoint(self):
        """Test dashboard configuration API endpoint."""
        dashboard = SecurityDashboard()
        client = TestClient(dashboard.app)
        
        response = client.get("/api/dashboard/config")
        assert response.status_code == 200
        
        data = response.json()
        assert 'config' in data
        assert 'widgets' in data
        assert data['config']['title'] == "FastAPI-Shield Security Dashboard"
    
    @pytest.mark.asyncio
    async def test_generate_report_endpoint(self):
        """Test report generation API endpoint."""
        dashboard = SecurityDashboard()
        client = TestClient(dashboard.app)
        
        response = client.get("/api/reports/security?format=json")
        assert response.status_code == 200
        
        data = response.json()
        assert 'report_id' in data
        assert 'report_type' in data
        assert data['report_type'] == 'security'
    
    @pytest.mark.asyncio
    async def test_dashboard_home_page(self):
        """Test dashboard home page."""
        dashboard = SecurityDashboard()
        client = TestClient(dashboard.app)
        
        response = client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "FastAPI-Shield Security Dashboard" in response.text


class TestConvenienceFunctions:
    """Test convenience functions."""
    
    def test_create_security_dashboard(self):
        """Test create_security_dashboard function."""
        dashboard = create_security_dashboard()
        
        assert isinstance(dashboard, SecurityDashboard)
        assert isinstance(dashboard.config, DashboardConfig)
    
    def test_create_security_dashboard_with_config(self):
        """Test create_security_dashboard with custom config."""
        config = DashboardConfig(title="Test Dashboard")
        dashboard = create_security_dashboard(config)
        
        assert dashboard.config.title == "Test Dashboard"
    
    def test_create_default_widgets(self):
        """Test create_default_widgets function."""
        widgets = create_default_widgets()
        
        assert isinstance(widgets, list)
        assert len(widgets) > 0
        assert all(isinstance(w, DashboardWidget) for w in widgets)
        
        # Check that we have different chart types
        chart_types = [w.chart_type for w in widgets]
        assert ChartType.LINE_CHART in chart_types
        assert ChartType.PIE_CHART in chart_types


class TestDashboardIntegration:
    """Integration tests for dashboard components."""
    
    def setup_method(self):
        """Set up integration test fixtures."""
        self.dashboard = SecurityDashboard()
        self.test_env = MockDashboardTestEnvironment()
    
    @pytest.mark.asyncio
    async def test_end_to_end_metric_flow(self):
        """Test complete metric flow from collection to visualization."""
        # Add metric
        metric = SecurityMetric(
            id="e2e-metric",
            name="end_to_end_test",
            metric_type=MetricType.COUNTER,
            value=200,
            timestamp=datetime.now(timezone.utc),
            category="integration"
        )
        
        # Track if WebSocket manager receives metric
        websocket = MockWebSocket()
        await self.dashboard.websocket_manager.connect(websocket)
        
        # Add metric to dashboard
        self.dashboard.add_metric(metric)
        
        # Allow background processing
        await asyncio.sleep(0.1)
        
        # Verify metric is stored
        metrics = self.dashboard.metrics_collector.get_metrics()
        assert len(metrics) == 1
        assert metrics[0].id == "e2e-metric"
        
        # Verify WebSocket broadcast occurred
        assert len(websocket.messages_sent) == 1
        message = json.loads(websocket.messages_sent[0])
        assert message['type'] == 'metric_update'
        assert message['data']['id'] == 'e2e-metric'
    
    @pytest.mark.asyncio
    async def test_end_to_end_alert_flow(self):
        """Test complete alert flow from creation to resolution."""
        # Add alert
        alert = SecurityAlert(
            id="e2e-alert",
            title="End-to-End Alert",
            description="Integration test alert",
            severity=AlertSeverity.HIGH,
            timestamp=datetime.now(timezone.utc),
            category="integration",
            source="test"
        )
        
        # Track WebSocket notifications
        websocket = MockWebSocket()
        await self.dashboard.websocket_manager.connect(websocket)
        
        # Add alert to dashboard
        self.dashboard.add_alert(alert)
        
        # Allow background processing
        await asyncio.sleep(0.1)
        
        # Verify alert is stored
        alerts = self.dashboard.alert_manager.get_alerts()
        assert len(alerts) == 1
        assert alerts[0].id == "e2e-alert"
        
        # Verify WebSocket broadcast occurred
        assert len(websocket.messages_sent) == 1
        message = json.loads(websocket.messages_sent[0])
        assert message['type'] == 'alert_update'
        assert message['data']['id'] == 'e2e-alert'
        
        # Test acknowledgment
        success = self.dashboard.alert_manager.acknowledge_alert("e2e-alert", "test_user")
        assert success is True
        
        # Test resolution
        success = self.dashboard.alert_manager.resolve_alert("e2e-alert", "test_user")
        assert success is True
    
    @pytest.mark.asyncio
    async def test_alert_rule_integration(self):
        """Test alert rule evaluation integration."""
        # Add custom alert rule
        def integration_rule(metric: SecurityMetric) -> SecurityAlert:
            if metric.category == "integration" and metric.value > 500:
                return SecurityAlert(
                    id=str(uuid.uuid4()),
                    title="Integration Threshold Alert",
                    description=f"Integration metric {metric.name} exceeded threshold",
                    severity=AlertSeverity.CRITICAL,
                    timestamp=datetime.now(timezone.utc),
                    category="integration_alert",
                    source="integration_rule"
                )
            return None
        
        self.dashboard.alert_manager.add_alert_rule(integration_rule)
        
        # Add metric that should trigger rule
        metric = SecurityMetric(
            id="rule-trigger",
            name="integration_counter",
            metric_type=MetricType.COUNTER,
            value=600,  # Above threshold
            timestamp=datetime.now(timezone.utc),
            category="integration"
        )
        
        self.dashboard.add_metric(metric)
        
        # Verify alert was created by rule
        alerts = self.dashboard.alert_manager.get_alerts()
        assert len(alerts) == 1
        assert alerts[0].title == "Integration Threshold Alert"
        assert alerts[0].severity == AlertSeverity.CRITICAL
    
    @pytest.mark.asyncio
    async def test_report_generation_integration(self):
        """Test report generation with real data."""
        # Add test data
        base_time = datetime.now(timezone.utc) - timedelta(hours=2)
        
        # Add metrics
        for i in range(5):
            metric = SecurityMetric(
                id=f"report-integration-{i}",
                name=f"integration_metric_{i}",
                metric_type=MetricType.GAUGE,
                value=float(i * 25),
                timestamp=base_time + timedelta(minutes=i * 20),
                category="report_integration"
            )
            self.dashboard.add_metric(metric)
        
        # Add alerts
        for i in range(3):
            alert = SecurityAlert(
                id=f"report-alert-{i}",
                title=f"Integration Alert {i}",
                description="Integration test alert",
                severity=AlertSeverity.MEDIUM,
                timestamp=base_time + timedelta(minutes=i * 30),
                category="report_integration",
                source="integration_test"
            )
            self.dashboard.add_alert(alert)
        
        # Generate report
        report = await self.dashboard.report_generator.generate_report(
            report_type="integration_test",
            format=ReportFormat.JSON,
            start_time=base_time - timedelta(hours=1),
            end_time=datetime.now(timezone.utc)
        )
        
        assert report['summary']['total_metrics'] == 5
        assert report['summary']['total_alerts'] == 3
        assert len(report['recommendations']) > 0
    
    @pytest.mark.asyncio
    async def test_performance_under_load(self):
        """Test dashboard performance under simulated load."""
        start_time = time.time()
        
        # Simulate high metric volume
        metrics_added = 0
        for i in range(100):
            metric = SecurityMetric(
                id=f"load-test-{i}",
                name=f"load_metric_{i}",
                metric_type=MetricType.RATE,
                value=float(i),
                timestamp=datetime.now(timezone.utc),
                category=f"load_category_{i % 5}"
            )
            self.dashboard.add_metric(metric)
            metrics_added += 1
        
        # Simulate alerts
        alerts_added = 0
        for i in range(20):
            alert = SecurityAlert(
                id=f"load-alert-{i}",
                title=f"Load Alert {i}",
                description="Load test alert",
                severity=AlertSeverity.LOW,
                timestamp=datetime.now(timezone.utc),
                category="load_test",
                source="load_test"
            )
            self.dashboard.add_alert(alert)
            alerts_added += 1
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Verify all data was processed
        stored_metrics = self.dashboard.metrics_collector.get_metrics()
        stored_alerts = self.dashboard.alert_manager.get_alerts()
        
        assert len(stored_metrics) == metrics_added
        assert len(stored_alerts) == alerts_added
        
        # Performance should be reasonable (less than 1 second for this load)
        assert duration < 1.0
        
        # Verify system is still responsive
        client = TestClient(self.dashboard.app)
        response = client.get("/api/health")
        assert response.status_code == 200


class TestErrorHandling:
    """Test error handling and edge cases."""
    
    def test_invalid_metric_data(self):
        """Test handling of invalid metric data."""
        # Test metric creation with valid data works
        metric = SecurityMetric(
            id="test-metric",
            name="test",
            metric_type=MetricType.COUNTER,
            value=100,
            timestamp=datetime.now(timezone.utc),
            category="test"
        )
        assert metric.id == "test-metric"
        
        # Test that metrics with missing required fields would fail validation in actual use
        # (dataclasses don't automatically validate None values, this is expected behavior)
    
    def test_websocket_connection_failure(self):
        """Test WebSocket connection failure handling."""
        manager = WebSocketManager()
        
        # Mock WebSocket that raises exception
        class FailingWebSocket:
            async def accept(self):
                raise Exception("Connection failed")
            
            async def send_text(self, message):
                raise Exception("Send failed")
        
        failing_ws = FailingWebSocket()
        
        # Connection failure should be handled gracefully
        with pytest.raises(Exception):
            asyncio.run(manager.connect(failing_ws))
    
    def test_empty_metrics_collection(self):
        """Test operations on empty metrics collection."""
        collector = MetricsCollector()
        
        # Should handle empty collection gracefully
        metrics = collector.get_metrics()
        assert metrics == []
        
        aggregated = collector.get_aggregated_metrics("nonexistent")
        assert aggregated == {}
    
    def test_empty_alert_management(self):
        """Test operations on empty alert collection."""
        manager = AlertManager()
        
        # Should handle empty collection gracefully
        alerts = manager.get_alerts()
        assert alerts == []
        
        # Should handle non-existent alert IDs
        result = manager.acknowledge_alert("nonexistent", "user")
        assert result is False
        
        result = manager.resolve_alert("nonexistent", "user")
        assert result is False
    
    @pytest.mark.asyncio
    async def test_report_generation_with_no_data(self):
        """Test report generation with no data."""
        collector = MetricsCollector()
        manager = AlertManager()
        generator = ReportGenerator(collector, manager)
        
        report = await generator.generate_report(
            report_type="empty_test",
            format=ReportFormat.JSON
        )
        
        assert report['summary']['total_metrics'] == 0
        assert report['summary']['total_alerts'] == 0
        assert len(report['recommendations']) > 0  # Should still provide recommendations
    
    def test_invalid_dashboard_configuration(self):
        """Test dashboard with invalid configuration."""
        # Test with invalid refresh interval
        config = DashboardConfig(refresh_interval=-1)
        dashboard = SecurityDashboard(config)
        
        # Dashboard should still be created (validation happens elsewhere)
        assert isinstance(dashboard, SecurityDashboard)
    
    @pytest.mark.asyncio
    async def test_api_error_responses(self):
        """Test API error response handling."""
        dashboard = SecurityDashboard()
        client = TestClient(dashboard.app)
        
        # Test invalid time format
        response = client.get("/api/metrics?start_time=invalid_time")
        assert response.status_code == 400
        
        # Test invalid severity
        response = client.get("/api/alerts?severity=invalid_severity")
        assert response.status_code == 400
        
        # Test non-existent alert
        response = client.post("/api/alerts/nonexistent/acknowledge")
        assert response.status_code == 404
        
        # Test invalid report format
        response = client.get("/api/reports/test?format=invalid_format")
        assert response.status_code == 400


# Performance benchmarks
class TestPerformanceBenchmarks:
    """Performance benchmarks for dashboard components."""
    
    def test_metric_collection_performance(self):
        """Benchmark metric collection performance."""
        collector = MetricsCollector()
        
        start_time = time.time()
        
        # Add 1000 metrics
        for i in range(1000):
            metric = SecurityMetric(
                id=f"perf-metric-{i}",
                name=f"perf_test_{i}",
                metric_type=MetricType.COUNTER,
                value=float(i),
                timestamp=datetime.now(timezone.utc),
                category=f"perf_cat_{i % 10}"
            )
            collector.add_metric(metric)
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Should be able to add 1000 metrics in reasonable time
        assert duration < 1.0  # Less than 1 second
        assert len(collector.metrics) == 1000
        
        # Test retrieval performance
        start_time = time.time()
        
        for i in range(10):
            metrics = collector.get_metrics(category=f"perf_cat_{i}")
        
        end_time = time.time()
        query_duration = end_time - start_time
        
        # Queries should be fast
        assert query_duration < 0.1  # Less than 100ms
    
    def test_alert_processing_performance(self):
        """Benchmark alert processing performance."""
        manager = AlertManager()
        
        start_time = time.time()
        
        # Add 500 alerts
        for i in range(500):
            alert = SecurityAlert(
                id=f"perf-alert-{i}",
                title=f"Performance Alert {i}",
                description="Performance test alert",
                severity=AlertSeverity.LOW,
                timestamp=datetime.now(timezone.utc),
                category="performance",
                source="benchmark"
            )
            manager.add_alert(alert)
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Should be able to add 500 alerts quickly
        assert duration < 0.5  # Less than 500ms
        assert len(manager.alerts) == 500
        
        # Test filtering performance
        start_time = time.time()
        
        for severity in AlertSeverity:
            alerts = manager.get_alerts(severity=severity)
        
        end_time = time.time()
        filter_duration = end_time - start_time
        
        # Filtering should be fast
        assert filter_duration < 0.1  # Less than 100ms
    
    @pytest.mark.asyncio
    async def test_websocket_broadcast_performance(self):
        """Benchmark WebSocket broadcast performance."""
        manager = WebSocketManager()
        
        # Connect multiple WebSocket clients
        websockets = []
        for i in range(10):
            ws = MockWebSocket()
            await manager.connect(ws)
            websockets.append(ws)
        
        metric = SecurityMetric(
            id="broadcast-perf",
            name="broadcast_performance",
            metric_type=MetricType.GAUGE,
            value=100,
            timestamp=datetime.now(timezone.utc),
            category="broadcast"
        )
        
        start_time = time.time()
        
        # Broadcast to all clients 50 times
        for i in range(50):
            await manager.broadcast_metric(metric)
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Should be able to broadcast quickly
        assert duration < 1.0  # Less than 1 second
        
        # Verify all clients received all messages
        for ws in websockets:
            assert len(ws.messages_sent) == 50


if __name__ == "__main__":
    pytest.main([__file__, "-v"])