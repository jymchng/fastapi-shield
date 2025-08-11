"""Mock infrastructure for security dashboard testing."""

import asyncio
import json
import time
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Callable, Set
from unittest.mock import Mock, AsyncMock
import uuid

from fastapi import WebSocket
from fastapi.testclient import TestClient

from src.fastapi_shield.security_dashboard import (
    SecurityMetric, SecurityAlert, MetricType, AlertSeverity,
    ChartType, DashboardWidget, DashboardConfig
)


class MockWebSocket:
    """Mock WebSocket for testing."""
    
    def __init__(self):
        self.is_connected = False
        self.messages_sent = []
        self.messages_received = []
        self.accept_called = False
        self.close_called = False
        
    async def accept(self):
        """Mock accept connection."""
        self.is_connected = True
        self.accept_called = True
    
    async def send_text(self, message: str):
        """Mock send text message."""
        if not self.is_connected:
            raise Exception("WebSocket not connected")
        self.messages_sent.append(message)
    
    async def receive_text(self) -> str:
        """Mock receive text message."""
        if not self.is_connected:
            raise Exception("WebSocket not connected")
        if self.messages_received:
            return self.messages_received.pop(0)
        # Simulate waiting for message
        await asyncio.sleep(0.1)
        return json.dumps({"type": "ping"})
    
    def add_received_message(self, message: str):
        """Add message to received queue."""
        self.messages_received.append(message)
    
    def close(self):
        """Mock close connection."""
        self.is_connected = False
        self.close_called = True


class MockMetricsDatabase:
    """Mock database for metrics storage."""
    
    def __init__(self):
        self.metrics = []
        self.queries_executed = []
        self.connection_count = 0
    
    def store_metric(self, metric: SecurityMetric):
        """Store a metric."""
        self.metrics.append(metric)
        return True
    
    def query_metrics(self, filters: Dict[str, Any] = None) -> List[SecurityMetric]:
        """Query metrics with filters."""
        self.queries_executed.append(filters or {})
        
        if not filters:
            return self.metrics
        
        filtered = []
        for metric in self.metrics:
            match = True
            
            if 'category' in filters and metric.category != filters['category']:
                match = False
            if 'start_time' in filters and metric.timestamp < filters['start_time']:
                match = False
            if 'end_time' in filters and metric.timestamp > filters['end_time']:
                match = False
            
            if match:
                filtered.append(metric)
        
        return filtered
    
    def get_aggregated_data(self, category: str) -> Dict[str, Any]:
        """Get aggregated metrics data."""
        category_metrics = [m for m in self.metrics if m.category == category]
        
        if not category_metrics:
            return {}
        
        values = [m.value for m in category_metrics]
        return {
            'count': len(category_metrics),
            'sum': sum(values),
            'avg': sum(values) / len(values),
            'min': min(values),
            'max': max(values)
        }


class MockAlertNotificationService:
    """Mock alert notification service."""
    
    def __init__(self):
        self.notifications_sent = []
        self.email_recipients = []
        self.sms_recipients = []
        self.webhook_urls = []
        self.notification_failures = []
    
    async def send_email_notification(self, alert: SecurityAlert, recipients: List[str]):
        """Mock send email notification."""
        self.notifications_sent.append({
            'type': 'email',
            'alert_id': alert.id,
            'recipients': recipients,
            'timestamp': datetime.now(timezone.utc)
        })
        self.email_recipients.extend(recipients)
        return True
    
    async def send_sms_notification(self, alert: SecurityAlert, recipients: List[str]):
        """Mock send SMS notification."""
        self.notifications_sent.append({
            'type': 'sms',
            'alert_id': alert.id,
            'recipients': recipients,
            'timestamp': datetime.now(timezone.utc)
        })
        self.sms_recipients.extend(recipients)
        return True
    
    async def send_webhook_notification(self, alert: SecurityAlert, webhook_urls: List[str]):
        """Mock send webhook notification."""
        self.notifications_sent.append({
            'type': 'webhook',
            'alert_id': alert.id,
            'urls': webhook_urls,
            'timestamp': datetime.now(timezone.utc)
        })
        self.webhook_urls.extend(webhook_urls)
        return True
    
    def simulate_failure(self, notification_type: str):
        """Simulate notification failure."""
        self.notification_failures.append(notification_type)
        return False


class MockReportExporter:
    """Mock report export service."""
    
    def __init__(self):
        self.exports_generated = []
        self.export_failures = []
        self.storage_location = "/tmp/mock_reports"
    
    async def export_to_pdf(self, report_data: Dict[str, Any]) -> str:
        """Mock PDF export."""
        export_id = str(uuid.uuid4())
        file_path = f"{self.storage_location}/report_{export_id}.pdf"
        
        self.exports_generated.append({
            'id': export_id,
            'type': 'pdf',
            'file_path': file_path,
            'size_bytes': len(json.dumps(report_data)) * 2,  # Simulate PDF size
            'timestamp': datetime.now(timezone.utc)
        })
        
        return file_path
    
    async def export_to_excel(self, report_data: Dict[str, Any]) -> str:
        """Mock Excel export."""
        export_id = str(uuid.uuid4())
        file_path = f"{self.storage_location}/report_{export_id}.xlsx"
        
        self.exports_generated.append({
            'id': export_id,
            'type': 'excel',
            'file_path': file_path,
            'size_bytes': len(json.dumps(report_data)),
            'timestamp': datetime.now(timezone.utc)
        })
        
        return file_path
    
    async def export_to_csv(self, data: List[Dict[str, Any]]) -> str:
        """Mock CSV export."""
        export_id = str(uuid.uuid4())
        file_path = f"{self.storage_location}/data_{export_id}.csv"
        
        self.exports_generated.append({
            'id': export_id,
            'type': 'csv',
            'file_path': file_path,
            'size_bytes': sum(len(str(row)) for row in data),
            'timestamp': datetime.now(timezone.utc)
        })
        
        return file_path
    
    def simulate_export_failure(self, export_type: str):
        """Simulate export failure."""
        self.export_failures.append(export_type)
        raise Exception(f"Mock export failure for {export_type}")


class MockChartRenderer:
    """Mock chart rendering service."""
    
    def __init__(self):
        self.charts_rendered = []
        self.render_failures = []
        self.supported_formats = ['png', 'svg', 'html']
    
    async def render_line_chart(self, data: List[Dict[str, Any]], options: Dict[str, Any] = None) -> str:
        """Mock line chart rendering."""
        chart_id = str(uuid.uuid4())
        
        self.charts_rendered.append({
            'id': chart_id,
            'type': 'line_chart',
            'data_points': len(data),
            'options': options or {},
            'timestamp': datetime.now(timezone.utc)
        })
        
        return f"<svg id='{chart_id}'>Mock Line Chart</svg>"
    
    async def render_pie_chart(self, data: List[Dict[str, Any]], options: Dict[str, Any] = None) -> str:
        """Mock pie chart rendering."""
        chart_id = str(uuid.uuid4())
        
        self.charts_rendered.append({
            'id': chart_id,
            'type': 'pie_chart',
            'data_points': len(data),
            'options': options or {},
            'timestamp': datetime.now(timezone.utc)
        })
        
        return f"<svg id='{chart_id}'>Mock Pie Chart</svg>"
    
    async def render_gauge_chart(self, value: float, options: Dict[str, Any] = None) -> str:
        """Mock gauge chart rendering."""
        chart_id = str(uuid.uuid4())
        
        self.charts_rendered.append({
            'id': chart_id,
            'type': 'gauge_chart',
            'value': value,
            'options': options or {},
            'timestamp': datetime.now(timezone.utc)
        })
        
        return f"<svg id='{chart_id}'>Mock Gauge Chart - {value}</svg>"
    
    async def render_heatmap(self, data: List[List[float]], options: Dict[str, Any] = None) -> str:
        """Mock heatmap rendering."""
        chart_id = str(uuid.uuid4())
        
        self.charts_rendered.append({
            'id': chart_id,
            'type': 'heatmap',
            'data_dimensions': f"{len(data)}x{len(data[0]) if data else 0}",
            'options': options or {},
            'timestamp': datetime.now(timezone.utc)
        })
        
        return f"<svg id='{chart_id}'>Mock Heatmap</svg>"
    
    def simulate_render_failure(self, chart_type: str):
        """Simulate chart rendering failure."""
        self.render_failures.append(chart_type)
        raise Exception(f"Mock rendering failure for {chart_type}")


class MockAnalyticsEngine:
    """Mock analytics engine for advanced calculations."""
    
    def __init__(self):
        self.calculations_performed = []
        self.analysis_results = {}
        self.prediction_accuracy = 0.85
    
    async def calculate_trends(self, metrics: List[SecurityMetric]) -> Dict[str, Any]:
        """Mock trend calculation."""
        self.calculations_performed.append({
            'type': 'trends',
            'metric_count': len(metrics),
            'timestamp': datetime.now(timezone.utc)
        })
        
        # Simulate trend calculation
        categories = list(set(m.category for m in metrics))
        trends = {}
        
        for category in categories:
            category_metrics = [m for m in metrics if m.category == category]
            if len(category_metrics) >= 2:
                # Simple trend: compare first and last values
                first_value = category_metrics[0].value
                last_value = category_metrics[-1].value
                
                if last_value > first_value * 1.1:
                    trend = "increasing"
                elif last_value < first_value * 0.9:
                    trend = "decreasing"
                else:
                    trend = "stable"
                
                trends[category] = {
                    'direction': trend,
                    'change_percent': ((last_value - first_value) / first_value) * 100 if first_value != 0 else 0,
                    'confidence': 0.8
                }
        
        return trends
    
    async def detect_anomalies(self, metrics: List[SecurityMetric]) -> List[Dict[str, Any]]:
        """Mock anomaly detection."""
        self.calculations_performed.append({
            'type': 'anomalies',
            'metric_count': len(metrics),
            'timestamp': datetime.now(timezone.utc)
        })
        
        anomalies = []
        
        # Simulate finding anomalies in high-value metrics
        for metric in metrics:
            if metric.value > 1000:  # Arbitrary threshold for demo
                anomalies.append({
                    'metric_id': metric.id,
                    'metric_name': metric.name,
                    'category': metric.category,
                    'value': metric.value,
                    'expected_range': [0, 500],
                    'anomaly_score': min(1.0, metric.value / 1000),
                    'timestamp': metric.timestamp.isoformat()
                })
        
        return anomalies
    
    async def predict_future_values(self, metrics: List[SecurityMetric], horizon_minutes: int = 60) -> Dict[str, List[float]]:
        """Mock value prediction."""
        self.calculations_performed.append({
            'type': 'prediction',
            'metric_count': len(metrics),
            'horizon_minutes': horizon_minutes,
            'timestamp': datetime.now(timezone.utc)
        })
        
        predictions = {}
        categories = list(set(m.category for m in metrics))
        
        for category in categories:
            category_metrics = [m for m in metrics if m.category == category]
            if category_metrics:
                # Simple prediction: linear extrapolation
                last_value = category_metrics[-1].value
                trend_factor = 1.05 if len(category_metrics) > 1 else 1.0
                
                prediction_points = []
                for i in range(horizon_minutes):
                    predicted_value = last_value * (trend_factor ** (i / 60))
                    prediction_points.append(predicted_value)
                
                predictions[category] = prediction_points
        
        return predictions
    
    async def generate_insights(self, metrics: List[SecurityMetric], alerts: List[SecurityAlert]) -> List[str]:
        """Mock insight generation."""
        self.calculations_performed.append({
            'type': 'insights',
            'metric_count': len(metrics),
            'alert_count': len(alerts),
            'timestamp': datetime.now(timezone.utc)
        })
        
        insights = []
        
        # Generate mock insights based on data patterns
        if len(alerts) > 10:
            insights.append("High alert volume detected in the last period")
        
        critical_alerts = [a for a in alerts if a.severity == AlertSeverity.CRITICAL]
        if critical_alerts:
            insights.append(f"{len(critical_alerts)} critical alerts require immediate attention")
        
        category_counts = defaultdict(int)
        for metric in metrics:
            category_counts[metric.category] += 1
        
        if category_counts:
            top_category = max(category_counts.items(), key=lambda x: x[1])
            insights.append(f"Highest metric activity in '{top_category[0]}' category ({top_category[1]} metrics)")
        
        if not insights:
            insights.append("System operating within normal parameters")
        
        return insights


class MockDashboardTestEnvironment:
    """Comprehensive mock environment for dashboard testing."""
    
    def __init__(self):
        self.metrics_db = MockMetricsDatabase()
        self.notification_service = MockAlertNotificationService()
        self.report_exporter = MockReportExporter()
        self.chart_renderer = MockChartRenderer()
        self.analytics_engine = MockAnalyticsEngine()
        
        # Test data generators
        self.test_metrics = self._generate_test_metrics()
        self.test_alerts = self._generate_test_alerts()
        self.test_widgets = self._generate_test_widgets()
        
        # Performance tracking
        self.response_times = []
        self.memory_usage = []
        self.api_calls = []
    
    def _generate_test_metrics(self) -> List[SecurityMetric]:
        """Generate test security metrics."""
        metrics = []
        categories = ['security_events', 'performance', 'errors', 'requests', 'authentication']
        
        base_time = datetime.now(timezone.utc) - timedelta(hours=24)
        
        for i in range(100):
            timestamp = base_time + timedelta(minutes=i * 15)
            category = categories[i % len(categories)]
            
            metric = SecurityMetric(
                id=str(uuid.uuid4()),
                name=f"test_metric_{i}",
                metric_type=MetricType.COUNTER,
                value=float(i * 10 + (i % 7) * 50),  # Varying values
                timestamp=timestamp,
                category=category,
                tags={
                    'environment': 'test',
                    'source': 'mock_generator',
                    'priority': 'medium' if i % 3 == 0 else 'low'
                },
                metadata={
                    'test_index': i,
                    'batch_id': f"batch_{i // 10}"
                }
            )
            metrics.append(metric)
        
        return metrics
    
    def _generate_test_alerts(self) -> List[SecurityAlert]:
        """Generate test security alerts."""
        alerts = []
        severities = list(AlertSeverity)
        categories = ['security', 'performance', 'system', 'network']
        
        base_time = datetime.now(timezone.utc) - timedelta(hours=12)
        
        for i in range(20):
            timestamp = base_time + timedelta(minutes=i * 30)
            severity = severities[i % len(severities)]
            category = categories[i % len(categories)]
            
            alert = SecurityAlert(
                id=str(uuid.uuid4()),
                title=f"Test Alert {i + 1}",
                description=f"This is a test alert for {category} issues",
                severity=severity,
                timestamp=timestamp,
                category=category,
                source="test_generator",
                affected_resources=[f"resource_{i}", f"component_{i % 3}"],
                recommended_actions=[
                    f"Action 1 for alert {i + 1}",
                    f"Action 2 for alert {i + 1}"
                ],
                is_acknowledged=i % 4 == 0,
                resolved=i % 5 == 0,
                metadata={
                    'test_alert': True,
                    'alert_index': i
                }
            )
            alerts.append(alert)
        
        return alerts
    
    def _generate_test_widgets(self) -> List[DashboardWidget]:
        """Generate test dashboard widgets."""
        return [
            DashboardWidget(
                id="test_line_chart",
                title="Test Line Chart",
                chart_type=ChartType.LINE_CHART,
                metric_query="category:performance",
                position={"x": 0, "y": 0, "width": 6, "height": 4}
            ),
            DashboardWidget(
                id="test_pie_chart",
                title="Test Pie Chart",
                chart_type=ChartType.PIE_CHART,
                metric_query="category:*",
                position={"x": 6, "y": 0, "width": 6, "height": 4}
            ),
            DashboardWidget(
                id="test_gauge",
                title="Test Gauge",
                chart_type=ChartType.GAUGE_CHART,
                metric_query="category:system",
                position={"x": 0, "y": 4, "width": 4, "height": 3}
            )
        ]
    
    def track_api_call(self, endpoint: str, response_time: float, status_code: int):
        """Track API call for performance analysis."""
        self.api_calls.append({
            'endpoint': endpoint,
            'response_time': response_time,
            'status_code': status_code,
            'timestamp': datetime.now(timezone.utc)
        })
        self.response_times.append(response_time)
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics."""
        if not self.response_times:
            return {'status': 'no_data'}
        
        return {
            'avg_response_time': sum(self.response_times) / len(self.response_times),
            'max_response_time': max(self.response_times),
            'min_response_time': min(self.response_times),
            'total_api_calls': len(self.api_calls),
            'success_rate': len([c for c in self.api_calls if c['status_code'] < 400]) / len(self.api_calls)
        }
    
    def simulate_high_load(self, duration_seconds: int = 10):
        """Simulate high load scenario."""
        start_time = time.time()
        metrics_generated = 0
        alerts_generated = 0
        
        while time.time() - start_time < duration_seconds:
            # Generate rapid metrics
            for i in range(10):
                metric = SecurityMetric(
                    id=str(uuid.uuid4()),
                    name=f"high_load_metric_{metrics_generated}",
                    metric_type=MetricType.RATE,
                    value=float(metrics_generated * 2),
                    timestamp=datetime.now(timezone.utc),
                    category="high_load_test",
                    tags={'load_test': True}
                )
                self.metrics_db.store_metric(metric)
                metrics_generated += 1
            
            # Generate some alerts
            if metrics_generated % 50 == 0:
                alert = SecurityAlert(
                    id=str(uuid.uuid4()),
                    title="High Load Alert",
                    description="System under high load during testing",
                    severity=AlertSeverity.MEDIUM,
                    timestamp=datetime.now(timezone.utc),
                    category="load_test",
                    source="load_simulator"
                )
                alerts_generated += 1
            
            time.sleep(0.1)
        
        return {
            'duration': duration_seconds,
            'metrics_generated': metrics_generated,
            'alerts_generated': alerts_generated,
            'avg_rate': metrics_generated / duration_seconds
        }
    
    def reset(self):
        """Reset all mock services to clean state."""
        self.metrics_db = MockMetricsDatabase()
        self.notification_service = MockAlertNotificationService()
        self.report_exporter = MockReportExporter()
        self.chart_renderer = MockChartRenderer()
        self.analytics_engine = MockAnalyticsEngine()
        self.response_times.clear()
        self.memory_usage.clear()
        self.api_calls.clear()


# Export all mock classes
__all__ = [
    'MockWebSocket',
    'MockMetricsDatabase',
    'MockAlertNotificationService',
    'MockReportExporter',
    'MockChartRenderer',
    'MockAnalyticsEngine',
    'MockDashboardTestEnvironment'
]