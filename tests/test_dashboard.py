"""Tests for Shield Metrics Dashboard."""

import asyncio
import json
import pytest
import sqlite3
import tempfile
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch, Mock, MagicMock
from fastapi.testclient import TestClient

from fastapi_shield.dashboard import (
    MetricsDashboard,
    DashboardConfig,
    DashboardMiddleware,
    MetricType,
    AlertSeverity,
    AlertStatus,
    DashboardTheme,
    Metric,
    MetricValue,
    Alert,
    AlertRule,
    AlertManager,
    SQLiteMetricStorage,
    DashboardWebSocketManager,
    create_dashboard,
    create_alert_rule,
)

from tests.mocks.dashboard_mocks import (
    MockMetricStorage,
    MockWebSocket,
    DashboardTestScenarios,
    AlertManagerTestHelper,
    DashboardTestClient,
    MetricsGeneratorHelper,
    TempDatabaseHelper,
)


class TestMetricValue:
    """Test MetricValue functionality."""
    
    def test_basic_metric_value_creation(self):
        """Test basic metric value creation."""
        timestamp = datetime.now(timezone.utc)
        labels = {"method": "GET", "status": "200"}
        
        value = MetricValue(
            value=42.5,
            timestamp=timestamp,
            labels=labels
        )
        
        assert value.value == 42.5
        assert value.timestamp == timestamp
        assert value.labels == labels
    
    def test_metric_value_to_dict(self):
        """Test metric value serialization."""
        timestamp = datetime.now(timezone.utc)
        labels = {"test": "value"}
        
        value = MetricValue(
            value=100,
            timestamp=timestamp,
            labels=labels
        )
        
        result = value.to_dict()
        
        assert result["value"] == 100
        assert result["timestamp"] == timestamp.isoformat()
        assert result["labels"] == labels
    
    def test_metric_value_without_labels(self):
        """Test metric value creation without labels."""
        timestamp = datetime.now(timezone.utc)
        
        value = MetricValue(value=10, timestamp=timestamp)
        
        assert value.labels == {}


class TestMetric:
    """Test Metric functionality."""
    
    def test_basic_metric_creation(self):
        """Test basic metric creation."""
        metric = Metric(
            name="test_metric",
            type=MetricType.COUNTER,
            description="Test metric",
            unit="count"
        )
        
        assert metric.name == "test_metric"
        assert metric.type == MetricType.COUNTER
        assert metric.description == "Test metric"
        assert metric.unit == "count"
        assert len(metric.values) == 0
        assert len(metric.labels) == 0
    
    def test_add_metric_value(self):
        """Test adding values to metric."""
        metric = Metric("test_counter", MetricType.COUNTER)
        
        labels = {"endpoint": "/api/test"}
        metric.add_value(10, labels)
        
        assert len(metric.values) == 1
        assert metric.values[0].value == 10
        assert metric.values[0].labels == labels
        assert "endpoint" in metric.labels
    
    def test_get_latest_value(self):
        """Test getting latest metric value."""
        metric = Metric("test_gauge", MetricType.GAUGE)
        
        # Empty metric
        assert metric.get_latest() is None
        
        # Add values
        metric.add_value(10)
        metric.add_value(20)
        
        latest = metric.get_latest()
        assert latest.value == 20
    
    def test_get_values_since(self):
        """Test getting values since timestamp."""
        metric = Metric("test_metric", MetricType.GAUGE)
        
        base_time = datetime.now(timezone.utc) - timedelta(minutes=10)
        
        # Add values at different times
        for i in range(5):
            timestamp = base_time + timedelta(minutes=i * 2)
            value = MetricValue(value=i, timestamp=timestamp)
            metric.values.append(value)
        
        # Get values since 5 minutes ago
        since = base_time + timedelta(minutes=5)
        recent_values = metric.get_values_since(since)
        
        # Values are at 0, 2, 4, 6, 8 minutes from base_time
        # Since = 5 minutes from base_time
        # Values >= 5 minutes are: 6, 8 minutes = 2 values
        assert len(recent_values) == 2  # Values at 6, 8 minutes
        assert all(v.timestamp >= since for v in recent_values)
    
    def test_get_values_in_range(self):
        """Test getting values within time range."""
        metric = Metric("test_metric", MetricType.GAUGE)
        
        base_time = datetime.now(timezone.utc) - timedelta(minutes=10)
        
        # Add values at different times
        for i in range(6):
            timestamp = base_time + timedelta(minutes=i * 2)
            value = MetricValue(value=i, timestamp=timestamp)
            metric.values.append(value)
        
        # Get values between 2-8 minutes ago
        start = base_time + timedelta(minutes=2)
        end = base_time + timedelta(minutes=8)
        range_values = metric.get_values_in_range(start, end)
        
        assert len(range_values) == 4  # Values at 2, 4, 6, 8 minutes
        assert all(start <= v.timestamp <= end for v in range_values)
    
    def test_calculate_rate_counter(self):
        """Test rate calculation for counter metrics."""
        metric = Metric("requests_total", MetricType.COUNTER)
        
        base_time = datetime.now(timezone.utc) - timedelta(seconds=120)
        
        # Add counter values (cumulative)
        for i in range(5):
            timestamp = base_time + timedelta(seconds=i * 30)
            value = MetricValue(value=i * 10, timestamp=timestamp)  # 0, 10, 20, 30, 40
            metric.values.append(value)
        
        rate = metric.calculate_rate(60)  # 60 second window
        
        # Rate should be increase per second
        # Last 60 seconds: from 20 to 40 = 20 increase over 60 seconds = 0.33/sec
        assert rate > 0
        assert rate < 1  # Should be less than 1 per second
    
    def test_calculate_rate_insufficient_data(self):
        """Test rate calculation with insufficient data."""
        metric = Metric("test_metric", MetricType.COUNTER)
        
        # No data
        assert metric.calculate_rate() == 0.0
        
        # Single data point
        metric.add_value(10)
        assert metric.calculate_rate() == 0.0


class TestAlertRule:
    """Test AlertRule functionality."""
    
    def test_basic_alert_rule_creation(self):
        """Test basic alert rule creation."""
        rule = AlertRule(
            id="test-rule",
            name="Test Alert",
            metric_name="cpu_usage",
            condition="gt",
            threshold=80.0,
            duration=60,
            severity=AlertSeverity.WARNING
        )
        
        assert rule.id == "test-rule"
        assert rule.name == "Test Alert"
        assert rule.metric_name == "cpu_usage"
        assert rule.condition == "gt"
        assert rule.threshold == 80.0
        assert rule.duration == 60
        assert rule.severity == AlertSeverity.WARNING
        assert rule.enabled is True
        assert rule.trigger_count == 0
    
    def test_alert_rule_evaluation_gt(self):
        """Test alert rule evaluation with greater than condition."""
        rule = AlertRule(
            id="test",
            name="Test",
            metric_name="test",
            condition="gt",
            threshold=50.0,
            duration=60,
            severity=AlertSeverity.WARNING
        )
        
        # Value above threshold
        value_high = MetricValue(value=60.0, timestamp=datetime.now(timezone.utc))
        assert rule.evaluate(value_high) is True
        
        # Value below threshold
        value_low = MetricValue(value=40.0, timestamp=datetime.now(timezone.utc))
        assert rule.evaluate(value_low) is False
        
        # Value equal to threshold
        value_equal = MetricValue(value=50.0, timestamp=datetime.now(timezone.utc))
        assert rule.evaluate(value_equal) is False
    
    def test_alert_rule_evaluation_lt(self):
        """Test alert rule evaluation with less than condition."""
        rule = AlertRule(
            id="test",
            name="Test",
            metric_name="test",
            condition="lt",
            threshold=50.0,
            duration=60,
            severity=AlertSeverity.WARNING
        )
        
        # Value below threshold
        value_low = MetricValue(value=40.0, timestamp=datetime.now(timezone.utc))
        assert rule.evaluate(value_low) is True
        
        # Value above threshold
        value_high = MetricValue(value=60.0, timestamp=datetime.now(timezone.utc))
        assert rule.evaluate(value_high) is False
    
    def test_alert_rule_evaluation_disabled(self):
        """Test disabled alert rule evaluation."""
        rule = AlertRule(
            id="test",
            name="Test",
            metric_name="test",
            condition="gt",
            threshold=50.0,
            duration=60,
            severity=AlertSeverity.WARNING,
            enabled=False
        )
        
        value = MetricValue(value=100.0, timestamp=datetime.now(timezone.utc))
        assert rule.evaluate(value) is False
    
    def test_alert_rule_to_dict(self):
        """Test alert rule serialization."""
        rule = AlertRule(
            id="test-rule",
            name="Test Alert",
            metric_name="cpu_usage",
            condition="gt",
            threshold=80.0,
            duration=60,
            severity=AlertSeverity.WARNING,
            description="Test description"
        )
        
        result = rule.to_dict()
        
        assert result["id"] == "test-rule"
        assert result["name"] == "Test Alert"
        assert result["metric_name"] == "cpu_usage"
        assert result["condition"] == "gt"
        assert result["threshold"] == 80.0
        assert result["severity"] == "warning"
        assert result["description"] == "Test description"


class TestAlert:
    """Test Alert functionality."""
    
    def test_basic_alert_creation(self):
        """Test basic alert creation."""
        alert = Alert(
            id="alert-1",
            rule_id="rule-1",
            rule_name="Test Rule",
            metric_name="cpu_usage",
            metric_value=85.0,
            threshold=80.0,
            severity=AlertSeverity.WARNING,
            status=AlertStatus.ACTIVE,
            message="CPU usage too high"
        )
        
        assert alert.id == "alert-1"
        assert alert.rule_id == "rule-1"
        assert alert.severity == AlertSeverity.WARNING
        assert alert.status == AlertStatus.ACTIVE
        assert alert.resolved_at is None
        assert alert.acknowledged_at is None
    
    def test_alert_acknowledge(self):
        """Test alert acknowledgment."""
        alert = Alert(
            id="alert-1",
            rule_id="rule-1",
            rule_name="Test Rule",
            metric_name="cpu_usage",
            metric_value=85.0,
            threshold=80.0,
            severity=AlertSeverity.WARNING,
            status=AlertStatus.ACTIVE,
            message="Test alert"
        )
        
        alert.acknowledge("testuser")
        
        assert alert.status == AlertStatus.ACKNOWLEDGED
        assert alert.acknowledged_by == "testuser"
        assert alert.acknowledged_at is not None
    
    def test_alert_resolve(self):
        """Test alert resolution."""
        alert = Alert(
            id="alert-1",
            rule_id="rule-1",
            rule_name="Test Rule",
            metric_name="cpu_usage",
            metric_value=85.0,
            threshold=80.0,
            severity=AlertSeverity.WARNING,
            status=AlertStatus.ACTIVE,
            message="Test alert"
        )
        
        alert.resolve()
        
        assert alert.status == AlertStatus.RESOLVED
        assert alert.resolved_at is not None
    
    def test_alert_silence(self):
        """Test alert silencing."""
        alert = Alert(
            id="alert-1",
            rule_id="rule-1",
            rule_name="Test Rule",
            metric_name="cpu_usage",
            metric_value=85.0,
            threshold=80.0,
            severity=AlertSeverity.WARNING,
            status=AlertStatus.ACTIVE,
            message="Test alert"
        )
        
        alert.silence()
        
        assert alert.status == AlertStatus.SILENCED
    
    def test_alert_to_dict(self):
        """Test alert serialization."""
        alert = Alert(
            id="alert-1",
            rule_id="rule-1",
            rule_name="Test Rule",
            metric_name="cpu_usage",
            metric_value=85.0,
            threshold=80.0,
            severity=AlertSeverity.WARNING,
            status=AlertStatus.ACTIVE,
            message="Test alert",
            labels={"host": "server1"}
        )
        
        result = alert.to_dict()
        
        assert result["id"] == "alert-1"
        assert result["rule_id"] == "rule-1"
        assert result["metric_name"] == "cpu_usage"
        assert result["metric_value"] == 85.0
        assert result["severity"] == "warning"
        assert result["status"] == "active"
        assert result["labels"] == {"host": "server1"}


class TestSQLiteMetricStorage:
    """Test SQLiteMetricStorage functionality."""
    
    @pytest.mark.asyncio
    async def test_store_and_retrieve_metric(self):
        """Test storing and retrieving metrics."""
        with TempDatabaseHelper() as db_path:
            storage = SQLiteMetricStorage(db_path)
            
            # Create test metric
            metric = Metric(
                name="test_metric",
                type=MetricType.COUNTER,
                description="Test metric",
                unit="count"
            )
            metric.add_value(10, {"label": "value"})
            metric.add_value(20, {"label": "value2"})
            
            # Store metric
            success = await storage.store_metric(metric)
            assert success is True
            
            # Retrieve metric
            retrieved = await storage.get_metric("test_metric")
            assert retrieved is not None
            assert retrieved.name == "test_metric"
            assert retrieved.type == MetricType.COUNTER
            assert retrieved.description == "Test metric"
            assert len(retrieved.values) == 2
    
    @pytest.mark.asyncio
    async def test_get_all_metrics(self):
        """Test getting all metrics."""
        with TempDatabaseHelper() as db_path:
            storage = SQLiteMetricStorage(db_path)
            
            # Store multiple metrics
            metrics = DashboardTestScenarios.create_sample_metrics()
            for metric in metrics:
                await storage.store_metric(metric)
            
            # Retrieve all metrics
            all_metrics = await storage.get_all_metrics()
            assert len(all_metrics) == len(metrics)
            
            metric_names = [m.name for m in all_metrics]
            assert "requests_total" in metric_names
            assert "cpu_usage" in metric_names
    
    @pytest.mark.asyncio
    async def test_delete_metric(self):
        """Test deleting metrics."""
        with TempDatabaseHelper() as db_path:
            storage = SQLiteMetricStorage(db_path)
            
            # Store metric
            metric = Metric("test_metric", MetricType.GAUGE)
            metric.add_value(42)
            await storage.store_metric(metric)
            
            # Verify it exists
            retrieved = await storage.get_metric("test_metric")
            assert retrieved is not None
            
            # Delete metric
            success = await storage.delete_metric("test_metric")
            assert success is True
            
            # Verify it's gone
            retrieved = await storage.get_metric("test_metric")
            assert retrieved is None
    
    @pytest.mark.asyncio
    async def test_get_nonexistent_metric(self):
        """Test getting non-existent metric."""
        with TempDatabaseHelper() as db_path:
            storage = SQLiteMetricStorage(db_path)
            
            retrieved = await storage.get_metric("nonexistent")
            assert retrieved is None
    
    @pytest.mark.asyncio
    async def test_get_metrics_by_labels(self):
        """Test getting metrics by labels."""
        with TempDatabaseHelper() as db_path:
            storage = SQLiteMetricStorage(db_path)
            
            # Store metric with labeled values
            metric = DashboardTestScenarios.create_metric_with_labels()
            await storage.store_metric(metric)
            
            # Get by labels
            results = await storage.get_metrics_by_labels({"method": "GET"})
            assert len(results) >= 1
            
            # Verify the metric has the expected labels
            found_metric = results[0]
            has_get_requests = any(
                v.labels.get("method") == "GET" 
                for v in found_metric.values
            )
            assert has_get_requests


class TestAlertManager:
    """Test AlertManager functionality."""
    
    def setup_method(self):
        """Setup for each test."""
        self.storage = MockMetricStorage()
        self.alert_manager = AlertManager(self.storage)
    
    def test_add_and_get_alert_rule(self):
        """Test adding and retrieving alert rules."""
        rule = create_alert_rule(
            name="Test Rule",
            metric_name="cpu_usage",
            condition="gt",
            threshold=80.0
        )
        
        success = self.alert_manager.add_rule(rule)
        assert success is True
        
        retrieved = self.alert_manager.get_rule(rule.id)
        assert retrieved is not None
        assert retrieved.name == "Test Rule"
        
        all_rules = self.alert_manager.get_all_rules()
        assert len(all_rules) == 1
        assert all_rules[0].name == "Test Rule"
    
    def test_remove_alert_rule(self):
        """Test removing alert rules."""
        rule = create_alert_rule(
            name="Test Rule",
            metric_name="cpu_usage",
            condition="gt",
            threshold=80.0
        )
        
        self.alert_manager.add_rule(rule)
        
        # Verify it exists
        assert self.alert_manager.get_rule(rule.id) is not None
        
        # Remove it
        success = self.alert_manager.remove_rule(rule.id)
        assert success is True
        
        # Verify it's gone
        assert self.alert_manager.get_rule(rule.id) is None
    
    def test_evaluate_metric_no_trigger(self):
        """Test metric evaluation that doesn't trigger alert."""
        rule = create_alert_rule(
            name="CPU High",
            metric_name="cpu_usage",
            condition="gt",
            threshold=80.0,
            duration=60
        )
        self.alert_manager.add_rule(rule)
        
        # Create metric with value below threshold
        metric = Metric("cpu_usage", MetricType.GAUGE)
        metric.add_value(50.0)  # Below threshold
        
        self.alert_manager.evaluate_metric(metric)
        
        # Should not trigger alert
        active_alerts = self.alert_manager.get_active_alerts()
        assert len(active_alerts) == 0
    
    def test_evaluate_metric_trigger_alert(self):
        """Test metric evaluation that triggers alert."""
        rule = create_alert_rule(
            name="CPU High",
            metric_name="cpu_usage",
            condition="gt",
            threshold=80.0,
            duration=0  # Trigger immediately
        )
        self.alert_manager.add_rule(rule)
        
        # Create metric with value above threshold
        metric = Metric("cpu_usage", MetricType.GAUGE)
        AlertManagerTestHelper.simulate_alert_condition_met(metric, rule, duration_seconds=0)
        
        self.alert_manager.evaluate_metric(metric)
        
        # Should trigger alert
        active_alerts = self.alert_manager.get_active_alerts()
        assert len(active_alerts) == 1
        assert active_alerts[0].rule_name == "CPU High"
        assert active_alerts[0].status == AlertStatus.ACTIVE
    
    def test_alert_duration_requirement(self):
        """Test that alerts require duration to be met."""
        rule = create_alert_rule(
            name="Memory High",
            metric_name="memory_usage",
            condition="gt",
            threshold=90.0,
            duration=60  # 60 seconds duration required
        )
        self.alert_manager.add_rule(rule)
        
        metric = Metric("memory_usage", MetricType.GAUGE)
        
        # Add a single value above threshold (not sustained)
        metric.add_value(95.0)
        
        self.alert_manager.evaluate_metric(metric)
        
        # Should not trigger alert immediately
        active_alerts = self.alert_manager.get_active_alerts()
        assert len(active_alerts) == 0
        
        # Simulate condition being true for required duration by adding historical values
        # We need to ensure the condition state is properly set up
        now = datetime.now(timezone.utc)
        start_time = now - timedelta(seconds=65)  # 65 seconds ago
        
        # Manually set up the condition state to simulate it started 65 seconds ago
        self.alert_manager._condition_states[rule.id] = {"started": start_time}
        
        # Add a current triggering value
        metric.add_value(95.0)  # Above threshold
        
        self.alert_manager.evaluate_metric(metric)
        
        # Now should trigger alert since condition has been true long enough
        active_alerts = self.alert_manager.get_active_alerts()
        assert len(active_alerts) == 1
    
    def test_acknowledge_alert(self):
        """Test acknowledging alerts."""
        # First trigger an alert
        rule = create_alert_rule(
            name="Test Alert",
            metric_name="test_metric",
            condition="gt",
            threshold=50.0,
            duration=0
        )
        self.alert_manager.add_rule(rule)
        
        metric = Metric("test_metric", MetricType.GAUGE)
        AlertManagerTestHelper.simulate_alert_condition_met(metric, rule)
        
        self.alert_manager.evaluate_metric(metric)
        
        active_alerts = self.alert_manager.get_active_alerts()
        assert len(active_alerts) == 1
        
        alert_id = active_alerts[0].id
        
        # Acknowledge the alert
        success = self.alert_manager.acknowledge_alert(alert_id, "testuser")
        assert success is True
        
        # Verify acknowledgment
        alert = self.alert_manager.active_alerts[alert_id]
        assert alert.status == AlertStatus.ACKNOWLEDGED
        assert alert.acknowledged_by == "testuser"
    
    def test_silence_alert(self):
        """Test silencing alerts."""
        # First trigger an alert
        rule = create_alert_rule(
            name="Test Alert",
            metric_name="test_metric",
            condition="gt",
            threshold=50.0,
            duration=0
        )
        self.alert_manager.add_rule(rule)
        
        metric = Metric("test_metric", MetricType.GAUGE)
        AlertManagerTestHelper.simulate_alert_condition_met(metric, rule)
        
        self.alert_manager.evaluate_metric(metric)
        
        active_alerts = self.alert_manager.get_active_alerts()
        assert len(active_alerts) == 1
        
        alert_id = active_alerts[0].id
        
        # Silence the alert
        success = self.alert_manager.silence_alert(alert_id)
        assert success is True
        
        # Verify silence
        alert = self.alert_manager.active_alerts[alert_id]
        assert alert.status == AlertStatus.SILENCED
    
    def test_alert_callbacks(self):
        """Test alert callbacks."""
        callback = AlertManagerTestHelper.create_mock_callback()
        self.alert_manager.add_callback(callback)
        
        # Trigger an alert
        rule = create_alert_rule(
            name="Callback Test",
            metric_name="test_metric",
            condition="gt",
            threshold=50.0,
            duration=0
        )
        self.alert_manager.add_rule(rule)
        
        metric = Metric("test_metric", MetricType.GAUGE)
        AlertManagerTestHelper.simulate_alert_condition_met(metric, rule)
        
        self.alert_manager.evaluate_metric(metric)
        
        # Verify callback was called
        callback.assert_called_once()
        
        # Verify callback received the alert
        call_args = callback.call_args[0]
        alert = call_args[0]
        assert isinstance(alert, Alert)
        assert alert.rule_name == "Callback Test"
    
    def test_alert_callback_error_handling(self):
        """Test error handling in alert callbacks."""
        failing_callback = AlertManagerTestHelper.create_failing_callback()
        normal_callback = AlertManagerTestHelper.create_mock_callback()
        
        self.alert_manager.add_callback(failing_callback)
        self.alert_manager.add_callback(normal_callback)
        
        # Trigger an alert
        rule = create_alert_rule(
            name="Error Test",
            metric_name="test_metric",
            condition="gt",
            threshold=50.0,
            duration=0
        )
        self.alert_manager.add_rule(rule)
        
        metric = Metric("test_metric", MetricType.GAUGE)
        AlertManagerTestHelper.simulate_alert_condition_met(metric, rule)
        
        # Should not raise exception despite failing callback
        self.alert_manager.evaluate_metric(metric)
        
        # Both callbacks should have been called
        failing_callback.assert_called_once()
        normal_callback.assert_called_once()
    
    def test_alert_resolution(self):
        """Test automatic alert resolution."""
        rule = create_alert_rule(
            name="Resolution Test",
            metric_name="test_metric",
            condition="gt",
            threshold=50.0,
            duration=0
        )
        self.alert_manager.add_rule(rule)
        
        metric = Metric("test_metric", MetricType.GAUGE)
        
        # First, trigger the alert
        AlertManagerTestHelper.simulate_alert_condition_met(metric, rule)
        self.alert_manager.evaluate_metric(metric)
        
        active_alerts = self.alert_manager.get_active_alerts()
        assert len(active_alerts) == 1
        
        # Now add a value that doesn't meet the condition
        metric.add_value(30.0)  # Below threshold
        self.alert_manager.evaluate_metric(metric)
        
        # Alert should be resolved
        active_alerts = self.alert_manager.get_active_alerts()
        assert len(active_alerts) == 0


class TestDashboardWebSocketManager:
    """Test DashboardWebSocketManager functionality."""
    
    def setup_method(self):
        """Setup for each test."""
        self.manager = DashboardWebSocketManager()
    
    @pytest.mark.asyncio
    async def test_connect_websocket(self):
        """Test WebSocket connection."""
        mock_ws = MockWebSocket()
        
        await self.manager.connect(mock_ws)
        
        assert mock_ws.accept_calls == 1
        assert mock_ws in self.manager.active_connections
        assert len(self.manager.active_connections) == 1
    
    def test_disconnect_websocket(self):
        """Test WebSocket disconnection."""
        mock_ws = MockWebSocket()
        self.manager.active_connections.add(mock_ws)
        
        self.manager.disconnect(mock_ws)
        
        assert mock_ws not in self.manager.active_connections
        assert len(self.manager.active_connections) == 0
    
    @pytest.mark.asyncio
    async def test_broadcast_message(self):
        """Test broadcasting messages."""
        mock_ws1 = MockWebSocket()
        mock_ws2 = MockWebSocket()
        
        await self.manager.connect(mock_ws1)
        await self.manager.connect(mock_ws2)
        
        message = {"type": "test", "data": "hello"}
        await self.manager.broadcast(message)
        
        expected_message = json.dumps(message)
        
        assert expected_message in mock_ws1.sent_messages
        assert expected_message in mock_ws2.sent_messages
        assert mock_ws1.send_calls == 1
        assert mock_ws2.send_calls == 1
    
    @pytest.mark.asyncio
    async def test_broadcast_with_failed_connection(self):
        """Test broadcasting with failed connections."""
        working_ws = MockWebSocket()
        failing_ws = MockWebSocket()
        failing_ws.should_fail_send = True
        
        await self.manager.connect(working_ws)
        await self.manager.connect(failing_ws)
        
        assert len(self.manager.active_connections) == 2
        
        message = {"type": "test", "data": "hello"}
        await self.manager.broadcast(message)
        
        # Working connection should receive message
        assert len(working_ws.sent_messages) == 1
        
        # Failed connection should be removed
        assert len(self.manager.active_connections) == 1
        assert working_ws in self.manager.active_connections
        assert failing_ws not in self.manager.active_connections
    
    @pytest.mark.asyncio
    async def test_send_metric_update(self):
        """Test sending metric updates."""
        mock_ws = MockWebSocket()
        await self.manager.connect(mock_ws)
        
        metric = Metric("test_metric", MetricType.GAUGE, "Test metric")
        metric.add_value(42.0, {"label": "test"})
        
        await self.manager.send_metric_update(metric)
        
        assert len(mock_ws.sent_messages) == 1
        
        message = json.loads(mock_ws.sent_messages[0])
        assert message["type"] == "metric_update"
        assert message["data"]["name"] == "test_metric"
        assert message["data"]["value"] == 42.0
        assert message["data"]["labels"] == {"label": "test"}
    
    @pytest.mark.asyncio
    async def test_send_alert_update(self):
        """Test sending alert updates."""
        mock_ws = MockWebSocket()
        await self.manager.connect(mock_ws)
        
        alert = Alert(
            id="test-alert",
            rule_id="test-rule",
            rule_name="Test Alert",
            metric_name="test_metric",
            metric_value=100.0,
            threshold=80.0,
            severity=AlertSeverity.WARNING,
            status=AlertStatus.ACTIVE,
            message="Test alert message"
        )
        
        await self.manager.send_alert_update(alert)
        
        assert len(mock_ws.sent_messages) == 1
        
        message = json.loads(mock_ws.sent_messages[0])
        assert message["type"] == "alert_update"
        assert message["data"]["id"] == "test-alert"
        assert message["data"]["rule_name"] == "Test Alert"
        assert message["data"]["status"] == "active"


class TestDashboardConfig:
    """Test DashboardConfig functionality."""
    
    def test_default_config(self):
        """Test default dashboard configuration."""
        config = DashboardConfig()
        
        assert config.title == "Shield Metrics Dashboard"
        assert config.theme == DashboardTheme.LIGHT
        assert config.refresh_interval == 5
        assert config.enable_auth is False
        assert config.host == "0.0.0.0"
        assert config.port == 8080
    
    def test_custom_config(self):
        """Test custom dashboard configuration."""
        config = DashboardConfig(
            title="Custom Dashboard",
            port=9090,
            enable_auth=True,
            username="custom_user",
            password="custom_pass"
        )
        
        assert config.title == "Custom Dashboard"
        assert config.port == 9090
        assert config.enable_auth is True
        assert config.username == "custom_user"
        assert config.password == "custom_pass"
    
    def test_config_to_dict(self):
        """Test config serialization."""
        config = DashboardConfig(
            title="Test Dashboard",
            port=8888,
            enable_auth=True
        )
        
        result = config.to_dict()
        
        assert result["title"] == "Test Dashboard"
        assert result["port"] == 8888
        assert result["enable_auth"] is True


class TestMetricsDashboard:
    """Test MetricsDashboard functionality."""
    
    def setup_method(self):
        """Setup for each test."""
        self.config = DashboardConfig(port=8888)  # Use different port for testing
        self.storage = MockMetricStorage()
        self.dashboard = MetricsDashboard(self.config, self.storage)
    
    def test_dashboard_initialization(self):
        """Test dashboard initialization."""
        assert self.dashboard.config.port == 8888
        assert isinstance(self.dashboard.storage, MockMetricStorage)
        assert isinstance(self.dashboard.alert_manager, AlertManager)
        assert isinstance(self.dashboard.websocket_manager, DashboardWebSocketManager)
        assert self.dashboard.app is not None
    
    def test_register_metric(self):
        """Test metric registration."""
        metric = self.dashboard.register_metric(
            "test_metric",
            MetricType.COUNTER,
            "Test metric",
            "count"
        )
        
        assert metric.name == "test_metric"
        assert metric.type == MetricType.COUNTER
        assert "test_metric" in self.dashboard.metrics
        
        # Registering same metric should return existing one
        metric2 = self.dashboard.register_metric("test_metric", MetricType.GAUGE)
        assert metric is metric2
    
    def test_record_metric_existing(self):
        """Test recording values for existing metrics."""
        self.dashboard.register_metric("requests", MetricType.COUNTER)
        
        self.dashboard.record_metric("requests", 10, {"endpoint": "/api"})
        
        metric = self.dashboard.metrics["requests"]
        assert len(metric.values) == 1
        assert metric.values[0].value == 10
        assert metric.values[0].labels == {"endpoint": "/api"}
    
    def test_record_metric_auto_register(self):
        """Test auto-registration when recording unknown metric."""
        self.dashboard.record_metric("unknown_metric", 42.5)
        
        assert "unknown_metric" in self.dashboard.metrics
        metric = self.dashboard.metrics["unknown_metric"]
        assert metric.type == MetricType.GAUGE
        assert len(metric.values) == 1
        assert metric.values[0].value == 42.5
    
    def test_dashboard_api_endpoints(self):
        """Test dashboard API endpoints."""
        client = TestClient(self.dashboard.app)
        
        # Register some test metrics
        self.dashboard.register_metric("cpu_usage", MetricType.GAUGE, "CPU usage", "%")
        self.dashboard.record_metric("cpu_usage", 75.5, {"core": "0"})
        
        # Test metrics endpoint
        response = client.get("/api/metrics")
        assert response.status_code == 200
        
        data = response.json()
        assert "metrics" in data
        assert len(data["metrics"]) == 1
        assert data["metrics"][0]["name"] == "cpu_usage"
        assert data["metrics"][0]["latest_value"] == 75.5
    
    def test_dashboard_specific_metric_endpoint(self):
        """Test specific metric endpoint."""
        client = TestClient(self.dashboard.app)
        
        # Register and populate metric
        metric = self.dashboard.register_metric("requests", MetricType.COUNTER)
        self.dashboard.record_metric("requests", 10)
        self.dashboard.record_metric("requests", 20)
        
        # Test specific metric endpoint
        response = client.get("/api/metrics/requests")
        assert response.status_code == 200
        
        data = response.json()
        assert data["name"] == "requests"
        assert data["type"] == "counter"
        assert len(data["values"]) == 2
    
    def test_dashboard_nonexistent_metric_endpoint(self):
        """Test endpoint for non-existent metric."""
        client = TestClient(self.dashboard.app)
        
        response = client.get("/api/metrics/nonexistent")
        assert response.status_code == 404
    
    def test_dashboard_alerts_endpoint(self):
        """Test alerts endpoint."""
        client = TestClient(self.dashboard.app)
        
        # Add some test alerts
        rule = create_alert_rule("Test Alert", "cpu", "gt", 80.0)
        self.dashboard.alert_manager.add_rule(rule)
        
        response = client.get("/api/alerts")
        assert response.status_code == 200
        
        data = response.json()
        assert "active" in data
        assert "history" in data
        assert isinstance(data["active"], list)
        assert isinstance(data["history"], list)
    
    def test_dashboard_alert_rules_endpoint(self):
        """Test alert rules endpoint."""
        client = TestClient(self.dashboard.app)
        
        # Add test rule
        rule = create_alert_rule("CPU High", "cpu_usage", "gt", 80.0)
        self.dashboard.alert_manager.add_rule(rule)
        
        response = client.get("/api/alert-rules")
        assert response.status_code == 200
        
        data = response.json()
        assert "rules" in data
        assert len(data["rules"]) == 1
        assert data["rules"][0]["name"] == "CPU High"
    
    def test_dashboard_create_alert_rule_endpoint(self):
        """Test creating alert rule via API."""
        client = TestClient(self.dashboard.app)
        
        rule_data = {
            "name": "Memory Alert",
            "metric_name": "memory_usage",
            "condition": "gt",
            "threshold": 90.0,
            "severity": "error"
        }
        
        response = client.post("/api/alert-rules", json=rule_data)
        assert response.status_code == 200
        
        data = response.json()
        assert data["name"] == "Memory Alert"
        assert data["metric_name"] == "memory_usage"
        assert data["threshold"] == 90.0
        
        # Verify rule was actually added
        rules = self.dashboard.alert_manager.get_all_rules()
        assert len(rules) == 1
        assert rules[0].name == "Memory Alert"
    
    def test_dashboard_main_page_endpoint(self):
        """Test main dashboard page."""
        client = TestClient(self.dashboard.app)
        
        response = client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "Shield Metrics Dashboard" in response.text


class TestDashboardMiddleware:
    """Test DashboardMiddleware functionality."""
    
    def test_middleware_initialization(self):
        """Test middleware initialization."""
        dashboard = MetricsDashboard()
        middleware = DashboardMiddleware(Mock(), dashboard)
        
        assert middleware.dashboard is dashboard
        
        # Verify HTTP metrics were registered
        assert "http_requests_total" in dashboard.metrics
        assert "http_request_duration" in dashboard.metrics
        assert "http_responses_total" in dashboard.metrics
        assert "active_connections" in dashboard.metrics
    
    @pytest.mark.asyncio
    async def test_middleware_request_tracking(self):
        """Test middleware request tracking."""
        dashboard = MetricsDashboard()
        
        from fastapi import FastAPI, Request, Response
        
        app = FastAPI()
        app.add_middleware(DashboardMiddleware, dashboard=dashboard)
        
        @app.get("/test")
        async def test_endpoint():
            return {"message": "test"}
        
        client = TestClient(app)
        response = client.get("/test")
        
        assert response.status_code == 200
        
        # Verify metrics were recorded
        requests_metric = dashboard.metrics["http_requests_total"]
        assert len(requests_metric.values) >= 1
        
        duration_metric = dashboard.metrics["http_request_duration"]
        assert len(duration_metric.values) >= 1
        
        responses_metric = dashboard.metrics["http_responses_total"]
        assert len(responses_metric.values) >= 1


class TestConvenienceFunctions:
    """Test convenience functions."""
    
    def test_create_dashboard(self):
        """Test create_dashboard convenience function."""
        dashboard = create_dashboard(
            title="Test Dashboard",
            port=9999,
            enable_auth=True,
            username="test",
            password="secret"
        )
        
        assert isinstance(dashboard, MetricsDashboard)
        assert dashboard.config.title == "Test Dashboard"
        assert dashboard.config.port == 9999
        assert dashboard.config.enable_auth is True
        assert dashboard.config.username == "test"
        assert dashboard.config.password == "secret"
    
    def test_create_alert_rule(self):
        """Test create_alert_rule convenience function."""
        rule = create_alert_rule(
            name="Test Rule",
            metric_name="cpu_usage",
            condition="gt",
            threshold=85.0,
            severity=AlertSeverity.ERROR,
            duration=120,
            description="CPU usage too high"
        )
        
        assert isinstance(rule, AlertRule)
        assert rule.name == "Test Rule"
        assert rule.metric_name == "cpu_usage"
        assert rule.condition == "gt"
        assert rule.threshold == 85.0
        assert rule.severity == AlertSeverity.ERROR
        assert rule.duration == 120
        assert rule.description == "CPU usage too high"
        assert rule.id is not None


class TestIntegrationScenarios:
    """Test integration scenarios combining multiple components."""
    
    @pytest.mark.asyncio
    async def test_end_to_end_metric_and_alert_flow(self):
        """Test complete flow from metric recording to alert triggering."""
        # Setup dashboard
        config = DashboardConfig(port=8889)
        storage = MockMetricStorage()
        dashboard = MetricsDashboard(config, storage)
        
        # Register metric and alert rule
        dashboard.register_metric("cpu_usage", MetricType.GAUGE, "CPU usage", "%")
        
        rule = create_alert_rule(
            name="CPU Alert",
            metric_name="cpu_usage",
            condition="gt",
            threshold=80.0,
            duration=0  # Immediate trigger
        )
        dashboard.alert_manager.add_rule(rule)
        
        # Record low value (should not trigger)
        dashboard.record_metric("cpu_usage", 50.0)
        
        active_alerts = dashboard.alert_manager.get_active_alerts()
        assert len(active_alerts) == 0
        
        # Record high value (should trigger)
        dashboard.record_metric("cpu_usage", 90.0)
        
        active_alerts = dashboard.alert_manager.get_active_alerts()
        assert len(active_alerts) == 1
        assert active_alerts[0].rule_name == "CPU Alert"
        assert active_alerts[0].metric_value == 90.0
    
    @pytest.mark.asyncio
    async def test_dashboard_with_storage_integration(self):
        """Test dashboard with storage integration."""
        with TempDatabaseHelper() as db_path:
            config = DashboardConfig(database_path=db_path)
            storage = SQLiteMetricStorage(db_path)
            dashboard = MetricsDashboard(config, storage)
            
            # Register and record metrics
            dashboard.register_metric("requests", MetricType.COUNTER, "HTTP requests")
            dashboard.record_metric("requests", 100, {"method": "GET"})
            dashboard.record_metric("requests", 200, {"method": "POST"})
            
            # Store to database
            metric = dashboard.metrics["requests"]
            await storage.store_metric(metric)
            
            # Retrieve from database
            retrieved = await storage.get_metric("requests")
            assert retrieved is not None
            assert retrieved.name == "requests"
            assert len(retrieved.values) >= 2
    
    def test_websocket_integration_with_alerts(self):
        """Test WebSocket integration with alert system."""
        dashboard = MetricsDashboard()
        
        # Setup mock WebSocket
        mock_ws = MockWebSocket()
        dashboard.websocket_manager.active_connections.add(mock_ws)
        
        # Setup callback to capture alerts (sync version)
        captured_alerts = []
        
        def capture_alert_sync(alert):
            captured_alerts.append(alert)
        
        dashboard.alert_manager.add_callback(capture_alert_sync)
        
        # Create and trigger alert
        rule = create_alert_rule(
            name="WebSocket Test",
            metric_name="test_metric",
            condition="gt",
            threshold=50.0,
            duration=0
        )
        dashboard.alert_manager.add_rule(rule)
        
        metric = Metric("test_metric", MetricType.GAUGE)
        AlertManagerTestHelper.simulate_alert_condition_met(metric, rule)
        
        # Trigger the alert
        dashboard.alert_manager.evaluate_metric(metric)
        
        # Verify alert was captured
        assert len(captured_alerts) == 1
        assert captured_alerts[0].rule_name == "WebSocket Test"
        
        # Verify WebSocket setup (dashboard adds its own callback + our test callback = 2)
        assert len(dashboard.alert_manager.callbacks) == 2
        assert mock_ws in dashboard.websocket_manager.active_connections
    
    def test_dashboard_api_with_authentication(self):
        """Test dashboard API with authentication."""
        config = DashboardConfig(
            enable_auth=True,
            username="testuser",
            password="testpass"
        )
        dashboard = MetricsDashboard(config)
        client = TestClient(dashboard.app)
        
        # Test without authentication
        response = client.get("/api/metrics")
        assert response.status_code == 401
        
        # Test with wrong credentials
        response = client.get("/api/metrics", auth=("wrong", "wrong"))
        assert response.status_code == 401
        
        # Test with correct credentials
        dashboard.register_metric("test", MetricType.GAUGE)
        response = client.get("/api/metrics", auth=("testuser", "testpass"))
        assert response.status_code == 200
        
        data = response.json()
        assert "metrics" in data
    
    @pytest.mark.asyncio
    async def test_comprehensive_dashboard_functionality(self):
        """Test comprehensive dashboard functionality."""
        # Create dashboard with all features
        config = DashboardConfig(
            title="Comprehensive Test",
            enable_alerts=True,
            enable_export=True
        )
        
        with TempDatabaseHelper() as db_path:
            config.database_path = db_path
            storage = SQLiteMetricStorage(db_path)
            dashboard = MetricsDashboard(config, storage)
            
            # Register multiple metrics
            cpu_metric = dashboard.register_metric("cpu_usage", MetricType.GAUGE, "CPU usage", "%")
            memory_metric = dashboard.register_metric("memory_usage", MetricType.GAUGE, "Memory usage", "%")
            requests_metric = dashboard.register_metric("requests_total", MetricType.COUNTER, "Total requests")
            
            # Record values
            dashboard.record_metric("cpu_usage", 75.0, {"core": "0"})
            dashboard.record_metric("memory_usage", 60.0, {"type": "heap"})
            dashboard.record_metric("requests_total", 1000, {"endpoint": "/api"})
            
            # Create alert rules
            cpu_rule = create_alert_rule("CPU High", "cpu_usage", "gt", 80.0)
            memory_rule = create_alert_rule("Memory High", "memory_usage", "gt", 90.0)
            
            dashboard.alert_manager.add_rule(cpu_rule)
            dashboard.alert_manager.add_rule(memory_rule)
            
            # Test API endpoints
            client = TestClient(dashboard.app)
            
            # Get all metrics
            response = client.get("/api/metrics")
            assert response.status_code == 200
            data = response.json()
            assert len(data["metrics"]) == 3
            
            # Get specific metric
            response = client.get("/api/metrics/cpu_usage")
            assert response.status_code == 200
            data = response.json()
            assert data["name"] == "cpu_usage"
            assert data["type"] == "gauge"
            
            # Get alert rules
            response = client.get("/api/alert-rules")
            assert response.status_code == 200
            data = response.json()
            assert len(data["rules"]) == 2
            
            # Get chart data
            response = client.get("/api/charts/cpu_usage?time_range=1h")
            assert response.status_code == 200
            data = response.json()
            assert "labels" in data
            assert "datasets" in data
            
            # Store metrics in database
            await storage.store_metric(cpu_metric)
            await storage.store_metric(memory_metric)
            await storage.store_metric(requests_metric)
            
            # Verify storage
            stored_metrics = await storage.get_all_metrics()
            assert len(stored_metrics) == 3