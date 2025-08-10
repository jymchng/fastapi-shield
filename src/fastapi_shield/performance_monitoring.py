"""Performance monitoring shield for FastAPI Shield.

This module provides comprehensive performance monitoring capabilities including
response time measurement, resource usage tracking, and integration with popular
monitoring services like Prometheus, DataDog, and New Relic. It supports
real-time metrics collection, alert generation, and historical data storage.
"""

import asyncio
import json
import os
import statistics
import time
import threading
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Callable, Union, Tuple
from threading import Lock, Thread
from dataclasses import dataclass, field

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    psutil = None
    PSUTIL_AVAILABLE = False

import httpx
from fastapi import HTTPException, Request, Response, status

from fastapi_shield.shield import Shield


class MonitoringService(str, Enum):
    """Supported monitoring services."""
    PROMETHEUS = "prometheus"
    DATADOG = "datadog"
    NEW_RELIC = "new_relic"
    CUSTOM = "custom"


class AlertSeverity(str, Enum):
    """Alert severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class MetricType(str, Enum):
    """Types of metrics."""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"


@dataclass
class PerformanceMetric:
    """Performance metric data structure."""
    name: str
    value: float
    metric_type: MetricType
    timestamp: datetime = field(default_factory=datetime.utcnow)
    labels: Dict[str, str] = field(default_factory=dict)
    unit: str = "ms"


@dataclass
class ResourceUsage:
    """System resource usage data."""
    cpu_percent: float
    memory_percent: float
    memory_used_mb: float
    disk_io_read_mb: float
    disk_io_write_mb: float
    network_sent_mb: float
    network_recv_mb: float
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class AlertThreshold:
    """Alert threshold configuration."""
    metric_name: str
    threshold_value: float
    comparison: str  # "greater_than", "less_than", "equal_to"
    severity: AlertSeverity
    window_seconds: int = 300  # 5 minute window
    consecutive_breaches: int = 3
    enabled: bool = True


@dataclass
class Alert:
    """Alert instance."""
    id: str
    threshold: AlertThreshold
    current_value: float
    breach_count: int
    first_breach_time: datetime
    last_breach_time: datetime
    resolved: bool = False
    resolved_time: Optional[datetime] = None


class MetricsStorage:
    """Thread-safe metrics storage with time-based retention."""
    
    def __init__(self, retention_hours: int = 24, max_metrics_per_endpoint: int = 10000):
        self.retention_hours = retention_hours
        self.max_metrics_per_endpoint = max_metrics_per_endpoint
        self._metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=max_metrics_per_endpoint))
        self._resource_usage: deque = deque(maxlen=max_metrics_per_endpoint)
        self._lock = Lock()
        
        # Start cleanup thread
        self._cleanup_thread = Thread(target=self._cleanup_old_metrics, daemon=True)
        self._cleanup_thread.start()
    
    def add_metric(self, endpoint: str, metric: PerformanceMetric) -> None:
        """Add a performance metric."""
        with self._lock:
            self._metrics[endpoint].append(metric)
    
    def add_resource_usage(self, usage: ResourceUsage) -> None:
        """Add resource usage data."""
        with self._lock:
            self._resource_usage.append(usage)
    
    def get_metrics(self, endpoint: str, start_time: Optional[datetime] = None, 
                   end_time: Optional[datetime] = None) -> List[PerformanceMetric]:
        """Get metrics for an endpoint within time range."""
        with self._lock:
            metrics = list(self._metrics.get(endpoint, []))
            
            if start_time or end_time:
                filtered_metrics = []
                for metric in metrics:
                    if start_time and metric.timestamp < start_time:
                        continue
                    if end_time and metric.timestamp > end_time:
                        continue
                    filtered_metrics.append(metric)
                return filtered_metrics
            
            return metrics
    
    def get_resource_usage(self, start_time: Optional[datetime] = None,
                          end_time: Optional[datetime] = None) -> List[ResourceUsage]:
        """Get resource usage data within time range."""
        with self._lock:
            usage_data = list(self._resource_usage)
            
            if start_time or end_time:
                filtered_data = []
                for usage in usage_data:
                    if start_time and usage.timestamp < start_time:
                        continue
                    if end_time and usage.timestamp > end_time:
                        continue
                    filtered_data.append(usage)
                return filtered_data
            
            return usage_data
    
    def get_statistics(self, endpoint: str, metric_name: str, 
                      window_minutes: int = 60) -> Dict[str, float]:
        """Calculate statistics for a metric within a time window."""
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(minutes=window_minutes)
        
        metrics = self.get_metrics(endpoint, start_time, end_time)
        values = [m.value for m in metrics if m.name == metric_name]
        
        if not values:
            return {"count": 0}
        
        return {
            "count": len(values),
            "min": min(values),
            "max": max(values),
            "mean": statistics.mean(values),
            "median": statistics.median(values),
            "p95": self._percentile(values, 95),
            "p99": self._percentile(values, 99),
            "stddev": statistics.stdev(values) if len(values) > 1 else 0.0
        }
    
    def _percentile(self, values: List[float], percentile: int) -> float:
        """Calculate percentile value."""
        if not values:
            return 0.0
        sorted_values = sorted(values)
        index = int((percentile / 100.0) * (len(sorted_values) - 1))
        return sorted_values[index]
    
    def _cleanup_old_metrics(self) -> None:
        """Background thread to clean up old metrics."""
        while True:
            try:
                cutoff_time = datetime.utcnow() - timedelta(hours=self.retention_hours)
                
                with self._lock:
                    # Clean up endpoint metrics
                    for endpoint in list(self._metrics.keys()):
                        metrics = self._metrics[endpoint]
                        while metrics and metrics[0].timestamp < cutoff_time:
                            metrics.popleft()
                        
                        # Remove empty endpoint entries
                        if not metrics:
                            del self._metrics[endpoint]
                    
                    # Clean up resource usage
                    while (self._resource_usage and 
                           self._resource_usage[0].timestamp < cutoff_time):
                        self._resource_usage.popleft()
                
                # Sleep for 5 minutes before next cleanup
                time.sleep(300)
                
            except Exception:
                # Continue running even if cleanup fails
                time.sleep(300)


class MonitoringServiceProvider(ABC):
    """Abstract base class for monitoring service providers."""
    
    @abstractmethod
    async def send_metric(self, metric: PerformanceMetric) -> bool:
        """Send a performance metric to the monitoring service."""
        pass
    
    @abstractmethod
    async def send_alert(self, alert: Alert) -> bool:
        """Send an alert to the monitoring service."""
        pass
    
    @abstractmethod
    async def health_check(self) -> bool:
        """Check if the monitoring service is healthy."""
        pass


class PrometheusProvider(MonitoringServiceProvider):
    """Prometheus monitoring service provider."""
    
    def __init__(
        self,
        pushgateway_url: str,
        job_name: str = "fastapi-shield",
        timeout: int = 10,
        basic_auth: Optional[Tuple[str, str]] = None
    ):
        self.pushgateway_url = pushgateway_url.rstrip('/')
        self.job_name = job_name
        self.timeout = timeout
        self.basic_auth = basic_auth
        self._client = httpx.AsyncClient(timeout=timeout)
    
    async def send_metric(self, metric: PerformanceMetric) -> bool:
        """Send metric to Prometheus pushgateway."""
        try:
            # Convert metric to Prometheus format
            labels = ",".join([f'{k}="{v}"' for k, v in metric.labels.items()])
            if labels:
                metric_line = f'{metric.name}{{{labels}}} {metric.value}'
            else:
                metric_line = f'{metric.name} {metric.value}'
            
            url = f"{self.pushgateway_url}/metrics/job/{self.job_name}"
            headers = {"Content-Type": "text/plain"}
            auth = self.basic_auth if self.basic_auth else None
            
            response = await self._client.post(
                url,
                content=metric_line,
                headers=headers,
                auth=auth
            )
            
            return response.status_code in [200, 202]
            
        except Exception:
            return False
    
    async def send_alert(self, alert: Alert) -> bool:
        """Send alert as a Prometheus metric."""
        alert_metric = PerformanceMetric(
            name="fastapi_shield_alert",
            value=1.0 if not alert.resolved else 0.0,
            metric_type=MetricType.GAUGE,
            labels={
                "alert_id": alert.id,
                "metric_name": alert.threshold.metric_name,
                "severity": alert.threshold.severity.value,
                "threshold": str(alert.threshold.threshold_value),
                "current_value": str(alert.current_value)
            }
        )
        
        return await self.send_metric(alert_metric)
    
    async def health_check(self) -> bool:
        """Check Prometheus pushgateway health."""
        try:
            response = await self._client.get(f"{self.pushgateway_url}/-/healthy")
            return response.status_code == 200
        except Exception:
            return False


class DataDogProvider(MonitoringServiceProvider):
    """DataDog monitoring service provider."""
    
    def __init__(
        self,
        api_key: str,
        app_key: str,
        api_url: str = "https://api.datadoghq.com",
        timeout: int = 10
    ):
        self.api_key = api_key
        self.app_key = app_key
        self.api_url = api_url.rstrip('/')
        self.timeout = timeout
        self._client = httpx.AsyncClient(timeout=timeout)
    
    async def send_metric(self, metric: PerformanceMetric) -> bool:
        """Send metric to DataDog."""
        try:
            tags = [f"{k}:{v}" for k, v in metric.labels.items()]
            
            payload = {
                "series": [{
                    "metric": metric.name,
                    "points": [
                        [int(metric.timestamp.timestamp()), metric.value]
                    ],
                    "tags": tags,
                    "type": self._convert_metric_type(metric.metric_type)
                }]
            }
            
            headers = {
                "Content-Type": "application/json",
                "DD-API-KEY": self.api_key,
                "DD-APPLICATION-KEY": self.app_key
            }
            
            response = await self._client.post(
                f"{self.api_url}/api/v1/series",
                json=payload,
                headers=headers
            )
            
            return response.status_code in [200, 202]
            
        except Exception:
            return False
    
    async def send_alert(self, alert: Alert) -> bool:
        """Send alert to DataDog events API."""
        try:
            event_data = {
                "title": f"FastAPI Shield Alert: {alert.threshold.metric_name}",
                "text": (
                    f"Alert {alert.id} triggered\n"
                    f"Metric: {alert.threshold.metric_name}\n"
                    f"Current value: {alert.current_value}\n"
                    f"Threshold: {alert.threshold.threshold_value}\n"
                    f"Severity: {alert.threshold.severity.value}"
                ),
                "alert_type": self._convert_severity(alert.threshold.severity),
                "source_type_name": "fastapi-shield",
                "tags": [
                    f"alert_id:{alert.id}",
                    f"metric:{alert.threshold.metric_name}",
                    f"severity:{alert.threshold.severity.value}"
                ]
            }
            
            if alert.resolved:
                event_data["title"] = f"FastAPI Shield Alert Resolved: {alert.threshold.metric_name}"
                event_data["alert_type"] = "success"
            
            headers = {
                "Content-Type": "application/json",
                "DD-API-KEY": self.api_key
            }
            
            response = await self._client.post(
                f"{self.api_url}/api/v1/events",
                json=event_data,
                headers=headers
            )
            
            return response.status_code in [200, 202]
            
        except Exception:
            return False
    
    async def health_check(self) -> bool:
        """Check DataDog API health."""
        try:
            headers = {
                "DD-API-KEY": self.api_key,
                "DD-APPLICATION-KEY": self.app_key
            }
            
            response = await self._client.get(
                f"{self.api_url}/api/v1/validate",
                headers=headers
            )
            
            return response.status_code == 200
        except Exception:
            return False
    
    def _convert_metric_type(self, metric_type: MetricType) -> str:
        """Convert internal metric type to DataDog type."""
        mapping = {
            MetricType.COUNTER: "count",
            MetricType.GAUGE: "gauge",
            MetricType.HISTOGRAM: "histogram",
            MetricType.TIMER: "gauge"
        }
        return mapping.get(metric_type, "gauge")
    
    def _convert_severity(self, severity: AlertSeverity) -> str:
        """Convert severity to DataDog alert type."""
        mapping = {
            AlertSeverity.LOW: "info",
            AlertSeverity.MEDIUM: "warning",
            AlertSeverity.HIGH: "error",
            AlertSeverity.CRITICAL: "error"
        }
        return mapping.get(severity, "warning")


class NewRelicProvider(MonitoringServiceProvider):
    """New Relic monitoring service provider."""
    
    def __init__(
        self,
        license_key: str,
        account_id: str,
        api_url: str = "https://metric-api.newrelic.com",
        timeout: int = 10
    ):
        self.license_key = license_key
        self.account_id = account_id
        self.api_url = api_url.rstrip('/')
        self.timeout = timeout
        self._client = httpx.AsyncClient(timeout=timeout)
    
    async def send_metric(self, metric: PerformanceMetric) -> bool:
        """Send metric to New Relic."""
        try:
            attributes = dict(metric.labels)
            attributes.update({
                "metric_type": metric.metric_type.value,
                "unit": metric.unit
            })
            
            payload = [{
                "metrics": [{
                    "name": metric.name,
                    "type": self._convert_metric_type(metric.metric_type),
                    "value": metric.value,
                    "timestamp": int(metric.timestamp.timestamp() * 1000),
                    "attributes": attributes
                }]
            }]
            
            headers = {
                "Content-Type": "application/json",
                "Api-Key": self.license_key
            }
            
            response = await self._client.post(
                f"{self.api_url}/metric/v1",
                json=payload,
                headers=headers
            )
            
            return response.status_code in [200, 202]
            
        except Exception:
            return False
    
    async def send_alert(self, alert: Alert) -> bool:
        """Send alert to New Relic insights API."""
        try:
            event_data = {
                "eventType": "FastAPIShieldAlert",
                "alertId": alert.id,
                "metricName": alert.threshold.metric_name,
                "currentValue": alert.current_value,
                "thresholdValue": alert.threshold.threshold_value,
                "severity": alert.threshold.severity.value,
                "resolved": alert.resolved,
                "breachCount": alert.breach_count,
                "firstBreachTime": alert.first_breach_time.isoformat(),
                "lastBreachTime": alert.last_breach_time.isoformat()
            }
            
            if alert.resolved and alert.resolved_time:
                event_data["resolvedTime"] = alert.resolved_time.isoformat()
            
            headers = {
                "Content-Type": "application/json",
                "Api-Key": self.license_key
            }
            
            response = await self._client.post(
                f"https://insights-collector.newrelic.com/v1/accounts/{self.account_id}/events",
                json=event_data,
                headers=headers
            )
            
            return response.status_code in [200, 202]
            
        except Exception:
            return False
    
    async def health_check(self) -> bool:
        """Check New Relic API health."""
        try:
            headers = {"Api-Key": self.license_key}
            
            # Test with a simple metric submission
            test_payload = [{
                "metrics": [{
                    "name": "fastapi_shield.health_check",
                    "type": "gauge",
                    "value": 1,
                    "timestamp": int(time.time() * 1000)
                }]
            }]
            
            response = await self._client.post(
                f"{self.api_url}/metric/v1",
                json=test_payload,
                headers=headers
            )
            
            return response.status_code in [200, 202]
        except Exception:
            return False
    
    def _convert_metric_type(self, metric_type: MetricType) -> str:
        """Convert internal metric type to New Relic type."""
        mapping = {
            MetricType.COUNTER: "count",
            MetricType.GAUGE: "gauge",
            MetricType.HISTOGRAM: "gauge",
            MetricType.TIMER: "gauge"
        }
        return mapping.get(metric_type, "gauge")


class CustomProvider(MonitoringServiceProvider):
    """Custom monitoring service provider using callback functions."""
    
    def __init__(
        self,
        metric_callback: Callable[[PerformanceMetric], bool],
        alert_callback: Optional[Callable[[Alert], bool]] = None,
        health_callback: Optional[Callable[[], bool]] = None
    ):
        self.metric_callback = metric_callback
        self.alert_callback = alert_callback
        self.health_callback = health_callback
    
    async def send_metric(self, metric: PerformanceMetric) -> bool:
        """Send metric using custom callback."""
        try:
            if asyncio.iscoroutinefunction(self.metric_callback):
                return await self.metric_callback(metric)
            else:
                return self.metric_callback(metric)
        except Exception:
            return False
    
    async def send_alert(self, alert: Alert) -> bool:
        """Send alert using custom callback."""
        if not self.alert_callback:
            return True  # No-op if no callback provided
        
        try:
            if asyncio.iscoroutinefunction(self.alert_callback):
                return await self.alert_callback(alert)
            else:
                return self.alert_callback(alert)
        except Exception:
            return False
    
    async def health_check(self) -> bool:
        """Check health using custom callback."""
        if not self.health_callback:
            return True  # Always healthy if no callback provided
        
        try:
            if asyncio.iscoroutinefunction(self.health_callback):
                return await self.health_callback()
            else:
                return self.health_callback()
        except Exception:
            return False


class ResourceMonitor:
    """System resource usage monitor."""
    
    def __init__(self, collection_interval: int = 30):
        self.collection_interval = collection_interval
        self._running = False
        self._thread: Optional[Thread] = None
        self._callbacks: List[Callable[[ResourceUsage], None]] = []
        self._last_disk_io = None
        self._last_network_io = None
    
    def add_callback(self, callback: Callable[[ResourceUsage], None]) -> None:
        """Add callback for resource usage updates."""
        self._callbacks.append(callback)
    
    def start(self) -> None:
        """Start resource monitoring."""
        if self._running:
            return
        
        self._running = True
        self._thread = Thread(target=self._monitor_resources, daemon=True)
        self._thread.start()
    
    def stop(self) -> None:
        """Stop resource monitoring."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
    
    def _monitor_resources(self) -> None:
        """Background thread for resource monitoring."""
        while self._running:
            try:
                usage = self._collect_resource_usage()
                
                for callback in self._callbacks:
                    try:
                        callback(usage)
                    except Exception:
                        continue  # Don't let one callback failure stop others
                
                time.sleep(self.collection_interval)
                
            except Exception:
                # Continue monitoring even if collection fails
                time.sleep(self.collection_interval)
    
    def _collect_resource_usage(self) -> ResourceUsage:
        """Collect current resource usage."""
        if not PSUTIL_AVAILABLE:
            # Return zero values when psutil is not available
            return ResourceUsage(
                cpu_percent=0.0,
                memory_percent=0.0,
                memory_used_mb=0.0,
                disk_io_read_mb=0.0,
                disk_io_write_mb=0.0,
                network_sent_mb=0.0,
                network_recv_mb=0.0
            )
        
        # CPU and memory
        cpu_percent = psutil.cpu_percent()
        memory = psutil.virtual_memory()
        memory_percent = memory.percent
        memory_used_mb = memory.used / (1024 * 1024)
        
        # Disk I/O
        disk_io = psutil.disk_io_counters()
        if disk_io:
            if self._last_disk_io:
                disk_read_mb = (disk_io.read_bytes - self._last_disk_io.read_bytes) / (1024 * 1024)
                disk_write_mb = (disk_io.write_bytes - self._last_disk_io.write_bytes) / (1024 * 1024)
            else:
                disk_read_mb = disk_write_mb = 0.0
            self._last_disk_io = disk_io
        else:
            disk_read_mb = disk_write_mb = 0.0
        
        # Network I/O
        network_io = psutil.net_io_counters()
        if network_io:
            if self._last_network_io:
                network_sent_mb = (network_io.bytes_sent - self._last_network_io.bytes_sent) / (1024 * 1024)
                network_recv_mb = (network_io.bytes_recv - self._last_network_io.bytes_recv) / (1024 * 1024)
            else:
                network_sent_mb = network_recv_mb = 0.0
            self._last_network_io = network_io
        else:
            network_sent_mb = network_recv_mb = 0.0
        
        return ResourceUsage(
            cpu_percent=cpu_percent,
            memory_percent=memory_percent,
            memory_used_mb=memory_used_mb,
            disk_io_read_mb=disk_read_mb,
            disk_io_write_mb=disk_write_mb,
            network_sent_mb=network_sent_mb,
            network_recv_mb=network_recv_mb
        )


class AlertManager:
    """Alert management and threshold monitoring."""
    
    def __init__(self):
        self.thresholds: Dict[str, AlertThreshold] = {}
        self.active_alerts: Dict[str, Alert] = {}
        self.alert_history: List[Alert] = []
        self._lock = Lock()
        self._breach_tracking: Dict[str, List[datetime]] = defaultdict(list)
    
    def add_threshold(self, threshold: AlertThreshold) -> None:
        """Add an alert threshold."""
        with self._lock:
            self.thresholds[threshold.metric_name] = threshold
    
    def remove_threshold(self, metric_name: str) -> None:
        """Remove an alert threshold."""
        with self._lock:
            self.thresholds.pop(metric_name, None)
            self._breach_tracking.pop(metric_name, None)
    
    def check_thresholds(self, metrics: List[PerformanceMetric]) -> List[Alert]:
        """Check metrics against thresholds and generate alerts."""
        new_alerts = []
        current_time = datetime.utcnow()
        
        with self._lock:
            for metric in metrics:
                threshold = self.thresholds.get(metric.name)
                if not threshold or not threshold.enabled:
                    continue
                
                breach_detected = self._check_threshold_breach(metric.value, threshold)
                
                if breach_detected:
                    self._record_breach(metric.name, current_time, threshold)
                    
                    # Check if we have enough consecutive breaches
                    recent_breaches = self._get_recent_breaches(metric.name, threshold)
                    
                    if len(recent_breaches) >= threshold.consecutive_breaches:
                        alert_id = f"{metric.name}_{int(current_time.timestamp())}"
                        
                        # Create or update alert
                        if metric.name not in self.active_alerts:
                            alert = Alert(
                                id=alert_id,
                                threshold=threshold,
                                current_value=metric.value,
                                breach_count=len(recent_breaches),
                                first_breach_time=recent_breaches[0],
                                last_breach_time=current_time
                            )
                            self.active_alerts[metric.name] = alert
                            new_alerts.append(alert)
                        else:
                            # Update existing alert
                            alert = self.active_alerts[metric.name]
                            alert.current_value = metric.value
                            alert.breach_count = len(recent_breaches)
                            alert.last_breach_time = current_time
                
                else:
                    # Clear breach tracking and resolve alert if exists
                    self._breach_tracking[metric.name] = []
                    
                    if metric.name in self.active_alerts:
                        alert = self.active_alerts[metric.name]
                        alert.resolved = True
                        alert.resolved_time = current_time
                        self.alert_history.append(alert)
                        del self.active_alerts[metric.name]
                        new_alerts.append(alert)  # Send resolved alert
        
        return new_alerts
    
    def get_active_alerts(self) -> List[Alert]:
        """Get all active alerts."""
        with self._lock:
            return list(self.active_alerts.values())
    
    def get_alert_history(self, hours: int = 24) -> List[Alert]:
        """Get alert history for specified hours."""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        with self._lock:
            return [
                alert for alert in self.alert_history
                if alert.first_breach_time >= cutoff_time
            ]
    
    def _check_threshold_breach(self, value: float, threshold: AlertThreshold) -> bool:
        """Check if a value breaches the threshold."""
        if threshold.comparison == "greater_than":
            return value > threshold.threshold_value
        elif threshold.comparison == "less_than":
            return value < threshold.threshold_value
        elif threshold.comparison == "equal_to":
            return abs(value - threshold.threshold_value) < 0.001  # Float comparison
        return False
    
    def _record_breach(self, metric_name: str, breach_time: datetime, 
                      threshold: AlertThreshold) -> None:
        """Record a threshold breach."""
        breaches = self._breach_tracking[metric_name]
        breaches.append(breach_time)
        
        # Keep only recent breaches within the window
        window_start = breach_time - timedelta(seconds=threshold.window_seconds)
        self._breach_tracking[metric_name] = [
            t for t in breaches if t >= window_start
        ]
    
    def _get_recent_breaches(self, metric_name: str, 
                           threshold: AlertThreshold) -> List[datetime]:
        """Get recent breaches within the window."""
        current_time = datetime.utcnow()
        window_start = current_time - timedelta(seconds=threshold.window_seconds)
        
        return [
            t for t in self._breach_tracking[metric_name]
            if t >= window_start
        ]


class PerformanceMonitoringConfig:
    """Configuration for performance monitoring shield."""
    
    def __init__(
        self,
        providers: List[MonitoringServiceProvider],
        thresholds: Optional[List[AlertThreshold]] = None,
        collect_resource_usage: bool = True,
        resource_collection_interval: int = 30,
        metrics_retention_hours: int = 24,
        max_metrics_per_endpoint: int = 10000,
        send_metrics_async: bool = True,
        batch_size: int = 100,
        batch_timeout_seconds: int = 60,
        exclude_endpoints: Optional[List[str]] = None,
        include_request_body_size: bool = True,
        include_response_body_size: bool = True,
        track_user_metrics: bool = True,
        custom_labels: Optional[Dict[str, Callable[[Request], str]]] = None
    ):
        self.providers = providers
        self.thresholds = thresholds or []
        self.collect_resource_usage = collect_resource_usage
        self.resource_collection_interval = resource_collection_interval
        self.metrics_retention_hours = metrics_retention_hours
        self.max_metrics_per_endpoint = max_metrics_per_endpoint
        self.send_metrics_async = send_metrics_async
        self.batch_size = batch_size
        self.batch_timeout_seconds = batch_timeout_seconds
        self.exclude_endpoints = exclude_endpoints or []
        self.include_request_body_size = include_request_body_size
        self.include_response_body_size = include_response_body_size
        self.track_user_metrics = track_user_metrics
        self.custom_labels = custom_labels or {}


class PerformanceMonitoringShield(Shield):
    """Performance monitoring shield for comprehensive metrics collection."""
    
    def __init__(self, config: PerformanceMonitoringConfig):
        self.config = config
        self.storage = MetricsStorage(
            retention_hours=config.metrics_retention_hours,
            max_metrics_per_endpoint=config.max_metrics_per_endpoint
        )
        self.alert_manager = AlertManager()
        self.resource_monitor = ResourceMonitor(
            collection_interval=config.resource_collection_interval
        )
        
        # Initialize alert thresholds
        for threshold in config.thresholds:
            self.alert_manager.add_threshold(threshold)
        
        # Set up resource monitoring if enabled
        if config.collect_resource_usage:
            self.resource_monitor.add_callback(self.storage.add_resource_usage)
            self.resource_monitor.start()
        
        # Metric batching for async sending
        self._metric_batch: List[PerformanceMetric] = []
        self._batch_lock = Lock()
        self._last_batch_send = time.time()
        
        if config.send_metrics_async:
            self._batch_thread = Thread(target=self._process_metric_batches, daemon=True)
            self._batch_thread.start()
        
        super().__init__(self._shield_function)
    
    async def _shield_function(self, request: Request) -> Optional[Dict[str, Any]]:
        """Main shield function for performance monitoring."""
        # Check if endpoint should be excluded
        endpoint_path = request.url.path
        if endpoint_path in self.config.exclude_endpoints:
            return None
        
        # Record start time and initial metrics
        start_time = time.time()
        start_memory = psutil.virtual_memory().used if PSUTIL_AVAILABLE else 0
        
        # Extract labels
        labels = self._extract_labels(request)
        
        # Measure request body size if enabled
        request_body_size = 0
        if self.config.include_request_body_size:
            try:
                if hasattr(request, '_body'):
                    request_body_size = len(request._body)
                elif 'content-length' in request.headers:
                    request_body_size = int(request.headers.get('content-length', '0'))
            except (ValueError, AttributeError):
                pass
        
        # Store start metrics for the response phase
        request.state.performance_start_time = start_time
        request.state.performance_start_memory = start_memory
        request.state.performance_labels = labels
        request.state.performance_request_body_size = request_body_size
        
        return {
            "performance_monitoring": {
                "start_time": start_time,
                "endpoint": endpoint_path,
                "method": request.method,
                "labels": labels
            }
        }
    
    def _extract_labels(self, request: Request) -> Dict[str, str]:
        """Extract labels for metrics."""
        labels = {
            "method": request.method,
            "endpoint": request.url.path,
            "host": request.headers.get("host", "unknown")
        }
        
        # Add user tracking if enabled
        if self.config.track_user_metrics:
            user_id = (
                request.headers.get("x-user-id") or
                request.headers.get("user-id") or
                "anonymous"
            )
            labels["user_id"] = user_id
        
        # Add custom labels
        for label_name, extractor in self.config.custom_labels.items():
            try:
                labels[label_name] = extractor(request)
            except Exception:
                labels[label_name] = "error"
        
        return labels
    
    async def record_response_metrics(self, request: Request, response: Response) -> None:
        """Record metrics after response is ready."""
        if not hasattr(request.state, 'performance_start_time'):
            return
        
        end_time = time.time()
        end_memory = psutil.virtual_memory().used if PSUTIL_AVAILABLE else 0
        
        # Calculate metrics
        response_time_ms = (end_time - request.state.performance_start_time) * 1000
        memory_used_mb = (end_memory - request.state.performance_start_memory) / (1024 * 1024)
        
        labels = request.state.performance_labels
        labels.update({
            "status_code": str(response.status_code),
            "status_class": f"{response.status_code // 100}xx"
        })
        
        endpoint = request.url.path
        
        # Response body size if enabled
        response_body_size = 0
        if self.config.include_response_body_size and hasattr(response, 'body'):
            try:
                if isinstance(response.body, bytes):
                    response_body_size = len(response.body)
                elif hasattr(response, 'content'):
                    response_body_size = len(str(response.content))
            except (AttributeError, TypeError):
                pass
        
        # Create performance metrics
        metrics = [
            PerformanceMetric(
                name="http_request_duration_ms",
                value=response_time_ms,
                metric_type=MetricType.HISTOGRAM,
                labels=labels,
                unit="ms"
            ),
            PerformanceMetric(
                name="http_request_memory_mb",
                value=memory_used_mb,
                metric_type=MetricType.GAUGE,
                labels=labels,
                unit="MB"
            ),
            PerformanceMetric(
                name="http_requests_total",
                value=1,
                metric_type=MetricType.COUNTER,
                labels=labels,
                unit="requests"
            )
        ]
        
        # Add body size metrics if enabled
        if self.config.include_request_body_size:
            metrics.append(PerformanceMetric(
                name="http_request_body_size_bytes",
                value=request.state.performance_request_body_size,
                metric_type=MetricType.HISTOGRAM,
                labels=labels,
                unit="bytes"
            ))
        
        if self.config.include_response_body_size:
            metrics.append(PerformanceMetric(
                name="http_response_body_size_bytes",
                value=response_body_size,
                metric_type=MetricType.HISTOGRAM,
                labels=labels,
                unit="bytes"
            ))
        
        # Store metrics locally
        for metric in metrics:
            self.storage.add_metric(endpoint, metric)
        
        # Check for alerts
        alerts = self.alert_manager.check_thresholds(metrics)
        
        # Send metrics to monitoring services
        if self.config.send_metrics_async:
            self._add_to_batch(metrics)
        else:
            await self._send_metrics_immediately(metrics)
        
        # Send alerts
        for alert in alerts:
            await self._send_alert(alert)
    
    def _add_to_batch(self, metrics: List[PerformanceMetric]) -> None:
        """Add metrics to batch for async sending."""
        with self._batch_lock:
            self._metric_batch.extend(metrics)
    
    async def _send_metrics_immediately(self, metrics: List[PerformanceMetric]) -> None:
        """Send metrics immediately to all providers."""
        tasks = []
        for provider in self.config.providers:
            for metric in metrics:
                tasks.append(provider.send_metric(metric))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _send_alert(self, alert: Alert) -> None:
        """Send alert to all providers."""
        tasks = []
        for provider in self.config.providers:
            tasks.append(provider.send_alert(alert))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    def _process_metric_batches(self) -> None:
        """Background thread to process metric batches."""
        while True:
            try:
                current_time = time.time()
                should_send = False
                batch_to_send = []
                
                with self._batch_lock:
                    if (len(self._metric_batch) >= self.config.batch_size or
                        current_time - self._last_batch_send >= self.config.batch_timeout_seconds):
                        
                        if self._metric_batch:
                            batch_to_send = self._metric_batch[:self.config.batch_size]
                            self._metric_batch = self._metric_batch[self.config.batch_size:]
                            self._last_batch_send = current_time
                            should_send = True
                
                if should_send:
                    asyncio.run(self._send_metrics_immediately(batch_to_send))
                
                time.sleep(1)  # Check every second
                
            except Exception:
                time.sleep(1)  # Continue even if batch processing fails
    
    def get_metrics(self, endpoint: str, start_time: Optional[datetime] = None,
                   end_time: Optional[datetime] = None) -> List[PerformanceMetric]:
        """Get metrics for an endpoint."""
        return self.storage.get_metrics(endpoint, start_time, end_time)
    
    def get_statistics(self, endpoint: str, metric_name: str,
                      window_minutes: int = 60) -> Dict[str, float]:
        """Get statistics for a metric."""
        return self.storage.get_statistics(endpoint, metric_name, window_minutes)
    
    def get_resource_usage(self, start_time: Optional[datetime] = None,
                          end_time: Optional[datetime] = None) -> List[ResourceUsage]:
        """Get resource usage data."""
        return self.storage.get_resource_usage(start_time, end_time)
    
    def get_active_alerts(self) -> List[Alert]:
        """Get active alerts."""
        return self.alert_manager.get_active_alerts()
    
    def add_threshold(self, threshold: AlertThreshold) -> None:
        """Add an alert threshold."""
        self.alert_manager.add_threshold(threshold)
    
    def remove_threshold(self, metric_name: str) -> None:
        """Remove an alert threshold."""
        self.alert_manager.remove_threshold(metric_name)


# Convenience functions for creating shields

def performance_monitoring_shield(
    providers: List[MonitoringServiceProvider],
    thresholds: Optional[List[AlertThreshold]] = None,
    collect_resource_usage: bool = True,
    metrics_retention_hours: int = 24,
    send_metrics_async: bool = True,
    exclude_endpoints: Optional[List[str]] = None
) -> PerformanceMonitoringShield:
    """Create a performance monitoring shield with specified configuration.
    
    Args:
        providers: List of monitoring service providers
        thresholds: List of alert thresholds
        collect_resource_usage: Whether to collect system resource usage
        metrics_retention_hours: Hours to retain metrics data
        send_metrics_async: Whether to send metrics asynchronously
        exclude_endpoints: List of endpoint paths to exclude from monitoring
    
    Returns:
        PerformanceMonitoringShield instance
    """
    config = PerformanceMonitoringConfig(
        providers=providers,
        thresholds=thresholds,
        collect_resource_usage=collect_resource_usage,
        metrics_retention_hours=metrics_retention_hours,
        send_metrics_async=send_metrics_async,
        exclude_endpoints=exclude_endpoints
    )
    
    return PerformanceMonitoringShield(config)


def prometheus_performance_shield(
    pushgateway_url: str,
    job_name: str = "fastapi-shield",
    thresholds: Optional[List[AlertThreshold]] = None,
    basic_auth: Optional[Tuple[str, str]] = None
) -> PerformanceMonitoringShield:
    """Create a performance monitoring shield with Prometheus provider.
    
    Args:
        pushgateway_url: URL of Prometheus pushgateway
        job_name: Job name for metrics
        thresholds: List of alert thresholds
        basic_auth: Basic authentication credentials (username, password)
    
    Returns:
        PerformanceMonitoringShield instance
    """
    provider = PrometheusProvider(
        pushgateway_url=pushgateway_url,
        job_name=job_name,
        basic_auth=basic_auth
    )
    
    return performance_monitoring_shield(
        providers=[provider],
        thresholds=thresholds
    )


def datadog_performance_shield(
    api_key: str,
    app_key: str,
    thresholds: Optional[List[AlertThreshold]] = None,
    api_url: str = "https://api.datadoghq.com"
) -> PerformanceMonitoringShield:
    """Create a performance monitoring shield with DataDog provider.
    
    Args:
        api_key: DataDog API key
        app_key: DataDog application key
        thresholds: List of alert thresholds
        api_url: DataDog API URL
    
    Returns:
        PerformanceMonitoringShield instance
    """
    provider = DataDogProvider(
        api_key=api_key,
        app_key=app_key,
        api_url=api_url
    )
    
    return performance_monitoring_shield(
        providers=[provider],
        thresholds=thresholds
    )


def newrelic_performance_shield(
    license_key: str,
    account_id: str,
    thresholds: Optional[List[AlertThreshold]] = None,
    api_url: str = "https://metric-api.newrelic.com"
) -> PerformanceMonitoringShield:
    """Create a performance monitoring shield with New Relic provider.
    
    Args:
        license_key: New Relic license key
        account_id: New Relic account ID
        thresholds: List of alert thresholds
        api_url: New Relic API URL
    
    Returns:
        PerformanceMonitoringShield instance
    """
    provider = NewRelicProvider(
        license_key=license_key,
        account_id=account_id,
        api_url=api_url
    )
    
    return performance_monitoring_shield(
        providers=[provider],
        thresholds=thresholds
    )


def multi_provider_performance_shield(
    prometheus_config: Optional[Dict[str, Any]] = None,
    datadog_config: Optional[Dict[str, Any]] = None,
    newrelic_config: Optional[Dict[str, Any]] = None,
    thresholds: Optional[List[AlertThreshold]] = None
) -> PerformanceMonitoringShield:
    """Create a performance monitoring shield with multiple providers.
    
    Args:
        prometheus_config: Prometheus provider configuration
        datadog_config: DataDog provider configuration
        newrelic_config: New Relic provider configuration
        thresholds: List of alert thresholds
    
    Returns:
        PerformanceMonitoringShield instance
    """
    providers = []
    
    if prometheus_config:
        providers.append(PrometheusProvider(**prometheus_config))
    
    if datadog_config:
        providers.append(DataDogProvider(**datadog_config))
    
    if newrelic_config:
        providers.append(NewRelicProvider(**newrelic_config))
    
    if not providers:
        raise ValueError("At least one monitoring provider must be configured")
    
    return performance_monitoring_shield(
        providers=providers,
        thresholds=thresholds
    )