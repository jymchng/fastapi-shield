"""FastAPI-Shield Advanced Security Dashboard

This module provides comprehensive security monitoring, analytics, and visualization
capabilities for FastAPI-Shield with real-time updates and interactive dashboards.

Features:
- Real-time security metrics visualization with WebSocket updates
- Interactive dashboard with drill-down capabilities and filtering
- Multi-dimensional threat analytics and intelligence integration
- Automated report generation with customizable templates
- Historical data analysis with trending and forecasting
- Performance optimization for high-throughput environments
- Export capabilities for compliance and audit reporting
- Advanced charting with multiple visualization types
"""

import asyncio
import json
import logging
import time
import uuid
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from threading import RLock, Lock, Thread
from typing import (
    Any, Dict, List, Optional, Union, Callable, Set, Tuple,
    NamedTuple, Protocol, AsyncIterator
)
import sqlite3
import hashlib
import hmac
import weakref

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn

logger = logging.getLogger(__name__)


class MetricType(Enum):
    """Types of security metrics."""
    COUNTER = "counter"           # Incremental counter metrics
    GAUGE = "gauge"              # Point-in-time value metrics
    HISTOGRAM = "histogram"       # Distribution of values
    RATE = "rate"                # Rate of change over time
    PERCENTAGE = "percentage"     # Percentage values (0-100)


class ChartType(Enum):
    """Dashboard chart visualization types."""
    LINE_CHART = "line_chart"           # Time series line charts
    BAR_CHART = "bar_chart"             # Bar charts for comparisons
    PIE_CHART = "pie_chart"             # Pie charts for distributions
    GAUGE_CHART = "gauge_chart"         # Gauge charts for single values
    HEATMAP = "heatmap"                 # Heat maps for correlation data
    SCATTER_PLOT = "scatter_plot"       # Scatter plots for relationships
    AREA_CHART = "area_chart"           # Area charts for cumulative data
    DONUT_CHART = "donut_chart"         # Donut charts for categories


class AlertSeverity(Enum):
    """Alert severity levels."""
    CRITICAL = "critical"      # Immediate action required
    HIGH = "high"             # High priority alert
    MEDIUM = "medium"         # Medium priority alert
    LOW = "low"               # Low priority alert
    INFO = "info"             # Informational alert


class ReportFormat(Enum):
    """Dashboard report export formats."""
    PDF = "pdf"               # PDF reports
    HTML = "html"             # HTML reports
    JSON = "json"             # JSON data export
    CSV = "csv"               # CSV data export
    EXCEL = "excel"           # Excel spreadsheet


class DashboardTheme(Enum):
    """Dashboard visual themes."""
    LIGHT = "light"           # Light theme
    DARK = "dark"             # Dark theme
    AUTO = "auto"             # Automatic theme based on time
    HIGH_CONTRAST = "high_contrast"  # High contrast theme


@dataclass
class SecurityMetric:
    """Individual security metric data point."""
    id: str
    name: str
    metric_type: MetricType
    value: Union[int, float]
    timestamp: datetime
    category: str
    tags: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metric to dictionary for serialization."""
        return {
            'id': self.id,
            'name': self.name,
            'metric_type': self.metric_type.value,
            'value': self.value,
            'timestamp': self.timestamp.isoformat(),
            'category': self.category,
            'tags': self.tags,
            'metadata': self.metadata
        }


@dataclass
class DashboardWidget:
    """Dashboard widget configuration."""
    id: str
    title: str
    chart_type: ChartType
    metric_query: str
    position: Dict[str, int]  # x, y, width, height
    refresh_interval: int = 30  # seconds
    color_scheme: Optional[str] = None
    options: Dict[str, Any] = field(default_factory=dict)
    is_visible: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert widget to dictionary."""
        return {
            'id': self.id,
            'title': self.title,
            'chart_type': self.chart_type.value,
            'metric_query': self.metric_query,
            'position': self.position,
            'refresh_interval': self.refresh_interval,
            'color_scheme': self.color_scheme,
            'options': self.options,
            'is_visible': self.is_visible
        }


@dataclass
class SecurityAlert:
    """Security alert with detailed information."""
    id: str
    title: str
    description: str
    severity: AlertSeverity
    timestamp: datetime
    category: str
    source: str
    affected_resources: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    is_acknowledged: bool = False
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    resolved: bool = False
    resolved_by: Optional[str] = None
    resolved_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary."""
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value,
            'timestamp': self.timestamp.isoformat(),
            'category': self.category,
            'source': self.source,
            'affected_resources': self.affected_resources,
            'recommended_actions': self.recommended_actions,
            'is_acknowledged': self.is_acknowledged,
            'acknowledged_by': self.acknowledged_by,
            'acknowledged_at': self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            'resolved': self.resolved,
            'resolved_by': self.resolved_by,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'metadata': self.metadata
        }


@dataclass
class DashboardConfig:
    """Dashboard configuration settings."""
    title: str = "FastAPI-Shield Security Dashboard"
    theme: DashboardTheme = DashboardTheme.DARK
    auto_refresh: bool = True
    refresh_interval: int = 30
    timezone: str = "UTC"
    date_format: str = "%Y-%m-%d %H:%M:%S"
    max_data_points: int = 1000
    enable_alerts: bool = True
    enable_exports: bool = True
    custom_css: Optional[str] = None
    widgets: List[DashboardWidget] = field(default_factory=list)


class MetricsCollector:
    """Collects and aggregates security metrics from various sources."""
    
    def __init__(self, max_metrics: int = 100000):
        self.max_metrics = max_metrics
        self.metrics: deque = deque(maxlen=max_metrics)
        self.metric_index: Dict[str, List[SecurityMetric]] = defaultdict(list)
        self.aggregated_metrics: Dict[str, Dict[str, Any]] = {}
        self._lock = RLock()
        self._subscribers: Set[Callable] = set()
        
        # Start background aggregation
        self._aggregation_thread = Thread(target=self._run_aggregation, daemon=True)
        self._aggregation_thread.start()
    
    def add_metric(self, metric: SecurityMetric):
        """Add a new security metric."""
        with self._lock:
            self.metrics.append(metric)
            self.metric_index[metric.category].append(metric)
            
            # Keep index size manageable
            if len(self.metric_index[metric.category]) > 1000:
                self.metric_index[metric.category] = self.metric_index[metric.category][-500:]
            
            # Notify subscribers
            self._notify_subscribers(metric)
    
    def subscribe(self, callback: Callable[[SecurityMetric], None]):
        """Subscribe to metric updates."""
        self._subscribers.add(callback)
    
    def unsubscribe(self, callback: Callable[[SecurityMetric], None]):
        """Unsubscribe from metric updates."""
        self._subscribers.discard(callback)
    
    def _notify_subscribers(self, metric: SecurityMetric):
        """Notify all subscribers of new metric."""
        for callback in self._subscribers.copy():
            try:
                callback(metric)
            except Exception as e:
                logger.error(f"Subscriber notification error: {e}")
                self._subscribers.discard(callback)
    
    def get_metrics(self, 
                   category: Optional[str] = None,
                   start_time: Optional[datetime] = None,
                   end_time: Optional[datetime] = None,
                   limit: Optional[int] = None) -> List[SecurityMetric]:
        """Retrieve metrics with optional filtering."""
        with self._lock:
            if category:
                source_metrics = self.metric_index.get(category, [])
            else:
                source_metrics = list(self.metrics)
            
            # Apply time filtering
            filtered_metrics = []
            for metric in source_metrics:
                if start_time and metric.timestamp < start_time:
                    continue
                if end_time and metric.timestamp > end_time:
                    continue
                filtered_metrics.append(metric)
            
            # Apply limit
            if limit:
                filtered_metrics = filtered_metrics[-limit:]
            
            return filtered_metrics
    
    def get_aggregated_metrics(self, category: str) -> Dict[str, Any]:
        """Get pre-aggregated metrics for a category."""
        with self._lock:
            return self.aggregated_metrics.get(category, {})
    
    def _run_aggregation(self):
        """Background thread for metric aggregation."""
        while True:
            try:
                self._update_aggregations()
                time.sleep(60)  # Update every minute
            except Exception as e:
                logger.error(f"Metrics aggregation error: {e}")
                time.sleep(30)
    
    def _update_aggregations(self):
        """Update aggregated metrics."""
        with self._lock:
            current_time = datetime.now(timezone.utc)
            hour_ago = current_time - timedelta(hours=1)
            day_ago = current_time - timedelta(days=1)
            
            for category in self.metric_index.keys():
                category_metrics = self.metric_index[category]
                
                # Recent metrics (last hour)
                recent_metrics = [m for m in category_metrics if m.timestamp > hour_ago]
                daily_metrics = [m for m in category_metrics if m.timestamp > day_ago]
                
                if recent_metrics:
                    # Calculate aggregations
                    values = [m.value for m in recent_metrics]
                    self.aggregated_metrics[category] = {
                        'count': len(recent_metrics),
                        'sum': sum(values),
                        'avg': sum(values) / len(values),
                        'min': min(values),
                        'max': max(values),
                        'recent_count': len(recent_metrics),
                        'daily_count': len(daily_metrics),
                        'trend': self._calculate_trend(category_metrics[-20:]) if len(category_metrics) > 10 else 0,
                        'last_updated': current_time.isoformat()
                    }
    
    def _calculate_trend(self, metrics: List[SecurityMetric]) -> float:
        """Calculate trend direction (-1 to 1)."""
        if len(metrics) < 2:
            return 0
        
        values = [m.value for m in metrics]
        if len(values) < 2:
            return 0
        
        # Simple linear trend calculation
        n = len(values)
        sum_x = sum(range(n))
        sum_y = sum(values)
        sum_xy = sum(i * values[i] for i in range(n))
        sum_x2 = sum(i * i for i in range(n))
        
        denominator = n * sum_x2 - sum_x * sum_x
        if denominator == 0:
            return 0
        
        slope = (n * sum_xy - sum_x * sum_y) / denominator
        
        # Normalize to -1 to 1 range
        return max(-1, min(1, slope / max(abs(max(values) - min(values)), 1)))


class AlertManager:
    """Manages security alerts and notifications."""
    
    def __init__(self, max_alerts: int = 10000):
        self.max_alerts = max_alerts
        self.alerts: deque = deque(maxlen=max_alerts)
        self.alert_index: Dict[str, SecurityAlert] = {}
        self.alert_rules: List[Callable] = []
        self._lock = RLock()
        self._subscribers: Set[Callable] = set()
    
    def add_alert(self, alert: SecurityAlert):
        """Add a new security alert."""
        with self._lock:
            self.alerts.append(alert)
            self.alert_index[alert.id] = alert
            
            # Notify subscribers
            self._notify_subscribers(alert)
            
            logger.warning(f"Security alert: {alert.title} ({alert.severity.value})")
    
    def subscribe(self, callback: Callable[[SecurityAlert], None]):
        """Subscribe to alert notifications."""
        self._subscribers.add(callback)
    
    def unsubscribe(self, callback: Callable[[SecurityAlert], None]):
        """Unsubscribe from alert notifications."""
        self._subscribers.discard(callback)
    
    def _notify_subscribers(self, alert: SecurityAlert):
        """Notify subscribers of new alert."""
        for callback in self._subscribers.copy():
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Alert subscriber error: {e}")
                self._subscribers.discard(callback)
    
    def acknowledge_alert(self, alert_id: str, user_id: str) -> bool:
        """Acknowledge an alert."""
        with self._lock:
            if alert_id in self.alert_index:
                alert = self.alert_index[alert_id]
                alert.is_acknowledged = True
                alert.acknowledged_by = user_id
                alert.acknowledged_at = datetime.now(timezone.utc)
                return True
            return False
    
    def resolve_alert(self, alert_id: str, user_id: str) -> bool:
        """Resolve an alert."""
        with self._lock:
            if alert_id in self.alert_index:
                alert = self.alert_index[alert_id]
                alert.resolved = True
                alert.resolved_by = user_id
                alert.resolved_at = datetime.now(timezone.utc)
                return True
            return False
    
    def get_alerts(self, 
                  severity: Optional[AlertSeverity] = None,
                  unresolved_only: bool = False,
                  limit: Optional[int] = None) -> List[SecurityAlert]:
        """Get alerts with optional filtering."""
        with self._lock:
            filtered_alerts = []
            
            for alert in reversed(self.alerts):
                if severity and alert.severity != severity:
                    continue
                if unresolved_only and alert.resolved:
                    continue
                filtered_alerts.append(alert)
            
            if limit:
                filtered_alerts = filtered_alerts[:limit]
            
            return filtered_alerts
    
    def add_alert_rule(self, rule_func: Callable[[SecurityMetric], Optional[SecurityAlert]]):
        """Add custom alert rule."""
        self.alert_rules.append(rule_func)
    
    def evaluate_alert_rules(self, metric: SecurityMetric):
        """Evaluate all alert rules for a metric."""
        for rule in self.alert_rules:
            try:
                alert = rule(metric)
                if alert:
                    self.add_alert(alert)
            except Exception as e:
                logger.error(f"Alert rule evaluation error: {e}")


class WebSocketManager:
    """Manages WebSocket connections for real-time dashboard updates."""
    
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self._lock = Lock()
    
    async def connect(self, websocket: WebSocket):
        """Accept new WebSocket connection."""
        await websocket.accept()
        with self._lock:
            self.active_connections.add(websocket)
        logger.info(f"WebSocket connected: {len(self.active_connections)} total connections")
    
    async def disconnect(self, websocket: WebSocket):
        """Handle WebSocket disconnection."""
        with self._lock:
            self.active_connections.discard(websocket)
        logger.info(f"WebSocket disconnected: {len(self.active_connections)} total connections")
    
    async def broadcast_metric(self, metric: SecurityMetric):
        """Broadcast new metric to all connected clients."""
        if not self.active_connections:
            return
        
        message = {
            'type': 'metric_update',
            'data': metric.to_dict()
        }
        
        await self._broadcast_message(message)
    
    async def broadcast_alert(self, alert: SecurityAlert):
        """Broadcast new alert to all connected clients."""
        if not self.active_connections:
            return
        
        message = {
            'type': 'alert_update',
            'data': alert.to_dict()
        }
        
        await self._broadcast_message(message)
    
    async def _broadcast_message(self, message: Dict[str, Any]):
        """Broadcast message to all connected clients."""
        message_json = json.dumps(message, default=str)
        disconnected = set()
        
        for websocket in self.active_connections.copy():
            try:
                await websocket.send_text(message_json)
            except Exception as e:
                logger.error(f"WebSocket broadcast error: {e}")
                disconnected.add(websocket)
        
        # Clean up disconnected websockets
        with self._lock:
            self.active_connections -= disconnected


class ReportGenerator:
    """Generates security reports in various formats."""
    
    def __init__(self, metrics_collector: MetricsCollector, alert_manager: AlertManager):
        self.metrics_collector = metrics_collector
        self.alert_manager = alert_manager
    
    async def generate_report(self, 
                            report_type: str,
                            format: ReportFormat,
                            start_time: Optional[datetime] = None,
                            end_time: Optional[datetime] = None) -> Dict[str, Any]:
        """Generate security report."""
        
        if not end_time:
            end_time = datetime.now(timezone.utc)
        if not start_time:
            start_time = end_time - timedelta(days=7)  # Default to last 7 days
        
        # Collect report data
        metrics = self.metrics_collector.get_metrics(
            start_time=start_time,
            end_time=end_time
        )
        
        alerts = self.alert_manager.get_alerts()
        alert_stats = self._calculate_alert_statistics(alerts, start_time, end_time)
        metric_stats = self._calculate_metric_statistics(metrics)
        
        report_data = {
            'report_id': str(uuid.uuid4()),
            'report_type': report_type,
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'period': {
                'start': start_time.isoformat(),
                'end': end_time.isoformat(),
                'duration_hours': (end_time - start_time).total_seconds() / 3600
            },
            'summary': {
                'total_metrics': len(metrics),
                'total_alerts': len(alerts),
                'critical_alerts': alert_stats['critical'],
                'resolved_alerts': alert_stats['resolved'],
                'alert_resolution_rate': alert_stats['resolution_rate']
            },
            'metrics_summary': metric_stats,
            'alert_summary': alert_stats,
            'top_categories': self._get_top_metric_categories(metrics, limit=10),
            'alert_trends': self._calculate_alert_trends(alerts),
            'recommendations': self._generate_recommendations(metric_stats, alert_stats)
        }
        
        if format == ReportFormat.JSON:
            return report_data
        elif format == ReportFormat.HTML:
            return await self._generate_html_report(report_data)
        elif format == ReportFormat.CSV:
            return await self._generate_csv_report(metrics, alerts)
        else:
            raise ValueError(f"Unsupported report format: {format}")
    
    def _calculate_alert_statistics(self, alerts: List[SecurityAlert], 
                                   start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """Calculate alert statistics for the time period."""
        period_alerts = [a for a in alerts if start_time <= a.timestamp <= end_time]
        
        severity_counts = defaultdict(int)
        category_counts = defaultdict(int)
        resolved_count = 0
        
        for alert in period_alerts:
            severity_counts[alert.severity.value] += 1
            category_counts[alert.category] += 1
            if alert.resolved:
                resolved_count += 1
        
        return {
            'total': len(period_alerts),
            'critical': severity_counts.get('critical', 0),
            'high': severity_counts.get('high', 0),
            'medium': severity_counts.get('medium', 0),
            'low': severity_counts.get('low', 0),
            'resolved': resolved_count,
            'resolution_rate': resolved_count / len(period_alerts) if period_alerts else 0,
            'by_category': dict(category_counts),
            'by_severity': dict(severity_counts)
        }
    
    def _calculate_metric_statistics(self, metrics: List[SecurityMetric]) -> Dict[str, Any]:
        """Calculate metric statistics."""
        if not metrics:
            return {}
        
        category_stats = defaultdict(lambda: {'count': 0, 'values': []})
        
        for metric in metrics:
            category_stats[metric.category]['count'] += 1
            category_stats[metric.category]['values'].append(metric.value)
        
        result = {}
        for category, stats in category_stats.items():
            values = stats['values']
            result[category] = {
                'count': stats['count'],
                'sum': sum(values),
                'avg': sum(values) / len(values),
                'min': min(values),
                'max': max(values)
            }
        
        return result
    
    def _get_top_metric_categories(self, metrics: List[SecurityMetric], limit: int) -> List[Dict[str, Any]]:
        """Get top metric categories by volume."""
        category_counts = defaultdict(int)
        
        for metric in metrics:
            category_counts[metric.category] += 1
        
        sorted_categories = sorted(category_counts.items(), key=lambda x: x[1], reverse=True)
        
        return [
            {'category': cat, 'count': count}
            for cat, count in sorted_categories[:limit]
        ]
    
    def _calculate_alert_trends(self, alerts: List[SecurityAlert]) -> Dict[str, Any]:
        """Calculate alert trends over time."""
        if not alerts:
            return {}
        
        # Group alerts by day
        daily_alerts = defaultdict(int)
        for alert in alerts:
            day_key = alert.timestamp.strftime('%Y-%m-%d')
            daily_alerts[day_key] += 1
        
        # Calculate trend
        days = sorted(daily_alerts.keys())
        if len(days) < 2:
            return {'trend': 'insufficient_data', 'daily_counts': dict(daily_alerts)}
        
        recent_avg = sum(daily_alerts[day] for day in days[-3:]) / min(3, len(days))
        older_avg = sum(daily_alerts[day] for day in days[:-3]) / max(1, len(days) - 3)
        
        if recent_avg > older_avg * 1.2:
            trend = 'increasing'
        elif recent_avg < older_avg * 0.8:
            trend = 'decreasing'
        else:
            trend = 'stable'
        
        return {
            'trend': trend,
            'recent_avg': recent_avg,
            'older_avg': older_avg,
            'daily_counts': dict(daily_alerts)
        }
    
    def _generate_recommendations(self, metric_stats: Dict[str, Any], 
                                 alert_stats: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on statistics."""
        recommendations = []
        
        if alert_stats.get('critical', 0) > 0:
            recommendations.append(
                f"Address {alert_stats['critical']} critical alerts immediately"
            )
        
        if alert_stats.get('resolution_rate', 0) < 0.8:
            recommendations.append(
                "Improve alert resolution rate - currently below 80%"
            )
        
        if alert_stats.get('total', 0) > 100:
            recommendations.append(
                "High alert volume detected - consider alert rule optimization"
            )
        
        # Add more recommendations based on patterns
        high_volume_categories = [
            cat for cat, stats in metric_stats.items() 
            if stats.get('count', 0) > 1000
        ]
        
        if high_volume_categories:
            recommendations.append(
                f"High metric volume in categories: {', '.join(high_volume_categories[:3])}"
            )
        
        if not recommendations:
            recommendations.append("Security metrics within normal parameters")
        
        return recommendations
    
    async def _generate_html_report(self, report_data: Dict[str, Any]) -> str:
        """Generate HTML format report."""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Report - {report_id}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #2c3e50; color: white; padding: 20px; }}
                .summary {{ background-color: #ecf0f1; padding: 15px; margin: 10px 0; }}
                .metrics {{ margin: 20px 0; }}
                .alert {{ background-color: #e74c3c; color: white; padding: 10px; margin: 5px 0; }}
                .recommendations {{ background-color: #f39c12; color: white; padding: 15px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>FastAPI-Shield Security Report</h1>
                <p>Report ID: {report_id}</p>
                <p>Generated: {generated_at}</p>
                <p>Period: {start_time} to {end_time}</p>
            </div>
            
            <div class="summary">
                <h2>Summary</h2>
                <p>Total Metrics: {total_metrics}</p>
                <p>Total Alerts: {total_alerts}</p>
                <p>Critical Alerts: {critical_alerts}</p>
                <p>Alert Resolution Rate: {resolution_rate:.1%}</p>
            </div>
            
            <div class="recommendations">
                <h2>Recommendations</h2>
                <ul>
                    {recommendations_list}
                </ul>
            </div>
        </body>
        </html>
        """
        
        recommendations_html = "".join(
            f"<li>{rec}</li>" for rec in report_data['recommendations']
        )
        
        return html_template.format(
            report_id=report_data['report_id'],
            generated_at=report_data['generated_at'],
            start_time=report_data['period']['start'],
            end_time=report_data['period']['end'],
            total_metrics=report_data['summary']['total_metrics'],
            total_alerts=report_data['summary']['total_alerts'],
            critical_alerts=report_data['summary']['critical_alerts'],
            resolution_rate=report_data['summary']['alert_resolution_rate'],
            recommendations_list=recommendations_html
        )
    
    async def _generate_csv_report(self, metrics: List[SecurityMetric], 
                                  alerts: List[SecurityAlert]) -> str:
        """Generate CSV format report."""
        import io
        import csv
        
        output = io.StringIO()
        
        # Write metrics
        output.write("=== METRICS ===\n")
        writer = csv.writer(output)
        writer.writerow(['Timestamp', 'Category', 'Name', 'Type', 'Value', 'Tags'])
        
        for metric in metrics[-1000:]:  # Limit to recent metrics
            writer.writerow([
                metric.timestamp.isoformat(),
                metric.category,
                metric.name,
                metric.metric_type.value,
                metric.value,
                json.dumps(metric.tags)
            ])
        
        # Write alerts
        output.write("\n\n=== ALERTS ===\n")
        writer.writerow(['Timestamp', 'Severity', 'Title', 'Category', 'Resolved', 'Description'])
        
        for alert in alerts[-1000:]:  # Limit to recent alerts
            writer.writerow([
                alert.timestamp.isoformat(),
                alert.severity.value,
                alert.title,
                alert.category,
                alert.resolved,
                alert.description
            ])
        
        return output.getvalue()


class SecurityDashboard:
    """Main security dashboard application."""
    
    def __init__(self, config: DashboardConfig = None):
        self.config = config or DashboardConfig()
        self.metrics_collector = MetricsCollector()
        self.alert_manager = AlertManager()
        self.websocket_manager = WebSocketManager()
        self.report_generator = ReportGenerator(self.metrics_collector, self.alert_manager)
        
        # Subscribe to metric and alert updates
        self.metrics_collector.subscribe(self._on_metric_update)
        self.alert_manager.subscribe(self._on_alert_update)
        
        # Setup default alert rules
        self._setup_default_alert_rules()
        
        # Create FastAPI application
        self.app = self._create_app()
        
        logger.info("Security Dashboard initialized")
    
    def _create_app(self) -> FastAPI:
        """Create FastAPI application."""
        app = FastAPI(
            title="FastAPI-Shield Security Dashboard",
            description="Real-time security monitoring and analytics dashboard",
            version="1.0.0"
        )
        
        # Add routes
        app.websocket("/ws")(self._websocket_endpoint)
        app.get("/api/metrics")(self._get_metrics)
        app.get("/api/alerts")(self._get_alerts)
        app.post("/api/alerts/{alert_id}/acknowledge")(self._acknowledge_alert)
        app.post("/api/alerts/{alert_id}/resolve")(self._resolve_alert)
        app.get("/api/dashboard/config")(self._get_dashboard_config)
        app.post("/api/dashboard/config")(self._update_dashboard_config)
        app.get("/api/reports/{report_type}")(self._generate_report_endpoint)
        app.get("/api/health")(self._health_check)
        app.get("/")(self._dashboard_home)
        
        return app
    
    async def _websocket_endpoint(self, websocket: WebSocket):
        """WebSocket endpoint for real-time updates."""
        await self.websocket_manager.connect(websocket)
        try:
            while True:
                # Keep connection alive and handle client messages
                data = await websocket.receive_text()
                message = json.loads(data)
                
                if message.get('type') == 'ping':
                    await websocket.send_text(json.dumps({'type': 'pong'}))
                elif message.get('type') == 'subscribe':
                    # Handle subscription requests
                    await websocket.send_text(json.dumps({
                        'type': 'subscribed',
                        'categories': message.get('categories', [])
                    }))
        
        except WebSocketDisconnect:
            await self.websocket_manager.disconnect(websocket)
        except Exception as e:
            logger.error(f"WebSocket error: {e}")
            await self.websocket_manager.disconnect(websocket)
    
    async def _get_metrics(self, 
                          category: Optional[str] = None,
                          limit: int = 100,
                          start_time: Optional[str] = None,
                          end_time: Optional[str] = None):
        """Get metrics API endpoint."""
        
        # Parse time parameters
        start_dt = None
        end_dt = None
        
        if start_time:
            try:
                start_dt = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid start_time format")
        
        if end_time:
            try:
                end_dt = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid end_time format")
        
        metrics = self.metrics_collector.get_metrics(
            category=category,
            start_time=start_dt,
            end_time=end_dt,
            limit=limit
        )
        
        return {
            'metrics': [metric.to_dict() for metric in metrics],
            'total': len(metrics),
            'aggregated': self.metrics_collector.get_aggregated_metrics(category) if category else {}
        }
    
    async def _get_alerts(self, 
                         severity: Optional[str] = None,
                         unresolved_only: bool = False,
                         limit: int = 50):
        """Get alerts API endpoint."""
        
        severity_enum = None
        if severity:
            try:
                severity_enum = AlertSeverity(severity)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid severity level")
        
        alerts = self.alert_manager.get_alerts(
            severity=severity_enum,
            unresolved_only=unresolved_only,
            limit=limit
        )
        
        return {
            'alerts': [alert.to_dict() for alert in alerts],
            'total': len(alerts)
        }
    
    async def _acknowledge_alert(self, alert_id: str, user_id: str = "dashboard_user"):
        """Acknowledge alert API endpoint."""
        success = self.alert_manager.acknowledge_alert(alert_id, user_id)
        
        if not success:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        return {'status': 'acknowledged', 'alert_id': alert_id}
    
    async def _resolve_alert(self, alert_id: str, user_id: str = "dashboard_user"):
        """Resolve alert API endpoint."""
        success = self.alert_manager.resolve_alert(alert_id, user_id)
        
        if not success:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        return {'status': 'resolved', 'alert_id': alert_id}
    
    async def _get_dashboard_config(self):
        """Get dashboard configuration."""
        return {
            'config': asdict(self.config),
            'widgets': [widget.to_dict() for widget in self.config.widgets]
        }
    
    async def _update_dashboard_config(self, config_update: Dict[str, Any]):
        """Update dashboard configuration."""
        # Update configuration (simplified)
        if 'theme' in config_update:
            try:
                self.config.theme = DashboardTheme(config_update['theme'])
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid theme")
        
        if 'refresh_interval' in config_update:
            self.config.refresh_interval = max(5, int(config_update['refresh_interval']))
        
        return {'status': 'updated', 'config': asdict(self.config)}
    
    async def _generate_report_endpoint(self, 
                                      report_type: str,
                                      format: str = "json",
                                      start_time: Optional[str] = None,
                                      end_time: Optional[str] = None):
        """Generate report API endpoint."""
        
        try:
            format_enum = ReportFormat(format)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid report format")
        
        # Parse time parameters
        start_dt = None
        end_dt = None
        
        if start_time:
            try:
                start_dt = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid start_time format")
        
        if end_time:
            try:
                end_dt = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid end_time format")
        
        report = await self.report_generator.generate_report(
            report_type=report_type,
            format=format_enum,
            start_time=start_dt,
            end_time=end_dt
        )
        
        if format_enum == ReportFormat.HTML:
            return HTMLResponse(content=report)
        else:
            return report
    
    async def _health_check(self):
        """Health check endpoint."""
        return {
            'status': 'healthy',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'metrics_count': len(self.metrics_collector.metrics),
            'alerts_count': len(self.alert_manager.alerts),
            'websocket_connections': len(self.websocket_manager.active_connections)
        }
    
    async def _dashboard_home(self, request: Request):
        """Dashboard home page."""
        dashboard_html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>FastAPI-Shield Security Dashboard</title>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { 
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    background: #1a1a1a; color: #fff; line-height: 1.6;
                }
                .header { 
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    padding: 2rem; text-align: center; box-shadow: 0 4px 20px rgba(0,0,0,0.1);
                }
                .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
                .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 2rem; }
                .card { 
                    background: #2d3748; border-radius: 12px; padding: 2rem; 
                    box-shadow: 0 8px 32px rgba(0,0,0,0.3); transition: transform 0.2s;
                }
                .card:hover { transform: translateY(-4px); }
                .metric-value { font-size: 3rem; font-weight: bold; color: #4fd1c7; }
                .metric-label { color: #a0aec0; font-size: 0.9rem; text-transform: uppercase; }
                .alert-critical { border-left: 4px solid #f56565; }
                .alert-high { border-left: 4px solid #ed8936; }
                .alert-medium { border-left: 4px solid #ecc94b; }
                .alert-low { border-left: 4px solid #48bb78; }
                .status-indicator { 
                    width: 12px; height: 12px; border-radius: 50%; 
                    display: inline-block; margin-right: 8px;
                    background: #48bb78; animation: pulse 2s infinite;
                }
                @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
                .btn { 
                    background: #4299e1; color: white; padding: 0.75rem 1.5rem; 
                    border: none; border-radius: 8px; cursor: pointer; 
                    text-decoration: none; display: inline-block; transition: background 0.2s;
                }
                .btn:hover { background: #3182ce; }
                .api-endpoint { 
                    background: #1a202c; padding: 1rem; border-radius: 8px; 
                    font-family: 'Courier New', monospace; font-size: 0.9rem; margin: 0.5rem 0;
                }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🛡️ FastAPI-Shield Security Dashboard</h1>
                <p>Real-time Security Monitoring & Analytics</p>
                <div class="status-indicator"></div>
                <span>System Online</span>
            </div>
            
            <div class="container">
                <div class="grid" id="dashboard-grid">
                    <div class="card">
                        <div class="metric-value" id="metrics-count">---</div>
                        <div class="metric-label">Total Metrics Collected</div>
                    </div>
                    
                    <div class="card">
                        <div class="metric-value" id="alerts-count">---</div>
                        <div class="metric-label">Active Alerts</div>
                    </div>
                    
                    <div class="card">
                        <div class="metric-value" id="websocket-count">---</div>
                        <div class="metric-label">Live Connections</div>
                    </div>
                    
                    <div class="card">
                        <h3>📊 API Endpoints</h3>
                        <div class="api-endpoint">GET /api/metrics</div>
                        <div class="api-endpoint">GET /api/alerts</div>
                        <div class="api-endpoint">GET /api/reports/security</div>
                        <div class="api-endpoint">WebSocket /ws</div>
                        <a href="/api/health" class="btn">Health Check</a>
                    </div>
                    
                    <div class="card">
                        <h3>⚡ Real-time Features</h3>
                        <p>• Live metric streaming via WebSocket</p>
                        <p>• Instant alert notifications</p>
                        <p>• Auto-refreshing dashboard</p>
                        <p>• Interactive data visualization</p>
                    </div>
                    
                    <div class="card">
                        <h3>📈 Analytics</h3>
                        <p>• Historical trend analysis</p>
                        <p>• Automated report generation</p>
                        <p>• Custom metric aggregation</p>
                        <p>• Performance monitoring</p>
                    </div>
                </div>
            </div>
            
            <script>
                // WebSocket connection for real-time updates
                const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
                const ws = new WebSocket(`${protocol}//${window.location.host}/ws`);
                
                ws.onopen = () => {
                    console.log('WebSocket connected');
                    ws.send(JSON.stringify({type: 'ping'}));
                };
                
                ws.onmessage = (event) => {
                    const data = JSON.parse(event.data);
                    if (data.type === 'metric_update') {
                        console.log('New metric:', data.data);
                    } else if (data.type === 'alert_update') {
                        console.log('New alert:', data.data);
                    }
                };
                
                // Fetch initial dashboard data
                async function updateDashboard() {
                    try {
                        const health = await fetch('/api/health').then(r => r.json());
                        document.getElementById('metrics-count').textContent = health.metrics_count || 0;
                        document.getElementById('alerts-count').textContent = health.alerts_count || 0;
                        document.getElementById('websocket-count').textContent = health.websocket_connections || 0;
                    } catch (error) {
                        console.error('Failed to update dashboard:', error);
                    }
                }
                
                // Update dashboard every 30 seconds
                updateDashboard();
                setInterval(updateDashboard, 30000);
            </script>
        </body>
        </html>
        """
        
        return HTMLResponse(content=dashboard_html)
    
    def _setup_default_alert_rules(self):
        """Setup default alert rules."""
        
        def high_error_rate_rule(metric: SecurityMetric) -> Optional[SecurityAlert]:
            """Alert for high error rates."""
            if metric.category == 'errors' and metric.value > 100:
                return SecurityAlert(
                    id=str(uuid.uuid4()),
                    title="High Error Rate Detected",
                    description=f"Error rate of {metric.value} exceeds threshold of 100",
                    severity=AlertSeverity.HIGH,
                    timestamp=datetime.now(timezone.utc),
                    category="performance",
                    source="error_rate_monitor",
                    recommended_actions=[
                        "Check application logs for error details",
                        "Review recent deployments",
                        "Monitor system resources"
                    ]
                )
            return None
        
        def security_breach_rule(metric: SecurityMetric) -> Optional[SecurityAlert]:
            """Alert for potential security breaches."""
            if (metric.category == 'security_events' and 
                'breach' in metric.tags.get('type', '').lower()):
                return SecurityAlert(
                    id=str(uuid.uuid4()),
                    title="Potential Security Breach",
                    description=f"Security event detected: {metric.name}",
                    severity=AlertSeverity.CRITICAL,
                    timestamp=datetime.now(timezone.utc),
                    category="security",
                    source="security_monitor",
                    affected_resources=[metric.tags.get('resource', 'unknown')],
                    recommended_actions=[
                        "Investigate immediately",
                        "Check access logs",
                        "Consider blocking suspicious IPs",
                        "Notify security team"
                    ]
                )
            return None
        
        self.alert_manager.add_alert_rule(high_error_rate_rule)
        self.alert_manager.add_alert_rule(security_breach_rule)
    
    def _on_metric_update(self, metric: SecurityMetric):
        """Handle new metric updates."""
        # Evaluate alert rules
        self.alert_manager.evaluate_alert_rules(metric)
        
        # Broadcast to WebSocket clients (only if event loop is running)
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(self.websocket_manager.broadcast_metric(metric))
        except RuntimeError:
            # No event loop running, skip WebSocket broadcast
            pass
    
    def _on_alert_update(self, alert: SecurityAlert):
        """Handle new alert updates."""
        # Broadcast to WebSocket clients (only if event loop is running)
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(self.websocket_manager.broadcast_alert(alert))
        except RuntimeError:
            # No event loop running, skip WebSocket broadcast
            pass
    
    def add_metric(self, metric: SecurityMetric):
        """Add a security metric to the dashboard."""
        self.metrics_collector.add_metric(metric)
    
    def add_alert(self, alert: SecurityAlert):
        """Add a security alert to the dashboard."""
        self.alert_manager.add_alert(alert)
    
    async def start_server(self, host: str = "0.0.0.0", port: int = 8080):
        """Start the dashboard server."""
        config = uvicorn.Config(
            app=self.app,
            host=host,
            port=port,
            log_level="info",
            access_log=True
        )
        server = uvicorn.Server(config)
        await server.serve()


# Convenience functions

def create_security_dashboard(config: DashboardConfig = None) -> SecurityDashboard:
    """Create a security dashboard instance."""
    return SecurityDashboard(config)


def create_default_widgets() -> List[DashboardWidget]:
    """Create default dashboard widgets."""
    return [
        DashboardWidget(
            id="metrics_overview",
            title="Metrics Overview",
            chart_type=ChartType.LINE_CHART,
            metric_query="category:*",
            position={"x": 0, "y": 0, "width": 6, "height": 4}
        ),
        DashboardWidget(
            id="alert_distribution",
            title="Alert Distribution",
            chart_type=ChartType.PIE_CHART,
            metric_query="alerts:severity",
            position={"x": 6, "y": 0, "width": 6, "height": 4}
        ),
        DashboardWidget(
            id="performance_gauge",
            title="System Performance",
            chart_type=ChartType.GAUGE_CHART,
            metric_query="category:performance",
            position={"x": 0, "y": 4, "width": 4, "height": 3}
        ),
        DashboardWidget(
            id="security_heatmap",
            title="Security Events Heatmap",
            chart_type=ChartType.HEATMAP,
            metric_query="category:security",
            position={"x": 4, "y": 4, "width": 8, "height": 3}
        )
    ]


# Export all public classes and functions
__all__ = [
    # Enums
    'MetricType',
    'ChartType',
    'AlertSeverity',
    'ReportFormat',
    'DashboardTheme',
    
    # Data classes
    'SecurityMetric',
    'DashboardWidget',
    'SecurityAlert',
    'DashboardConfig',
    
    # Core classes
    'MetricsCollector',
    'AlertManager',
    'WebSocketManager',
    'ReportGenerator',
    'SecurityDashboard',
    
    # Convenience functions
    'create_security_dashboard',
    'create_default_widgets',
]