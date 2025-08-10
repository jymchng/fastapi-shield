"""Shield Metrics Dashboard for FastAPI Shield.

This module provides a comprehensive web-based dashboard for monitoring and visualizing
shield performance, metrics, and alerts with real-time updates and historical analysis.
"""

import asyncio
import json
import logging
import sqlite3
import time
import threading
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, Callable, Set, Tuple
from urllib.parse import quote
import uuid
import warnings

from fastapi import FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates
import uvicorn
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.websockets import WebSocketState

try:
    import plotly.graph_objects as go
    import plotly.utils
    from plotly.subplots import make_subplots
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False


class MetricType(str, Enum):
    """Metric type enumeration."""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    RATE = "rate"
    PERCENTAGE = "percentage"
    DURATION = "duration"


class AlertSeverity(str, Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class AlertStatus(str, Enum):
    """Alert status enumeration."""
    ACTIVE = "active"
    RESOLVED = "resolved"
    SILENCED = "silenced"
    ACKNOWLEDGED = "acknowledged"


class DashboardTheme(str, Enum):
    """Dashboard theme options."""
    LIGHT = "light"
    DARK = "dark"
    AUTO = "auto"


@dataclass
class MetricValue:
    """Individual metric value with timestamp."""
    value: Union[int, float]
    timestamp: datetime
    labels: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "value": self.value,
            "timestamp": self.timestamp.isoformat(),
            "labels": self.labels
        }


@dataclass
class Metric:
    """Metric definition and storage."""
    name: str
    type: MetricType
    description: str = ""
    unit: str = ""
    labels: Set[str] = field(default_factory=set)
    values: deque = field(default_factory=lambda: deque(maxlen=10000))
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def add_value(self, value: Union[int, float], labels: Dict[str, str] = None):
        """Add a new metric value."""
        metric_value = MetricValue(
            value=value,
            timestamp=datetime.now(timezone.utc),
            labels=labels or {}
        )
        self.values.append(metric_value)
        
        # Update known labels
        if labels:
            self.labels.update(labels.keys())
    
    def get_latest(self) -> Optional[MetricValue]:
        """Get the latest metric value."""
        return self.values[-1] if self.values else None
    
    def get_values_since(self, since: datetime) -> List[MetricValue]:
        """Get values since a specific timestamp."""
        return [v for v in self.values if v.timestamp >= since]
    
    def get_values_in_range(self, start: datetime, end: datetime) -> List[MetricValue]:
        """Get values within a time range."""
        return [v for v in self.values if start <= v.timestamp <= end]
    
    def calculate_rate(self, window_seconds: int = 60) -> float:
        """Calculate rate per second over a time window."""
        now = datetime.now(timezone.utc)
        since = now - timedelta(seconds=window_seconds)
        values = self.get_values_since(since)
        
        if len(values) < 2:
            return 0.0
        
        time_span = (values[-1].timestamp - values[0].timestamp).total_seconds()
        if time_span <= 0:
            return 0.0
        
        if self.type == MetricType.COUNTER:
            # For counters, calculate increase over time
            total_increase = values[-1].value - values[0].value
            return total_increase / time_span
        else:
            # For other types, calculate average rate
            return len(values) / time_span


@dataclass
class AlertRule:
    """Alert rule configuration."""
    id: str
    name: str
    metric_name: str
    condition: str  # "gt", "lt", "eq", "gte", "lte", "ne"
    threshold: Union[int, float]
    duration: int  # seconds the condition must be true
    severity: AlertSeverity
    description: str = ""
    labels: Dict[str, str] = field(default_factory=dict)
    enabled: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_triggered: Optional[datetime] = None
    trigger_count: int = 0
    
    def evaluate(self, metric_value: MetricValue) -> bool:
        """Evaluate if the alert condition is met."""
        if not self.enabled:
            return False
        
        value = metric_value.value
        
        if self.condition == "gt":
            return value > self.threshold
        elif self.condition == "lt":
            return value < self.threshold
        elif self.condition == "eq":
            return value == self.threshold
        elif self.condition == "gte":
            return value >= self.threshold
        elif self.condition == "lte":
            return value <= self.threshold
        elif self.condition == "ne":
            return value != self.threshold
        else:
            return False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "metric_name": self.metric_name,
            "condition": self.condition,
            "threshold": self.threshold,
            "duration": self.duration,
            "severity": self.severity.value,
            "description": self.description,
            "labels": self.labels,
            "enabled": self.enabled,
            "created_at": self.created_at.isoformat(),
            "last_triggered": self.last_triggered.isoformat() if self.last_triggered else None,
            "trigger_count": self.trigger_count
        }


@dataclass
class Alert:
    """Active or resolved alert."""
    id: str
    rule_id: str
    rule_name: str
    metric_name: str
    metric_value: Union[int, float]
    threshold: Union[int, float]
    severity: AlertSeverity
    status: AlertStatus
    message: str
    labels: Dict[str, str] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at: Optional[datetime] = None
    acknowledged_at: Optional[datetime] = None
    acknowledged_by: Optional[str] = None
    
    def acknowledge(self, acknowledged_by: str = "system"):
        """Acknowledge the alert."""
        self.status = AlertStatus.ACKNOWLEDGED
        self.acknowledged_at = datetime.now(timezone.utc)
        self.acknowledged_by = acknowledged_by
    
    def resolve(self):
        """Resolve the alert."""
        self.status = AlertStatus.RESOLVED
        self.resolved_at = datetime.now(timezone.utc)
    
    def silence(self):
        """Silence the alert."""
        self.status = AlertStatus.SILENCED
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "metric_name": self.metric_name,
            "metric_value": self.metric_value,
            "threshold": self.threshold,
            "severity": self.severity.value,
            "status": self.status.value,
            "message": self.message,
            "labels": self.labels,
            "created_at": self.created_at.isoformat(),
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "acknowledged_at": self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            "acknowledged_by": self.acknowledged_by
        }


@dataclass
class DashboardConfig:
    """Dashboard configuration."""
    title: str = "Shield Metrics Dashboard"
    theme: DashboardTheme = DashboardTheme.LIGHT
    refresh_interval: int = 5  # seconds
    max_data_points: int = 1000
    enable_auth: bool = False
    username: str = "admin"
    password: str = "admin"
    host: str = "0.0.0.0"
    port: int = 8080
    enable_ssl: bool = False
    ssl_cert_path: Optional[str] = None
    ssl_key_path: Optional[str] = None
    database_path: str = "dashboard.db"
    static_files_path: Optional[str] = None
    custom_css: Optional[str] = None
    enable_export: bool = True
    enable_alerts: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


class MetricStorage(ABC):
    """Abstract base class for metric storage backends."""
    
    @abstractmethod
    async def store_metric(self, metric: Metric) -> bool:
        """Store a metric."""
        pass
    
    @abstractmethod
    async def get_metric(self, name: str) -> Optional[Metric]:
        """Get a metric by name."""
        pass
    
    @abstractmethod
    async def get_all_metrics(self) -> List[Metric]:
        """Get all metrics."""
        pass
    
    @abstractmethod
    async def delete_metric(self, name: str) -> bool:
        """Delete a metric."""
        pass
    
    @abstractmethod
    async def get_metrics_by_labels(self, labels: Dict[str, str]) -> List[Metric]:
        """Get metrics by labels."""
        pass


class SQLiteMetricStorage(MetricStorage):
    """SQLite-based metric storage."""
    
    def __init__(self, database_path: str = "dashboard.db"):
        self.database_path = database_path
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self._init_database()
    
    def _init_database(self):
        """Initialize the database schema."""
        with sqlite3.connect(self.database_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS metrics (
                    name TEXT PRIMARY KEY,
                    type TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    unit TEXT DEFAULT '',
                    labels TEXT DEFAULT '{}',
                    created_at TEXT NOT NULL
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS metric_values (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    metric_name TEXT NOT NULL,
                    value REAL NOT NULL,
                    timestamp TEXT NOT NULL,
                    labels TEXT DEFAULT '{}',
                    FOREIGN KEY (metric_name) REFERENCES metrics (name) ON DELETE CASCADE
                )
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_metric_values_metric_name 
                ON metric_values (metric_name)
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_metric_values_timestamp 
                ON metric_values (timestamp)
            """)
            
            conn.commit()
    
    async def store_metric(self, metric: Metric) -> bool:
        """Store a metric."""
        try:
            with sqlite3.connect(self.database_path) as conn:
                # Store metric definition
                conn.execute("""
                    INSERT OR REPLACE INTO metrics 
                    (name, type, description, unit, labels, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    metric.name,
                    metric.type.value,
                    metric.description,
                    metric.unit,
                    json.dumps(list(metric.labels)),
                    metric.created_at.isoformat()
                ))
                
                # Store metric values
                for value in metric.values:
                    conn.execute("""
                        INSERT INTO metric_values 
                        (metric_name, value, timestamp, labels)
                        VALUES (?, ?, ?, ?)
                    """, (
                        metric.name,
                        value.value,
                        value.timestamp.isoformat(),
                        json.dumps(value.labels)
                    ))
                
                conn.commit()
                return True
        
        except Exception as e:
            self.logger.error(f"Failed to store metric {metric.name}: {e}")
            return False
    
    async def get_metric(self, name: str) -> Optional[Metric]:
        """Get a metric by name."""
        try:
            with sqlite3.connect(self.database_path) as conn:
                conn.row_factory = sqlite3.Row
                
                # Get metric definition
                result = conn.execute("""
                    SELECT * FROM metrics WHERE name = ?
                """, (name,)).fetchone()
                
                if not result:
                    return None
                
                # Get metric values
                values = conn.execute("""
                    SELECT value, timestamp, labels 
                    FROM metric_values 
                    WHERE metric_name = ? 
                    ORDER BY timestamp DESC 
                    LIMIT 10000
                """, (name,)).fetchall()
                
                # Reconstruct metric
                metric = Metric(
                    name=result["name"],
                    type=MetricType(result["type"]),
                    description=result["description"],
                    unit=result["unit"],
                    labels=set(json.loads(result["labels"])),
                    created_at=datetime.fromisoformat(result["created_at"])
                )
                
                for value_row in values:
                    metric_value = MetricValue(
                        value=value_row["value"],
                        timestamp=datetime.fromisoformat(value_row["timestamp"]),
                        labels=json.loads(value_row["labels"])
                    )
                    metric.values.appendleft(metric_value)
                
                return metric
        
        except Exception as e:
            self.logger.error(f"Failed to get metric {name}: {e}")
            return None
    
    async def get_all_metrics(self) -> List[Metric]:
        """Get all metrics."""
        try:
            with sqlite3.connect(self.database_path) as conn:
                conn.row_factory = sqlite3.Row
                
                results = conn.execute("SELECT name FROM metrics").fetchall()
                
                metrics = []
                for row in results:
                    metric = await self.get_metric(row["name"])
                    if metric:
                        metrics.append(metric)
                
                return metrics
        
        except Exception as e:
            self.logger.error(f"Failed to get all metrics: {e}")
            return []
    
    async def delete_metric(self, name: str) -> bool:
        """Delete a metric."""
        try:
            with sqlite3.connect(self.database_path) as conn:
                conn.execute("DELETE FROM metrics WHERE name = ?", (name,))
                conn.commit()
                return True
        
        except Exception as e:
            self.logger.error(f"Failed to delete metric {name}: {e}")
            return False
    
    async def get_metrics_by_labels(self, labels: Dict[str, str]) -> List[Metric]:
        """Get metrics by labels."""
        metrics = await self.get_all_metrics()
        filtered_metrics = []
        
        for metric in metrics:
            # Check if metric has all required labels
            if all(label in metric.labels for label in labels.keys()):
                # Check recent values for matching label values
                recent_values = list(metric.values)[-100:]  # Check last 100 values
                for value in recent_values:
                    if all(value.labels.get(k) == v for k, v in labels.items()):
                        filtered_metrics.append(metric)
                        break
        
        return filtered_metrics


class AlertManager:
    """Alert management system."""
    
    def __init__(self, storage: MetricStorage):
        self.storage = storage
        self.rules: Dict[str, AlertRule] = {}
        self.active_alerts: Dict[str, Alert] = {}
        self.alert_history: List[Alert] = []
        self.callbacks: List[Callable[[Alert], None]] = []
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self._condition_states: Dict[str, Dict[str, datetime]] = defaultdict(dict)
    
    def add_rule(self, rule: AlertRule) -> bool:
        """Add an alert rule."""
        try:
            self.rules[rule.id] = rule
            self.logger.info(f"Added alert rule: {rule.name}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to add alert rule {rule.name}: {e}")
            return False
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove an alert rule."""
        try:
            if rule_id in self.rules:
                del self.rules[rule_id]
                # Clean up condition states
                if rule_id in self._condition_states:
                    del self._condition_states[rule_id]
                self.logger.info(f"Removed alert rule: {rule_id}")
                return True
            return False
        except Exception as e:
            self.logger.error(f"Failed to remove alert rule {rule_id}: {e}")
            return False
    
    def get_rule(self, rule_id: str) -> Optional[AlertRule]:
        """Get an alert rule by ID."""
        return self.rules.get(rule_id)
    
    def get_all_rules(self) -> List[AlertRule]:
        """Get all alert rules."""
        return list(self.rules.values())
    
    def evaluate_metric(self, metric: Metric):
        """Evaluate a metric against all applicable alert rules."""
        latest_value = metric.get_latest()
        if not latest_value:
            return
        
        for rule in self.rules.values():
            if rule.metric_name == metric.name:
                self._evaluate_rule(rule, latest_value)
    
    def _evaluate_rule(self, rule: AlertRule, metric_value: MetricValue):
        """Evaluate a single rule against a metric value."""
        if not rule.evaluate(metric_value):
            # Condition not met, clear any existing state
            if rule.id in self._condition_states:
                del self._condition_states[rule.id]
            
            # Check if we should resolve an existing alert
            for alert_id, alert in list(self.active_alerts.items()):
                if alert.rule_id == rule.id:
                    self._resolve_alert(alert)
            return
        
        # Condition met, track timing
        now = datetime.now(timezone.utc)
        
        if rule.id not in self._condition_states:
            self._condition_states[rule.id] = {"started": now}
            return
        
        # Check if condition has been true long enough
        started = self._condition_states[rule.id]["started"]
        duration = (now - started).total_seconds()
        
        if duration >= rule.duration:
            # Trigger alert if not already active
            existing_alert = None
            for alert in self.active_alerts.values():
                if alert.rule_id == rule.id and alert.status == AlertStatus.ACTIVE:
                    existing_alert = alert
                    break
            
            if not existing_alert:
                self._trigger_alert(rule, metric_value)
    
    def _trigger_alert(self, rule: AlertRule, metric_value: MetricValue):
        """Trigger an alert."""
        alert_id = str(uuid.uuid4())
        
        alert = Alert(
            id=alert_id,
            rule_id=rule.id,
            rule_name=rule.name,
            metric_name=rule.metric_name,
            metric_value=metric_value.value,
            threshold=rule.threshold,
            severity=rule.severity,
            status=AlertStatus.ACTIVE,
            message=f"{rule.name}: {rule.metric_name} is {metric_value.value} (threshold: {rule.threshold})",
            labels=metric_value.labels
        )
        
        self.active_alerts[alert_id] = alert
        self.alert_history.append(alert)
        
        # Update rule statistics
        rule.last_triggered = alert.created_at
        rule.trigger_count += 1
        
        # Notify callbacks
        for callback in self.callbacks:
            try:
                callback(alert)
            except Exception as e:
                self.logger.error(f"Error in alert callback: {e}")
        
        self.logger.warning(f"Alert triggered: {alert.message}")
    
    def _resolve_alert(self, alert: Alert):
        """Resolve an alert."""
        alert.resolve()
        
        if alert.id in self.active_alerts:
            del self.active_alerts[alert.id]
        
        self.logger.info(f"Alert resolved: {alert.rule_name}")
        
        # Notify callbacks
        for callback in self.callbacks:
            try:
                callback(alert)
            except Exception as e:
                self.logger.error(f"Error in alert callback: {e}")
    
    def acknowledge_alert(self, alert_id: str, acknowledged_by: str = "user") -> bool:
        """Acknowledge an alert."""
        if alert_id in self.active_alerts:
            self.active_alerts[alert_id].acknowledge(acknowledged_by)
            return True
        return False
    
    def silence_alert(self, alert_id: str) -> bool:
        """Silence an alert."""
        if alert_id in self.active_alerts:
            self.active_alerts[alert_id].silence()
            return True
        return False
    
    def get_active_alerts(self) -> List[Alert]:
        """Get all active alerts."""
        return list(self.active_alerts.values())
    
    def get_alert_history(self, limit: int = 100) -> List[Alert]:
        """Get alert history."""
        return self.alert_history[-limit:]
    
    def add_callback(self, callback: Callable[[Alert], None]):
        """Add an alert callback."""
        self.callbacks.append(callback)


class DashboardWebSocketManager:
    """WebSocket connection manager for real-time updates."""
    
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    async def connect(self, websocket: WebSocket):
        """Accept a WebSocket connection."""
        await websocket.accept()
        self.active_connections.add(websocket)
        self.logger.info(f"WebSocket connected. Total connections: {len(self.active_connections)}")
    
    def disconnect(self, websocket: WebSocket):
        """Remove a WebSocket connection."""
        self.active_connections.discard(websocket)
        self.logger.info(f"WebSocket disconnected. Total connections: {len(self.active_connections)}")
    
    async def broadcast(self, message: Dict[str, Any]):
        """Broadcast a message to all connected clients."""
        if not self.active_connections:
            return
        
        message_json = json.dumps(message)
        disconnected = set()
        
        for connection in self.active_connections.copy():
            try:
                if connection.client_state == WebSocketState.CONNECTED:
                    await connection.send_text(message_json)
                else:
                    disconnected.add(connection)
            except Exception as e:
                self.logger.warning(f"Failed to send WebSocket message: {e}")
                disconnected.add(connection)
        
        # Remove disconnected clients
        self.active_connections -= disconnected
    
    async def send_metric_update(self, metric: Metric):
        """Send metric update to all clients."""
        latest_value = metric.get_latest()
        if latest_value:
            await self.broadcast({
                "type": "metric_update",
                "data": {
                    "name": metric.name,
                    "type": metric.type.value,
                    "value": latest_value.value,
                    "timestamp": latest_value.timestamp.isoformat(),
                    "labels": latest_value.labels
                }
            })
    
    async def send_alert_update(self, alert: Alert):
        """Send alert update to all clients."""
        await self.broadcast({
            "type": "alert_update",
            "data": alert.to_dict()
        })


class MetricsDashboard:
    """Main metrics dashboard application."""
    
    def __init__(self, config: DashboardConfig = None, storage: MetricStorage = None):
        self.config = config or DashboardConfig()
        self.storage = storage or SQLiteMetricStorage(self.config.database_path)
        self.alert_manager = AlertManager(self.storage)
        self.websocket_manager = DashboardWebSocketManager()
        
        self.metrics: Dict[str, Metric] = {}
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # FastAPI app
        self.app = FastAPI(title=self.config.title)
        self.security = HTTPBasic() if self.config.enable_auth else None
        
        # Setup routes
        self._setup_routes()
        self._setup_websockets()
        
        # Setup alert callbacks
        self.alert_manager.add_callback(self._on_alert_update)
        
        # Background tasks
        self._background_tasks: Set[asyncio.Task] = set()
    
    def _setup_routes(self):
        """Setup FastAPI routes."""
        
        # Static files
        if self.config.static_files_path:
            self.app.mount("/static", StaticFiles(directory=self.config.static_files_path), name="static")
        
        # Authentication dependency
        async def get_current_user(credentials: HTTPBasicCredentials = Depends(self.security)) if self.config.enable_auth else lambda: None:
            if self.config.enable_auth:
                if credentials.username != self.config.username or credentials.password != self.config.password:
                    raise HTTPException(status_code=401, detail="Invalid credentials")
            return credentials.username if self.config.enable_auth else "anonymous"
        
        # Main dashboard route
        @self.app.get("/", response_class=HTMLResponse)
        async def dashboard(request: Request, user = Depends(get_current_user)):
            """Serve the main dashboard page."""
            return self._render_dashboard_html()
        
        # API routes
        @self.app.get("/api/metrics")
        async def get_metrics(user = Depends(get_current_user)):
            """Get all metrics."""
            metrics_data = []
            for metric in self.metrics.values():
                latest_value = metric.get_latest()
                metrics_data.append({
                    "name": metric.name,
                    "type": metric.type.value,
                    "description": metric.description,
                    "unit": metric.unit,
                    "latest_value": latest_value.value if latest_value else None,
                    "latest_timestamp": latest_value.timestamp.isoformat() if latest_value else None,
                    "total_values": len(metric.values)
                })
            
            return {"metrics": metrics_data}
        
        @self.app.get("/api/metrics/{metric_name}")
        async def get_metric(metric_name: str, since: Optional[str] = None, user = Depends(get_current_user)):
            """Get specific metric data."""
            if metric_name not in self.metrics:
                raise HTTPException(status_code=404, detail="Metric not found")
            
            metric = self.metrics[metric_name]
            
            if since:
                try:
                    since_dt = datetime.fromisoformat(since.replace('Z', '+00:00'))
                    values = metric.get_values_since(since_dt)
                except ValueError:
                    raise HTTPException(status_code=400, detail="Invalid datetime format")
            else:
                values = list(metric.values)
            
            return {
                "name": metric.name,
                "type": metric.type.value,
                "description": metric.description,
                "unit": metric.unit,
                "values": [v.to_dict() for v in values]
            }
        
        @self.app.post("/api/metrics/{metric_name}")
        async def add_metric_value(
            metric_name: str, 
            value: float, 
            labels: Dict[str, str] = None, 
            user = Depends(get_current_user)
        ):
            """Add a new metric value."""
            if metric_name not in self.metrics:
                raise HTTPException(status_code=404, detail="Metric not found")
            
            self.metrics[metric_name].add_value(value, labels)
            await self.websocket_manager.send_metric_update(self.metrics[metric_name])
            
            return {"status": "success"}
        
        # Alert routes
        @self.app.get("/api/alerts")
        async def get_alerts(user = Depends(get_current_user)):
            """Get all alerts."""
            return {
                "active": [alert.to_dict() for alert in self.alert_manager.get_active_alerts()],
                "history": [alert.to_dict() for alert in self.alert_manager.get_alert_history()]
            }
        
        @self.app.post("/api/alerts/{alert_id}/acknowledge")
        async def acknowledge_alert(alert_id: str, user = Depends(get_current_user)):
            """Acknowledge an alert."""
            success = self.alert_manager.acknowledge_alert(alert_id, user)
            if not success:
                raise HTTPException(status_code=404, detail="Alert not found")
            return {"status": "success"}
        
        @self.app.post("/api/alerts/{alert_id}/silence")
        async def silence_alert(alert_id: str, user = Depends(get_current_user)):
            """Silence an alert."""
            success = self.alert_manager.silence_alert(alert_id)
            if not success:
                raise HTTPException(status_code=404, detail="Alert not found")
            return {"status": "success"}
        
        # Alert rules routes
        @self.app.get("/api/alert-rules")
        async def get_alert_rules(user = Depends(get_current_user)):
            """Get all alert rules."""
            return {"rules": [rule.to_dict() for rule in self.alert_manager.get_all_rules()]}
        
        @self.app.post("/api/alert-rules")
        async def create_alert_rule(rule_data: Dict[str, Any], user = Depends(get_current_user)):
            """Create a new alert rule."""
            rule = AlertRule(
                id=rule_data.get("id", str(uuid.uuid4())),
                name=rule_data["name"],
                metric_name=rule_data["metric_name"],
                condition=rule_data["condition"],
                threshold=rule_data["threshold"],
                duration=rule_data.get("duration", 60),
                severity=AlertSeverity(rule_data.get("severity", "warning")),
                description=rule_data.get("description", ""),
                labels=rule_data.get("labels", {}),
                enabled=rule_data.get("enabled", True)
            )
            
            success = self.alert_manager.add_rule(rule)
            if not success:
                raise HTTPException(status_code=400, detail="Failed to create alert rule")
            
            return rule.to_dict()
        
        @self.app.delete("/api/alert-rules/{rule_id}")
        async def delete_alert_rule(rule_id: str, user = Depends(get_current_user)):
            """Delete an alert rule."""
            success = self.alert_manager.remove_rule(rule_id)
            if not success:
                raise HTTPException(status_code=404, detail="Alert rule not found")
            return {"status": "success"}
        
        # Chart data route
        @self.app.get("/api/charts/{metric_name}")
        async def get_chart_data(
            metric_name: str, 
            chart_type: str = "line",
            time_range: str = "1h",
            user = Depends(get_current_user)
        ):
            """Get chart data for a metric."""
            if metric_name not in self.metrics:
                raise HTTPException(status_code=404, detail="Metric not found")
            
            metric = self.metrics[metric_name]
            
            # Calculate time range
            now = datetime.now(timezone.utc)
            if time_range == "1h":
                since = now - timedelta(hours=1)
            elif time_range == "24h":
                since = now - timedelta(days=1)
            elif time_range == "7d":
                since = now - timedelta(days=7)
            elif time_range == "30d":
                since = now - timedelta(days=30)
            else:
                since = now - timedelta(hours=1)
            
            values = metric.get_values_since(since)
            
            chart_data = {
                "labels": [v.timestamp.isoformat() for v in values],
                "datasets": [{
                    "label": metric.name,
                    "data": [v.value for v in values],
                    "borderColor": "rgb(75, 192, 192)",
                    "backgroundColor": "rgba(75, 192, 192, 0.1)",
                    "tension": 0.1
                }]
            }
            
            return chart_data
    
    def _setup_websockets(self):
        """Setup WebSocket endpoints."""
        
        @self.app.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket):
            """WebSocket endpoint for real-time updates."""
            await self.websocket_manager.connect(websocket)
            try:
                while True:
                    data = await websocket.receive_text()
                    # Handle client messages if needed
                    message = json.loads(data)
                    if message.get("type") == "ping":
                        await websocket.send_text(json.dumps({"type": "pong"}))
            except WebSocketDisconnect:
                self.websocket_manager.disconnect(websocket)
    
    def _render_dashboard_html(self) -> str:
        """Render the dashboard HTML."""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Shield Metrics Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        .metric-card {
            @apply bg-white rounded-lg shadow-md p-6 border-l-4 border-blue-500;
        }
        .alert-card {
            @apply bg-white rounded-lg shadow-md p-4 border-l-4;
        }
        .alert-critical { @apply border-red-500; }
        .alert-error { @apply border-red-400; }
        .alert-warning { @apply border-yellow-500; }
        .alert-info { @apply border-blue-500; }
    </style>
</head>
<body class="bg-gray-100">
    <div class="container mx-auto px-4 py-8">
        <header class="mb-8">
            <h1 class="text-3xl font-bold text-gray-800">Shield Metrics Dashboard</h1>
            <p class="text-gray-600 mt-2">Real-time monitoring and alerts</p>
        </header>

        <!-- Metrics Overview -->
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8" id="metrics-overview">
            <!-- Dynamic metric cards will be inserted here -->
        </div>

        <!-- Charts Section -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8" id="charts-section">
            <!-- Dynamic charts will be inserted here -->
        </div>

        <!-- Alerts Section -->
        <div class="bg-white rounded-lg shadow-md p-6 mb-8">
            <h2 class="text-xl font-semibold text-gray-800 mb-4">Active Alerts</h2>
            <div id="alerts-container">
                <!-- Dynamic alerts will be inserted here -->
            </div>
        </div>

        <!-- Alert Rules Management -->
        <div class="bg-white rounded-lg shadow-md p-6">
            <h2 class="text-xl font-semibold text-gray-800 mb-4">Alert Rules</h2>
            <div class="mb-4">
                <button class="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600" onclick="showAddRuleModal()">
                    Add Alert Rule
                </button>
            </div>
            <div id="alert-rules-container">
                <!-- Dynamic alert rules will be inserted here -->
            </div>
        </div>
    </div>

    <!-- Add Rule Modal -->
    <div id="add-rule-modal" class="fixed inset-0 bg-gray-600 bg-opacity-50 hidden">
        <div class="flex items-center justify-center min-h-screen">
            <div class="bg-white rounded-lg p-6 w-full max-w-md">
                <h3 class="text-lg font-semibold mb-4">Add Alert Rule</h3>
                <form id="add-rule-form">
                    <div class="mb-4">
                        <label class="block text-sm font-medium text-gray-700">Name</label>
                        <input type="text" name="name" class="mt-1 block w-full rounded-md border-gray-300 shadow-sm">
                    </div>
                    <div class="mb-4">
                        <label class="block text-sm font-medium text-gray-700">Metric Name</label>
                        <select name="metric_name" class="mt-1 block w-full rounded-md border-gray-300 shadow-sm" id="metric-select">
                            <!-- Options populated by JavaScript -->
                        </select>
                    </div>
                    <div class="mb-4">
                        <label class="block text-sm font-medium text-gray-700">Condition</label>
                        <select name="condition" class="mt-1 block w-full rounded-md border-gray-300 shadow-sm">
                            <option value="gt">Greater than</option>
                            <option value="lt">Less than</option>
                            <option value="gte">Greater than or equal</option>
                            <option value="lte">Less than or equal</option>
                            <option value="eq">Equal to</option>
                            <option value="ne">Not equal to</option>
                        </select>
                    </div>
                    <div class="mb-4">
                        <label class="block text-sm font-medium text-gray-700">Threshold</label>
                        <input type="number" name="threshold" step="any" class="mt-1 block w-full rounded-md border-gray-300 shadow-sm">
                    </div>
                    <div class="mb-4">
                        <label class="block text-sm font-medium text-gray-700">Severity</label>
                        <select name="severity" class="mt-1 block w-full rounded-md border-gray-300 shadow-sm">
                            <option value="info">Info</option>
                            <option value="warning">Warning</option>
                            <option value="error">Error</option>
                            <option value="critical">Critical</option>
                        </select>
                    </div>
                    <div class="flex justify-end space-x-2">
                        <button type="button" class="px-4 py-2 text-gray-600 border rounded hover:bg-gray-50" onclick="hideAddRuleModal()">
                            Cancel
                        </button>
                        <button type="submit" class="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600">
                            Add Rule
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <script>
        // WebSocket connection
        const ws = new WebSocket(`ws://${window.location.host}/ws`);
        
        ws.onopen = function() {
            console.log('WebSocket connected');
        };
        
        ws.onmessage = function(event) {
            const message = JSON.parse(event.data);
            handleWebSocketMessage(message);
        };
        
        ws.onclose = function() {
            console.log('WebSocket disconnected');
            // Attempt to reconnect after 5 seconds
            setTimeout(() => location.reload(), 5000);
        };

        // Keep connection alive
        setInterval(() => {
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({type: 'ping'}));
            }
        }, 30000);

        // Handle WebSocket messages
        function handleWebSocketMessage(message) {
            if (message.type === 'metric_update') {
                updateMetricCard(message.data);
                updateCharts(message.data);
            } else if (message.type === 'alert_update') {
                updateAlertsDisplay();
            }
        }

        // Load initial data
        async function loadDashboardData() {
            try {
                // Load metrics
                const metricsResponse = await fetch('/api/metrics');
                const metricsData = await metricsResponse.json();
                displayMetrics(metricsData.metrics);
                
                // Load alerts
                const alertsResponse = await fetch('/api/alerts');
                const alertsData = await alertsResponse.json();
                displayAlerts(alertsData.active);
                
                // Load alert rules
                const rulesResponse = await fetch('/api/alert-rules');
                const rulesData = await rulesResponse.json();
                displayAlertRules(rulesData.rules);
                
                // Load charts
                for (const metric of metricsData.metrics) {
                    await loadChart(metric.name);
                }
                
                populateMetricSelect(metricsData.metrics);
            } catch (error) {
                console.error('Error loading dashboard data:', error);
            }
        }

        // Display metrics
        function displayMetrics(metrics) {
            const container = document.getElementById('metrics-overview');
            container.innerHTML = '';
            
            metrics.forEach(metric => {
                const card = document.createElement('div');
                card.className = 'metric-card';
                card.innerHTML = `
                    <h3 class="text-lg font-semibold text-gray-800">${metric.name}</h3>
                    <p class="text-2xl font-bold text-blue-600" id="metric-${metric.name}">
                        ${metric.latest_value !== null ? metric.latest_value : 'N/A'}
                    </p>
                    <p class="text-sm text-gray-500">${metric.unit}</p>
                    <p class="text-xs text-gray-400">${metric.description}</p>
                `;
                container.appendChild(card);
            });
        }

        // Update metric card
        function updateMetricCard(metricData) {
            const element = document.getElementById(`metric-${metricData.name}`);
            if (element) {
                element.textContent = metricData.value;
            }
        }

        // Display alerts
        function displayAlerts(alerts) {
            const container = document.getElementById('alerts-container');
            
            if (alerts.length === 0) {
                container.innerHTML = '<p class="text-gray-500">No active alerts</p>';
                return;
            }
            
            container.innerHTML = '';
            alerts.forEach(alert => {
                const card = document.createElement('div');
                card.className = `alert-card alert-${alert.severity} mb-2`;
                card.innerHTML = `
                    <div class="flex justify-between items-start">
                        <div>
                            <h4 class="font-semibold">${alert.rule_name}</h4>
                            <p class="text-sm text-gray-600">${alert.message}</p>
                            <p class="text-xs text-gray-500">${new Date(alert.created_at).toLocaleString()}</p>
                        </div>
                        <div class="flex space-x-2">
                            <button class="text-xs bg-gray-200 px-2 py-1 rounded hover:bg-gray-300"
                                    onclick="acknowledgeAlert('${alert.id}')">
                                Acknowledge
                            </button>
                            <button class="text-xs bg-red-200 px-2 py-1 rounded hover:bg-red-300"
                                    onclick="silenceAlert('${alert.id}')">
                                Silence
                            </button>
                        </div>
                    </div>
                `;
                container.appendChild(card);
            });
        }

        // Display alert rules
        function displayAlertRules(rules) {
            const container = document.getElementById('alert-rules-container');
            
            if (rules.length === 0) {
                container.innerHTML = '<p class="text-gray-500">No alert rules configured</p>';
                return;
            }
            
            container.innerHTML = '';
            const table = document.createElement('table');
            table.className = 'min-w-full divide-y divide-gray-200';
            table.innerHTML = `
                <thead class="bg-gray-50">
                    <tr>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Name</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Metric</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Condition</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Severity</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Actions</th>
                    </tr>
                </thead>
                <tbody class="bg-white divide-y divide-gray-200">
                    ${rules.map(rule => `
                        <tr>
                            <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">${rule.name}</td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${rule.metric_name}</td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${rule.condition} ${rule.threshold}</td>
                            <td class="px-6 py-4 whitespace-nowrap">
                                <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-${rule.severity === 'critical' ? 'red' : rule.severity === 'error' ? 'red' : rule.severity === 'warning' ? 'yellow' : 'blue'}-100 text-${rule.severity === 'critical' ? 'red' : rule.severity === 'error' ? 'red' : rule.severity === 'warning' ? 'yellow' : 'blue'}-800">
                                    ${rule.severity}
                                </span>
                            </td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                                <button class="text-red-600 hover:text-red-900" onclick="deleteAlertRule('${rule.id}')">Delete</button>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            `;
            container.appendChild(table);
        }

        // Load chart data
        async function loadChart(metricName) {
            try {
                const response = await fetch(`/api/charts/${metricName}?time_range=1h`);
                const chartData = await response.json();
                
                const container = document.getElementById('charts-section');
                const chartDiv = document.createElement('div');
                chartDiv.className = 'bg-white rounded-lg shadow-md p-6';
                chartDiv.innerHTML = `
                    <h3 class="text-lg font-semibold text-gray-800 mb-4">${metricName}</h3>
                    <canvas id="chart-${metricName}" width="400" height="200"></canvas>
                `;
                container.appendChild(chartDiv);
                
                const ctx = document.getElementById(`chart-${metricName}`).getContext('2d');
                new Chart(ctx, {
                    type: 'line',
                    data: chartData,
                    options: {
                        responsive: true,
                        scales: {
                            x: {
                                type: 'time',
                                time: {
                                    parser: 'YYYY-MM-DDTHH:mm:ss.sssZ'
                                }
                            }
                        }
                    }
                });
            } catch (error) {
                console.error(`Error loading chart for ${metricName}:`, error);
            }
        }

        // Alert actions
        async function acknowledgeAlert(alertId) {
            try {
                await fetch(`/api/alerts/${alertId}/acknowledge`, { method: 'POST' });
                updateAlertsDisplay();
            } catch (error) {
                console.error('Error acknowledging alert:', error);
            }
        }

        async function silenceAlert(alertId) {
            try {
                await fetch(`/api/alerts/${alertId}/silence`, { method: 'POST' });
                updateAlertsDisplay();
            } catch (error) {
                console.error('Error silencing alert:', error);
            }
        }

        async function updateAlertsDisplay() {
            try {
                const response = await fetch('/api/alerts');
                const data = await response.json();
                displayAlerts(data.active);
            } catch (error) {
                console.error('Error updating alerts:', error);
            }
        }

        // Alert rule management
        function showAddRuleModal() {
            document.getElementById('add-rule-modal').classList.remove('hidden');
        }

        function hideAddRuleModal() {
            document.getElementById('add-rule-modal').classList.add('hidden');
        }

        function populateMetricSelect(metrics) {
            const select = document.getElementById('metric-select');
            select.innerHTML = '';
            metrics.forEach(metric => {
                const option = document.createElement('option');
                option.value = metric.name;
                option.textContent = metric.name;
                select.appendChild(option);
            });
        }

        document.getElementById('add-rule-form').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const formData = new FormData(e.target);
            const ruleData = Object.fromEntries(formData);
            ruleData.threshold = parseFloat(ruleData.threshold);
            
            try {
                await fetch('/api/alert-rules', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(ruleData)
                });
                
                hideAddRuleModal();
                
                // Reload alert rules
                const response = await fetch('/api/alert-rules');
                const data = await response.json();
                displayAlertRules(data.rules);
            } catch (error) {
                console.error('Error creating alert rule:', error);
            }
        });

        async function deleteAlertRule(ruleId) {
            if (confirm('Are you sure you want to delete this alert rule?')) {
                try {
                    await fetch(`/api/alert-rules/${ruleId}`, { method: 'DELETE' });
                    
                    // Reload alert rules
                    const response = await fetch('/api/alert-rules');
                    const data = await response.json();
                    displayAlertRules(data.rules);
                } catch (error) {
                    console.error('Error deleting alert rule:', error);
                }
            }
        }

        // Initialize dashboard
        loadDashboardData();
        
        // Refresh data every 30 seconds
        setInterval(loadDashboardData, 30000);
    </script>
</body>
</html>
        """
    
    async def _on_alert_update(self, alert: Alert):
        """Handle alert updates."""
        await self.websocket_manager.send_alert_update(alert)
    
    def register_metric(self, name: str, metric_type: MetricType, description: str = "", unit: str = "") -> Metric:
        """Register a new metric."""
        if name in self.metrics:
            return self.metrics[name]
        
        metric = Metric(
            name=name,
            type=metric_type,
            description=description,
            unit=unit
        )
        
        self.metrics[name] = metric
        self.logger.info(f"Registered metric: {name}")
        
        return metric
    
    def record_metric(self, name: str, value: Union[int, float], labels: Dict[str, str] = None):
        """Record a metric value."""
        if name not in self.metrics:
            self.logger.warning(f"Metric {name} not registered, auto-registering as gauge")
            self.register_metric(name, MetricType.GAUGE)
        
        metric = self.metrics[name]
        metric.add_value(value, labels)
        
        # Evaluate alerts
        self.alert_manager.evaluate_metric(metric)
        
        # Trigger async update
        if self._background_tasks:
            task = asyncio.create_task(self.websocket_manager.send_metric_update(metric))
            self._background_tasks.add(task)
            task.add_done_callback(self._background_tasks.discard)
    
    async def start_server(self):
        """Start the dashboard server."""
        config = uvicorn.Config(
            self.app,
            host=self.config.host,
            port=self.config.port,
            ssl_keyfile=self.config.ssl_key_path if self.config.enable_ssl else None,
            ssl_certfile=self.config.ssl_cert_path if self.config.enable_ssl else None
        )
        server = uvicorn.Server(config)
        
        self.logger.info(f"Starting dashboard server on {self.config.host}:{self.config.port}")
        await server.serve()
    
    def run(self):
        """Run the dashboard server."""
        try:
            asyncio.run(self.start_server())
        except KeyboardInterrupt:
            self.logger.info("Dashboard server stopped by user")


# Convenience functions and utilities

def create_dashboard(
    title: str = "Shield Metrics Dashboard",
    port: int = 8080,
    enable_auth: bool = False,
    username: str = "admin",
    password: str = "admin"
) -> MetricsDashboard:
    """Create a metrics dashboard with basic configuration."""
    config = DashboardConfig(
        title=title,
        port=port,
        enable_auth=enable_auth,
        username=username,
        password=password
    )
    
    return MetricsDashboard(config)


def create_alert_rule(
    name: str,
    metric_name: str,
    condition: str,
    threshold: Union[int, float],
    severity: AlertSeverity = AlertSeverity.WARNING,
    duration: int = 60,
    description: str = ""
) -> AlertRule:
    """Create an alert rule."""
    return AlertRule(
        id=str(uuid.uuid4()),
        name=name,
        metric_name=metric_name,
        condition=condition,
        threshold=threshold,
        duration=duration,
        severity=severity,
        description=description
    )


class DashboardMiddleware(BaseHTTPMiddleware):
    """Middleware to automatically collect HTTP metrics."""
    
    def __init__(self, app, dashboard: MetricsDashboard):
        super().__init__(app)
        self.dashboard = dashboard
        
        # Register common HTTP metrics
        self.dashboard.register_metric("http_requests_total", MetricType.COUNTER, "Total HTTP requests")
        self.dashboard.register_metric("http_request_duration", MetricType.HISTOGRAM, "HTTP request duration", "seconds")
        self.dashboard.register_metric("http_responses_total", MetricType.COUNTER, "Total HTTP responses")
        self.dashboard.register_metric("active_connections", MetricType.GAUGE, "Active connections")
    
    async def dispatch(self, request: Request, call_next):
        """Process HTTP request and collect metrics."""
        start_time = time.time()
        
        # Record request
        self.dashboard.record_metric(
            "http_requests_total", 
            1, 
            labels={
                "method": request.method,
                "path": str(request.url.path)
            }
        )
        
        response = await call_next(request)
        
        # Record response
        duration = time.time() - start_time
        self.dashboard.record_metric(
            "http_request_duration",
            duration,
            labels={
                "method": request.method,
                "path": str(request.url.path),
                "status": str(response.status_code)
            }
        )
        
        self.dashboard.record_metric(
            "http_responses_total",
            1,
            labels={
                "method": request.method,
                "status": str(response.status_code)
            }
        )
        
        return response


# Integration helpers for shield systems

def integrate_with_shield_manager(dashboard: MetricsDashboard, shield_manager):
    """Integrate dashboard with a shield manager to collect shield metrics."""
    
    # Register shield-specific metrics
    dashboard.register_metric("shield_executions_total", MetricType.COUNTER, "Total shield executions")
    dashboard.register_metric("shield_execution_duration", MetricType.HISTOGRAM, "Shield execution duration", "seconds")
    dashboard.register_metric("shield_blocks_total", MetricType.COUNTER, "Total requests blocked by shields")
    dashboard.register_metric("shield_allows_total", MetricType.COUNTER, "Total requests allowed by shields")
    dashboard.register_metric("shield_errors_total", MetricType.COUNTER, "Total shield errors")
    
    # Add alert rules for common shield scenarios
    dashboard.alert_manager.add_rule(create_alert_rule(
        name="High Shield Error Rate",
        metric_name="shield_errors_total",
        condition="gt",
        threshold=10,
        severity=AlertSeverity.ERROR,
        description="Shield error rate is too high"
    ))
    
    dashboard.alert_manager.add_rule(create_alert_rule(
        name="High Block Rate",
        metric_name="shield_blocks_total", 
        condition="gt",
        threshold=100,
        severity=AlertSeverity.WARNING,
        description="Unusually high number of blocked requests"
    ))
    
    return dashboard