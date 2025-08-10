"""Request timeout shield for FastAPI Shield.

This module provides comprehensive request timeout functionality to prevent
resource exhaustion from slow clients and long-running requests. It includes
configurable timeouts per endpoint, graceful timeout handling, metrics collection,
and integration with async request processing.
"""

import asyncio
import time
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Union, Callable, Set, Pattern, Tuple
from dataclasses import dataclass, field
import re
import logging

from fastapi import HTTPException, Request, Response, status

from fastapi_shield.shield import Shield


class TimeoutTrigger(str, Enum):
    """Different types of timeout triggers."""
    REQUEST_DURATION = "request_duration"  # Total time from start to finish
    IDLE_TIME = "idle_time"  # Time without activity
    PROCESSING_TIME = "processing_time"  # Time spent in handler
    CONNECTION_TIME = "connection_time"  # Time connection has been open


class TimeoutAction(str, Enum):
    """Actions to take when timeout occurs."""
    TERMINATE = "terminate"  # Terminate request immediately
    WARNING = "warning"  # Log warning but continue
    GRACEFUL_STOP = "graceful_stop"  # Allow current operation to complete
    REDIRECT = "redirect"  # Redirect to a different endpoint


class TimeoutGranularity(str, Enum):
    """Different levels of timeout granularity."""
    GLOBAL = "global"  # One timeout for entire application
    SHIELD = "shield"  # Per shield instance
    ENDPOINT = "endpoint"  # Per endpoint pattern
    METHOD = "method"  # Per HTTP method
    CLIENT = "client"  # Per client IP/identifier
    USER = "user"  # Per authenticated user


@dataclass
class TimeoutMetrics:
    """Metrics collected for timeout events."""
    total_requests: int = 0
    timed_out_requests: int = 0
    average_duration: float = 0.0
    max_duration: float = 0.0
    min_duration: float = float('inf')
    timeout_by_trigger: Dict[TimeoutTrigger, int] = field(default_factory=dict)
    timeout_by_endpoint: Dict[str, int] = field(default_factory=dict)
    recent_timeouts: deque = field(default_factory=lambda: deque(maxlen=100))
    
    def record_request(self, duration: float, endpoint: str, timed_out: bool = False, trigger: Optional[TimeoutTrigger] = None):
        """Record a request completion or timeout."""
        self.total_requests += 1
        
        # Update duration statistics
        if self.min_duration == float('inf'):
            self.min_duration = duration
        else:
            self.min_duration = min(self.min_duration, duration)
        
        self.max_duration = max(self.max_duration, duration)
        
        # Update average (incremental calculation)
        self.average_duration = (
            (self.average_duration * (self.total_requests - 1) + duration) / self.total_requests
        )
        
        if timed_out:
            self.timed_out_requests += 1
            
            if trigger:
                self.timeout_by_trigger[trigger] = self.timeout_by_trigger.get(trigger, 0) + 1
            
            self.timeout_by_endpoint[endpoint] = self.timeout_by_endpoint.get(endpoint, 0) + 1
            
            self.recent_timeouts.append({
                'timestamp': datetime.now(timezone.utc),
                'duration': duration,
                'endpoint': endpoint,
                'trigger': trigger.value if trigger else None
            })
    
    def get_timeout_rate(self) -> float:
        """Get the timeout rate as a percentage."""
        if self.total_requests == 0:
            return 0.0
        return (self.timed_out_requests / self.total_requests) * 100
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary."""
        return {
            'total_requests': self.total_requests,
            'timed_out_requests': self.timed_out_requests,
            'timeout_rate_percent': self.get_timeout_rate(),
            'average_duration': self.average_duration,
            'max_duration': self.max_duration,
            'min_duration': self.min_duration if self.min_duration != float('inf') else 0.0,
            'timeout_by_trigger': dict(self.timeout_by_trigger),
            'timeout_by_endpoint': dict(self.timeout_by_endpoint),
            'recent_timeouts_count': len(self.recent_timeouts)
        }


@dataclass
class TimeoutConfiguration:
    """Configuration for a specific timeout rule."""
    timeout_seconds: float
    trigger: TimeoutTrigger = TimeoutTrigger.REQUEST_DURATION
    action: TimeoutAction = TimeoutAction.TERMINATE
    endpoint_pattern: Optional[str] = None
    http_methods: Optional[List[str]] = None
    client_patterns: Optional[List[str]] = None
    priority: int = 0  # Higher priority rules are applied first
    warning_threshold: Optional[float] = None  # Warn if request approaches timeout
    custom_message: Optional[str] = None
    redirect_url: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def matches_request(self, request: Request, endpoint: str, method: str, client_id: str) -> bool:
        """Check if this configuration matches the given request."""
        # Check endpoint pattern
        if self.endpoint_pattern:
            try:
                if not re.match(self.endpoint_pattern, endpoint):
                    return False
            except re.error:
                # Invalid regex pattern, don't match
                return False
        
        # Check HTTP methods
        if self.http_methods:
            if method.upper() not in [m.upper() for m in self.http_methods]:
                return False
        
        # Check client patterns
        if self.client_patterns:
            client_match = False
            for pattern in self.client_patterns:
                try:
                    if re.match(pattern, client_id):
                        client_match = True
                        break
                except re.error:
                    # Invalid regex pattern, skip
                    continue
            if not client_match:
                return False
        
        return True


@dataclass
class ActiveRequest:
    """Information about an active request being monitored for timeout."""
    request_id: str
    request: Request
    endpoint: str
    method: str
    client_id: str
    start_time: float
    last_activity_time: float
    timeout_config: TimeoutConfiguration
    task: Optional[asyncio.Task] = None
    processing_start_time: Optional[float] = None
    warning_sent: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def get_duration(self) -> float:
        """Get current request duration."""
        return time.time() - self.start_time
    
    def get_idle_time(self) -> float:
        """Get time since last activity."""
        return time.time() - self.last_activity_time
    
    def get_processing_time(self) -> float:
        """Get time spent in processing."""
        if self.processing_start_time is None:
            return 0.0
        return time.time() - self.processing_start_time
    
    def update_activity(self):
        """Update the last activity timestamp."""
        self.last_activity_time = time.time()
    
    def start_processing(self):
        """Mark the start of request processing."""
        self.processing_start_time = time.time()
        self.update_activity()
    
    def should_timeout(self) -> Tuple[bool, TimeoutTrigger]:
        """Check if this request should timeout based on its configuration."""
        if self.timeout_config.trigger == TimeoutTrigger.REQUEST_DURATION:
            if self.get_duration() > self.timeout_config.timeout_seconds:
                return True, TimeoutTrigger.REQUEST_DURATION
        
        elif self.timeout_config.trigger == TimeoutTrigger.IDLE_TIME:
            if self.get_idle_time() > self.timeout_config.timeout_seconds:
                return True, TimeoutTrigger.IDLE_TIME
        
        elif self.timeout_config.trigger == TimeoutTrigger.PROCESSING_TIME:
            if self.get_processing_time() > self.timeout_config.timeout_seconds:
                return True, TimeoutTrigger.PROCESSING_TIME
        
        return False, None
    
    def should_warn(self) -> bool:
        """Check if a warning should be sent for approaching timeout."""
        if self.warning_sent or not self.timeout_config.warning_threshold:
            return False
        
        if self.timeout_config.trigger == TimeoutTrigger.REQUEST_DURATION:
            return self.get_duration() > self.timeout_config.warning_threshold
        elif self.timeout_config.trigger == TimeoutTrigger.IDLE_TIME:
            return self.get_idle_time() > self.timeout_config.warning_threshold
        elif self.timeout_config.trigger == TimeoutTrigger.PROCESSING_TIME:
            return self.get_processing_time() > self.timeout_config.warning_threshold
        
        return False


class TimeoutNotifier(ABC):
    """Abstract base class for timeout notification handlers."""
    
    @abstractmethod
    async def notify_timeout(self, active_request: ActiveRequest, trigger: TimeoutTrigger) -> None:
        """Handle timeout notification."""
        pass
    
    @abstractmethod
    async def notify_warning(self, active_request: ActiveRequest) -> None:
        """Handle timeout warning notification."""
        pass


class LoggingTimeoutNotifier(TimeoutNotifier):
    """Timeout notifier that logs events."""
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
    
    async def notify_timeout(self, active_request: ActiveRequest, trigger: TimeoutTrigger) -> None:
        """Log timeout event."""
        self.logger.warning(
            f"Request timeout: {active_request.endpoint} "
            f"({active_request.method}) from {active_request.client_id} "
            f"after {active_request.get_duration():.2f}s "
            f"(trigger: {trigger.value})"
        )
    
    async def notify_warning(self, active_request: ActiveRequest) -> None:
        """Log timeout warning."""
        self.logger.info(
            f"Request approaching timeout: {active_request.endpoint} "
            f"({active_request.method}) from {active_request.client_id} "
            f"duration: {active_request.get_duration():.2f}s"
        )


class MetricsTimeoutNotifier(TimeoutNotifier):
    """Timeout notifier that collects metrics."""
    
    def __init__(self, metrics_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None):
        self.metrics_callback = metrics_callback
    
    async def notify_timeout(self, active_request: ActiveRequest, trigger: TimeoutTrigger) -> None:
        """Send timeout metrics."""
        if self.metrics_callback:
            metrics_data = {
                'event': 'timeout',
                'endpoint': active_request.endpoint,
                'method': active_request.method,
                'client_id': active_request.client_id,
                'duration': active_request.get_duration(),
                'trigger': trigger.value,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            self.metrics_callback('request_timeout', metrics_data)
    
    async def notify_warning(self, active_request: ActiveRequest) -> None:
        """Send warning metrics."""
        if self.metrics_callback:
            metrics_data = {
                'event': 'timeout_warning',
                'endpoint': active_request.endpoint,
                'method': active_request.method,
                'client_id': active_request.client_id,
                'duration': active_request.get_duration(),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            self.metrics_callback('request_timeout_warning', metrics_data)


class WebhookTimeoutNotifier(TimeoutNotifier):
    """Timeout notifier that sends webhooks."""
    
    def __init__(self, webhook_url: str, timeout: int = 5):
        self.webhook_url = webhook_url
        self.timeout = timeout
        try:
            import httpx
            self._client = httpx.AsyncClient(timeout=timeout)
        except ImportError:
            self._client = None
    
    async def notify_timeout(self, active_request: ActiveRequest, trigger: TimeoutTrigger) -> None:
        """Send timeout webhook."""
        if not self._client:
            return
        
        payload = {
            'event': 'timeout',
            'endpoint': active_request.endpoint,
            'method': active_request.method,
            'client_id': active_request.client_id,
            'duration': active_request.get_duration(),
            'trigger': trigger.value,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        try:
            await self._client.post(self.webhook_url, json=payload)
        except Exception:
            # Webhook failures should not break the timeout handling
            pass
    
    async def notify_warning(self, active_request: ActiveRequest) -> None:
        """Send warning webhook."""
        if not self._client:
            return
        
        payload = {
            'event': 'timeout_warning',
            'endpoint': active_request.endpoint,
            'method': active_request.method,
            'client_id': active_request.client_id,
            'duration': active_request.get_duration(),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        try:
            await self._client.post(self.webhook_url, json=payload)
        except Exception:
            # Webhook failures should not break the timeout handling
            pass


class TimeoutException(Exception):
    """Exception raised when a request times out."""
    
    def __init__(self, message: str, trigger: TimeoutTrigger, duration: float, endpoint: str):
        self.trigger = trigger
        self.duration = duration
        self.endpoint = endpoint
        super().__init__(message)


@dataclass
class RequestTimeoutConfig:
    """Configuration for request timeout shield."""
    
    default_timeout_seconds: float = 30.0
    check_interval_seconds: float = 1.0
    enable_metrics: bool = True
    enable_warnings: bool = True
    granularity: TimeoutGranularity = TimeoutGranularity.ENDPOINT
    timeout_configurations: List[TimeoutConfiguration] = field(default_factory=list)
    notifiers: List[TimeoutNotifier] = field(default_factory=list)
    max_concurrent_requests: Optional[int] = None
    client_id_extractor: Optional[Callable[[Request], str]] = None
    endpoint_extractor: Optional[Callable[[Request], str]] = None
    custom_error_response: Optional[Dict[str, Any]] = None
    graceful_shutdown_timeout: float = 5.0
    enable_request_tracking: bool = True
    request_id_header: str = "X-Request-ID"
    
    def __post_init__(self):
        if not self.notifiers:
            # Add default logging notifier
            self.notifiers = [LoggingTimeoutNotifier()]


class RequestTimeoutShield(Shield):
    """Request timeout shield for preventing resource exhaustion from long-running requests."""
    
    def __init__(self, config: RequestTimeoutConfig):
        self.config = config
        self.active_requests: Dict[str, ActiveRequest] = {}
        self.metrics = TimeoutMetrics()
        self._monitor_task: Optional[asyncio.Task] = None
        self._shutdown_event: Optional[asyncio.Event] = None
        self._lock: Optional[asyncio.Lock] = None
        self._initialized = False
        
        # Sort timeout configurations by priority (higher first)
        self.config.timeout_configurations.sort(key=lambda x: x.priority, reverse=True)
        
        super().__init__(self._shield_function)
    
    def _ensure_initialized(self):
        """Ensure async components are initialized."""
        if not self._initialized:
            self._shutdown_event = asyncio.Event()
            self._lock = asyncio.Lock()
            self._initialized = True
            self._start_monitor()
    
    def _start_monitor(self):
        """Start the timeout monitoring task."""
        if self._monitor_task is None or self._monitor_task.done():
            try:
                self._monitor_task = asyncio.create_task(self._timeout_monitor())
            except RuntimeError:
                # No event loop running, monitor will start when needed
                self._monitor_task = None
    
    async def _timeout_monitor(self):
        """Monitor active requests for timeouts."""
        while not self._shutdown_event.is_set():
            try:
                await self._check_timeouts()
                await asyncio.sleep(self.config.check_interval_seconds)
            except asyncio.CancelledError:
                break
            except Exception as e:
                # Log error but continue monitoring
                logging.getLogger(__name__).error(f"Error in timeout monitor: {e}")
                await asyncio.sleep(self.config.check_interval_seconds)
    
    async def _check_timeouts(self):
        """Check all active requests for timeouts and warnings."""
        if not self._initialized:
            return
        
        async with self._lock:
            timed_out_requests = []
            warning_requests = []
            
            for request_id, active_request in self.active_requests.items():
                # Check for timeout
                should_timeout, trigger = active_request.should_timeout()
                if should_timeout:
                    timed_out_requests.append((request_id, active_request, trigger))
                elif active_request.should_warn():
                    warning_requests.append(active_request)
            
            # Handle timeouts
            for request_id, active_request, trigger in timed_out_requests:
                await self._handle_timeout(request_id, active_request, trigger)
            
            # Handle warnings
            for active_request in warning_requests:
                await self._handle_warning(active_request)
    
    async def _handle_timeout(self, request_id: str, active_request: ActiveRequest, trigger: TimeoutTrigger):
        """Handle a request timeout."""
        # Record metrics
        self.metrics.record_request(
            duration=active_request.get_duration(),
            endpoint=active_request.endpoint,
            timed_out=True,
            trigger=trigger
        )
        
        # Notify handlers
        for notifier in self.config.notifiers:
            try:
                await notifier.notify_timeout(active_request, trigger)
            except Exception as e:
                logging.getLogger(__name__).error(f"Error in timeout notifier: {e}")
        
        # Take action based on configuration
        if active_request.timeout_config.action == TimeoutAction.TERMINATE:
            await self._terminate_request(active_request, trigger)
        elif active_request.timeout_config.action == TimeoutAction.GRACEFUL_STOP:
            await self._graceful_stop_request(active_request, trigger)
        
        # Remove from active requests
        self.active_requests.pop(request_id, None)
    
    async def _handle_warning(self, active_request: ActiveRequest):
        """Handle a timeout warning."""
        active_request.warning_sent = True
        
        for notifier in self.config.notifiers:
            try:
                await notifier.notify_warning(active_request)
            except Exception as e:
                logging.getLogger(__name__).error(f"Error in warning notifier: {e}")
    
    async def _terminate_request(self, active_request: ActiveRequest, trigger: TimeoutTrigger):
        """Terminate a request due to timeout."""
        if active_request.task and not active_request.task.done():
            active_request.task.cancel()
        
        # The actual HTTP response will be handled by the shield function
        # when it detects the request is no longer in active_requests
    
    async def _graceful_stop_request(self, active_request: ActiveRequest, trigger: TimeoutTrigger):
        """Gracefully stop a request due to timeout."""
        if active_request.task and not active_request.task.done():
            # Allow some time for graceful shutdown
            try:
                await asyncio.wait_for(
                    asyncio.shield(active_request.task),
                    timeout=self.config.graceful_shutdown_timeout
                )
            except asyncio.TimeoutError:
                # If graceful shutdown takes too long, force cancel
                active_request.task.cancel()
    
    def _get_client_id(self, request: Request) -> str:
        """Extract client identifier from request."""
        if self.config.client_id_extractor:
            return self.config.client_id_extractor(request)
        
        # Default client ID extraction
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        client_host = getattr(request.client, "host", "unknown") if request.client else "unknown"
        return client_host
    
    def _get_endpoint(self, request: Request) -> str:
        """Extract endpoint identifier from request."""
        if self.config.endpoint_extractor:
            return self.config.endpoint_extractor(request)
        
        # Default endpoint extraction
        return request.url.path
    
    def _get_request_id(self, request: Request) -> str:
        """Extract or generate request ID."""
        request_id = None
        if hasattr(request, 'headers') and request.headers is not None:
            request_id = request.headers.get(self.config.request_id_header)
        
        if request_id:
            return request_id
        
        # Generate request ID if not present
        import uuid
        return str(uuid.uuid4())
    
    def _find_timeout_config(self, request: Request, endpoint: str, method: str, client_id: str) -> TimeoutConfiguration:
        """Find the appropriate timeout configuration for a request."""
        # Check configurations in priority order
        for config in self.config.timeout_configurations:
            if config.matches_request(request, endpoint, method, client_id):
                return config
        
        # Return default configuration
        return TimeoutConfiguration(
            timeout_seconds=self.config.default_timeout_seconds,
            trigger=TimeoutTrigger.REQUEST_DURATION,
            action=TimeoutAction.TERMINATE
        )
    
    async def _shield_function(self, request: Request) -> Optional[Dict[str, Any]]:
        """Main shield function for request timeout monitoring."""
        if not self.config.enable_request_tracking:
            return None
        
        # Ensure shield is initialized
        self._ensure_initialized()
        
        # Check concurrent request limit
        if self.config.max_concurrent_requests:
            if len(self.active_requests) >= self.config.max_concurrent_requests:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail={
                        "error": "too_many_requests",
                        "message": "Maximum concurrent requests exceeded",
                        "retry_after": self.config.check_interval_seconds
                    }
                )
        
        # Extract request information
        request_id = self._get_request_id(request)
        endpoint = self._get_endpoint(request)
        method = request.method
        client_id = self._get_client_id(request)
        
        # Check if this request is already timed out
        async with self._lock:
            if request_id in self.active_requests:
                # Request was already timed out and removed
                error_message = "Request timed out"
                
                # Find the configuration to get custom message
                timeout_config = self._find_timeout_config(request, endpoint, method, client_id)
                if timeout_config.custom_message:
                    error_message = timeout_config.custom_message
                
                if timeout_config.action == TimeoutAction.REDIRECT and timeout_config.redirect_url:
                    raise HTTPException(
                        status_code=status.HTTP_302_FOUND,
                        detail={"Location": timeout_config.redirect_url}
                    )
                
                # Use custom error response if configured
                error_detail = self.config.custom_error_response or {
                    "error": "request_timeout",
                    "message": error_message,
                    "endpoint": endpoint,
                    "request_id": request_id
                }
                
                raise HTTPException(
                    status_code=status.HTTP_408_REQUEST_TIMEOUT,
                    detail=error_detail
                )
        
        # Find timeout configuration
        timeout_config = self._find_timeout_config(request, endpoint, method, client_id)
        
        # Create active request tracking
        start_time = time.time()
        active_request = ActiveRequest(
            request_id=request_id,
            request=request,
            endpoint=endpoint,
            method=method,
            client_id=client_id,
            start_time=start_time,
            last_activity_time=start_time,
            timeout_config=timeout_config
        )
        
        # Add to active requests
        async with self._lock:
            self.active_requests[request_id] = active_request
        
        try:
            # Mark processing start
            active_request.start_processing()
            
            # Return request tracking information
            return {
                "request_timeout": {
                    "request_id": request_id,
                    "timeout_seconds": timeout_config.timeout_seconds,
                    "trigger": timeout_config.trigger.value,
                    "endpoint": endpoint,
                    "start_time": start_time,
                    "client_id": client_id
                }
            }
        
        finally:
            # Clean up will be handled by the monitor task or response processing
            pass
    
    async def complete_request(self, request_id: str) -> None:
        """Mark a request as completed."""
        if not self._initialized:
            return
        
        async with self._lock:
            if request_id in self.active_requests:
                active_request = self.active_requests.pop(request_id)
                
                # Record successful completion
                self.metrics.record_request(
                    duration=active_request.get_duration(),
                    endpoint=active_request.endpoint,
                    timed_out=False
                )
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get current timeout metrics."""
        base_metrics = self.metrics.to_dict()
        
        # Add current state information
        base_metrics.update({
            'active_requests': len(self.active_requests),
            'max_concurrent_requests': self.config.max_concurrent_requests,
            'monitor_running': self._monitor_task is not None and not self._monitor_task.done(),
            'configurations_count': len(self.config.timeout_configurations),
            'initialized': self._initialized
        })
        
        return base_metrics
    
    def get_active_requests(self) -> Dict[str, Dict[str, Any]]:
        """Get information about currently active requests."""
        active_info = {}
        
        for request_id, active_request in self.active_requests.items():
            active_info[request_id] = {
                'endpoint': active_request.endpoint,
                'method': active_request.method,
                'client_id': active_request.client_id,
                'duration': active_request.get_duration(),
                'idle_time': active_request.get_idle_time(),
                'processing_time': active_request.get_processing_time(),
                'timeout_seconds': active_request.timeout_config.timeout_seconds,
                'trigger': active_request.timeout_config.trigger.value,
                'warning_sent': active_request.warning_sent
            }
        
        return active_info
    
    async def shutdown(self):
        """Gracefully shutdown the timeout shield."""
        if not self._initialized:
            return
        
        self._shutdown_event.set()
        
        if self._monitor_task and not self._monitor_task.done():
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        
        # Cancel all active requests
        async with self._lock:
            for active_request in self.active_requests.values():
                if active_request.task and not active_request.task.done():
                    active_request.task.cancel()
            
            self.active_requests.clear()


# Convenience functions for creating timeout shields

def request_timeout_shield(
    timeout_seconds: float = 30.0,
    check_interval: float = 1.0,
    enable_metrics: bool = True,
    enable_warnings: bool = True
) -> RequestTimeoutShield:
    """Create a basic request timeout shield.
    
    Args:
        timeout_seconds: Default timeout for all requests
        check_interval: How often to check for timeouts (seconds)
        enable_metrics: Whether to collect timeout metrics
        enable_warnings: Whether to send warnings for approaching timeouts
    
    Returns:
        RequestTimeoutShield instance
    """
    config = RequestTimeoutConfig(
        default_timeout_seconds=timeout_seconds,
        check_interval_seconds=check_interval,
        enable_metrics=enable_metrics,
        enable_warnings=enable_warnings
    )
    
    return RequestTimeoutShield(config)


def endpoint_timeout_shield(
    endpoint_timeouts: Dict[str, float],
    default_timeout: float = 30.0,
    check_interval: float = 1.0
) -> RequestTimeoutShield:
    """Create a timeout shield with per-endpoint timeouts.
    
    Args:
        endpoint_timeouts: Mapping of endpoint patterns to timeout values
        default_timeout: Default timeout for endpoints not specified
        check_interval: How often to check for timeouts (seconds)
    
    Returns:
        RequestTimeoutShield instance
    """
    timeout_configs = []
    
    for pattern, timeout in endpoint_timeouts.items():
        timeout_configs.append(
            TimeoutConfiguration(
                timeout_seconds=timeout,
                endpoint_pattern=pattern,
                priority=1
            )
        )
    
    config = RequestTimeoutConfig(
        default_timeout_seconds=default_timeout,
        check_interval_seconds=check_interval,
        timeout_configurations=timeout_configs
    )
    
    return RequestTimeoutShield(config)


def method_timeout_shield(
    method_timeouts: Dict[str, float],
    default_timeout: float = 30.0
) -> RequestTimeoutShield:
    """Create a timeout shield with per-HTTP-method timeouts.
    
    Args:
        method_timeouts: Mapping of HTTP methods to timeout values
        default_timeout: Default timeout for methods not specified
    
    Returns:
        RequestTimeoutShield instance
    """
    timeout_configs = []
    
    for method, timeout in method_timeouts.items():
        timeout_configs.append(
            TimeoutConfiguration(
                timeout_seconds=timeout,
                http_methods=[method],
                priority=1
            )
        )
    
    config = RequestTimeoutConfig(
        default_timeout_seconds=default_timeout,
        timeout_configurations=timeout_configs
    )
    
    return RequestTimeoutShield(config)


def idle_timeout_shield(
    idle_timeout_seconds: float = 10.0,
    check_interval: float = 0.5
) -> RequestTimeoutShield:
    """Create a timeout shield that monitors idle time.
    
    Args:
        idle_timeout_seconds: Timeout for idle connections
        check_interval: How often to check for idle timeouts
    
    Returns:
        RequestTimeoutShield instance
    """
    config = RequestTimeoutConfig(
        default_timeout_seconds=idle_timeout_seconds,
        check_interval_seconds=check_interval,
        timeout_configurations=[
            TimeoutConfiguration(
                timeout_seconds=idle_timeout_seconds,
                trigger=TimeoutTrigger.IDLE_TIME,
                priority=1
            )
        ]
    )
    
    return RequestTimeoutShield(config)


def processing_timeout_shield(
    processing_timeout_seconds: float = 15.0,
    warning_threshold_seconds: Optional[float] = None
) -> RequestTimeoutShield:
    """Create a timeout shield that monitors processing time.
    
    Args:
        processing_timeout_seconds: Timeout for request processing
        warning_threshold_seconds: Send warning at this threshold
    
    Returns:
        RequestTimeoutShield instance
    """
    warning_threshold = warning_threshold_seconds or (processing_timeout_seconds * 0.8)
    
    config = RequestTimeoutConfig(
        default_timeout_seconds=processing_timeout_seconds,
        timeout_configurations=[
            TimeoutConfiguration(
                timeout_seconds=processing_timeout_seconds,
                trigger=TimeoutTrigger.PROCESSING_TIME,
                warning_threshold=warning_threshold,
                priority=1
            )
        ]
    )
    
    return RequestTimeoutShield(config)


def graceful_timeout_shield(
    timeout_seconds: float = 30.0,
    graceful_shutdown_timeout: float = 5.0,
    custom_message: Optional[str] = None
) -> RequestTimeoutShield:
    """Create a timeout shield with graceful termination.
    
    Args:
        timeout_seconds: Request timeout
        graceful_shutdown_timeout: Time to allow for graceful shutdown
        custom_message: Custom timeout message
    
    Returns:
        RequestTimeoutShield instance
    """
    config = RequestTimeoutConfig(
        default_timeout_seconds=timeout_seconds,
        graceful_shutdown_timeout=graceful_shutdown_timeout,
        timeout_configurations=[
            TimeoutConfiguration(
                timeout_seconds=timeout_seconds,
                action=TimeoutAction.GRACEFUL_STOP,
                custom_message=custom_message,
                priority=1
            )
        ]
    )
    
    return RequestTimeoutShield(config)


def comprehensive_timeout_shield(
    default_timeout: float = 30.0,
    endpoint_timeouts: Optional[Dict[str, float]] = None,
    method_timeouts: Optional[Dict[str, float]] = None,
    idle_timeout: Optional[float] = None,
    processing_timeout: Optional[float] = None,
    max_concurrent_requests: Optional[int] = None,
    webhook_url: Optional[str] = None,
    custom_notifiers: Optional[List[TimeoutNotifier]] = None
) -> RequestTimeoutShield:
    """Create a comprehensive timeout shield with multiple timeout types.
    
    Args:
        default_timeout: Default timeout for requests
        endpoint_timeouts: Per-endpoint timeout overrides
        method_timeouts: Per-HTTP-method timeout overrides  
        idle_timeout: Idle connection timeout
        processing_timeout: Request processing timeout
        max_concurrent_requests: Maximum concurrent requests
        webhook_url: Webhook URL for timeout notifications
        custom_notifiers: Additional notification handlers
    
    Returns:
        RequestTimeoutShield instance
    """
    timeout_configs = []
    notifiers = [LoggingTimeoutNotifier()]
    
    # Add endpoint-specific timeouts
    if endpoint_timeouts:
        for pattern, timeout in endpoint_timeouts.items():
            timeout_configs.append(
                TimeoutConfiguration(
                    timeout_seconds=timeout,
                    endpoint_pattern=pattern,
                    priority=3
                )
            )
    
    # Add method-specific timeouts
    if method_timeouts:
        for method, timeout in method_timeouts.items():
            timeout_configs.append(
                TimeoutConfiguration(
                    timeout_seconds=timeout,
                    http_methods=[method],
                    priority=2
                )
            )
    
    # Add idle timeout
    if idle_timeout:
        timeout_configs.append(
            TimeoutConfiguration(
                timeout_seconds=idle_timeout,
                trigger=TimeoutTrigger.IDLE_TIME,
                priority=1
            )
        )
    
    # Add processing timeout
    if processing_timeout:
        timeout_configs.append(
            TimeoutConfiguration(
                timeout_seconds=processing_timeout,
                trigger=TimeoutTrigger.PROCESSING_TIME,
                warning_threshold=processing_timeout * 0.8,
                priority=1
            )
        )
    
    # Add webhook notifier
    if webhook_url:
        notifiers.append(WebhookTimeoutNotifier(webhook_url))
    
    # Add custom notifiers
    if custom_notifiers:
        notifiers.extend(custom_notifiers)
    
    config = RequestTimeoutConfig(
        default_timeout_seconds=default_timeout,
        timeout_configurations=timeout_configs,
        notifiers=notifiers,
        max_concurrent_requests=max_concurrent_requests
    )
    
    return RequestTimeoutShield(config)