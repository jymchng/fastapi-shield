"""Request Tracing Shield for FastAPI Shield.

This module provides comprehensive distributed tracing support with OpenTelemetry
integration, support for multiple tracing backends, custom span creation, and
performance monitoring for FastAPI endpoints.
"""

import json
import time
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union, Callable
import contextlib

from fastapi import HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from fastapi_shield.shield import Shield, shield

# Optional OpenTelemetry imports - gracefully handle if not installed
try:
    from opentelemetry import trace
    from opentelemetry.trace import Status, StatusCode, Span
    from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
    from opentelemetry.baggage.propagation import W3CBaggagePropagator
    from opentelemetry.propagate import extract, inject
    from opentelemetry.context import get_current, attach, detach
    from opentelemetry.util.http import get_excluded_urls
    OPENTELEMETRY_AVAILABLE = True
except ImportError:
    OPENTELEMETRY_AVAILABLE = False
    # Create mock classes for type hints
    class Span:
        pass
    class Status:
        pass
    class StatusCode:
        OK = "OK"
        ERROR = "ERROR"


class TracingBackend(str, Enum):
    """Supported tracing backends."""
    OPENTELEMETRY = "opentelemetry"
    JAEGER = "jaeger"
    ZIPKIN = "zipkin"
    DATADOG = "datadog"
    CUSTOM = "custom"


class SpanKind(str, Enum):
    """Span kinds for different operation types."""
    INTERNAL = "internal"
    SERVER = "server"
    CLIENT = "client"
    PRODUCER = "producer"
    CONSUMER = "consumer"


class TracingLevel(str, Enum):
    """Tracing levels for granular control."""
    OFF = "off"
    ERROR_ONLY = "error_only"
    BASIC = "basic"
    DETAILED = "detailed"
    VERBOSE = "verbose"


class SpanAttribute(BaseModel):
    """Span attribute model."""
    key: str = Field(description="Attribute key")
    value: Union[str, int, float, bool] = Field(description="Attribute value")


class SpanEvent(BaseModel):
    """Span event model."""
    name: str = Field(description="Event name")
    timestamp: Optional[datetime] = Field(default=None, description="Event timestamp")
    attributes: Dict[str, Union[str, int, float, bool]] = Field(default_factory=dict, description="Event attributes")


class TraceContext(BaseModel):
    """Trace context information."""
    trace_id: str = Field(description="Trace ID")
    span_id: str = Field(description="Span ID")
    parent_span_id: Optional[str] = Field(default=None, description="Parent span ID")
    trace_flags: int = Field(default=1, description="Trace flags")
    baggage: Dict[str, str] = Field(default_factory=dict, description="Baggage items")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class RequestTracingConfig(BaseModel):
    """Request tracing configuration."""
    backend: TracingBackend = Field(default=TracingBackend.OPENTELEMETRY, description="Tracing backend")
    service_name: str = Field(default="fastapi-shield", description="Service name for tracing")
    tracing_level: TracingLevel = Field(default=TracingLevel.BASIC, description="Tracing level")
    
    # Span configuration
    create_root_span: bool = Field(default=True, description="Create root span for requests")
    include_request_body: bool = Field(default=False, description="Include request body in spans")
    include_response_body: bool = Field(default=False, description="Include response body in spans")
    include_headers: bool = Field(default=True, description="Include headers in spans")
    include_query_params: bool = Field(default=True, description="Include query parameters in spans")
    
    # Performance monitoring
    record_performance_metrics: bool = Field(default=True, description="Record performance metrics")
    slow_request_threshold_ms: float = Field(default=1000.0, description="Slow request threshold in milliseconds")
    
    # Sampling configuration
    sampling_rate: float = Field(default=1.0, description="Sampling rate (0.0 to 1.0)")
    
    # Custom attributes
    custom_attributes: Dict[str, str] = Field(default_factory=dict, description="Custom span attributes")
    excluded_paths: List[str] = Field(default_factory=list, description="Paths to exclude from tracing")
    
    # Backend-specific configurations
    jaeger_config: Dict[str, Any] = Field(default_factory=dict, description="Jaeger-specific configuration")
    zipkin_config: Dict[str, Any] = Field(default_factory=dict, description="Zipkin-specific configuration")
    datadog_config: Dict[str, Any] = Field(default_factory=dict, description="DataDog-specific configuration")


class TracingMetrics(BaseModel):
    """Tracing metrics collection."""
    total_requests: int = Field(default=0, description="Total traced requests")
    slow_requests: int = Field(default=0, description="Number of slow requests")
    error_requests: int = Field(default=0, description="Number of error requests")
    average_duration_ms: float = Field(default=0.0, description="Average request duration")
    total_spans_created: int = Field(default=0, description="Total spans created")
    last_updated: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class TracerProvider(ABC):
    """Abstract base class for tracing providers."""
    
    @abstractmethod
    def create_span(self, name: str, kind: SpanKind = SpanKind.INTERNAL, 
                   parent_context: Optional[Any] = None) -> Any:
        """Create a new span."""
        pass
    
    @abstractmethod
    def set_span_attributes(self, span: Any, attributes: Dict[str, Any]):
        """Set attributes on a span."""
        pass
    
    @abstractmethod
    def add_span_event(self, span: Any, event: SpanEvent):
        """Add an event to a span."""
        pass
    
    @abstractmethod
    def set_span_status(self, span: Any, status_code: str, description: Optional[str] = None):
        """Set span status."""
        pass
    
    @abstractmethod
    def finish_span(self, span: Any):
        """Finish a span."""
        pass
    
    @abstractmethod
    def extract_context(self, headers: Dict[str, str]) -> Optional[Any]:
        """Extract trace context from headers."""
        pass
    
    @abstractmethod
    def inject_context(self, context: Any, headers: Dict[str, str]):
        """Inject trace context into headers."""
        pass


class OpenTelemetryProvider(TracerProvider):
    """OpenTelemetry tracing provider."""
    
    def __init__(self, service_name: str = "fastapi-shield"):
        if not OPENTELEMETRY_AVAILABLE:
            raise ImportError("OpenTelemetry is not available. Install with: pip install opentelemetry-api opentelemetry-sdk")
        
        self.tracer = trace.get_tracer(service_name)
        self.propagator = TraceContextTextMapPropagator()
    
    def create_span(self, name: str, kind: SpanKind = SpanKind.INTERNAL, 
                   parent_context: Optional[Any] = None) -> Span:
        """Create a new span."""
        trace_kind = trace.SpanKind.INTERNAL
        if kind == SpanKind.SERVER:
            trace_kind = trace.SpanKind.SERVER
        elif kind == SpanKind.CLIENT:
            trace_kind = trace.SpanKind.CLIENT
        elif kind == SpanKind.PRODUCER:
            trace_kind = trace.SpanKind.PRODUCER
        elif kind == SpanKind.CONSUMER:
            trace_kind = trace.SpanKind.CONSUMER
        
        if parent_context:
            return self.tracer.start_span(name, kind=trace_kind, context=parent_context)
        else:
            return self.tracer.start_span(name, kind=trace_kind)
    
    def set_span_attributes(self, span: Span, attributes: Dict[str, Any]):
        """Set attributes on a span."""
        for key, value in attributes.items():
            span.set_attribute(key, value)
    
    def add_span_event(self, span: Span, event: SpanEvent):
        """Add an event to a span."""
        timestamp_ns = None
        if event.timestamp:
            timestamp_ns = int(event.timestamp.timestamp() * 1_000_000_000)
        
        span.add_event(event.name, event.attributes, timestamp_ns)
    
    def set_span_status(self, span: Span, status_code: str, description: Optional[str] = None):
        """Set span status."""
        otel_status = Status(StatusCode.OK if status_code == "OK" else StatusCode.ERROR, description)
        span.set_status(otel_status)
    
    def finish_span(self, span: Span):
        """Finish a span."""
        span.end()
    
    def extract_context(self, headers: Dict[str, str]) -> Optional[Any]:
        """Extract trace context from headers."""
        return self.propagator.extract(headers)
    
    def inject_context(self, context: Any, headers: Dict[str, str]):
        """Inject trace context into headers."""
        self.propagator.inject(headers, context=context)


class RequestTracer:
    """Main request tracer that manages tracing lifecycle."""
    
    def __init__(self, config: RequestTracingConfig):
        self.config = config
        self.metrics = TracingMetrics()
        
        # Initialize tracer provider based on backend
        if config.backend == TracingBackend.OPENTELEMETRY and OPENTELEMETRY_AVAILABLE:
            self.provider = OpenTelemetryProvider(config.service_name)
        else:
            raise ValueError(f"Tracing backend {config.backend} is not supported")
    
    def should_trace_request(self, request: Request) -> bool:
        """Determine if request should be traced."""
        if self.config.tracing_level == TracingLevel.OFF:
            return False
        
        # Check excluded paths
        path = request.url.path
        for excluded_path in self.config.excluded_paths:
            if path.startswith(excluded_path):
                return False
        
        # Apply sampling
        import random
        return random.random() <= self.config.sampling_rate
    
    def create_request_span(self, request: Request, shield_name: str = "request") -> Any:
        """Create a span for the request."""
        # Extract parent context from headers
        parent_context = self.provider.extract_context(dict(request.headers))
        
        # Create span name
        span_name = f"{request.method} {request.url.path}"
        if shield_name != "request":
            span_name = f"{shield_name}: {span_name}"
        
        # Create the span
        span = self.provider.create_span(span_name, SpanKind.SERVER, parent_context)
        
        # Add basic attributes
        attributes = {
            "http.method": request.method,
            "http.url": str(request.url),
            "http.scheme": request.url.scheme,
            "http.host": request.url.hostname or "",
            "http.route": request.url.path,
            "user_agent.original": request.headers.get("user-agent", ""),
            "service.name": self.config.service_name,
            "shield.name": shield_name
        }
        
        # Add query parameters if enabled
        if self.config.include_query_params and request.query_params:
            for key, value in request.query_params.items():
                attributes[f"http.query.{key}"] = value
        
        # Add headers if enabled (excluding sensitive ones)
        if self.config.include_headers:
            sensitive_headers = {"authorization", "cookie", "x-api-key", "x-auth-token"}
            for header_name, header_value in request.headers.items():
                if header_name.lower() not in sensitive_headers:
                    attributes[f"http.request.header.{header_name}"] = header_value
        
        # Add custom attributes
        attributes.update(self.config.custom_attributes)
        
        self.provider.set_span_attributes(span, attributes)
        
        # Update metrics
        self.metrics.total_requests += 1
        self.metrics.total_spans_created += 1
        
        return span
    
    def add_request_body_to_span(self, span: Any, body: bytes):
        """Add request body to span if enabled."""
        if self.config.include_request_body and body:
            try:
                # Try to decode as text first
                body_str = body.decode('utf-8')
                # Check if it's valid JSON
                try:
                    json.loads(body_str)  # Validate JSON
                    self.provider.set_span_attributes(span, {"http.request.body": body_str})
                except json.JSONDecodeError:
                    # Not JSON, store as string (truncated)
                    truncated_body = body_str[:1000] + "..." if len(body_str) > 1000 else body_str
                    self.provider.set_span_attributes(span, {"http.request.body": truncated_body})
            except UnicodeDecodeError:
                # Binary data - store as binary indicator
                self.provider.set_span_attributes(span, {"http.request.body": "<binary data>"})
    
    def add_response_to_span(self, span: Any, response: Response):
        """Add response information to span."""
        attributes = {
            "http.status_code": response.status_code,
            "http.response.size": len(getattr(response, 'body', b''))
        }
        
        # Add response headers if enabled
        if self.config.include_headers:
            for header_name, header_value in response.headers.items():
                attributes[f"http.response.header.{header_name}"] = header_value
        
        self.provider.set_span_attributes(span, attributes)
        
        # Set span status based on HTTP status
        if response.status_code >= 400:
            self.provider.set_span_status(span, "ERROR", f"HTTP {response.status_code}")
            self.metrics.error_requests += 1
        else:
            self.provider.set_span_status(span, "OK")
    
    def add_exception_to_span(self, span: Any, exception: Exception):
        """Add exception information to span."""
        attributes = {
            "exception.type": type(exception).__name__,
            "exception.message": str(exception)
        }
        
        self.provider.set_span_attributes(span, attributes)
        self.provider.set_span_status(span, "ERROR", str(exception))
        
        # Add exception event
        event = SpanEvent(
            name="exception",
            attributes=attributes
        )
        self.provider.add_span_event(span, event)
        
        self.metrics.error_requests += 1
    
    def finish_request_span(self, span: Any, start_time: float):
        """Finish request span and record metrics."""
        end_time = time.time()
        duration_ms = (end_time - start_time) * 1000
        
        # Add timing attributes
        self.provider.set_span_attributes(span, {
            "duration_ms": duration_ms,
            "start_time": start_time,
            "end_time": end_time
        })
        
        # Check if it's a slow request
        if duration_ms > self.config.slow_request_threshold_ms:
            self.metrics.slow_requests += 1
            self.provider.add_span_event(span, SpanEvent(
                name="slow_request",
                attributes={"threshold_ms": self.config.slow_request_threshold_ms}
            ))
        
        # Update average duration (avoid division by zero)
        if self.metrics.total_requests > 0:
            total_duration = self.metrics.average_duration_ms * (self.metrics.total_requests - 1) + duration_ms
            self.metrics.average_duration_ms = total_duration / self.metrics.total_requests
        else:
            self.metrics.average_duration_ms = duration_ms
        
        self.provider.finish_span(span)
    
    def create_custom_span(self, name: str, attributes: Optional[Dict[str, Any]] = None) -> Any:
        """Create a custom span for additional operations."""
        span = self.provider.create_span(name, SpanKind.INTERNAL)
        
        if attributes:
            self.provider.set_span_attributes(span, attributes)
        
        self.metrics.total_spans_created += 1
        return span
    
    def get_metrics(self) -> TracingMetrics:
        """Get current tracing metrics."""
        self.metrics.last_updated = datetime.now(timezone.utc)
        return self.metrics


class RequestTracingShield(Shield):
    """Request tracing shield for FastAPI endpoints."""
    
    def __init__(self, config: RequestTracingConfig, **kwargs):
        self.config = config
        self.tracer = RequestTracer(config)
        
        super().__init__(
            self._tracing_guard,
            name=kwargs.get('name', 'Request Tracing'),
            auto_error=kwargs.get('auto_error', True),
            exception_to_raise_if_fail=kwargs.get('exception_to_raise_if_fail'),
            default_response_to_return_if_fail=kwargs.get('default_response_to_return_if_fail')
        )
    
    async def _tracing_guard(self, request: Request, response: Response) -> Optional[Dict[str, Any]]:
        """Tracing guard function that creates and manages spans."""
        if not self.tracer.should_trace_request(request):
            return {
                'tracing_enabled': False,
                'tracer': self.tracer,
                'span': None
            }
        
        try:
            # Create request span
            span = self.tracer.create_request_span(request, self.name)
            start_time = time.time()
            
            # Store in request state for access in endpoints
            request.state.trace_span = span
            request.state.tracer = self.tracer
            
            # Add request body if available and enabled
            if hasattr(request, '_body'):
                self.tracer.add_request_body_to_span(span, request._body)
            
            # Return tracing context
            return {
                'tracing_enabled': True,
                'tracer': self.tracer,
                'span': span,
                'start_time': start_time,
                'trace_context': self._extract_trace_context(request)
            }
            
        except Exception as e:
            # Handle any errors in tracing setup
            try:
                if 'span' in locals():
                    self.tracer.add_exception_to_span(span, e)
                    self.tracer.finish_request_span(span, start_time if 'start_time' in locals() else time.time())
            except:
                pass  # Ignore errors in error handling
            
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Tracing setup failed: {str(e)}"
                )
            
            return {
                'tracing_enabled': False,
                'tracer': self.tracer,
                'span': None,
                'error': str(e)
            }
    
    def _extract_trace_context(self, request: Request) -> TraceContext:
        """Extract trace context from request."""
        trace_id = str(uuid.uuid4())
        span_id = str(uuid.uuid4())
        
        # Try to extract from traceparent header
        traceparent = request.headers.get('traceparent')
        if traceparent:
            parts = traceparent.split('-')
            if len(parts) >= 3:
                trace_id = parts[1]
                span_id = parts[2]
        
        return TraceContext(
            trace_id=trace_id,
            span_id=span_id,
            trace_flags=1,
            baggage={}
        )


# Convenience functions for creating common tracing shields

def request_tracing_shield(
    service_name: str = "fastapi-shield",
    backend: TracingBackend = TracingBackend.OPENTELEMETRY,
    tracing_level: TracingLevel = TracingLevel.BASIC,
    **kwargs
) -> RequestTracingShield:
    """Create a basic request tracing shield."""
    config = RequestTracingConfig(
        backend=backend,
        service_name=service_name,
        tracing_level=tracing_level
    )
    
    return RequestTracingShield(config=config, **kwargs)


def detailed_tracing_shield(
    service_name: str = "fastapi-shield",
    include_request_body: bool = True,
    include_response_body: bool = True,
    slow_threshold_ms: float = 500.0,
    **kwargs
) -> RequestTracingShield:
    """Create a detailed tracing shield with full request/response logging."""
    config = RequestTracingConfig(
        service_name=service_name,
        tracing_level=TracingLevel.DETAILED,
        include_request_body=include_request_body,
        include_response_body=include_response_body,
        slow_request_threshold_ms=slow_threshold_ms,
        record_performance_metrics=True
    )
    
    return RequestTracingShield(config=config, **kwargs)


def performance_tracing_shield(
    service_name: str = "fastapi-shield",
    slow_threshold_ms: float = 1000.0,
    sampling_rate: float = 0.1,
    **kwargs
) -> RequestTracingShield:
    """Create a performance-focused tracing shield with sampling."""
    config = RequestTracingConfig(
        service_name=service_name,
        tracing_level=TracingLevel.BASIC,
        record_performance_metrics=True,
        slow_request_threshold_ms=slow_threshold_ms,
        sampling_rate=sampling_rate,
        include_request_body=False,
        include_response_body=False
    )
    
    return RequestTracingShield(config=config, **kwargs)


def error_tracing_shield(
    service_name: str = "fastapi-shield",
    **kwargs
) -> RequestTracingShield:
    """Create an error-only tracing shield that only traces failed requests."""
    config = RequestTracingConfig(
        service_name=service_name,
        tracing_level=TracingLevel.ERROR_ONLY,
        sampling_rate=1.0,  # Always trace errors
        record_performance_metrics=True
    )
    
    return RequestTracingShield(config=config, **kwargs)