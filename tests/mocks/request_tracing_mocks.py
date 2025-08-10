"""Mock objects for Request Tracing testing."""

import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from unittest.mock import Mock

from fastapi_shield.request_tracing import (
    TracerProvider, SpanKind, SpanEvent
)


class MockSpan:
    """Mock span object for testing."""
    
    def __init__(self, name: str, span_id: str = "test-span-1"):
        self.name = name
        self.span_id = span_id
        self.attributes: Dict[str, Any] = {}
        self.events: List[Dict[str, Any]] = []
        self.status = "OK"
        self.status_description: Optional[str] = None
        self.start_time = time.time()
        self.end_time: Optional[float] = None
        self.finished = False
    
    def set_attribute(self, key: str, value: Any):
        """Mock set attribute method."""
        self.attributes[key] = value
    
    def add_event(self, name: str, attributes: Dict[str, Any], timestamp: Optional[int] = None):
        """Mock add event method."""
        self.events.append({
            'name': name,
            'attributes': attributes,
            'timestamp': timestamp or time.time_ns()
        })
    
    def set_status(self, status):
        """Mock set status method."""
        if hasattr(status, 'status_code'):
            self.status = "OK" if status.status_code.name == "OK" else "ERROR"
            self.status_description = status.description
        else:
            self.status = str(status)
    
    def end(self):
        """Mock end method."""
        self.end_time = time.time()
        self.finished = True
    
    def get_span_context(self):
        """Mock get span context."""
        return MockSpanContext(self.span_id)


class MockSpanContext:
    """Mock span context for testing."""
    
    def __init__(self, span_id: str):
        self.span_id = span_id
        self.trace_id = "test-trace-123"


class MockTracer:
    """Mock tracer for testing."""
    
    def __init__(self, service_name: str = "test-service"):
        self.service_name = service_name
        self.spans: List[MockSpan] = []
        self._span_counter = 0
    
    def start_span(self, name: str, kind=None, context=None):
        """Mock start span method."""
        self._span_counter += 1
        span = MockSpan(name, f"test-span-{self._span_counter}")
        self.spans.append(span)
        return span
    
    def get_spans(self) -> List[MockSpan]:
        """Get all created spans."""
        return self.spans
    
    def clear_spans(self):
        """Clear all spans."""
        self.spans.clear()
        self._span_counter = 0


class MockPropagator:
    """Mock propagator for testing."""
    
    def extract(self, headers: Dict[str, str]) -> Optional[str]:
        """Mock extract context."""
        return headers.get('traceparent')
    
    def inject(self, headers: Dict[str, str], context=None):
        """Mock inject context."""
        if context:
            headers['traceparent'] = f"00-test-trace-123-test-span-456-01"


class MockTracerProviderForTesting(TracerProvider):
    """Mock tracer provider specifically for testing."""
    
    def __init__(self, service_name: str = "test-service"):
        self.service_name = service_name
        self.spans: List[MockSpan] = []
        self._span_counter = 0
        self.contexts: List[Dict[str, str]] = []
        self.injected_headers: List[Dict[str, str]] = []
    
    def create_span(self, name: str, kind: SpanKind = SpanKind.INTERNAL, 
                   parent_context: Optional[Any] = None) -> MockSpan:
        """Create a mock span."""
        self._span_counter += 1
        span = MockSpan(name, f"test-span-{self._span_counter}")
        span.kind = kind
        span.parent_context = parent_context
        self.spans.append(span)
        return span
    
    def set_span_attributes(self, span: MockSpan, attributes: Dict[str, Any]):
        """Set attributes on mock span."""
        span.attributes.update(attributes)
    
    def add_span_event(self, span: MockSpan, event: SpanEvent):
        """Add event to mock span."""
        span.events.append({
            'name': event.name,
            'timestamp': event.timestamp or datetime.now(timezone.utc),
            'attributes': event.attributes
        })
    
    def set_span_status(self, span: MockSpan, status_code: str, description: Optional[str] = None):
        """Set mock span status."""
        span.status = status_code
        span.status_description = description
    
    def finish_span(self, span: MockSpan):
        """Finish mock span."""
        span.end_time = time.time()
        span.finished = True
    
    def extract_context(self, headers: Dict[str, str]) -> Optional[str]:
        """Mock extract context."""
        context = headers.get('traceparent')
        if context:
            self.contexts.append(headers.copy())
        return context
    
    def inject_context(self, context: Any, headers: Dict[str, str]):
        """Mock inject context."""
        if context:
            headers['traceparent'] = f"00-test-trace-123-{context}-01"
            self.injected_headers.append(headers.copy())
    
    def get_spans(self) -> List[MockSpan]:
        """Get all spans."""
        return self.spans
    
    def get_span_by_name(self, name: str) -> Optional[MockSpan]:
        """Get span by name."""
        for span in self.spans:
            if span.name == name:
                return span
        return None
    
    def clear_spans(self):
        """Clear all recorded spans."""
        self.spans.clear()
        self._span_counter = 0
        self.contexts.clear()
        self.injected_headers.clear()


def create_mock_request_with_tracing(
    method: str = "GET",
    path: str = "/test",
    headers: Optional[Dict[str, str]] = None,
    query_params: Optional[Dict[str, str]] = None,
    body: bytes = b"",
    traceparent: Optional[str] = None
) -> Mock:
    """Create a mock FastAPI Request with tracing headers."""
    request = Mock()
    request.method = method
    request.url = Mock()
    request.url.path = path
    request.url.scheme = "http"
    request.url.hostname = "localhost"
    request.headers = headers or {}
    request.query_params = query_params or {}
    request._body = body
    request.state = Mock()
    
    # Add traceparent header if specified
    if traceparent:
        request.headers['traceparent'] = traceparent
    
    return request


def create_mock_response_with_tracing(
    status_code: int = 200,
    headers: Optional[Dict[str, str]] = None,
    body: bytes = b""
) -> Mock:
    """Create a mock FastAPI Response with tracing."""
    response = Mock()
    response.status_code = status_code
    response.headers = headers or {}
    response.body = body
    
    return response


class MockOpenTelemetryModules:
    """Mock OpenTelemetry modules for testing when OTel is not installed."""
    
    def __init__(self):
        self.trace = Mock()
        self.trace.get_tracer.return_value = MockTracer()
        self.trace.SpanKind = Mock()
        self.trace.SpanKind.INTERNAL = "INTERNAL"
        self.trace.SpanKind.SERVER = "SERVER"
        self.trace.SpanKind.CLIENT = "CLIENT"
        
        # Status classes
        self.Status = Mock()
        self.StatusCode = Mock()
        self.StatusCode.OK = "OK"
        self.StatusCode.ERROR = "ERROR"
        
        # Propagator
        self.TraceContextTextMapPropagator = Mock(return_value=MockPropagator())


def patch_opentelemetry_imports():
    """Patch OpenTelemetry imports for testing."""
    import sys
    mock_modules = MockOpenTelemetryModules()
    
    # Mock the modules
    sys.modules['opentelemetry'] = Mock()
    sys.modules['opentelemetry.trace'] = mock_modules.trace
    sys.modules['opentelemetry.trace.propagation'] = Mock()
    sys.modules['opentelemetry.trace.propagation.tracecontext'] = Mock()
    sys.modules['opentelemetry.trace.propagation.tracecontext'].TraceContextTextMapPropagator = mock_modules.TraceContextTextMapPropagator
    
    return mock_modules