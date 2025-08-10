"""Mock objects for Request Tracing testing."""

import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from unittest.mock import Mock

from fastapi_shield.request_tracing import (
    TracerProvider, SpanKind, SpanEvent
)

class MockTracerProvider(TracerProvider):
    """Mock tracing provider for testing and when tracing is disabled."""
    
    def __init__(self, service_name: str = "fastapi-shield"):
        self.service_name = service_name
        self.spans: List[Dict[str, Any]] = []
        self.current_span_id = 0
    
    def create_span(self, name: str, kind: SpanKind = SpanKind.INTERNAL, 
                   parent_context: Optional[Any] = None) -> Dict[str, Any]:
        """Create a mock span."""
        self.current_span_id += 1
        span = {
            "span_id": str(self.current_span_id),
            "name": name,
            "kind": kind,
            "start_time": time.time(),
            "attributes": {},
            "events": [],
            "status": "OK",
            "finished": False
        }
        self.spans.append(span)
        return span
    
    def set_span_attributes(self, span: Dict[str, Any], attributes: Dict[str, Any]):
        """Set attributes on a mock span."""
        span["attributes"].update(attributes)
    
    def add_span_event(self, span: Dict[str, Any], event: SpanEvent):
        """Add an event to a mock span."""
        span["events"].append({
            "name": event.name,
            "timestamp": event.timestamp or datetime.now(timezone.utc),
            "attributes": event.attributes
        })
    
    def set_span_status(self, span: Dict[str, Any], status_code: str, description: Optional[str] = None):
        """Set mock span status."""
        span["status"] = status_code
        if description:
            span["status_description"] = description
    
    def finish_span(self, span: Dict[str, Any]):
        """Finish a mock span."""
        span["end_time"] = time.time()
        span["duration_ms"] = (span["end_time"] - span["start_time"]) * 1000
        span["finished"] = True
    
    def extract_context(self, headers: Dict[str, str]) -> Optional[Any]:
        """Mock extract trace context."""
        return headers.get("traceparent")
    
    def inject_context(self, context: Any, headers: Dict[str, str]):
        """Mock inject trace context."""
        if context:
            headers["traceparent"] = str(context)
    
    def get_spans(self) -> List[Dict[str, Any]]:
        """Get all recorded spans."""
        return self.spans
    
    def clear_spans(self):
        """Clear recorded spans."""
        self.spans.clear()
        self.current_span_id = 0
        
        
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


class MockJaegerTracer:
    """Mock Jaeger tracer for testing."""
    
    def __init__(self, service_name: str = "test-service"):
        self.service_name = service_name
        self.spans: List[Dict[str, Any]] = []
        self._span_counter = 0
        
        # Mock format constants
        self.Format = Mock()
        self.Format.HTTP_HEADERS = "http_headers"
    
    def start_span(self, operation_name: str, child_of=None, tags=None):
        """Mock start span for Jaeger."""
        self._span_counter += 1
        span = {
            'span_id': f"jaeger-span-{self._span_counter}",
            'operation_name': operation_name,
            'child_of': child_of,
            'tags': tags or {},
            'logs': [],
            'start_time': time.time(),
            'finished': False
        }
        self.spans.append(span)
        
        # Mock span object with methods
        mock_span = Mock()
        mock_span._span_data = span
        mock_span.set_tag = lambda key, value: span['tags'].update({key: value})
        mock_span.log_kv = lambda data, timestamp=None: span['logs'].append({'data': data, 'timestamp': timestamp})
        mock_span.finish = lambda: span.update({'finished': True, 'end_time': time.time()})
        
        return mock_span
    
    def extract(self, format, carrier):
        """Mock extract context from headers."""
        if format == self.Format.HTTP_HEADERS:
            return carrier.get('uber-trace-id')
        return None
    
    def inject(self, context, format, carrier):
        """Mock inject context into headers."""
        if format == self.Format.HTTP_HEADERS and context:
            carrier['uber-trace-id'] = f"mock-trace-{context}"


class MockJaegerConfig:
    """Mock Jaeger config for testing."""
    
    def __init__(self, config: Dict[str, Any], service_name: str):
        self.config = config
        self.service_name = service_name
    
    def initialize_tracer(self):
        """Mock initialize tracer."""
        return MockJaegerTracer(self.service_name)


class MockZipkinSpan:
    """Mock Zipkin span for testing."""
    
    def __init__(self, name: str, span_id: str):
        self.name = name
        self.span_id = span_id
        self.tags = {}
        self.logs = []
        self.start_time = time.time()
        self.end_time = None
        self.finished = False


class MockDatadogSpan:
    """Mock DataDog span for testing."""
    
    def __init__(self, operation_name: str, service: str):
        self.operation_name = operation_name
        self.service = service
        self.tags: Dict[str, Any] = {}
        self.error = 0
        self.start_time = time.time()
        self.end_time = None
        self.finished = False
        self._parent = None
    
    def set_tag(self, key: str, value: Any):
        """Mock set tag method."""
        self.tags[key] = value
    
    def finish(self):
        """Mock finish method."""
        self.end_time = time.time()
        self.finished = True


class MockDatadogTracer:
    """Mock DataDog tracer for testing."""
    
    def __init__(self):
        self.spans: List[MockDatadogSpan] = []
        self._span_counter = 0
        self._config = {}
    
    def trace(self, operation_name: str, service: str = None):
        """Mock trace method."""
        self._span_counter += 1
        span = MockDatadogSpan(operation_name, service or "test-service")
        self.spans.append(span)
        return span
    
    def configure(self, **kwargs):
        """Mock configure method."""
        self._config.update(kwargs)
    
    def get_call_context(self):
        """Mock get call context."""
        mock_context = Mock()
        mock_context.trace_id = 123456789
        mock_context.span_id = 987654321
        return mock_context


class MockJaegerProviderForTesting(TracerProvider):
    """Mock Jaeger provider for testing without actual Jaeger dependency."""
    
    def __init__(self, service_name: str = "test-service", config: Optional[Dict[str, Any]] = None):
        self.service_name = service_name
        self.config = config or {}
        self.tracer = MockJaegerTracer(service_name)
        self.spans: List[Dict[str, Any]] = []
    
    def create_span(self, name: str, kind: SpanKind = SpanKind.INTERNAL, 
                   parent_context: Optional[Any] = None) -> Dict[str, Any]:
        """Create a mock Jaeger span."""
        span_data = {
            'span_id': f"jaeger-{len(self.spans) + 1}",
            'name': name,
            'kind': kind,
            'start_time': time.time(),
            'tags': {'span.kind': kind.value},
            'logs': [],
            'parent_context': parent_context,
            'finished': False
        }
        self.spans.append(span_data)
        return span_data
    
    def set_span_attributes(self, span: Dict[str, Any], attributes: Dict[str, Any]):
        """Set attributes on mock Jaeger span."""
        span['tags'].update(attributes)
    
    def add_span_event(self, span: Dict[str, Any], event: SpanEvent):
        """Add event to mock Jaeger span."""
        log_entry = {
            'event': event.name,
            'timestamp': event.timestamp or datetime.now(timezone.utc),
            **event.attributes
        }
        span['logs'].append(log_entry)
    
    def set_span_status(self, span: Dict[str, Any], status_code: str, description: Optional[str] = None):
        """Set mock Jaeger span status."""
        span['tags']['status.code'] = status_code
        if description:
            span['tags']['status.description'] = description
        if status_code != "OK":
            span['tags']['error'] = True
    
    def finish_span(self, span: Dict[str, Any]):
        """Finish mock Jaeger span."""
        span['end_time'] = time.time()
        span['finished'] = True
    
    def extract_context(self, headers: Dict[str, str]) -> Optional[Any]:
        """Mock extract context for Jaeger."""
        return headers.get('uber-trace-id')
    
    def inject_context(self, context: Any, headers: Dict[str, str]):
        """Mock inject context for Jaeger."""
        if context:
            headers['uber-trace-id'] = f"mock-jaeger-{context}"


class MockZipkinProviderForTesting(TracerProvider):
    """Mock Zipkin provider for testing without actual Zipkin dependency."""
    
    def __init__(self, service_name: str = "test-service", config: Optional[Dict[str, Any]] = None):
        self.service_name = service_name
        self.config = config or {}
        self.spans: List[Dict[str, Any]] = []
        self._active_spans = {}
    
    def create_span(self, name: str, kind: SpanKind = SpanKind.INTERNAL, 
                   parent_context: Optional[Any] = None) -> Dict[str, Any]:
        """Create a mock Zipkin span."""
        span_id = str(uuid.uuid4().hex[:16])
        span_data = {
            'span_id': span_id,
            'operation_name': name,
            'kind': kind,
            'start_time': time.time(),
            'tags': {'span.kind': kind.value},
            'logs': [],
            'parent_context': parent_context,
            'finished': False
        }
        self.spans.append(span_data)
        self._active_spans[span_id] = span_data
        return span_data
    
    def set_span_attributes(self, span: Dict[str, Any], attributes: Dict[str, Any]):
        """Set attributes on mock Zipkin span."""
        if span and 'tags' in span:
            span['tags'].update(attributes)
    
    def add_span_event(self, span: Dict[str, Any], event: SpanEvent):
        """Add event to mock Zipkin span."""
        if span and 'logs' in span:
            log_entry = {
                'timestamp': event.timestamp or datetime.now(timezone.utc),
                'fields': {'event': event.name, **event.attributes}
            }
            span['logs'].append(log_entry)
    
    def set_span_status(self, span: Dict[str, Any], status_code: str, description: Optional[str] = None):
        """Set mock Zipkin span status."""
        if span and 'tags' in span:
            span['tags']['status.code'] = status_code
            if description:
                span['tags']['status.description'] = description
            if status_code != "OK":
                span['tags']['error'] = True
    
    def finish_span(self, span: Dict[str, Any]):
        """Finish mock Zipkin span."""
        if span:
            span['end_time'] = time.time()
            span['finished'] = True
    
    def extract_context(self, headers: Dict[str, str]) -> Optional[Any]:
        """Mock extract context for Zipkin."""
        trace_id = headers.get('X-B3-TraceId')
        span_id = headers.get('X-B3-SpanId')
        if trace_id and span_id:
            return {
                'trace_id': trace_id,
                'span_id': span_id,
                'parent_span_id': headers.get('X-B3-ParentSpanId'),
                'sampled': headers.get('X-B3-Sampled', '1') == '1'
            }
        return None
    
    def inject_context(self, context: Any, headers: Dict[str, str]):
        """Mock inject context for Zipkin."""
        if context and isinstance(context, dict):
            headers['X-B3-TraceId'] = context.get('trace_id', str(uuid.uuid4().hex))
            headers['X-B3-SpanId'] = context.get('span_id', str(uuid.uuid4().hex[:16]))
            if context.get('parent_span_id'):
                headers['X-B3-ParentSpanId'] = context['parent_span_id']
            headers['X-B3-Sampled'] = '1' if context.get('sampled', True) else '0'


class MockDatadogProviderForTesting(TracerProvider):
    """Mock DataDog provider for testing without actual DataDog dependency."""
    
    def __init__(self, service_name: str = "test-service", config: Optional[Dict[str, Any]] = None):
        self.service_name = service_name
        self.config = config or {}
        self.tracer = MockDatadogTracer()
        self.spans: List[MockDatadogSpan] = []
    
    def create_span(self, name: str, kind: SpanKind = SpanKind.INTERNAL, 
                   parent_context: Optional[Any] = None) -> MockDatadogSpan:
        """Create a mock DataDog span."""
        span = self.tracer.trace(name, self.service_name)
        span.set_tag('span.kind', kind.value)
        if parent_context:
            span._parent = parent_context
        self.spans.append(span)
        return span
    
    def set_span_attributes(self, span: MockDatadogSpan, attributes: Dict[str, Any]):
        """Set attributes on mock DataDog span."""
        for key, value in attributes.items():
            span.set_tag(key, value)
    
    def add_span_event(self, span: MockDatadogSpan, event: SpanEvent):
        """Add event to mock DataDog span."""
        # DataDog doesn't have events, so we'll add it as tags
        span.set_tag(f"event.{event.name}", True)
        for key, value in event.attributes.items():
            span.set_tag(f"event.{event.name}.{key}", value)
    
    def set_span_status(self, span: MockDatadogSpan, status_code: str, description: Optional[str] = None):
        """Set mock DataDog span status."""
        span.set_tag('status.code', status_code)
        if description:
            span.set_tag('status.description', description)
        if status_code != "OK":
            span.error = 1
    
    def finish_span(self, span: MockDatadogSpan):
        """Finish mock DataDog span."""
        span.finish()
    
    def extract_context(self, headers: Dict[str, str]) -> Optional[Any]:
        """Mock extract context for DataDog."""
        trace_id = headers.get('x-datadog-trace-id')
        parent_id = headers.get('x-datadog-parent-id')
        if trace_id:
            context = self.tracer.get_call_context()
            context.trace_id = int(trace_id)
            if parent_id:
                context.span_id = int(parent_id)
            return context
        return None
    
    def inject_context(self, context: Any, headers: Dict[str, str]):
        """Mock inject context for DataDog."""
        if context and hasattr(context, 'trace_id'):
            headers['x-datadog-trace-id'] = str(context.trace_id)
            headers['x-datadog-parent-id'] = str(context.span_id)


def patch_tracing_backend_imports():
    """Patch all tracing backend imports for comprehensive testing."""
    import sys
    
    # Patch OpenTelemetry
    otel_modules = MockOpenTelemetryModules()
    sys.modules['opentelemetry'] = Mock()
    sys.modules['opentelemetry.trace'] = otel_modules.trace
    sys.modules['opentelemetry.trace.propagation'] = Mock()
    sys.modules['opentelemetry.trace.propagation.tracecontext'] = Mock()
    sys.modules['opentelemetry.trace.propagation.tracecontext'].TraceContextTextMapPropagator = otel_modules.TraceContextTextMapPropagator
    
    # Patch Jaeger
    sys.modules['jaeger_client'] = Mock()
    sys.modules['jaeger_client'].Config = MockJaegerConfig
    sys.modules['jaeger_client.tracer'] = Mock()
    sys.modules['jaeger_client.tracer'].Tracer = MockJaegerTracer
    
    # Patch Zipkin
    sys.modules['py_zipkin'] = Mock()
    sys.modules['py_zipkin.zipkin'] = Mock()
    sys.modules['py_zipkin.zipkin'].zipkin_span = Mock()
    sys.modules['py_zipkin.transport'] = Mock()
    sys.modules['py_zipkin.transport'].Transport = Mock()
    
    # Patch DataDog
    sys.modules['ddtrace'] = Mock()
    sys.modules['ddtrace'].tracer = MockDatadogTracer()
    sys.modules['ddtrace.span'] = Mock()
    sys.modules['ddtrace.span'].Span = MockDatadogSpan
    
    return {
        'opentelemetry': otel_modules,
        'jaeger': MockJaegerConfig,
        'zipkin': Mock(),
        'datadog': MockDatadogTracer()
    }


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