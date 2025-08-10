"""Tests for Request Tracing Shield functionality."""

import json
import time
from datetime import datetime, timezone
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from fastapi_shield.request_tracing import (
    RequestTracingShield,
    RequestTracingConfig,
    TracingBackend,
    SpanKind,
    TracingLevel,
    SpanAttribute,
    SpanEvent,
    TraceContext,
    TracingMetrics,
    MockTracerProvider,
    OpenTelemetryProvider,
    RequestTracer,
    request_tracing_shield,
    detailed_tracing_shield,
    performance_tracing_shield,
    error_tracing_shield,
    OPENTELEMETRY_AVAILABLE,
)
from tests.mocks.request_tracing_mocks import (
    MockSpan,
    MockTracer,
    MockTracerProviderForTesting,
    create_mock_request_with_tracing,
    create_mock_response_with_tracing,
    patch_opentelemetry_imports,
)


class TestSpanEvent:
    """Test span event functionality."""
    
    def test_span_event_creation(self):
        """Test creating a span event."""
        event = SpanEvent(
            name="test_event",
            attributes={"key": "value", "count": 42}
        )
        
        assert event.name == "test_event"
        assert event.attributes["key"] == "value"
        assert event.attributes["count"] == 42
        assert event.timestamp is None  # Should be None by default
    
    def test_span_event_with_timestamp(self):
        """Test span event with explicit timestamp."""
        now = datetime.now(timezone.utc)
        event = SpanEvent(
            name="timed_event",
            timestamp=now,
            attributes={"test": True}
        )
        
        assert event.timestamp == now
        assert event.attributes["test"] is True


class TestTraceContext:
    """Test trace context functionality."""
    
    def test_trace_context_creation(self):
        """Test creating trace context."""
        context = TraceContext(
            trace_id="test-trace-123",
            span_id="test-span-456",
            parent_span_id="parent-span-789"
        )
        
        assert context.trace_id == "test-trace-123"
        assert context.span_id == "test-span-456"
        assert context.parent_span_id == "parent-span-789"
        assert context.trace_flags == 1
        assert len(context.baggage) == 0
    
    def test_trace_context_with_baggage(self):
        """Test trace context with baggage."""
        context = TraceContext(
            trace_id="test-trace",
            span_id="test-span",
            baggage={"user": "test", "session": "123"}
        )
        
        assert context.baggage["user"] == "test"
        assert context.baggage["session"] == "123"


class TestRequestTracingConfig:
    """Test request tracing configuration."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = RequestTracingConfig()
        
        assert config.backend == TracingBackend.OPENTELEMETRY
        assert config.service_name == "fastapi-shield"
        assert config.tracing_level == TracingLevel.BASIC
        assert config.create_root_span is True
        assert config.sampling_rate == 1.0
        assert len(config.excluded_paths) == 0
    
    def test_custom_config(self):
        """Test custom configuration."""
        config = RequestTracingConfig(
            backend=TracingBackend.JAEGER,
            service_name="my-service",
            tracing_level=TracingLevel.DETAILED,
            include_request_body=True,
            sampling_rate=0.5,
            excluded_paths=["/health", "/metrics"]
        )
        
        assert config.backend == TracingBackend.JAEGER
        assert config.service_name == "my-service"
        assert config.tracing_level == TracingLevel.DETAILED
        assert config.include_request_body is True
        assert config.sampling_rate == 0.5
        assert "/health" in config.excluded_paths
        assert "/metrics" in config.excluded_paths


class TestMockTracerProvider:
    """Test mock tracer provider functionality."""
    
    def test_mock_provider_creation(self):
        """Test creating mock tracer provider."""
        provider = MockTracerProvider("test-service")
        
        assert provider.service_name == "test-service"
        assert len(provider.spans) == 0
    
    def test_create_span(self):
        """Test creating spans with mock provider."""
        provider = MockTracerProvider()
        
        span = provider.create_span("test-operation", SpanKind.SERVER)
        
        assert span["name"] == "test-operation"
        assert span["kind"] == SpanKind.SERVER
        assert span["span_id"] == "1"
        assert span["finished"] is False
        assert len(provider.spans) == 1
    
    def test_set_span_attributes(self):
        """Test setting span attributes."""
        provider = MockTracerProvider()
        span = provider.create_span("test")
        
        attributes = {"http.method": "GET", "http.status_code": 200}
        provider.set_span_attributes(span, attributes)
        
        assert span["attributes"]["http.method"] == "GET"
        assert span["attributes"]["http.status_code"] == 200
    
    def test_add_span_event(self):
        """Test adding span events."""
        provider = MockTracerProvider()
        span = provider.create_span("test")
        
        event = SpanEvent(name="request_received", attributes={"size": 1024})
        provider.add_span_event(span, event)
        
        assert len(span["events"]) == 1
        assert span["events"][0]["name"] == "request_received"
        assert span["events"][0]["attributes"]["size"] == 1024
    
    def test_finish_span(self):
        """Test finishing spans."""
        provider = MockTracerProvider()
        span = provider.create_span("test")
        
        # Simulate some processing time
        time.sleep(0.01)
        provider.finish_span(span)
        
        assert span["finished"] is True
        assert span["end_time"] > span["start_time"]
        assert span["duration_ms"] > 0
    
    def test_extract_and_inject_context(self):
        """Test context extraction and injection."""
        provider = MockTracerProvider()
        
        # Test extraction
        headers_with_trace = {"traceparent": "00-trace123-span456-01"}
        context = provider.extract_context(headers_with_trace)
        assert context == "00-trace123-span456-01"
        
        # Test extraction without traceparent
        empty_headers = {}
        context = provider.extract_context(empty_headers)
        assert context is None
        
        # Test injection
        headers = {}
        provider.inject_context("test-context", headers)
        assert "traceparent" in headers
        assert headers["traceparent"] == "test-context"


class TestRequestTracer:
    """Test request tracer functionality."""
    
    def test_tracer_creation(self):
        """Test creating request tracer."""
        config = RequestTracingConfig(service_name="test-service")
        tracer = RequestTracer(config)
        
        assert tracer.config.service_name == "test-service"
        assert isinstance(tracer.provider, MockTracerProvider)  # Default since OTel not available
        assert tracer.metrics.total_requests == 0
    
    def test_should_trace_request_basic(self):
        """Test basic request tracing decision."""
        config = RequestTracingConfig(tracing_level=TracingLevel.BASIC, sampling_rate=1.0)
        tracer = RequestTracer(config)
        
        request = create_mock_request_with_tracing(path="/api/test")
        assert tracer.should_trace_request(request) is True
    
    def test_should_trace_request_disabled(self):
        """Test tracing disabled."""
        config = RequestTracingConfig(tracing_level=TracingLevel.OFF)
        tracer = RequestTracer(config)
        
        request = create_mock_request_with_tracing(path="/api/test")
        assert tracer.should_trace_request(request) is False
    
    def test_should_trace_request_excluded_paths(self):
        """Test request tracing with excluded paths."""
        config = RequestTracingConfig(excluded_paths=["/health", "/metrics"])
        tracer = RequestTracer(config)
        
        health_request = create_mock_request_with_tracing(path="/health")
        assert tracer.should_trace_request(health_request) is False
        
        api_request = create_mock_request_with_tracing(path="/api/users")
        assert tracer.should_trace_request(api_request) is True
    
    def test_should_trace_request_sampling(self):
        """Test request tracing with sampling."""
        config = RequestTracingConfig(sampling_rate=0.0)  # Never sample
        tracer = RequestTracer(config)
        
        request = create_mock_request_with_tracing(path="/api/test")
        # With 0.0 sampling rate, should never trace
        assert tracer.should_trace_request(request) is False
    
    def test_create_request_span(self):
        """Test creating request span."""
        config = RequestTracingConfig()
        tracer = RequestTracer(config)
        
        request = create_mock_request_with_tracing(
            method="POST",
            path="/api/users",
            headers={"User-Agent": "Test-Agent", "Content-Type": "application/json"},
            query_params={"filter": "active", "limit": "10"}
        )
        
        span = tracer.create_request_span(request, "test_shield")
        
        # Check span was created
        assert span is not None
        
        # Check metrics were updated
        assert tracer.metrics.total_requests == 1
        assert tracer.metrics.total_spans_created == 1
        
        # Check span attributes (for mock provider)
        if hasattr(span, 'get'):  # Mock span is a dict
            assert span["name"] == "test_shield: POST /api/users"
    
    def test_add_request_body_to_span(self):
        """Test adding request body to span."""
        config = RequestTracingConfig(include_request_body=True)
        tracer = RequestTracer(config)
        
        # Test with JSON body
        json_body = json.dumps({"name": "test", "value": 123}).encode('utf-8')
        span = tracer.provider.create_span("test")
        tracer.add_request_body_to_span(span, json_body)
        
        # Mock provider should have body in attributes
        assert "http.request.body" in span["attributes"]
        
        # Test with actual binary data (non-UTF-8)
        binary_body = bytes([0, 1, 2, 255])  # Include non-UTF-8 byte
        span2 = tracer.provider.create_span("test2")
        tracer.add_request_body_to_span(span2, binary_body)
        
        assert span2["attributes"]["http.request.body"] == "<binary data>"
    
    def test_add_response_to_span(self):
        """Test adding response to span."""
        config = RequestTracingConfig(include_headers=True)
        tracer = RequestTracer(config)
        
        span = tracer.provider.create_span("test")
        response = create_mock_response_with_tracing(
            status_code=201,
            headers={"Content-Type": "application/json"},
            body=b'{"created": true}'
        )
        
        tracer.add_response_to_span(span, response)
        
        # Check attributes were set
        assert span["attributes"]["http.status_code"] == 201
        assert span["attributes"]["http.response.size"] == len(b'{"created": true}')
        assert span["status"] == "OK"  # 201 is success
        
        # Test error response
        span2 = tracer.provider.create_span("test2")
        error_response = create_mock_response_with_tracing(status_code=500)
        
        tracer.add_response_to_span(span2, error_response)
        
        assert span2["status"] == "ERROR"
        assert tracer.metrics.error_requests == 1
    
    def test_add_exception_to_span(self):
        """Test adding exception to span."""
        config = RequestTracingConfig()
        tracer = RequestTracer(config)
        
        span = tracer.provider.create_span("test")
        exception = ValueError("Test error message")
        
        tracer.add_exception_to_span(span, exception)
        
        # Check exception attributes
        assert span["attributes"]["exception.type"] == "ValueError"
        assert span["attributes"]["exception.message"] == "Test error message"
        assert span["status"] == "ERROR"
        
        # Check exception event was added
        assert len(span["events"]) == 1
        assert span["events"][0]["name"] == "exception"
        
        # Check metrics
        assert tracer.metrics.error_requests == 1
    
    def test_finish_request_span(self):
        """Test finishing request span."""
        config = RequestTracingConfig(slow_request_threshold_ms=100.0)
        tracer = RequestTracer(config)
        
        # First create a request span to set up metrics properly
        request = create_mock_request_with_tracing()
        span = tracer.create_request_span(request)  # This increments total_requests
        start_time = time.time()
        
        # Simulate slow request
        time.sleep(0.11)  # 110ms - above threshold
        
        tracer.finish_request_span(span, start_time)
        
        # Check span was finished
        assert span["finished"] is True
        assert span["duration_ms"] > 100  # Above threshold
        
        # Check slow request was detected
        assert tracer.metrics.slow_requests == 1
        
        # Check slow request event was added
        slow_events = [e for e in span["events"] if e["name"] == "slow_request"]
        assert len(slow_events) == 1
    
    def test_create_custom_span(self):
        """Test creating custom spans."""
        config = RequestTracingConfig()
        tracer = RequestTracer(config)
        
        attributes = {"operation": "database_query", "table": "users"}
        span = tracer.create_custom_span("db_query", attributes)
        
        assert span is not None
        assert span["name"] == "db_query"
        assert span["attributes"]["operation"] == "database_query"
        assert span["attributes"]["table"] == "users"
        
        # Check metrics
        assert tracer.metrics.total_spans_created == 1
    
    def test_get_metrics(self):
        """Test getting tracing metrics."""
        config = RequestTracingConfig()
        tracer = RequestTracer(config)
        
        # Generate some activity
        tracer.metrics.total_requests = 100
        tracer.metrics.slow_requests = 5
        tracer.metrics.error_requests = 3
        tracer.metrics.average_duration_ms = 250.5
        
        metrics = tracer.get_metrics()
        
        assert metrics.total_requests == 100
        assert metrics.slow_requests == 5
        assert metrics.error_requests == 3
        assert metrics.average_duration_ms == 250.5
        assert metrics.last_updated is not None


class TestRequestTracingShield:
    """Test request tracing shield functionality."""
    
    def test_shield_creation(self):
        """Test creating request tracing shield."""
        config = RequestTracingConfig()
        shield = RequestTracingShield(config)
        
        assert shield.config == config
        assert isinstance(shield.tracer, RequestTracer)
    
    @pytest.mark.asyncio
    async def test_tracing_guard_enabled(self):
        """Test tracing guard when tracing is enabled."""
        config = RequestTracingConfig(tracing_level=TracingLevel.BASIC)
        shield = RequestTracingShield(config)
        
        request = create_mock_request_with_tracing(path="/api/test")
        response = create_mock_response_with_tracing()
        
        result = await shield._tracing_guard(request, response)
        
        assert result is not None
        assert result["tracing_enabled"] is True
        assert result["tracer"] is not None
        assert result["span"] is not None
        assert "start_time" in result
        assert "trace_context" in result
    
    @pytest.mark.asyncio
    async def test_tracing_guard_disabled(self):
        """Test tracing guard when tracing is disabled."""
        config = RequestTracingConfig(tracing_level=TracingLevel.OFF)
        shield = RequestTracingShield(config)
        
        request = create_mock_request_with_tracing()
        response = create_mock_response_with_tracing()
        
        result = await shield._tracing_guard(request, response)
        
        assert result is not None
        assert result["tracing_enabled"] is False
        assert result["tracer"] is not None
        assert result["span"] is None
    
    @pytest.mark.asyncio
    async def test_tracing_guard_excluded_path(self):
        """Test tracing guard with excluded paths."""
        config = RequestTracingConfig(excluded_paths=["/health"])
        shield = RequestTracingShield(config)
        
        request = create_mock_request_with_tracing(path="/health")
        response = create_mock_response_with_tracing()
        
        result = await shield._tracing_guard(request, response)
        
        assert result["tracing_enabled"] is False
    
    @pytest.mark.asyncio
    async def test_tracing_guard_with_traceparent(self):
        """Test tracing guard with existing trace context."""
        config = RequestTracingConfig()
        shield = RequestTracingShield(config)
        
        request = create_mock_request_with_tracing(
            traceparent="00-0af7651916cd43dd8448eb211c80319c-b9c7c989f97918e1-01"
        )
        response = create_mock_response_with_tracing()
        
        result = await shield._tracing_guard(request, response)
        
        assert result["tracing_enabled"] is True
        trace_context = result["trace_context"]
        assert "0af7651916cd43dd8448eb211c80319c" in trace_context.trace_id
    
    @pytest.mark.asyncio
    async def test_tracing_guard_exception_handling(self):
        """Test tracing guard exception handling."""
        config = RequestTracingConfig()
        shield = RequestTracingShield(config, auto_error=False)
        
        # Mock should_trace_request to return True first
        shield.tracer.should_trace_request = Mock(return_value=True)
        
        # Create a problematic request that might cause issues
        request = create_mock_request_with_tracing()
        response = create_mock_response_with_tracing()
        
        # Mock the tracer to raise an exception after span creation
        original_create_span = shield.tracer.create_request_span
        def mock_create_span(*args, **kwargs):
            span = original_create_span(*args, **kwargs)
            # Raise error after span is created but before returning
            raise ValueError("Tracing error")
        
        shield.tracer.create_request_span = mock_create_span
        
        result = await shield._tracing_guard(request, response)
        
        # Should handle gracefully when auto_error=False
        assert result["tracing_enabled"] is False
        assert "error" in result
    
    @pytest.mark.asyncio 
    async def test_tracing_guard_exception_with_auto_error(self):
        """Test tracing guard exception handling with auto_error=True."""
        config = RequestTracingConfig()
        shield = RequestTracingShield(config, auto_error=True)
        
        # Mock should_trace_request to return True first
        shield.tracer.should_trace_request = Mock(return_value=True)
        
        request = create_mock_request_with_tracing()
        response = create_mock_response_with_tracing()
        
        # Mock the tracer to raise an exception after span creation
        original_create_span = shield.tracer.create_request_span
        def mock_create_span(*args, **kwargs):
            span = original_create_span(*args, **kwargs)
            # Raise error after span is created but before returning
            raise ValueError("Tracing error")
        
        shield.tracer.create_request_span = mock_create_span
        
        with pytest.raises(HTTPException) as exc_info:
            await shield._tracing_guard(request, response)
        
        assert exc_info.value.status_code == 500
        assert "Tracing setup failed" in exc_info.value.detail


@pytest.mark.skipif(not OPENTELEMETRY_AVAILABLE, reason="OpenTelemetry not available")
class TestOpenTelemetryProvider:
    """Test OpenTelemetry provider functionality."""
    
    def test_opentelemetry_provider_creation(self):
        """Test creating OpenTelemetry provider."""
        # This test only runs if OpenTelemetry is actually available
        provider = OpenTelemetryProvider("test-service")
        assert provider.tracer is not None


class TestConvenienceFunctions:
    """Test convenience shield creation functions."""
    
    def test_basic_tracing_shield(self):
        """Test basic tracing shield creation."""
        shield = request_tracing_shield(
            service_name="my-service",
            backend=TracingBackend.JAEGER,
            tracing_level=TracingLevel.DETAILED
        )
        
        assert isinstance(shield, RequestTracingShield)
        assert shield.config.service_name == "my-service"
        assert shield.config.backend == TracingBackend.JAEGER
        assert shield.config.tracing_level == TracingLevel.DETAILED
    
    def test_detailed_tracing_shield(self):
        """Test detailed tracing shield creation."""
        shield = detailed_tracing_shield(
            service_name="detailed-service",
            include_request_body=True,
            include_response_body=True,
            slow_threshold_ms=250.0
        )
        
        assert isinstance(shield, RequestTracingShield)
        assert shield.config.service_name == "detailed-service"
        assert shield.config.tracing_level == TracingLevel.DETAILED
        assert shield.config.include_request_body is True
        assert shield.config.include_response_body is True
        assert shield.config.slow_request_threshold_ms == 250.0
    
    def test_performance_tracing_shield(self):
        """Test performance tracing shield creation."""
        shield = performance_tracing_shield(
            service_name="perf-service",
            slow_threshold_ms=500.0,
            sampling_rate=0.1
        )
        
        assert isinstance(shield, RequestTracingShield)
        assert shield.config.service_name == "perf-service"
        assert shield.config.tracing_level == TracingLevel.BASIC
        assert shield.config.slow_request_threshold_ms == 500.0
        assert shield.config.sampling_rate == 0.1
        assert shield.config.include_request_body is False
        assert shield.config.include_response_body is False
    
    def test_error_tracing_shield(self):
        """Test error tracing shield creation."""
        shield = error_tracing_shield(service_name="error-service")
        
        assert isinstance(shield, RequestTracingShield)
        assert shield.config.service_name == "error-service"
        assert shield.config.tracing_level == TracingLevel.ERROR_ONLY
        assert shield.config.sampling_rate == 1.0


class TestIntegration:
    """Integration tests with FastAPI."""
    
    def test_tracing_shield_integration(self):
        """Test tracing shield integration with FastAPI."""
        app = FastAPI()
        
        shield = request_tracing_shield(
            service_name="test-app",
            tracing_level=TracingLevel.BASIC
        )
        
        @app.get("/api/test")
        @shield
        def test_endpoint():
            return {"message": "Test endpoint"}
        
        @app.get("/health")
        def health_endpoint():
            return {"status": "healthy"}
        
        client = TestClient(app)
        
        # Test traced endpoint
        response = client.get("/api/test")
        assert response.status_code == 200
        assert response.json()["message"] == "Test endpoint"
        
        # Check that spans were created
        assert len(shield.tracer.provider.spans) > 0
        
        # Test untraced endpoint
        response = client.get("/health")
        assert response.status_code == 200
    
    def test_tracing_shield_with_excluded_paths(self):
        """Test tracing shield with excluded paths."""
        app = FastAPI()
        
        shield = request_tracing_shield(
            service_name="test-app",
            excluded_paths=["/health", "/metrics"]
        )
        shield.config.excluded_paths = ["/health", "/metrics"]
        
        @app.get("/api/users")
        @shield
        def get_users():
            return {"users": []}
        
        @app.get("/health")
        @shield
        def health_check():
            return {"status": "ok"}
        
        client = TestClient(app)
        
        # Clear any existing spans
        shield.tracer.provider.clear_spans()
        
        # Test traced endpoint
        response = client.get("/api/users")
        assert response.status_code == 200
        traced_spans = len(shield.tracer.provider.spans)
        
        # Test excluded endpoint
        response = client.get("/health")
        assert response.status_code == 200
        # Should have same number of spans (health not traced)
        assert len(shield.tracer.provider.spans) == traced_spans
    
    def test_tracing_shield_error_handling(self):
        """Test tracing shield with endpoint errors."""
        app = FastAPI()
        
        shield = detailed_tracing_shield(service_name="error-test")
        
        @app.get("/api/error")
        @shield
        def error_endpoint():
            raise ValueError("Test error")
        
        client = TestClient(app)
        
        # This will trigger an exception in the endpoint, but the shield should handle tracing
        try:
            response = client.get("/api/error")
        except Exception:
            pass  # Expected to fail due to endpoint error
        
        # Check that spans were created despite the error
        assert len(shield.tracer.provider.spans) > 0


class TestEdgeCases:
    """Test edge cases and error conditions."""
    
    def test_tracer_with_zero_sampling(self):
        """Test tracer with zero sampling rate."""
        config = RequestTracingConfig(sampling_rate=0.0)
        tracer = RequestTracer(config)
        
        request = create_mock_request_with_tracing()
        
        # Should never trace with 0.0 sampling
        for _ in range(10):
            assert tracer.should_trace_request(request) is False
    
    def test_tracer_with_empty_request_body(self):
        """Test tracer with empty request body."""
        config = RequestTracingConfig(include_request_body=True)
        tracer = RequestTracer(config)
        
        span = tracer.provider.create_span("test")
        tracer.add_request_body_to_span(span, b"")
        
        # Should handle empty body gracefully
        assert span["attributes"].get("http.request.body") is None
    
    def test_tracer_with_large_request_body(self):
        """Test tracer with large request body."""
        config = RequestTracingConfig(include_request_body=True)
        tracer = RequestTracer(config)
        
        # Create a large body (over 1000 chars)
        large_body = "x" * 1500
        
        span = tracer.provider.create_span("test")
        tracer.add_request_body_to_span(span, large_body.encode('utf-8'))
        
        # Should truncate large bodies
        stored_body = span["attributes"]["http.request.body"]
        assert len(stored_body) <= 1003  # 1000 + "..."
        assert stored_body.endswith("...")
    
    def test_metrics_averaging(self):
        """Test metrics duration averaging."""
        config = RequestTracingConfig()
        tracer = RequestTracer(config)
        
        # Create first request to establish baseline
        request1 = create_mock_request_with_tracing()
        span1 = tracer.create_request_span(request1)  # This sets total_requests=1
        tracer.finish_request_span(span1, time.time() - 0.1)  # 100ms duration
        
        first_avg = tracer.metrics.average_duration_ms
        assert abs(first_avg - 100.0) < 50.0  # Allow tolerance for timing
        
        # Create second request
        request2 = create_mock_request_with_tracing()
        span2 = tracer.create_request_span(request2)  # This sets total_requests=2
        tracer.finish_request_span(span2, time.time() - 0.2)  # 200ms duration
        
        # Average should be somewhere between 100 and 200
        final_avg = tracer.metrics.average_duration_ms
        assert 100.0 < final_avg < 200.0
    
    def test_shield_with_custom_attributes(self):
        """Test shield with custom attributes."""
        config = RequestTracingConfig(
            custom_attributes={"version": "1.0", "environment": "test"}
        )
        tracer = RequestTracer(config)
        
        request = create_mock_request_with_tracing()
        span = tracer.create_request_span(request)
        
        # Should include custom attributes
        assert span["attributes"]["version"] == "1.0"
        assert span["attributes"]["environment"] == "test"
    
    def test_span_status_with_different_codes(self):
        """Test span status setting with different HTTP status codes."""
        config = RequestTracingConfig()
        tracer = RequestTracer(config)
        
        span = tracer.provider.create_span("test")
        
        # Test various status codes
        success_response = create_mock_response_with_tracing(status_code=200)
        tracer.add_response_to_span(span, success_response)
        assert span["status"] == "OK"
        
        # Test client error
        span2 = tracer.provider.create_span("test2")
        client_error_response = create_mock_response_with_tracing(status_code=404)
        tracer.add_response_to_span(span2, client_error_response)
        assert span2["status"] == "ERROR"
        
        # Test server error
        span3 = tracer.provider.create_span("test3")
        server_error_response = create_mock_response_with_tracing(status_code=500)
        tracer.add_response_to_span(span3, server_error_response)
        assert span3["status"] == "ERROR"
    
    def test_context_extraction_edge_cases(self):
        """Test context extraction edge cases."""
        provider = MockTracerProvider()
        
        # Test with malformed traceparent
        malformed_headers = {"traceparent": "invalid-format"}
        context = provider.extract_context(malformed_headers)
        assert context == "invalid-format"  # Mock just returns the value
        
        # Test with missing headers
        empty_headers = {}
        context = provider.extract_context(empty_headers)
        assert context is None
        
        # Test injection with None context
        headers = {}
        provider.inject_context(None, headers)
        assert "traceparent" not in headers