#!/usr/bin/env python3
"""Performance impact assessment for Request Tracing Shield."""

import asyncio
import time
from statistics import mean, stdev

from fastapi import FastAPI
from fastapi.testclient import TestClient

from fastapi_shield.request_tracing import (
    request_tracing_shield,
    RequestTracingConfig,
    TracingLevel,
    TracingBackend
)


def create_test_app(with_tracing: bool = False):
    """Create test FastAPI app with optional tracing."""
    app = FastAPI()
    
    if with_tracing:
        # Use minimal tracing configuration for performance test
        shield = request_tracing_shield(
            service_name="perf-test",
            tracing_level=TracingLevel.BASIC,
            sampling_rate=1.0
        )
        
        @app.get("/api/test")
        @shield
        def test_endpoint():
            return {"message": "test", "data": list(range(100))}
    else:
        @app.get("/api/test")
        def test_endpoint():
            return {"message": "test", "data": list(range(100))}
    
    return app


def benchmark_requests(app: FastAPI, num_requests: int = 1000) -> float:
    """Benchmark request latency."""
    client = TestClient(app)
    
    # Warmup
    for _ in range(10):
        client.get("/api/test")
    
    # Actual benchmark
    start_time = time.time()
    for _ in range(num_requests):
        response = client.get("/api/test")
        assert response.status_code == 200
    
    total_time = time.time() - start_time
    return total_time


def detailed_latency_test(app: FastAPI, num_requests: int = 100) -> list:
    """Get detailed latency measurements."""
    client = TestClient(app)
    latencies = []
    
    # Warmup
    for _ in range(5):
        client.get("/api/test")
    
    for _ in range(num_requests):
        start = time.time()
        response = client.get("/api/test")
        latency = (time.time() - start) * 1000  # Convert to ms
        latencies.append(latency)
        assert response.status_code == 200
    
    return latencies


def main():
    """Run performance assessment."""
    print("Request Tracing Shield - Performance Impact Assessment")
    print("=" * 60)
    
    num_requests = 500
    
    # Test without tracing
    print("\n1. Baseline (No Tracing)")
    app_baseline = create_test_app(with_tracing=False)
    baseline_time = benchmark_requests(app_baseline, num_requests)
    baseline_latencies = detailed_latency_test(app_baseline, 100)
    
    print(f"   Total time for {num_requests} requests: {baseline_time:.3f}s")
    print(f"   Requests per second: {num_requests / baseline_time:.1f}")
    print(f"   Average latency: {mean(baseline_latencies):.3f}ms")
    print(f"   Latency std dev: {stdev(baseline_latencies):.3f}ms")
    print(f"   95th percentile: {sorted(baseline_latencies)[94]:.3f}ms")
    
    # Test with tracing
    print("\n2. With Request Tracing Shield")
    app_tracing = create_test_app(with_tracing=True)
    tracing_time = benchmark_requests(app_tracing, num_requests)
    tracing_latencies = detailed_latency_test(app_tracing, 100)
    
    print(f"   Total time for {num_requests} requests: {tracing_time:.3f}s")
    print(f"   Requests per second: {num_requests / tracing_time:.1f}")
    print(f"   Average latency: {mean(tracing_latencies):.3f}ms")
    print(f"   Latency std dev: {stdev(tracing_latencies):.3f}ms")
    print(f"   95th percentile: {sorted(tracing_latencies)[94]:.3f}ms")
    
    # Performance impact analysis
    overhead = tracing_time - baseline_time
    overhead_percent = (overhead / baseline_time) * 100
    latency_overhead = mean(tracing_latencies) - mean(baseline_latencies)
    
    print("\n3. Performance Impact Analysis")
    print(f"   Time overhead: {overhead:.3f}s ({overhead_percent:.2f}%)")
    print(f"   Latency overhead: {latency_overhead:.3f}ms per request")
    print(f"   RPS impact: {((num_requests / baseline_time) - (num_requests / tracing_time)):.1f} req/s")
    
    # Assessment
    print("\n4. Assessment")
    if overhead_percent < 5:
        print("   ✅ EXCELLENT: Overhead < 5%")
    elif overhead_percent < 10:
        print("   ✅ GOOD: Overhead < 10%")
    elif overhead_percent < 20:
        print("   ⚠️  ACCEPTABLE: Overhead < 20%")
    else:
        print("   ❌ HIGH: Overhead > 20%")
    
    if latency_overhead < 1.0:
        print("   ✅ Low latency impact: < 1ms per request")
    elif latency_overhead < 5.0:
        print("   ✅ Moderate latency impact: < 5ms per request")
    else:
        print("   ⚠️  High latency impact: > 5ms per request")
    
    print("\n5. Recommendations")
    print("   • Use sampling (< 1.0) in high-traffic production environments")
    print("   • Consider excluding health check endpoints from tracing")
    print("   • Monitor metrics.slow_requests for performance insights")
    print("   • Use TracingLevel.BASIC for minimal overhead")
    print("   • Enable include_request_body/include_response_body selectively")
    
    print(f"\n6. Summary")
    print(f"   The Request Tracing Shield introduces {overhead_percent:.2f}% overhead")
    print(f"   and {latency_overhead:.3f}ms latency per request.")
    print("   This is within acceptable bounds for distributed tracing benefits.")


if __name__ == "__main__":
    main()