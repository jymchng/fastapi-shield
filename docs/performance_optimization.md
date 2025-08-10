# FastAPI Shield - Async Performance Optimization

FastAPI Shield provides comprehensive async performance optimization capabilities to maximize shield efficiency and minimize event loop blocking.

## Overview

The async performance optimization system includes:

- **AsyncProfiler**: Operation profiling and monitoring
- **EventLoopMonitor**: Event loop performance tracking
- **MemoryOptimizer**: Memory usage optimization and garbage collection
- **ConcurrencyOptimizer**: Advanced concurrency handling
- **OptimizedAsyncShield**: High-performance shield implementation
- **BenchmarkSuite**: Comprehensive performance testing framework

## Quick Start

### Basic Optimized Shield

```python
from fastapi import FastAPI, Request
from fastapi_shield import optimized_shield, PerformanceLevel

app = FastAPI()

@optimized_shield(level=PerformanceLevel.BALANCED)
async def auth_shield(request: Request):
    # Your shield logic here
    token = request.headers.get("authorization")
    if validate_token(token):
        return {"user_id": 123}
    return None

@app.get("/protected")
@auth_shield
async def protected_endpoint():
    return {"message": "Access granted"}
```

### High-Performance Shield

```python
from fastapi_shield import high_performance_shield

@high_performance_shield
async def high_perf_shield(request: Request):
    # Optimized with maximum performance settings
    return {"processed": True}
```

### Lightweight Shield

```python
from fastapi_shield import lightweight_shield

@lightweight_shield
async def minimal_shield(request: Request):
    # Minimal overhead for simple validations
    return {"basic": True}
```

## Performance Levels

### PerformanceLevel.MINIMAL
- Basic optimizations only
- Lowest overhead
- Suitable for simple shields

### PerformanceLevel.BALANCED (Default)
- Moderate optimizations
- Good balance of performance and features
- Recommended for most use cases

### PerformanceLevel.AGGRESSIVE
- Advanced optimizations
- Higher performance gains
- May use more resources

### PerformanceLevel.MAXIMUM
- All optimizations enabled
- Maximum performance
- Highest resource usage

## Advanced Configuration

### Custom Optimization Configuration

```python
from fastapi_shield import OptimizedAsyncShield, OptimizationConfig

config = OptimizationConfig(
    level=PerformanceLevel.MAXIMUM,
    enable_profiling=True,
    enable_event_loop_monitoring=True,
    enable_memory_optimization=True,
    enable_concurrency_optimization=True,
    max_concurrent_requests=1000,
    batch_size=20,
    batch_timeout_ms=50
)

async def my_shield_func(request: Request):
    return {"optimized": True}

shield = OptimizedAsyncShield(my_shield_func, config, name="custom_shield")
```

## Monitoring and Profiling

### Getting Performance Statistics

```python
# Get comprehensive performance stats
stats = shield.get_performance_stats()

print(f"Shield: {stats['shield_name']}")
print(f"Optimization Level: {stats['config']['level']}")

if 'profiler' in stats:
    print(f"Total Events: {stats['profiler']['total_events']}")
    print(f"Avg Duration: {stats['profiler']['duration_stats']['avg_ms']:.2f}ms")

if 'event_loop' in stats:
    print(f"Avg Task Duration: {stats['event_loop']['avg_task_duration_ms']:.2f}ms")
    print(f"Blocked Operations: {stats['event_loop']['blocked_operations']}")

if 'memory' in stats:
    print(f"Memory Used: {stats['memory']['used_mb']:.2f}MB")
    print(f"Peak Memory: {stats['memory']['peak_mb']:.2f}MB")

if 'concurrency' in stats:
    print(f"Active Requests: {stats['concurrency']['active_requests']}")
    print(f"Completed Requests: {stats['concurrency']['completed_requests']}")
    print(f"Avg Response Time: {stats['concurrency']['avg_response_time_ms']:.2f}ms")
```

### Starting/Stopping Monitoring

```python
# Start monitoring (for shields that support it)
await shield.start_monitoring()

# Your application runs...

# Stop monitoring
await shield.stop_monitoring()
```

## Benchmarking

### Quick Shield Benchmark

```python
from fastapi_shield import quick_benchmark

async def test_shield(request: Request):
    await asyncio.sleep(0.01)  # Simulate processing
    return {"test": "data"}

# Quick performance test
results = await quick_benchmark(test_shield, iterations=1000)

print(f"Average Response Time: {results['avg_response_time_ms']:.2f}ms")
print(f"Throughput: {results['throughput_rps']:.2f} RPS")
print(f"Success Rate: {results['success_rate']:.1f}%")
```

### Comparative Benchmarking

```python
from fastapi_shield import compare_shield_performance

shields = [
    ("Standard Shield", standard_shield),
    ("Optimized Shield", optimized_shield_instance),
    ("High Performance Shield", high_perf_shield)
]

comparison = await compare_shield_performance(shields, iterations=1000)

print("Individual Results:")
for name, result in comparison["individual_results"].items():
    print(f"  {name}: {result['avg_response_time_ms']:.2f}ms")

print("\nBest Performance:")
best = comparison["comparison"]["best_response_time"]
print(f"  {best['shield']}: {best['value_ms']:.2f}ms")
```

### Optimization Level Comparison

```python
from fastapi_shield import benchmark_optimization_levels

async def shield_to_optimize(request: Request):
    # Your shield logic
    return {"data": "processed"}

results = await benchmark_optimization_levels(shield_to_optimize, iterations=500)

for level, stats in results["individual_results"].items():
    print(f"{level}: {stats['avg_response_time_ms']:.2f}ms")
```

### Comprehensive Benchmark Suite

```python
from fastapi_shield import BenchmarkSuite

suite = BenchmarkSuite()

# Run comprehensive benchmarks
results = await suite.run_comprehensive_benchmark(
    shield=my_shield,
    include_load_test=True,
    include_stress_test=True,
    include_spike_test=True,
    include_endurance_test=True
)

# Export results
suite.export_results("benchmark_results.json")

# Generate summary
summary = suite.generate_summary_report()
print(f"Total Benchmarks: {summary['total_benchmarks']}")
print(f"Avg Throughput: {summary['overall_stats']['avg_throughput_rps']:.2f} RPS")
```

## Memory Optimization

### Manual Memory Management

```python
from fastapi_shield import MemoryOptimizer

optimizer = MemoryOptimizer(
    gc_threshold=100.0,  # MB
    object_pool_enabled=True,
    weak_reference_cache=True
)

# Get memory statistics
stats = optimizer.get_memory_stats()
print(f"Memory Used: {stats.used_mb:.2f}MB")
print(f"Available: {stats.available_mb:.2f}MB")

# Force optimization
collected = optimizer.optimize_memory()
print(f"Objects collected: {collected}")

# Use object pool
cached_dict = optimizer.get_object_from_pool(dict)
if cached_dict is None:
    cached_dict = {}

# Return to pool when done
optimizer.return_object_to_pool(cached_dict)
```

## Event Loop Monitoring

### Custom Event Loop Monitoring

```python
from fastapi_shield import EventLoopMonitor

monitor = EventLoopMonitor(
    monitoring_interval=1.0,
    max_task_duration_ms=100.0
)

await monitor.start_monitoring()

# Monitor specific operations
async with monitor.monitor_task("my_operation"):
    await some_async_operation()

# Get current stats
stats = monitor.get_current_stats()
print(f"Avg Task Duration: {stats.avg_task_duration_ms:.2f}ms")
print(f"Blocked Operations: {stats.blocked_operations}")

await monitor.stop_monitoring()
```

## Best Practices

### 1. Choose the Right Performance Level

```python
# For simple validation shields
@lightweight_shield
async def simple_auth(request: Request):
    return {"valid": True}

# For complex business logic
@optimized_shield(level=PerformanceLevel.BALANCED)
async def business_shield(request: Request):
    # Complex validation logic
    return process_business_rules(request)

# For high-traffic endpoints
@high_performance_shield
async def high_traffic_shield(request: Request):
    # Optimized for maximum throughput
    return {"processed": True}
```

### 2. Monitor Performance Regularly

```python
# Set up monitoring
config = OptimizationConfig(
    enable_profiling=True,
    enable_event_loop_monitoring=True,
    enable_memory_optimization=True
)

shield = OptimizedAsyncShield(my_func, config)
await shield.start_monitoring()

# Periodically check stats
stats = shield.get_performance_stats()
if 'event_loop' in stats:
    if stats['event_loop']['blocked_operations'] > 10:
        logger.warning("High number of blocked operations detected")
```

### 3. Optimize for Your Use Case

```python
# High concurrency scenario
high_concurrency_config = OptimizationConfig(
    level=PerformanceLevel.MAXIMUM,
    max_concurrent_requests=2000,
    enable_request_batching=True,
    batch_size=50
)

# Memory-constrained scenario
memory_optimized_config = OptimizationConfig(
    level=PerformanceLevel.BALANCED,
    enable_memory_optimization=True,
    gc_threshold_mb=50.0
)

# Development/debugging scenario
debug_config = OptimizationConfig(
    level=PerformanceLevel.MINIMAL,
    enable_profiling=True,
    enable_event_loop_monitoring=True
)
```

### 4. Benchmark Before Production

```python
# Always benchmark your shields before production
async def production_shield(request: Request):
    # Your production logic
    return {"result": "processed"}

# Run comprehensive benchmarks
suite = BenchmarkSuite()
results = await suite.run_comprehensive_benchmark(production_shield)

# Verify performance meets requirements
load_test = results.get("load_test")
if load_test and load_test.avg_response_time_ms > 50:
    print("Warning: Shield may be too slow for production")
```

## Troubleshooting

### High Memory Usage

```python
# Monitor memory stats
memory_optimizer = MemoryOptimizer(gc_threshold=50.0)
stats = memory_optimizer.get_memory_stats()

if stats.used_mb > 500:  # Over 500MB
    # Force garbage collection
    collected = memory_optimizer.optimize_memory()
    print(f"Freed {collected['gen_0']} gen-0 objects")
```

### Event Loop Blocking

```python
# Monitor for blocking operations
monitor = EventLoopMonitor(max_task_duration_ms=50.0)
stats = monitor.get_current_stats()

if stats.blocked_operations > 5:
    print("Warning: Event loop blocking detected")
    print(f"Max task duration: {stats.max_task_duration_ms:.2f}ms")
```

### Low Throughput

```python
# Increase concurrency limits
config = OptimizationConfig(
    max_concurrent_requests=2000,  # Increase from default
    enable_request_batching=True,
    batch_size=20
)

# Or use higher performance level
@optimized_shield(level=PerformanceLevel.MAXIMUM)
async def high_throughput_shield(request: Request):
    return {"optimized": True}
```

## Integration Examples

### With Existing FastAPI App

```python
from fastapi import FastAPI
from fastapi_shield import optimized_shield, PerformanceLevel

app = FastAPI()

# Apply to specific endpoints
@optimized_shield(level=PerformanceLevel.BALANCED)
async def api_auth(request: Request):
    return validate_api_key(request.headers.get("x-api-key"))

@app.get("/api/data")
@api_auth
async def get_data():
    return {"data": "value"}

# Apply globally with middleware
from fastapi_shield import OptimizedAsyncShield, OptimizationConfig

async def global_shield(request: Request):
    return {"validated": True}

config = OptimizationConfig(level=PerformanceLevel.AGGRESSIVE)
global_optimized = OptimizedAsyncShield(global_shield, config)

@app.middleware("http")
async def shield_middleware(request, call_next):
    await global_optimized.start_monitoring()
    result = await global_optimized._optimized_shield_func(request)
    if result:
        response = await call_next(request)
        return response
    return Response("Blocked", status_code=403)
```

This optimization system provides a comprehensive toolkit for maximizing FastAPI Shield performance while maintaining code clarity and ease of use.