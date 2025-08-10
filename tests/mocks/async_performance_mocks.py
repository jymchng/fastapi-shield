"""Mock classes and utilities for async performance testing."""

import asyncio
import time
from typing import Any, Dict, List, Optional, Callable
from unittest.mock import Mock, AsyncMock
from dataclasses import dataclass

from fastapi import Request, Response

from fastapi_shield.async_performance import (
    PerformanceLevel,
    OptimizationConfig,
    ProfilerEvent,
    ProfilerData,
    EventLoopStats,
    MemoryStats,
    ConcurrencyStats
)


class MockRequest:
    """Mock request for testing."""
    
    def __init__(self, method: str = "GET", path: str = "/test", 
                 headers: Dict[str, str] = None):
        self.method = method
        self.url = Mock()
        self.url.path = path
        self.headers = headers or {}
        self.state = Mock()


class MockResponse:
    """Mock response for testing."""
    
    def __init__(self, status_code: int = 200, body: bytes = b"test response"):
        self.status_code = status_code
        self.body = body


class MockAsyncShield:
    """Mock async shield for performance testing."""
    
    def __init__(self, name: str = "test_shield", delay_ms: float = 10.0, 
                 should_block: bool = False, should_fail: bool = False):
        self.name = name
        self.delay_ms = delay_ms
        self.should_block = should_block
        self.should_fail = should_fail
        self.call_count = 0
        self.execution_times = []
    
    async def __call__(self, request: Request) -> Optional[Dict[str, Any]]:
        """Mock shield execution."""
        start_time = time.perf_counter()
        self.call_count += 1
        
        if self.should_fail:
            raise RuntimeError(f"Mock shield {self.name} failed")
        
        # Simulate processing delay
        if self.should_block:
            # Simulate blocking operation (sleep without yield)
            time.sleep(self.delay_ms / 1000)
        else:
            # Proper async delay
            await asyncio.sleep(self.delay_ms / 1000)
        
        execution_time = (time.perf_counter() - start_time) * 1000
        self.execution_times.append(execution_time)
        
        if self.should_fail:
            return None
        
        return {
            "shield_name": self.name,
            "execution_time_ms": execution_time,
            "call_count": self.call_count
        }


class MockSyncShield:
    """Mock synchronous shield for testing."""
    
    def __init__(self, name: str = "sync_shield", delay_ms: float = 5.0,
                 should_fail: bool = False):
        self.name = name
        self.delay_ms = delay_ms
        self.should_fail = should_fail
        self.call_count = 0
    
    def __call__(self, request: Request) -> Optional[Dict[str, Any]]:
        """Mock sync shield execution."""
        self.call_count += 1
        
        if self.should_fail:
            raise ValueError(f"Mock sync shield {self.name} failed")
        
        # Simulate processing delay
        time.sleep(self.delay_ms / 1000)
        
        return {
            "shield_name": self.name,
            "call_count": self.call_count
        }


class MockCPUIntensiveShield:
    """Mock CPU-intensive shield for testing."""
    
    def __init__(self, name: str = "cpu_shield", iterations: int = 10000):
        self.name = name
        self.iterations = iterations
        self.call_count = 0
    
    def __call__(self, request: Request) -> Dict[str, Any]:
        """CPU-intensive shield execution."""
        self.call_count += 1
        
        # Simulate CPU-intensive work
        result = 0
        for i in range(self.iterations):
            result += i * i
        
        return {
            "shield_name": self.name,
            "result": result,
            "call_count": self.call_count
        }


class MockIOIntensiveShield:
    """Mock I/O intensive shield for testing."""
    
    def __init__(self, name: str = "io_shield", io_delay_ms: float = 50.0):
        self.name = name
        self.io_delay_ms = io_delay_ms
        self.call_count = 0
    
    async def __call__(self, request: Request) -> Dict[str, Any]:
        """I/O intensive shield execution."""
        self.call_count += 1
        
        # Simulate multiple I/O operations
        for _ in range(3):
            await asyncio.sleep(self.io_delay_ms / 3000)  # Spread delay across operations
        
        return {
            "shield_name": self.name,
            "call_count": self.call_count
        }


class MockMemoryHeavyShield:
    """Mock memory-heavy shield for testing."""
    
    def __init__(self, name: str = "memory_shield", memory_mb: float = 10.0):
        self.name = name
        self.memory_mb = memory_mb
        self.call_count = 0
        self._allocated_data = []
    
    async def __call__(self, request: Request) -> Dict[str, Any]:
        """Memory-heavy shield execution."""
        self.call_count += 1
        
        # Allocate memory (approximately)
        data_size = int(self.memory_mb * 1024 * 1024 / 8)  # Rough estimate for list of ints
        data = list(range(data_size))
        self._allocated_data.append(data)
        
        await asyncio.sleep(0.01)  # Brief processing delay
        
        # Clean up some data to simulate memory churn
        if len(self._allocated_data) > 5:
            self._allocated_data.pop(0)
        
        return {
            "shield_name": self.name,
            "allocated_mb": self.memory_mb,
            "call_count": self.call_count
        }


class MockProfiler:
    """Mock profiler for testing."""
    
    def __init__(self):
        self.events: List[ProfilerData] = []
        self.enabled = True
    
    def enable(self) -> None:
        self.enabled = True
    
    def disable(self) -> None:
        self.enabled = False
    
    def record_event(self, event: ProfilerEvent, shield_name: str, 
                    endpoint: str, duration_ms: float = None, 
                    data: Dict[str, Any] = None) -> None:
        """Record a profiler event."""
        if not self.enabled:
            return
        
        event_data = ProfilerData(
            event=event,
            timestamp=time.perf_counter(),
            shield_name=shield_name,
            endpoint=endpoint,
            duration_ms=duration_ms,
            data=data or {}
        )
        
        self.events.append(event_data)
    
    def get_events(self, shield_name: str = None) -> List[ProfilerData]:
        """Get recorded events."""
        if shield_name:
            return [e for e in self.events if e.shield_name == shield_name]
        return self.events.copy()
    
    def clear(self) -> None:
        """Clear all events."""
        self.events.clear()


class MockEventLoopMonitor:
    """Mock event loop monitor for testing."""
    
    def __init__(self):
        self.monitoring = False
        self.stats_history: List[EventLoopStats] = []
        self.task_durations: List[float] = []
        self.blocked_operations = 0
        self.cpu_bound_operations = 0
        self.io_bound_operations = 0
    
    async def start_monitoring(self) -> None:
        """Start monitoring."""
        self.monitoring = True
    
    async def stop_monitoring(self) -> None:
        """Stop monitoring."""
        self.monitoring = False
    
    def record_task_duration(self, duration_ms: float) -> None:
        """Record task duration."""
        self.task_durations.append(duration_ms)
    
    def record_blocked_operation(self) -> None:
        """Record blocked operation."""
        self.blocked_operations += 1
    
    def record_cpu_bound_operation(self) -> None:
        """Record CPU bound operation."""
        self.cpu_bound_operations += 1
    
    def record_io_bound_operation(self) -> None:
        """Record I/O bound operation."""
        self.io_bound_operations += 1
    
    def get_current_stats(self) -> EventLoopStats:
        """Get current statistics."""
        avg_duration = sum(self.task_durations) / len(self.task_durations) if self.task_durations else 0
        max_duration = max(self.task_durations) if self.task_durations else 0
        
        return EventLoopStats(
            avg_task_duration_ms=avg_duration,
            max_task_duration_ms=max_duration,
            pending_tasks=5,  # Mock value
            blocked_operations=self.blocked_operations,
            cpu_bound_operations=self.cpu_bound_operations,
            io_bound_operations=self.io_bound_operations
        )


class MockMemoryOptimizer:
    """Mock memory optimizer for testing."""
    
    def __init__(self):
        self.optimization_count = 0
        self.current_memory_mb = 50.0
        self.peak_memory_mb = 50.0
    
    def get_memory_stats(self) -> MemoryStats:
        """Get memory statistics."""
        return MemoryStats(
            total_mb=1024.0,
            used_mb=self.current_memory_mb,
            available_mb=1024.0 - self.current_memory_mb,
            peak_mb=self.peak_memory_mb,
            gc_collections={0: 10, 1: 5, 2: 1},
            object_counts={"dict": 100, "list": 50, "str": 200}
        )
    
    def optimize_memory(self) -> Dict[str, int]:
        """Perform memory optimization."""
        self.optimization_count += 1
        return {
            "gen_0": 10,
            "gen_1": 5,
            "gen_2": 1,
            "pool_dict": 20
        }
    
    def get_object_from_pool(self, obj_type: type) -> Optional[Any]:
        """Get object from pool."""
        if obj_type == dict:
            return {}
        elif obj_type == list:
            return []
        return None
    
    def return_object_to_pool(self, obj: Any) -> None:
        """Return object to pool."""
        pass  # Mock implementation


class MockConcurrencyOptimizer:
    """Mock concurrency optimizer for testing."""
    
    def __init__(self):
        self.active_requests = 0
        self.completed_requests = 0
        self.failed_requests = 0
        self.max_concurrent = 0
        self.response_times: List[float] = []
    
    async def limit_concurrency(self, request_id: str):
        """Mock concurrency limiter context manager."""
        class MockLimiter:
            def __init__(self, optimizer):
                self.optimizer = optimizer
            
            async def __aenter__(self):
                self.optimizer.active_requests += 1
                if self.optimizer.active_requests > self.optimizer.max_concurrent:
                    self.optimizer.max_concurrent = self.optimizer.active_requests
                return self
            
            async def __aexit__(self, exc_type, exc_val, exc_tb):
                self.optimizer.active_requests -= 1
                if exc_type is None:
                    self.optimizer.completed_requests += 1
                else:
                    self.optimizer.failed_requests += 1
        
        return MockLimiter(self)
    
    async def execute_with_optimization(self, func: Callable, *args, **kwargs) -> Any:
        """Execute with optimization."""
        return await func(*args, **kwargs)
    
    def get_current_stats(self) -> ConcurrencyStats:
        """Get current statistics."""
        avg_response_time = sum(self.response_times) / len(self.response_times) if self.response_times else 0
        
        return ConcurrencyStats(
            active_requests=self.active_requests,
            queued_requests=0,  # Mock value
            completed_requests=self.completed_requests,
            failed_requests=self.failed_requests,
            avg_response_time_ms=avg_response_time,
            max_concurrent=self.max_concurrent
        )


class MockOptimizedShield:
    """Mock optimized shield for testing."""
    
    def __init__(self, name: str = "optimized_shield", 
                 optimization_level: PerformanceLevel = PerformanceLevel.BALANCED):
        self.name = name
        self.optimization_level = optimization_level
        self.call_count = 0
        self.profiler = MockProfiler()
        self.event_loop_monitor = MockEventLoopMonitor()
        self.memory_optimizer = MockMemoryOptimizer()
        self.concurrency_optimizer = MockConcurrencyOptimizer()
    
    async def __call__(self, request: Request) -> Dict[str, Any]:
        """Mock optimized shield execution."""
        self.call_count += 1
        
        # Record profiler event
        self.profiler.record_event(
            ProfilerEvent.SHIELD_START, 
            self.name, 
            request.url.path,
            duration_ms=5.0
        )
        
        # Simulate optimized processing
        await asyncio.sleep(0.001)  # Very fast due to optimizations
        
        return {
            "shield_name": self.name,
            "optimization_level": self.optimization_level.value,
            "call_count": self.call_count
        }
    
    async def start_monitoring(self) -> None:
        """Start monitoring."""
        await self.event_loop_monitor.start_monitoring()
    
    async def stop_monitoring(self) -> None:
        """Stop monitoring."""
        await self.event_loop_monitor.stop_monitoring()
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics."""
        return {
            "shield_name": self.name,
            "optimization_level": self.optimization_level.value,
            "call_count": self.call_count,
            "profiler_events": len(self.profiler.events),
            "memory_optimizations": self.memory_optimizer.optimization_count,
            "completed_requests": self.concurrency_optimizer.completed_requests
        }


class PerformanceTestHelper:
    """Helper class for performance testing scenarios."""
    
    @staticmethod
    def create_load_test_shields(count: int = 5) -> List[MockAsyncShield]:
        """Create multiple shields for load testing."""
        shields = []
        for i in range(count):
            shield = MockAsyncShield(
                name=f"load_shield_{i}",
                delay_ms=10.0 + (i * 2)  # Varying delays
            )
            shields.append(shield)
        return shields
    
    @staticmethod
    def create_mixed_performance_shields() -> List[tuple]:
        """Create shields with different performance characteristics."""
        return [
            ("fast_shield", MockAsyncShield("fast", delay_ms=1.0)),
            ("medium_shield", MockAsyncShield("medium", delay_ms=10.0)),
            ("slow_shield", MockAsyncShield("slow", delay_ms=50.0)),
            ("cpu_intensive", MockCPUIntensiveShield("cpu", iterations=1000)),
            ("io_intensive", MockIOIntensiveShield("io", io_delay_ms=20.0)),
            ("memory_heavy", MockMemoryHeavyShield("memory", memory_mb=5.0))
        ]
    
    @staticmethod
    async def simulate_concurrent_requests(shield, request_count: int = 100, 
                                         concurrency: int = 10) -> List[float]:
        """Simulate concurrent requests and return response times."""
        semaphore = asyncio.Semaphore(concurrency)
        response_times = []
        
        async def make_request():
            async with semaphore:
                start_time = time.perf_counter()
                request = MockRequest()
                try:
                    await shield(request)
                    duration = (time.perf_counter() - start_time) * 1000
                    response_times.append(duration)
                except Exception:
                    # Record failed requests as high response times
                    response_times.append(5000.0)  # 5 second timeout
        
        tasks = [make_request() for _ in range(request_count)]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        return response_times
    
    @staticmethod
    def create_optimization_configs() -> List[OptimizationConfig]:
        """Create different optimization configurations for testing."""
        return [
            OptimizationConfig(level=PerformanceLevel.MINIMAL),
            OptimizationConfig(level=PerformanceLevel.BALANCED),
            OptimizationConfig(level=PerformanceLevel.AGGRESSIVE),
            OptimizationConfig(level=PerformanceLevel.MAXIMUM),
            OptimizationConfig(
                level=PerformanceLevel.BALANCED,
                enable_profiling=False,
                enable_memory_optimization=False
            ),
            OptimizationConfig(
                level=PerformanceLevel.MAXIMUM,
                max_concurrent_requests=50,
                enable_request_batching=True,
                batch_size=20
            )
        ]