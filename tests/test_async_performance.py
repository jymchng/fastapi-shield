"""Comprehensive tests for async performance optimization."""

import asyncio
import gc
import pytest
import time
from datetime import datetime, timedelta
from typing import Dict, Any
from unittest.mock import Mock, patch, MagicMock

from fastapi import Request, HTTPException

from fastapi_shield.async_performance import (
    AsyncProfiler,
    EventLoopMonitor,
    MemoryOptimizer,
    ConcurrencyOptimizer,
    PerformanceBenchmark,
    OptimizationConfig,
    OptimizedAsyncShield,
    PerformanceLevel,
    ProfilerEvent,
    ProfilerData,
    EventLoopStats,
    MemoryStats,
    ConcurrencyStats,
    optimized_shield,
    high_performance_shield,
    lightweight_shield
)

from tests.mocks.async_performance_mocks import (
    MockAsyncShield,
    MockSyncShield,
    MockCPUIntensiveShield,
    MockIOIntensiveShield,
    MockMemoryHeavyShield,
    MockRequest,
    MockResponse,
    PerformanceTestHelper
)


class TestAsyncProfiler:
    """Tests for AsyncProfiler functionality."""
    
    def test_profiler_initialization(self):
        """Test profiler initialization."""
        profiler = AsyncProfiler(max_events=1000, enable_memory_tracking=True)
        
        assert profiler.max_events == 1000
        assert profiler.enable_memory_tracking is True
        assert len(profiler.events) == 0
        assert len(profiler.active_operations) == 0
        assert profiler._enabled is True
    
    def test_profiler_enable_disable(self):
        """Test enabling and disabling profiler."""
        profiler = AsyncProfiler()
        
        assert profiler._enabled is True
        
        profiler.disable()
        assert profiler._enabled is False
        
        profiler.enable()
        assert profiler._enabled is True
    
    @pytest.mark.asyncio
    async def test_profile_async_operation(self):
        """Test async operation profiling."""
        profiler = AsyncProfiler()
        
        async def test_operation():
            await asyncio.sleep(0.01)  # 10ms delay
            return "completed"
        
        async with profiler.profile_async_operation(
            ProfilerEvent.SHIELD_START, "test_shield", "/test"
        ):
            result = await test_operation()
        
        assert result == "completed"
        assert len(profiler.events) >= 1
        
        event = profiler.events[-1]
        assert event.shield_name == "test_shield"
        assert event.endpoint == "/test"
        assert event.duration_ms is not None
        assert event.duration_ms >= 10  # At least 10ms due to sleep
    
    def test_profile_operation_context_manager(self):
        """Test sync operation profiling context manager."""
        profiler = AsyncProfiler()
        
        def test_operation():
            time.sleep(0.01)  # 10ms delay
            return "completed"
        
        with profiler.profile_operation(
            ProfilerEvent.SHIELD_START, "test_shield", "/test"
        ):
            result = test_operation()
        
        assert result == "completed"
        assert len(profiler.events) >= 2  # start and end events
    
    def test_get_events_filtering(self):
        """Test event filtering."""
        profiler = AsyncProfiler()
        
        # Add test events
        event1 = ProfilerData(
            event=ProfilerEvent.SHIELD_START,
            timestamp=time.perf_counter(),
            shield_name="shield1",
            endpoint="/test1",
            duration_ms=10.0
        )
        
        event2 = ProfilerData(
            event=ProfilerEvent.DEPENDENCY_START,
            timestamp=time.perf_counter(),
            shield_name="shield2", 
            endpoint="/test2",
            duration_ms=20.0
        )
        
        profiler.events.extend([event1, event2])
        
        # Test filtering by shield name
        shield1_events = profiler.get_events(shield_name="shield1")
        assert len(shield1_events) == 1
        assert shield1_events[0].shield_name == "shield1"
        
        # Test filtering by event type
        shield_events = profiler.get_events(event_type=ProfilerEvent.SHIELD_START)
        assert len(shield_events) == 1
        assert shield_events[0].event == ProfilerEvent.SHIELD_START
    
    def test_get_statistics(self):
        """Test statistics calculation."""
        profiler = AsyncProfiler()
        
        # Add test events with durations
        for i in range(10):
            event = ProfilerData(
                event=ProfilerEvent.SHIELD_START,
                timestamp=time.perf_counter(),
                shield_name="test_shield",
                endpoint="/test",
                duration_ms=float(10 + i)  # 10-19ms range
            )
            profiler.events.append(event)
        
        stats = profiler.get_statistics("test_shield")
        
        assert stats["total_events"] == 10
        assert "duration_stats" in stats
        assert stats["duration_stats"]["min_ms"] == 10.0
        assert stats["duration_stats"]["max_ms"] == 19.0
        assert stats["duration_stats"]["avg_ms"] == 14.5
        assert stats["duration_stats"]["total_ms"] == 145.0
    
    def test_profiler_disabled_operations(self):
        """Test profiler behavior when disabled."""
        profiler = AsyncProfiler()
        profiler.disable()
        
        with profiler.profile_operation(
            ProfilerEvent.SHIELD_START, "test_shield", "/test"
        ):
            time.sleep(0.01)
        
        assert len(profiler.events) == 0  # No events recorded when disabled
    
    def test_clear_profiler_data(self):
        """Test clearing profiler data."""
        profiler = AsyncProfiler()
        
        # Add some test data
        event = ProfilerData(
            event=ProfilerEvent.SHIELD_START,
            timestamp=time.perf_counter(),
            shield_name="test_shield",
            endpoint="/test"
        )
        profiler.events.append(event)
        profiler.active_operations["test"] = event
        
        assert len(profiler.events) == 1
        assert len(profiler.active_operations) == 1
        
        profiler.clear()
        
        assert len(profiler.events) == 0
        assert len(profiler.active_operations) == 0


class TestEventLoopMonitor:
    """Tests for EventLoopMonitor functionality."""
    
    @pytest.mark.asyncio
    async def test_monitor_initialization(self):
        """Test monitor initialization."""
        monitor = EventLoopMonitor(monitoring_interval=0.1, max_task_duration_ms=50.0)
        
        assert monitor.monitoring_interval == 0.1
        assert monitor.max_task_duration_ms == 50.0
        assert monitor._monitoring is False
        assert len(monitor._stats_history) == 0
    
    @pytest.mark.asyncio
    async def test_start_stop_monitoring(self):
        """Test starting and stopping monitoring."""
        monitor = EventLoopMonitor(monitoring_interval=0.01)  # Very short interval for testing
        
        assert monitor._monitoring is False
        assert monitor._monitor_task is None
        
        await monitor.start_monitoring()
        assert monitor._monitoring is True
        assert monitor._monitor_task is not None
        
        # Let it run briefly
        await asyncio.sleep(0.05)
        
        await monitor.stop_monitoring()
        assert monitor._monitoring is False
    
    @pytest.mark.asyncio
    async def test_monitor_task_context_manager(self):
        """Test task monitoring context manager."""
        monitor = EventLoopMonitor()
        
        async def test_task():
            await asyncio.sleep(0.01)  # 10ms delay
        
        async with monitor.monitor_task("test_task"):
            await test_task()
        
        # Check that task duration was recorded
        assert len(monitor._task_durations) == 1
        assert monitor._task_durations[0] >= 10  # At least 10ms
    
    def test_record_operations(self):
        """Test recording different operation types."""
        monitor = EventLoopMonitor()
        
        assert monitor._blocked_operations == 0
        assert monitor._cpu_bound_operations == 0
        assert monitor._io_bound_operations == 0
        
        monitor.record_blocked_operation()
        monitor.record_cpu_bound_operation()
        monitor.record_io_bound_operation()
        
        assert monitor._blocked_operations == 1
        assert monitor._cpu_bound_operations == 1
        assert monitor._io_bound_operations == 1
    
    def test_record_task_duration(self):
        """Test task duration recording."""
        monitor = EventLoopMonitor()
        
        assert len(monitor._task_durations) == 0
        
        monitor.record_task_duration(25.5)
        monitor.record_task_duration(30.2)
        
        assert len(monitor._task_durations) == 2
        assert 25.5 in monitor._task_durations
        assert 30.2 in monitor._task_durations
    
    @pytest.mark.asyncio
    async def test_get_current_stats(self):
        """Test getting current statistics."""
        monitor = EventLoopMonitor()
        
        # Record some test data
        monitor.record_task_duration(15.0)
        monitor.record_task_duration(25.0)
        monitor.record_blocked_operation()
        monitor.record_cpu_bound_operation()
        
        stats = monitor.get_current_stats()
        
        assert isinstance(stats, EventLoopStats)
        assert stats.avg_task_duration_ms == 20.0  # (15 + 25) / 2
        assert stats.max_task_duration_ms == 25.0
        assert stats.blocked_operations >= 1
        assert stats.cpu_bound_operations >= 1
    
    def test_get_stats_history(self):
        """Test getting statistics history."""
        monitor = EventLoopMonitor()
        
        # Add some test stats
        stats1 = EventLoopStats(
            avg_task_duration_ms=10.0,
            max_task_duration_ms=20.0,
            pending_tasks=5,
            blocked_operations=1,
            cpu_bound_operations=2,
            io_bound_operations=3
        )
        
        stats2 = EventLoopStats(
            avg_task_duration_ms=15.0,
            max_task_duration_ms=30.0,
            pending_tasks=3,
            blocked_operations=0,
            cpu_bound_operations=1,
            io_bound_operations=2
        )
        
        monitor._stats_history.extend([stats1, stats2])
        
        history = monitor.get_stats_history(hours=24)
        assert len(history) == 2
        assert history[0].avg_task_duration_ms == 10.0
        assert history[1].avg_task_duration_ms == 15.0


class TestMemoryOptimizer:
    """Tests for MemoryOptimizer functionality."""
    
    @patch('fastapi_shield.async_performance.PSUTIL_AVAILABLE', True)
    @patch('psutil.Process')
    @patch('psutil.virtual_memory')
    def test_get_memory_stats(self, mock_virtual_memory, mock_process):
        """Test memory statistics collection."""
        # Mock system memory
        mock_virtual_memory.return_value = Mock()
        mock_virtual_memory.return_value.total = 8 * 1024 * 1024 * 1024  # 8GB
        mock_virtual_memory.return_value.available = 4 * 1024 * 1024 * 1024  # 4GB
        
        # Mock process memory
        mock_process_instance = Mock()
        mock_process.return_value = mock_process_instance
        mock_memory_info = Mock()
        mock_memory_info.rss = 100 * 1024 * 1024  # 100MB
        mock_process_instance.memory_info.return_value = mock_memory_info
        
        optimizer = MemoryOptimizer()
        
        with patch('gc.get_count', return_value=[10, 5, 1]):
            with patch('gc.get_objects', return_value=['a', 'b', 'c'] * 10):
                stats = optimizer.get_memory_stats()
        
        assert isinstance(stats, MemoryStats)
        assert stats.total_mb == 8192.0  # 8GB in MB
        assert stats.used_mb == 100.0  # 100MB
        assert stats.available_mb == 4096.0  # 4GB in MB
        assert stats.gc_collections == {0: 10, 1: 5, 2: 1}
    
    @patch('gc.collect')
    def test_optimize_memory(self, mock_gc_collect):
        """Test memory optimization."""
        mock_gc_collect.side_effect = [5, 3, 1]  # Return values for each generation
        
        optimizer = MemoryOptimizer()
        result = optimizer.optimize_memory()
        
        assert isinstance(result, dict)
        assert "gen_0" in result
        assert "gen_1" in result
        assert "gen_2" in result
        assert result["gen_0"] == 5
        assert result["gen_1"] == 3
        assert result["gen_2"] == 1
    
    def test_object_pool_operations(self):
        """Test object pool functionality."""
        optimizer = MemoryOptimizer(object_pool_enabled=True)
        
        # Test getting from empty pool
        obj = optimizer.get_object_from_pool(dict)
        assert obj is None
        
        # Test returning object to pool
        test_dict = {"test": "data"}
        optimizer.return_object_to_pool(test_dict)
        
        # Test getting from pool after return
        retrieved_obj = optimizer.get_object_from_pool(dict)
        assert isinstance(retrieved_obj, dict)
        assert len(retrieved_obj) == 0  # Should be cleared
    
    def test_weak_reference_cache(self):
        """Test weak reference cache functionality."""
        optimizer = MemoryOptimizer(weak_reference_cache=True)
        
        # Test cache miss
        obj = optimizer.get_from_weak_cache("test_key")
        assert obj is None
        
        # Test setting and getting from cache
        test_obj = {"cached": "data"}
        optimizer.set_in_weak_cache("test_key", test_obj)
        
        retrieved_obj = optimizer.get_from_weak_cache("test_key")
        assert retrieved_obj is test_obj
        assert retrieved_obj["cached"] == "data"
    
    def test_stats_history(self):
        """Test memory statistics history."""
        optimizer = MemoryOptimizer()
        
        # Add some mock stats
        stats1 = MemoryStats(
            total_mb=1024.0,
            used_mb=512.0,
            available_mb=512.0,
            peak_mb=600.0
        )
        
        stats2 = MemoryStats(
            total_mb=1024.0,
            used_mb=256.0,
            available_mb=768.0,
            peak_mb=600.0
        )
        
        optimizer._stats_history.extend([stats1, stats2])
        
        history = optimizer.get_stats_history(hours=24)
        assert len(history) == 2
        assert history[0].used_mb == 512.0
        assert history[1].used_mb == 256.0


class TestConcurrencyOptimizer:
    """Tests for ConcurrencyOptimizer functionality."""
    
    def test_optimizer_initialization(self):
        """Test optimizer initialization."""
        optimizer = ConcurrencyOptimizer(
            max_concurrent_requests=100,
            request_queue_size=500,
            enable_request_batching=True,
            batch_size=20,
            batch_timeout_ms=100
        )
        
        assert optimizer.max_concurrent_requests == 100
        assert optimizer.request_queue_size == 500
        assert optimizer.enable_request_batching is True
        assert optimizer.batch_size == 20
        assert optimizer.batch_timeout_ms == 100
    
    @pytest.mark.asyncio
    async def test_limit_concurrency(self):
        """Test concurrency limiting."""
        optimizer = ConcurrencyOptimizer(max_concurrent_requests=2)
        
        async def test_operation():
            await asyncio.sleep(0.01)
            return "completed"
        
        # Test single request
        async with optimizer.limit_concurrency("request_1"):
            result = await test_operation()
        
        assert result == "completed"
        assert optimizer._completed_requests == 1
        assert len(optimizer._active_requests) == 0  # Should be empty after completion
    
    @pytest.mark.asyncio
    async def test_concurrent_request_handling(self):
        """Test handling multiple concurrent requests."""
        optimizer = ConcurrencyOptimizer(max_concurrent_requests=3)
        
        async def test_request(request_id: str):
            async with optimizer.limit_concurrency(request_id):
                await asyncio.sleep(0.01)
                return f"completed_{request_id}"
        
        # Start multiple concurrent requests
        tasks = [test_request(f"req_{i}") for i in range(5)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        assert len(results) == 5
        assert all(isinstance(r, str) and r.startswith("completed_") for r in results)
        assert optimizer._completed_requests == 5
    
    @pytest.mark.asyncio
    async def test_execute_with_optimization(self):
        """Test optimized execution."""
        optimizer = ConcurrencyOptimizer(enable_request_batching=False)  # Disable batching for simpler test
        
        async def test_func(value):
            await asyncio.sleep(0.001)
            return value * 2
        
        result = await optimizer.execute_with_optimization(test_func, 5)
        assert result == 10
    
    def test_get_current_stats(self):
        """Test getting current statistics."""
        optimizer = ConcurrencyOptimizer()
        
        # Simulate some activity
        optimizer._completed_requests = 10
        optimizer._failed_requests = 2
        optimizer._max_concurrent_seen = 5
        optimizer._response_times.extend([10.0, 15.0, 20.0, 25.0])
        
        stats = optimizer.get_current_stats()
        
        assert isinstance(stats, ConcurrencyStats)
        assert stats.completed_requests == 10
        assert stats.failed_requests == 2
        assert stats.max_concurrent == 5
        assert stats.avg_response_time_ms == 17.5  # Average of response times
    
    def test_stats_history(self):
        """Test concurrency statistics history."""
        optimizer = ConcurrencyOptimizer()
        
        # Add some test stats
        stats1 = ConcurrencyStats(
            active_requests=5,
            queued_requests=2,
            completed_requests=100,
            failed_requests=5,
            avg_response_time_ms=20.0,
            max_concurrent=10
        )
        
        stats2 = ConcurrencyStats(
            active_requests=3,
            queued_requests=1,
            completed_requests=150,
            failed_requests=8,
            avg_response_time_ms=18.5,
            max_concurrent=12
        )
        
        optimizer._stats_history.extend([stats1, stats2])
        
        history = optimizer.get_stats_history(hours=24)
        assert len(history) == 2
        assert history[0].completed_requests == 100
        assert history[1].completed_requests == 150


class TestPerformanceBenchmark:
    """Tests for PerformanceBenchmark functionality."""
    
    def test_benchmark_initialization(self):
        """Test benchmark initialization."""
        benchmark = PerformanceBenchmark(
            name="test_benchmark",
            iterations=500,
            warmup_iterations=50
        )
        
        assert benchmark.name == "test_benchmark"
        assert benchmark.iterations == 500
        assert benchmark.warmup_iterations == 50
        assert len(benchmark.results) == 0
    
    @pytest.mark.asyncio
    async def test_benchmark_async_function(self):
        """Test benchmarking async function."""
        benchmark = PerformanceBenchmark("async_test", iterations=10, warmup_iterations=2)
        
        async def test_func():
            await asyncio.sleep(0.001)  # 1ms delay
            return "result"
        
        async with benchmark.benchmark_async(test_func):
            stats = benchmark.get_statistics()
        
        assert len(benchmark.results) == 10
        assert stats["name"] == "async_test"
        assert stats["iterations"] == 10
        assert stats["min_ms"] >= 1.0  # At least 1ms due to sleep
        assert stats["max_ms"] > 0
        assert stats["mean_ms"] > 0
        assert stats["ops_per_sec"] > 0
    
    def test_benchmark_sync_function(self):
        """Test benchmarking sync function."""
        benchmark = PerformanceBenchmark("sync_test", iterations=10, warmup_iterations=2)
        
        def test_func():
            time.sleep(0.001)  # 1ms delay
            return "result"
        
        with benchmark.benchmark_sync(test_func):
            stats = benchmark.get_statistics()
        
        assert len(benchmark.results) == 10
        assert stats["name"] == "sync_test"
        assert stats["iterations"] == 10
        assert stats["min_ms"] >= 1.0  # At least 1ms due to sleep
    
    def test_get_statistics_empty(self):
        """Test statistics calculation with no results."""
        benchmark = PerformanceBenchmark("empty_test")
        stats = benchmark.get_statistics()
        
        assert stats == {}
    
    def test_get_statistics_single_result(self):
        """Test statistics calculation with single result."""
        benchmark = PerformanceBenchmark("single_test")
        benchmark.results = [10.5]
        
        stats = benchmark.get_statistics()
        
        assert stats["min_ms"] == 10.5
        assert stats["max_ms"] == 10.5
        assert stats["mean_ms"] == 10.5
        assert stats["median_ms"] == 10.5
        assert stats["std_dev"] == 0.0


class TestOptimizationConfig:
    """Tests for OptimizationConfig."""
    
    def test_default_config(self):
        """Test default configuration."""
        config = OptimizationConfig()
        
        assert config.level == PerformanceLevel.BALANCED
        assert config.enable_profiling is True
        assert config.enable_event_loop_monitoring is True
        assert config.enable_memory_optimization is True
        assert config.enable_concurrency_optimization is True
    
    def test_custom_config(self):
        """Test custom configuration."""
        config = OptimizationConfig(
            level=PerformanceLevel.MAXIMUM,
            enable_profiling=False,
            max_concurrent_requests=500,
            batch_size=25
        )
        
        assert config.level == PerformanceLevel.MAXIMUM
        assert config.enable_profiling is False
        assert config.max_concurrent_requests == 500
        assert config.batch_size == 25


class TestOptimizedAsyncShield:
    """Tests for OptimizedAsyncShield functionality."""
    
    @pytest.mark.asyncio
    async def test_optimized_shield_creation(self):
        """Test creating optimized shield."""
        async def test_shield_func(request):
            await asyncio.sleep(0.001)
            return {"test": "data"}
        
        config = OptimizationConfig(level=PerformanceLevel.BALANCED)
        shield = OptimizedAsyncShield(test_shield_func, config, name="test_shield")
        
        assert shield.name == "test_shield"
        assert shield.config.level == PerformanceLevel.BALANCED
        assert shield.profiler is not None
        assert shield.event_loop_monitor is not None
        assert shield.memory_optimizer is not None
        assert shield.concurrency_optimizer is not None
    
    @pytest.mark.asyncio
    async def test_optimized_shield_execution(self):
        """Test optimized shield execution."""
        call_count = 0
        
        async def test_shield_func(request):
            nonlocal call_count
            call_count += 1
            await asyncio.sleep(0.001)
            return {"call_count": call_count}
        
        config = OptimizationConfig(level=PerformanceLevel.BALANCED)
        shield = OptimizedAsyncShield(test_shield_func, config)
        
        request = MockRequest(path="/test")
        result = await shield._optimized_shield_func(request)
        
        assert result["call_count"] == 1
        assert call_count == 1
    
    @pytest.mark.asyncio
    async def test_shield_monitoring_lifecycle(self):
        """Test shield monitoring start/stop."""
        async def test_shield_func(request):
            return {"test": "data"}
        
        config = OptimizationConfig(level=PerformanceLevel.BALANCED)
        shield = OptimizedAsyncShield(test_shield_func, config)
        
        await shield.start_monitoring()
        assert shield.event_loop_monitor._monitoring is True
        
        await shield.stop_monitoring()
        assert shield.event_loop_monitor._monitoring is False
    
    def test_get_performance_stats(self):
        """Test getting performance statistics."""
        async def test_shield_func(request):
            return {"test": "data"}
        
        config = OptimizationConfig(level=PerformanceLevel.MAXIMUM)
        shield = OptimizedAsyncShield(test_shield_func, config, name="perf_test")
        
        stats = shield.get_performance_stats()
        
        assert stats["shield_name"] == "perf_test"
        assert stats["config"]["level"] == "maximum"
        assert stats["config"]["profiling_enabled"] is True
        assert stats["config"]["event_loop_monitoring_enabled"] is True
        assert stats["config"]["memory_optimization_enabled"] is True
        assert stats["config"]["concurrency_optimization_enabled"] is True
    
    @pytest.mark.asyncio
    async def test_sync_shield_optimization(self):
        """Test optimization of sync shield functions."""
        call_count = 0
        
        def sync_shield_func(request):
            nonlocal call_count
            call_count += 1
            time.sleep(0.001)  # Small delay
            return {"call_count": call_count}
        
        config = OptimizationConfig(
            level=PerformanceLevel.BALANCED,
            enable_concurrency_optimization=True
        )
        shield = OptimizedAsyncShield(sync_shield_func, config)
        
        request = MockRequest(path="/test")
        result = await shield._optimized_shield_func(request)
        
        assert result["call_count"] == 1
        assert call_count == 1


class TestConvenienceFunctions:
    """Tests for convenience functions."""
    
    @pytest.mark.asyncio
    async def test_optimized_shield_decorator(self):
        """Test optimized_shield decorator."""
        @optimized_shield(level=PerformanceLevel.BALANCED)
        async def test_shield(request):
            return {"test": "optimized"}
        
        assert isinstance(test_shield, OptimizedAsyncShield)
        assert test_shield.config.level == PerformanceLevel.BALANCED
        
        request = MockRequest()
        result = await test_shield._optimized_shield_func(request)
        assert result["test"] == "optimized"
    
    @pytest.mark.asyncio
    async def test_high_performance_shield(self):
        """Test high_performance_shield function."""
        @high_performance_shield
        async def test_shield(request):
            return {"test": "high_performance"}
        
        assert isinstance(test_shield, OptimizedAsyncShield)
        assert test_shield.config.level == PerformanceLevel.MAXIMUM
        assert test_shield.config.enable_profiling is True
        assert test_shield.config.enable_concurrency_optimization is True
    
    @pytest.mark.asyncio
    async def test_lightweight_shield(self):
        """Test lightweight_shield function."""
        @lightweight_shield
        async def test_shield(request):
            return {"test": "lightweight"}
        
        assert isinstance(test_shield, OptimizedAsyncShield)
        assert test_shield.config.level == PerformanceLevel.MINIMAL
        assert test_shield.config.enable_profiling is False
        assert test_shield.config.enable_event_loop_monitoring is False


class TestIntegrationScenarios:
    """Integration tests for async performance optimization."""
    
    @pytest.mark.asyncio
    async def test_comprehensive_optimization_pipeline(self):
        """Test complete optimization pipeline."""
        async def complex_shield(request):
            # Simulate complex operations
            await asyncio.sleep(0.001)  # I/O operation
            
            # CPU work
            result = sum(range(1000))
            
            # Memory allocation
            data = list(range(100))
            
            return {
                "processed": True,
                "result": result,
                "data_size": len(data)
            }
        
        config = OptimizationConfig(
            level=PerformanceLevel.MAXIMUM,
            enable_profiling=True,
            enable_event_loop_monitoring=True,
            enable_memory_optimization=True,
            enable_concurrency_optimization=True
        )
        
        shield = OptimizedAsyncShield(complex_shield, config, name="complex_test")
        
        await shield.start_monitoring()
        
        # Execute multiple times to generate data
        request = MockRequest(path="/complex")
        results = []
        
        for _ in range(10):
            result = await shield._optimized_shield_func(request)
            results.append(result)
        
        await shield.stop_monitoring()
        
        # Verify results
        assert len(results) == 10
        assert all(r["processed"] for r in results)
        assert all(r["result"] == 499500 for r in results)  # sum(range(1000))
        
        # Check performance stats
        stats = shield.get_performance_stats()
        assert stats["shield_name"] == "complex_test"
        
        # Check profiler recorded events
        if shield.profiler:
            events = shield.profiler.get_events("complex_test")
            assert len(events) > 0
    
    @pytest.mark.asyncio
    async def test_performance_under_load(self):
        """Test performance optimization under load."""
        request_count = 0
        
        async def load_test_shield(request):
            nonlocal request_count
            request_count += 1
            await asyncio.sleep(0.001)  # Simulate processing
            return {"request_id": request_count}
        
        config = OptimizationConfig(
            level=PerformanceLevel.AGGRESSIVE,
            max_concurrent_requests=20,
            enable_request_batching=True,
            batch_size=5
        )
        
        shield = OptimizedAsyncShield(load_test_shield, config)
        
        # Simulate concurrent load
        semaphore = asyncio.Semaphore(10)
        
        async def make_request(req_id):
            async with semaphore:
                request = MockRequest(path=f"/test_{req_id}")
                return await shield._optimized_shield_func(request)
        
        # Execute concurrent requests
        tasks = [make_request(i) for i in range(50)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Verify all requests completed
        successful_results = [r for r in results if isinstance(r, dict)]
        assert len(successful_results) == 50
        assert request_count == 50
        
        # Check concurrency stats
        if shield.concurrency_optimizer:
            stats = shield.concurrency_optimizer.get_current_stats()
            assert stats.completed_requests >= 50
    
    @pytest.mark.asyncio
    async def test_error_handling_with_optimization(self):
        """Test error handling in optimized shields."""
        async def failing_shield(request):
            if request.url.path.endswith("fail"):
                raise HTTPException(status_code=400, detail="Test error")
            return {"success": True}
        
        config = OptimizationConfig(level=PerformanceLevel.BALANCED)
        shield = OptimizedAsyncShield(failing_shield, config)
        
        # Test successful request
        success_request = MockRequest(path="/success")
        result = await shield._optimized_shield_func(success_request)
        assert result["success"] is True
        
        # Test failing request
        fail_request = MockRequest(path="/fail")
        
        with pytest.raises(HTTPException) as exc_info:
            await shield._optimized_shield_func(fail_request)
        
        assert exc_info.value.status_code == 400
        assert exc_info.value.detail == "Test error"
    
    @pytest.mark.asyncio
    async def test_memory_optimization_effectiveness(self):
        """Test memory optimization effectiveness."""
        allocated_data = []
        
        async def memory_heavy_shield(request):
            # Allocate significant memory
            data = list(range(10000))  # Large list
            allocated_data.append(data)
            
            # Process data
            result = sum(data)
            
            return {"result": result, "data_size": len(data)}
        
        config = OptimizationConfig(
            level=PerformanceLevel.MAXIMUM,
            enable_memory_optimization=True,
            gc_threshold_mb=1.0  # Low threshold to trigger optimization
        )
        
        shield = OptimizedAsyncShield(memory_heavy_shield, config)
        
        # Execute multiple times to trigger memory optimization
        request = MockRequest(path="/memory_test")
        
        for _ in range(10):
            result = await shield._optimized_shield_func(request)
            assert result["result"] == sum(range(10000))
        
        # Check that memory optimizer was used
        if shield.memory_optimizer:
            memory_stats = shield.memory_optimizer.get_memory_stats()
            assert isinstance(memory_stats, MemoryStats)
    
    @pytest.mark.asyncio
    async def test_profiler_event_loop_integration(self):
        """Test integration between profiler and event loop monitoring."""
        async def monitored_shield(request):
            # Simulate various operations
            await asyncio.sleep(0.005)  # I/O wait
            
            # CPU work
            for _ in range(1000):
                pass
            
            # Another I/O wait
            await asyncio.sleep(0.005)
            
            return {"monitored": True}
        
        config = OptimizationConfig(
            level=PerformanceLevel.MAXIMUM,
            enable_profiling=True,
            enable_event_loop_monitoring=True,
            max_task_duration_ms=5.0  # Low threshold to detect blocking
        )
        
        shield = OptimizedAsyncShield(monitored_shield, config, name="monitored_test")
        
        await shield.start_monitoring()
        
        # Execute shield
        request = MockRequest(path="/monitored")
        result = await shield._optimized_shield_func(request)
        
        await shield.stop_monitoring()
        
        assert result["monitored"] is True
        
        # Check that both profiler and event loop monitor recorded data
        if shield.profiler:
            profiler_events = shield.profiler.get_events("monitored_test")
            assert len(profiler_events) > 0
        
        if shield.event_loop_monitor:
            event_stats = shield.event_loop_monitor.get_current_stats()
            assert isinstance(event_stats, EventLoopStats)


class TestPerformanceTestingHelpers:
    """Tests for performance testing helper utilities."""
    
    @pytest.mark.asyncio
    async def test_simulate_concurrent_requests(self):
        """Test concurrent request simulation."""
        shield = MockAsyncShield("test_shield", delay_ms=5.0)
        
        response_times = await PerformanceTestHelper.simulate_concurrent_requests(
            shield, request_count=20, concurrency=5
        )
        
        assert len(response_times) == 20
        assert all(rt >= 5.0 for rt in response_times)  # At least 5ms due to mock delay
        assert shield.call_count == 20
    
    def test_create_mixed_performance_shields(self):
        """Test creating mixed performance shields."""
        shields = PerformanceTestHelper.create_mixed_performance_shields()
        
        assert len(shields) == 6
        assert shields[0][0] == "fast_shield"
        assert shields[1][0] == "medium_shield"
        assert shields[2][0] == "slow_shield"
        assert shields[3][0] == "cpu_intensive"
        assert shields[4][0] == "io_intensive"
        assert shields[5][0] == "memory_heavy"
    
    def test_create_optimization_configs(self):
        """Test creating optimization configurations."""
        configs = PerformanceTestHelper.create_optimization_configs()
        
        assert len(configs) >= 4  # At least one for each performance level
        
        # Check that different levels are represented
        levels = {config.level for config in configs}
        assert PerformanceLevel.MINIMAL in levels
        assert PerformanceLevel.BALANCED in levels
        assert PerformanceLevel.AGGRESSIVE in levels
        assert PerformanceLevel.MAXIMUM in levels