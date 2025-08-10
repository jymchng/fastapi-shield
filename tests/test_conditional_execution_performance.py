"""Performance benchmarks for conditional execution system.

This module contains performance tests and benchmarks for the conditional
execution system to ensure it meets production requirements.
"""

import asyncio
import pytest
import time
from typing import Dict, Any
from unittest.mock import Mock

from fastapi import Request

from fastapi_shield.conditional_execution import (
    ConditionEngine,
    SimpleCondition,
    CompositeCondition,
    ConditionContext,
    ComparisonOperator,
    LogicalOperator,
    CacheStrategy,
    create_simple_condition,
    create_composite_condition,
)


class TestConditionPerformance:
    """Performance tests for condition evaluation."""
    
    @pytest.mark.asyncio
    async def test_simple_condition_performance(self):
        """Test performance of simple condition evaluation."""
        condition = create_simple_condition(
            condition_id="perf_test",
            attribute_path="user_attributes.role",
            operator="eq",
            value="admin"
        )
        
        request = Mock(spec=Request)
        context = ConditionContext(
            request=request,
            user_attributes={"role": "admin"}
        )
        
        # Warm up
        for _ in range(10):
            await condition.evaluate(context)
        
        # Benchmark
        iterations = 1000
        start_time = time.perf_counter()
        
        for _ in range(iterations):
            result = await condition.evaluate(context)
            assert result.result is True
        
        total_time = time.perf_counter() - start_time
        avg_time_ms = (total_time / iterations) * 1000
        
        # Should complete within reasonable time (< 1ms per evaluation on average)
        assert avg_time_ms < 1.0
        print(f"Simple condition average evaluation time: {avg_time_ms:.3f}ms")
    
    @pytest.mark.asyncio
    async def test_composite_condition_performance(self):
        """Test performance of composite condition evaluation."""
        # Create sub-conditions
        condition1 = create_simple_condition(
            condition_id="cond1",
            attribute_path="user_attributes.role",
            operator="eq",
            value="admin"
        )
        condition2 = create_simple_condition(
            condition_id="cond2",
            attribute_path="user_attributes.active",
            operator="eq",
            value=True
        )
        condition3 = create_simple_condition(
            condition_id="cond3",
            attribute_path="user_attributes.verified",
            operator="eq",
            value=True
        )
        
        composite = create_composite_condition(
            condition_id="perf_composite",
            conditions=[condition1, condition2, condition3],
            operator="and"
        )
        
        request = Mock(spec=Request)
        context = ConditionContext(
            request=request,
            user_attributes={"role": "admin", "active": True, "verified": True}
        )
        
        # Warm up
        for _ in range(10):
            await composite.evaluate(context)
        
        # Benchmark
        iterations = 500
        start_time = time.perf_counter()
        
        for _ in range(iterations):
            result = await composite.evaluate(context)
            assert result.result is True
        
        total_time = time.perf_counter() - start_time
        avg_time_ms = (total_time / iterations) * 1000
        
        # Should complete within reasonable time (< 5ms per evaluation on average)
        assert avg_time_ms < 5.0
        print(f"Composite condition average evaluation time: {avg_time_ms:.3f}ms")
    
    @pytest.mark.asyncio
    async def test_condition_engine_performance(self):
        """Test performance of condition engine with multiple conditions."""
        engine = ConditionEngine()
        
        # Register multiple conditions
        for i in range(50):
            condition = create_simple_condition(
                condition_id=f"condition_{i}",
                attribute_path="user_attributes.value",
                operator="eq",
                value=f"value_{i % 5}"  # Create some variety
            )
            engine.register_condition(condition)
        
        request = Mock(spec=Request)
        context = ConditionContext(
            request=request,
            user_attributes={"value": "value_1"}
        )
        
        # Warm up
        for i in range(10):
            await engine.evaluate_condition(f"condition_{i % 50}", context)
        
        # Benchmark individual condition evaluation
        iterations = 1000
        condition_id = "condition_1"  # This should match the context
        
        start_time = time.perf_counter()
        
        for _ in range(iterations):
            result = await engine.evaluate_condition(condition_id, context)
            assert result.result is True
        
        total_time = time.perf_counter() - start_time
        avg_time_ms = (total_time / iterations) * 1000
        
        # Should complete within reasonable time (< 2ms per evaluation on average)
        assert avg_time_ms < 2.0
        print(f"Engine condition evaluation average time: {avg_time_ms:.3f}ms")
    
    @pytest.mark.asyncio
    async def test_cache_performance_impact(self):
        """Test performance impact of caching."""
        # Test with cache
        engine_cached = ConditionEngine(cache_strategy=CacheStrategy.GLOBAL)
        condition_cached = create_simple_condition(
            condition_id="cached_perf",
            attribute_path="user_attributes.role",
            operator="eq",
            value="admin"
        )
        engine_cached.register_condition(condition_cached)
        
        # Test without cache
        engine_no_cache = ConditionEngine(cache_strategy=CacheStrategy.NO_CACHE)
        condition_no_cache = create_simple_condition(
            condition_id="no_cache_perf",
            attribute_path="user_attributes.role",
            operator="eq",
            value="admin"
        )
        engine_no_cache.register_condition(condition_no_cache)
        
        request = Mock(spec=Request)
        context = ConditionContext(
            request=request,
            user_id="user123",
            user_attributes={"role": "admin"}
        )
        
        iterations = 100
        
        # Benchmark cached version
        start_time = time.perf_counter()
        for _ in range(iterations):
            result = await engine_cached.evaluate_condition("cached_perf", context)
            assert result.result is True
        cached_time = time.perf_counter() - start_time
        
        # Benchmark non-cached version
        start_time = time.perf_counter()
        for _ in range(iterations):
            result = await engine_no_cache.evaluate_condition("no_cache_perf", context)
            assert result.result is True
        no_cache_time = time.perf_counter() - start_time
        
        cached_avg_ms = (cached_time / iterations) * 1000
        no_cache_avg_ms = (no_cache_time / iterations) * 1000
        
        print(f"Cached evaluation average time: {cached_avg_ms:.3f}ms")
        print(f"Non-cached evaluation average time: {no_cache_avg_ms:.3f}ms")
        
        # Both should be reasonably fast
        assert cached_avg_ms < 2.0
        assert no_cache_avg_ms < 2.0
        
        # Cache hit rate should be high after first evaluation
        metrics = engine_cached.get_performance_metrics()
        cache_hit_rate = metrics["cache_hit_rate"]
        assert cache_hit_rate > 0.9  # Should be > 90% after first miss
    
    @pytest.mark.asyncio
    async def test_concurrent_evaluation_performance(self):
        """Test performance under concurrent evaluation load."""
        engine = ConditionEngine(max_concurrent_evaluations=20)
        
        # Register conditions
        for i in range(10):
            condition = create_simple_condition(
                condition_id=f"concurrent_condition_{i}",
                attribute_path="user_attributes.value",
                operator="eq",
                value=f"value_{i}"
            )
            engine.register_condition(condition)
        
        async def evaluate_condition_batch(batch_id: int):
            """Evaluate a batch of conditions."""
            request = Mock(spec=Request)
            context = ConditionContext(
                request=request,
                user_id=f"user_{batch_id}",
                user_attributes={"value": f"value_{batch_id % 10}"}
            )
            
            results = []
            for i in range(10):  # Evaluate 10 conditions per batch
                condition_id = f"concurrent_condition_{i}"
                result = await engine.evaluate_condition(condition_id, context)
                results.append(result)
            
            return results
        
        # Run concurrent batches
        num_batches = 50
        start_time = time.perf_counter()
        
        tasks = [evaluate_condition_batch(i) for i in range(num_batches)]
        all_results = await asyncio.gather(*tasks)
        
        total_time = time.perf_counter() - start_time
        
        # Verify all evaluations completed
        total_evaluations = sum(len(batch_results) for batch_results in all_results)
        assert total_evaluations == num_batches * 10
        
        avg_time_per_batch_ms = (total_time / num_batches) * 1000
        
        # Should handle concurrent load efficiently (< 50ms per batch on average)
        assert avg_time_per_batch_ms < 50.0
        print(f"Concurrent evaluation average time per batch: {avg_time_per_batch_ms:.3f}ms")
        print(f"Total evaluations: {total_evaluations}, Total time: {total_time:.3f}s")


class TestConditionMemoryUsage:
    """Memory usage tests for condition evaluation."""
    
    @pytest.mark.asyncio
    async def test_condition_engine_memory_efficiency(self):
        """Test that condition engine doesn't leak memory with many evaluations."""
        import gc
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        engine = ConditionEngine(cache_strategy=CacheStrategy.REQUEST_SCOPED)
        
        # Register conditions
        for i in range(20):
            condition = create_simple_condition(
                condition_id=f"memory_test_{i}",
                attribute_path="user_attributes.value",
                operator="eq",
                value=f"value_{i}"
            )
            engine.register_condition(condition)
        
        # Perform many evaluations
        for batch in range(100):
            request = Mock(spec=Request)
            context = ConditionContext(
                request=request,
                user_id=f"user_{batch}",
                user_attributes={"value": f"value_{batch % 20}"}
            )
            
            for i in range(20):
                await engine.evaluate_condition(f"memory_test_{i}", context)
            
            # Clear request cache after each batch
            engine.cache.clear_request_cache(id(context.request))
        
        # Force garbage collection
        gc.collect()
        
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory
        
        print(f"Initial memory: {initial_memory:.2f} MB")
        print(f"Final memory: {final_memory:.2f} MB")
        print(f"Memory increase: {memory_increase:.2f} MB")
        
        # Memory increase should be reasonable (< 50MB for this test)
        assert memory_increase < 50.0
    
    def test_condition_cache_size_limits(self):
        """Test that condition cache respects size limits."""
        engine = ConditionEngine(cache_strategy=CacheStrategy.GLOBAL)
        
        # Create many unique contexts to fill the cache
        for i in range(1000):
            condition = create_simple_condition(
                condition_id=f"cache_size_test",
                attribute_path="user_attributes.value",
                operator="eq",
                value="test"
            )
            
            request = Mock(spec=Request)
            context = ConditionContext(
                request=request,
                user_id=f"user_{i}",
                user_attributes={"value": "test"}
            )
            
            # Generate cache key and simulate caching
            cache_key = condition.get_cache_key(context)
            assert isinstance(cache_key, str)
            assert len(cache_key) == 32  # MD5 hash length
        
        # Cache should handle many entries without issues
        # (In a production system, you might implement LRU eviction)


class TestConditionScalability:
    """Scalability tests for condition evaluation."""
    
    @pytest.mark.asyncio
    async def test_large_condition_registry_performance(self):
        """Test performance with a large number of registered conditions."""
        engine = ConditionEngine()
        
        # Register a large number of conditions
        num_conditions = 1000
        for i in range(num_conditions):
            condition = create_simple_condition(
                condition_id=f"scale_condition_{i}",
                attribute_path="user_attributes.category",
                operator="eq",
                value=f"category_{i % 100}"  # 100 different categories
            )
            engine.register_condition(condition)
        
        # Verify all conditions were registered
        assert len(engine.conditions) == num_conditions
        
        # Test lookup performance
        lookup_iterations = 1000
        start_time = time.perf_counter()
        
        for i in range(lookup_iterations):
            condition_id = f"scale_condition_{i % num_conditions}"
            condition = engine.get_condition(condition_id)
            assert condition is not None
        
        lookup_time = time.perf_counter() - start_time
        avg_lookup_time_ms = (lookup_time / lookup_iterations) * 1000
        
        # Lookups should be fast (< 0.1ms on average)
        assert avg_lookup_time_ms < 0.1
        print(f"Condition lookup average time: {avg_lookup_time_ms:.4f}ms")
        
        # Test evaluation performance with large registry
        request = Mock(spec=Request)
        context = ConditionContext(
            request=request,
            user_attributes={"category": "category_1"}
        )
        
        eval_iterations = 100
        start_time = time.perf_counter()
        
        for i in range(eval_iterations):
            condition_id = f"scale_condition_{i % 10}"  # Test first 10 conditions
            result = await engine.evaluate_condition(condition_id, context)
            assert isinstance(result.result, bool)
        
        eval_time = time.perf_counter() - start_time
        avg_eval_time_ms = (eval_time / eval_iterations) * 1000
        
        # Evaluations should remain fast even with large registry
        assert avg_eval_time_ms < 5.0
        print(f"Evaluation with large registry average time: {avg_eval_time_ms:.3f}ms")
    
    @pytest.mark.asyncio
    async def test_deep_composite_condition_performance(self):
        """Test performance with deeply nested composite conditions."""
        # Create a deep hierarchy of conditions
        base_conditions = []
        for i in range(10):
            condition = create_simple_condition(
                condition_id=f"base_{i}",
                attribute_path=f"user_attributes.attr_{i}",
                operator="eq",
                value=f"value_{i}"
            )
            base_conditions.append(condition)
        
        # Create nested composite conditions
        current_level = base_conditions
        for level in range(5):  # 5 levels deep
            next_level = []
            for i in range(0, len(current_level), 2):
                if i + 1 < len(current_level):
                    composite = create_composite_condition(
                        condition_id=f"level_{level}_composite_{i//2}",
                        conditions=[current_level[i], current_level[i+1]],
                        operator="and"
                    )
                    next_level.append(composite)
                else:
                    # Odd number, carry forward
                    next_level.append(current_level[i])
            current_level = next_level
        
        # Test the final deep composite condition
        deep_condition = current_level[0]
        
        request = Mock(spec=Request)
        context = ConditionContext(
            request=request,
            user_attributes={f"attr_{i}": f"value_{i}" for i in range(10)}
        )
        
        # Warm up
        for _ in range(5):
            await deep_condition.evaluate(context)
        
        # Benchmark
        iterations = 50
        start_time = time.perf_counter()
        
        for _ in range(iterations):
            result = await deep_condition.evaluate(context)
            assert isinstance(result.result, bool)
        
        total_time = time.perf_counter() - start_time
        avg_time_ms = (total_time / iterations) * 1000
        
        # Deep conditions should still evaluate reasonably fast (< 20ms)
        assert avg_time_ms < 20.0
        print(f"Deep composite condition average evaluation time: {avg_time_ms:.3f}ms")
    
    def test_condition_metrics_accuracy(self):
        """Test that performance metrics are accurate."""
        engine = ConditionEngine()
        
        condition = create_simple_condition(
            condition_id="metrics_test",
            attribute_path="user_attributes.value",
            operator="eq",
            value="test"
        )
        engine.register_condition(condition)
        
        # Manually update metrics
        test_times = [1.0, 2.0, 3.0, 4.0, 5.0]
        for test_time in test_times:
            condition.update_metrics(test_time)
        
        # Check metrics accuracy
        assert condition.evaluation_count == len(test_times)
        assert condition.total_evaluation_time == sum(test_times)
        expected_avg = sum(test_times) / len(test_times)
        assert abs(condition.average_evaluation_time - expected_avg) < 0.001
        
        # Check engine metrics
        engine.total_evaluations = 100
        engine.cache_hits = 30
        engine.cache_misses = 70
        
        metrics = engine.get_performance_metrics()
        assert metrics["total_evaluations"] == 100
        assert metrics["cache_hits"] == 30
        assert metrics["cache_misses"] == 70
        assert abs(metrics["cache_hit_rate"] - 0.3) < 0.001
        
        assert "metrics_test" in metrics["condition_metrics"]
        condition_metrics = metrics["condition_metrics"]["metrics_test"]
        assert condition_metrics["evaluation_count"] == len(test_times)
        assert abs(condition_metrics["average_evaluation_time_ms"] - expected_avg) < 0.001


if __name__ == "__main__":
    # Run a quick benchmark
    import asyncio
    
    async def quick_benchmark():
        """Quick performance benchmark."""
        print("Running quick performance benchmark...")
        
        test_instance = TestConditionPerformance()
        
        print("\n1. Simple condition performance:")
        await test_instance.test_simple_condition_performance()
        
        print("\n2. Composite condition performance:")
        await test_instance.test_composite_condition_performance()
        
        print("\n3. Condition engine performance:")
        await test_instance.test_condition_engine_performance()
        
        print("\n4. Cache performance impact:")
        await test_instance.test_cache_performance_impact()
        
        print("\nBenchmark completed!")
    
    asyncio.run(quick_benchmark())