"""Mock classes and utilities for request timeout shield testing."""

import asyncio
import time
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Callable, Tuple
from unittest.mock import Mock, AsyncMock
import logging

from fastapi_shield.request_timeout import (
    TimeoutNotifier,
    TimeoutTrigger,
    TimeoutAction,
    TimeoutGranularity,
    TimeoutConfiguration,
    TimeoutMetrics,
    ActiveRequest,
    RequestTimeoutConfig
)


class MockTimeoutNotifier(TimeoutNotifier):
    """Mock timeout notifier for testing."""
    
    def __init__(self):
        self.timeout_notifications: List[Dict[str, Any]] = []
        self.warning_notifications: List[Dict[str, Any]] = []
        self.should_fail_timeout = False
        self.should_fail_warning = False
        self.timeout_delay = 0.0
        self.warning_delay = 0.0
    
    async def notify_timeout(self, active_request: ActiveRequest, trigger: TimeoutTrigger) -> None:
        """Mock timeout notification."""
        if self.timeout_delay > 0:
            await asyncio.sleep(self.timeout_delay)
        
        if self.should_fail_timeout:
            raise Exception("Mock timeout notification failure")
        
        self.timeout_notifications.append({
            'request_id': active_request.request_id,
            'endpoint': active_request.endpoint,
            'method': active_request.method,
            'client_id': active_request.client_id,
            'duration': active_request.get_duration(),
            'trigger': trigger,
            'timestamp': time.time()
        })
    
    async def notify_warning(self, active_request: ActiveRequest) -> None:
        """Mock warning notification."""
        if self.warning_delay > 0:
            await asyncio.sleep(self.warning_delay)
        
        if self.should_fail_warning:
            raise Exception("Mock warning notification failure")
        
        self.warning_notifications.append({
            'request_id': active_request.request_id,
            'endpoint': active_request.endpoint,
            'method': active_request.method,
            'client_id': active_request.client_id,
            'duration': active_request.get_duration(),
            'timestamp': time.time()
        })
    
    def reset(self):
        """Reset notification history."""
        self.timeout_notifications = []
        self.warning_notifications = []
        self.should_fail_timeout = False
        self.should_fail_warning = False
        self.timeout_delay = 0.0
        self.warning_delay = 0.0


class MockRequest:
    """Mock FastAPI request for testing."""
    
    def __init__(
        self,
        path: str = "/test",
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        client_host: str = "127.0.0.1",
        query_params: Optional[Dict[str, str]] = None
    ):
        self.url = Mock()
        self.url.path = path
        self.method = method
        self.headers = headers or {}
        self.client = Mock()
        self.client.host = client_host
        self.query_params = query_params or {}
    
    def __repr__(self):
        return f"MockRequest({self.method} {self.url.path})"


class SlowTask:
    """Utility class for simulating slow operations in tests."""
    
    def __init__(self, duration: float, should_cancel: bool = False):
        self.duration = duration
        self.should_cancel = should_cancel
        self.start_time = None
        self.end_time = None
        self.was_cancelled = False
        self.task: Optional[asyncio.Task] = None
    
    async def __call__(self):
        """Execute the slow operation."""
        self.start_time = time.time()
        
        try:
            await asyncio.sleep(self.duration)
            self.end_time = time.time()
        except asyncio.CancelledError:
            self.was_cancelled = True
            self.end_time = time.time()
            raise
    
    def get_actual_duration(self) -> Optional[float]:
        """Get the actual duration the task ran."""
        if self.start_time is None:
            return None
        end_time = self.end_time or time.time()
        return end_time - self.start_time
    
    async def start(self) -> asyncio.Task:
        """Start the task and return it."""
        self.task = asyncio.create_task(self())
        return self.task


class TimeoutTestHelper:
    """Helper class for timeout-related testing."""
    
    @staticmethod
    def create_timeout_config(
        timeout_seconds: float = 5.0,
        trigger: TimeoutTrigger = TimeoutTrigger.REQUEST_DURATION,
        action: TimeoutAction = TimeoutAction.TERMINATE,
        endpoint_pattern: Optional[str] = None,
        http_methods: Optional[List[str]] = None,
        priority: int = 0,
        warning_threshold: Optional[float] = None,
        custom_message: Optional[str] = None
    ) -> TimeoutConfiguration:
        """Create a timeout configuration for testing."""
        return TimeoutConfiguration(
            timeout_seconds=timeout_seconds,
            trigger=trigger,
            action=action,
            endpoint_pattern=endpoint_pattern,
            http_methods=http_methods,
            priority=priority,
            warning_threshold=warning_threshold,
            custom_message=custom_message
        )
    
    @staticmethod
    def create_active_request(
        request_id: str = "test-request-123",
        endpoint: str = "/test",
        method: str = "GET",
        client_id: str = "127.0.0.1",
        timeout_seconds: float = 5.0,
        trigger: TimeoutTrigger = TimeoutTrigger.REQUEST_DURATION,
        start_time_offset: float = 0.0
    ) -> ActiveRequest:
        """Create an active request for testing."""
        request = MockRequest(path=endpoint, method=method, client_host=client_id)
        
        timeout_config = TimeoutTestHelper.create_timeout_config(
            timeout_seconds=timeout_seconds,
            trigger=trigger
        )
        
        start_time = time.time() - start_time_offset
        
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
        
        return active_request
    
    @staticmethod
    def create_expired_request(
        timeout_seconds: float = 5.0,
        expired_by: float = 1.0,
        trigger: TimeoutTrigger = TimeoutTrigger.REQUEST_DURATION
    ) -> ActiveRequest:
        """Create an active request that has already timed out."""
        return TimeoutTestHelper.create_active_request(
            timeout_seconds=timeout_seconds,
            trigger=trigger,
            start_time_offset=timeout_seconds + expired_by
        )
    
    @staticmethod
    def create_warning_request(
        timeout_seconds: float = 10.0,
        warning_threshold: float = 7.0,
        current_duration: float = 8.0
    ) -> ActiveRequest:
        """Create an active request that should trigger a warning."""
        timeout_config = TimeoutTestHelper.create_timeout_config(
            timeout_seconds=timeout_seconds,
            warning_threshold=warning_threshold
        )
        
        start_time = time.time() - current_duration
        
        active_request = ActiveRequest(
            request_id="warning-request-123",
            request=MockRequest(),
            endpoint="/test",
            method="GET",
            client_id="127.0.0.1",
            start_time=start_time,
            last_activity_time=start_time,
            timeout_config=timeout_config
        )
        
        return active_request


class MockMetricsCollector:
    """Mock metrics collector for testing timeout metrics."""
    
    def __init__(self):
        self.metrics_data: List[Tuple[str, Dict[str, Any]]] = []
        self.call_count = 0
    
    def collect_metric(self, metric_name: str, data: Dict[str, Any]):
        """Mock metric collection."""
        self.call_count += 1
        self.metrics_data.append((metric_name, data.copy()))
    
    def get_metrics_by_name(self, metric_name: str) -> List[Dict[str, Any]]:
        """Get all metrics with a specific name."""
        return [data for name, data in self.metrics_data if name == metric_name]
    
    def get_timeout_events(self) -> List[Dict[str, Any]]:
        """Get all timeout event metrics."""
        return self.get_metrics_by_name("request_timeout")
    
    def get_warning_events(self) -> List[Dict[str, Any]]:
        """Get all warning event metrics."""
        return self.get_metrics_by_name("request_timeout_warning")
    
    def reset(self):
        """Reset collected metrics."""
        self.metrics_data = []
        self.call_count = 0


class TimeoutScenarioSimulator:
    """Simulator for complex timeout scenarios in tests."""
    
    def __init__(self, shield_config: Optional[RequestTimeoutConfig] = None):
        self.shield_config = shield_config or RequestTimeoutConfig()
        self.active_requests: Dict[str, ActiveRequest] = {}
        self.completed_requests: List[Dict[str, Any]] = []
        self.timed_out_requests: List[Dict[str, Any]] = []
    
    def create_request_burst(
        self,
        count: int,
        endpoint_pattern: str = "/api/test-{}",
        timeout_seconds: float = 5.0,
        stagger_delay: float = 0.1
    ) -> List[ActiveRequest]:
        """Create a burst of concurrent requests."""
        requests = []
        base_time = time.time()
        
        for i in range(count):
            request_id = f"burst-request-{i}"
            endpoint = endpoint_pattern.format(i)
            
            # Stagger start times slightly
            start_time = base_time - (i * stagger_delay)
            
            active_request = ActiveRequest(
                request_id=request_id,
                request=MockRequest(path=endpoint),
                endpoint=endpoint,
                method="GET",
                client_id=f"client-{i % 3}",  # Simulate multiple clients
                start_time=start_time,
                last_activity_time=start_time,
                timeout_config=TimeoutTestHelper.create_timeout_config(
                    timeout_seconds=timeout_seconds
                )
            )
            
            self.active_requests[request_id] = active_request
            requests.append(active_request)
        
        return requests
    
    def simulate_mixed_workload(
        self,
        fast_requests: int = 5,
        slow_requests: int = 3,
        fast_timeout: float = 2.0,
        slow_timeout: float = 10.0
    ) -> Tuple[List[ActiveRequest], List[ActiveRequest]]:
        """Simulate a mixed workload with fast and slow requests."""
        fast_reqs = self.create_request_burst(
            fast_requests,
            endpoint_pattern="/api/fast-{}",
            timeout_seconds=fast_timeout
        )
        
        # Adjust indices for slow requests to avoid conflicts
        slow_start_index = len(self.active_requests)
        slow_reqs = []
        base_time = time.time()
        
        for i in range(slow_requests):
            request_id = f"slow-request-{i}"
            endpoint = f"/api/slow-{i}"
            
            # Stagger start times slightly
            start_time = base_time - (i * 0.1)
            
            active_request = ActiveRequest(
                request_id=request_id,
                request=MockRequest(path=endpoint),
                endpoint=endpoint,
                method="GET",
                client_id=f"client-{i % 3}",  # Simulate multiple clients
                start_time=start_time,
                last_activity_time=start_time,
                timeout_config=TimeoutTestHelper.create_timeout_config(
                    timeout_seconds=slow_timeout
                )
            )
            
            self.active_requests[request_id] = active_request
            slow_reqs.append(active_request)
        
        return fast_reqs, slow_reqs
    
    def simulate_timeout_escalation(
        self,
        base_timeout: float = 5.0,
        escalation_factor: float = 1.5,
        levels: int = 3
    ) -> List[ActiveRequest]:
        """Simulate requests with escalating timeout thresholds."""
        requests = []
        
        for level in range(levels):
            timeout = base_timeout * (escalation_factor ** level)
            
            active_request = TimeoutTestHelper.create_active_request(
                request_id=f"escalation-{level}",
                endpoint=f"/api/level-{level}",
                timeout_seconds=timeout
            )
            
            self.active_requests[active_request.request_id] = active_request
            requests.append(active_request)
        
        return requests
    
    def check_timeouts(self) -> Tuple[List[ActiveRequest], List[ActiveRequest]]:
        """Check which requests should timeout and which should warn."""
        timed_out = []
        warnings = []
        
        for active_request in self.active_requests.values():
            should_timeout, trigger = active_request.should_timeout()
            
            if should_timeout:
                timed_out.append(active_request)
                self.timed_out_requests.append({
                    'request_id': active_request.request_id,
                    'endpoint': active_request.endpoint,
                    'duration': active_request.get_duration(),
                    'trigger': trigger,
                    'timestamp': time.time()
                })
            elif active_request.should_warn():
                warnings.append(active_request)
        
        return timed_out, warnings
    
    def complete_request(self, request_id: str, duration: Optional[float] = None):
        """Mark a request as completed."""
        if request_id in self.active_requests:
            active_request = self.active_requests.pop(request_id)
            
            actual_duration = duration or active_request.get_duration()
            
            self.completed_requests.append({
                'request_id': request_id,
                'endpoint': active_request.endpoint,
                'duration': actual_duration,
                'completed_at': time.time()
            })
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get simulation statistics."""
        total_requests = len(self.completed_requests) + len(self.timed_out_requests) + len(self.active_requests)
        
        return {
            'total_requests': total_requests,
            'active_requests': len(self.active_requests),
            'completed_requests': len(self.completed_requests),
            'timed_out_requests': len(self.timed_out_requests),
            'timeout_rate': len(self.timed_out_requests) / total_requests if total_requests > 0 else 0,
            'average_completion_time': (
                sum(req['duration'] for req in self.completed_requests) / len(self.completed_requests)
                if self.completed_requests else 0
            )
        }


class ConcurrencyTestHelper:
    """Helper for testing concurrent timeout scenarios."""
    
    @staticmethod
    async def create_concurrent_requests(
        count: int,
        task_duration: float,
        timeout_seconds: float,
        start_delay: float = 0.0
    ) -> Tuple[List[asyncio.Task], List[SlowTask]]:
        """Create concurrent requests with controlled timing."""
        tasks = []
        slow_operations = []
        
        # Create and start all tasks
        for i in range(count):
            slow_op = SlowTask(task_duration)
            slow_operations.append(slow_op)
            
            # Add start delay if specified
            if start_delay > 0:
                await asyncio.sleep(start_delay)
            
            task = await slow_op.start()
            tasks.append(task)
        
        return tasks, slow_operations
    
    @staticmethod
    async def wait_for_timeout_or_completion(
        tasks: List[asyncio.Task],
        timeout_seconds: float,
        check_interval: float = 0.1
    ) -> Dict[str, List[asyncio.Task]]:
        """Wait for tasks to either complete or timeout."""
        start_time = time.time()
        completed = []
        timed_out = []
        cancelled = []
        
        while tasks and (time.time() - start_time) < timeout_seconds:
            # Check task states
            still_running = []
            
            for task in tasks:
                if task.done():
                    if task.cancelled():
                        cancelled.append(task)
                    elif task.exception():
                        # Task failed
                        timed_out.append(task)
                    else:
                        completed.append(task)
                else:
                    still_running.append(task)
            
            tasks = still_running
            
            if not tasks:
                break
            
            await asyncio.sleep(check_interval)
        
        # Cancel remaining tasks (simulating timeout)
        for task in tasks:
            if not task.done():
                task.cancel()
                timed_out.append(task)
        
        return {
            'completed': completed,
            'timed_out': timed_out,
            'cancelled': cancelled
        }
    
    @staticmethod
    async def stress_test_timeouts(
        request_count: int,
        timeout_seconds: float,
        task_duration_range: Tuple[float, float] = (1.0, 10.0),
        batch_size: int = 10
    ) -> Dict[str, Any]:
        """Perform stress testing of timeout functionality."""
        import random
        
        results = {
            'total_requests': request_count,
            'batches_processed': 0,
            'completed': 0,
            'timed_out': 0,
            'errors': 0,
            'average_duration': 0.0
        }
        
        total_duration = 0.0
        
        # Process requests in batches to avoid overwhelming the system
        for batch_start in range(0, request_count, batch_size):
            batch_end = min(batch_start + batch_size, request_count)
            batch_count = batch_end - batch_start
            
            # Create batch with random durations
            batch_durations = [
                random.uniform(*task_duration_range)
                for _ in range(batch_count)
            ]
            
            batch_tasks = []
            batch_slow_ops = []
            
            for duration in batch_durations:
                slow_op = SlowTask(duration)
                batch_slow_ops.append(slow_op)
                task = await slow_op.start()
                batch_tasks.append(task)
            
            # Wait for batch completion or timeout
            batch_results = await ConcurrencyTestHelper.wait_for_timeout_or_completion(
                batch_tasks, timeout_seconds
            )
            
            # Update results
            results['completed'] += len(batch_results['completed'])
            results['timed_out'] += len(batch_results['timed_out']) + len(batch_results['cancelled'])
            results['batches_processed'] += 1
            
            # Calculate durations
            for slow_op in batch_slow_ops:
                actual_duration = slow_op.get_actual_duration()
                if actual_duration is not None:
                    total_duration += actual_duration
        
        # Calculate average duration
        processed_requests = results['completed'] + results['timed_out']
        if processed_requests > 0:
            results['average_duration'] = total_duration / processed_requests
        
        return results


class PerformanceTestHelper:
    """Helper for performance-related timeout testing."""
    
    @staticmethod
    def measure_timeout_overhead(
        base_operation_time: float,
        timeout_check_interval: float,
        measurement_duration: float = 10.0
    ) -> Dict[str, float]:
        """Measure the overhead introduced by timeout monitoring."""
        start_time = time.time()
        operations_without_timeout = 0
        operations_with_timeout = 0
        
        # Measure baseline performance
        baseline_start = time.time()
        while time.time() - baseline_start < measurement_duration / 2:
            # Simulate operation without timeout
            time.sleep(base_operation_time)
            operations_without_timeout += 1
        
        baseline_time = time.time() - baseline_start
        
        # Measure with timeout monitoring
        timeout_start = time.time()
        while time.time() - timeout_start < measurement_duration / 2:
            # Simulate operation with timeout checking
            time.sleep(base_operation_time)
            time.sleep(timeout_check_interval)  # Simulating timeout check overhead
            operations_with_timeout += 1
        
        timeout_time = time.time() - timeout_start
        
        # Calculate metrics
        ops_per_second_baseline = operations_without_timeout / baseline_time
        ops_per_second_timeout = operations_with_timeout / timeout_time
        
        overhead_percentage = (
            ((ops_per_second_baseline - ops_per_second_timeout) / ops_per_second_baseline) * 100
            if ops_per_second_baseline > 0 else 0
        )
        
        return {
            'baseline_ops_per_second': ops_per_second_baseline,
            'timeout_ops_per_second': ops_per_second_timeout,
            'overhead_percentage': overhead_percentage,
            'absolute_overhead_seconds': timeout_check_interval,
            'operations_without_timeout': operations_without_timeout,
            'operations_with_timeout': operations_with_timeout
        }
    
    @staticmethod
    async def benchmark_timeout_detection(
        active_requests_count: int,
        check_rounds: int = 100
    ) -> Dict[str, float]:
        """Benchmark timeout detection performance."""
        # Create mock active requests
        active_requests = {}
        
        for i in range(active_requests_count):
            # Mix of timed out and active requests
            is_timed_out = i % 3 == 0  # Every 3rd request is timed out
            start_offset = 10.0 if is_timed_out else 1.0
            
            active_request = TimeoutTestHelper.create_active_request(
                request_id=f"bench-{i}",
                endpoint=f"/api/bench-{i}",
                timeout_seconds=5.0,
                start_time_offset=start_offset
            )
            
            active_requests[active_request.request_id] = active_request
        
        # Measure timeout checking performance
        start_time = time.time()
        
        timed_out_count = 0
        warning_count = 0
        
        for round_num in range(check_rounds):
            for active_request in active_requests.values():
                should_timeout, _ = active_request.should_timeout()
                if should_timeout:
                    timed_out_count += 1
                elif active_request.should_warn():
                    warning_count += 1
        
        end_time = time.time()
        
        total_checks = active_requests_count * check_rounds
        total_time = end_time - start_time
        
        return {
            'total_requests': active_requests_count,
            'check_rounds': check_rounds,
            'total_checks': total_checks,
            'total_time_seconds': total_time,
            'checks_per_second': total_checks / total_time if total_time > 0 else 0,
            'average_check_time_microseconds': (total_time / total_checks) * 1_000_000 if total_checks > 0 else 0,
            'timed_out_detections': timed_out_count,
            'warning_detections': warning_count
        }


class EdgeCaseTestHelper:
    """Helper for testing edge cases and error conditions."""
    
    @staticmethod
    def create_edge_case_requests() -> List[ActiveRequest]:
        """Create requests that test edge cases."""
        edge_cases = []
        
        # Request with zero timeout
        zero_timeout = TimeoutTestHelper.create_active_request(
            request_id="zero-timeout",
            timeout_seconds=0.0
        )
        edge_cases.append(zero_timeout)
        
        # Request with very large timeout
        huge_timeout = TimeoutTestHelper.create_active_request(
            request_id="huge-timeout",
            timeout_seconds=86400.0  # 1 day
        )
        edge_cases.append(huge_timeout)
        
        # Request with negative start time
        negative_time = TimeoutTestHelper.create_active_request(
            request_id="negative-time",
            start_time_offset=-10.0  # Started in the future?
        )
        edge_cases.append(negative_time)
        
        # Request with fractional timeout
        fractional_timeout = TimeoutTestHelper.create_active_request(
            request_id="fractional-timeout",
            timeout_seconds=0.001
        )
        edge_cases.append(fractional_timeout)
        
        return edge_cases
    
    @staticmethod
    def create_malformed_configurations() -> List[TimeoutConfiguration]:
        """Create timeout configurations that test edge cases."""
        edge_configs = []
        
        # Configuration with invalid regex pattern
        try:
            invalid_regex = TimeoutConfiguration(
                timeout_seconds=5.0,
                endpoint_pattern="[invalid regex"
            )
            edge_configs.append(invalid_regex)
        except Exception:
            pass  # Expected to fail
        
        # Configuration with empty values
        empty_config = TimeoutConfiguration(
            timeout_seconds=5.0,
            http_methods=[],
            client_patterns=[]
        )
        edge_configs.append(empty_config)
        
        # Configuration with negative priority
        negative_priority = TimeoutConfiguration(
            timeout_seconds=5.0,
            priority=-100
        )
        edge_configs.append(negative_priority)
        
        return edge_configs
    
    @staticmethod
    async def test_notification_failures(
        notifier: MockTimeoutNotifier,
        active_request: ActiveRequest,
        trigger: TimeoutTrigger
    ) -> Dict[str, bool]:
        """Test notification failure scenarios."""
        results = {}
        
        # Test timeout notification failure
        notifier.should_fail_timeout = True
        try:
            await notifier.notify_timeout(active_request, trigger)
            results['timeout_failure_handled'] = False
        except Exception:
            results['timeout_failure_handled'] = True
        finally:
            notifier.should_fail_timeout = False
        
        # Test warning notification failure
        notifier.should_fail_warning = True
        try:
            await notifier.notify_warning(active_request)
            results['warning_failure_handled'] = False
        except Exception:
            results['warning_failure_handled'] = True
        finally:
            notifier.should_fail_warning = False
        
        return results