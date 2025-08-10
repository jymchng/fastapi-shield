"""Async Shield Performance Optimization for FastAPI Shield.

This module provides comprehensive performance optimization capabilities for async shields,
including operation profiling, event loop monitoring, memory optimization, and benchmarking.
It focuses on reducing event loop blocking, improving concurrent request handling, and
optimizing resource usage.
"""

import asyncio
import gc
import inspect
import logging
import time
import weakref
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from functools import wraps
from threading import Lock, Thread
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, TypeVar, Union
from concurrent.futures import ThreadPoolExecutor

try:
    import uvloop
    UVLOOP_AVAILABLE = True
except ImportError:
    uvloop = None
    UVLOOP_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    psutil = None
    PSUTIL_AVAILABLE = False

from fastapi import HTTPException, Request, Response, status
from fastapi.dependencies.utils import is_coroutine_callable

from fastapi_shield.shield import Shield

T = TypeVar('T')

logger = logging.getLogger(__name__)


class PerformanceLevel(str, Enum):
    """Performance optimization levels."""
    MINIMAL = "minimal"
    BALANCED = "balanced"
    AGGRESSIVE = "aggressive"
    MAXIMUM = "maximum"


class OptimizationType(str, Enum):
    """Types of optimizations."""
    EVENT_LOOP = "event_loop"
    MEMORY = "memory"
    CACHING = "caching"
    CONCURRENCY = "concurrency"
    PROFILING = "profiling"


class ProfilerEvent(str, Enum):
    """Profiler event types."""
    SHIELD_START = "shield_start"
    SHIELD_END = "shield_end"
    DEPENDENCY_START = "dependency_start"
    DEPENDENCY_END = "dependency_end"
    ASYNC_WAIT_START = "async_wait_start"
    ASYNC_WAIT_END = "async_wait_end"
    MEMORY_ALLOCATION = "memory_allocation"
    EVENT_LOOP_BLOCK = "event_loop_block"


@dataclass
class PerformanceMetric:
    """Performance metric data structure."""
    name: str
    value: float
    timestamp: datetime = field(default_factory=datetime.utcnow)
    tags: Dict[str, str] = field(default_factory=dict)
    unit: str = "ms"


@dataclass
class ProfilerData:
    """Profiler event data."""
    event: ProfilerEvent
    timestamp: float
    shield_name: str
    endpoint: str
    data: Dict[str, Any] = field(default_factory=dict)
    duration_ms: Optional[float] = None
    memory_mb: Optional[float] = None


@dataclass
class EventLoopStats:
    """Event loop performance statistics."""
    avg_task_duration_ms: float
    max_task_duration_ms: float
    pending_tasks: int
    blocked_operations: int
    cpu_bound_operations: int
    io_bound_operations: int
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class MemoryStats:
    """Memory usage statistics."""
    total_mb: float
    used_mb: float
    available_mb: float
    peak_mb: float
    gc_collections: Dict[int, int] = field(default_factory=dict)
    object_counts: Dict[str, int] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ConcurrencyStats:
    """Concurrency performance statistics."""
    active_requests: int
    queued_requests: int
    completed_requests: int
    failed_requests: int
    avg_response_time_ms: float
    max_concurrent: int
    timestamp: datetime = field(default_factory=datetime.utcnow)


class AsyncProfiler:
    """High-performance async operation profiler."""
    
    def __init__(self, max_events: int = 100000, enable_memory_tracking: bool = True):
        self.max_events = max_events
        self.enable_memory_tracking = enable_memory_tracking
        self.events: deque[ProfilerData] = deque(maxlen=max_events)
        self.active_operations: Dict[str, ProfilerData] = {}
        self._lock = Lock()
        self._enabled = True
    
    def enable(self) -> None:
        """Enable the profiler."""
        self._enabled = True
    
    def disable(self) -> None:
        """Disable the profiler."""
        self._enabled = False
    
    @contextmanager
    def profile_operation(self, event: ProfilerEvent, shield_name: str, 
                         endpoint: str, data: Optional[Dict[str, Any]] = None):
        """Context manager for profiling operations."""
        if not self._enabled:
            yield
            return
        
        start_time = time.perf_counter()
        start_memory = self._get_memory_usage() if self.enable_memory_tracking else None
        
        # Use timestamp instead of task ID for sync operations
        operation_id = f"{shield_name}_{endpoint}_{int(start_time * 1000000)}"
        
        start_event = ProfilerData(
            event=event,
            timestamp=start_time,
            shield_name=shield_name,
            endpoint=endpoint,
            data=data or {},
            memory_mb=start_memory
        )
        
        with self._lock:
            self.active_operations[operation_id] = start_event
        
        try:
            yield
        finally:
            end_time = time.perf_counter()
            end_memory = self._get_memory_usage() if self.enable_memory_tracking else None
            
            duration_ms = (end_time - start_time) * 1000
            memory_delta = (end_memory - start_memory) if (start_memory and end_memory) else None
            
            end_event = ProfilerData(
                event=ProfilerEvent(event.value.replace("_start", "_end")),
                timestamp=end_time,
                shield_name=shield_name,
                endpoint=endpoint,
                data=data or {},
                duration_ms=duration_ms,
                memory_mb=memory_delta
            )
            
            with self._lock:
                self.events.extend([start_event, end_event])
                self.active_operations.pop(operation_id, None)
    
    @asynccontextmanager
    async def profile_async_operation(self, event: ProfilerEvent, shield_name: str,
                                    endpoint: str, data: Optional[Dict[str, Any]] = None):
        """Async context manager for profiling async operations."""
        if not self._enabled:
            yield
            return
        
        start_time = time.perf_counter()
        start_memory = self._get_memory_usage() if self.enable_memory_tracking else None
        
        try:
            # Track potential event loop blocking
            if event in [ProfilerEvent.SHIELD_START, ProfilerEvent.DEPENDENCY_START]:
                await asyncio.sleep(0)  # Yield control
            
            yield
            
        finally:
            end_time = time.perf_counter()
            end_memory = self._get_memory_usage() if self.enable_memory_tracking else None
            
            duration_ms = (end_time - start_time) * 1000
            memory_delta = (end_memory - start_memory) if (start_memory and end_memory) else None
            
            # Detect potential blocking
            if duration_ms > 50:  # More than 50ms might indicate blocking
                blocking_event = ProfilerData(
                    event=ProfilerEvent.EVENT_LOOP_BLOCK,
                    timestamp=end_time,
                    shield_name=shield_name,
                    endpoint=endpoint,
                    data={"blocking_duration_ms": duration_ms},
                    duration_ms=duration_ms
                )
                
                with self._lock:
                    self.events.append(blocking_event)
            
            profile_event = ProfilerData(
                event=event,
                timestamp=end_time,
                shield_name=shield_name,
                endpoint=endpoint,
                data=data or {},
                duration_ms=duration_ms,
                memory_mb=memory_delta
            )
            
            with self._lock:
                self.events.append(profile_event)
    
    def get_events(self, shield_name: Optional[str] = None, 
                  event_type: Optional[ProfilerEvent] = None,
                  since: Optional[datetime] = None) -> List[ProfilerData]:
        """Get profiler events with optional filtering."""
        with self._lock:
            events = list(self.events)
        
        filtered_events = []
        for event in events:
            if shield_name and event.shield_name != shield_name:
                continue
            if event_type and event.event != event_type:
                continue
            if since and datetime.fromtimestamp(event.timestamp) < since:
                continue
            filtered_events.append(event)
        
        return filtered_events
    
    def get_statistics(self, shield_name: Optional[str] = None) -> Dict[str, Any]:
        """Get profiler statistics."""
        events = self.get_events(shield_name)
        
        if not events:
            return {}
        
        durations = [e.duration_ms for e in events if e.duration_ms is not None]
        memory_usage = [e.memory_mb for e in events if e.memory_mb is not None]
        
        stats = {
            "total_events": len(events),
            "event_types": defaultdict(int),
            "shields": defaultdict(int),
            "endpoints": defaultdict(int),
        }
        
        for event in events:
            stats["event_types"][event.event.value] += 1
            stats["shields"][event.shield_name] += 1
            stats["endpoints"][event.endpoint] += 1
        
        if durations:
            stats["duration_stats"] = {
                "min_ms": min(durations),
                "max_ms": max(durations),
                "avg_ms": sum(durations) / len(durations),
                "total_ms": sum(durations)
            }
        
        if memory_usage:
            stats["memory_stats"] = {
                "min_mb": min(memory_usage),
                "max_mb": max(memory_usage),
                "avg_mb": sum(memory_usage) / len(memory_usage),
                "total_mb": sum(memory_usage)
            }
        
        return stats
    
    def _get_memory_usage(self) -> Optional[float]:
        """Get current memory usage in MB."""
        if not PSUTIL_AVAILABLE:
            return None
        
        try:
            process = psutil.Process()
            return process.memory_info().rss / (1024 * 1024)
        except Exception:
            return None
    
    def clear(self) -> None:
        """Clear all profiler data."""
        with self._lock:
            self.events.clear()
            self.active_operations.clear()


class EventLoopMonitor:
    """Event loop performance monitoring and optimization."""
    
    def __init__(self, monitoring_interval: float = 1.0, max_task_duration_ms: float = 100.0):
        self.monitoring_interval = monitoring_interval
        self.max_task_duration_ms = max_task_duration_ms
        self._monitoring = False
        self._stats_history: deque[EventLoopStats] = deque(maxlen=1000)
        self._task_durations: deque[float] = deque(maxlen=10000)
        self._blocked_operations = 0
        self._cpu_bound_operations = 0
        self._io_bound_operations = 0
        self._monitor_task: Optional[asyncio.Task] = None
        self._lock = Lock()
    
    async def start_monitoring(self) -> None:
        """Start event loop monitoring."""
        if self._monitoring:
            return
        
        self._monitoring = True
        self._monitor_task = asyncio.create_task(self._monitor_loop())
        logger.info("Event loop monitoring started")
    
    async def stop_monitoring(self) -> None:
        """Stop event loop monitoring."""
        if not self._monitoring:
            return
        
        self._monitoring = False
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Event loop monitoring stopped")
    
    async def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        while self._monitoring:
            try:
                stats = await self._collect_stats()
                
                with self._lock:
                    self._stats_history.append(stats)
                
                # Log warnings for performance issues
                if stats.max_task_duration_ms > self.max_task_duration_ms:
                    logger.warning(
                        f"Long-running task detected: {stats.max_task_duration_ms:.2f}ms "
                        f"(threshold: {self.max_task_duration_ms}ms)"
                    )
                
                if stats.blocked_operations > 0:
                    logger.warning(f"Detected {stats.blocked_operations} blocked operations")
                
                await asyncio.sleep(self.monitoring_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in event loop monitoring: {e}")
                await asyncio.sleep(self.monitoring_interval)
    
    async def _collect_stats(self) -> EventLoopStats:
        """Collect event loop statistics."""
        try:
            loop = asyncio.get_running_loop()
            # Get all tasks
            all_tasks = asyncio.all_tasks(loop)
            pending_tasks = len([t for t in all_tasks if not t.done()])
        except RuntimeError:
            # No running loop
            pending_tasks = 0
        
        # Calculate task duration stats
        with self._lock:
            durations = list(self._task_durations) if self._task_durations else [0.0]
            avg_duration = sum(durations) / len(durations)
            max_duration = max(durations) if durations else 0.0
            
            blocked_ops = self._blocked_operations
            cpu_bound_ops = self._cpu_bound_operations
            io_bound_ops = self._io_bound_operations
            
            # Reset counters
            self._blocked_operations = 0
            self._cpu_bound_operations = 0
            self._io_bound_operations = 0
        
        return EventLoopStats(
            avg_task_duration_ms=avg_duration,
            max_task_duration_ms=max_duration,
            pending_tasks=pending_tasks,
            blocked_operations=blocked_ops,
            cpu_bound_operations=cpu_bound_ops,
            io_bound_operations=io_bound_ops
        )
    
    def record_task_duration(self, duration_ms: float) -> None:
        """Record a task duration."""
        with self._lock:
            self._task_durations.append(duration_ms)
    
    def record_blocked_operation(self) -> None:
        """Record a blocked operation."""
        with self._lock:
            self._blocked_operations += 1
    
    def record_cpu_bound_operation(self) -> None:
        """Record a CPU-bound operation."""
        with self._lock:
            self._cpu_bound_operations += 1
    
    def record_io_bound_operation(self) -> None:
        """Record an I/O-bound operation."""
        with self._lock:
            self._io_bound_operations += 1
    
    def get_current_stats(self) -> Optional[EventLoopStats]:
        """Get the most recent event loop statistics."""
        with self._lock:
            if self._stats_history:
                return self._stats_history[-1]
        
        # If no history, create current stats
        durations = list(self._task_durations) if self._task_durations else [0.0]
        avg_duration = sum(durations) / len(durations) if durations else 0.0
        max_duration = max(durations) if durations else 0.0
        
        return EventLoopStats(
            avg_task_duration_ms=avg_duration,
            max_task_duration_ms=max_duration,
            pending_tasks=0,  # Can't determine without event loop
            blocked_operations=self._blocked_operations,
            cpu_bound_operations=self._cpu_bound_operations,
            io_bound_operations=self._io_bound_operations
        )
    
    def get_stats_history(self, hours: int = 1) -> List[EventLoopStats]:
        """Get event loop statistics history."""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        with self._lock:
            return [
                stat for stat in self._stats_history
                if stat.timestamp >= cutoff_time
            ]
    
    @asynccontextmanager
    async def monitor_task(self, task_name: str = "unknown"):
        """Context manager to monitor a specific task."""
        start_time = time.perf_counter()
        
        try:
            yield
        finally:
            duration_ms = (time.perf_counter() - start_time) * 1000
            self.record_task_duration(duration_ms)
            
            if duration_ms > self.max_task_duration_ms:
                self.record_blocked_operation()
                logger.debug(f"Task '{task_name}' took {duration_ms:.2f}ms")


class MemoryOptimizer:
    """Memory usage optimization and monitoring."""
    
    def __init__(self, 
                 gc_threshold: float = 100.0,  # MB
                 weak_reference_cache: bool = True,
                 object_pool_enabled: bool = True):
        self.gc_threshold = gc_threshold
        self.weak_reference_cache = weak_reference_cache
        self.object_pool_enabled = object_pool_enabled
        self._stats_history: deque[MemoryStats] = deque(maxlen=1000)
        self._object_pools: Dict[type, deque] = defaultdict(lambda: deque(maxlen=1000))
        # Use regular dict instead of WeakValueDictionary to avoid reference issues
        self._weak_cache: Dict[str, Any] = {}
        self._lock = Lock()
    
    def get_memory_stats(self) -> MemoryStats:
        """Get current memory statistics."""
        if not PSUTIL_AVAILABLE:
            return MemoryStats(
                total_mb=0.0,
                used_mb=0.0,
                available_mb=0.0,
                peak_mb=0.0,
                gc_collections={},
                object_counts={}
            )
        
        try:
            process = psutil.Process()
            memory_info = process.memory_info()
            system_memory = psutil.virtual_memory()
            
            # Get GC statistics
            gc_stats = {}
            for generation in range(3):
                gc_stats[generation] = gc.get_count()[generation]
            
            # Get object counts
            object_counts = {}
            for obj_type in [dict, list, tuple, set, str]:
                count = len(gc.get_objects())
                if count > 0:
                    object_counts[obj_type.__name__] = count
            
            stats = MemoryStats(
                total_mb=system_memory.total / (1024 * 1024),
                used_mb=memory_info.rss / (1024 * 1024),
                available_mb=system_memory.available / (1024 * 1024),
                peak_mb=memory_info.peak_wss / (1024 * 1024) if hasattr(memory_info, 'peak_wss') else 0.0,
                gc_collections=gc_stats,
                object_counts=object_counts
            )
            
            with self._lock:
                self._stats_history.append(stats)
            
            # Trigger GC if memory usage is high
            if stats.used_mb > self.gc_threshold:
                self.optimize_memory()
            
            return stats
            
        except Exception as e:
            logger.error(f"Error collecting memory stats: {e}")
            return MemoryStats(0.0, 0.0, 0.0, 0.0)
    
    def optimize_memory(self) -> Dict[str, int]:
        """Perform memory optimization."""
        logger.info("Starting memory optimization")
        
        # Force garbage collection
        collected = {}
        for generation in range(3):
            collected[f"gen_{generation}"] = gc.collect(generation)
        
        # Clear object pools if they're too large
        with self._lock:
            for obj_type, pool in self._object_pools.items():
                if len(pool) > 500:  # Arbitrary threshold
                    old_size = len(pool)
                    pool.clear()
                    collected[f"pool_{obj_type.__name__}"] = old_size
        
        # Clear weak reference cache
        if self.weak_reference_cache:
            old_cache_size = len(self._weak_cache)
            self._weak_cache.clear()
            collected["weak_cache"] = old_cache_size
        
        logger.info(f"Memory optimization completed: {collected}")
        return collected
    
    def get_object_from_pool(self, obj_type: type) -> Optional[Any]:
        """Get an object from the object pool."""
        if not self.object_pool_enabled:
            return None
        
        with self._lock:
            pool = self._object_pools.get(obj_type)
            if pool:
                try:
                    return pool.popleft()
                except IndexError:
                    pass
        return None
    
    def return_object_to_pool(self, obj: Any) -> None:
        """Return an object to the object pool."""
        if not self.object_pool_enabled:
            return
        
        obj_type = type(obj)
        
        # Clear the object state
        if hasattr(obj, '__dict__'):
            obj.__dict__.clear()
        elif isinstance(obj, dict):
            obj.clear()
        elif isinstance(obj, list):
            obj.clear()
        
        with self._lock:
            pool = self._object_pools[obj_type]
            if len(pool) < 1000:  # Don't let pools grow too large
                pool.append(obj)
    
    def get_from_weak_cache(self, key: str) -> Optional[Any]:
        """Get an object from weak reference cache."""
        if not self.weak_reference_cache:
            return None
        
        return self._weak_cache.get(key)
    
    def set_in_weak_cache(self, key: str, obj: Any) -> None:
        """Set an object in weak reference cache."""
        if not self.weak_reference_cache:
            return
        
        self._weak_cache[key] = obj
    
    def get_stats_history(self, hours: int = 1) -> List[MemoryStats]:
        """Get memory statistics history."""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        with self._lock:
            return [
                stat for stat in self._stats_history
                if stat.timestamp >= cutoff_time
            ]


class ConcurrencyOptimizer:
    """Concurrency optimization and monitoring."""
    
    def __init__(self,
                 max_concurrent_requests: int = 1000,
                 request_queue_size: int = 5000,
                 enable_request_batching: bool = True,
                 batch_size: int = 10,
                 batch_timeout_ms: int = 50):
        self.max_concurrent_requests = max_concurrent_requests
        self.request_queue_size = request_queue_size
        self.enable_request_batching = enable_request_batching
        self.batch_size = batch_size
        self.batch_timeout_ms = batch_timeout_ms
        
        self._active_requests: Set[str] = set()
        self._request_queue_size = request_queue_size
        self._request_queue: Optional[asyncio.Queue] = None
        self._completed_requests = 0
        self._failed_requests = 0
        self._max_concurrent_seen = 0
        self._response_times: deque[float] = deque(maxlen=10000)
        self._stats_history: deque[ConcurrencyStats] = deque(maxlen=1000)
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._lock = Lock()
        
        # Request batching
        self._batch_queue: List[Tuple[asyncio.Future, Callable, Tuple, Dict]] = []
        self._batch_lock = Lock()
        self._batch_task: Optional[asyncio.Task] = None
        self._batch_processor_started = False
    
    async def _ensure_batch_processor_started(self) -> None:
        """Ensure the batch processor is started (lazy initialization)."""
        if self.enable_request_batching and not self._batch_processor_started:
            self._batch_processor_started = True
            try:
                self._batch_task = asyncio.create_task(self._process_batches())
            except RuntimeError:
                # No event loop available, will start later
                self._batch_processor_started = False
    
    async def _process_batches(self) -> None:
        """Process request batches."""
        while True:
            try:
                # Wait for batch timeout or batch size
                await asyncio.sleep(self.batch_timeout_ms / 1000)
                
                batch_to_process = []
                with self._batch_lock:
                    if self._batch_queue:
                        batch_size = min(self.batch_size, len(self._batch_queue))
                        batch_to_process = self._batch_queue[:batch_size]
                        self._batch_queue = self._batch_queue[batch_size:]
                
                if batch_to_process:
                    await self._execute_batch(batch_to_process)
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in batch processor: {e}")
    
    async def _execute_batch(self, batch: List[Tuple[asyncio.Future, Callable, Tuple, Dict]]) -> None:
        """Execute a batch of requests."""
        tasks = []
        
        for future, func, args, kwargs in batch:
            if not future.cancelled():
                task = asyncio.create_task(self._execute_single_request(func, args, kwargs))
                tasks.append((future, task))
        
        # Wait for all tasks to complete
        if tasks:
            results = await asyncio.gather(*[task for _, task in tasks], return_exceptions=True)
            
            # Set results in futures
            for (future, _), result in zip(tasks, results):
                if not future.cancelled():
                    if isinstance(result, Exception):
                        future.set_exception(result)
                    else:
                        future.set_result(result)
    
    async def _execute_single_request(self, func: Callable, args: Tuple, kwargs: Dict) -> Any:
        """Execute a single request."""
        if is_coroutine_callable(func):
            return await func(*args, **kwargs)
        else:
            # Run sync function in thread pool to avoid blocking
            loop = asyncio.get_running_loop()
            with ThreadPoolExecutor() as executor:
                return await loop.run_in_executor(executor, func, *args, **kwargs)
    
    async def _ensure_semaphore_initialized(self) -> None:
        """Ensure semaphore and queue are initialized."""
        if self._semaphore is None:
            try:
                self._semaphore = asyncio.Semaphore(self.max_concurrent_requests)
            except RuntimeError:
                # No event loop available
                pass
        
        if self._request_queue is None:
            try:
                self._request_queue = asyncio.Queue(maxsize=self._request_queue_size)
            except RuntimeError:
                # No event loop available
                pass

    @asynccontextmanager
    async def limit_concurrency(self, request_id: str):
        """Context manager to limit request concurrency."""
        await self._ensure_semaphore_initialized()
        
        if self._semaphore is None:
            # Fallback without semaphore
            yield
            return
            
        # Acquire semaphore
        await self._semaphore.acquire()
        
        start_time = time.perf_counter()
        
        try:
            with self._lock:
                self._active_requests.add(request_id)
                current_concurrent = len(self._active_requests)
                if current_concurrent > self._max_concurrent_seen:
                    self._max_concurrent_seen = current_concurrent
            
            yield
            
            with self._lock:
                self._completed_requests += 1
                
        except Exception:
            with self._lock:
                self._failed_requests += 1
            raise
            
        finally:
            response_time_ms = (time.perf_counter() - start_time) * 1000
            
            with self._lock:
                self._active_requests.discard(request_id)
                self._response_times.append(response_time_ms)
            
            self._semaphore.release()
    
    async def execute_with_optimization(self, func: Callable, *args, **kwargs) -> Any:
        """Execute a function with concurrency optimization."""
        if not self.enable_request_batching:
            return await self._execute_single_request(func, args, kwargs)
        
        # Ensure batch processor is started
        await self._ensure_batch_processor_started()
        
        # Add to batch queue
        future = asyncio.Future()
        
        with self._batch_lock:
            self._batch_queue.append((future, func, args, kwargs))
            
            # If batch is full, trigger immediate processing
            if len(self._batch_queue) >= self.batch_size:
                batch_to_process = self._batch_queue[:self.batch_size]
                self._batch_queue = self._batch_queue[self.batch_size:]
                
                # Process batch immediately
                asyncio.create_task(self._execute_batch(batch_to_process))
        
        return await future
    
    def get_current_stats(self) -> ConcurrencyStats:
        """Get current concurrency statistics."""
        with self._lock:
            active_count = len(self._active_requests)
            queued_count = self._request_queue.qsize() if self._request_queue else 0
            completed_count = self._completed_requests
            failed_count = self._failed_requests
            max_concurrent = self._max_concurrent_seen
            
            avg_response_time = 0.0
            if self._response_times:
                avg_response_time = sum(self._response_times) / len(self._response_times)
        
        stats = ConcurrencyStats(
            active_requests=active_count,
            queued_requests=queued_count,
            completed_requests=completed_count,
            failed_requests=failed_count,
            avg_response_time_ms=avg_response_time,
            max_concurrent=max_concurrent
        )
        
        with self._lock:
            self._stats_history.append(stats)
        
        return stats
    
    def get_stats_history(self, hours: int = 1) -> List[ConcurrencyStats]:
        """Get concurrency statistics history."""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        with self._lock:
            return [
                stat for stat in self._stats_history
                if stat.timestamp >= cutoff_time
            ]


class PerformanceBenchmark:
    """Performance benchmarking framework."""
    
    def __init__(self, name: str, iterations: int = 1000, warmup_iterations: int = 100):
        self.name = name
        self.iterations = iterations
        self.warmup_iterations = warmup_iterations
        self.results: List[float] = []
        self.metadata: Dict[str, Any] = {}
    
    @asynccontextmanager
    async def benchmark_async(self, func: Callable, *args, **kwargs):
        """Benchmark an async function."""
        # Warmup
        for _ in range(self.warmup_iterations):
            if is_coroutine_callable(func):
                await func(*args, **kwargs)
            else:
                func(*args, **kwargs)
        
        # Actual benchmarking
        results = []
        for _ in range(self.iterations):
            start_time = time.perf_counter()
            
            if is_coroutine_callable(func):
                await func(*args, **kwargs)
            else:
                func(*args, **kwargs)
            
            end_time = time.perf_counter()
            results.append((end_time - start_time) * 1000)  # Convert to ms
        
        self.results = results
        yield self.get_statistics()
    
    @contextmanager
    def benchmark_sync(self, func: Callable, *args, **kwargs):
        """Benchmark a sync function."""
        # Warmup
        for _ in range(self.warmup_iterations):
            func(*args, **kwargs)
        
        # Actual benchmarking
        results = []
        for _ in range(self.iterations):
            start_time = time.perf_counter()
            func(*args, **kwargs)
            end_time = time.perf_counter()
            results.append((end_time - start_time) * 1000)  # Convert to ms
        
        self.results = results
        yield self.get_statistics()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get benchmark statistics."""
        if not self.results:
            return {}
        
        sorted_results = sorted(self.results)
        n = len(sorted_results)
        
        return {
            "name": self.name,
            "iterations": self.iterations,
            "min_ms": min(sorted_results),
            "max_ms": max(sorted_results),
            "mean_ms": sum(sorted_results) / n,
            "median_ms": sorted_results[n // 2],
            "p95_ms": sorted_results[int(n * 0.95)],
            "p99_ms": sorted_results[int(n * 0.99)],
            "std_dev": self._calculate_std_dev(sorted_results),
            "ops_per_sec": 1000 / (sum(sorted_results) / n),
            "metadata": self.metadata
        }
    
    def _calculate_std_dev(self, values: List[float]) -> float:
        """Calculate standard deviation."""
        if len(values) < 2:
            return 0.0
        
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / (len(values) - 1)
        return variance ** 0.5


@dataclass
class OptimizationConfig:
    """Configuration for async performance optimization."""
    level: PerformanceLevel = PerformanceLevel.BALANCED
    enable_profiling: bool = True
    enable_event_loop_monitoring: bool = True
    enable_memory_optimization: bool = True
    enable_concurrency_optimization: bool = True
    
    # Profiler settings
    max_profiler_events: int = 100000
    enable_memory_tracking: bool = True
    
    # Event loop monitoring settings
    monitoring_interval: float = 1.0
    max_task_duration_ms: float = 100.0
    
    # Memory optimization settings
    gc_threshold_mb: float = 100.0
    weak_reference_cache: bool = True
    object_pool_enabled: bool = True
    
    # Concurrency optimization settings
    max_concurrent_requests: int = 1000
    request_queue_size: int = 5000
    enable_request_batching: bool = True
    batch_size: int = 10
    batch_timeout_ms: int = 50


class OptimizedAsyncShield(Shield):
    """High-performance optimized async shield."""
    
    def __init__(self, 
                 shield_func: Callable,
                 config: OptimizationConfig,
                 name: str = None,
                 **shield_kwargs):
        
        self.config = config
        self.profiler = AsyncProfiler(
            max_events=config.max_profiler_events,
            enable_memory_tracking=config.enable_memory_tracking
        ) if config.enable_profiling else None
        
        self.event_loop_monitor = EventLoopMonitor(
            monitoring_interval=config.monitoring_interval,
            max_task_duration_ms=config.max_task_duration_ms
        ) if config.enable_event_loop_monitoring else None
        
        self.memory_optimizer = MemoryOptimizer(
            gc_threshold=config.gc_threshold_mb,
            weak_reference_cache=config.weak_reference_cache,
            object_pool_enabled=config.object_pool_enabled
        ) if config.enable_memory_optimization else None
        
        self.concurrency_optimizer = ConcurrencyOptimizer(
            max_concurrent_requests=config.max_concurrent_requests,
            request_queue_size=config.request_queue_size,
            enable_request_batching=config.enable_request_batching,
            batch_size=config.batch_size,
            batch_timeout_ms=config.batch_timeout_ms
        ) if config.enable_concurrency_optimization else None
        
        self._optimized_shield_func = self._optimize_shield_function(shield_func)
        
        super().__init__(
            self._optimized_shield_func,
            name=name or getattr(shield_func, '__name__', 'optimized_shield'),
            **shield_kwargs
        )
    
    async def start_monitoring(self) -> None:
        """Start all monitoring systems."""
        if self.event_loop_monitor:
            await self.event_loop_monitor.start_monitoring()
    
    async def stop_monitoring(self) -> None:
        """Stop all monitoring systems."""
        if self.event_loop_monitor:
            await self.event_loop_monitor.stop_monitoring()
    
    def _optimize_shield_function(self, shield_func: Callable) -> Callable:
        """Optimize the shield function for performance."""
        if is_coroutine_callable(shield_func):
            return self._optimize_async_shield_function(shield_func)
        else:
            return self._optimize_sync_shield_function(shield_func)
    
    def _optimize_async_shield_function(self, shield_func: Callable) -> Callable:
        """Optimize async shield function."""
        @wraps(shield_func)
        async def optimized_shield(*args, **kwargs):
            request = kwargs.get('request')
            endpoint = request.url.path if request else "unknown"
            
            # Generate unique request ID for concurrency tracking
            request_id = f"{endpoint}_{id(asyncio.current_task())}"
            
            # Apply concurrency limits
            if self.concurrency_optimizer:
                async with self.concurrency_optimizer.limit_concurrency(request_id):
                    return await self._execute_optimized_shield(
                        shield_func, endpoint, *args, **kwargs
                    )
            else:
                return await self._execute_optimized_shield(
                    shield_func, endpoint, *args, **kwargs
                )
        
        return optimized_shield
    
    def _optimize_sync_shield_function(self, shield_func: Callable) -> Callable:
        """Optimize sync shield function."""
        @wraps(shield_func)
        async def optimized_shield(*args, **kwargs):
            request = kwargs.get('request')
            endpoint = request.url.path if request else "unknown"
            
            # Generate unique request ID for concurrency tracking
            request_id = f"{endpoint}_{time.time()}"
            
            # Apply concurrency limits
            if self.concurrency_optimizer:
                async with self.concurrency_optimizer.limit_concurrency(request_id):
                    return await self._execute_optimized_shield_sync(
                        shield_func, endpoint, *args, **kwargs
                    )
            else:
                return await self._execute_optimized_shield_sync(
                    shield_func, endpoint, *args, **kwargs
                )
        
        return optimized_shield
    
    async def _execute_optimized_shield(self, shield_func: Callable, endpoint: str, 
                                      *args, **kwargs) -> Any:
        """Execute optimized async shield function."""
        # Profiling
        if self.profiler:
            async with self.profiler.profile_async_operation(
                ProfilerEvent.SHIELD_START, self.name, endpoint
            ):
                # Event loop monitoring
                if self.event_loop_monitor:
                    async with self.event_loop_monitor.monitor_task(f"shield_{self.name}"):
                        return await shield_func(*args, **kwargs)
                else:
                    return await shield_func(*args, **kwargs)
        else:
            # Event loop monitoring only
            if self.event_loop_monitor:
                async with self.event_loop_monitor.monitor_task(f"shield_{self.name}"):
                    return await shield_func(*args, **kwargs)
            else:
                return await shield_func(*args, **kwargs)
    
    async def _execute_optimized_shield_sync(self, shield_func: Callable, endpoint: str,
                                           *args, **kwargs) -> Any:
        """Execute optimized sync shield function."""
        # For sync functions, run in thread pool to avoid blocking event loop
        if self.concurrency_optimizer:
            return await self.concurrency_optimizer.execute_with_optimization(
                shield_func, *args, **kwargs
            )
        else:
            # Fallback to thread pool execution
            loop = asyncio.get_running_loop()
            with ThreadPoolExecutor() as executor:
                return await loop.run_in_executor(executor, shield_func, *args, **kwargs)
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get comprehensive performance statistics."""
        stats = {
            "shield_name": self.name,
            "config": {
                "level": self.config.level.value,
                "profiling_enabled": self.config.enable_profiling,
                "event_loop_monitoring_enabled": self.config.enable_event_loop_monitoring,
                "memory_optimization_enabled": self.config.enable_memory_optimization,
                "concurrency_optimization_enabled": self.config.enable_concurrency_optimization,
            }
        }
        
        if self.profiler:
            stats["profiler"] = self.profiler.get_statistics(self.name)
        
        if self.event_loop_monitor:
            current_stats = self.event_loop_monitor.get_current_stats()
            if current_stats:
                stats["event_loop"] = {
                    "avg_task_duration_ms": current_stats.avg_task_duration_ms,
                    "max_task_duration_ms": current_stats.max_task_duration_ms,
                    "pending_tasks": current_stats.pending_tasks,
                    "blocked_operations": current_stats.blocked_operations,
                    "cpu_bound_operations": current_stats.cpu_bound_operations,
                    "io_bound_operations": current_stats.io_bound_operations,
                }
        
        if self.memory_optimizer:
            memory_stats = self.memory_optimizer.get_memory_stats()
            stats["memory"] = {
                "used_mb": memory_stats.used_mb,
                "available_mb": memory_stats.available_mb,
                "peak_mb": memory_stats.peak_mb,
                "gc_collections": memory_stats.gc_collections,
            }
        
        if self.concurrency_optimizer:
            concurrency_stats = self.concurrency_optimizer.get_current_stats()
            stats["concurrency"] = {
                "active_requests": concurrency_stats.active_requests,
                "queued_requests": concurrency_stats.queued_requests,
                "completed_requests": concurrency_stats.completed_requests,
                "failed_requests": concurrency_stats.failed_requests,
                "avg_response_time_ms": concurrency_stats.avg_response_time_ms,
                "max_concurrent": concurrency_stats.max_concurrent,
            }
        
        return stats


# Convenience functions for creating optimized shields

def optimized_shield(
    shield_func: Optional[Callable] = None,
    /,
    level: PerformanceLevel = PerformanceLevel.BALANCED,
    enable_profiling: bool = True,
    enable_event_loop_monitoring: bool = True,
    enable_memory_optimization: bool = True,
    enable_concurrency_optimization: bool = True,
    name: str = None,
    **shield_kwargs
) -> OptimizedAsyncShield:
    """Create an optimized async shield with performance enhancements.
    
    Args:
        shield_func: The shield function to optimize
        level: Performance optimization level
        enable_profiling: Enable operation profiling
        enable_event_loop_monitoring: Enable event loop monitoring
        enable_memory_optimization: Enable memory optimization
        enable_concurrency_optimization: Enable concurrency optimization
        name: Shield name
        **shield_kwargs: Additional shield arguments
    
    Returns:
        OptimizedAsyncShield: Optimized shield instance
    """
    config = OptimizationConfig(
        level=level,
        enable_profiling=enable_profiling,
        enable_event_loop_monitoring=enable_event_loop_monitoring,
        enable_memory_optimization=enable_memory_optimization,
        enable_concurrency_optimization=enable_concurrency_optimization
    )
    
    if shield_func is None:
        return lambda func: optimized_shield(
            func, level=level, enable_profiling=enable_profiling,
            enable_event_loop_monitoring=enable_event_loop_monitoring,
            enable_memory_optimization=enable_memory_optimization,
            enable_concurrency_optimization=enable_concurrency_optimization,
            name=name, **shield_kwargs
        )
    
    return OptimizedAsyncShield(shield_func, config, name=name, **shield_kwargs)


def high_performance_shield(shield_func: Optional[Callable] = None, /, name: str = None) -> OptimizedAsyncShield:
    """Create a high-performance shield with maximum optimizations.
    
    Args:
        shield_func: The shield function to optimize
        name: Shield name
    
    Returns:
        OptimizedAsyncShield: High-performance optimized shield
    """
    return optimized_shield(
        shield_func,
        level=PerformanceLevel.MAXIMUM,
        enable_profiling=True,
        enable_event_loop_monitoring=True,
        enable_memory_optimization=True,
        enable_concurrency_optimization=True,
        name=name
    )


def lightweight_shield(shield_func: Optional[Callable] = None, /, name: str = None) -> OptimizedAsyncShield:
    """Create a lightweight shield with minimal optimizations.
    
    Args:
        shield_func: The shield function to optimize
        name: Shield name
    
    Returns:
        OptimizedAsyncShield: Lightweight optimized shield
    """
    return optimized_shield(
        shield_func,
        level=PerformanceLevel.MINIMAL,
        enable_profiling=False,
        enable_event_loop_monitoring=False,
        enable_memory_optimization=True,
        enable_concurrency_optimization=True,
        name=name
    )