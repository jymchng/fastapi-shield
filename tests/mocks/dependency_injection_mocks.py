"""Mock classes for dependency injection testing."""

import asyncio
import time
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Callable, Type
from unittest.mock import Mock, AsyncMock

from fastapi_shield.dependency_injection import (
    DependencyMetadata, DependencyInstance, InjectionContext,
    DependencyScope, CacheStrategy, LifecyclePhase, DependencyState,
    DependencyError, CircularDependencyError, DependencyNotFoundError
)


class MockDependency:
    """Mock dependency class for testing."""
    
    def __init__(self, name: str = "MockDependency", value: Any = "mock_value"):
        self.name = name
        self.value = value
        self.creation_time = datetime.now()
        self.call_count = 0
        self.disposed = False
    
    def __call__(self):
        self.call_count += 1
        return self.value
    
    def dispose(self):
        self.disposed = True
    
    def health_check(self):
        return not self.disposed


class MockAsyncDependency:
    """Mock async dependency class for testing."""
    
    def __init__(self, name: str = "MockAsyncDependency", value: Any = "mock_async_value"):
        self.name = name
        self.value = value
        self.creation_time = datetime.now()
        self.call_count = 0
        self.disposed = False
    
    async def __call__(self):
        await asyncio.sleep(0.01)  # Simulate async work
        self.call_count += 1
        return self.value
    
    async def dispose(self):
        await asyncio.sleep(0.01)
        self.disposed = True
    
    def health_check(self):
        return not self.disposed


class MockDependencyWithDeps:
    """Mock dependency that depends on other dependencies."""
    
    def __init__(self, dep1: MockDependency, dep2: MockDependency):
        self.dep1 = dep1
        self.dep2 = dep2
        self.value = f"combined:{dep1.value}:{dep2.value}"
        self.creation_time = datetime.now()


class MockFailingDependency:
    """Mock dependency that can be configured to fail."""
    
    def __init__(self, should_fail: bool = False, failure_message: str = "Mock failure"):
        self.should_fail = should_fail
        self.failure_message = failure_message
        self.call_count = 0
    
    def __call__(self):
        self.call_count += 1
        if self.should_fail:
            raise Exception(self.failure_message)
        return "success"
    
    def set_should_fail(self, should_fail: bool):
        self.should_fail = should_fail


class MockSlowDependency:
    """Mock dependency with configurable delay."""
    
    def __init__(self, delay_seconds: float = 0.1, value: Any = "slow_value"):
        self.delay_seconds = delay_seconds
        self.value = value
        self.call_count = 0
    
    async def __call__(self):
        await asyncio.sleep(self.delay_seconds)
        self.call_count += 1
        return self.value


class MockDependencyRegistry:
    """Mock dependency registry for testing."""
    
    def __init__(self):
        self._dependencies: Dict[str, DependencyMetadata] = {}
        self._instances: Dict[str, DependencyInstance] = {}
        self.lifecycle_hooks: Dict[LifecyclePhase, List[Callable]] = {}
        self.circular_dependencies: List[List[str]] = []
        self.registration_history: List[Dict[str, Any]] = []
        self.unregistration_history: List[str] = []
    
    def register(
        self,
        name: str,
        dependency_type: Type[Any],
        factory: Callable,
        scope: DependencyScope = DependencyScope.TRANSIENT,
        cache_strategy: CacheStrategy = CacheStrategy.NONE,
        **kwargs
    ) -> DependencyMetadata:
        metadata = DependencyMetadata(
            name=name,
            dependency_type=dependency_type,
            factory=factory,
            scope=scope,
            cache_strategy=cache_strategy,
            **kwargs
        )
        self._dependencies[name] = metadata
        
        self.registration_history.append({
            "name": name,
            "type": dependency_type,
            "scope": scope,
            "cache_strategy": cache_strategy,
            "timestamp": datetime.now()
        })
        
        return metadata
    
    def unregister(self, name: str) -> bool:
        if name in self._dependencies:
            del self._dependencies[name]
            self.unregistration_history.append(name)
            return True
        return False
    
    def get_metadata(self, name: str) -> Optional[DependencyMetadata]:
        return self._dependencies.get(name)
    
    def list_dependencies(self) -> List[str]:
        return list(self._dependencies.keys())
    
    def add_lifecycle_hook(self, phase: LifecyclePhase, hook: Callable):
        if phase not in self.lifecycle_hooks:
            self.lifecycle_hooks[phase] = []
        self.lifecycle_hooks[phase].append(hook)
    
    def check_circular_dependencies(self) -> List[List[str]]:
        return self.circular_dependencies
    
    def set_circular_dependencies(self, cycles: List[List[str]]):
        """Set mock circular dependencies for testing."""
        self.circular_dependencies = cycles
    
    def get_statistics(self) -> Dict[str, Any]:
        return {
            "registered_dependencies": len(self._dependencies),
            "active_instances": len(self._instances),
            "circular_dependencies": len(self.circular_dependencies),
            "registration_count": len(self.registration_history),
            "unregistration_count": len(self.unregistration_history)
        }


class MockDependencyCache:
    """Mock dependency cache for testing."""
    
    def __init__(self, max_size: int = 100):
        self.max_size = max_size
        self._cache: Dict[str, DependencyInstance] = {}
        self.get_calls: List[str] = []
        self.set_calls: List[tuple] = []
        self.remove_calls: List[str] = []
        self.clear_calls: int = 0
        self.cleanup_calls: List[float] = []
    
    def get(self, key: str) -> Optional[DependencyInstance]:
        self.get_calls.append(key)
        return self._cache.get(key)
    
    def set(self, key: str, instance: DependencyInstance):
        self.set_calls.append((key, instance))
        self._cache[key] = instance
        
        # Simulate LRU eviction
        if len(self._cache) > self.max_size:
            oldest_key = next(iter(self._cache))
            del self._cache[oldest_key]
    
    def remove(self, key: str) -> Optional[DependencyInstance]:
        self.remove_calls.append(key)
        return self._cache.pop(key, None)
    
    def clear(self):
        self.clear_calls += 1
        self._cache.clear()
    
    def cleanup_expired(self, ttl_seconds: float):
        self.cleanup_calls.append(ttl_seconds)
        cutoff = datetime.now() - timedelta(seconds=ttl_seconds)
        expired_keys = [
            key for key, instance in self._cache.items()
            if instance.last_accessed < cutoff
        ]
        for key in expired_keys:
            del self._cache[key]
    
    def get_statistics(self) -> Dict[str, Any]:
        return {
            "cache_size": len(self._cache),
            "get_calls": len(self.get_calls),
            "set_calls": len(self.set_calls),
            "remove_calls": len(self.remove_calls),
            "clear_calls": self.clear_calls
        }


class MockCircularDependencyDetector:
    """Mock circular dependency detector for testing."""
    
    def __init__(self):
        self.dependencies: Dict[str, Set[str]] = {}
        self.add_dependency_calls: List[tuple] = []
        self.check_calls: List[tuple] = []
        self.detect_all_calls: int = 0
        self.mock_cycles: List[List[str]] = []
    
    def add_dependency(self, dependent: str, dependency: str):
        self.add_dependency_calls.append((dependent, dependency))
        if dependent not in self.dependencies:
            self.dependencies[dependent] = set()
        self.dependencies[dependent].add(dependency)
    
    def check_circular_dependency(self, start: str, target: str) -> Optional[List[str]]:
        self.check_calls.append((start, target))
        # Return mock cycle if configured
        for cycle in self.mock_cycles:
            if start in cycle and target in cycle:
                return cycle
        return None
    
    def detect_all_cycles(self) -> List[List[str]]:
        self.detect_all_calls += 1
        return self.mock_cycles
    
    def set_mock_cycles(self, cycles: List[List[str]]):
        """Set mock cycles for testing."""
        self.mock_cycles = cycles


class MockLifecycleHook:
    """Mock lifecycle hook for testing."""
    
    def __init__(self, phase: LifecyclePhase, priority: int = 0):
        self.phase = phase
        self.priority = priority
        self.hook_id = str(uuid.uuid4())
        self.execution_history: List[Dict[str, Any]] = []
        self.should_fail = False
        self.failure_message = "Mock hook failure"
    
    async def execute(self, context: InjectionContext, instance: Any = None, metadata: Optional[DependencyMetadata] = None):
        execution_record = {
            "context": context,
            "instance": instance,
            "metadata": metadata,
            "timestamp": datetime.now()
        }
        self.execution_history.append(execution_record)
        
        if self.should_fail:
            raise Exception(self.failure_message)
    
    def set_should_fail(self, should_fail: bool, message: str = "Mock hook failure"):
        self.should_fail = should_fail
        self.failure_message = message


class MockDependencyInjector:
    """Mock dependency injector for testing."""
    
    def __init__(self):
        self.registry = MockDependencyRegistry()
        self.injection_history: List[Dict[str, Any]] = []
        self.injection_contexts: Dict[str, InjectionContext] = {}
        self.scope_instances: Dict[str, Dict[str, Any]] = {}
        self.performance_metrics: Dict[str, List[float]] = {}
        self.should_fail_injection = False
        self.failure_message = "Mock injection failure"
        self.injection_delay = 0.0
    
    async def inject(
        self,
        dependency_name: str,
        context: Optional[InjectionContext] = None,
        force_new: bool = False
    ) -> Any:
        if self.injection_delay > 0:
            await asyncio.sleep(self.injection_delay)
        
        if context is None:
            context = InjectionContext(request_id=str(uuid.uuid4()))
        
        injection_record = {
            "dependency_name": dependency_name,
            "context": context,
            "force_new": force_new,
            "timestamp": datetime.now()
        }
        self.injection_history.append(injection_record)
        
        if self.should_fail_injection:
            raise DependencyNotFoundError(self.failure_message, dependency_name)
        
        # Return mock instance
        return f"mock_instance:{dependency_name}"
    
    async def cleanup_scope(self, scope: DependencyScope, scope_id: str):
        if scope_id in self.scope_instances:
            del self.scope_instances[scope_id]
    
    def set_should_fail(self, should_fail: bool, message: str = "Mock injection failure"):
        self.should_fail_injection = should_fail
        self.failure_message = message
    
    def set_injection_delay(self, delay: float):
        self.injection_delay = delay
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        return dict(self.performance_metrics)


class MockPerformanceTracker:
    """Mock performance tracker for testing."""
    
    def __init__(self):
        self.injection_records: List[Dict[str, Any]] = []
        self.metrics: Dict[str, Dict[str, float]] = {}
    
    def record_injection(self, dependency_name: str, duration: float):
        self.injection_records.append({
            "dependency_name": dependency_name,
            "duration": duration,
            "timestamp": datetime.now()
        })
        
        if dependency_name not in self.metrics:
            self.metrics[dependency_name] = {
                "total_time": 0.0,
                "count": 0,
                "min_time": float('inf'),
                "max_time": 0.0
            }
        
        metrics = self.metrics[dependency_name]
        metrics["total_time"] += duration
        metrics["count"] += 1
        metrics["min_time"] = min(metrics["min_time"], duration)
        metrics["max_time"] = max(metrics["max_time"], duration)
    
    def get_metrics(self) -> Dict[str, Any]:
        result = {}
        for name, metrics in self.metrics.items():
            if metrics["count"] > 0:
                result[name] = {
                    "count": metrics["count"],
                    "avg_time": metrics["total_time"] / metrics["count"],
                    "min_time": metrics["min_time"],
                    "max_time": metrics["max_time"],
                    "total_time": metrics["total_time"]
                }
        return result


# Factory functions for creating mock objects
def create_mock_dependency_metadata(
    name: str = "test_dependency",
    dependency_type: Type = MockDependency,
    factory: Optional[Callable] = None,
    scope: DependencyScope = DependencyScope.TRANSIENT,
    cache_strategy: CacheStrategy = CacheStrategy.NONE,
    **kwargs
) -> DependencyMetadata:
    """Create mock dependency metadata."""
    if factory is None:
        factory = MockDependency
    
    return DependencyMetadata(
        name=name,
        dependency_type=dependency_type,
        factory=factory,
        scope=scope,
        cache_strategy=cache_strategy,
        **kwargs
    )


def create_mock_dependency_instance(
    dependency_name: str = "test_dependency",
    instance: Any = None,
    state: DependencyState = DependencyState.READY,
    **kwargs
) -> DependencyInstance:
    """Create mock dependency instance."""
    if instance is None:
        instance = MockDependency(dependency_name)
    
    return DependencyInstance(
        instance_id=str(uuid.uuid4()),
        dependency_name=dependency_name,
        instance=instance,
        state=state,
        **kwargs
    )


def create_mock_injection_context(
    request_id: Optional[str] = None,
    **kwargs
) -> InjectionContext:
    """Create mock injection context."""
    return InjectionContext(
        request_id=request_id or str(uuid.uuid4()),
        **kwargs
    )


def create_test_dependency_chain() -> List[MockDependency]:
    """Create a chain of test dependencies for testing."""
    dep_a = MockDependency("DepA", "value_a")
    dep_b = MockDependency("DepB", "value_b")
    dep_c = MockDependencyWithDeps(dep_a, dep_b)
    return [dep_a, dep_b, dep_c]


def create_circular_dependency_chain() -> List[str]:
    """Create a circular dependency chain for testing."""
    return ["A", "B", "C", "A"]


class MockRequest:
    """Mock FastAPI Request for testing."""
    
    def __init__(
        self,
        session_id: Optional[str] = None,
        user_id: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None
    ):
        self.session_id = session_id
        self.user_id = user_id
        self.headers = headers or {}
        self.method = "GET"
        self.url = Mock()
        self.url.path = "/test"


class MockBackgroundTasks:
    """Mock FastAPI BackgroundTasks for testing."""
    
    def __init__(self):
        self.tasks: List[Dict[str, Any]] = []
    
    def add_task(self, func: Callable, *args, **kwargs):
        self.tasks.append({
            "func": func,
            "args": args,
            "kwargs": kwargs
        })


# Helper functions for test setup
def setup_test_registry() -> MockDependencyRegistry:
    """Set up a test registry with common dependencies."""
    registry = MockDependencyRegistry()
    
    # Register basic dependencies
    registry.register("simple_dep", MockDependency, MockDependency)
    registry.register("async_dep", MockAsyncDependency, MockAsyncDependency)
    registry.register("failing_dep", MockFailingDependency, MockFailingDependency)
    
    return registry


def setup_test_injector() -> MockDependencyInjector:
    """Set up a test injector with mock registry."""
    injector = MockDependencyInjector()
    injector.registry = setup_test_registry()
    return injector


def create_performance_test_scenario(
    dependency_count: int = 10,
    injection_count: int = 100
) -> List[Dict[str, Any]]:
    """Create a performance test scenario."""
    scenarios = []
    
    for i in range(dependency_count):
        dep_name = f"perf_dep_{i}"
        for j in range(injection_count):
            scenarios.append({
                "dependency_name": dep_name,
                "injection_time": 0.001 + (i * 0.0001),  # Simulated injection time
                "context_id": f"context_{j}"
            })
    
    return scenarios


def create_memory_pressure_scenario(
    instance_count: int = 1000
) -> List[DependencyInstance]:
    """Create scenario for memory pressure testing."""
    instances = []
    
    for i in range(instance_count):
        instance = create_mock_dependency_instance(
            dependency_name=f"memory_test_dep_{i}",
            instance=MockDependency(f"dep_{i}", f"large_value_{i}" * 1000)  # Large values
        )
        instances.append(instance)
    
    return instances