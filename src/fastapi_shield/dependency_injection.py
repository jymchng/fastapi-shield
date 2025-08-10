"""Enhanced dependency injection system for FastAPI Shield.

This module provides comprehensive dependency injection capabilities including
caching strategies, lifecycle management, performance optimization, and
circular dependency detection.
"""

import asyncio
import functools
import inspect
import logging
import threading
import time
import uuid
import weakref
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import (
    Any, Dict, List, Optional, Set, Type, Union, Callable, TypeVar,
    Awaitable, Generic, cast, get_type_hints
)
import sys

from fastapi import Depends, Request, BackgroundTasks
from fastapi.dependencies.utils import get_dependant, solve_dependencies
from fastapi.dependencies.models import Dependant
from starlette.requests import Request as StarletteRequest

from fastapi_shield.shield import Shield

logger = logging.getLogger(__name__)

T = TypeVar('T')
F = TypeVar('F', bound=Callable)


class CacheStrategy(str, Enum):
    """Caching strategies for dependencies."""
    NONE = "none"
    SINGLETON = "singleton"
    REQUEST_SCOPED = "request_scoped"
    SESSION_SCOPED = "session_scoped"
    TIME_BASED = "time_based"
    LRU = "lru"
    WEAK_REF = "weak_ref"


class DependencyScope(str, Enum):
    """Dependency scopes."""
    TRANSIENT = "transient"
    SINGLETON = "singleton"
    REQUEST = "request"
    SESSION = "session"
    THREAD = "thread"
    ASYNC_CONTEXT = "async_context"


class LifecyclePhase(str, Enum):
    """Lifecycle phases for dependencies."""
    BEFORE_CREATION = "before_creation"
    AFTER_CREATION = "after_creation"
    BEFORE_INJECTION = "before_injection"
    AFTER_INJECTION = "after_injection"
    BEFORE_CLEANUP = "before_cleanup"
    AFTER_CLEANUP = "after_cleanup"


class DependencyState(str, Enum):
    """States of dependency instances."""
    PENDING = "pending"
    CREATING = "creating"
    READY = "ready"
    INJECTING = "injecting"
    ACTIVE = "active"
    DISPOSING = "disposing"
    DISPOSED = "disposed"
    ERROR = "error"


@dataclass
class DependencyMetadata:
    """Metadata for dependency registration."""
    name: str
    dependency_type: Type[Any]
    factory: Callable
    scope: DependencyScope = DependencyScope.TRANSIENT
    cache_strategy: CacheStrategy = CacheStrategy.NONE
    ttl_seconds: Optional[float] = None
    max_instances: Optional[int] = None
    tags: Set[str] = field(default_factory=set)
    priority: int = 0
    lazy: bool = False
    async_creation: bool = False
    dispose_func: Optional[Callable] = None
    health_check: Optional[Callable] = None
    created_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DependencyInstance:
    """Instance of a dependency with lifecycle information."""
    instance_id: str
    dependency_name: str
    instance: Any
    state: DependencyState = DependencyState.PENDING
    created_at: datetime = field(default_factory=datetime.now)
    last_accessed: datetime = field(default_factory=datetime.now)
    access_count: int = 0
    scope_context: Optional[str] = None
    cleanup_callbacks: List[Callable] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def mark_accessed(self):
        """Mark instance as accessed."""
        self.last_accessed = datetime.now()
        self.access_count += 1


@dataclass
class InjectionContext:
    """Context for dependency injection."""
    request_id: str
    request: Optional[Request] = None
    session_id: Optional[str] = None
    user_id: Optional[str] = None
    thread_id: Optional[str] = None
    async_context_id: Optional[str] = None
    injection_path: List[str] = field(default_factory=list)
    custom_attributes: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)


class DependencyError(Exception):
    """Base exception for dependency injection errors."""
    
    def __init__(self, message: str, dependency_name: Optional[str] = None):
        super().__init__(message)
        self.dependency_name = dependency_name


class CircularDependencyError(DependencyError):
    """Raised when circular dependencies are detected."""
    
    def __init__(self, cycle_path: List[str]):
        self.cycle_path = cycle_path
        cycle_str = " -> ".join(cycle_path + [cycle_path[0]])
        super().__init__(f"Circular dependency detected: {cycle_str}")


class DependencyNotFoundError(DependencyError):
    """Raised when a dependency cannot be found."""
    pass


class DependencyCreationError(DependencyError):
    """Raised when dependency creation fails."""
    pass


class DependencyCache:
    """Cache for dependency instances."""
    
    def __init__(self, max_size: int = 1000):
        self.max_size = max_size
        self._cache: Dict[str, DependencyInstance] = {}
        self._access_order = deque()
        self._lock = threading.RLock()
    
    def get(self, key: str) -> Optional[DependencyInstance]:
        """Get cached dependency instance."""
        with self._lock:
            if key in self._cache:
                instance = self._cache[key]
                instance.mark_accessed()
                # Move to end of access order
                if key in self._access_order:
                    self._access_order.remove(key)
                self._access_order.append(key)
                return instance
            return None
    
    def set(self, key: str, instance: DependencyInstance):
        """Cache dependency instance."""
        with self._lock:
            if len(self._cache) >= self.max_size and key not in self._cache:
                # Remove least recently used
                lru_key = self._access_order.popleft()
                old_instance = self._cache.pop(lru_key)
                self._cleanup_instance(old_instance)
            
            self._cache[key] = instance
            if key in self._access_order:
                self._access_order.remove(key)
            self._access_order.append(key)
    
    def remove(self, key: str) -> Optional[DependencyInstance]:
        """Remove cached instance."""
        with self._lock:
            instance = self._cache.pop(key, None)
            if instance:
                if key in self._access_order:
                    self._access_order.remove(key)
                self._cleanup_instance(instance)
            return instance
    
    def clear(self):
        """Clear all cached instances."""
        with self._lock:
            for instance in self._cache.values():
                self._cleanup_instance(instance)
            self._cache.clear()
            self._access_order.clear()
    
    def cleanup_expired(self, ttl_seconds: float):
        """Clean up expired instances."""
        cutoff = datetime.now() - timedelta(seconds=ttl_seconds)
        expired_keys = []
        
        with self._lock:
            for key, instance in self._cache.items():
                if instance.last_accessed < cutoff:
                    expired_keys.append(key)
        
        for key in expired_keys:
            self.remove(key)
    
    def _cleanup_instance(self, instance: DependencyInstance):
        """Clean up a dependency instance."""
        try:
            instance.state = DependencyState.DISPOSING
            for cleanup_callback in instance.cleanup_callbacks:
                try:
                    cleanup_callback()
                except Exception as e:
                    logger.warning(f"Error during cleanup for {instance.dependency_name}: {e}")
            instance.state = DependencyState.DISPOSED
        except Exception as e:
            logger.error(f"Error disposing instance {instance.instance_id}: {e}")
            instance.state = DependencyState.ERROR
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self._lock:
            total_instances = len(self._cache)
            total_accesses = sum(inst.access_count for inst in self._cache.values())
            
            return {
                "total_instances": total_instances,
                "total_accesses": total_accesses,
                "cache_hit_ratio": 0.0 if total_instances == 0 else total_accesses / total_instances,
                "oldest_instance": min(
                    (inst.created_at for inst in self._cache.values()),
                    default=None
                ),
                "newest_instance": max(
                    (inst.created_at for inst in self._cache.values()),
                    default=None
                )
            }


class LifecycleHook:
    """Lifecycle hook for dependency management."""
    
    def __init__(self, phase: LifecyclePhase, callback: Callable, priority: int = 0):
        self.phase = phase
        self.callback = callback
        self.priority = priority
        self.hook_id = str(uuid.uuid4())
    
    async def execute(self, context: InjectionContext, instance: Any = None, metadata: Optional[DependencyMetadata] = None):
        """Execute the lifecycle hook."""
        try:
            if asyncio.iscoroutinefunction(self.callback):
                await self.callback(context, instance, metadata)
            else:
                self.callback(context, instance, metadata)
        except Exception as e:
            logger.error(f"Error executing lifecycle hook {self.hook_id}: {e}")
            raise


class CircularDependencyDetector:
    """Detects circular dependencies in dependency graph."""
    
    def __init__(self):
        self._dependency_graph: Dict[str, Set[str]] = defaultdict(set)
        self._lock = threading.RLock()
    
    def add_dependency(self, dependent: str, dependency: str):
        """Add dependency relationship."""
        with self._lock:
            self._dependency_graph[dependent].add(dependency)
    
    def check_circular_dependency(self, start: str, target: str) -> Optional[List[str]]:
        """Check for circular dependency from start to target."""
        visited = set()
        path = []
        
        def dfs(node: str) -> Optional[List[str]]:
            if node in visited:
                # Found cycle
                cycle_start = path.index(node)
                return path[cycle_start:]
            
            if node == target and len(path) > 0:
                return path + [node]
            
            visited.add(node)
            path.append(node)
            
            for neighbor in self._dependency_graph.get(node, set()):
                result = dfs(neighbor)
                if result:
                    return result
            
            path.pop()
            return None
        
        return dfs(start)
    
    def detect_all_cycles(self) -> List[List[str]]:
        """Detect all circular dependencies."""
        cycles = []
        visited_global = set()
        
        def dfs(node: str, visited: Set[str], path: List[str]):
            if node in visited:
                cycle_start = path.index(node)
                cycle = path[cycle_start:]
                if len(cycle) > 1:  # Avoid self-loops
                    cycles.append(cycle)
                return
            
            visited.add(node)
            path.append(node)
            
            for neighbor in self._dependency_graph.get(node, set()):
                if neighbor not in visited_global:
                    dfs(neighbor, visited.copy(), path.copy())
            
            visited_global.add(node)
        
        for node in self._dependency_graph:
            if node not in visited_global:
                dfs(node, set(), [])
        
        return cycles


class DependencyRegistry:
    """Registry for managing dependency metadata and instances."""
    
    def __init__(self):
        self._dependencies: Dict[str, DependencyMetadata] = {}
        self._instances: Dict[str, DependencyInstance] = {}
        self._cache = DependencyCache()
        self._lifecycle_hooks: Dict[LifecyclePhase, List[LifecycleHook]] = defaultdict(list)
        self._circular_detector = CircularDependencyDetector()
        self._lock = threading.RLock()
        self._cleanup_task: Optional[asyncio.Task] = None
        self._performance_metrics: Dict[str, Any] = defaultdict(list)
    
    def register(
        self,
        name: str,
        dependency_type: Type[T],
        factory: Callable[..., T],
        scope: DependencyScope = DependencyScope.TRANSIENT,
        cache_strategy: CacheStrategy = CacheStrategy.NONE,
        ttl_seconds: Optional[float] = None,
        **kwargs
    ) -> DependencyMetadata:
        """Register a dependency."""
        with self._lock:
            if name in self._dependencies:
                logger.warning(f"Dependency '{name}' is being re-registered")
            
            metadata = DependencyMetadata(
                name=name,
                dependency_type=dependency_type,
                factory=factory,
                scope=scope,
                cache_strategy=cache_strategy,
                ttl_seconds=ttl_seconds,
                **kwargs
            )
            
            self._dependencies[name] = metadata
            
            # Add to circular dependency detector
            factory_deps = self._extract_factory_dependencies(factory)
            for dep_name in factory_deps:
                self._circular_detector.add_dependency(name, dep_name)
            
            logger.debug(f"Registered dependency: {name}")
            return metadata
    
    def unregister(self, name: str) -> bool:
        """Unregister a dependency."""
        with self._lock:
            if name not in self._dependencies:
                return False
            
            # Clean up instances
            instances_to_remove = [
                inst_id for inst_id, inst in self._instances.items()
                if inst.dependency_name == name
            ]
            
            for inst_id in instances_to_remove:
                self._cleanup_instance(inst_id)
            
            del self._dependencies[name]
            logger.debug(f"Unregistered dependency: {name}")
            return True
    
    def get_metadata(self, name: str) -> Optional[DependencyMetadata]:
        """Get dependency metadata."""
        return self._dependencies.get(name)
    
    def list_dependencies(self) -> List[str]:
        """List all registered dependencies."""
        return list(self._dependencies.keys())
    
    def add_lifecycle_hook(self, hook: LifecycleHook):
        """Add lifecycle hook."""
        with self._lock:
            self._lifecycle_hooks[hook.phase].append(hook)
            self._lifecycle_hooks[hook.phase].sort(key=lambda h: h.priority, reverse=True)
    
    def remove_lifecycle_hook(self, hook_id: str) -> bool:
        """Remove lifecycle hook."""
        with self._lock:
            for phase, hooks in self._lifecycle_hooks.items():
                for i, hook in enumerate(hooks):
                    if hook.hook_id == hook_id:
                        del hooks[i]
                        return True
            return False
    
    async def execute_lifecycle_hooks(
        self,
        phase: LifecyclePhase,
        context: InjectionContext,
        instance: Any = None,
        metadata: Optional[DependencyMetadata] = None
    ):
        """Execute lifecycle hooks for a phase."""
        hooks = self._lifecycle_hooks.get(phase, [])
        for hook in hooks:
            try:
                await hook.execute(context, instance, metadata)
            except Exception as e:
                logger.error(f"Lifecycle hook failed in phase {phase}: {e}")
    
    def check_circular_dependencies(self) -> List[List[str]]:
        """Check for circular dependencies."""
        return self._circular_detector.detect_all_cycles()
    
    def _extract_factory_dependencies(self, factory: Callable) -> Set[str]:
        """Extract dependency names from factory function signature."""
        dependencies = set()
        
        try:
            signature = inspect.signature(factory)
            for param in signature.parameters.values():
                if hasattr(param.annotation, '__name__'):
                    dependencies.add(param.annotation.__name__)
                # Handle FastAPI Depends
                if hasattr(param.default, 'dependency'):
                    dep_name = getattr(param.default.dependency, '__name__', str(param.default.dependency))
                    dependencies.add(dep_name)
        except Exception as e:
            logger.warning(f"Could not extract dependencies from factory {factory}: {e}")
        
        return dependencies
    
    def _cleanup_instance(self, instance_id: str):
        """Clean up a specific instance."""
        with self._lock:
            instance = self._instances.pop(instance_id, None)
            if instance:
                try:
                    instance.state = DependencyState.DISPOSING
                    for cleanup_callback in instance.cleanup_callbacks:
                        cleanup_callback()
                    instance.state = DependencyState.DISPOSED
                    logger.debug(f"Cleaned up instance {instance_id}")
                except Exception as e:
                    logger.error(f"Error cleaning up instance {instance_id}: {e}")
                    instance.state = DependencyState.ERROR
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get registry statistics."""
        with self._lock:
            cycles = self.check_circular_dependencies()
            return {
                "registered_dependencies": len(self._dependencies),
                "active_instances": len(self._instances),
                "circular_dependencies": len(cycles),
                "cache_stats": self._cache.get_statistics(),
                "performance_metrics": dict(self._performance_metrics)
            }


class EnhancedDependencyInjector:
    """Enhanced dependency injector with advanced features."""
    
    def __init__(self, registry: Optional[DependencyRegistry] = None):
        self.registry = registry or DependencyRegistry()
        self._injection_contexts: Dict[str, InjectionContext] = {}
        self._scope_instances: Dict[str, Dict[str, Any]] = defaultdict(dict)
        self._weak_refs: weakref.WeakValueDictionary = weakref.WeakValueDictionary()
        self._lock = threading.RLock()
        self._performance_tracker = DependencyPerformanceTracker()
    
    async def inject(
        self,
        dependency_name: str,
        context: Optional[InjectionContext] = None,
        force_new: bool = False
    ) -> Any:
        """Inject a dependency."""
        if context is None:
            context = InjectionContext(request_id=str(uuid.uuid4()))
        
        start_time = time.time()
        
        try:
            # Check for circular dependency
            if dependency_name in context.injection_path:
                raise CircularDependencyError(context.injection_path + [dependency_name])
            
            context.injection_path.append(dependency_name)
            
            metadata = self.registry.get_metadata(dependency_name)
            if not metadata:
                raise DependencyNotFoundError(f"Dependency '{dependency_name}' not found")
            
            # Execute before injection hooks
            await self.registry.execute_lifecycle_hooks(
                LifecyclePhase.BEFORE_INJECTION, context, metadata=metadata
            )
            
            # Get or create instance
            instance = await self._get_or_create_instance(metadata, context, force_new)
            
            # Execute after injection hooks
            await self.registry.execute_lifecycle_hooks(
                LifecyclePhase.AFTER_INJECTION, context, instance, metadata
            )
            
            # Track performance
            duration = time.time() - start_time
            self._performance_tracker.record_injection(dependency_name, duration)
            
            context.injection_path.pop()
            return instance
            
        except (CircularDependencyError, DependencyNotFoundError):
            context.injection_path.pop()
            raise  # Re-raise specific dependency errors without wrapping
        except Exception as e:
            context.injection_path.pop()
            logger.error(f"Failed to inject dependency '{dependency_name}': {e}")
            raise DependencyCreationError(f"Failed to inject '{dependency_name}': {e}")
    
    async def _get_or_create_instance(
        self,
        metadata: DependencyMetadata,
        context: InjectionContext,
        force_new: bool = False
    ) -> Any:
        """Get existing or create new instance based on scope and caching."""
        cache_key = self._get_cache_key(metadata, context)
        
        if not force_new:
            # Try to get from cache
            cached_instance = self._get_cached_instance(metadata, cache_key, context)
            if cached_instance is not None:
                return cached_instance
        
        # Create new instance
        return await self._create_instance(metadata, context, cache_key)
    
    def _get_cache_key(self, metadata: DependencyMetadata, context: InjectionContext) -> str:
        """Generate cache key based on scope and context."""
        base_key = metadata.name
        
        if metadata.scope == DependencyScope.SINGLETON:
            return f"singleton:{base_key}"
        elif metadata.scope == DependencyScope.REQUEST:
            return f"request:{context.request_id}:{base_key}"
        elif metadata.scope == DependencyScope.SESSION:
            return f"session:{context.session_id}:{base_key}"
        elif metadata.scope == DependencyScope.THREAD:
            return f"thread:{context.thread_id}:{base_key}"
        elif metadata.scope == DependencyScope.ASYNC_CONTEXT:
            return f"async:{context.async_context_id}:{base_key}"
        else:
            return f"transient:{uuid.uuid4()}:{base_key}"
    
    def _get_cached_instance(
        self,
        metadata: DependencyMetadata,
        cache_key: str,
        context: InjectionContext
    ) -> Optional[Any]:
        """Get cached instance if available and valid."""
        if metadata.cache_strategy == CacheStrategy.NONE:
            return None
        
        cached = self.registry._cache.get(cache_key)
        if cached is None:
            return None
        
        # Check TTL if applicable
        if metadata.ttl_seconds:
            age = (datetime.now() - cached.created_at).total_seconds()
            if age > metadata.ttl_seconds:
                self.registry._cache.remove(cache_key)
                return None
        
        # Check health if health check is provided
        if metadata.health_check:
            try:
                if asyncio.iscoroutinefunction(metadata.health_check):
                    # Note: This is a synchronous check, so we can't await
                    # In production, health checks should be sync or handled differently
                    pass
                else:
                    healthy = metadata.health_check(cached.instance)
                    if not healthy:
                        self.registry._cache.remove(cache_key)
                        return None
            except Exception as e:
                logger.warning(f"Health check failed for {metadata.name}: {e}")
                self.registry._cache.remove(cache_key)
                return None
        
        cached.mark_accessed()
        return cached.instance
    
    async def _create_instance(
        self,
        metadata: DependencyMetadata,
        context: InjectionContext,
        cache_key: str
    ) -> Any:
        """Create new instance of dependency."""
        # Execute before creation hooks
        await self.registry.execute_lifecycle_hooks(
            LifecyclePhase.BEFORE_CREATION, context, metadata=metadata
        )
        
        try:
            # Resolve factory dependencies
            factory_kwargs = await self._resolve_factory_dependencies(metadata.factory, context)
            
            # Create instance
            if metadata.async_creation or asyncio.iscoroutinefunction(metadata.factory):
                instance = await metadata.factory(**factory_kwargs)
            else:
                instance = metadata.factory(**factory_kwargs)
            
            # Create dependency instance wrapper
            dep_instance = DependencyInstance(
                instance_id=str(uuid.uuid4()),
                dependency_name=metadata.name,
                instance=instance,
                state=DependencyState.READY,
                scope_context=cache_key
            )
            
            # Add cleanup callback if dispose function is provided
            if metadata.dispose_func:
                dep_instance.cleanup_callbacks.append(
                    lambda: self._dispose_instance(instance, metadata.dispose_func)
                )
            
            # Cache instance if caching is enabled
            if metadata.cache_strategy != CacheStrategy.NONE:
                self.registry._cache.set(cache_key, dep_instance)
            
            # Store in registry
            with self._lock:
                self.registry._instances[dep_instance.instance_id] = dep_instance
            
            # Execute after creation hooks
            await self.registry.execute_lifecycle_hooks(
                LifecyclePhase.AFTER_CREATION, context, instance, metadata
            )
            
            dep_instance.state = DependencyState.ACTIVE
            return instance
            
        except Exception as e:
            logger.error(f"Failed to create instance of {metadata.name}: {e}")
            raise DependencyCreationError(f"Failed to create '{metadata.name}': {e}")
    
    async def _resolve_factory_dependencies(
        self,
        factory: Callable,
        context: InjectionContext
    ) -> Dict[str, Any]:
        """Resolve dependencies for factory function."""
        kwargs = {}
        
        try:
            signature = inspect.signature(factory)
            for param_name, param in signature.parameters.items():
                # Skip self parameter
                if param_name == 'self':
                    continue
                
                # Handle FastAPI Depends
                if hasattr(param.default, 'dependency'):
                    dep_func = param.default.dependency
                    if hasattr(dep_func, '__name__'):
                        dep_name = dep_func.__name__
                        kwargs[param_name] = await self.inject(dep_name, context)
                
                # Handle type annotations as dependency names
                elif hasattr(param.annotation, '__name__'):
                    dep_name = param.annotation.__name__
                    if self.registry.get_metadata(dep_name):
                        kwargs[param_name] = await self.inject(dep_name, context)
                
                # Handle special injections (Request, BackgroundTasks, etc.)
                elif param.annotation == Request or param.annotation == StarletteRequest:
                    if context.request:
                        kwargs[param_name] = context.request
                elif param.annotation == InjectionContext:
                    kwargs[param_name] = context
                elif param.annotation == BackgroundTasks:
                    # This would need to be provided by the framework
                    pass
        
        except Exception as e:
            logger.warning(f"Could not resolve dependencies for {factory}: {e}")
        
        return kwargs
    
    def _dispose_instance(self, instance: Any, dispose_func: Callable):
        """Dispose of instance using provided dispose function."""
        try:
            if asyncio.iscoroutinefunction(dispose_func):
                # Schedule for async disposal
                asyncio.create_task(dispose_func(instance))
            else:
                dispose_func(instance)
        except Exception as e:
            logger.error(f"Error disposing instance: {e}")
    
    async def cleanup_scope(self, scope: DependencyScope, scope_id: str):
        """Clean up all instances in a scope."""
        instances_to_cleanup = []
        
        with self._lock:
            for inst_id, instance in self.registry._instances.items():
                if instance.scope_context and scope_id in instance.scope_context:
                    instances_to_cleanup.append(inst_id)
        
        for inst_id in instances_to_cleanup:
            await self.registry.execute_lifecycle_hooks(
                LifecyclePhase.BEFORE_CLEANUP,
                InjectionContext(request_id=str(uuid.uuid4()))
            )
            self.registry._cleanup_instance(inst_id)
            await self.registry.execute_lifecycle_hooks(
                LifecyclePhase.AFTER_CLEANUP,
                InjectionContext(request_id=str(uuid.uuid4()))
            )
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics."""
        return self._performance_tracker.get_metrics()


class DependencyPerformanceTracker:
    """Tracks performance metrics for dependency injection."""
    
    def __init__(self):
        self._injection_times: Dict[str, List[float]] = defaultdict(list)
        self._injection_counts: Dict[str, int] = defaultdict(int)
        self._lock = threading.RLock()
    
    def record_injection(self, dependency_name: str, duration: float):
        """Record injection timing."""
        with self._lock:
            self._injection_times[dependency_name].append(duration)
            self._injection_counts[dependency_name] += 1
            
            # Keep only recent measurements (last 1000)
            if len(self._injection_times[dependency_name]) > 1000:
                self._injection_times[dependency_name] = self._injection_times[dependency_name][-1000:]
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get performance metrics."""
        with self._lock:
            metrics = {}
            
            for dep_name, times in self._injection_times.items():
                if times:
                    metrics[dep_name] = {
                        "count": self._injection_counts[dep_name],
                        "avg_time": sum(times) / len(times),
                        "min_time": min(times),
                        "max_time": max(times),
                        "recent_avg": sum(times[-100:]) / min(len(times), 100)
                    }
            
            return metrics


class EnhancedShieldedDepends:
    """Enhanced version of ShieldedDepends with advanced DI features."""
    
    def __init__(
        self,
        dependency: Callable[..., Any],
        injector: Optional[EnhancedDependencyInjector] = None,
        cache_strategy: CacheStrategy = CacheStrategy.REQUEST_SCOPED,
        scope: DependencyScope = DependencyScope.REQUEST,
        ttl_seconds: Optional[float] = None,
        use_cache: bool = True,
        health_check: Optional[Callable] = None,
        dispose_func: Optional[Callable] = None,
        tags: Optional[Set[str]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        self.dependency = dependency
        self.injector = injector or _get_default_injector()
        self.dependency_name = getattr(dependency, '__name__', str(dependency))
        
        # Register dependency if not already registered
        if not self.injector.registry.get_metadata(self.dependency_name):
            self.injector.registry.register(
                name=self.dependency_name,
                dependency_type=type(dependency),
                factory=dependency,
                cache_strategy=cache_strategy,
                scope=scope,
                ttl_seconds=ttl_seconds,
                health_check=health_check,
                dispose_func=dispose_func,
                tags=tags or set(),
                metadata=metadata or {}
            )
    
    async def __call__(self, request: Optional[Request] = None) -> Any:
        """Resolve dependency with enhanced injection."""
        context = InjectionContext(
            request_id=str(uuid.uuid4()),
            request=request,
            session_id=getattr(request, 'session_id', None) if request else None,
            user_id=getattr(request, 'user_id', None) if request else None,
            thread_id=str(threading.get_ident()),
            async_context_id=str(id(asyncio.current_task())) if asyncio.current_task() else None
        )
        
        return await self.injector.inject(self.dependency_name, context)


# Global injector instance
_default_injector: Optional[EnhancedDependencyInjector] = None
_injector_lock = threading.Lock()


def _get_default_injector() -> EnhancedDependencyInjector:
    """Get or create default injector."""
    global _default_injector
    with _injector_lock:
        if _default_injector is None:
            _default_injector = EnhancedDependencyInjector()
        return _default_injector


def get_dependency_injector() -> EnhancedDependencyInjector:
    """Get the global dependency injector."""
    return _get_default_injector()


def set_dependency_injector(injector: EnhancedDependencyInjector):
    """Set the global dependency injector."""
    global _default_injector
    with _injector_lock:
        _default_injector = injector


def register_dependency(
    name: Optional[str] = None,
    scope: DependencyScope = DependencyScope.TRANSIENT,
    cache_strategy: CacheStrategy = CacheStrategy.NONE,
    ttl_seconds: Optional[float] = None,
    health_check: Optional[Callable] = None,
    dispose_func: Optional[Callable] = None,
    tags: Optional[Set[str]] = None,
    **kwargs
) -> Callable[[Callable], Callable]:
    """Decorator to register a dependency."""
    def decorator(func: Callable) -> Callable:
        dep_name = name or func.__name__
        injector = get_dependency_injector()
        
        injector.registry.register(
            name=dep_name,
            dependency_type=type(func),
            factory=func,
            scope=scope,
            cache_strategy=cache_strategy,
            ttl_seconds=ttl_seconds,
            health_check=health_check,
            dispose_func=dispose_func,
            tags=tags or set(),
            **kwargs
        )
        
        return func
    return decorator


def singleton(
    name: Optional[str] = None,
    cache_strategy: CacheStrategy = CacheStrategy.SINGLETON,
    **kwargs
) -> Callable[[Callable], Callable]:
    """Decorator to register a singleton dependency."""
    return register_dependency(
        name=name,
        scope=DependencyScope.SINGLETON,
        cache_strategy=cache_strategy,
        **kwargs
    )


def request_scoped(
    name: Optional[str] = None,
    cache_strategy: CacheStrategy = CacheStrategy.REQUEST_SCOPED,
    **kwargs
) -> Callable[[Callable], Callable]:
    """Decorator to register a request-scoped dependency."""
    return register_dependency(
        name=name,
        scope=DependencyScope.REQUEST,
        cache_strategy=cache_strategy,
        **kwargs
    )


def transient(name: Optional[str] = None, **kwargs) -> Callable[[Callable], Callable]:
    """Decorator to register a transient dependency."""
    return register_dependency(
        name=name,
        scope=DependencyScope.TRANSIENT,
        cache_strategy=CacheStrategy.NONE,
        **kwargs
    )


@contextmanager
def injection_context(**kwargs):
    """Context manager for dependency injection context."""
    injector = get_dependency_injector()
    context = InjectionContext(
        request_id=str(uuid.uuid4()),
        **kwargs
    )
    
    with injector._lock:
        context_id = context.request_id
        injector._injection_contexts[context_id] = context
    
    try:
        yield context
    finally:
        with injector._lock:
            injector._injection_contexts.pop(context_id, None)


@asynccontextmanager
async def async_injection_context(**kwargs):
    """Async context manager for dependency injection context."""
    injector = get_dependency_injector()
    context = InjectionContext(
        request_id=str(uuid.uuid4()),
        **kwargs
    )
    
    with injector._lock:
        context_id = context.request_id
        injector._injection_contexts[context_id] = context
    
    try:
        yield context
    finally:
        with injector._lock:
            injector._injection_contexts.pop(context_id, None)


# Lifecycle hook decorators
def before_creation(priority: int = 0):
    """Decorator to register before creation hook."""
    def decorator(func: Callable):
        hook = LifecycleHook(LifecyclePhase.BEFORE_CREATION, func, priority)
        get_dependency_injector().registry.add_lifecycle_hook(hook)
        return func
    return decorator


def after_creation(priority: int = 0):
    """Decorator to register after creation hook."""
    def decorator(func: Callable):
        hook = LifecycleHook(LifecyclePhase.AFTER_CREATION, func, priority)
        get_dependency_injector().registry.add_lifecycle_hook(hook)
        return func
    return decorator


def before_injection(priority: int = 0):
    """Decorator to register before injection hook."""
    def decorator(func: Callable):
        hook = LifecycleHook(LifecyclePhase.BEFORE_INJECTION, func, priority)
        get_dependency_injector().registry.add_lifecycle_hook(hook)
        return func
    return decorator


def after_injection(priority: int = 0):
    """Decorator to register after injection hook."""
    def decorator(func: Callable):
        hook = LifecycleHook(LifecyclePhase.AFTER_INJECTION, func, priority)
        get_dependency_injector().registry.add_lifecycle_hook(hook)
        return func
    return decorator


# Utility functions
def inject_dependency(name: str, context: Optional[InjectionContext] = None) -> Any:
    """Inject a dependency by name."""
    injector = get_dependency_injector()
    if context is None:
        context = InjectionContext(request_id=str(uuid.uuid4()))
    
    return asyncio.create_task(injector.inject(name, context))


async def async_inject_dependency(name: str, context: Optional[InjectionContext] = None) -> Any:
    """Async inject a dependency by name."""
    injector = get_dependency_injector()
    if context is None:
        context = InjectionContext(request_id=str(uuid.uuid4()))
    
    return await injector.inject(name, context)


def get_dependency_metadata(name: str) -> Optional[DependencyMetadata]:
    """Get metadata for a dependency."""
    injector = get_dependency_injector()
    return injector.registry.get_metadata(name)


def list_registered_dependencies() -> List[str]:
    """List all registered dependencies."""
    injector = get_dependency_injector()
    return injector.registry.list_dependencies()


def check_circular_dependencies() -> List[List[str]]:
    """Check for circular dependencies."""
    injector = get_dependency_injector()
    return injector.registry.check_circular_dependencies()


def get_injection_statistics() -> Dict[str, Any]:
    """Get injection statistics."""
    injector = get_dependency_injector()
    registry_stats = injector.registry.get_statistics()
    performance_stats = injector.get_performance_metrics()
    
    return {
        "registry": registry_stats,
        "performance": performance_stats,
        "injector_info": {
            "active_contexts": len(injector._injection_contexts),
            "scope_instances": len(injector._scope_instances)
        }
    }


async def cleanup_dependencies():
    """Clean up all dependencies."""
    injector = get_dependency_injector()
    
    # Clean up all scopes
    for scope in DependencyScope:
        scope_ids = []
        with injector._lock:
            for instance in injector.registry._instances.values():
                if instance.scope_context:
                    scope_ids.append(instance.scope_context)
        
        for scope_id in set(scope_ids):
            await injector.cleanup_scope(scope, scope_id)
    
    # Clear cache
    injector.registry._cache.clear()


# Enhanced FastAPI integration
def ShieldedDepends(
    dependency: Callable[..., Any],
    cache_strategy: CacheStrategy = CacheStrategy.REQUEST_SCOPED,
    scope: DependencyScope = DependencyScope.REQUEST,
    ttl_seconds: Optional[float] = None,
    use_cache: bool = True,
    **kwargs
) -> EnhancedShieldedDepends:
    """Enhanced ShieldedDepends with advanced caching and lifecycle management."""
    return EnhancedShieldedDepends(
        dependency=dependency,
        cache_strategy=cache_strategy,
        scope=scope,
        ttl_seconds=ttl_seconds,
        use_cache=use_cache,
        **kwargs
    )