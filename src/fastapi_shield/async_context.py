"""Async context management for FastAPI Shield.

This module provides comprehensive async context management capabilities including
context variable support, asyncio task management, resource cleanup optimization,
context propagation, and async logging integration.
"""

import asyncio
import contextvars
import functools
import logging
import threading
import time
import uuid
import weakref
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import (
    Any, Dict, List, Optional, Set, Type, Union, Callable, TypeVar,
    Awaitable, Generic, AsyncIterator, Iterator, AsyncContextManager,
    ContextManager, Coroutine
)
import sys
from collections import defaultdict, deque

from fastapi import Request, Response
from starlette.concurrency import run_in_threadpool

from fastapi_shield.shield import Shield

logger = logging.getLogger(__name__)

T = TypeVar('T')
F = TypeVar('F', bound=Callable[..., Any])


class ContextScope(str, Enum):
    """Scope levels for async contexts."""
    TASK = "task"
    REQUEST = "request"
    SESSION = "session"
    APPLICATION = "application"
    GLOBAL = "global"


class ContextState(str, Enum):
    """States of async contexts."""
    CREATED = "created"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    ERROR = "error"
    CLEANED_UP = "cleaned_up"


class ContextPriority(int, Enum):
    """Priority levels for context operations."""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


class CleanupStrategy(str, Enum):
    """Strategies for resource cleanup."""
    IMMEDIATE = "immediate"
    DELAYED = "delayed"
    LAZY = "lazy"
    BATCH = "batch"
    CUSTOM = "custom"


@dataclass
class AsyncContextInfo:
    """Information about an async context."""
    context_id: str
    scope: ContextScope
    state: ContextState = ContextState.CREATED
    priority: ContextPriority = ContextPriority.NORMAL
    created_at: datetime = field(default_factory=datetime.now)
    last_accessed: datetime = field(default_factory=datetime.now)
    task_id: Optional[str] = None
    request_id: Optional[str] = None
    session_id: Optional[str] = None
    parent_context_id: Optional[str] = None
    child_context_ids: Set[str] = field(default_factory=set)
    variables: Dict[str, Any] = field(default_factory=dict)
    resources: Dict[str, Any] = field(default_factory=dict)
    cleanup_callbacks: List[Callable] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def mark_accessed(self):
        """Mark context as accessed."""
        self.last_accessed = datetime.now()


@dataclass
class ResourceInfo:
    """Information about a managed resource."""
    resource_id: str
    resource_type: str
    resource: Any
    context_id: str
    scope: ContextScope
    cleanup_strategy: CleanupStrategy = CleanupStrategy.IMMEDIATE
    priority: ContextPriority = ContextPriority.NORMAL
    created_at: datetime = field(default_factory=datetime.now)
    last_used: datetime = field(default_factory=datetime.now)
    cleanup_callback: Optional[Callable] = None
    dependencies: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def mark_used(self):
        """Mark resource as used."""
        self.last_used = datetime.now()


class AsyncContextError(Exception):
    """Base exception for async context errors."""
    pass


class ContextNotFoundError(AsyncContextError):
    """Raised when a context is not found."""
    pass


class ContextStateError(AsyncContextError):
    """Raised when context is in invalid state for operation."""
    pass


class ResourceError(AsyncContextError):
    """Raised when resource operations fail."""
    pass


class ContextVariable(Generic[T]):
    """Enhanced context variable with async support."""
    
    def __init__(
        self,
        name: str,
        default: T = None,
        scope: ContextScope = ContextScope.TASK,
        auto_cleanup: bool = True
    ):
        self.name = name
        self.default = default
        self.scope = scope
        self.auto_cleanup = auto_cleanup
        self._var = contextvars.ContextVar(name, default=default)
    
    def get(self, default: Optional[T] = None) -> T:
        """Get context variable value."""
        try:
            return self._var.get()
        except LookupError:
            return default if default is not None else self.default
    
    def set(self, value: T) -> contextvars.Token:
        """Set context variable value."""
        token = self._var.set(value)
        return token
    
    def reset(self, token: contextvars.Token):
        """Reset context variable to previous value."""
        self._var.reset(token)
    
    def delete(self):
        """Delete context variable."""
        try:
            # Get current value, then set to default
            current = self._var.get()
            if current != self.default:
                self._var.set(self.default)
        except LookupError:
            # Already at default/unset
            pass
    
    def copy_context(self) -> contextvars.Context:
        """Copy current context."""
        return contextvars.copy_context()


class AsyncResource(ABC):
    """Abstract base class for async resources."""
    
    def __init__(
        self,
        resource_id: str,
        cleanup_strategy: CleanupStrategy = CleanupStrategy.IMMEDIATE
    ):
        self.resource_id = resource_id
        self.cleanup_strategy = cleanup_strategy
        self._cleanup_callbacks: List[Callable] = []
    
    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the resource."""
        pass
    
    @abstractmethod
    async def cleanup(self) -> None:
        """Clean up the resource."""
        pass
    
    def add_cleanup_callback(self, callback: Callable):
        """Add cleanup callback."""
        self._cleanup_callbacks.append(callback)
    
    async def _execute_cleanup_callbacks(self):
        """Execute all cleanup callbacks."""
        for callback in self._cleanup_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback()
                else:
                    callback()
            except Exception as e:
                logger.warning(f"Cleanup callback failed for {self.resource_id}: {e}")


class AsyncResourcePool:
    """Pool for managing async resources."""
    
    def __init__(
        self,
        pool_id: str,
        max_resources: int = 100,
        cleanup_interval: float = 60.0
    ):
        self.pool_id = pool_id
        self.max_resources = max_resources
        self.cleanup_interval = cleanup_interval
        self._resources: Dict[str, ResourceInfo] = {}
        self._by_context: Dict[str, Set[str]] = defaultdict(set)
        self._by_scope: Dict[ContextScope, Set[str]] = defaultdict(set)
        self._lock = asyncio.Lock()
        self._cleanup_task: Optional[asyncio.Task] = None
        self._stats = {
            "created": 0,
            "cleaned": 0,
            "errors": 0,
            "active": 0
        }
    
    async def start_cleanup_task(self):
        """Start periodic cleanup task."""
        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(self._periodic_cleanup())
    
    async def stop_cleanup_task(self):
        """Stop periodic cleanup task."""
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
    
    async def add_resource(
        self,
        resource: AsyncResource,
        context_id: str,
        scope: ContextScope = ContextScope.TASK,
        **kwargs
    ) -> str:
        """Add resource to pool."""
        async with self._lock:
            if len(self._resources) >= self.max_resources:
                await self._cleanup_expired_resources()
                
                if len(self._resources) >= self.max_resources:
                    raise ResourceError(f"Resource pool {self.pool_id} is full")
            
            resource_info = ResourceInfo(
                resource_id=resource.resource_id,
                resource_type=resource.__class__.__name__,
                resource=resource,
                context_id=context_id,
                scope=scope,
                **kwargs
            )
            
            self._resources[resource.resource_id] = resource_info
            self._by_context[context_id].add(resource.resource_id)
            self._by_scope[scope].add(resource.resource_id)
            
            self._stats["created"] += 1
            self._stats["active"] = len(self._resources)
            
            logger.debug(f"Added resource {resource.resource_id} to pool {self.pool_id}")
            return resource.resource_id
    
    async def get_resource(self, resource_id: str) -> Optional[AsyncResource]:
        """Get resource from pool."""
        async with self._lock:
            resource_info = self._resources.get(resource_id)
            if resource_info:
                resource_info.mark_used()
                return resource_info.resource
            return None
    
    async def remove_resource(self, resource_id: str) -> bool:
        """Remove resource from pool."""
        async with self._lock:
            resource_info = self._resources.get(resource_id)
            if not resource_info:
                return False
            
            # Clean up resource
            try:
                await resource_info.resource.cleanup()
                if resource_info.cleanup_callback:
                    await resource_info.cleanup_callback(resource_info.resource)
                
                self._stats["cleaned"] += 1
            except Exception as e:
                logger.error(f"Error cleaning up resource {resource_id}: {e}")
                self._stats["errors"] += 1
            
            # Remove from tracking
            del self._resources[resource_id]
            self._by_context[resource_info.context_id].discard(resource_id)
            self._by_scope[resource_info.scope].discard(resource_id)
            
            self._stats["active"] = len(self._resources)
            
            logger.debug(f"Removed resource {resource_id} from pool {self.pool_id}")
            return True
    
    async def cleanup_context_resources(self, context_id: str) -> int:
        """Clean up all resources for a context."""
        resource_ids = list(self._by_context.get(context_id, set()))
        cleaned_count = 0
        
        for resource_id in resource_ids:
            if await self.remove_resource(resource_id):
                cleaned_count += 1
        
        return cleaned_count
    
    async def cleanup_scope_resources(self, scope: ContextScope) -> int:
        """Clean up all resources for a scope."""
        resource_ids = list(self._by_scope.get(scope, set()))
        cleaned_count = 0
        
        for resource_id in resource_ids:
            if await self.remove_resource(resource_id):
                cleaned_count += 1
        
        return cleaned_count
    
    async def _cleanup_expired_resources(self):
        """Clean up expired resources."""
        current_time = datetime.now()
        expired_resources = []
        
        for resource_id, resource_info in self._resources.items():
            # Check if resource hasn't been used recently
            if (current_time - resource_info.last_used).total_seconds() > self.cleanup_interval:
                expired_resources.append(resource_id)
        
        for resource_id in expired_resources:
            await self.remove_resource(resource_id)
    
    async def _periodic_cleanup(self):
        """Periodic cleanup task."""
        try:
            while True:
                await asyncio.sleep(self.cleanup_interval)
                await self._cleanup_expired_resources()
        except asyncio.CancelledError:
            logger.debug(f"Cleanup task for pool {self.pool_id} cancelled")
            raise
        except Exception as e:
            logger.error(f"Error in periodic cleanup for pool {self.pool_id}: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get pool statistics."""
        return {
            **self._stats,
            "pool_id": self.pool_id,
            "max_resources": self.max_resources,
            "cleanup_interval": self.cleanup_interval,
            "contexts": len(self._by_context),
            "scopes": {scope.value: len(resources) for scope, resources in self._by_scope.items()}
        }


class AsyncContextManager:
    """Manager for async contexts and resources."""
    
    def __init__(self):
        self._contexts: Dict[str, AsyncContextInfo] = {}
        self._context_hierarchy: Dict[str, Set[str]] = defaultdict(set)
        self._resource_pools: Dict[str, AsyncResourcePool] = {}
        self._context_vars: Dict[str, ContextVariable] = {}
        self._cleanup_tasks: Dict[str, asyncio.Task] = {}
        self._lock = asyncio.Lock()
        self._global_cleanup_task: Optional[asyncio.Task] = None
        self._metrics = {
            "contexts_created": 0,
            "contexts_completed": 0,
            "contexts_cancelled": 0,
            "contexts_errors": 0,
            "resources_managed": 0,
            "cleanup_operations": 0
        }
    
    async def start(self):
        """Start the context manager."""
        if self._global_cleanup_task is None or self._global_cleanup_task.done():
            self._global_cleanup_task = asyncio.create_task(self._global_cleanup_loop())
        
        # Start resource pool cleanup tasks
        for pool in self._resource_pools.values():
            await pool.start_cleanup_task()
    
    async def stop(self):
        """Stop the context manager."""
        # Cancel global cleanup task
        if self._global_cleanup_task and not self._global_cleanup_task.done():
            self._global_cleanup_task.cancel()
            try:
                await self._global_cleanup_task
            except asyncio.CancelledError:
                pass
        
        # Stop all resource pools
        for pool in self._resource_pools.values():
            await pool.stop_cleanup_task()
        
        # Clean up all contexts
        await self.cleanup_all_contexts()
    
    async def create_context(
        self,
        scope: ContextScope = ContextScope.TASK,
        priority: ContextPriority = ContextPriority.NORMAL,
        parent_context_id: Optional[str] = None,
        **metadata
    ) -> str:
        """Create a new async context."""
        context_id = str(uuid.uuid4())
        
        # Get current task info
        current_task = asyncio.current_task()
        task_id = str(id(current_task)) if current_task else None
        
        # Auto-detect parent context if not specified
        if parent_context_id is None:
            parent_context_id = await self._find_current_context_id()
        
        async with self._lock:
            context_info = AsyncContextInfo(
                context_id=context_id,
                scope=scope,
                priority=priority,
                task_id=task_id,
                parent_context_id=parent_context_id,
                metadata=metadata
            )
            
            self._contexts[context_id] = context_info
            
            # Update hierarchy
            if parent_context_id and parent_context_id in self._contexts:
                self._context_hierarchy[parent_context_id].add(context_id)
                self._contexts[parent_context_id].child_context_ids.add(context_id)
            
            self._metrics["contexts_created"] += 1
        
        logger.debug(f"Created async context {context_id} with scope {scope}")
        return context_id
    
    async def _find_current_context_id(self) -> Optional[str]:
        """Find current context ID for the current task."""
        current_task = asyncio.current_task()
        if not current_task:
            return None
        
        task_id = str(id(current_task))
        
        # Find active context for current task
        for ctx_id, ctx_info in self._contexts.items():
            if ctx_info.task_id == task_id and ctx_info.state == ContextState.ACTIVE:
                return ctx_id
        
        return None
    
    async def get_context(self, context_id: str) -> Optional[AsyncContextInfo]:
        """Get context information."""
        async with self._lock:
            context_info = self._contexts.get(context_id)
            if context_info:
                context_info.mark_accessed()
            return context_info
    
    async def activate_context(self, context_id: str):
        """Activate a context."""
        async with self._lock:
            context_info = self._contexts.get(context_id)
            if not context_info:
                raise ContextNotFoundError(f"Context {context_id} not found")
            
            if context_info.state not in [ContextState.CREATED, ContextState.SUSPENDED]:
                raise ContextStateError(f"Context {context_id} cannot be activated from state {context_info.state}")
            
            context_info.state = ContextState.ACTIVE
            context_info.mark_accessed()
        
        logger.debug(f"Activated context {context_id}")
    
    async def suspend_context(self, context_id: str):
        """Suspend a context."""
        async with self._lock:
            context_info = self._contexts.get(context_id)
            if not context_info:
                raise ContextNotFoundError(f"Context {context_id} not found")
            
            if context_info.state not in [ContextState.ACTIVE]:
                raise ContextStateError(f"Context {context_id} cannot be suspended from state {context_info.state}")
            
            context_info.state = ContextState.SUSPENDED
            context_info.mark_accessed()
        
        logger.debug(f"Suspended context {context_id}")
    
    async def complete_context(self, context_id: str):
        """Complete a context."""
        async with self._lock:
            context_info = self._contexts.get(context_id)
            if not context_info:
                raise ContextNotFoundError(f"Context {context_id} not found")
            
            context_info.state = ContextState.COMPLETED
            context_info.mark_accessed()
        
        # Schedule cleanup
        await self._schedule_context_cleanup(context_id)
        
        self._metrics["contexts_completed"] += 1
        logger.debug(f"Completed context {context_id}")
    
    async def cancel_context(self, context_id: str):
        """Cancel a context."""
        async with self._lock:
            context_info = self._contexts.get(context_id)
            if not context_info:
                raise ContextNotFoundError(f"Context {context_id} not found")
            
            context_info.state = ContextState.CANCELLED
            context_info.mark_accessed()
        
        # Schedule cleanup
        await self._schedule_context_cleanup(context_id)
        
        self._metrics["contexts_cancelled"] += 1
        logger.debug(f"Cancelled context {context_id}")
    
    async def error_context(self, context_id: str, error: Exception):
        """Mark context as having an error."""
        async with self._lock:
            context_info = self._contexts.get(context_id)
            if not context_info:
                raise ContextNotFoundError(f"Context {context_id} not found")
            
            context_info.state = ContextState.ERROR
            context_info.metadata["error"] = str(error)
            context_info.metadata["error_type"] = error.__class__.__name__
            context_info.mark_accessed()
        
        # Schedule cleanup
        await self._schedule_context_cleanup(context_id)
        
        self._metrics["contexts_errors"] += 1
        logger.error(f"Context {context_id} encountered error: {error}")
    
    async def set_context_variable(self, context_id: str, key: str, value: Any):
        """Set a variable in context."""
        async with self._lock:
            context_info = self._contexts.get(context_id)
            if not context_info:
                raise ContextNotFoundError(f"Context {context_id} not found")
            
            context_info.variables[key] = value
            context_info.mark_accessed()
    
    async def get_context_variable(self, context_id: str, key: str, default: Any = None) -> Any:
        """Get a variable from context."""
        async with self._lock:
            context_info = self._contexts.get(context_id)
            if not context_info:
                raise ContextNotFoundError(f"Context {context_id} not found")
            
            context_info.mark_accessed()
            return context_info.variables.get(key, default)
    
    def create_resource_pool(
        self,
        pool_id: str,
        max_resources: int = 100,
        cleanup_interval: float = 60.0
    ) -> AsyncResourcePool:
        """Create a resource pool."""
        pool = AsyncResourcePool(pool_id, max_resources, cleanup_interval)
        self._resource_pools[pool_id] = pool
        return pool
    
    def get_resource_pool(self, pool_id: str) -> Optional[AsyncResourcePool]:
        """Get a resource pool."""
        return self._resource_pools.get(pool_id)
    
    def create_context_variable(
        self,
        name: str,
        default: Any = None,
        scope: ContextScope = ContextScope.TASK,
        auto_cleanup: bool = True
    ) -> ContextVariable:
        """Create a context variable."""
        var = ContextVariable(name, default, scope, auto_cleanup)
        self._context_vars[name] = var
        return var
    
    def get_context_variable_definition(self, name: str) -> Optional[ContextVariable]:
        """Get a context variable definition."""
        return self._context_vars.get(name)
    
    async def _schedule_context_cleanup(self, context_id: str):
        """Schedule cleanup for a context."""
        if context_id not in self._cleanup_tasks:
            task = asyncio.create_task(self._cleanup_context(context_id))
            self._cleanup_tasks[context_id] = task
    
    async def _cleanup_context(self, context_id: str):
        """Clean up a context."""
        try:
            async with self._lock:
                context_info = self._contexts.get(context_id)
                if not context_info:
                    return
                
                # Execute cleanup callbacks
                for callback in context_info.cleanup_callbacks:
                    try:
                        if asyncio.iscoroutinefunction(callback):
                            await callback()
                        else:
                            callback()
                    except Exception as e:
                        logger.warning(f"Cleanup callback failed for context {context_id}: {e}")
                
                # Clean up child contexts
                for child_id in list(context_info.child_context_ids):
                    await self._cleanup_context(child_id)
                
                # Remove from hierarchy
                if context_info.parent_context_id:
                    parent_children = self._context_hierarchy.get(context_info.parent_context_id)
                    if parent_children:
                        parent_children.discard(context_id)
                    
                    parent_info = self._contexts.get(context_info.parent_context_id)
                    if parent_info:
                        parent_info.child_context_ids.discard(context_id)
                
                # Clean up resources for this context
                for pool in self._resource_pools.values():
                    await pool.cleanup_context_resources(context_id)
                
                # Update state
                context_info.state = ContextState.CLEANED_UP
                
                # Remove from tracking after delay to allow for final operations
                asyncio.create_task(self._delayed_context_removal(context_id))
                
                self._metrics["cleanup_operations"] += 1
        
        except Exception as e:
            logger.error(f"Error cleaning up context {context_id}: {e}")
        finally:
            # Remove cleanup task
            self._cleanup_tasks.pop(context_id, None)
    
    async def _delayed_context_removal(self, context_id: str, delay: float = 10.0):
        """Remove context after delay."""
        await asyncio.sleep(delay)
        async with self._lock:
            self._contexts.pop(context_id, None)
            self._context_hierarchy.pop(context_id, None)
    
    async def cleanup_all_contexts(self):
        """Clean up all contexts."""
        context_ids = list(self._contexts.keys())
        
        for context_id in context_ids:
            await self._cleanup_context(context_id)
    
    async def _global_cleanup_loop(self):
        """Global cleanup loop."""
        try:
            while True:
                await asyncio.sleep(300)  # Run every 5 minutes
                await self._cleanup_stale_contexts()
        except asyncio.CancelledError:
            logger.debug("Global cleanup loop cancelled")
            raise
        except Exception as e:
            logger.error(f"Error in global cleanup loop: {e}")
    
    async def _cleanup_stale_contexts(self):
        """Clean up stale contexts."""
        current_time = datetime.now()
        stale_contexts = []
        
        async with self._lock:
            for context_id, context_info in self._contexts.items():
                # Clean up contexts that haven't been accessed in a while
                age = (current_time - context_info.last_accessed).total_seconds()
                
                if age > 3600:  # 1 hour
                    if context_info.state in [ContextState.COMPLETED, ContextState.CANCELLED, ContextState.ERROR]:
                        stale_contexts.append(context_id)
                elif age > 86400:  # 24 hours
                    # Force cleanup of very old contexts
                    stale_contexts.append(context_id)
        
        for context_id in stale_contexts:
            await self._cleanup_context(context_id)
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get context manager metrics."""
        return {
            **self._metrics,
            "active_contexts": len(self._contexts),
            "resource_pools": len(self._resource_pools),
            "context_variables": len(self._context_vars),
            "cleanup_tasks": len(self._cleanup_tasks),
            "pool_stats": {
                pool_id: pool.get_stats()
                for pool_id, pool in self._resource_pools.items()
            }
        }


# Global context manager instance
_global_context_manager: Optional[AsyncContextManager] = None
_manager_lock = threading.Lock()


def get_context_manager() -> AsyncContextManager:
    """Get global context manager."""
    global _global_context_manager
    with _manager_lock:
        if _global_context_manager is None:
            _global_context_manager = AsyncContextManager()
        return _global_context_manager


def set_context_manager(manager: AsyncContextManager):
    """Set global context manager."""
    global _global_context_manager
    with _manager_lock:
        _global_context_manager = manager


@asynccontextmanager
async def async_context(
    scope: ContextScope = ContextScope.TASK,
    priority: ContextPriority = ContextPriority.NORMAL,
    auto_cleanup: bool = True,
    **metadata
) -> AsyncIterator[str]:
    """Async context manager for managing async contexts."""
    manager = get_context_manager()
    context_id = await manager.create_context(scope, priority, **metadata)
    
    try:
        await manager.activate_context(context_id)
        yield context_id
        await manager.complete_context(context_id)
    except asyncio.CancelledError:
        await manager.cancel_context(context_id)
        raise
    except Exception as e:
        await manager.error_context(context_id, e)
        raise


@asynccontextmanager
async def async_resource_context(
    resource: AsyncResource,
    pool_id: str = "default",
    scope: ContextScope = ContextScope.TASK,
    **kwargs
) -> AsyncIterator[AsyncResource]:
    """Async context manager for managing resources."""
    manager = get_context_manager()
    
    # Get or create resource pool
    pool = manager.get_resource_pool(pool_id)
    if pool is None:
        pool = manager.create_resource_pool(pool_id)
        await pool.start_cleanup_task()
    
    # Create context for resource
    async with async_context(scope=scope) as context_id:
        await resource.initialize()
        await pool.add_resource(resource, context_id, scope, **kwargs)
        
        try:
            yield resource
        finally:
            await pool.remove_resource(resource.resource_id)


def async_context_aware(
    scope: ContextScope = ContextScope.TASK,
    priority: ContextPriority = ContextPriority.NORMAL,
    auto_cleanup: bool = True,
    propagate_context: bool = True
):
    """Decorator to make functions async context aware."""
    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            if propagate_context:
                # Use existing context if available
                current_task = asyncio.current_task()
                task_id = str(id(current_task)) if current_task else None
                
                manager = get_context_manager()
                existing_context = None
                
                # Try to find existing context for this task
                for ctx_id, ctx_info in manager._contexts.items():
                    if ctx_info.task_id == task_id and ctx_info.state == ContextState.ACTIVE:
                        existing_context = ctx_id
                        break
                
                if existing_context:
                    # Use existing context
                    return await func(*args, **kwargs)
            
            # Create new context
            async with async_context(scope, priority, auto_cleanup) as context_id:
                return await func(*args, **kwargs)
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            # For sync functions, create a simple context
            return func(*args, **kwargs)
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


class AsyncShieldWrapper:
    """Wrapper for shields with async context management."""
    
    def __init__(
        self,
        shield: Shield,
        context_scope: ContextScope = ContextScope.REQUEST,
        resource_pool_id: str = "shields",
        auto_cleanup: bool = True
    ):
        self.shield = shield
        self.context_scope = context_scope
        self.resource_pool_id = resource_pool_id
        self.auto_cleanup = auto_cleanup
        self._context_manager = get_context_manager()
    
    async def __call__(self, request: Request, *args, **kwargs):
        """Execute shield with async context management."""
        # Create context for shield execution
        async with async_context(
            scope=self.context_scope,
            shield_name=getattr(self.shield, '__name__', 'unknown'),
            request_path=request.url.path,
            request_method=request.method
        ) as context_id:
            # Set context variables
            await self._context_manager.set_context_variable(context_id, 'request', request)
            await self._context_manager.set_context_variable(context_id, 'shield', self.shield)
            
            # Execute shield
            try:
                if asyncio.iscoroutinefunction(self.shield.shield_func):
                    result = await self.shield.shield_func(request, *args, **kwargs)
                else:
                    result = await run_in_threadpool(self.shield.shield_func, request, *args, **kwargs)
                
                await self._context_manager.set_context_variable(context_id, 'result', result)
                return result
            
            except Exception as e:
                await self._context_manager.set_context_variable(context_id, 'error', e)
                raise


def shield_with_async_context(
    context_scope: ContextScope = ContextScope.REQUEST,
    resource_pool_id: str = "shields",
    auto_cleanup: bool = True
):
    """Decorator to add async context management to shields."""
    def decorator(shield_class_or_func):
        if isinstance(shield_class_or_func, Shield):
            return AsyncShieldWrapper(
                shield_class_or_func,
                context_scope,
                resource_pool_id,
                auto_cleanup
            )
        elif callable(shield_class_or_func):
            # Wrap function in shield first
            shield = Shield(shield_class_or_func)
            return AsyncShieldWrapper(
                shield,
                context_scope,
                resource_pool_id,
                auto_cleanup
            )
        else:
            raise TypeError("Expected Shield instance or callable")
    
    return decorator


# Context variables for common use cases
current_request: ContextVariable[Optional[Request]] = ContextVariable(
    "current_request", None, ContextScope.REQUEST
)

current_response: ContextVariable[Optional[Response]] = ContextVariable(
    "current_response", None, ContextScope.REQUEST
)

current_user: ContextVariable[Optional[Any]] = ContextVariable(
    "current_user", None, ContextScope.REQUEST
)

current_shield: ContextVariable[Optional[Shield]] = ContextVariable(
    "current_shield", None, ContextScope.TASK
)


# Utility functions
async def get_current_context_id() -> Optional[str]:
    """Get current context ID."""
    manager = get_context_manager()
    current_task = asyncio.current_task()
    
    if not current_task:
        return None
    
    task_id = str(id(current_task))
    
    # Find active context for current task
    for ctx_id, ctx_info in manager._contexts.items():
        if ctx_info.task_id == task_id and ctx_info.state == ContextState.ACTIVE:
            return ctx_id
    
    return None


async def get_current_context() -> Optional[AsyncContextInfo]:
    """Get current context info."""
    context_id = await get_current_context_id()
    if context_id:
        manager = get_context_manager()
        return await manager.get_context(context_id)
    return None


async def set_context_variable(key: str, value: Any):
    """Set variable in current context."""
    context_id = await get_current_context_id()
    if context_id:
        manager = get_context_manager()
        await manager.set_context_variable(context_id, key, value)


async def get_context_variable(key: str, default: Any = None) -> Any:
    """Get variable from current context."""
    context_id = await get_current_context_id()
    if context_id:
        manager = get_context_manager()
        return await manager.get_context_variable(context_id, key, default)
    return default


async def cleanup_context_resources(scope: ContextScope):
    """Clean up resources for a scope."""
    manager = get_context_manager()
    total_cleaned = 0
    
    for pool in manager._resource_pools.values():
        cleaned = await pool.cleanup_scope_resources(scope)
        total_cleaned += cleaned
    
    return total_cleaned


async def get_context_metrics() -> Dict[str, Any]:
    """Get context metrics."""
    manager = get_context_manager()
    return manager.get_metrics()


# Exception handling with async context
class AsyncContextExceptionHandler:
    """Exception handler with async context support."""
    
    def __init__(self):
        self._handlers: Dict[Type[Exception], List[Callable]] = defaultdict(list)
    
    def register_handler(self, exception_type: Type[Exception], handler: Callable):
        """Register exception handler."""
        self._handlers[exception_type].append(handler)
    
    async def handle_exception(self, exception: Exception, context_id: Optional[str] = None):
        """Handle exception with context."""
        if context_id is None:
            context_id = await get_current_context_id()
        
        handlers = self._handlers.get(type(exception), [])
        handlers.extend(self._handlers.get(Exception, []))
        
        for handler in handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(exception, context_id)
                else:
                    handler(exception, context_id)
            except Exception as handler_error:
                logger.error(f"Exception handler failed: {handler_error}")


# Global exception handler
_global_exception_handler = AsyncContextExceptionHandler()


def get_exception_handler() -> AsyncContextExceptionHandler:
    """Get global exception handler."""
    return _global_exception_handler


def register_exception_handler(exception_type: Type[Exception], handler: Callable):
    """Register global exception handler."""
    _global_exception_handler.register_handler(exception_type, handler)


# Async context initialization
async def initialize_async_context_system():
    """Initialize the async context system."""
    manager = get_context_manager()
    await manager.start()
    
    # Create default resource pools
    manager.create_resource_pool("default", max_resources=1000)
    manager.create_resource_pool("shields", max_resources=500)
    manager.create_resource_pool("requests", max_resources=2000)
    
    logger.info("Async context system initialized")


async def shutdown_async_context_system():
    """Shutdown the async context system."""
    manager = get_context_manager()
    await manager.stop()
    logger.info("Async context system shutdown")


# FastAPI integration
def setup_async_context_middleware(app):
    """Set up async context middleware for FastAPI."""
    from fastapi.middleware.base import BaseHTTPMiddleware
    
    class AsyncContextMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            async with async_context(
                scope=ContextScope.REQUEST,
                request_path=request.url.path,
                request_method=request.method
            ) as context_id:
                # Set request in context
                current_request.set(request)
                await set_context_variable('request_id', context_id)
                
                try:
                    response = await call_next(request)
                    current_response.set(response)
                    return response
                except Exception as e:
                    await get_exception_handler().handle_exception(e, context_id)
                    raise
    
    app.add_middleware(AsyncContextMiddleware)
    return app