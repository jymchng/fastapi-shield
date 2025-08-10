"""Mock classes and utilities for testing async context management."""

import asyncio
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set
from unittest.mock import AsyncMock, MagicMock

from fastapi import Request, Response
from fastapi_shield.async_context import (
    AsyncResource, AsyncContextInfo, ResourceInfo, ContextScope,
    ContextState, ContextPriority, CleanupStrategy
)
from fastapi_shield.shield import Shield


class MockAsyncResource(AsyncResource):
    """Mock async resource for testing."""
    
    def __init__(
        self,
        resource_id: str,
        cleanup_strategy: CleanupStrategy = CleanupStrategy.IMMEDIATE,
        initialize_delay: float = 0.0,
        cleanup_delay: float = 0.0,
        fail_initialize: bool = False,
        fail_cleanup: bool = False
    ):
        super().__init__(resource_id, cleanup_strategy)
        self.initialize_delay = initialize_delay
        self.cleanup_delay = cleanup_delay
        self.fail_initialize = fail_initialize
        self.fail_cleanup = fail_cleanup
        self.initialized = False
        self.cleaned_up = False
        self.initialize_called = False
        self.cleanup_called = False
        
    async def initialize(self) -> None:
        """Initialize the mock resource."""
        self.initialize_called = True
        
        if self.initialize_delay > 0:
            await asyncio.sleep(self.initialize_delay)
        
        if self.fail_initialize:
            raise RuntimeError(f"Failed to initialize resource {self.resource_id}")
        
        self.initialized = True
        
    async def cleanup(self) -> None:
        """Clean up the mock resource."""
        self.cleanup_called = True
        
        if self.cleanup_delay > 0:
            await asyncio.sleep(self.cleanup_delay)
        
        if self.fail_cleanup:
            raise RuntimeError(f"Failed to cleanup resource {self.resource_id}")
        
        self.cleaned_up = True
        await self._execute_cleanup_callbacks()


class MockDatabaseResource(MockAsyncResource):
    """Mock database resource."""
    
    def __init__(self, resource_id: str, **kwargs):
        super().__init__(resource_id, **kwargs)
        self.connections = []
        self.max_connections = 10
        
    async def initialize(self) -> None:
        """Initialize database connections."""
        await super().initialize()
        self.connections = [f"conn_{i}" for i in range(self.max_connections)]
        
    async def cleanup(self) -> None:
        """Close database connections."""
        self.connections.clear()
        await super().cleanup()
        
    def get_connection(self) -> str:
        """Get a database connection."""
        if self.connections:
            return self.connections.pop()
        raise RuntimeError("No available connections")


class MockCacheResource(MockAsyncResource):
    """Mock cache resource."""
    
    def __init__(self, resource_id: str, **kwargs):
        super().__init__(resource_id, **kwargs)
        self.cache_data = {}
        self.cache_size = 0
        
    async def initialize(self) -> None:
        """Initialize cache."""
        await super().initialize()
        self.cache_data = {}
        
    async def cleanup(self) -> None:
        """Clear cache."""
        self.cache_data.clear()
        self.cache_size = 0
        await super().cleanup()
        
    def set(self, key: str, value: Any):
        """Set cache value."""
        self.cache_data[key] = value
        self.cache_size = len(self.cache_data)
        
    def get(self, key: str, default=None):
        """Get cache value."""
        return self.cache_data.get(key, default)


class MockNetworkResource(MockAsyncResource):
    """Mock network resource."""
    
    def __init__(self, resource_id: str, **kwargs):
        super().__init__(resource_id, **kwargs)
        self.connections = {}
        self.max_connections = 5
        
    async def initialize(self) -> None:
        """Initialize network connections."""
        await super().initialize()
        self.connections = {}
        
    async def cleanup(self) -> None:
        """Close network connections."""
        for conn in self.connections.values():
            await self._close_connection(conn)
        self.connections.clear()
        await super().cleanup()
        
    async def _close_connection(self, conn):
        """Close a single connection."""
        await asyncio.sleep(0.01)  # Simulate network cleanup
        
    async def connect(self, host: str, port: int):
        """Create a network connection."""
        if len(self.connections) >= self.max_connections:
            raise RuntimeError("Too many connections")
        
        conn_id = f"{host}:{port}"
        self.connections[conn_id] = {"host": host, "port": port, "connected": True}
        return conn_id


class MockShield(Shield):
    """Mock shield for testing async context integration."""
    
    def __init__(
        self,
        name: str = "test_shield",
        should_pass: bool = True,
        execution_delay: float = 0.0,
        raise_exception: Optional[Exception] = None,
        require_context: bool = False
    ):
        self.name = name
        self.should_pass = should_pass
        self.execution_delay = execution_delay
        self.raise_exception = raise_exception
        self.require_context = require_context
        self.call_count = 0
        self.last_request = None
        self.context_info = {}
        
        super().__init__(self._mock_shield_func, name=name)
        
    async def _mock_shield_func(self, request: Request, **kwargs):
        """Mock shield function."""
        self.call_count += 1
        self.last_request = request
        
        if self.execution_delay > 0:
            await asyncio.sleep(self.execution_delay)
        
        if self.raise_exception:
            raise self.raise_exception
        
        if self.require_context:
            # Check if we're in an async context
            from fastapi_shield.async_context import get_current_context_id
            context_id = await get_current_context_id()
            if not context_id:
                raise RuntimeError("No async context available")
            self.context_info["context_id"] = context_id
        
        return self.should_pass


class MockContextInfo:
    """Mock context info for testing."""
    
    def __init__(
        self,
        context_id: str = None,
        scope: ContextScope = ContextScope.TASK,
        state: ContextState = ContextState.CREATED,
        **kwargs
    ):
        self.context_id = context_id or str(uuid.uuid4())
        self.scope = scope
        self.state = state
        self.priority = kwargs.get('priority', ContextPriority.NORMAL)
        self.created_at = kwargs.get('created_at', datetime.now())
        self.last_accessed = kwargs.get('last_accessed', datetime.now())
        self.task_id = kwargs.get('task_id')
        self.request_id = kwargs.get('request_id')
        self.session_id = kwargs.get('session_id')
        self.parent_context_id = kwargs.get('parent_context_id')
        self.child_context_ids = kwargs.get('child_context_ids', set())
        self.variables = kwargs.get('variables', {})
        self.resources = kwargs.get('resources', {})
        self.cleanup_callbacks = kwargs.get('cleanup_callbacks', [])
        self.metadata = kwargs.get('metadata', {})
        
    def mark_accessed(self):
        """Mark context as accessed."""
        self.last_accessed = datetime.now()


class MockResourceInfo:
    """Mock resource info for testing."""
    
    def __init__(
        self,
        resource_id: str = None,
        resource_type: str = "MockResource",
        resource: Any = None,
        context_id: str = None,
        scope: ContextScope = ContextScope.TASK,
        **kwargs
    ):
        self.resource_id = resource_id or str(uuid.uuid4())
        self.resource_type = resource_type
        self.resource = resource or MockAsyncResource(self.resource_id)
        self.context_id = context_id or str(uuid.uuid4())
        self.scope = scope
        self.cleanup_strategy = kwargs.get('cleanup_strategy', CleanupStrategy.IMMEDIATE)
        self.priority = kwargs.get('priority', ContextPriority.NORMAL)
        self.created_at = kwargs.get('created_at', datetime.now())
        self.last_used = kwargs.get('last_used', datetime.now())
        self.cleanup_callback = kwargs.get('cleanup_callback')
        self.dependencies = kwargs.get('dependencies', set())
        self.metadata = kwargs.get('metadata', {})
        
    def mark_used(self):
        """Mark resource as used."""
        self.last_used = datetime.now()


class MockRequest:
    """Mock FastAPI request for testing."""
    
    def __init__(
        self,
        method: str = "GET",
        url_path: str = "/test",
        headers: Dict[str, str] = None,
        query_params: Dict[str, str] = None,
        body: bytes = b"",
        **kwargs
    ):
        self.method = method
        self.url = MockURL(url_path, query_params or {})
        self.headers = headers or {}
        self.query_params = query_params or {}
        self.body = body
        self.state = MagicMock()
        
        # Add any additional attributes
        for key, value in kwargs.items():
            setattr(self, key, value)


class MockURL:
    """Mock URL for testing."""
    
    def __init__(self, path: str, query_params: Dict[str, str] = None):
        self.path = path
        self.query_params = query_params or {}
        
    @property
    def query(self) -> str:
        """Get query string."""
        if not self.query_params:
            return ""
        return "&".join(f"{k}={v}" for k, v in self.query_params.items())


class MockResponse:
    """Mock FastAPI response for testing."""
    
    def __init__(
        self,
        status_code: int = 200,
        headers: Dict[str, str] = None,
        body: Any = None,
        **kwargs
    ):
        self.status_code = status_code
        self.headers = headers or {}
        self.body = body
        
        # Add any additional attributes
        for key, value in kwargs.items():
            setattr(self, key, value)


class AsyncContextManagerMock:
    """Mock async context manager for testing."""
    
    def __init__(
        self,
        contexts: Dict[str, AsyncContextInfo] = None,
        resource_pools: Dict[str, Any] = None,
        context_vars: Dict[str, Any] = None
    ):
        self.contexts = contexts or {}
        self.resource_pools = resource_pools or {}
        self.context_vars = context_vars or {}
        self._lock = asyncio.Lock()
        self.metrics = {
            "contexts_created": 0,
            "contexts_completed": 0,
            "contexts_cancelled": 0,
            "contexts_errors": 0,
            "resources_managed": 0,
            "cleanup_operations": 0
        }
        
        # Track method calls for testing
        self.method_calls = {}
        
    def _track_call(self, method_name: str, *args, **kwargs):
        """Track method calls for testing."""
        if method_name not in self.method_calls:
            self.method_calls[method_name] = []
        self.method_calls[method_name].append((args, kwargs))
    
    async def create_context(self, scope=ContextScope.TASK, **kwargs):
        """Mock create context."""
        self._track_call("create_context", scope, **kwargs)
        context_id = str(uuid.uuid4())
        
        context_info = AsyncContextInfo(
            context_id=context_id,
            scope=scope,
            **kwargs
        )
        
        self.contexts[context_id] = context_info
        self.metrics["contexts_created"] += 1
        return context_id
    
    async def get_context(self, context_id: str):
        """Mock get context."""
        self._track_call("get_context", context_id)
        return self.contexts.get(context_id)
    
    async def activate_context(self, context_id: str):
        """Mock activate context."""
        self._track_call("activate_context", context_id)
        if context_id in self.contexts:
            self.contexts[context_id].state = ContextState.ACTIVE
    
    async def complete_context(self, context_id: str):
        """Mock complete context."""
        self._track_call("complete_context", context_id)
        if context_id in self.contexts:
            self.contexts[context_id].state = ContextState.COMPLETED
            self.metrics["contexts_completed"] += 1
    
    async def cancel_context(self, context_id: str):
        """Mock cancel context."""
        self._track_call("cancel_context", context_id)
        if context_id in self.contexts:
            self.contexts[context_id].state = ContextState.CANCELLED
            self.metrics["contexts_cancelled"] += 1
    
    async def error_context(self, context_id: str, error: Exception):
        """Mock error context."""
        self._track_call("error_context", context_id, error)
        if context_id in self.contexts:
            self.contexts[context_id].state = ContextState.ERROR
            self.contexts[context_id].metadata["error"] = str(error)
            self.metrics["contexts_errors"] += 1
    
    async def set_context_variable(self, context_id: str, key: str, value: Any):
        """Mock set context variable."""
        self._track_call("set_context_variable", context_id, key, value)
        if context_id in self.contexts:
            self.contexts[context_id].variables[key] = value
    
    async def get_context_variable(self, context_id: str, key: str, default=None):
        """Mock get context variable."""
        self._track_call("get_context_variable", context_id, key, default)
        if context_id in self.contexts:
            return self.contexts[context_id].variables.get(key, default)
        return default
    
    def get_metrics(self):
        """Mock get metrics."""
        self._track_call("get_metrics")
        return {
            **self.metrics,
            "active_contexts": len(self.contexts),
            "resource_pools": len(self.resource_pools),
            "context_variables": len(self.context_vars),
            "method_calls": self.method_calls
        }


class MockAsyncResourcePool:
    """Mock async resource pool for testing."""
    
    def __init__(
        self,
        pool_id: str,
        max_resources: int = 100,
        cleanup_interval: float = 60.0
    ):
        self.pool_id = pool_id
        self.max_resources = max_resources
        self.cleanup_interval = cleanup_interval
        self.resources = {}
        self.by_context = {}
        self.by_scope = {}
        self.stats = {
            "created": 0,
            "cleaned": 0,
            "errors": 0,
            "active": 0
        }
        
        # Track method calls
        self.method_calls = {}
    
    def _track_call(self, method_name: str, *args, **kwargs):
        """Track method calls for testing."""
        if method_name not in self.method_calls:
            self.method_calls[method_name] = []
        self.method_calls[method_name].append((args, kwargs))
    
    async def add_resource(self, resource, context_id, scope=ContextScope.TASK, **kwargs):
        """Mock add resource."""
        self._track_call("add_resource", resource, context_id, scope, **kwargs)
        
        if len(self.resources) >= self.max_resources:
            raise RuntimeError("Pool is full")
        
        resource_info = ResourceInfo(
            resource_id=resource.resource_id,
            resource_type=resource.__class__.__name__,
            resource=resource,
            context_id=context_id,
            scope=scope,
            **kwargs
        )
        
        self.resources[resource.resource_id] = resource_info
        
        if context_id not in self.by_context:
            self.by_context[context_id] = set()
        self.by_context[context_id].add(resource.resource_id)
        
        if scope not in self.by_scope:
            self.by_scope[scope] = set()
        self.by_scope[scope].add(resource.resource_id)
        
        self.stats["created"] += 1
        self.stats["active"] = len(self.resources)
        
        return resource.resource_id
    
    async def get_resource(self, resource_id: str):
        """Mock get resource."""
        self._track_call("get_resource", resource_id)
        resource_info = self.resources.get(resource_id)
        if resource_info:
            resource_info.mark_used()
            return resource_info.resource
        return None
    
    async def remove_resource(self, resource_id: str):
        """Mock remove resource."""
        self._track_call("remove_resource", resource_id)
        resource_info = self.resources.get(resource_id)
        
        if not resource_info:
            return False
        
        # Mock cleanup
        try:
            await resource_info.resource.cleanup()
            self.stats["cleaned"] += 1
        except Exception:
            self.stats["errors"] += 1
        
        # Remove from tracking
        del self.resources[resource_id]
        
        if resource_info.context_id in self.by_context:
            self.by_context[resource_info.context_id].discard(resource_id)
        
        if resource_info.scope in self.by_scope:
            self.by_scope[resource_info.scope].discard(resource_id)
        
        self.stats["active"] = len(self.resources)
        return True
    
    async def cleanup_context_resources(self, context_id: str):
        """Mock cleanup context resources."""
        self._track_call("cleanup_context_resources", context_id)
        resource_ids = list(self.by_context.get(context_id, set()))
        cleaned_count = 0
        
        for resource_id in resource_ids:
            if await self.remove_resource(resource_id):
                cleaned_count += 1
        
        return cleaned_count
    
    async def cleanup_scope_resources(self, scope: ContextScope):
        """Mock cleanup scope resources."""
        self._track_call("cleanup_scope_resources", scope)
        resource_ids = list(self.by_scope.get(scope, set()))
        cleaned_count = 0
        
        for resource_id in resource_ids:
            if await self.remove_resource(resource_id):
                cleaned_count += 1
        
        return cleaned_count
    
    async def start_cleanup_task(self):
        """Mock start cleanup task."""
        self._track_call("start_cleanup_task")
    
    async def stop_cleanup_task(self):
        """Mock stop cleanup task."""
        self._track_call("stop_cleanup_task")
    
    def get_stats(self):
        """Mock get stats."""
        self._track_call("get_stats")
        return {
            **self.stats,
            "pool_id": self.pool_id,
            "max_resources": self.max_resources,
            "cleanup_interval": self.cleanup_interval,
            "contexts": len(self.by_context),
            "scopes": {scope.value: len(resources) for scope, resources in self.by_scope.items()}
        }


def create_mock_context_info(
    context_id: str = None,
    scope: ContextScope = ContextScope.TASK,
    state: ContextState = ContextState.ACTIVE,
    **kwargs
) -> AsyncContextInfo:
    """Create mock context info."""
    return AsyncContextInfo(
        context_id=context_id or str(uuid.uuid4()),
        scope=scope,
        state=state,
        **kwargs
    )


def create_mock_resource_info(
    resource_id: str = None,
    context_id: str = None,
    **kwargs
) -> ResourceInfo:
    """Create mock resource info."""
    resource = MockAsyncResource(resource_id or str(uuid.uuid4()))
    return ResourceInfo(
        resource_id=resource.resource_id,
        resource_type="MockAsyncResource",
        resource=resource,
        context_id=context_id or str(uuid.uuid4()),
        scope=ContextScope.TASK,
        **kwargs
    )


def create_mock_request(
    method: str = "GET",
    path: str = "/test",
    **kwargs
) -> MockRequest:
    """Create mock request."""
    return MockRequest(method=method, url_path=path, **kwargs)


def create_mock_response(
    status_code: int = 200,
    **kwargs
) -> MockResponse:
    """Create mock response."""
    return MockResponse(status_code=status_code, **kwargs)


async def create_test_resources(count: int = 5) -> List[MockAsyncResource]:
    """Create test resources."""
    resources = []
    
    for i in range(count):
        resource = MockAsyncResource(f"test_resource_{i}")
        await resource.initialize()
        resources.append(resource)
    
    return resources


def create_mock_shield(
    name: str = "test_shield",
    should_pass: bool = True,
    **kwargs
) -> MockShield:
    """Create mock shield."""
    return MockShield(name=name, should_pass=should_pass, **kwargs)


class AsyncTaskTracker:
    """Track async tasks for testing."""
    
    def __init__(self):
        self.tasks = []
        self.completed_tasks = []
        self.failed_tasks = []
        
    async def track_task(self, coro):
        """Track an async task."""
        task = asyncio.create_task(coro)
        self.tasks.append(task)
        
        try:
            result = await task
            self.completed_tasks.append(task)
            return result
        except Exception as e:
            self.failed_tasks.append((task, e))
            raise
    
    def get_stats(self):
        """Get task statistics."""
        return {
            "total_tasks": len(self.tasks),
            "completed_tasks": len(self.completed_tasks),
            "failed_tasks": len(self.failed_tasks),
            "active_tasks": len(self.tasks) - len(self.completed_tasks) - len(self.failed_tasks)
        }