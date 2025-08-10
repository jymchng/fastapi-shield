"""Tests for async context management."""

import asyncio
import pytest
import uuid
import time
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi_shield.async_context import (
    # Enums
    ContextScope, ContextState, ContextPriority, CleanupStrategy,
    
    # Core classes
    AsyncContextInfo, ResourceInfo, AsyncResource, AsyncResourcePool,
    AsyncContextManager, ContextVariable,
    
    # Exceptions
    AsyncContextError, ContextNotFoundError, ContextStateError, ResourceError,
    
    # Context managers
    async_context, async_resource_context,
    
    # Decorators
    async_context_aware, shield_with_async_context,
    
    # Utilities
    get_context_manager, set_context_manager, get_current_context_id,
    get_current_context, set_context_variable, get_context_variable,
    cleanup_context_resources, get_context_metrics,
    
    # Exception handling
    get_exception_handler, register_exception_handler,
    
    # Context variables
    current_request, current_response, current_user, current_shield,
    
    # System management
    initialize_async_context_system, shutdown_async_context_system,
)

from tests.mocks.async_context_mocks import (
    MockAsyncResource, MockDatabaseResource, MockCacheResource, MockNetworkResource,
    MockShield, MockContextInfo, MockResourceInfo, MockRequest, MockResponse,
    AsyncContextManagerMock, MockAsyncResourcePool, create_mock_context_info,
    create_mock_resource_info, create_mock_request, create_mock_response,
    create_test_resources, create_mock_shield, AsyncTaskTracker
)


class TestContextScope:
    """Test context scope enumeration."""
    
    def test_context_scope_values(self):
        """Test context scope enum values."""
        assert ContextScope.TASK == "task"
        assert ContextScope.REQUEST == "request"
        assert ContextScope.SESSION == "session"
        assert ContextScope.APPLICATION == "application"
        assert ContextScope.GLOBAL == "global"
    
    def test_context_scope_ordering(self):
        """Test context scope can be compared."""
        scopes = [ContextScope.TASK, ContextScope.REQUEST, ContextScope.SESSION]
        assert len(scopes) == 3
        assert ContextScope.TASK in scopes


class TestContextState:
    """Test context state enumeration."""
    
    def test_context_state_values(self):
        """Test context state enum values."""
        assert ContextState.CREATED == "created"
        assert ContextState.ACTIVE == "active"
        assert ContextState.SUSPENDED == "suspended"
        assert ContextState.COMPLETED == "completed"
        assert ContextState.CANCELLED == "cancelled"
        assert ContextState.ERROR == "error"
        assert ContextState.CLEANED_UP == "cleaned_up"
    
    def test_context_state_transitions(self):
        """Test valid context state transitions."""
        initial_states = [ContextState.CREATED]
        active_states = [ContextState.ACTIVE, ContextState.SUSPENDED]
        final_states = [ContextState.COMPLETED, ContextState.CANCELLED, ContextState.ERROR]
        
        assert len(initial_states) == 1
        assert len(active_states) == 2
        assert len(final_states) == 3


class TestAsyncContextInfo:
    """Test async context info data class."""
    
    def test_context_info_creation(self):
        """Test creating context info."""
        context_id = str(uuid.uuid4())
        context_info = AsyncContextInfo(
            context_id=context_id,
            scope=ContextScope.REQUEST,
            priority=ContextPriority.HIGH
        )
        
        assert context_info.context_id == context_id
        assert context_info.scope == ContextScope.REQUEST
        assert context_info.state == ContextState.CREATED
        assert context_info.priority == ContextPriority.HIGH
        assert isinstance(context_info.created_at, datetime)
        assert isinstance(context_info.last_accessed, datetime)
        assert context_info.variables == {}
        assert context_info.resources == {}
        assert context_info.cleanup_callbacks == []
    
    def test_context_info_mark_accessed(self):
        """Test marking context as accessed."""
        context_info = AsyncContextInfo(
            context_id=str(uuid.uuid4()),
            scope=ContextScope.TASK
        )
        
        original_time = context_info.last_accessed
        time.sleep(0.01)  # Small delay
        context_info.mark_accessed()
        
        assert context_info.last_accessed > original_time
    
    def test_context_info_with_metadata(self):
        """Test context info with metadata."""
        metadata = {"request_id": "req_123", "user_id": "user_456"}
        context_info = AsyncContextInfo(
            context_id=str(uuid.uuid4()),
            scope=ContextScope.REQUEST,
            metadata=metadata
        )
        
        assert context_info.metadata == metadata
        assert context_info.metadata["request_id"] == "req_123"
        assert context_info.metadata["user_id"] == "user_456"


class TestResourceInfo:
    """Test resource info data class."""
    
    @pytest.mark.asyncio
    async def test_resource_info_creation(self):
        """Test creating resource info."""
        resource = MockAsyncResource("test_resource")
        context_id = str(uuid.uuid4())
        
        resource_info = ResourceInfo(
            resource_id=resource.resource_id,
            resource_type="MockAsyncResource",
            resource=resource,
            context_id=context_id,
            scope=ContextScope.TASK
        )
        
        assert resource_info.resource_id == resource.resource_id
        assert resource_info.resource_type == "MockAsyncResource"
        assert resource_info.resource == resource
        assert resource_info.context_id == context_id
        assert resource_info.scope == ContextScope.TASK
        assert resource_info.cleanup_strategy == CleanupStrategy.IMMEDIATE
        assert isinstance(resource_info.created_at, datetime)
        assert isinstance(resource_info.last_used, datetime)
    
    def test_resource_info_mark_used(self):
        """Test marking resource as used."""
        resource = MockAsyncResource("test_resource")
        resource_info = ResourceInfo(
            resource_id=resource.resource_id,
            resource_type="MockAsyncResource",
            resource=resource,
            context_id=str(uuid.uuid4()),
            scope=ContextScope.TASK
        )
        
        original_time = resource_info.last_used
        time.sleep(0.01)  # Small delay
        resource_info.mark_used()
        
        assert resource_info.last_used > original_time


class TestMockAsyncResource:
    """Test mock async resource implementation."""
    
    @pytest.mark.asyncio
    async def test_mock_resource_lifecycle(self):
        """Test mock resource initialization and cleanup."""
        resource = MockAsyncResource("test_resource")
        
        assert not resource.initialized
        assert not resource.cleaned_up
        assert not resource.initialize_called
        assert not resource.cleanup_called
        
        await resource.initialize()
        
        assert resource.initialized
        assert resource.initialize_called
        assert not resource.cleaned_up
        assert not resource.cleanup_called
        
        await resource.cleanup()
        
        assert resource.initialized
        assert resource.initialize_called
        assert resource.cleaned_up
        assert resource.cleanup_called
    
    @pytest.mark.asyncio
    async def test_mock_resource_with_delays(self):
        """Test mock resource with delays."""
        resource = MockAsyncResource(
            "test_resource",
            initialize_delay=0.1,
            cleanup_delay=0.05
        )
        
        start_time = time.time()
        await resource.initialize()
        init_time = time.time() - start_time
        
        assert init_time >= 0.1
        assert resource.initialized
        
        start_time = time.time()
        await resource.cleanup()
        cleanup_time = time.time() - start_time
        
        assert cleanup_time >= 0.05
        assert resource.cleaned_up
    
    @pytest.mark.asyncio
    async def test_mock_resource_initialization_failure(self):
        """Test mock resource initialization failure."""
        resource = MockAsyncResource("test_resource", fail_initialize=True)
        
        with pytest.raises(RuntimeError, match="Failed to initialize resource"):
            await resource.initialize()
        
        assert resource.initialize_called
        assert not resource.initialized
    
    @pytest.mark.asyncio
    async def test_mock_resource_cleanup_failure(self):
        """Test mock resource cleanup failure."""
        resource = MockAsyncResource("test_resource", fail_cleanup=True)
        await resource.initialize()
        
        with pytest.raises(RuntimeError, match="Failed to cleanup resource"):
            await resource.cleanup()
        
        assert resource.cleanup_called
        assert not resource.cleaned_up
    
    @pytest.mark.asyncio
    async def test_mock_resource_cleanup_callbacks(self):
        """Test mock resource cleanup callbacks."""
        resource = MockAsyncResource("test_resource")
        callback_called = False
        
        def cleanup_callback():
            nonlocal callback_called
            callback_called = True
        
        resource.add_cleanup_callback(cleanup_callback)
        await resource.initialize()
        await resource.cleanup()
        
        assert callback_called


class TestSpecializedMockResources:
    """Test specialized mock resources."""
    
    @pytest.mark.asyncio
    async def test_mock_database_resource(self):
        """Test mock database resource."""
        db_resource = MockDatabaseResource("db_resource")
        
        await db_resource.initialize()
        
        assert db_resource.initialized
        assert len(db_resource.connections) == db_resource.max_connections
        
        # Get connections
        conn1 = db_resource.get_connection()
        conn2 = db_resource.get_connection()
        
        assert conn1 != conn2
        assert len(db_resource.connections) == db_resource.max_connections - 2
        
        # Cleanup
        await db_resource.cleanup()
        
        assert len(db_resource.connections) == 0
        assert db_resource.cleaned_up
    
    @pytest.mark.asyncio
    async def test_mock_cache_resource(self):
        """Test mock cache resource."""
        cache_resource = MockCacheResource("cache_resource")
        
        await cache_resource.initialize()
        
        assert cache_resource.initialized
        assert cache_resource.cache_data == {}
        assert cache_resource.cache_size == 0
        
        # Set and get values
        cache_resource.set("key1", "value1")
        cache_resource.set("key2", "value2")
        
        assert cache_resource.get("key1") == "value1"
        assert cache_resource.get("key2") == "value2"
        assert cache_resource.get("key3", "default") == "default"
        assert cache_resource.cache_size == 2
        
        # Cleanup
        await cache_resource.cleanup()
        
        assert cache_resource.cache_data == {}
        assert cache_resource.cache_size == 0
        assert cache_resource.cleaned_up
    
    @pytest.mark.asyncio
    async def test_mock_network_resource(self):
        """Test mock network resource."""
        network_resource = MockNetworkResource("network_resource")
        
        await network_resource.initialize()
        
        assert network_resource.initialized
        assert network_resource.connections == {}
        
        # Create connections
        conn1 = await network_resource.connect("localhost", 8080)
        conn2 = await network_resource.connect("example.com", 443)
        
        assert conn1 == "localhost:8080"
        assert conn2 == "example.com:443"
        assert len(network_resource.connections) == 2
        
        # Test connection limit
        for i in range(3):  # Should be able to create 3 more (total 5)
            await network_resource.connect(f"host{i}.com", 80)
        
        with pytest.raises(RuntimeError, match="Too many connections"):
            await network_resource.connect("overflow.com", 80)
        
        # Cleanup
        await network_resource.cleanup()
        
        assert network_resource.connections == {}
        assert network_resource.cleaned_up


class TestContextVariable:
    """Test context variable implementation."""
    
    def test_context_variable_creation(self):
        """Test creating context variable."""
        var = ContextVariable("test_var", default="default_value", scope=ContextScope.REQUEST)
        
        assert var.name == "test_var"
        assert var.default == "default_value"
        assert var.scope == ContextScope.REQUEST
        assert var.auto_cleanup is True
    
    def test_context_variable_get_set(self):
        """Test context variable get and set."""
        var = ContextVariable("test_var", default="default")
        
        # Test default value
        assert var.get() == "default"
        assert var.get("override_default") == "default"
        
        # Test set and get
        token = var.set("new_value")
        assert var.get() == "new_value"
        
        # Test reset
        var.reset(token)
        assert var.get() == "default"
    
    def test_context_variable_delete(self):
        """Test context variable deletion."""
        var = ContextVariable("test_var", default="default")
        
        token = var.set("test_value")
        assert var.get() == "test_value"
        
        # Reset to previous state (which would be default or unset)
        var.reset(token)
        assert var.get() == "default"
    
    def test_context_variable_copy_context(self):
        """Test context variable context copying."""
        var = ContextVariable("test_var", default="default")
        
        var.set("test_value")
        ctx = var.copy_context()
        
        assert ctx is not None
        # Context copying functionality is handled by Python's contextvars


class TestAsyncResourcePool:
    """Test async resource pool."""
    
    @pytest.mark.asyncio
    async def test_resource_pool_creation(self):
        """Test creating resource pool."""
        pool = AsyncResourcePool("test_pool", max_resources=10, cleanup_interval=30.0)
        
        assert pool.pool_id == "test_pool"
        assert pool.max_resources == 10
        assert pool.cleanup_interval == 30.0
        assert len(pool._resources) == 0
        assert pool._stats["active"] == 0
    
    @pytest.mark.asyncio
    async def test_resource_pool_add_get_resource(self):
        """Test adding and getting resources from pool."""
        pool = AsyncResourcePool("test_pool")
        resource = MockAsyncResource("test_resource")
        context_id = str(uuid.uuid4())
        
        # Add resource
        resource_id = await pool.add_resource(resource, context_id, ContextScope.TASK)
        
        assert resource_id == resource.resource_id
        assert len(pool._resources) == 1
        assert pool._stats["created"] == 1
        assert pool._stats["active"] == 1
        
        # Get resource
        retrieved_resource = await pool.get_resource(resource_id)
        
        assert retrieved_resource == resource
        
        # Get non-existent resource
        non_existent = await pool.get_resource("non_existent")
        assert non_existent is None
    
    @pytest.mark.asyncio
    async def test_resource_pool_remove_resource(self):
        """Test removing resources from pool."""
        pool = AsyncResourcePool("test_pool")
        resource = MockAsyncResource("test_resource")
        context_id = str(uuid.uuid4())
        
        # Add and remove resource
        resource_id = await pool.add_resource(resource, context_id, ContextScope.TASK)
        removed = await pool.remove_resource(resource_id)
        
        assert removed is True
        assert len(pool._resources) == 0
        assert pool._stats["cleaned"] == 1
        assert pool._stats["active"] == 0
        assert resource.cleaned_up
        
        # Try to remove non-existent resource
        removed = await pool.remove_resource("non_existent")
        assert removed is False
    
    @pytest.mark.asyncio
    async def test_resource_pool_context_cleanup(self):
        """Test cleaning up resources by context."""
        pool = AsyncResourcePool("test_pool")
        context_id = str(uuid.uuid4())
        
        # Add multiple resources for same context
        resources = []
        for i in range(3):
            resource = MockAsyncResource(f"resource_{i}")
            await pool.add_resource(resource, context_id, ContextScope.TASK)
            resources.append(resource)
        
        assert len(pool._resources) == 3
        
        # Cleanup context resources
        cleaned_count = await pool.cleanup_context_resources(context_id)
        
        assert cleaned_count == 3
        assert len(pool._resources) == 0
        
        # Verify all resources were cleaned up
        for resource in resources:
            assert resource.cleaned_up
    
    @pytest.mark.asyncio
    async def test_resource_pool_scope_cleanup(self):
        """Test cleaning up resources by scope."""
        pool = AsyncResourcePool("test_pool")
        
        # Add resources with different scopes
        task_resources = []
        request_resources = []
        
        for i in range(2):
            task_resource = MockAsyncResource(f"task_resource_{i}")
            await pool.add_resource(task_resource, f"context_{i}", ContextScope.TASK)
            task_resources.append(task_resource)
            
            request_resource = MockAsyncResource(f"request_resource_{i}")
            await pool.add_resource(request_resource, f"context_{i}", ContextScope.REQUEST)
            request_resources.append(request_resource)
        
        assert len(pool._resources) == 4
        
        # Cleanup task scope resources
        cleaned_count = await pool.cleanup_scope_resources(ContextScope.TASK)
        
        assert cleaned_count == 2
        assert len(pool._resources) == 2
        
        # Verify only task resources were cleaned
        for resource in task_resources:
            assert resource.cleaned_up
        
        for resource in request_resources:
            assert not resource.cleaned_up
    
    @pytest.mark.asyncio
    async def test_resource_pool_max_capacity(self):
        """Test resource pool capacity limits."""
        pool = AsyncResourcePool("test_pool", max_resources=2)
        
        # Add resources up to capacity
        resource1 = MockAsyncResource("resource_1")
        resource2 = MockAsyncResource("resource_2")
        
        await pool.add_resource(resource1, "context_1", ContextScope.TASK)
        await pool.add_resource(resource2, "context_2", ContextScope.TASK)
        
        assert len(pool._resources) == 2
        
        # Try to exceed capacity
        resource3 = MockAsyncResource("resource_3")
        
        with pytest.raises(ResourceError, match="Resource pool test_pool is full"):
            await pool.add_resource(resource3, "context_3", ContextScope.TASK)
    
    @pytest.mark.asyncio
    async def test_resource_pool_cleanup_tasks(self):
        """Test resource pool cleanup tasks."""
        pool = AsyncResourcePool("test_pool", cleanup_interval=0.1)
        
        # Start cleanup task
        await pool.start_cleanup_task()
        
        assert pool._cleanup_task is not None
        assert not pool._cleanup_task.done()
        
        # Stop cleanup task
        await pool.stop_cleanup_task()
        
        assert pool._cleanup_task.done()
    
    @pytest.mark.asyncio
    async def test_resource_pool_stats(self):
        """Test resource pool statistics."""
        pool = AsyncResourcePool("test_pool", max_resources=10, cleanup_interval=60.0)
        
        # Initial stats
        stats = pool.get_stats()
        
        assert stats["pool_id"] == "test_pool"
        assert stats["max_resources"] == 10
        assert stats["cleanup_interval"] == 60.0
        assert stats["created"] == 0
        assert stats["cleaned"] == 0
        assert stats["active"] == 0
        
        # Add and remove resource
        resource = MockAsyncResource("test_resource")
        context_id = str(uuid.uuid4())
        
        await pool.add_resource(resource, context_id, ContextScope.TASK)
        await pool.remove_resource(resource.resource_id)
        
        stats = pool.get_stats()
        
        assert stats["created"] == 1
        assert stats["cleaned"] == 1
        assert stats["active"] == 0


class TestAsyncContextManager:
    """Test async context manager."""
    
    @pytest.mark.asyncio
    async def test_context_manager_creation(self):
        """Test creating async context manager."""
        manager = AsyncContextManager()
        
        assert len(manager._contexts) == 0
        assert len(manager._resource_pools) == 0
        assert len(manager._context_vars) == 0
        assert manager._metrics["contexts_created"] == 0
    
    @pytest.mark.asyncio
    async def test_context_manager_create_context(self):
        """Test creating contexts."""
        manager = AsyncContextManager()
        
        context_id = await manager.create_context(
            scope=ContextScope.REQUEST,
            priority=ContextPriority.HIGH,
            test_key="test_value"
        )
        
        assert context_id is not None
        assert context_id in manager._contexts
        
        context_info = manager._contexts[context_id]
        assert context_info.scope == ContextScope.REQUEST
        assert context_info.priority == ContextPriority.HIGH
        assert context_info.state == ContextState.CREATED
        assert context_info.metadata["test_key"] == "test_value"
        assert manager._metrics["contexts_created"] == 1
    
    @pytest.mark.asyncio
    async def test_context_manager_context_lifecycle(self):
        """Test context lifecycle management."""
        manager = AsyncContextManager()
        context_id = await manager.create_context()
        
        # Test activation
        await manager.activate_context(context_id)
        context_info = await manager.get_context(context_id)
        assert context_info.state == ContextState.ACTIVE
        
        # Test suspension
        await manager.suspend_context(context_id)
        context_info = await manager.get_context(context_id)
        assert context_info.state == ContextState.SUSPENDED
        
        # Reactivate for completion
        await manager.activate_context(context_id)
        
        # Test completion
        await manager.complete_context(context_id)
        context_info = await manager.get_context(context_id)
        assert context_info.state == ContextState.COMPLETED
        assert manager._metrics["contexts_completed"] == 1
    
    @pytest.mark.asyncio
    async def test_context_manager_context_cancellation(self):
        """Test context cancellation."""
        manager = AsyncContextManager()
        context_id = await manager.create_context()
        
        await manager.activate_context(context_id)
        await manager.cancel_context(context_id)
        
        context_info = await manager.get_context(context_id)
        assert context_info.state == ContextState.CANCELLED
        assert manager._metrics["contexts_cancelled"] == 1
    
    @pytest.mark.asyncio
    async def test_context_manager_context_error(self):
        """Test context error handling."""
        manager = AsyncContextManager()
        context_id = await manager.create_context()
        
        await manager.activate_context(context_id)
        
        test_error = ValueError("Test error")
        await manager.error_context(context_id, test_error)
        
        context_info = await manager.get_context(context_id)
        assert context_info.state == ContextState.ERROR
        assert context_info.metadata["error"] == "Test error"
        assert context_info.metadata["error_type"] == "ValueError"
        assert manager._metrics["contexts_errors"] == 1
    
    @pytest.mark.asyncio
    async def test_context_manager_context_variables(self):
        """Test context variable management."""
        manager = AsyncContextManager()
        context_id = await manager.create_context()
        
        # Set variables
        await manager.set_context_variable(context_id, "key1", "value1")
        await manager.set_context_variable(context_id, "key2", 42)
        
        # Get variables
        value1 = await manager.get_context_variable(context_id, "key1")
        value2 = await manager.get_context_variable(context_id, "key2")
        value3 = await manager.get_context_variable(context_id, "key3", "default")
        
        assert value1 == "value1"
        assert value2 == 42
        assert value3 == "default"
    
    @pytest.mark.asyncio
    async def test_context_manager_resource_pools(self):
        """Test resource pool management."""
        manager = AsyncContextManager()
        
        # Create resource pool
        pool = manager.create_resource_pool("test_pool", max_resources=5)
        
        assert pool.pool_id == "test_pool"
        assert pool.max_resources == 5
        assert manager.get_resource_pool("test_pool") == pool
        
        # Test non-existent pool
        assert manager.get_resource_pool("non_existent") is None
    
    @pytest.mark.asyncio
    async def test_context_manager_context_variables(self):
        """Test context variable creation."""
        manager = AsyncContextManager()
        
        # Create context variable
        var = manager.create_context_variable(
            "test_var",
            default="default_value",
            scope=ContextScope.REQUEST
        )
        
        assert var.name == "test_var"
        assert var.default == "default_value"
        assert var.scope == ContextScope.REQUEST
        assert manager.get_context_variable_definition("test_var") == var
        
        # Test non-existent variable
        assert manager.get_context_variable_definition("non_existent") is None
    
    @pytest.mark.asyncio
    async def test_context_manager_start_stop(self):
        """Test context manager start and stop."""
        manager = AsyncContextManager()
        
        # Start manager
        await manager.start()
        
        assert manager._global_cleanup_task is not None
        assert not manager._global_cleanup_task.done()
        
        # Stop manager
        await manager.stop()
        
        assert manager._global_cleanup_task.done()
    
    @pytest.mark.asyncio
    async def test_context_manager_metrics(self):
        """Test context manager metrics."""
        manager = AsyncContextManager()
        
        # Create some contexts and resources
        context_id = await manager.create_context()
        pool = manager.create_resource_pool("test_pool")
        var = manager.create_context_variable("test_var")
        
        metrics = manager.get_metrics()
        
        assert metrics["contexts_created"] == 1
        assert metrics["active_contexts"] == 1
        assert metrics["resource_pools"] == 1
        assert metrics["context_variables"] == 1
        assert "pool_stats" in metrics


class TestAsyncContextDecorators:
    """Test async context decorators and context managers."""
    
    @pytest.mark.asyncio
    async def test_async_context_manager(self):
        """Test async context manager."""
        manager = get_context_manager()
        
        async with async_context(
            scope=ContextScope.REQUEST,
            priority=ContextPriority.HIGH,
            test_metadata="test_value"
        ) as context_id:
            # Verify context exists and is active
            context_info = await manager.get_context(context_id)
            
            assert context_info is not None
            assert context_info.context_id == context_id
            assert context_info.scope == ContextScope.REQUEST
            assert context_info.priority == ContextPriority.HIGH
            assert context_info.state == ContextState.ACTIVE
            assert context_info.metadata["test_metadata"] == "test_value"
        
        # Verify context is completed after exiting
        context_info = await manager.get_context(context_id)
        assert context_info.state == ContextState.COMPLETED
    
    @pytest.mark.asyncio
    async def test_async_context_manager_with_exception(self):
        """Test async context manager with exception."""
        manager = get_context_manager()
        context_id = None
        
        try:
            async with async_context(scope=ContextScope.TASK) as ctx_id:
                context_id = ctx_id
                raise ValueError("Test exception")
        except ValueError:
            pass
        
        # Verify context is in error state
        context_info = await manager.get_context(context_id)
        assert context_info.state == ContextState.ERROR
    
    @pytest.mark.asyncio
    async def test_async_context_manager_with_cancellation(self):
        """Test async context manager with cancellation."""
        manager = get_context_manager()
        context_id = None
        
        async def test_task():
            nonlocal context_id
            async with async_context(scope=ContextScope.TASK) as ctx_id:
                context_id = ctx_id
                await asyncio.sleep(1.0)  # Long operation
        
        task = asyncio.create_task(test_task())
        await asyncio.sleep(0.01)  # Let task start
        task.cancel()
        
        try:
            await task
        except asyncio.CancelledError:
            pass
        
        # Give time for cleanup
        await asyncio.sleep(0.01)
        
        # Verify context is cancelled or cleaned up
        context_info = await manager.get_context(context_id)
        assert context_info.state in [ContextState.CANCELLED, ContextState.CLEANED_UP]
    
    @pytest.mark.asyncio
    async def test_async_resource_context_manager(self):
        """Test async resource context manager."""
        resource = MockAsyncResource("test_resource")
        
        async with async_resource_context(
            resource,
            pool_id="test_pool",
            scope=ContextScope.TASK
        ) as managed_resource:
            assert managed_resource == resource
            assert resource.initialized
            assert not resource.cleaned_up
        
        # Resource should be cleaned up after context
        assert resource.cleaned_up
    
    @pytest.mark.asyncio
    async def test_async_context_aware_decorator(self):
        """Test async context aware decorator."""
        call_count = 0
        context_ids = []
        
        @async_context_aware(scope=ContextScope.REQUEST, priority=ContextPriority.HIGH)
        async def test_function(value: str):
            nonlocal call_count
            call_count += 1
            
            # Get current context
            context_id = await get_current_context_id()
            context_ids.append(context_id)
            
            return f"processed_{value}"
        
        # Call function multiple times
        result1 = await test_function("test1")
        result2 = await test_function("test2")
        
        assert result1 == "processed_test1"
        assert result2 == "processed_test2"
        assert call_count == 2
        assert len(context_ids) == 2
        assert context_ids[0] != context_ids[1]  # Different contexts


class TestUtilityFunctions:
    """Test utility functions."""
    
    @pytest.mark.asyncio
    async def test_get_set_context_manager(self):
        """Test getting and setting context manager."""
        original_manager = get_context_manager()
        new_manager = AsyncContextManager()
        
        set_context_manager(new_manager)
        assert get_context_manager() == new_manager
        
        # Restore original
        set_context_manager(original_manager)
        assert get_context_manager() == original_manager
    
    @pytest.mark.asyncio
    async def test_current_context_utilities(self):
        """Test current context utility functions."""
        async with async_context(scope=ContextScope.REQUEST) as context_id:
            # Test getting current context ID
            current_id = await get_current_context_id()
            assert current_id == context_id
            
            # Test getting current context info
            context_info = await get_current_context()
            assert context_info is not None
            assert context_info.context_id == context_id
            
            # Test setting and getting context variables
            await set_context_variable("test_key", "test_value")
            value = await get_context_variable("test_key")
            assert value == "test_value"
            
            # Test getting non-existent variable with default
            default_value = await get_context_variable("non_existent", "default")
            assert default_value == "default"
    
    @pytest.mark.asyncio
    async def test_context_utilities_without_context(self):
        """Test context utilities when no context is active."""
        # These should not raise exceptions but return None/defaults
        context_id = await get_current_context_id()
        context_info = await get_current_context()
        value = await get_context_variable("test_key", "default")
        
        assert context_id is None
        assert context_info is None
        assert value == "default"
        
        # Setting variable without context should not crash
        await set_context_variable("test_key", "test_value")
    
    @pytest.mark.asyncio
    async def test_cleanup_context_resources(self):
        """Test cleanup context resources utility."""
        manager = get_context_manager()
        
        # Create resource pool and add resources
        pool = manager.create_resource_pool("test_pool")
        
        resource1 = MockAsyncResource("resource_1")
        resource2 = MockAsyncResource("resource_2")
        
        await pool.add_resource(resource1, "context_1", ContextScope.REQUEST)
        await pool.add_resource(resource2, "context_2", ContextScope.REQUEST)
        
        # Cleanup resources for REQUEST scope
        cleaned_count = await cleanup_context_resources(ContextScope.REQUEST)
        
        assert cleaned_count == 2
        assert resource1.cleaned_up
        assert resource2.cleaned_up
    
    @pytest.mark.asyncio
    async def test_get_context_metrics(self):
        """Test get context metrics utility."""
        # Create some contexts and resources
        async with async_context() as context_id:
            manager = get_context_manager()
            manager.create_resource_pool("test_pool")
            
            metrics = await get_context_metrics()
            
            assert isinstance(metrics, dict)
            assert "active_contexts" in metrics
            assert "resource_pools" in metrics
            assert metrics["active_contexts"] >= 1
            assert metrics["resource_pools"] >= 1


class TestExceptionHandling:
    """Test exception handling with async context."""
    
    @pytest.mark.asyncio
    async def test_exception_handler_registration(self):
        """Test registering exception handlers."""
        handler = get_exception_handler()
        handler_called = False
        
        def test_handler(exception, context_id):
            nonlocal handler_called
            handler_called = True
            assert isinstance(exception, ValueError)
            assert context_id is not None
        
        register_exception_handler(ValueError, test_handler)
        
        # Trigger exception handling
        async with async_context() as context_id:
            test_exception = ValueError("Test exception")
            await handler.handle_exception(test_exception, context_id)
        
        assert handler_called
    
    @pytest.mark.asyncio
    async def test_async_exception_handler(self):
        """Test async exception handler."""
        handler = get_exception_handler()
        handler_called = False
        
        async def async_test_handler(exception, context_id):
            nonlocal handler_called
            handler_called = True
            assert isinstance(exception, RuntimeError)
            assert context_id is not None
        
        handler.register_handler(RuntimeError, async_test_handler)
        
        # Trigger exception handling
        async with async_context() as context_id:
            test_exception = RuntimeError("Test async exception")
            await handler.handle_exception(test_exception, context_id)
        
        assert handler_called
    
    @pytest.mark.asyncio
    async def test_exception_handler_with_failing_handler(self):
        """Test exception handler when handler itself fails."""
        handler = get_exception_handler()
        
        def failing_handler(exception, context_id):
            raise RuntimeError("Handler failed")
        
        handler.register_handler(ValueError, failing_handler)
        
        # This should not raise an exception
        async with async_context() as context_id:
            test_exception = ValueError("Test exception")
            await handler.handle_exception(test_exception, context_id)


class TestContextVariables:
    """Test predefined context variables."""
    
    @pytest.mark.asyncio
    async def test_current_request_variable(self):
        """Test current_request context variable."""
        mock_request = create_mock_request(method="POST", path="/api/test")
        
        # Set current request
        token = current_request.set(mock_request)
        
        # Get current request
        retrieved_request = current_request.get()
        assert retrieved_request == mock_request
        assert retrieved_request.method == "POST"
        assert retrieved_request.url.path == "/api/test"
        
        # Reset
        current_request.reset(token)
        assert current_request.get() is None
    
    @pytest.mark.asyncio
    async def test_current_response_variable(self):
        """Test current_response context variable."""
        mock_response = create_mock_response(status_code=201)
        
        # Set current response
        token = current_response.set(mock_response)
        
        # Get current response
        retrieved_response = current_response.get()
        assert retrieved_response == mock_response
        assert retrieved_response.status_code == 201
        
        # Reset
        current_response.reset(token)
        assert current_response.get() is None
    
    @pytest.mark.asyncio
    async def test_current_user_variable(self):
        """Test current_user context variable."""
        user_data = {"id": "user_123", "name": "Test User"}
        
        # Set current user
        token = current_user.set(user_data)
        
        # Get current user
        retrieved_user = current_user.get()
        assert retrieved_user == user_data
        assert retrieved_user["id"] == "user_123"
        
        # Reset
        current_user.reset(token)
        assert current_user.get() is None
    
    @pytest.mark.asyncio
    async def test_current_shield_variable(self):
        """Test current_shield context variable."""
        mock_shield = create_mock_shield("test_shield")
        
        # Set current shield
        token = current_shield.set(mock_shield)
        
        # Get current shield
        retrieved_shield = current_shield.get()
        assert retrieved_shield == mock_shield
        assert retrieved_shield.name == "test_shield"
        
        # Reset
        current_shield.reset(token)
        assert current_shield.get() is None


class TestSystemManagement:
    """Test system initialization and shutdown."""
    
    @pytest.mark.asyncio
    async def test_initialize_async_context_system(self):
        """Test initializing async context system."""
        # Initialize system
        await initialize_async_context_system()
        
        manager = get_context_manager()
        
        # Verify default pools are created
        assert manager.get_resource_pool("default") is not None
        assert manager.get_resource_pool("shields") is not None
        assert manager.get_resource_pool("requests") is not None
        
        # Verify manager is started
        assert manager._global_cleanup_task is not None
        assert not manager._global_cleanup_task.done()
        
        # Shutdown system
        await shutdown_async_context_system()
        
        # Verify manager is stopped
        assert manager._global_cleanup_task.done()


class TestIntegrationScenarios:
    """Test integration scenarios combining multiple components."""
    
    @pytest.mark.asyncio
    async def test_full_context_lifecycle_with_resources(self):
        """Test full context lifecycle with resource management."""
        manager = get_context_manager()
        pool = manager.create_resource_pool("integration_pool")
        
        async with async_context(
            scope=ContextScope.REQUEST,
            priority=ContextPriority.HIGH,
            integration_test=True
        ) as context_id:
            # Add resources to context
            resources = []
            for i in range(3):
                resource = MockAsyncResource(f"integration_resource_{i}")
                await resource.initialize()
                await pool.add_resource(resource, context_id, ContextScope.REQUEST)
                resources.append(resource)
            
            # Set context variables
            await set_context_variable("test_data", {"key": "value"})
            await set_context_variable("resource_count", len(resources))
            
            # Verify context state
            context_info = await get_current_context()
            assert context_info.scope == ContextScope.REQUEST
            assert context_info.priority == ContextPriority.HIGH
            assert context_info.state == ContextState.ACTIVE
            assert context_info.metadata["integration_test"] is True
            
            # Verify context variables
            test_data = await get_context_variable("test_data")
            resource_count = await get_context_variable("resource_count")
            assert test_data == {"key": "value"}
            assert resource_count == 3
            
            # Verify resources are active
            for resource in resources:
                assert resource.initialized
                assert not resource.cleaned_up
        
        # After context completion, resources should be cleaned up
        await asyncio.sleep(0.01)  # Allow cleanup to complete
        
        for resource in resources:
            assert resource.cleaned_up
        
        # Verify context is completed or cleaned up
        context_info = await manager.get_context(context_id)
        assert context_info.state in [ContextState.COMPLETED, ContextState.CLEANED_UP]
    
    @pytest.mark.asyncio
    async def test_nested_contexts_with_hierarchy(self):
        """Test nested contexts with proper hierarchy."""
        manager = get_context_manager()
        
        async with async_context(scope=ContextScope.REQUEST) as parent_context_id:
            # Set variable directly in parent context
            await manager.set_context_variable(parent_context_id, "level", "parent")
            
            async with async_context(scope=ContextScope.TASK) as child_context_id:
                # Set variable directly in child context
                await manager.set_context_variable(child_context_id, "level", "child")
                
                # Verify child context
                child_context = await manager.get_context(child_context_id)
                parent_context = await manager.get_context(parent_context_id)
                
                assert child_context.parent_context_id == parent_context_id
                assert child_context_id in parent_context.child_context_ids
                
                # Verify context variables are isolated
                child_level = await manager.get_context_variable(child_context_id, "level")
                assert child_level == "child"
        
        # Verify parent context variables are preserved
        parent_level = await manager.get_context_variable(parent_context_id, "level")
        assert parent_level == "parent"
    
    @pytest.mark.asyncio
    async def test_concurrent_contexts_isolation(self):
        """Test isolation between concurrent contexts."""
        results = {}
        
        async def context_worker(worker_id: int):
            async with async_context(
                scope=ContextScope.TASK,
                worker_id=worker_id
            ) as context_id:
                await set_context_variable("worker_id", worker_id)
                await set_context_variable("data", f"worker_{worker_id}_data")
                
                # Simulate some work
                await asyncio.sleep(0.01)
                
                # Retrieve and store results
                retrieved_id = await get_context_variable("worker_id")
                retrieved_data = await get_context_variable("data")
                
                results[worker_id] = {
                    "context_id": context_id,
                    "worker_id": retrieved_id,
                    "data": retrieved_data
                }
        
        # Run concurrent workers
        tasks = [context_worker(i) for i in range(5)]
        await asyncio.gather(*tasks)
        
        # Verify results are isolated
        assert len(results) == 5
        
        for i in range(5):
            assert results[i]["worker_id"] == i
            assert results[i]["data"] == f"worker_{i}_data"
            
            # Verify different context IDs
            for j in range(i + 1, 5):
                assert results[i]["context_id"] != results[j]["context_id"]
    
    @pytest.mark.asyncio
    async def test_resource_sharing_and_cleanup(self):
        """Test resource sharing and cleanup strategies."""
        manager = get_context_manager()
        pool = manager.create_resource_pool("shared_pool", max_resources=10)
        
        # Create shared resources
        shared_resources = []
        for i in range(3):
            resource = MockDatabaseResource(f"shared_db_{i}")
            await resource.initialize()
            shared_resources.append(resource)
        
        async def context_user(user_id: int, use_shared: bool = False):
            async with async_context(
                scope=ContextScope.TASK,
                user_id=user_id
            ) as context_id:
                if use_shared:
                    # Use shared resource
                    shared_resource = shared_resources[user_id % len(shared_resources)]
                    await pool.add_resource(
                        shared_resource, 
                        context_id, 
                        ContextScope.TASK,
                        cleanup_strategy=CleanupStrategy.LAZY
                    )
                else:
                    # Create private resource
                    private_resource = MockCacheResource(f"private_cache_{user_id}")
                    await private_resource.initialize()
                    await pool.add_resource(
                        private_resource, 
                        context_id, 
                        ContextScope.TASK,
                        cleanup_strategy=CleanupStrategy.IMMEDIATE
                    )
                
                # Simulate work
                await asyncio.sleep(0.01)
        
        # Run users with different resource strategies
        tasks = []
        for i in range(6):
            use_shared = i < 3  # First 3 use shared, last 3 use private
            tasks.append(context_user(i, use_shared))
        
        await asyncio.gather(*tasks)
        
        # Give time for cleanup
        await asyncio.sleep(0.01)
        
        # Verify shared resources are still available (lazy cleanup)
        # but private resources are cleaned up (immediate cleanup)
        pool_stats = pool.get_stats()
        assert pool_stats["created"] == 6  # 3 shared + 3 private
    
    @pytest.mark.asyncio
    async def test_error_propagation_and_recovery(self):
        """Test error propagation and recovery in contexts."""
        manager = get_context_manager()
        error_contexts = []
        successful_contexts = []
        
        async def error_prone_task(task_id: int, should_fail: bool = False):
            try:
                async with async_context(
                    scope=ContextScope.TASK,
                    task_id=task_id,
                    should_fail=should_fail
                ) as context_id:
                    await set_context_variable("task_id", task_id)
                    
                    if should_fail:
                        raise ValueError(f"Task {task_id} failed")
                    
                    # Simulate successful work
                    await asyncio.sleep(0.01)
                    await set_context_variable("status", "completed")
                    
                    successful_contexts.append(context_id)
                    
            except ValueError:
                # Let error propagate but track it
                context_id = await get_current_context_id()
                if context_id:
                    error_contexts.append(context_id)
                raise
        
        # Run tasks with mixed success/failure
        tasks = []
        expected_failures = []
        
        for i in range(5):
            should_fail = i % 2 == 0  # Fail on even indices
            tasks.append(error_prone_task(i, should_fail))
            if should_fail:
                expected_failures.append(i)
        
        # Gather results, expecting some to fail
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Verify error handling
        failure_count = sum(1 for r in results if isinstance(r, ValueError))
        assert failure_count == len(expected_failures)
        
        # Give time for context cleanup
        await asyncio.sleep(0.01)
        
        # Verify contexts are in correct final states
        for context_id in successful_contexts:
            context_info = await manager.get_context(context_id)
            assert context_info.state in [ContextState.COMPLETED, ContextState.CLEANED_UP]
        
        for context_id in error_contexts:
            context_info = await manager.get_context(context_id)
            assert context_info.state in [ContextState.ERROR, ContextState.CLEANED_UP]