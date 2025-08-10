"""Comprehensive tests for generator shield functionality covering edge cases and integration scenarios."""

import asyncio
import time
from contextlib import contextmanager
from typing import Optional

from fastapi import FastAPI, Request, HTTPException, Depends, Query, Header
from fastapi.testclient import TestClient

from fastapi_shield import shield, ShieldedDepends


def test_generator_shield_with_complex_dependency_injection():
    """Test generator shield with complex FastAPI dependency injection."""
    app = FastAPI()
    
    # Mock database dependency
    def get_db():
        return {"connection": "mock_db"}
    
    def get_current_user(auth_data: dict, db: dict = Depends(get_db)):
        return {
            "id": auth_data["user_id"],
            "name": auth_data["username"],
            "db_connection": db["connection"]
        }

    @shield(name="ComplexAuth")
    async def complex_auth_shield(request: Request, token: str = Header(alias="X-Auth-Token")):
        if token == "valid_token":
            try:
                yield {"user_id": 123, "username": "john_doe"}
            finally:
                # Simulate cleanup like closing connections
                pass
        else:
            try:
                yield None
            finally:
                pass

    @app.get("/complex")
    @complex_auth_shield
    def complex_endpoint(
        user=ShieldedDepends(get_current_user),
        page: int = Query(default=1)
    ):
        return {"user": user, "page": page}

    client = TestClient(app)
    
    # Test successful auth
    resp = client.get("/complex?page=2", headers={"X-Auth-Token": "valid_token"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["user"]["id"] == 123
    assert data["user"]["name"] == "john_doe"
    assert data["user"]["db_connection"] == "mock_db"
    assert data["page"] == 2
    
    # Test failed auth
    resp = client.get("/complex", headers={"X-Auth-Token": "invalid"})
    assert resp.status_code == 500


def test_generator_shield_with_async_context_manager():
    """Test generator shield that uses async context managers internally."""
    app = FastAPI()
    resources = []

    class AsyncResource:
        def __init__(self, name):
            self.name = name
            
        async def __aenter__(self):
            resources.append(f"acquired:{self.name}")
            return self
            
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            resources.append(f"released:{self.name}")

    @shield(name="ResourceManager")
    async def resource_shield(request: Request):
        async with AsyncResource("database") as db:
            try:
                yield {"resource": db.name}
            finally:
                # Additional cleanup can happen here
                resources.append("shield_cleanup")

    @app.get("/resource")
    @resource_shield
    def resource_endpoint(data=ShieldedDepends(lambda x: x)):
        return {"data": data}

    client = TestClient(app)
    resp = client.get("/resource")
    
    assert resp.status_code == 200
    assert "acquired:database" in resources
    assert "released:database" in resources
    assert "shield_cleanup" in resources


def test_generator_shield_with_timing_and_metrics():
    """Test generator shield that measures endpoint execution time."""
    app = FastAPI()
    metrics = []

    @shield(name="TimingShield")
    def timing_shield(request: Request):
        start_time = time.time()
        try:
            yield {"start_time": start_time}
        finally:
            end_time = time.time()
            duration = end_time - start_time
            metrics.append({
                "path": request.url.path,
                "duration": duration,
                "method": request.method
            })

    @app.get("/timed")
    @timing_shield
    def timed_endpoint():
        time.sleep(0.01)  # Simulate some work
        return {"message": "completed"}

    client = TestClient(app)
    resp = client.get("/timed")
    
    assert resp.status_code == 200
    assert len(metrics) == 1
    assert metrics[0]["path"] == "/timed"
    assert metrics[0]["method"] == "GET"
    assert metrics[0]["duration"] > 0


def test_sync_generator_with_sync_endpoint():
    """Test sync generator shield with sync endpoint."""
    app = FastAPI()
    execution_log = []

    @shield(name="SyncShield")
    def sync_shield(request: Request):
        execution_log.append("sync_enter")
        try:
            yield {"sync": True}
        finally:
            execution_log.append("sync_exit")

    @app.get("/sync_both")
    @sync_shield
    def sync_endpoint():
        execution_log.append("sync_endpoint")
        return {"sync": "endpoint"}

    client = TestClient(app)
    resp = client.get("/sync_both")
    
    assert resp.status_code == 200
    assert resp.json() == {"sync": "endpoint"}
    assert execution_log == ["sync_enter", "sync_endpoint", "sync_exit"]


def test_async_generator_with_sync_endpoint():
    """Test async generator shield with sync endpoint."""
    app = FastAPI()
    execution_log = []

    @shield(name="AsyncShield")
    async def async_shield(request: Request):
        execution_log.append("async_enter")
        try:
            yield {"async": True}
        finally:
            execution_log.append("async_exit")

    @app.get("/mixed_async_sync")
    @async_shield
    def sync_endpoint():  # Note: sync endpoint with async shield
        execution_log.append("sync_endpoint")
        return {"mixed": True}

    client = TestClient(app)
    resp = client.get("/mixed_async_sync")
    
    assert resp.status_code == 200
    assert resp.json() == {"mixed": True}
    assert execution_log == ["async_enter", "sync_endpoint", "async_exit"]


def test_generator_shield_with_request_body_validation():
    """Test generator shield that validates request body."""
    app = FastAPI()
    validated_bodies = []

    @shield(name="BodyValidator")
    async def body_validator(request: Request):
        body = await request.body()
        if b"valid" in body:
            try:
                validated_bodies.append(body.decode())
                yield {"body_valid": True}
            finally:
                validated_bodies.append("cleanup")
        else:
            try:
                yield None
            finally:
                validated_bodies.append("blocked_cleanup")

    @app.post("/validate_body")
    @body_validator
    async def validate_body_endpoint():
        return {"body": "processed"}

    client = TestClient(app)
    
    # Test valid body
    resp = client.post("/validate_body", data="valid_data")
    assert resp.status_code == 200
    assert "valid_data" in validated_bodies
    assert "cleanup" in validated_bodies
    
    # Test invalid body
    validated_bodies.clear()
    resp = client.post("/validate_body", data="invalid_data")
    assert resp.status_code == 500
    assert "blocked_cleanup" in validated_bodies


def test_generator_shield_exception_during_yield():
    """Test exception handling when exception occurs exactly at yield point."""
    app = FastAPI()

    @shield(name="YieldException")
    def yield_exception_shield(request: Request):
        try:
            raise ValueError("Error at yield")
            yield {"never": "reached"}  # pragma: no cover
        finally:
            pass

    @app.get("/yield_exception")
    @yield_exception_shield
    def yield_exception_endpoint():  # pragma: no cover
        return {"should": "not_run"}

    client = TestClient(app)
    resp = client.get("/yield_exception")
    
    assert resp.status_code == 500
    assert "Shield with name `YieldException` failed: Error at yield" in resp.text


def test_generator_shield_with_multiple_yields():
    """Test that generator shields only use the first yield value."""
    app = FastAPI()
    yield_count = {"count": 0}

    @shield(name="MultiYield")
    def multi_yield_shield(request: Request):
        try:
            yield_count["count"] += 1
            yield {"first": "yield"}
            yield_count["count"] += 1  # Should not be reached
            yield {"second": "yield"}  # pragma: no cover
        finally:
            yield_count["final_count"] = yield_count["count"]

    @app.get("/multi_yield")
    @multi_yield_shield
    def multi_yield_endpoint(data=ShieldedDepends(lambda x: x)):
        return {"received": data}

    client = TestClient(app)
    resp = client.get("/multi_yield")
    
    assert resp.status_code == 200
    assert resp.json()["received"]["first"] == "yield"
    assert yield_count["count"] == 1  # Should only reach first yield
    assert yield_count["final_count"] == 1


def test_generator_shield_with_path_parameters():
    """Test generator shield that uses path parameters."""
    app = FastAPI()
    accessed_ids = []

    @shield(name="PathParamShield")
    def path_param_shield(request: Request, user_id: int):
        accessed_ids.append(user_id)
        if user_id > 0:
            try:
                yield {"user_id": user_id, "valid": True}
            finally:
                accessed_ids.append(f"cleanup:{user_id}")
        else:
            try:
                yield None
            finally:
                accessed_ids.append(f"blocked:{user_id}")

    @app.get("/users/{user_id}")
    @path_param_shield
    def get_user(user_id: int, data=ShieldedDepends(lambda x: x)):
        return {"user_id": user_id, "data": data}

    client = TestClient(app)
    
    # Test valid user_id
    resp = client.get("/users/123")
    assert resp.status_code == 200
    assert 123 in accessed_ids
    assert "cleanup:123" in accessed_ids
    
    # Test invalid user_id
    resp = client.get("/users/0") 
    assert resp.status_code == 500
    assert 0 in accessed_ids
    assert "blocked:0" in accessed_ids


def test_generator_shield_preserves_request_state():
    """Test that generator shields can preserve and modify request state."""
    app = FastAPI()

    @shield(name="StateManager") 
    async def state_manager_shield(request: Request):
        # Set some state
        if not hasattr(request.state, "processed_by"):
            request.state.processed_by = []
        request.state.processed_by.append("shield")
        
        try:
            yield {"state_set": True}
        finally:
            request.state.processed_by.append("shield_cleanup")

    @app.get("/state")
    @state_manager_shield
    def state_endpoint(request: Request):
        request.state.processed_by.append("endpoint")
        return {"processed_by": list(request.state.processed_by)}

    client = TestClient(app)
    resp = client.get("/state")
    
    assert resp.status_code == 200
    processed_by = resp.json()["processed_by"]
    assert "shield" in processed_by
    assert "endpoint" in processed_by
    # Note: cleanup happens after response, so not visible in response


def test_generator_shield_with_conditional_logic():
    """Test generator shield with complex conditional logic."""
    app = FastAPI()
    decisions = []

    @shield(name="ConditionalShield")
    def conditional_shield(request: Request, auth: Optional[str] = Header(default=None)):
        if auth is None:
            decisions.append("no_auth")
            try:
                yield None
            finally:
                decisions.append("no_auth_cleanup")
        elif auth.startswith("Bearer "):
            token = auth.replace("Bearer ", "")
            if len(token) > 10:
                decisions.append("valid_token")
                try:
                    yield {"token": token, "valid": True}
                finally:
                    decisions.append("valid_cleanup")
            else:
                decisions.append("invalid_token")
                try:
                    yield None
                finally:
                    decisions.append("invalid_cleanup")
        else:
            decisions.append("malformed_auth")
            try:
                yield None
            finally:
                decisions.append("malformed_cleanup")

    @app.get("/conditional")
    @conditional_shield
    def conditional_endpoint():
        decisions.append("endpoint_executed")
        return {"success": True}

    client = TestClient(app)
    
    # Test no auth
    resp = client.get("/conditional")
    assert resp.status_code == 500
    assert "no_auth" in decisions
    assert "no_auth_cleanup" in decisions
    
    # Test valid token
    decisions.clear()
    resp = client.get("/conditional", headers={"Authorization": "Bearer valid_long_token"})
    assert resp.status_code == 200
    assert "valid_token" in decisions
    assert "endpoint_executed" in decisions
    assert "valid_cleanup" in decisions
    
    # Test invalid token
    decisions.clear()
    resp = client.get("/conditional", headers={"Authorization": "Bearer short"})
    assert resp.status_code == 500
    assert "invalid_token" in decisions
    assert "invalid_cleanup" in decisions


def test_generator_shield_with_nested_try_except():
    """Test generator shield with nested try/except blocks."""
    app = FastAPI()
    caught_exceptions = []

    @shield(name="NestedTryExcept")
    async def nested_shield(request: Request):
        try:
            try:
                # Simulate some operation that might fail
                if request.headers.get("X-Trigger-Error"):
                    raise ValueError("Triggered error")
                yield {"nested": "success"}
            except ValueError as e:
                caught_exceptions.append(str(e))
                # Re-raise to test exception propagation
                raise
        finally:
            caught_exceptions.append("outer_finally")

    @app.get("/nested")
    @nested_shield
    def nested_endpoint():
        return {"nested": "endpoint"}

    client = TestClient(app)
    
    # Test successful case
    resp = client.get("/nested")
    assert resp.status_code == 200
    assert "outer_finally" in caught_exceptions
    
    # Test error case
    caught_exceptions.clear()
    resp = client.get("/nested", headers={"X-Trigger-Error": "true"})
    assert resp.status_code == 500
    assert "Triggered error" in caught_exceptions
    assert "outer_finally" in caught_exceptions


def test_generator_shield_memory_cleanup():
    """Test that generator shields properly clean up memory and resources."""
    app = FastAPI()
    created_objects = []
    cleaned_objects = []

    class ResourceObject:
        def __init__(self, name):
            self.name = name
            created_objects.append(self.name)
            
        def cleanup(self):
            cleaned_objects.append(self.name)

    @shield(name="MemoryCleanup")
    def memory_cleanup_shield(request: Request):
        resource = ResourceObject(f"resource_{id(request)}")
        try:
            yield {"resource_name": resource.name}
        finally:
            resource.cleanup()

    @app.get("/memory")
    @memory_cleanup_shield
    def memory_endpoint():
        return {"status": "ok"}

    client = TestClient(app)
    
    # Make multiple requests to test cleanup
    for i in range(3):
        resp = client.get("/memory")
        assert resp.status_code == 200
    
    assert len(created_objects) == 3
    assert len(cleaned_objects) == 3
    assert set(created_objects) == set(cleaned_objects)


def test_generator_shield_with_streaming_response():
    """Test generator shield with streaming response from endpoint."""
    app = FastAPI()
    from fastapi.responses import StreamingResponse
    import io

    @shield(name="StreamingShield")
    async def streaming_shield(request: Request):
        try:
            yield {"streaming": True}
        finally:
            # Cleanup after streaming completes
            pass

    @app.get("/stream")
    @streaming_shield
    def streaming_endpoint():
        def generate():
            for i in range(3):
                yield f"chunk_{i}\n"
        
        return StreamingResponse(generate(), media_type="text/plain")

    client = TestClient(app)
    resp = client.get("/stream")
    
    assert resp.status_code == 200
    content = resp.text
    assert "chunk_0" in content
    assert "chunk_1" in content
    assert "chunk_2" in content


def test_generator_shield_performance_impact():
    """Test that generator shields don't significantly impact performance."""
    app = FastAPI()
    execution_times = []

    @shield(name="PerformanceShield")
    def performance_shield(request: Request):
        start = time.time()
        try:
            yield {"start": start}
        finally:
            end = time.time()
            execution_times.append(end - start)

    @app.get("/performance")
    @performance_shield  
    def performance_endpoint():
        # Minimal endpoint
        return {"ok": True}

    client = TestClient(app)
    
    # Make multiple requests to measure performance
    for _ in range(10):
        resp = client.get("/performance")
        assert resp.status_code == 200
    
    # Check that shield overhead is minimal (less than 1ms per request)
    avg_time = sum(execution_times) / len(execution_times)
    assert avg_time < 0.001  # Less than 1ms
    assert len(execution_times) == 10