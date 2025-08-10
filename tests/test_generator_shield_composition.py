"""Tests for multiple shields composition including generator and non-generator shields."""

from fastapi import FastAPI, Request, HTTPException
from fastapi.testclient import TestClient

from fastapi_shield import shield, ShieldedDepends


def test_multiple_generators_lifo_teardown_order():
    """Test that multiple generator shields teardown in LIFO order."""
    app = FastAPI()
    order = []

    @shield(name="First")
    async def first_shield(request: Request):
        order.append("enter:first")
        try:
            yield {"shield": "first"}
        finally:
            order.append("exit:first")

    @shield(name="Second") 
    def second_shield(request: Request):
        order.append("enter:second")
        try:
            yield {"shield": "second"}
        finally:
            order.append("exit:second")

    @shield(name="Third")
    async def third_shield(request: Request):
        order.append("enter:third")
        try:
            yield {"shield": "third"}
        finally:
            order.append("exit:third")

    @app.get("/multi")
    @first_shield  # outermost decorator, executes first
    @second_shield  # middle decorator
    @third_shield  # innermost decorator, executes last
    def multi_endpoint():
        order.append("endpoint")
        return {"ok": True}

    client = TestClient(app)
    resp = client.get("/multi")
    
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    # Shields should enter in decorator order, but exit in reverse (LIFO)
    expected_order = [
        "enter:first", "enter:second", "enter:third",  # Enter order
        "endpoint",  # Endpoint executes
        "exit:third", "exit:second", "exit:first"  # Exit in LIFO order
    ]
    assert order == expected_order


def test_mixed_generator_and_non_generator_shields():
    """Test combining generator shields with regular value-returning shields."""
    app = FastAPI()
    order = []

    @shield(name="Regular")
    async def regular_shield(request: Request):
        order.append("regular")
        return {"type": "regular"}
    
    @shield(name="Generator")
    def generator_shield(request: Request):
        order.append("enter:generator")
        try:
            yield {"type": "generator"}
        finally:
            order.append("exit:generator")

    @shield(name="Another")
    def another_regular(request: Request):
        order.append("another_regular")
        return {"type": "another"}

    @app.get("/mixed")
    @regular_shield
    @generator_shield
    @another_regular  # innermost
    def mixed_endpoint():
        order.append("endpoint")
        return {"mixed": True}

    client = TestClient(app)
    resp = client.get("/mixed")
    
    assert resp.status_code == 200
    assert resp.json() == {"mixed": True}
    # Only generator shields should have teardown
    expected_order = [
        "regular",  # Regular shield executes
        "enter:generator",  # Generator enters
        "another_regular",  # Another regular shield
        "endpoint",  # Endpoint executes
        "exit:generator"  # Only generator has teardown
    ]
    assert order == expected_order


def test_early_shield_blocks_subsequent_shields_no_teardown():
    """Test that if an early shield blocks, subsequent shields don't execute."""
    app = FastAPI()
    order = []

    @shield(name="AllowingGen")
    def allowing_gen(request: Request):
        order.append("enter:allowing")
        try:
            yield {"allowed": True}
        finally:
            order.append("exit:allowing")

    @shield(name="BlockingGen")
    async def blocking_gen(request: Request):
        order.append("enter:blocking")
        try:
            yield None  # Falsy - should block
        finally:
            order.append("exit:blocking")

    @shield(name="NeverReached")
    def never_reached(request: Request):
        order.append("never_reached")  # Should not execute
        try:
            yield {"should": "never_run"}
        finally:
            order.append("exit:never_reached")

    @app.get("/blocked")
    @allowing_gen  # outermost - should run and teardown
    @blocking_gen  # middle - should run, block, and teardown
    @never_reached  # innermost - should never execute
    def blocked_endpoint():  # pragma: no cover
        order.append("endpoint")  # Should never execute
        return {"blocked": False}

    client = TestClient(app)
    resp = client.get("/blocked")
    
    assert resp.status_code == 500
    # Only shields that entered should run teardown
    expected_order = [
        "enter:allowing",  # First shield enters
        "enter:blocking",  # Second shield enters but blocks
        "exit:blocking",   # Second shield tears down (because it entered)
        "exit:allowing"    # First shield tears down (because it entered)
    ]
    assert order == expected_order


def test_shielded_depends_works_with_generator_composition():
    """Test that ShieldedDepends receives data from the appropriate shield."""
    app = FastAPI()
    
    def extract_user(auth_data: dict):
        return f"User-{auth_data['user_id']}"
    
    def extract_resource(resource_data: dict):
        return f"Resource-{resource_data['resource_id']}"

    @shield(name="Auth")
    async def auth_shield(request: Request):
        try:
            yield {"user_id": 123, "role": "admin"}
        finally:
            pass

    @shield(name="Resource")  
    def resource_shield(request: Request):
        try:
            yield {"resource_id": 456, "permissions": ["read", "write"]}
        finally:
            pass

    @app.get("/composed")
    @auth_shield
    @resource_shield  # This will be the last shield to execute, so its data goes to ShieldedDepends
    def composed_endpoint(
        user=ShieldedDepends(extract_user),
        resource=ShieldedDepends(extract_resource)
    ):
        return {"user": user, "resource": resource}

    client = TestClient(app)
    resp = client.get("/composed")
    
    assert resp.status_code == 200
    # ShieldedDepends should receive data from the innermost successful shield
    result = resp.json()
    assert "user" in result
    assert "resource" in result


def test_generator_exception_propagates_through_composition():
    """Test that exceptions in generator shields propagate correctly through composition."""
    app = FastAPI()
    teardown_flags = {"outer": False, "inner": False}

    @shield(name="Outer")
    def outer_shield(request: Request):
        try:
            yield {"outer": True}
        finally:
            teardown_flags["outer"] = True

    @shield(name="Inner")
    async def inner_failing_shield(request: Request):
        try:
            yield {"inner": True}
        finally:
            teardown_flags["inner"] = True
            raise ValueError("Inner teardown failed")

    @app.get("/failing")
    @outer_shield
    @inner_failing_shield
    def failing_endpoint():
        return {"ok": True}

    client = TestClient(app)
    resp = client.get("/failing")
    
    # Should get 500 error from inner shield teardown failure
    assert resp.status_code == 500
    assert "Shield with name `Inner` failed: Inner teardown failed" in resp.text
    
    # Both shields should have run their teardown
    assert teardown_flags["outer"] is True
    assert teardown_flags["inner"] is True


def test_sync_async_generator_mix_in_composition():
    """Test mixing sync and async generators in shield composition."""
    app = FastAPI()
    execution_order = []

    @shield(name="AsyncGen")
    async def async_gen_shield(request: Request):
        execution_order.append("async_enter")
        try:
            yield {"async": True}
        finally:
            execution_order.append("async_exit")

    @shield(name="SyncGen")
    def sync_gen_shield(request: Request):
        execution_order.append("sync_enter")
        try:
            yield {"sync": True}
        finally:
            execution_order.append("sync_exit")

    @shield(name="AnotherAsync")
    async def another_async_shield(request: Request):
        execution_order.append("another_async_enter")
        try:
            yield {"another": True}
        finally:
            execution_order.append("another_async_exit")

    @app.get("/mixed_async_sync")
    @async_gen_shield
    @sync_gen_shield
    @another_async_shield
    def mixed_endpoint():
        execution_order.append("endpoint")
        return {"mixed_execution": True}

    client = TestClient(app)
    resp = client.get("/mixed_async_sync")
    
    assert resp.status_code == 200
    assert resp.json() == {"mixed_execution": True}
    
    expected_order = [
        "async_enter", "sync_enter", "another_async_enter",  # Enter phase
        "endpoint",  # Endpoint execution
        "another_async_exit", "sync_exit", "async_exit"  # Exit phase (LIFO)
    ]
    assert execution_order == expected_order


def test_empty_generator_blocks_request():
    """Test that a generator that doesn't yield anything blocks the request."""
    app = FastAPI()
    teardown_ran = {"ran": False}

    @shield(name="Empty")
    def empty_generator(request: Request):
        try:
            # Don't yield anything - should be treated as falsy
            return  # Explicit return to make generator empty
        finally:
            teardown_ran["ran"] = True

    @app.get("/empty")
    @empty_generator
    def empty_endpoint():  # pragma: no cover
        return {"should": "not_run"}

    client = TestClient(app)
    resp = client.get("/empty")
    
    assert resp.status_code == 500
    assert "Shield with name `Empty` blocks the request" in resp.text
    # Teardown should still run for empty generators
    assert teardown_ran["ran"] is True