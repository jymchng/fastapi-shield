"""Tests for error handling in generator shields."""

from fastapi import FastAPI, Request, HTTPException, status
from fastapi.testclient import TestClient

from fastapi_shield import shield, ShieldedDepends


def test_http_exception_in_async_generator_enter_propagates():
    """Test that HTTPException raised in async generator enter phase propagates as-is."""
    app = FastAPI()

    @shield(name="HTTPError")
    async def http_error_shield(request: Request):
        raise HTTPException(status_code=403, detail="Access forbidden")
        yield  # pragma: no cover

    @app.get("/http_error")
    @http_error_shield
    def http_error_endpoint():  # pragma: no cover
        return {"ok": True}

    client = TestClient(app)
    resp = client.get("/http_error")
    
    assert resp.status_code == 403
    assert resp.json()["detail"] == "Access forbidden"


def test_http_exception_in_sync_generator_enter_propagates():
    """Test that HTTPException raised in sync generator enter phase propagates as-is."""
    app = FastAPI()

    @shield(name="SyncHTTPError")
    def sync_http_error_shield(request: Request):
        raise HTTPException(status_code=401, detail="Authentication required")
        yield  # pragma: no cover

    @app.get("/sync_http_error")
    @sync_http_error_shield
    def sync_http_error_endpoint():  # pragma: no cover
        return {"ok": True}

    client = TestClient(app)
    resp = client.get("/sync_http_error")
    
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Authentication required"


def test_non_http_exception_in_async_generator_enter_maps_to_500():
    """Test that non-HTTPException in async generator enter maps to 500 with standardized detail."""
    app = FastAPI()

    @shield(name="AsyncRuntimeError")
    async def async_runtime_error_shield(request: Request):
        raise RuntimeError("Something went wrong")
        yield  # pragma: no cover

    @app.get("/async_runtime_error")
    @async_runtime_error_shield
    def async_runtime_error_endpoint():  # pragma: no cover
        return {"ok": True}

    client = TestClient(app)
    resp = client.get("/async_runtime_error")
    
    assert resp.status_code == 500
    assert resp.json()["detail"] == "Shield with name `AsyncRuntimeError` failed: Something went wrong"


def test_non_http_exception_in_sync_generator_enter_maps_to_500():
    """Test that non-HTTPException in sync generator enter maps to 500 with standardized detail."""
    app = FastAPI()

    @shield(name="SyncValueError")
    def sync_value_error_shield(request: Request):
        raise ValueError("Invalid value")
        yield  # pragma: no cover

    @app.get("/sync_value_error")
    @sync_value_error_shield
    def sync_value_error_endpoint():  # pragma: no cover
        return {"ok": True}

    client = TestClient(app)
    resp = client.get("/sync_value_error")
    
    assert resp.status_code == 500
    assert resp.json()["detail"] == "Shield with name `SyncValueError` failed: Invalid value"


def test_http_exception_in_async_generator_teardown_propagates():
    """Test that HTTPException raised in async generator teardown propagates as-is."""
    app = FastAPI()

    @shield(name="TeardownHTTPError")
    async def teardown_http_error_shield(request: Request):
        try:
            yield {"ok": True}
        finally:
            raise HTTPException(status_code=502, detail="Teardown failed")

    @app.get("/teardown_http_error")
    @teardown_http_error_shield
    def teardown_http_error_endpoint():
        return {"endpoint": "executed"}

    client = TestClient(app)
    resp = client.get("/teardown_http_error")
    
    # Teardown exception should override successful endpoint response
    assert resp.status_code == 502
    assert resp.json()["detail"] == "Teardown failed"


def test_http_exception_in_sync_generator_teardown_propagates():
    """Test that HTTPException raised in sync generator teardown propagates as-is."""
    app = FastAPI()

    @shield(name="SyncTeardownHTTPError")
    def sync_teardown_http_error_shield(request: Request):
        try:
            yield {"ok": True}
        finally:
            raise HTTPException(status_code=503, detail="Service unavailable in teardown")

    @app.get("/sync_teardown_http_error")
    @sync_teardown_http_error_shield
    def sync_teardown_http_error_endpoint():
        return {"endpoint": "executed"}

    client = TestClient(app)
    resp = client.get("/sync_teardown_http_error")
    
    assert resp.status_code == 503
    assert resp.json()["detail"] == "Service unavailable in teardown"


def test_non_http_exception_in_async_generator_teardown_maps_to_500():
    """Test that non-HTTPException in async generator teardown maps to 500."""
    app = FastAPI()

    @shield(name="AsyncTeardownError")
    async def async_teardown_error_shield(request: Request):
        try:
            yield {"ok": True}
        finally:
            raise ConnectionError("Database connection lost")

    @app.get("/async_teardown_error")
    @async_teardown_error_shield
    def async_teardown_error_endpoint():
        return {"endpoint": "executed"}

    client = TestClient(app)
    resp = client.get("/async_teardown_error")
    
    assert resp.status_code == 500
    assert resp.json()["detail"] == "Shield with name `AsyncTeardownError` failed: Database connection lost"


def test_non_http_exception_in_sync_generator_teardown_maps_to_500():
    """Test that non-HTTPException in sync generator teardown maps to 500."""
    app = FastAPI()

    @shield(name="SyncTeardownError")
    def sync_teardown_error_shield(request: Request):
        try:
            yield {"ok": True}
        finally:
            raise FileNotFoundError("Log file not found")

    @app.get("/sync_teardown_error")
    @sync_teardown_error_shield
    def sync_teardown_error_endpoint():
        return {"endpoint": "executed"}

    client = TestClient(app)
    resp = client.get("/sync_teardown_error")
    
    assert resp.status_code == 500
    assert resp.json()["detail"] == "Shield with name `SyncTeardownError` failed: Log file not found"


def test_endpoint_exception_preserved_despite_teardown_error():
    """Test that if both endpoint and teardown raise exceptions, endpoint exception is preserved."""
    app = FastAPI()

    @shield(name="EndpointAndTeardownError")
    async def endpoint_and_teardown_error_shield(request: Request):
        try:
            yield {"ok": True}
        finally:
            raise RuntimeError("Teardown error")

    @app.get("/endpoint_and_teardown_error")
    @endpoint_and_teardown_error_shield
    def endpoint_and_teardown_error_endpoint():
        raise HTTPException(status_code=418, detail="I'm a teapot")

    client = TestClient(app)
    resp = client.get("/endpoint_and_teardown_error")
    
    # Endpoint exception should be preserved, teardown error should be ignored or logged
    assert resp.status_code == 418
    assert resp.json()["detail"] == "I'm a teapot"


def test_generator_close_exception_on_falsy_enter():
    """Test exception handling when generator.close() fails after falsy enter value."""
    app = FastAPI()

    class CloseError(Exception):
        pass

    class FalsyGeneratorWithCloseError:
        def __init__(self, shield_func):
            self.shield_func = shield_func
            
        def __call__(self, **kwargs):
            gen = self.shield_func(**kwargs)
            # Manually control the generator to simulate close error
            try:
                enter_value = next(gen)
            except StopIteration:
                enter_value = None
                
            # Simulate close error
            original_close = gen.close
            def failing_close():
                original_close()
                raise CloseError("Close failed")
            gen.close = failing_close
            
            return gen, enter_value

    # We can't easily test this without modifying the shield implementation
    # But we can test the expected behavior with a custom shield
    @shield(name="FalsyWithCloseError")
    def falsy_with_potential_close_error(request: Request):
        try:
            yield None  # Falsy - should trigger close
        finally:
            # Simulate a problem during close/cleanup
            raise RuntimeError("Cleanup failed")

    @app.get("/falsy_close_error")
    @falsy_with_potential_close_error
    def falsy_close_error_endpoint():  # pragma: no cover
        return {"should": "not_execute"}

    client = TestClient(app)
    resp = client.get("/falsy_close_error")
    
    assert resp.status_code == 500
    # Should get the cleanup error message
    assert "Shield with name `FalsyWithCloseError` failed: Cleanup failed" in resp.text


def test_multiple_exceptions_in_composition():
    """Test error handling when multiple shields in composition throw exceptions."""
    app = FastAPI()

    @shield(name="OuterError")
    async def outer_error_shield(request: Request):
        try:
            yield {"outer": True}
        finally:
            raise ValueError("Outer teardown failed")

    @shield(name="InnerError")
    def inner_error_shield(request: Request):
        try:
            yield {"inner": True}
        finally:
            raise RuntimeError("Inner teardown failed")

    @app.get("/multiple_errors")
    @outer_error_shield
    @inner_error_shield
    def multiple_errors_endpoint():
        return {"ok": True}

    client = TestClient(app)
    resp = client.get("/multiple_errors")
    
    # Should get error from the first shield that fails in teardown order
    assert resp.status_code == 500
    # The inner shield should fail first due to LIFO teardown order
    assert "Shield with name `InnerError` failed: Inner teardown failed" in resp.text


def test_generator_stop_iteration_exception_treated_as_falsy():
    """Test that StopIteration from a generator is treated as falsy enter value."""
    app = FastAPI()
    teardown_executed = {"executed": False}

    @shield(name="StopIteration")
    def stop_iteration_shield(request: Request):
        try:
            # Generator that immediately stops without yielding
            return  # This creates a generator that raises StopIteration immediately
        finally:
            teardown_executed["executed"] = True

    @app.get("/stop_iteration")
    @stop_iteration_shield 
    def stop_iteration_endpoint():  # pragma: no cover
        return {"should": "not_execute"}

    client = TestClient(app)
    resp = client.get("/stop_iteration")
    
    assert resp.status_code == 500
    assert "Shield with name `StopIteration` blocks the request" in resp.text
    assert teardown_executed["executed"] is True


def test_async_generator_stop_async_iteration_treated_as_falsy():
    """Test that StopAsyncIteration from an async generator is treated as falsy."""
    app = FastAPI()
    teardown_executed = {"executed": False}

    @shield(name="StopAsyncIteration")
    async def stop_async_iteration_shield(request: Request):
        try:
            # Async generator that immediately stops without yielding
            return  # This creates an async generator that raises StopAsyncIteration immediately
        finally:
            teardown_executed["executed"] = True

    @app.get("/stop_async_iteration")
    @stop_async_iteration_shield
    def stop_async_iteration_endpoint():  # pragma: no cover
        return {"should": "not_execute"}

    client = TestClient(app)
    resp = client.get("/stop_async_iteration")
    
    assert resp.status_code == 500
    assert "Shield with name `StopAsyncIteration` blocks the request" in resp.text  
    assert teardown_executed["executed"] is True


def test_custom_auto_error_false_with_generator_exception():
    """Test custom response when auto_error=False and generator raises exception."""
    app = FastAPI()
    from fastapi import Response

    custom_response = Response(
        content="Custom error response", 
        status_code=422,
        headers={"X-Custom-Error": "true"}
    )

    @shield(
        name="CustomErrorResponse", 
        auto_error=False, 
        default_response_to_return_if_fail=custom_response
    )
    async def custom_error_shield(request: Request):
        try:
            yield None  # Falsy - should return custom response
        finally:
            pass

    @app.get("/custom_error_response")
    @custom_error_shield
    def custom_error_response_endpoint():  # pragma: no cover
        return {"should": "not_execute"}

    client = TestClient(app)
    resp = client.get("/custom_error_response")
    
    assert resp.status_code == 422
    assert resp.text == "Custom error response"
    assert resp.headers.get("X-Custom-Error") == "true"