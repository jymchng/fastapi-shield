import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI, Header
from fastapi_shield import shield, ShieldedDepends


class TestShieldExceptionsDoNotCrashApp:
    """Verify shields raising exceptions (ValueError, TypeError) do not crash the app.

    The app should respond with a 500 status code rather than crashing
    when a shield raises a non-HTTP exception. We test both sync and async shields.
    """

    def __init__(self):
        # Initialize instance variables so the type checker recognizes them
        self.app: FastAPI = FastAPI()

        # Sync shield that can raise exceptions based on header
        @shield(name="Sync Exception Shield")
        def sync_exception_shield(trigger: str = Header(default="none")):
            if trigger == "value":
                raise ValueError("sync value error")
            if trigger == "type":
                raise TypeError("sync type error")
            return {"ok": True}

        # Async shield that can raise exceptions based on header
        @shield(name="Async Exception Shield")
        async def async_exception_shield(trigger: str = Header(default="none")):
            if trigger == "value":
                raise ValueError("async value error")
            if trigger == "type":
                raise TypeError("async type error")
            return {"ok": True}

        @self.app.get("/sync")
        @sync_exception_shield
        async def sync_endpoint(data=ShieldedDepends(lambda d: d)):
            return {"message": "sync ok", "data": data}

        @self.app.get("/async")
        @async_exception_shield
        async def async_endpoint(data=ShieldedDepends(lambda d: d)):
            return {"message": "async ok", "data": data}

        self.client: TestClient = TestClient(self.app, raise_server_exceptions=False)

    # Sync shield exceptions
    def test_sync_valueerror_returns_500(self):
        response = self.client.get("/sync", headers={"trigger": "value"})
        assert response.status_code == 500

    def test_sync_typeerror_returns_500(self):
        response = self.client.get("/sync", headers={"trigger": "type"})
        assert response.status_code == 500

    # Async shield exceptions
    def test_async_valueerror_returns_500(self):
        response = self.client.get("/async", headers={"trigger": "value"})
        assert response.status_code == 500

    def test_async_typeerror_returns_500(self):
        response = self.client.get("/async", headers={"trigger": "type"})
        assert response.status_code == 500

    # Successful paths (no exception)
    def test_sync_success(self):
        response = self.client.get("/sync")
        assert response.status_code == 200
        assert response.json()["message"] == "sync ok"

    def test_async_success(self):
        response = self.client.get("/async")
        assert response.status_code == 200
        assert response.json()["message"] == "async ok"
