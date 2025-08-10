"""Mock classes and utilities for middleware bridge testing."""

import asyncio
import time
from typing import Any, Dict, List, Optional, Callable, Union
from unittest.mock import Mock, AsyncMock
from dataclasses import dataclass

from fastapi import Request, Response, HTTPException
from starlette.applications import Starlette
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from fastapi_shield.shield import Shield
from fastapi_shield.middleware_bridge import (
    MiddlewareConfig, MiddlewareType, ShieldPosition, ProcessingPhase,
    MiddlewareMetrics, MiddlewareContext
)


class MockRequest:
    """Mock request for middleware testing."""
    
    def __init__(self, method: str = "GET", path: str = "/test", 
                 headers: Dict[str, str] = None, query_params: Dict[str, str] = None):
        self.method = method
        self.headers = headers or {}
        self.query_params = query_params or {}
        
        # Mock URL
        self.url = Mock()
        self.url.path = path
        self.url.query = "&".join([f"{k}={v}" for k, v in self.query_params.items()])
        
        # Mock scope for ASGI
        self.scope = {
            "type": "http",
            "method": method,
            "path": path,
            "headers": [(k.encode(), v.encode()) for k, v in self.headers.items()],
            "query_string": self.url.query.encode(),
        }


class MockResponse:
    """Mock response for middleware testing."""
    
    def __init__(self, status_code: int = 200, content: Any = None, 
                 headers: Dict[str, str] = None):
        self.status_code = status_code
        self.content = content
        self.headers = headers or {}
    
    def __call__(self, scope: Scope, receive: Receive, send: Send):
        """ASGI interface for mock response."""
        async def asgi_app():
            await send({
                "type": "http.response.start",
                "status": self.status_code,
                "headers": [(k.encode(), v.encode()) for k, v in self.headers.items()],
            })
            
            body = ""
            if self.content:
                if isinstance(self.content, str):
                    body = self.content
                else:
                    import json
                    body = json.dumps(self.content)
            
            await send({
                "type": "http.response.body",
                "body": body.encode(),
            })
        
        return asgi_app()


class MockASGIApp:
    """Mock ASGI application for testing."""
    
    def __init__(self, response: MockResponse = None, delay_ms: float = 0):
        self.response = response or MockResponse()
        self.delay_ms = delay_ms
        self.calls: List[Dict[str, Any]] = []
        
    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        """ASGI application interface."""
        self.calls.append({
            "scope": scope,
            "timestamp": time.time(),
            "method": scope.get("method", "UNKNOWN"),
            "path": scope.get("path", "/"),
        })
        
        if self.delay_ms > 0:
            await asyncio.sleep(self.delay_ms / 1000)
        
        await self.response(scope, receive, send)


class MockShield:
    """Mock shield for middleware testing."""
    
    def __init__(self, name: str = "mock_shield", should_block: bool = False, 
                 delay_ms: float = 1.0, result: Any = None, should_fail: bool = False):
        self.name = name
        self.should_block = should_block
        self.delay_ms = delay_ms
        self.result = result or {"shield": name}
        self.should_fail = should_fail
        self.call_count = 0
        self.calls: List[Dict[str, Any]] = []
        
        # Mock shield properties
        self._guard_func = self._mock_guard_func
        self._guard_func_is_async = True
        self._guard_func_params = {"request": None}
        self.auto_error = True
        self._exception_to_raise_if_fail = HTTPException(
            status_code=403, detail=f"Mock shield {name} blocked request"
        )
        self._default_response_to_return_if_fail = PlainTextResponse(
            content=f"Mock shield {name} blocked request", status_code=403
        )
    
    async def _mock_guard_func(self, request: Request = None, **kwargs) -> Optional[Any]:
        """Mock shield guard function."""
        self.call_count += 1
        self.calls.append({
            "timestamp": time.time(),
            "request_path": request.url.path if request else None,
            "request_method": request.method if request else None,
            "kwargs": kwargs
        })
        
        if self.delay_ms > 0:
            await asyncio.sleep(self.delay_ms / 1000)
        
        if self.should_fail:
            raise RuntimeError(f"Mock shield {self.name} failed")
        
        if self.should_block:
            return None
        
        return self.result
    
    def __call__(self, endpoint):
        """Make shield act as decorator."""
        return endpoint


class MockSyncShield(MockShield):
    """Mock synchronous shield for testing."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._guard_func_is_async = False
        self._guard_func = self._mock_sync_guard_func
    
    def _mock_sync_guard_func(self, request: Request = None, **kwargs) -> Optional[Any]:
        """Mock sync shield guard function."""
        self.call_count += 1
        self.calls.append({
            "timestamp": time.time(),
            "request_path": request.url.path if request else None,
            "request_method": request.method if request else None,
            "kwargs": kwargs
        })
        
        if self.delay_ms > 0:
            time.sleep(self.delay_ms / 1000)
        
        if self.should_fail:
            raise RuntimeError(f"Mock sync shield {self.name} failed")
        
        if self.should_block:
            return None
        
        return self.result


class MockSlowShield(MockShield):
    """Mock shield that takes a long time to process."""
    
    def __init__(self, *args, delay_ms: float = 1000, **kwargs):
        super().__init__(*args, delay_ms=delay_ms, **kwargs)


class MockFailingShield(MockShield):
    """Mock shield that always fails."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, should_fail=True, **kwargs)


class MockBlockingShield(MockShield):
    """Mock shield that always blocks requests."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, should_block=True, **kwargs)


class MockMiddlewareConfig:
    """Mock middleware configuration for testing."""
    
    @staticmethod
    def create_basic_config(shield: MockShield) -> MiddlewareConfig:
        """Create basic test configuration."""
        return MiddlewareConfig(
            shield=shield,
            name=f"test_{shield.name}",
            position=ShieldPosition.BEFORE_ROUTING,
            enabled=True
        )
    
    @staticmethod
    def create_performance_config(shield: MockShield) -> MiddlewareConfig:
        """Create performance-optimized configuration."""
        return MiddlewareConfig(
            shield=shield,
            name=f"perf_{shield.name}",
            enable_caching=True,
            cache_ttl_seconds=60,
            timeout_seconds=5.0,
            max_body_size=1024 * 1024  # 1MB
        )
    
    @staticmethod
    def create_restricted_config(shield: MockShield) -> MiddlewareConfig:
        """Create configuration with path restrictions."""
        return MiddlewareConfig(
            shield=shield,
            name=f"restricted_{shield.name}",
            include_paths={"/api", "/admin"},
            ignore_paths={"/health", "/metrics"},
            methods={"GET", "POST"}
        )
    
    @staticmethod
    def create_error_handling_config(shield: MockShield) -> MiddlewareConfig:
        """Create configuration with custom error handling."""
        def custom_error_handler(error: Exception, request: Request) -> Response:
            return JSONResponse(
                status_code=400,
                content={"custom_error": str(error), "path": request.url.path}
            )
        
        return MiddlewareConfig(
            shield=shield,
            name=f"error_{shield.name}",
            auto_error=True,
            error_response_type="json",
            custom_error_handler=custom_error_handler,
            pass_through_on_error=False
        )


class MockReceive:
    """Mock ASGI receive callable."""
    
    def __init__(self, body: bytes = b"", more_body: bool = False):
        self.body = body
        self.more_body = more_body
        self.call_count = 0
    
    async def __call__(self) -> Message:
        """Mock receive implementation."""
        self.call_count += 1
        
        if self.call_count == 1:
            return {
                "type": "http.request",
                "body": self.body,
                "more_body": self.more_body
            }
        else:
            return {
                "type": "http.request",
                "body": b"",
                "more_body": False
            }


class MockSend:
    """Mock ASGI send callable."""
    
    def __init__(self):
        self.messages: List[Message] = []
        self.call_count = 0
    
    async def __call__(self, message: Message) -> None:
        """Mock send implementation."""
        self.call_count += 1
        self.messages.append(message)
    
    def get_response_start(self) -> Optional[Message]:
        """Get response start message."""
        for msg in self.messages:
            if msg["type"] == "http.response.start":
                return msg
        return None
    
    def get_response_body(self) -> bytes:
        """Get complete response body."""
        body = b""
        for msg in self.messages:
            if msg["type"] == "http.response.body":
                body += msg.get("body", b"")
        return body
    
    def get_status_code(self) -> Optional[int]:
        """Get response status code."""
        start_msg = self.get_response_start()
        return start_msg.get("status") if start_msg else None
    
    def get_headers(self) -> Dict[str, str]:
        """Get response headers."""
        start_msg = self.get_response_start()
        if not start_msg:
            return {}
        
        headers = {}
        for name, value in start_msg.get("headers", []):
            headers[name.decode()] = value.decode()
        return headers


class MockCallNext:
    """Mock call_next function for Starlette middleware testing."""
    
    def __init__(self, response: Response = None, delay_ms: float = 0, 
                 should_fail: bool = False):
        self.response = response or Response("OK", status_code=200)
        self.delay_ms = delay_ms
        self.should_fail = should_fail
        self.call_count = 0
        self.calls: List[Dict[str, Any]] = []
    
    async def __call__(self, request: Request) -> Response:
        """Mock call_next implementation."""
        self.call_count += 1
        self.calls.append({
            "timestamp": time.time(),
            "path": request.url.path,
            "method": request.method
        })
        
        if self.delay_ms > 0:
            await asyncio.sleep(self.delay_ms / 1000)
        
        if self.should_fail:
            raise HTTPException(status_code=500, detail="Downstream error")
        
        return self.response


class MiddlewareTestScenarios:
    """Common test scenarios for middleware testing."""
    
    @staticmethod
    def create_simple_auth_scenario():
        """Create simple authentication test scenario."""
        def auth_shield_func(request: Request) -> Optional[Dict[str, Any]]:
            auth_header = request.headers.get("authorization")
            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header[7:]
                if token == "valid-token":
                    return {"user_id": 123, "username": "testuser"}
            return None
        
        shield = MockShield("auth_shield")
        shield._guard_func = auth_shield_func
        shield._guard_func_is_async = False
        
        return {
            "shield": shield,
            "valid_request": MockRequest(
                headers={"authorization": "Bearer valid-token"}
            ),
            "invalid_request": MockRequest(
                headers={"authorization": "Bearer invalid-token"}
            ),
            "no_auth_request": MockRequest()
        }
    
    @staticmethod
    def create_rate_limiting_scenario():
        """Create rate limiting test scenario."""
        request_counts = {}
        
        async def rate_limit_shield_func(request: Request) -> Optional[Dict[str, Any]]:
            client_ip = "127.0.0.1"  # Mock IP
            current_count = request_counts.get(client_ip, 0)
            
            if current_count >= 5:  # Max 5 requests
                return None
            
            request_counts[client_ip] = current_count + 1
            return {"allowed": True, "remaining": 5 - current_count - 1}
        
        shield = MockShield("rate_limit_shield")
        shield._guard_func = rate_limit_shield_func
        
        return {
            "shield": shield,
            "requests": [MockRequest(path=f"/api/test/{i}") for i in range(10)],
            "reset_counts": lambda: request_counts.clear()
        }
    
    @staticmethod
    def create_permission_scenario():
        """Create permission-based access control scenario."""
        async def permission_shield_func(request: Request) -> Optional[Dict[str, Any]]:
            path = request.url.path
            method = request.method
            
            # Mock permission rules
            if path.startswith("/admin") and method in ["POST", "PUT", "DELETE"]:
                role = request.headers.get("x-user-role")
                if role != "admin":
                    return None
            
            return {"access_granted": True}
        
        shield = MockShield("permission_shield")
        shield._guard_func = permission_shield_func
        shield._guard_func_is_async = True
        
        return {
            "shield": shield,
            "admin_request": MockRequest(
                method="POST", path="/admin/users",
                headers={"x-user-role": "admin"}
            ),
            "user_request": MockRequest(
                method="POST", path="/admin/users", 
                headers={"x-user-role": "user"}
            ),
            "public_request": MockRequest(path="/api/public")
        }


class MiddlewareTestHelper:
    """Helper utilities for middleware testing."""
    
    @staticmethod
    def create_test_app(response: Response = None) -> MockASGIApp:
        """Create test ASGI app."""
        return MockASGIApp(response or MockResponse())
    
    @staticmethod
    def create_test_scope(method: str = "GET", path: str = "/test", 
                         headers: Dict[str, str] = None) -> Scope:
        """Create test ASGI scope."""
        return {
            "type": "http",
            "method": method,
            "path": path,
            "headers": [(k.encode(), v.encode()) for k, v in (headers or {}).items()],
            "query_string": b"",
        }
    
    @staticmethod
    async def run_asgi_middleware(middleware, scope: Scope, 
                                 receive: MockReceive = None, 
                                 send: MockSend = None) -> MockSend:
        """Run ASGI middleware and return send mock."""
        if receive is None:
            receive = MockReceive()
        if send is None:
            send = MockSend()
        
        await middleware(scope, receive, send)
        return send
    
    @staticmethod
    async def run_starlette_middleware(middleware, request: MockRequest,
                                     call_next: MockCallNext = None) -> Response:
        """Run Starlette middleware and return response."""
        if call_next is None:
            call_next = MockCallNext()
        
        # Convert MockRequest to proper Request
        real_request = Request(request.scope, MockReceive())
        return await middleware.dispatch(real_request, call_next)
    
    @staticmethod
    def assert_middleware_metrics(metrics: MiddlewareMetrics, 
                                expected_requests: int,
                                expected_blocked: int = 0,
                                expected_allowed: Optional[int] = None):
        """Assert middleware metrics match expectations."""
        if expected_allowed is None:
            expected_allowed = expected_requests - expected_blocked
        
        assert metrics.total_requests == expected_requests, \
            f"Expected {expected_requests} requests, got {metrics.total_requests}"
        assert metrics.blocked_requests == expected_blocked, \
            f"Expected {expected_blocked} blocked, got {metrics.blocked_requests}"
        assert metrics.allowed_requests == expected_allowed, \
            f"Expected {expected_allowed} allowed, got {metrics.allowed_requests}"
        
        # Verify processing times are reasonable
        if metrics.processing_times:
            assert all(t >= 0 for t in metrics.processing_times), \
                "All processing times should be non-negative"
            assert metrics.avg_processing_time_ms >= 0, \
                "Average processing time should be non-negative"
    
    @staticmethod
    def create_middleware_chain_test(shields: List[MockShield]) -> Dict[str, Any]:
        """Create test setup for middleware chain testing."""
        configs = [MockMiddlewareConfig.create_basic_config(shield) for shield in shields]
        requests = [
            MockRequest(path="/test/1"),
            MockRequest(path="/test/2", method="POST"),
            MockRequest(path="/admin/test", headers={"authorization": "Bearer token"})
        ]
        
        return {
            "shields": shields,
            "configs": configs,
            "test_requests": requests,
            "expected_order": [shield.name for shield in shields]
        }
    
    @staticmethod
    def simulate_concurrent_requests(middleware, requests: List[MockRequest],
                                   concurrency: int = 5) -> List[asyncio.Task]:
        """Create tasks for concurrent request testing."""
        tasks = []
        
        for i in range(0, len(requests), concurrency):
            batch = requests[i:i+concurrency]
            for request in batch:
                # Create task for each request (implementation depends on test)
                task = asyncio.create_task(
                    MiddlewareTestHelper._mock_concurrent_request(middleware, request)
                )
                tasks.append(task)
        
        return tasks
    
    @staticmethod
    async def _mock_concurrent_request(middleware, request: MockRequest):
        """Mock concurrent request processing."""
        # This would be implemented based on the specific middleware type being tested
        await asyncio.sleep(0.001)  # Simulate processing time
        return {"processed": True, "request_path": request.url.path}