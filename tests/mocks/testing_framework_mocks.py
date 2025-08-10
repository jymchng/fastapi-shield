"""Mock classes and utilities for testing the Shield Testing Framework."""

import asyncio
import json
import random
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import Mock

from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import JSONResponse

from fastapi_shield.shield import Shield
from fastapi_shield.testing import MockRequest


class MockShieldAlwaysAllow(Shield):
    """Mock shield that always allows requests."""
    
    def __init__(self, name: str = "AlwaysAllowShield", delay: float = 0.0):
        self.name = name
        self.delay = delay
        self.call_count = 0
        super().__init__(self._shield_function, name=name)
    
    async def _shield_function(self, request) -> Optional[Any]:
        """Shield function that always allows."""
        self.call_count += 1
        if self.delay > 0:
            await asyncio.sleep(self.delay)
        return None  # Allow request


class MockShieldAlwaysBlock(Shield):
    """Mock shield that always blocks requests."""
    
    def __init__(self, name: str = "AlwaysBlockShield", delay: float = 0.0, block_message: str = "Request blocked"):
        self.name = name
        self.delay = delay
        self.block_message = block_message
        self.call_count = 0
        super().__init__(self._shield_function, name=name)
    
    async def _shield_function(self, request) -> Optional[Any]:
        """Shield function that always blocks."""
        self.call_count += 1
        if self.delay > 0:
            await asyncio.sleep(self.delay)
        
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"error": self.block_message}
        )


class MockShieldConditional(Shield):
    """Mock shield that conditionally allows/blocks based on request properties."""
    
    def __init__(
        self, 
        name: str = "ConditionalShield",
        allow_methods: Optional[List[str]] = None,
        block_paths: Optional[List[str]] = None,
        require_headers: Optional[Dict[str, str]] = None
    ):
        self.name = name
        self.allow_methods = allow_methods or ["GET", "POST"]
        self.block_paths = block_paths or ["/blocked", "/forbidden"]
        self.require_headers = require_headers or {}
        self.call_count = 0
        self.blocked_count = 0
        self.allowed_count = 0
        super().__init__(self._shield_function, name=name)
    
    async def _shield_function(self, request) -> Optional[Any]:
        """Conditional shield function."""
        self.call_count += 1
        
        # Check method
        if request.method not in self.allow_methods:
            self.blocked_count += 1
            return JSONResponse(
                status_code=status.HTTP_405_METHOD_NOT_ALLOWED,
                content={"error": f"Method {request.method} not allowed"}
            )
        
        # Check blocked paths
        path = str(request.url.path) if hasattr(request.url, 'path') else str(request.url)
        for blocked_path in self.block_paths:
            if blocked_path in path:
                self.blocked_count += 1
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"error": f"Access to {blocked_path} is forbidden"}
                )
        
        # Check required headers
        for header_name, expected_value in self.require_headers.items():
            actual_value = request.headers.get(header_name)
            if actual_value != expected_value:
                self.blocked_count += 1
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"error": f"Missing or invalid header: {header_name}"}
                )
        
        self.allowed_count += 1
        return None  # Allow request


class MockShieldWithError(Shield):
    """Mock shield that raises errors during execution."""
    
    def __init__(
        self, 
        name: str = "ErrorShield",
        error_probability: float = 0.5,
        error_message: str = "Shield execution error"
    ):
        self.name = name
        self.error_probability = error_probability
        self.error_message = error_message
        self.call_count = 0
        self.error_count = 0
        super().__init__(self._shield_function, name=name)
    
    async def _shield_function(self, request) -> Optional[Any]:
        """Shield function that randomly raises errors."""
        self.call_count += 1
        
        if random.random() < self.error_probability:
            self.error_count += 1
            raise Exception(self.error_message)
        
        return None  # Allow request if no error


class MockShieldPerformance(Shield):
    """Mock shield for performance testing."""
    
    def __init__(
        self, 
        name: str = "PerformanceShield",
        min_delay: float = 0.001,
        max_delay: float = 0.01,
        cpu_intensive: bool = False
    ):
        self.name = name
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.cpu_intensive = cpu_intensive
        self.call_count = 0
        self.total_delay = 0.0
        super().__init__(self._shield_function, name=name)
    
    async def _shield_function(self, request) -> Optional[Any]:
        """Performance-focused shield function."""
        self.call_count += 1
        
        # Simulate processing delay
        delay = random.uniform(self.min_delay, self.max_delay)
        self.total_delay += delay
        
        if self.cpu_intensive:
            # Simulate CPU-intensive work
            _ = sum(i * i for i in range(1000))
        
        await asyncio.sleep(delay)
        return None  # Allow request
    
    def get_avg_delay(self) -> float:
        """Get average delay per call."""
        return self.total_delay / self.call_count if self.call_count > 0 else 0.0


class MockShieldRateLimit(Shield):
    """Mock shield that implements simple rate limiting."""
    
    def __init__(self, name: str = "RateLimitShield", max_requests: int = 5, window_seconds: int = 60):
        self.name = name
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = {}  # client_ip -> list of timestamps
        self.call_count = 0
        self.blocked_count = 0
        super().__init__(self._shield_function, name=name)
    
    async def _shield_function(self, request) -> Optional[Any]:
        """Rate limiting shield function."""
        import time
        
        self.call_count += 1
        current_time = time.time()
        
        # Get client IP
        client_ip = getattr(request.client, 'host', '127.0.0.1')
        
        # Initialize or clean old requests
        if client_ip not in self.requests:
            self.requests[client_ip] = []
        
        # Remove old requests outside the window
        self.requests[client_ip] = [
            timestamp for timestamp in self.requests[client_ip]
            if current_time - timestamp < self.window_seconds
        ]
        
        # Check rate limit
        if len(self.requests[client_ip]) >= self.max_requests:
            self.blocked_count += 1
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"error": "Rate limit exceeded"}
            )
        
        # Add current request
        self.requests[client_ip].append(current_time)
        return None  # Allow request


class TestShieldFactory:
    """Factory for creating various test shields."""
    
    @staticmethod
    def create_allow_shield(name: str = "AllowShield", delay: float = 0.0) -> MockShieldAlwaysAllow:
        """Create a shield that always allows."""
        return MockShieldAlwaysAllow(name, delay)
    
    @staticmethod
    def create_block_shield(name: str = "BlockShield", delay: float = 0.0) -> MockShieldAlwaysBlock:
        """Create a shield that always blocks."""
        return MockShieldAlwaysBlock(name, delay)
    
    @staticmethod
    def create_conditional_shield(
        name: str = "ConditionalShield",
        allow_methods: List[str] = None,
        block_paths: List[str] = None
    ) -> MockShieldConditional:
        """Create a conditional shield."""
        return MockShieldConditional(name, allow_methods, block_paths)
    
    @staticmethod
    def create_error_shield(
        name: str = "ErrorShield",
        error_probability: float = 0.5
    ) -> MockShieldWithError:
        """Create a shield that produces errors."""
        return MockShieldWithError(name, error_probability)
    
    @staticmethod
    def create_performance_shield(
        name: str = "PerfShield",
        min_delay: float = 0.001,
        max_delay: float = 0.01
    ) -> MockShieldPerformance:
        """Create a performance testing shield."""
        return MockShieldPerformance(name, min_delay, max_delay)
    
    @staticmethod
    def create_rate_limit_shield(
        name: str = "RateLimitShield",
        max_requests: int = 5
    ) -> MockShieldRateLimit:
        """Create a rate limiting shield."""
        return MockShieldRateLimit(name, max_requests)
    
    @staticmethod
    def create_shield_collection() -> List[Shield]:
        """Create a collection of different shields for testing."""
        return [
            TestShieldFactory.create_allow_shield("AllowShield1"),
            TestShieldFactory.create_block_shield("BlockShield1"),
            TestShieldFactory.create_conditional_shield("ConditionalShield1", ["GET"], ["/admin"]),
            TestShieldFactory.create_performance_shield("PerfShield1", 0.001, 0.005),
            TestShieldFactory.create_rate_limit_shield("RateLimitShield1", 3)
        ]


class MockFastAPIApp:
    """Mock FastAPI application for testing integration."""
    
    def __init__(self):
        self.app = FastAPI(title="Test App", version="1.0.0")
        self.setup_routes()
    
    def setup_routes(self):
        """Setup test routes."""
        
        @self.app.get("/")
        async def root():
            return {"message": "Hello World"}
        
        @self.app.get("/protected")
        async def protected():
            return {"message": "This is a protected endpoint"}
        
        @self.app.post("/data")
        async def create_data(data: Dict[str, Any]):
            return {"received": data, "status": "created"}
        
        @self.app.get("/error")
        async def error_endpoint():
            raise HTTPException(status_code=500, detail="Internal server error")
        
        @self.app.get("/slow")
        async def slow_endpoint():
            await asyncio.sleep(0.1)
            return {"message": "This was slow"}
    
    def get_app(self) -> FastAPI:
        """Get the FastAPI app instance."""
        return self.app


class TestScenarioBuilder:
    """Builder for creating comprehensive test scenarios."""
    
    @staticmethod
    def build_basic_scenarios() -> List[Dict[str, Any]]:
        """Build basic test scenarios."""
        return [
            {
                'name': 'basic_get',
                'method': 'GET',
                'url': '/',
                'expected_status': 200
            },
            {
                'name': 'basic_post',
                'method': 'POST',
                'url': '/data',
                'expected_status': 200,
                'kwargs': {'json': {'test': 'data'}}
            },
            {
                'name': 'not_found',
                'method': 'GET',
                'url': '/nonexistent',
                'expected_status': 404
            }
        ]
    
    @staticmethod
    def build_shield_test_scenarios() -> List[Dict[str, Any]]:
        """Build scenarios specifically for shield testing."""
        return [
            {
                'name': 'allow_valid_get',
                'request': MockRequest(method="GET", url="http://testserver/api/data"),
                'expected_outcome': 'allow',
                'description': 'Valid GET request should be allowed'
            },
            {
                'name': 'block_invalid_method',
                'request': MockRequest(method="DELETE", url="http://testserver/api/data"),
                'expected_outcome': 'block',
                'description': 'DELETE method should be blocked'
            },
            {
                'name': 'block_forbidden_path',
                'request': MockRequest(method="GET", url="http://testserver/admin/users"),
                'expected_outcome': 'block',
                'description': 'Admin path should be blocked'
            },
            {
                'name': 'allow_with_headers',
                'request': MockRequest(
                    method="POST",
                    url="http://testserver/api/create",
                    headers={"authorization": "Bearer token123", "content-type": "application/json"},
                    json_data={"name": "test"}
                ),
                'expected_outcome': 'allow',
                'description': 'POST with proper headers should be allowed'
            }
        ]
    
    @staticmethod
    def build_performance_scenarios() -> List[MockRequest]:
        """Build scenarios for performance testing."""
        scenarios = []
        
        # Various request types
        methods = ["GET", "POST", "PUT", "DELETE"]
        paths = ["/api/users", "/api/data", "/api/products", "/api/orders"]
        
        for method in methods:
            for path in paths:
                request = MockRequest(
                    method=method,
                    url=f"http://testserver{path}",
                    headers={"user-agent": f"PerfTest/{method}"},
                    json_data={"test": "performance"} if method in ["POST", "PUT"] else None
                )
                scenarios.append(request)
        
        return scenarios
    
    @staticmethod
    def build_error_scenarios() -> List[MockRequest]:
        """Build scenarios that might cause errors."""
        return [
            # Invalid JSON
            MockRequest(
                method="POST",
                url="http://testserver/api/data",
                body=b'{"invalid": json}',
                headers={"content-type": "application/json"}
            ),
            # Missing content-type
            MockRequest(
                method="POST",
                url="http://testserver/api/data",
                body=b'{"data": "test"}'
            ),
            # Very long URL
            MockRequest(
                method="GET",
                url="http://testserver/" + "a" * 1000
            ),
            # Special characters in headers
            MockRequest(
                method="GET",
                url="http://testserver/api/test",
                headers={"x-custom": "test\x00\x01\x02"}
            )
        ]


class TestResultValidator:
    """Validator for test results."""
    
    @staticmethod
    def validate_test_result(result, expected_status=None, expected_blocked=None):
        """Validate a single test result."""
        assert hasattr(result, 'result'), "Test result should have 'result' attribute"
        assert hasattr(result, 'shield_name'), "Test result should have 'shield_name' attribute"
        assert hasattr(result, 'test_name'), "Test result should have 'test_name' attribute"
        
        if expected_status is not None:
            assert result.result.status == expected_status, f"Expected status {expected_status}, got {result.result.status}"
        
        if expected_blocked is not None:
            assert result.blocked == expected_blocked, f"Expected blocked={expected_blocked}, got {result.blocked}"
    
    @staticmethod
    def validate_performance_metrics(metrics, min_requests=1):
        """Validate performance metrics."""
        # Check for either ShieldTestRunner metrics or PerformanceTestRunner metrics
        shield_runner_keys = ['iterations', 'avg_time', 'total_time', 'min_time', 'max_time']
        perf_runner_keys = ['total_requests', 'successful_executions', 'total_time', 'average_time_per_request', 'requests_per_second']
        
        has_shield_runner_keys = all(key in metrics for key in shield_runner_keys)
        has_perf_runner_keys = all(key in metrics for key in perf_runner_keys)
        
        assert has_shield_runner_keys or has_perf_runner_keys, f"Performance metrics missing required keys. Got: {list(metrics.keys())}"
        
        # Validate common fields
        assert metrics.get('total_time', 0) >= 0, "Total time should be non-negative"
        
        if has_shield_runner_keys:
            assert metrics.get('iterations', 0) >= min_requests, "Should have minimum number of requests"
            assert metrics['avg_time'] >= 0, "Average time should be non-negative"
            assert metrics['min_time'] >= 0, "Min time should be non-negative"
            assert metrics['max_time'] >= 0, "Max time should be non-negative"
        
        if has_perf_runner_keys:
            assert metrics.get('total_requests', 0) >= min_requests, "Should have minimum number of requests"
            assert metrics['average_time_per_request'] >= 0, "Average time should be non-negative"
            if metrics['total_time'] > 0:
                assert metrics['requests_per_second'] > 0, "RPS should be positive when total_time > 0"
    
    @staticmethod
    def validate_test_suite_summary(summary, min_shields=1, min_tests=1):
        """Validate test suite summary."""
        required_keys = [
            'suite_name', 'shields_tested', 'test_cases', 'total_results',
            'total_passed', 'total_failed', 'overall_pass_rate'
        ]
        
        for key in required_keys:
            assert key in summary, f"Suite summary missing key: {key}"
        
        assert summary['shields_tested'] >= min_shields, f"Should test at least {min_shields} shields"
        assert summary['total_results'] >= min_tests, f"Should have at least {min_tests} test results"
        assert 0 <= summary['overall_pass_rate'] <= 100, "Pass rate should be between 0 and 100"


class MockDatabase:
    """Mock database for testing data persistence in shields."""
    
    def __init__(self):
        self.data = {}
        self.access_log = []
    
    async def get(self, key: str) -> Any:
        """Get value from mock database."""
        self.access_log.append(('GET', key))
        return self.data.get(key)
    
    async def set(self, key: str, value: Any) -> bool:
        """Set value in mock database."""
        self.access_log.append(('SET', key, value))
        self.data[key] = value
        return True
    
    async def delete(self, key: str) -> bool:
        """Delete value from mock database."""
        self.access_log.append(('DELETE', key))
        if key in self.data:
            del self.data[key]
            return True
        return False
    
    def clear(self):
        """Clear all data."""
        self.data.clear()
        self.access_log.clear()
    
    def get_access_log(self) -> List[Tuple[str, ...]]:
        """Get access log."""
        return self.access_log.copy()


class MockCache:
    """Mock cache for testing caching in shields."""
    
    def __init__(self, max_size: int = 100):
        self.cache = {}
        self.max_size = max_size
        self.hits = 0
        self.misses = 0
        self.access_order = []
    
    async def get(self, key: str) -> Any:
        """Get value from cache."""
        if key in self.cache:
            self.hits += 1
            # Update access order
            if key in self.access_order:
                self.access_order.remove(key)
            self.access_order.append(key)
            return self.cache[key]
        else:
            self.misses += 1
            return None
    
    async def set(self, key: str, value: Any, ttl: int = None) -> bool:
        """Set value in cache."""
        # Simple LRU eviction if at capacity
        if len(self.cache) >= self.max_size and key not in self.cache:
            # Remove least recently used
            if self.access_order:
                lru_key = self.access_order.pop(0)
                if lru_key in self.cache:
                    del self.cache[lru_key]
        
        self.cache[key] = value
        
        # Update access order
        if key in self.access_order:
            self.access_order.remove(key)
        self.access_order.append(key)
        
        return True
    
    async def delete(self, key: str) -> bool:
        """Delete value from cache."""
        if key in self.cache:
            del self.cache[key]
            if key in self.access_order:
                self.access_order.remove(key)
            return True
        return False
    
    def clear(self):
        """Clear cache."""
        self.cache.clear()
        self.access_order.clear()
        self.hits = 0
        self.misses = 0
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        total_requests = self.hits + self.misses
        hit_rate = (self.hits / total_requests) * 100 if total_requests > 0 else 0
        
        return {
            'size': len(self.cache),
            'max_size': self.max_size,
            'hits': self.hits,
            'misses': self.misses,
            'hit_rate': hit_rate
        }