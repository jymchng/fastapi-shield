"""Tests for rate limiting shield functionality."""

import asyncio
import time
from typing import Dict, Any
from unittest.mock import Mock, patch

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient

from fastapi_shield.rate_limit import (
    RateLimitShield,
    RateLimitAlgorithm,
    RateLimitBackend,
    MemoryRateLimitBackend,
    rate_limit,
    per_ip_rate_limit,
    per_user_rate_limit,
)


class MockRequest:
    """Mock request for testing."""
    
    def __init__(self, client_host: str = "127.0.0.1", headers: Dict[str, str] = None,
                 path_params: Dict[str, Any] = None, query_params: Dict[str, str] = None):
        self.client = Mock()
        self.client.host = client_host
        self.headers = headers or {}
        self.path_params = path_params or {}
        self.query_params = query_params or {}


class TestMemoryRateLimitBackend:
    """Test the in-memory rate limit backend."""
    
    @pytest.fixture
    def backend(self):
        return MemoryRateLimitBackend()
    
    @pytest.mark.asyncio
    async def test_get_count_empty(self, backend):
        """Test get_count with no previous requests."""
        count = await backend.get_count("test_key", 60)
        assert count == 0
    
    @pytest.mark.asyncio
    async def test_increment_fixed_window(self, backend):
        """Test increment with fixed window."""
        key = "test_key:60"
        
        count1 = await backend.increment(key, 60)
        assert count1 == 1
        
        count2 = await backend.increment(key, 60)
        assert count2 == 2
    
    @pytest.mark.asyncio
    async def test_sliding_window_expiry(self, backend):
        """Test sliding window with time-based expiry."""
        key = "test_key"
        
        # Add some timestamps
        await backend.increment(key, 60)
        await backend.increment(key, 60)
        
        # Mock time to simulate time passage
        with patch('time.time', return_value=time.time() + 70):
            count = await backend.get_count(key, 60)
            assert count == 0  # Should be expired
    
    @pytest.mark.asyncio
    async def test_token_bucket_basic(self, backend):
        """Test basic token bucket functionality."""
        key = "bucket_key"
        
        # First request should succeed
        success1, remaining1 = await backend.consume_tokens(key, 1, 10, 1.0)
        assert success1 is True
        assert abs(remaining1 - 9.0) < 0.01  # Allow small floating point differences
        
        # Second request should succeed
        success2, remaining2 = await backend.consume_tokens(key, 1, 10, 1.0)
        assert success2 is True
        assert abs(remaining2 - 8.0) < 0.01  # Allow small floating point differences
    
    @pytest.mark.asyncio
    async def test_token_bucket_exhaustion(self, backend):
        """Test token bucket exhaustion."""
        key = "bucket_key"
        
        # Consume all tokens
        for i in range(10):
            success, remaining = await backend.consume_tokens(key, 1, 10, 1.0)
            assert success is True
        
        # Next request should fail
        success, remaining = await backend.consume_tokens(key, 1, 10, 1.0)
        assert success is False
        assert remaining < 1.0
    
    @pytest.mark.asyncio
    async def test_token_bucket_refill(self, backend):
        """Test token bucket refill over time."""
        key = "bucket_key"
        
        # Consume all tokens
        for _ in range(10):
            await backend.consume_tokens(key, 1, 10, 1.0)
        
        # Wait a bit and simulate time passage for refill
        import asyncio
        await asyncio.sleep(0.01)  # Small delay to ensure time has passed
        
        # Patch time to simulate 2 seconds later
        with patch('time.time', return_value=time.time() + 2):
            success, remaining = await backend.consume_tokens(key, 2, 10, 1.0)
            assert success is True
            assert abs(remaining - 0.0) < 0.02  # Allow for small precision differences
    
    @pytest.mark.asyncio
    async def test_reset_window(self, backend):
        """Test window reset functionality."""
        key = "test_key"
        
        await backend.increment(key, 60)
        await backend.reset_window(key)
        
        count = await backend.get_count(key, 60)
        assert count == 0


class TestRateLimitShield:
    """Test the RateLimitShield class."""
    
    def test_init_no_limits(self):
        """Test initialization with no limits raises error."""
        with pytest.raises(ValueError, match="At least one rate limit must be specified"):
            RateLimitShield()
    
    def test_init_token_bucket_no_per_second(self):
        """Test token bucket without requests_per_second raises error."""
        with pytest.raises(ValueError, match="Token bucket algorithm requires requests_per_second"):
            RateLimitShield(
                requests_per_minute=60,
                algorithm=RateLimitAlgorithm.TOKEN_BUCKET
            )
    
    def test_init_valid(self):
        """Test valid initialization."""
        shield = RateLimitShield(requests_per_minute=100)
        assert shield.requests_per_minute == 100
        assert shield.algorithm == RateLimitAlgorithm.SLIDING_WINDOW
        assert isinstance(shield.backend, MemoryRateLimitBackend)
    
    def test_default_key_func(self):
        """Test default key function."""
        shield = RateLimitShield(requests_per_minute=100)
        request = MockRequest(client_host="192.168.1.1")
        
        key = shield.key_func(request)
        assert key == "rate_limit:192.168.1.1"
    
    def test_default_key_func_x_forwarded_for(self):
        """Test default key function with X-Forwarded-For header."""
        shield = RateLimitShield(requests_per_minute=100)
        request = MockRequest(
            client_host="127.0.0.1",
            headers={"x-forwarded-for": "203.0.113.1, 192.168.1.1"}
        )
        
        key = shield.key_func(request)
        assert key == "rate_limit:203.0.113.1"
    
    @pytest.mark.asyncio
    async def test_check_rate_limit_allowed(self):
        """Test rate limit check when allowed."""
        shield = RateLimitShield(requests_per_minute=100)
        
        is_allowed, retry_after = await shield._check_rate_limit("test_key")
        assert is_allowed is True
        assert retry_after is None
    
    @pytest.mark.asyncio
    async def test_check_rate_limit_exceeded(self):
        """Test rate limit check when exceeded."""
        shield = RateLimitShield(requests_per_minute=2)
        
        # Make requests that exceed the limit
        for _ in range(3):
            await shield._increment_counters("test_key")
        
        is_allowed, retry_after = await shield._check_rate_limit("test_key")
        assert is_allowed is False
        assert retry_after == 60
    
    @pytest.mark.asyncio
    async def test_token_bucket_algorithm(self):
        """Test token bucket algorithm."""
        shield = RateLimitShield(
            requests_per_second=5,
            algorithm=RateLimitAlgorithm.TOKEN_BUCKET
        )
        
        # First few requests should succeed
        for _ in range(5):
            is_allowed, retry_after = await shield._check_rate_limit("test_key")
            assert is_allowed is True
        
        # Next request should fail
        is_allowed, retry_after = await shield._check_rate_limit("test_key")
        assert is_allowed is False
        assert retry_after is not None


class TestRateLimitIntegration:
    """Integration tests with FastAPI."""
    
    def test_rate_limit_decorator(self):
        """Test rate limiting with FastAPI integration."""
        app = FastAPI()
        
        @app.get("/test")
        @rate_limit(requests_per_minute=2)
        async def test_endpoint():
            return {"message": "success"}
        
        client = TestClient(app)
        
        # First two requests should succeed
        response1 = client.get("/test")
        assert response1.status_code == 200
        
        response2 = client.get("/test")
        assert response2.status_code == 200
        
        # Third request should be rate limited
        response3 = client.get("/test")
        assert response3.status_code == 429
        assert "Retry-After" in response3.headers
        assert "X-RateLimit-Limit" in response3.headers
    
    def test_per_ip_rate_limit(self):
        """Test per-IP rate limiting."""
        app = FastAPI()
        
        @app.get("/test")
        @per_ip_rate_limit(requests_per_minute=1)
        async def test_endpoint():
            return {"message": "success"}
        
        client = TestClient(app)
        
        # First request should succeed
        response1 = client.get("/test")
        assert response1.status_code == 200
        
        # Second request should be rate limited
        response2 = client.get("/test")
        assert response2.status_code == 429
    
    def test_per_user_rate_limit_path_param(self):
        """Test per-user rate limiting with path parameter."""
        app = FastAPI()
        
        @app.get("/users/{user_id}/profile")
        @per_user_rate_limit(requests_per_minute=1)
        async def get_user_profile(user_id: int):
            return {"user_id": user_id, "profile": "data"}
        
        client = TestClient(app)
        
        # First request for user 1 should succeed
        response1 = client.get("/users/1/profile")
        assert response1.status_code == 200
        
        # Second request for user 1 should be rate limited
        response2 = client.get("/users/1/profile")
        assert response2.status_code == 429
        
        # But request for user 2 should succeed (different user)
        response3 = client.get("/users/2/profile")
        assert response3.status_code == 200
    
    def test_per_user_rate_limit_query_param(self):
        """Test per-user rate limiting with query parameter."""
        app = FastAPI()
        
        @app.get("/data")
        @per_user_rate_limit(requests_per_minute=1)
        async def get_data():
            return {"data": "value"}
        
        client = TestClient(app)
        
        # First request for user should succeed
        response1 = client.get("/data?user_id=123")
        assert response1.status_code == 200
        
        # Second request for same user should be rate limited
        response2 = client.get("/data?user_id=123")
        assert response2.status_code == 429
        
        # But request for different user should succeed
        response3 = client.get("/data?user_id=456")
        assert response3.status_code == 200
    
    def test_per_user_rate_limit_header(self):
        """Test per-user rate limiting with header."""
        app = FastAPI()
        
        @app.get("/api/data")
        @per_user_rate_limit(requests_per_minute=1)
        async def get_api_data():
            return {"data": "api_value"}
        
        client = TestClient(app)
        
        # First request should succeed
        response1 = client.get("/api/data", headers={"X-User-ID": "user123"})
        assert response1.status_code == 200
        
        # Second request for same user should be rate limited
        response2 = client.get("/api/data", headers={"X-User-ID": "user123"})
        assert response2.status_code == 429
        
        # But request for different user should succeed
        response3 = client.get("/api/data", headers={"X-User-ID": "user456"})
        assert response3.status_code == 200
    
    def test_multiple_rate_limits(self):
        """Test multiple rate limits (per second and per minute)."""
        app = FastAPI()
        
        @app.get("/test")
        @rate_limit(requests_per_second=1, requests_per_minute=3)
        async def test_endpoint():
            return {"message": "success"}
        
        client = TestClient(app)
        
        # First request should succeed
        response1 = client.get("/test")
        assert response1.status_code == 200
        
        # Second request should be rate limited by per-second limit
        response2 = client.get("/test")
        assert response2.status_code == 429
    
    def test_fixed_window_algorithm(self):
        """Test fixed window algorithm."""
        app = FastAPI()
        
        @app.get("/test")
        @rate_limit(
            requests_per_minute=2,
            algorithm=RateLimitAlgorithm.FIXED_WINDOW
        )
        async def test_endpoint():
            return {"message": "success"}
        
        client = TestClient(app)
        
        # First two requests should succeed
        response1 = client.get("/test")
        assert response1.status_code == 200
        
        response2 = client.get("/test")
        assert response2.status_code == 200
        
        # Third request should be rate limited
        response3 = client.get("/test")
        assert response3.status_code == 429
    
    def test_token_bucket_algorithm(self):
        """Test token bucket algorithm."""
        app = FastAPI()
        
        @app.get("/test")
        @rate_limit(
            requests_per_second=3,
            algorithm=RateLimitAlgorithm.TOKEN_BUCKET
        )
        async def test_endpoint():
            return {"message": "success"}
        
        client = TestClient(app)
        
        # First three requests should succeed (bucket starts full)
        for _ in range(3):
            response = client.get("/test")
            assert response.status_code == 200
        
        # Fourth request should be rate limited
        response = client.get("/test")
        assert response.status_code == 429
    
    def test_custom_key_function(self):
        """Test custom key function."""
        def custom_key_func(request):
            return f"custom:{request.headers.get('api-key', 'anonymous')}"
        
        app = FastAPI()
        
        rate_limiter = RateLimitShield(
            requests_per_minute=1,
            key_func=custom_key_func
        )
        
        @app.get("/test")
        @rate_limiter.create_shield()
        async def test_endpoint():
            return {"message": "success"}
        
        client = TestClient(app)
        
        # First request with API key should succeed
        response1 = client.get("/test", headers={"api-key": "key123"})
        assert response1.status_code == 200
        
        # Second request with same API key should be rate limited
        response2 = client.get("/test", headers={"api-key": "key123"})
        assert response2.status_code == 429
        
        # But request with different API key should succeed
        response3 = client.get("/test", headers={"api-key": "key456"})
        assert response3.status_code == 200
    
    def test_rate_limit_headers(self):
        """Test rate limit response headers."""
        app = FastAPI()
        
        @app.get("/test")
        @rate_limit(requests_per_minute=1)
        async def test_endpoint():
            return {"message": "success"}
        
        client = TestClient(app)
        
        # First request should succeed
        response1 = client.get("/test")
        assert response1.status_code == 200
        
        # Second request should be rate limited with proper headers
        response2 = client.get("/test")
        assert response2.status_code == 429
        assert "Retry-After" in response2.headers
        assert "X-RateLimit-Limit" in response2.headers
        assert "X-RateLimit-Remaining" in response2.headers
        assert "X-RateLimit-Reset" in response2.headers
        
        assert response2.headers["X-RateLimit-Remaining"] == "0"
        assert int(response2.headers["Retry-After"]) > 0


class TestRateLimitEdgeCases:
    """Test edge cases and error conditions."""
    
    def test_no_client_ip(self):
        """Test handling when client IP is not available."""
        shield = RateLimitShield(requests_per_minute=100)
        request = Mock()
        request.client = None
        request.headers = {}
        
        key = shield.key_func(request)
        assert key == "rate_limit:unknown"
    
    @pytest.mark.asyncio
    async def test_concurrent_requests(self):
        """Test concurrent requests don't exceed rate limits."""
        shield = RateLimitShield(requests_per_minute=5)
        
        async def make_request():
            is_allowed, _ = await shield._check_rate_limit("test_key")
            if is_allowed:
                await shield._increment_counters("test_key")
            return is_allowed
        
        # Make 10 concurrent requests
        tasks = [make_request() for _ in range(10)]
        results = await asyncio.gather(*tasks)
        
        # Only 5 should be allowed due to rate limit
        allowed_count = sum(results)
        assert allowed_count <= 5
    
    def test_rate_limit_shield_parameters(self):
        """Test RateLimitShield with all parameters."""
        backend = MemoryRateLimitBackend()
        
        def custom_key_func(request):
            return f"custom:{request.client.host}"
        
        shield = RateLimitShield(
            requests_per_second=10,
            requests_per_minute=600,
            requests_per_hour=3600,
            requests_per_day=86400,
            algorithm=RateLimitAlgorithm.TOKEN_BUCKET,
            backend=backend,
            key_func=custom_key_func,
            max_tokens=15,
            refill_rate=10.0,
        )
        
        assert shield.requests_per_second == 10
        assert shield.requests_per_minute == 600
        assert shield.requests_per_hour == 3600
        assert shield.requests_per_day == 86400
        assert shield.algorithm == RateLimitAlgorithm.TOKEN_BUCKET
        assert shield.backend is backend
        assert shield.key_func is custom_key_func
        assert shield.max_tokens == 15
        assert shield.refill_rate == 10.0


class TestCustomBackend:
    """Test custom backend implementation."""
    
    class CustomTestBackend(RateLimitBackend):
        """Test backend that tracks calls."""
        
        def __init__(self):
            self.get_count_calls = 0
            self.increment_calls = 0
            self.token_calls = 0
            self.consume_calls = 0
            self.reset_calls = 0
        
        async def get_count(self, key: str, window_seconds: int) -> int:
            self.get_count_calls += 1
            return 0
        
        async def increment(self, key: str, window_seconds: int) -> int:
            self.increment_calls += 1
            return 1
        
        async def get_tokens(self, key: str) -> tuple[float, float]:
            self.token_calls += 1
            return 10.0, time.time()
        
        async def consume_tokens(self, key: str, tokens_to_consume: int,
                               max_tokens: int, refill_rate: float) -> tuple[bool, float]:
            self.consume_calls += 1
            return True, 9.0
        
        async def reset_window(self, key: str) -> None:
            self.reset_calls += 1
    
    @pytest.mark.asyncio
    async def test_custom_backend_sliding_window(self):
        """Test custom backend with sliding window."""
        backend = self.CustomTestBackend()
        shield = RateLimitShield(
            requests_per_minute=100,
            algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
            backend=backend
        )
        
        await shield._check_rate_limit("test_key")
        assert backend.get_count_calls == 1
    
    @pytest.mark.asyncio
    async def test_custom_backend_token_bucket(self):
        """Test custom backend with token bucket."""
        backend = self.CustomTestBackend()
        shield = RateLimitShield(
            requests_per_second=10,
            algorithm=RateLimitAlgorithm.TOKEN_BUCKET,
            backend=backend
        )
        
        await shield._check_rate_limit("test_key")
        assert backend.consume_calls == 1


if __name__ == "__main__":
    pytest.main([__file__])