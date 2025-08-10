"""Rate limiting shield for FastAPI Shield.

This module provides rate limiting functionality to prevent abuse and DoS attacks
by limiting the number of requests per time window. Supports multiple algorithms
and backends.
"""

import asyncio
import time
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, Optional, Union
from threading import Lock

from fastapi import HTTPException, Request, Response, status

from fastapi_shield.shield import Shield, shield


class RateLimitAlgorithm(str, Enum):
    """Rate limiting algorithms."""
    SLIDING_WINDOW = "sliding_window"
    FIXED_WINDOW = "fixed_window"
    TOKEN_BUCKET = "token_bucket"


class RateLimitBackend(ABC):
    """Abstract base class for rate limit storage backends."""
    
    @abstractmethod
    async def get_count(self, key: str, window_seconds: int) -> int:
        """Get current count for the key within the time window."""
        pass
    
    @abstractmethod
    async def increment(self, key: str, window_seconds: int) -> int:
        """Increment and return the new count for the key."""
        pass
    
    @abstractmethod
    async def get_tokens(self, key: str) -> tuple[float, float]:
        """Get current tokens and last refill time."""
        pass
    
    @abstractmethod
    async def consume_tokens(self, key: str, tokens_to_consume: int, 
                           max_tokens: int, refill_rate: float) -> tuple[bool, float]:
        """Consume tokens and return (success, tokens_remaining)."""
        pass
    
    @abstractmethod
    async def reset_window(self, key: str) -> None:
        """Reset the window for the key."""
        pass


class MemoryRateLimitBackend(RateLimitBackend):
    """In-memory rate limit backend using local storage."""
    
    def __init__(self):
        self._data: Dict[str, Any] = defaultdict(dict)
        self._lock = Lock()
    
    async def get_count(self, key: str, window_seconds: int) -> int:
        """Get current count for sliding window algorithm."""
        with self._lock:
            if key not in self._data:
                self._data[key] = {"timestamps": deque(), "count": 0}
            
            timestamps = self._data[key]["timestamps"]
            current_time = time.time()
            cutoff_time = current_time - window_seconds
            
            # Remove expired timestamps
            while timestamps and timestamps[0] < cutoff_time:
                timestamps.popleft()
            
            return len(timestamps)
    
    async def increment(self, key: str, window_seconds: int) -> int:
        """Increment count for the key."""
        with self._lock:
            current_time = time.time()
            
            if key not in self._data:
                self._data[key] = {"timestamps": deque(), "window_start": current_time, "count": 0}
            
            # For fixed window algorithm
            if "window_start" in self._data[key]:
                if current_time - self._data[key]["window_start"] >= window_seconds:
                    # Reset window
                    self._data[key]["count"] = 0
                    self._data[key]["window_start"] = current_time
                
                self._data[key]["count"] += 1
                return self._data[key]["count"]
            
            # For sliding window algorithm
            timestamps = self._data[key]["timestamps"]
            cutoff_time = current_time - window_seconds
            
            # Remove expired timestamps
            while timestamps and timestamps[0] < cutoff_time:
                timestamps.popleft()
            
            timestamps.append(current_time)
            return len(timestamps)
    
    async def get_tokens(self, key: str) -> tuple[float, float]:
        """Get current tokens and last refill time."""
        with self._lock:
            if key not in self._data:
                current_time = time.time()
                self._data[key] = {"tokens": 0.0, "last_refill": current_time}
                return 0.0, current_time
            
            tokens = self._data[key].get("tokens", 0.0)
            last_refill = self._data[key].get("last_refill", time.time())
            return tokens, last_refill
    
    async def consume_tokens(self, key: str, tokens_to_consume: int,
                           max_tokens: int, refill_rate: float) -> tuple[bool, float]:
        """Consume tokens from the bucket."""
        with self._lock:
            current_time = time.time()
            
            if key not in self._data:
                self._data[key] = {"tokens": float(max_tokens), "last_refill": current_time}
            
            # Refill tokens based on time passed
            time_passed = current_time - self._data[key]["last_refill"]
            tokens_to_add = time_passed * refill_rate
            current_tokens = min(max_tokens, self._data[key]["tokens"] + tokens_to_add)
            
            # Only update the last refill time if we actually refilled tokens
            if tokens_to_add > 0:
                self._data[key]["last_refill"] = current_time
                self._data[key]["tokens"] = current_tokens
            
            if current_tokens >= tokens_to_consume:
                self._data[key]["tokens"] -= tokens_to_consume
                return True, round(self._data[key]["tokens"], 6)  # Round to avoid floating point precision issues
            
            return False, round(current_tokens, 6)
    
    async def reset_window(self, key: str) -> None:
        """Reset the window for the key."""
        with self._lock:
            if key in self._data:
                del self._data[key]


class RateLimitShield:
    """Rate limiting shield with multiple algorithm support."""
    
    def __init__(
        self,
        requests_per_second: Optional[int] = None,
        requests_per_minute: Optional[int] = None,
        requests_per_hour: Optional[int] = None,
        requests_per_day: Optional[int] = None,
        algorithm: RateLimitAlgorithm = RateLimitAlgorithm.SLIDING_WINDOW,
        backend: Optional[RateLimitBackend] = None,
        key_func: Optional[callable] = None,
        skip_successful_requests: bool = False,
        skip_failed_requests: bool = False,
        max_tokens: Optional[int] = None,
        refill_rate: Optional[float] = None,
    ):
        """Initialize rate limiting shield.
        
        Args:
            requests_per_second: Max requests per second
            requests_per_minute: Max requests per minute  
            requests_per_hour: Max requests per hour
            requests_per_day: Max requests per day
            algorithm: Rate limiting algorithm to use
            backend: Storage backend (defaults to MemoryRateLimitBackend)
            key_func: Function to generate rate limit key from request
            skip_successful_requests: Don't count successful requests
            skip_failed_requests: Don't count failed requests
            max_tokens: Max tokens for token bucket (defaults to requests_per_second)
            refill_rate: Token refill rate per second (defaults to requests_per_second)
        """
        # Validate that at least one limit is specified
        limits = [requests_per_second, requests_per_minute, requests_per_hour, requests_per_day]
        if not any(limit is not None for limit in limits):
            raise ValueError("At least one rate limit must be specified")
        
        self.requests_per_second = requests_per_second
        self.requests_per_minute = requests_per_minute
        self.requests_per_hour = requests_per_hour
        self.requests_per_day = requests_per_day
        self.algorithm = algorithm
        self.backend = backend or MemoryRateLimitBackend()
        self.key_func = key_func or self._default_key_func
        self.skip_successful_requests = skip_successful_requests
        self.skip_failed_requests = skip_failed_requests
        
        # Token bucket specific settings
        if algorithm == RateLimitAlgorithm.TOKEN_BUCKET:
            if requests_per_second is None:
                raise ValueError("Token bucket algorithm requires requests_per_second")
            self.max_tokens = max_tokens or requests_per_second
            self.refill_rate = refill_rate or float(requests_per_second)
        
        # Pre-calculate time windows for efficiency
        self._limits = []
        if requests_per_second:
            self._limits.append((requests_per_second, 1))
        if requests_per_minute:
            self._limits.append((requests_per_minute, 60))
        if requests_per_hour:
            self._limits.append((requests_per_hour, 3600))
        if requests_per_day:
            self._limits.append((requests_per_day, 86400))
    
    def _default_key_func(self, request: Request) -> str:
        """Default key function uses client IP."""
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()
        else:
            client_ip = request.client.host if request.client else "unknown"
        return f"rate_limit:{client_ip}"
    
    async def _check_rate_limit(self, key: str) -> tuple[bool, Optional[int]]:
        """Check if request is within rate limits.
        
        Returns:
            tuple[bool, Optional[int]]: (is_allowed, retry_after_seconds)
        """
        if self.algorithm == RateLimitAlgorithm.TOKEN_BUCKET:
            return await self._check_token_bucket(key)
        
        for limit, window_seconds in self._limits:
            if self.algorithm == RateLimitAlgorithm.SLIDING_WINDOW:
                current_count = await self.backend.get_count(key + f":{window_seconds}", window_seconds)
            else:  # FIXED_WINDOW
                # For fixed window, check current count through backend
                # We'll use a peek functionality that doesn't increment
                current_count = await self._get_fixed_window_count(key + f":{window_seconds}", window_seconds)
            
            if current_count >= limit:
                return False, window_seconds
            
        return True, None
    
    async def _get_fixed_window_count(self, key: str, window_seconds: int) -> int:
        """Get current count for fixed window without incrementing."""
        if isinstance(self.backend, MemoryRateLimitBackend):
            with self.backend._lock:
                if key not in self.backend._data:
                    return 0
                
                current_time = time.time()
                data = self.backend._data[key]
                
                # Check if window has expired
                if current_time - data.get("window_start", 0) >= window_seconds:
                    return 0
                
                return data.get("count", 0)
        else:
            # For custom backends, fall back to increment then decrement
            # This is not ideal but ensures compatibility
            count = await self.backend.increment(key, window_seconds)
            return max(0, count - 1)
    
    async def _check_token_bucket(self, key: str) -> tuple[bool, Optional[int]]:
        """Check token bucket rate limit."""
        success, remaining_tokens = await self.backend.consume_tokens(
            key, 1, self.max_tokens, self.refill_rate
        )
        
        if not success:
            # Calculate retry after based on refill rate
            retry_after = max(1, int((1.0 - remaining_tokens) / self.refill_rate))
            return False, retry_after
        
        return True, None
    
    async def _increment_counters(self, key: str) -> None:
        """Increment rate limit counters."""
        if self.algorithm == RateLimitAlgorithm.TOKEN_BUCKET:
            return  # Already consumed in check
        
        if self.algorithm == RateLimitAlgorithm.SLIDING_WINDOW:
            # For sliding window, add timestamps to the backend
            for limit, window_seconds in self._limits:
                await self._add_timestamp_to_sliding_window(key + f":{window_seconds}")
        else:
            # For fixed window, use the increment method
            for limit, window_seconds in self._limits:
                await self.backend.increment(key + f":{window_seconds}", window_seconds)
    
    async def _add_timestamp_to_sliding_window(self, key: str) -> None:
        """Add a timestamp for sliding window tracking."""
        if isinstance(self.backend, MemoryRateLimitBackend):
            with self.backend._lock:
                current_time = time.time()
                if key not in self.backend._data:
                    self.backend._data[key] = {"timestamps": deque()}
                
                self.backend._data[key]["timestamps"].append(current_time)
    
    def create_shield(self, name: str = "RateLimit") -> Shield:
        """Create a shield instance for rate limiting."""
        
        async def rate_limit_shield(request: Request) -> Optional[Dict[str, Any]]:
            """Rate limiting shield function."""
            key = self.key_func(request)
            
            # Check rate limits
            is_allowed, retry_after = await self._check_rate_limit(key)
            
            if not is_allowed:
                headers = {}
                if retry_after:
                    headers["Retry-After"] = str(retry_after)
                
                # Add rate limit info headers
                headers["X-RateLimit-Limit"] = str(min(limit for limit, _ in self._limits))
                headers["X-RateLimit-Remaining"] = "0"
                headers["X-RateLimit-Reset"] = str(int(time.time() + retry_after) if retry_after else int(time.time() + 60))
                
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Rate limit exceeded",
                    headers=headers
                )
            
            # Increment counters for successful check
            await self._increment_counters(key)
            
            return {"rate_limit_key": key, "algorithm": self.algorithm.value}
        
        return shield(
            rate_limit_shield,
            name=name,
            auto_error=True,
        )


# Convenience functions for common rate limiting scenarios
def rate_limit(
    requests_per_second: Optional[int] = None,
    requests_per_minute: Optional[int] = None,
    requests_per_hour: Optional[int] = None,
    requests_per_day: Optional[int] = None,
    algorithm: RateLimitAlgorithm = RateLimitAlgorithm.SLIDING_WINDOW,
    backend: Optional[RateLimitBackend] = None,
    key_func: Optional[callable] = None,
    name: str = "RateLimit",
) -> Shield:
    """Create a rate limiting shield.
    
    Args:
        requests_per_second: Maximum requests per second
        requests_per_minute: Maximum requests per minute
        requests_per_hour: Maximum requests per hour
        requests_per_day: Maximum requests per day
        algorithm: Rate limiting algorithm
        backend: Storage backend
        key_func: Function to generate rate limit key
        name: Shield name
        
    Returns:
        Shield: Configured rate limiting shield
        
    Examples:
        ```python
        # Basic rate limiting
        @app.get("/api/data")
        @rate_limit(requests_per_minute=100)
        def get_data():
            return {"data": "value"}
        
        # Multiple limits
        @app.get("/api/upload")
        @rate_limit(requests_per_second=5, requests_per_hour=1000)
        def upload_file():
            return {"status": "uploaded"}
        
        # Token bucket algorithm
        @app.get("/api/burst")
        @rate_limit(
            requests_per_second=10,
            algorithm=RateLimitAlgorithm.TOKEN_BUCKET
        )
        def burst_endpoint():
            return {"data": "burst"}
        ```
    """
    rate_limiter = RateLimitShield(
        requests_per_second=requests_per_second,
        requests_per_minute=requests_per_minute,
        requests_per_hour=requests_per_hour,
        requests_per_day=requests_per_day,
        algorithm=algorithm,
        backend=backend,
        key_func=key_func,
    )
    return rate_limiter.create_shield(name=name)


def per_ip_rate_limit(
    requests_per_second: Optional[int] = None,
    requests_per_minute: Optional[int] = None,
    requests_per_hour: Optional[int] = None,
    requests_per_day: Optional[int] = None,
    algorithm: RateLimitAlgorithm = RateLimitAlgorithm.SLIDING_WINDOW,
) -> Shield:
    """Create a per-IP rate limiting shield."""
    return rate_limit(
        requests_per_second=requests_per_second,
        requests_per_minute=requests_per_minute,
        requests_per_hour=requests_per_hour,
        requests_per_day=requests_per_day,
        algorithm=algorithm,
        name="PerIPRateLimit",
    )


def per_user_rate_limit(
    requests_per_second: Optional[int] = None,
    requests_per_minute: Optional[int] = None,
    requests_per_hour: Optional[int] = None,
    requests_per_day: Optional[int] = None,
    algorithm: RateLimitAlgorithm = RateLimitAlgorithm.SLIDING_WINDOW,
    user_key_func: Optional[callable] = None,
) -> Shield:
    """Create a per-user rate limiting shield.
    
    Args:
        requests_per_second: Maximum requests per second per user
        requests_per_minute: Maximum requests per minute per user
        requests_per_hour: Maximum requests per hour per user
        requests_per_day: Maximum requests per day per user
        algorithm: Rate limiting algorithm
        user_key_func: Function to extract user ID from request
        
    Returns:
        Shield: Configured per-user rate limiting shield
    """
    def default_user_key_func(request: Request) -> str:
        """Default user key function - looks for user_id in various places."""
        # Try to get user_id from path params
        if hasattr(request, 'path_params') and 'user_id' in request.path_params:
            return f"rate_limit:user:{request.path_params['user_id']}"
        
        # Try to get from query params
        user_id = request.query_params.get('user_id')
        if user_id:
            return f"rate_limit:user:{user_id}"
        
        # Try to get from headers (common in APIs)
        user_id = request.headers.get('X-User-ID')
        if user_id:
            return f"rate_limit:user:{user_id}"
        
        # Fallback to IP-based limiting
        client_ip = request.client.host if request.client else "unknown"
        return f"rate_limit:user:ip:{client_ip}"
    
    key_func = user_key_func or default_user_key_func
    
    return rate_limit(
        requests_per_second=requests_per_second,
        requests_per_minute=requests_per_minute,
        requests_per_hour=requests_per_hour,
        requests_per_day=requests_per_day,
        algorithm=algorithm,
        key_func=key_func,
        name="PerUserRateLimit",
    )