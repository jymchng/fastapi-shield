"""Mock classes and utilities for request replay shield testing."""

import asyncio
import hashlib
import hmac
import json
import secrets
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Callable, Tuple, Set
from unittest.mock import Mock, AsyncMock
from urllib.parse import urlencode

from fastapi_shield.request_replay import (
    NonceStorage,
    ReplayProtectionResult,
    ReplayDetectionResult,
    ReplayProtectionStrategy,
    NonceFormat,
    TimestampFormat,
)


class MockRequest:
    """Mock FastAPI request for testing."""
    
    def __init__(
        self,
        method: str = "GET",
        path: str = "/test",
        query_params: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
        client_host: str = "127.0.0.1"
    ):
        self.method = method.upper()
        self.headers = headers or {}
        self.body_content = body
        self.client = Mock()
        self.client.host = client_host
        self.state = Mock()
        
        # Mock URL
        self.url = Mock()
        self.url.path = path
        
        # Mock query params with dict-like behavior
        class QueryDict(dict):
            def get(self, key, default=None):
                return super().get(key, default)
        
        self.query_params = QueryDict(query_params or {})
    
    async def body(self) -> bytes:
        """Return request body."""
        if isinstance(self.body_content, str):
            return self.body_content.encode()
        elif isinstance(self.body_content, bytes):
            return self.body_content
        else:
            return b""
    
    def add_header(self, name: str, value: str):
        """Add a header to the request."""
        self.headers[name] = value
    
    def add_query_param(self, name: str, value: str):
        """Add a query parameter to the request."""
        self.query_params[name] = value
    
    def set_body(self, body: str):
        """Set request body."""
        self.body_content = body


class MockNonceStorage(NonceStorage):
    """Mock nonce storage for testing."""
    
    def __init__(self, fail_operations: bool = False, simulate_timeout: bool = False):
        self.nonces: Dict[str, float] = {}  # nonce -> expiry_time
        self.fail_operations = fail_operations
        self.simulate_timeout = simulate_timeout
        self.store_calls = 0
        self.has_calls = 0
        self.remove_calls = 0
        self.cleanup_calls = 0
        self.stats_calls = 0
    
    async def store_nonce(self, nonce: str, ttl_seconds: float = None) -> bool:
        """Store a nonce with optional TTL."""
        self.store_calls += 1
        
        if self.fail_operations:
            return False
        
        if self.simulate_timeout:
            await asyncio.sleep(10)  # Simulate timeout
        
        expiry_time = time.time() + (ttl_seconds or 3600)
        self.nonces[nonce] = expiry_time
        return True
    
    async def has_nonce(self, nonce: str) -> bool:
        """Check if nonce exists."""
        self.has_calls += 1
        
        if self.fail_operations:
            raise Exception("Mock storage error")
        
        if self.simulate_timeout:
            await asyncio.sleep(10)  # Simulate timeout
        
        if nonce not in self.nonces:
            return False
        
        # Check if expired
        current_time = time.time()
        if current_time > self.nonces[nonce]:
            del self.nonces[nonce]
            return False
        
        return True
    
    async def remove_nonce(self, nonce: str) -> bool:
        """Remove a nonce."""
        self.remove_calls += 1
        
        if self.fail_operations:
            return False
        
        if nonce in self.nonces:
            del self.nonces[nonce]
            return True
        return False
    
    async def cleanup_expired(self) -> int:
        """Clean up expired nonces."""
        self.cleanup_calls += 1
        
        if self.fail_operations:
            raise Exception("Mock cleanup error")
        
        current_time = time.time()
        expired = []
        
        for nonce, expiry_time in self.nonces.items():
            if current_time > expiry_time:
                expired.append(nonce)
        
        for nonce in expired:
            del self.nonces[nonce]
        
        return len(expired)
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get storage statistics."""
        self.stats_calls += 1
        
        if self.fail_operations:
            return {'error': 'Mock stats error'}
        
        return {
            'total_nonces': len(self.nonces),
            'storage_type': 'mock',
            'store_calls': self.store_calls,
            'has_calls': self.has_calls,
            'remove_calls': self.remove_calls,
            'cleanup_calls': self.cleanup_calls,
            'stats_calls': self.stats_calls
        }
    
    def set_fail_operations(self, fail: bool):
        """Configure operations to fail."""
        self.fail_operations = fail
    
    def set_simulate_timeout(self, timeout: bool):
        """Configure operations to timeout."""
        self.simulate_timeout = timeout
    
    def get_nonce_count(self) -> int:
        """Get current nonce count."""
        return len(self.nonces)
    
    def add_nonce_directly(self, nonce: str, ttl_seconds: float = 3600):
        """Add nonce directly for testing."""
        self.nonces[nonce] = time.time() + ttl_seconds
    
    def expire_nonce(self, nonce: str):
        """Force expire a nonce for testing."""
        if nonce in self.nonces:
            self.nonces[nonce] = time.time() - 1


class MockRedisStorage:
    """Mock Redis storage for testing Redis functionality."""
    
    def __init__(self, fail_connection: bool = False):
        self.data: Dict[str, Tuple[str, float]] = {}  # key -> (value, expiry)
        self.fail_connection = fail_connection
        self.connected = not fail_connection
        self.ping_calls = 0
        self.setex_calls = 0
        self.exists_calls = 0
        self.delete_calls = 0
        self.keys_calls = 0
        self.info_calls = 0
    
    async def ping(self) -> bool:
        """Mock Redis ping."""
        self.ping_calls += 1
        if self.fail_connection:
            raise Exception("Redis connection failed")
        return True
    
    async def setex(self, key: str, ttl: int, value: str) -> bool:
        """Mock Redis setex."""
        self.setex_calls += 1
        if self.fail_connection:
            raise Exception("Redis connection failed")
        
        expiry = time.time() + ttl
        self.data[key] = (value, expiry)
        return True
    
    async def exists(self, key: str) -> int:
        """Mock Redis exists."""
        self.exists_calls += 1
        if self.fail_connection:
            raise Exception("Redis connection failed")
        
        if key not in self.data:
            return 0
        
        # Check expiry
        _, expiry = self.data[key]
        if time.time() > expiry:
            del self.data[key]
            return 0
        
        return 1
    
    async def delete(self, key: str) -> int:
        """Mock Redis delete."""
        self.delete_calls += 1
        if self.fail_connection:
            raise Exception("Redis connection failed")
        
        if key in self.data:
            del self.data[key]
            return 1
        return 0
    
    async def keys(self, pattern: str) -> List[str]:
        """Mock Redis keys."""
        self.keys_calls += 1
        if self.fail_connection:
            raise Exception("Redis connection failed")
        
        # Simple pattern matching for testing
        prefix = pattern.replace('*', '')
        return [key for key in self.data.keys() if key.startswith(prefix)]
    
    async def info(self, section: str = None) -> Dict[str, Any]:
        """Mock Redis info."""
        self.info_calls += 1
        if self.fail_connection:
            raise Exception("Redis connection failed")
        
        return {
            'used_memory_human': '1.2M',
            'connected_clients': 5
        }
    
    def set_connection_failure(self, fail: bool):
        """Configure connection to fail."""
        self.fail_connection = fail
        self.connected = not fail
    
    def get_data_size(self) -> int:
        """Get current data size."""
        return len(self.data)


class ReplayAttackSimulator:
    """Utility for simulating various replay attack scenarios."""
    
    def __init__(self):
        self.nonce_generator = secrets.token_hex
        self.used_nonces: Set[str] = set()
        self.used_timestamps: List[float] = []
    
    def generate_fresh_nonce(self) -> str:
        """Generate a fresh (unused) nonce."""
        while True:
            nonce = str(uuid.uuid4())
            if nonce not in self.used_nonces:
                self.used_nonces.add(nonce)
                return nonce
    
    def get_replayed_nonce(self) -> Optional[str]:
        """Get a previously used nonce for replay attack."""
        if self.used_nonces:
            return next(iter(self.used_nonces))
        return None
    
    def generate_fresh_timestamp(self) -> float:
        """Generate a fresh timestamp."""
        timestamp = time.time()
        self.used_timestamps.append(timestamp)
        return timestamp
    
    def get_old_timestamp(self, age_seconds: float = 3600) -> float:
        """Get an old timestamp for replay attack."""
        return time.time() - age_seconds
    
    def get_future_timestamp(self, future_seconds: float = 3600) -> float:
        """Get a future timestamp for clock skew testing."""
        return time.time() + future_seconds
    
    def create_valid_request(
        self,
        method: str = "POST",
        path: str = "/api/test",
        body: str = '{"test": "data"}',
        nonce: str = None,
        timestamp: float = None
    ) -> MockRequest:
        """Create a valid request with proper nonce and timestamp."""
        nonce = nonce or self.generate_fresh_nonce()
        timestamp = timestamp or self.generate_fresh_timestamp()
        
        request = MockRequest(
            method=method,
            path=path,
            body=body,
            headers={
                'X-Request-Nonce': nonce,
                'X-Request-Timestamp': str(timestamp),
                'Content-Type': 'application/json'
            }
        )
        
        return request
    
    def create_replay_request(
        self,
        original_request: MockRequest
    ) -> MockRequest:
        """Create a replay of an existing request."""
        return MockRequest(
            method=original_request.method,
            path=original_request.url.path,
            body=original_request.body_content,
            headers=original_request.headers.copy(),
            query_params=dict(original_request.query_params)
        )
    
    def create_request_with_signature(
        self,
        secret_key: str,
        method: str = "POST",
        path: str = "/api/test",
        body: str = '{"test": "data"}',
        nonce: str = None,
        timestamp: float = None,
        query_params: Dict[str, str] = None
    ) -> MockRequest:
        """Create a request with valid signature."""
        nonce = nonce or self.generate_fresh_nonce()
        timestamp = timestamp or self.generate_fresh_timestamp()
        timestamp_str = str(timestamp)
        
        # Calculate signature
        signature = self._generate_signature(
            secret_key, method, path, nonce, timestamp_str, body, query_params
        )
        
        headers = {
            'X-Request-Nonce': nonce,
            'X-Request-Timestamp': timestamp_str,
            'X-Request-Signature': signature,
            'Content-Type': 'application/json'
        }
        
        request = MockRequest(
            method=method,
            path=path,
            body=body,
            headers=headers,
            query_params=query_params or {}
        )
        
        return request
    
    def _generate_signature(
        self,
        secret_key: str,
        method: str,
        path: str,
        nonce: str,
        timestamp: str,
        body: str = "",
        query_params: Dict[str, str] = None
    ) -> str:
        """Generate HMAC signature for request."""
        # Create canonical string
        canonical_parts = [
            method.upper(),
            path,
            nonce,
            timestamp
        ]
        
        # Add sorted query parameters
        if query_params:
            sorted_params = sorted(query_params.items())
            query_string = "&".join(f"{k}={v}" for k, v in sorted_params)
            canonical_parts.append(query_string)
        
        # Add body hash
        if body:
            body_hash = hashlib.sha256(body.encode()).hexdigest()
            canonical_parts.append(body_hash)
        
        canonical_string = "\n".join(canonical_parts)
        
        # Generate HMAC signature
        secret_bytes = secret_key.encode() if isinstance(secret_key, str) else secret_key
        signature = hmac.new(
            secret_bytes,
            canonical_string.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return signature
    
    def tamper_with_signature(self, request: MockRequest) -> MockRequest:
        """Tamper with request signature to simulate attack."""
        if 'X-Request-Signature' in request.headers:
            # Change one character in signature
            original_sig = request.headers['X-Request-Signature']
            tampered_sig = 'X' + original_sig[1:] if original_sig[0] != 'X' else 'Y' + original_sig[1:]
            request.headers['X-Request-Signature'] = tampered_sig
        
        return request
    
    def create_malformed_request(self, malformation_type: str) -> MockRequest:
        """Create malformed requests for testing."""
        base_request = self.create_valid_request()
        
        if malformation_type == "missing_nonce":
            base_request.headers.pop('X-Request-Nonce', None)
        elif malformation_type == "missing_timestamp":
            base_request.headers.pop('X-Request-Timestamp', None)
        elif malformation_type == "invalid_timestamp":
            base_request.headers['X-Request-Timestamp'] = "invalid-timestamp"
        elif malformation_type == "invalid_nonce_format":
            base_request.headers['X-Request-Nonce'] = "invalid-uuid-format"
        elif malformation_type == "empty_nonce":
            base_request.headers['X-Request-Nonce'] = ""
        elif malformation_type == "empty_timestamp":
            base_request.headers['X-Request-Timestamp'] = ""
        
        return base_request


class PerformanceTestHelper:
    """Helper for performance testing replay protection."""
    
    @staticmethod
    async def generate_concurrent_requests(
        count: int,
        simulator: ReplayAttackSimulator,
        duplicate_ratio: float = 0.1
    ) -> List[MockRequest]:
        """Generate concurrent requests with some duplicates."""
        requests = []
        duplicate_count = int(count * duplicate_ratio)
        unique_count = count - duplicate_count
        
        # Generate unique requests
        for i in range(unique_count):
            request = simulator.create_valid_request(
                path=f"/api/test/{i}",
                body=f'{{"test": "data_{i}"}}'
            )
            requests.append(request)
        
        # Generate duplicate requests (reuse nonces from existing requests)
        if requests:
            for i in range(duplicate_count):
                original = requests[i % len(requests)]
                # Create a true duplicate by reusing the exact same nonce and timestamp
                duplicate = MockRequest(
                    method=original.method,
                    path=original.url.path,
                    body=original.body_content,
                    headers=original.headers.copy(),
                    query_params=dict(original.query_params)
                )
                requests.append(duplicate)
        
        return requests
    
    @staticmethod
    async def measure_shield_performance(
        shield,
        requests: List[MockRequest],
        concurrent: bool = True
    ) -> Dict[str, Any]:
        """Measure shield performance."""
        start_time = time.time()
        
        if concurrent:
            # Run requests concurrently
            tasks = [shield._shield_function(req) for req in requests]
            results = await asyncio.gather(*tasks, return_exceptions=True)
        else:
            # Run requests sequentially
            results = []
            for req in requests:
                result = await shield._shield_function(req)
                results.append(result)
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Analyze results
        blocked_count = sum(1 for r in results if r is not None)  # Non-None means blocked
        allowed_count = sum(1 for r in results if r is None)  # None means allowed
        errors_count = sum(1 for r in results if isinstance(r, Exception))
        
        return {
            'total_time_seconds': total_time,
            'requests_per_second': len(requests) / total_time if total_time > 0 else 0,
            'average_time_per_request': total_time / len(requests) if requests else 0,
            'total_requests': len(requests),
            'allowed_requests': allowed_count,
            'blocked_requests': blocked_count,
            'error_requests': errors_count,
            'concurrent': concurrent
        }


class ReplayTestScenarios:
    """Pre-defined test scenarios for replay protection."""
    
    @staticmethod
    def basic_replay_scenario() -> Dict[str, Any]:
        """Basic replay attack scenario."""
        simulator = ReplayAttackSimulator()
        
        # Create original request
        original = simulator.create_valid_request()
        
        # Create replay
        replay = simulator.create_replay_request(original)
        
        return {
            'name': 'basic_replay',
            'original_request': original,
            'replay_request': replay,
            'expected_original': True,
            'expected_replay': False
        }
    
    @staticmethod
    def timestamp_replay_scenario() -> Dict[str, Any]:
        """Timestamp-based replay scenario."""
        simulator = ReplayAttackSimulator()
        
        # Create request with old timestamp
        old_request = simulator.create_valid_request(
            timestamp=simulator.get_old_timestamp(3600)  # 1 hour old
        )
        
        # Create request with future timestamp
        future_request = simulator.create_valid_request(
            timestamp=simulator.get_future_timestamp(3600)  # 1 hour future
        )
        
        # Create valid request
        valid_request = simulator.create_valid_request()
        
        return {
            'name': 'timestamp_replay',
            'old_request': old_request,
            'future_request': future_request,
            'valid_request': valid_request,
            'expected_old': False,
            'expected_future': False,
            'expected_valid': True
        }
    
    @staticmethod
    def signature_tampering_scenario(secret_key: str) -> Dict[str, Any]:
        """Signature tampering scenario."""
        simulator = ReplayAttackSimulator()
        
        # Create valid signed request
        valid_request = simulator.create_request_with_signature(
            secret_key,
            body='{"sensitive": "data"}'
        )
        
        # Create tampered request
        tampered_request = simulator.create_request_with_signature(
            secret_key,
            body='{"sensitive": "data"}'
        )
        simulator.tamper_with_signature(tampered_request)
        
        return {
            'name': 'signature_tampering',
            'valid_request': valid_request,
            'tampered_request': tampered_request,
            'expected_valid': True,
            'expected_tampered': False
        }
    
    @staticmethod
    def malformed_request_scenarios() -> List[Dict[str, Any]]:
        """Various malformed request scenarios."""
        simulator = ReplayAttackSimulator()
        scenarios = []
        
        malformation_types = [
            'missing_nonce',
            'missing_timestamp',
            'invalid_timestamp',
            'invalid_nonce_format',
            'empty_nonce',
            'empty_timestamp'
        ]
        
        for malform_type in malformation_types:
            request = simulator.create_malformed_request(malform_type)
            scenarios.append({
                'name': f'malformed_{malform_type}',
                'request': request,
                'malformation_type': malform_type,
                'expected_allowed': False
            })
        
        return scenarios
    
    @staticmethod
    def distributed_replay_scenario() -> Dict[str, Any]:
        """Distributed replay attack scenario."""
        simulator = ReplayAttackSimulator()
        
        # Create original request
        original = simulator.create_valid_request(
            body='{"distributed": "attack"}'
        )
        
        # Create multiple replays from different "clients"
        replays = []
        for i in range(5):
            replay = simulator.create_replay_request(original)
            replay.client.host = f"192.168.1.{10 + i}"  # Different IPs
            replays.append(replay)
        
        return {
            'name': 'distributed_replay',
            'original_request': original,
            'replay_requests': replays,
            'expected_original': True,
            'expected_replays': [False] * len(replays)
        }


class IntegrationTestHelper:
    """Helper for integration testing scenarios."""
    
    @staticmethod
    def create_fastapi_test_app():
        """Create a FastAPI test application."""
        from fastapi import FastAPI, Request
        from fastapi.responses import JSONResponse
        
        app = FastAPI()
        
        @app.post("/api/secure")
        async def secure_endpoint(request: Request):
            return {"message": "Secure endpoint accessed"}
        
        @app.get("/api/public")
        async def public_endpoint():
            return {"message": "Public endpoint"}
        
        return app
    
    @staticmethod
    async def test_full_request_lifecycle(
        shield,
        request: MockRequest,
        expected_blocked: bool
    ) -> Dict[str, Any]:
        """Test full request lifecycle with shield."""
        start_time = time.time()
        
        # Run through shield
        shield_response = await shield._shield_function(request)
        
        end_time = time.time()
        
        # Analyze result
        was_blocked = shield_response is not None
        
        result = {
            'request_allowed': not was_blocked,
            'expected_blocked': expected_blocked,
            'correct_prediction': was_blocked == expected_blocked,
            'response_time_ms': (end_time - start_time) * 1000,
            'shield_response': shield_response
        }
        
        if shield_response and hasattr(shield_response, 'body'):
            try:
                response_body = json.loads(shield_response.body)
                result['response_body'] = response_body
            except:
                result['response_body'] = None
        
        return result
    
    @staticmethod
    def validate_shield_configuration(shield) -> Dict[str, Any]:
        """Validate shield configuration."""
        config = shield.config
        validation_results = {
            'valid': True,
            'issues': []
        }
        
        # Check required components
        if not config.nonce_storage:
            validation_results['issues'].append('No nonce storage configured')
            validation_results['valid'] = False
        
        if config.strategy in [config.strategy.SIGNATURE_BASED, config.strategy.COMBINED]:
            if not config.signature_secret:
                validation_results['issues'].append('Signature secret required for signature-based protection')
                validation_results['valid'] = False
        
        if config.replay_window_seconds <= 0:
            validation_results['issues'].append('Replay window must be positive')
            validation_results['valid'] = False
        
        if config.clock_skew_tolerance < 0:
            validation_results['issues'].append('Clock skew tolerance must be non-negative')
            validation_results['valid'] = False
        
        return validation_results