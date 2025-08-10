"""Mock classes and utilities for feature flag shield testing."""

import asyncio
import time
from typing import Any, Dict, Optional, Callable, List
from unittest.mock import AsyncMock, Mock

from fastapi_shield.feature_flag import (
    FeatureFlagProvider,
    EvaluationResult,
    FeatureFlagCache
)


class MockFeatureFlagProvider(FeatureFlagProvider):
    """Mock feature flag provider for testing."""
    
    def __init__(
        self,
        default_enabled: bool = True,
        evaluation_delay: float = 0.0,
        should_raise_exception: bool = False,
        health_status: bool = True,
        evaluation_results: Optional[Dict[str, EvaluationResult]] = None
    ):
        self.default_enabled = default_enabled
        self.evaluation_delay = evaluation_delay
        self.should_raise_exception = should_raise_exception
        self.health_status = health_status
        self.evaluation_results = evaluation_results or {}
        
        # Tracking
        self.evaluate_flag_calls = []
        self.get_all_flags_calls = []
        self.health_check_calls = []
    
    async def evaluate_flag(
        self,
        flag_key: str,
        user_context: Dict[str, Any],
        default_value: Any = False
    ) -> EvaluationResult:
        """Mock flag evaluation."""
        self.evaluate_flag_calls.append({
            "flag_key": flag_key,
            "user_context": user_context,
            "default_value": default_value,
            "timestamp": time.time()
        })
        
        if self.evaluation_delay > 0:
            await asyncio.sleep(self.evaluation_delay)
        
        if self.should_raise_exception:
            raise Exception("Mock evaluation exception")
        
        # Return custom result if provided
        if flag_key in self.evaluation_results:
            return self.evaluation_results[flag_key]
        
        # Default behavior
        return EvaluationResult(
            enabled=self.default_enabled,
            variation="mock_variation" if self.default_enabled else "control",
            reason="mock_evaluation",
            evaluation_time_ms=self.evaluation_delay * 1000
        )
    
    async def get_all_flags(self, user_context: Dict[str, Any]) -> Dict[str, EvaluationResult]:
        """Mock get all flags."""
        self.get_all_flags_calls.append({
            "user_context": user_context,
            "timestamp": time.time()
        })
        
        if self.should_raise_exception:
            raise Exception("Mock get all flags exception")
        
        return {
            "test_flag": EvaluationResult(enabled=True, reason="mock"),
            "another_flag": EvaluationResult(enabled=False, reason="mock")
        }
    
    async def health_check(self) -> bool:
        """Mock health check."""
        self.health_check_calls.append(time.time())
        return self.health_status
    
    def set_flag_result(self, flag_key: str, result: EvaluationResult):
        """Set custom result for a flag."""
        self.evaluation_results[flag_key] = result
    
    def set_health_status(self, healthy: bool):
        """Set health status."""
        self.health_status = healthy
    
    def reset_tracking(self):
        """Reset call tracking."""
        self.evaluate_flag_calls = []
        self.get_all_flags_calls = []
        self.health_check_calls = []


class MockLaunchDarklyProvider(MockFeatureFlagProvider):
    """Mock LaunchDarkly provider."""
    
    def __init__(self, sdk_key: str, **kwargs):
        super().__init__(**kwargs)
        self.sdk_key = sdk_key
    
    async def evaluate_flag(
        self,
        flag_key: str,
        user_context: Dict[str, Any],
        default_value: Any = False
    ) -> EvaluationResult:
        """Mock LaunchDarkly evaluation."""
        result = await super().evaluate_flag(flag_key, user_context, default_value)
        result.reason = "launchdarkly_mock"
        return result


class MockSplitProvider(MockFeatureFlagProvider):
    """Mock Split.io provider."""
    
    def __init__(self, api_key: str, **kwargs):
        super().__init__(**kwargs)
        self.api_key = api_key
    
    async def evaluate_flag(
        self,
        flag_key: str,
        user_context: Dict[str, Any],
        default_value: Any = False
    ) -> EvaluationResult:
        """Mock Split.io evaluation."""
        result = await super().evaluate_flag(flag_key, user_context, default_value)
        result.variation = "on" if result.enabled else "off"
        result.reason = "split_mock"
        return result


class MockUnleashProvider(MockFeatureFlagProvider):
    """Mock Unleash provider."""
    
    def __init__(self, api_url: str, client_key: str, app_name: str = "test", **kwargs):
        super().__init__(**kwargs)
        self.api_url = api_url
        self.client_key = client_key
        self.app_name = app_name
    
    async def evaluate_flag(
        self,
        flag_key: str,
        user_context: Dict[str, Any],
        default_value: Any = False
    ) -> EvaluationResult:
        """Mock Unleash evaluation."""
        result = await super().evaluate_flag(flag_key, user_context, default_value)
        result.reason = "unleash_mock"
        return result


class MockCustomProvider(MockFeatureFlagProvider):
    """Mock custom provider that uses callbacks."""
    
    def __init__(
        self,
        evaluation_callback: Optional[Callable] = None,
        flags_callback: Optional[Callable] = None,
        health_callback: Optional[Callable] = None,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.evaluation_callback = evaluation_callback or self._default_evaluation_callback
        self.flags_callback = flags_callback
        self.health_callback = health_callback
    
    def _default_evaluation_callback(
        self,
        flag_key: str,
        user_context: Dict[str, Any],
        default_value: Any = False
    ) -> EvaluationResult:
        """Default evaluation callback."""
        return EvaluationResult(
            enabled=self.default_enabled,
            reason="custom_mock"
        )


class MockCache(FeatureFlagCache):
    """Mock cache for testing."""
    
    def __init__(self, ttl_seconds: int = 300):
        super().__init__(ttl_seconds)
        self.get_calls = []
        self.set_calls = []
        self.clear_calls = []
    
    def get(self, cache_key: str) -> Optional[EvaluationResult]:
        """Mock cache get with tracking."""
        self.get_calls.append({
            "cache_key": cache_key,
            "timestamp": time.time()
        })
        return super().get(cache_key)
    
    def set(self, cache_key: str, result: EvaluationResult) -> None:
        """Mock cache set with tracking."""
        self.set_calls.append({
            "cache_key": cache_key,
            "result": result,
            "timestamp": time.time()
        })
        super().set(cache_key, result)
    
    def clear(self) -> None:
        """Mock cache clear with tracking."""
        self.clear_calls.append(time.time())
        super().clear()
    
    def reset_tracking(self):
        """Reset call tracking."""
        self.get_calls = []
        self.set_calls = []
        self.clear_calls = []


def create_mock_user_context_extractor(user_context: Dict[str, Any]) -> Callable:
    """Create a mock user context extractor that returns predefined context."""
    def extractor(request) -> Dict[str, Any]:
        return user_context.copy()
    return extractor


def create_failing_user_context_extractor() -> Callable:
    """Create a user context extractor that raises an exception."""
    def extractor(request) -> Dict[str, Any]:
        raise Exception("Mock user context extractor failure")
    return extractor


class AsyncContextManager:
    """Helper for creating async context managers in tests."""
    
    def __init__(self, value):
        self.value = value
    
    async def __aenter__(self):
        return self.value
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


def create_mock_http_response(status_code: int, json_data: Dict[str, Any]):
    """Create a mock HTTP response."""
    response = Mock()
    response.status_code = status_code
    response.json.return_value = json_data
    return response


def create_mock_http_client_with_responses(responses: List[Dict[str, Any]]):
    """Create a mock HTTP client that returns predefined responses."""
    client = AsyncMock()
    
    for response_config in responses:
        method = response_config.get("method", "get")
        status_code = response_config.get("status_code", 200)
        json_data = response_config.get("json", {})
        
        mock_response = create_mock_http_response(status_code, json_data)
        
        if method.lower() == "get":
            client.get.return_value = mock_response
        elif method.lower() == "post":
            client.post.return_value = mock_response
    
    return client


class PercentageTestHelper:
    """Helper for testing percentage-based rollouts."""
    
    @staticmethod
    def generate_user_contexts_for_percentage(count: int, base_user_id: str = "user") -> List[Dict[str, Any]]:
        """Generate user contexts that will produce a range of hash percentages."""
        contexts = []
        for i in range(count):
            contexts.append({
                "user_id": f"{base_user_id}_{i}",
                "ip_address": f"192.168.1.{i % 255}",
                "user_agent": f"TestAgent/{i}"
            })
        return contexts
    
    @staticmethod
    def calculate_expected_enabled_count(contexts: List[Dict[str, Any]], flag_key: str, percentage: int) -> int:
        """Calculate expected number of enabled flags for given contexts and percentage."""
        import hashlib
        
        enabled_count = 0
        for context in contexts:
            user_id = context.get("user_id", "anonymous")
            hash_input = f"{flag_key}:{user_id}"
            hash_value = hashlib.md5(hash_input.encode()).hexdigest()
            user_percentage = int(hash_value[:8], 16) % 100
            
            if user_percentage < percentage:
                enabled_count += 1
        
        return enabled_count


class LoadTestHelper:
    """Helper for load testing feature flag shields."""
    
    @staticmethod
    async def concurrent_evaluations(
        shield,
        request_mock,
        concurrent_count: int = 10,
        iterations: int = 5
    ) -> List[Dict[str, Any]]:
        """Perform concurrent evaluations and return results."""
        results = []
        
        for i in range(iterations):
            tasks = []
            for j in range(concurrent_count):
                task = asyncio.create_task(
                    shield._shield_function(request_mock)
                )
                tasks.append(task)
            
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            results.extend([
                {
                    "iteration": i,
                    "task": j,
                    "result": result,
                    "is_exception": isinstance(result, Exception)
                }
                for j, result in enumerate(batch_results)
            ])
        
        return results


class TimingHelper:
    """Helper for testing timing-related functionality."""
    
    @staticmethod
    def fast_forward_time(seconds: int):
        """Mock time.time() to simulate time passing."""
        original_time = time.time()
        
        def mock_time():
            return original_time + seconds
        
        return Mock(side_effect=mock_time)
    
    @staticmethod
    async def wait_for_cache_expiry(cache: FeatureFlagCache, additional_seconds: int = 1):
        """Wait for cache entries to expire."""
        await asyncio.sleep(cache.ttl_seconds + additional_seconds)


class ValidationHelper:
    """Helper for validating test results."""
    
    @staticmethod
    def assert_evaluation_result(
        result: EvaluationResult,
        expected_enabled: bool,
        expected_reason: Optional[str] = None,
        expected_cached: Optional[bool] = None,
        expected_fallback_used: Optional[bool] = None
    ):
        """Assert evaluation result properties."""
        assert result.enabled == expected_enabled
        
        if expected_reason is not None:
            assert result.reason == expected_reason
        
        if expected_cached is not None:
            assert result.cached == expected_cached
        
        if expected_fallback_used is not None:
            assert result.fallback_used == expected_fallback_used
    
    @staticmethod
    def assert_shield_response(
        response_data: Dict[str, Any],
        expected_enabled: bool,
        expected_flag_key: str,
        expected_cached: Optional[bool] = None
    ):
        """Assert shield response data."""
        assert "feature_flag" in response_data
        flag_data = response_data["feature_flag"]
        
        assert flag_data["key"] == expected_flag_key
        assert flag_data["enabled"] == expected_enabled
        
        if expected_cached is not None:
            assert flag_data["cached"] == expected_cached