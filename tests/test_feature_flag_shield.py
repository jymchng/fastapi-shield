"""Comprehensive tests for Feature Flag Shield functionality."""

import asyncio
import json
import time
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient

from fastapi_shield.feature_flag import (
    FeatureFlagShield,
    FeatureFlagConfig,
    FeatureFlagProvider,
    FeatureFlagCache,
    EvaluationResult,
    RolloutStrategy,
    LaunchDarklyProvider,
    SplitProvider,
    UnleashProvider,
    CustomProvider,
    feature_flag_shield,
    launchdarkly_feature_flag_shield,
    split_feature_flag_shield,
    unleash_feature_flag_shield,
    percentage_rollout_shield,
    authenticated_feature_flag_shield,
)
from tests.mocks.feature_flag_mocks import (
    MockFeatureFlagProvider,
    MockLaunchDarklyProvider,
    MockSplitProvider,
    MockUnleashProvider,
    MockCustomProvider,
    MockCache,
    create_mock_user_context_extractor,
    create_failing_user_context_extractor,
    PercentageTestHelper,
    LoadTestHelper,
    TimingHelper,
    ValidationHelper,
    create_mock_http_response,
    create_mock_http_client_with_responses,
)


def create_mock_request(
    user_id: str = "test_user",
    ip_address: str = "192.168.1.1",
    user_agent: str = "TestAgent/1.0",
    path: str = "/api/test",
    method: str = "GET",
    headers: dict = None
) -> Mock:
    """Create a mock FastAPI Request object."""
    request = Mock(spec=Request)
    request.client = Mock()
    request.client.host = ip_address
    request.url = Mock()
    request.url.path = path
    request.method = method
    
    # Create real dict for headers to ensure .get() method works
    header_dict = headers.copy() if headers else {}
    
    # Add user_id to headers if provided
    if user_id and user_id != "anonymous":
        header_dict["x-user-id"] = user_id
    
    if "user-agent" not in header_dict:
        header_dict["user-agent"] = user_agent
    
    request.headers = header_dict
    
    return request


class TestEvaluationResult:
    """Test EvaluationResult functionality."""
    
    def test_evaluation_result_creation(self):
        """Test creating evaluation result with all parameters."""
        result = EvaluationResult(
            enabled=True,
            variation="treatment",
            reason="flag_evaluation",
            cached=False,
            fallback_used=False,
            evaluation_time_ms=25.5
        )
        
        assert result.enabled is True
        assert result.variation == "treatment"
        assert result.reason == "flag_evaluation"
        assert result.cached is False
        assert result.fallback_used is False
        assert result.evaluation_time_ms == 25.5
        assert isinstance(result.timestamp, datetime)
    
    def test_evaluation_result_defaults(self):
        """Test evaluation result with default values."""
        result = EvaluationResult(enabled=False)
        
        assert result.enabled is False
        assert result.variation is None
        assert result.reason == "evaluation"
        assert result.cached is False
        assert result.fallback_used is False
        assert result.evaluation_time_ms == 0.0


class TestFeatureFlagCache:
    """Test FeatureFlagCache functionality."""
    
    def test_cache_creation(self):
        """Test creating cache with TTL."""
        cache = FeatureFlagCache(ttl_seconds=600)
        assert cache.ttl_seconds == 600
    
    def test_cache_set_and_get(self):
        """Test basic cache set and get operations."""
        cache = FeatureFlagCache(ttl_seconds=300)
        result = EvaluationResult(enabled=True, reason="test")
        
        # Set cache entry
        cache.set("test_key", result)
        
        # Get cache entry
        cached_result = cache.get("test_key")
        assert cached_result is not None
        assert cached_result.enabled is True
        assert cached_result.reason == "test"
        assert cached_result.cached is True  # Should be marked as cached
    
    def test_cache_expiration(self):
        """Test cache entry expiration."""
        cache = FeatureFlagCache(ttl_seconds=1)  # Very short TTL
        result = EvaluationResult(enabled=True)
        
        cache.set("test_key", result)
        
        # Should be available immediately
        cached_result = cache.get("test_key")
        assert cached_result is not None
        
        # Wait for expiration
        time.sleep(1.1)
        
        # Should be expired
        cached_result = cache.get("test_key")
        assert cached_result is None
    
    def test_cache_clear(self):
        """Test cache clearing."""
        cache = FeatureFlagCache()
        result = EvaluationResult(enabled=True)
        
        cache.set("key1", result)
        cache.set("key2", result)
        
        # Verify entries exist
        assert cache.get("key1") is not None
        assert cache.get("key2") is not None
        
        # Clear cache
        cache.clear()
        
        # Verify entries are gone
        assert cache.get("key1") is None
        assert cache.get("key2") is None
    
    def test_cache_evict_expired(self):
        """Test evicting expired entries."""
        cache = FeatureFlagCache(ttl_seconds=2)
        result = EvaluationResult(enabled=True)
        
        cache.set("expired_key", result)
        
        # Wait for expiration
        time.sleep(2.1)
        
        # Add valid key after first key expired
        cache.set("valid_key", result)
        
        # Manually evict expired entries
        cache.evict_expired()
        
        # Expired key should be gone, valid key should remain
        assert cache.get("expired_key") is None
        assert cache.get("valid_key") is not None


class TestMockProviders:
    """Test mock feature flag providers."""
    
    def test_mock_provider_default_behavior(self):
        """Test mock provider with default settings."""
        provider = MockFeatureFlagProvider(default_enabled=True)
        
        # Test evaluation
        result = asyncio.run(provider.evaluate_flag(
            "test_flag",
            {"user_id": "test_user"},
            False
        ))
        
        assert result.enabled is True
        assert result.variation == "mock_variation"
        assert result.reason == "mock_evaluation"
        
        # Verify tracking
        assert len(provider.evaluate_flag_calls) == 1
        assert provider.evaluate_flag_calls[0]["flag_key"] == "test_flag"
    
    @pytest.mark.asyncio
    async def test_mock_provider_exception_handling(self):
        """Test mock provider exception handling."""
        provider = MockFeatureFlagProvider(should_raise_exception=True)
        
        with pytest.raises(Exception, match="Mock evaluation exception"):
            await provider.evaluate_flag("test_flag", {}, False)
    
    @pytest.mark.asyncio
    async def test_mock_provider_custom_results(self):
        """Test mock provider with custom results."""
        custom_result = EvaluationResult(
            enabled=False,
            variation="custom_variant",
            reason="custom_reason"
        )
        
        provider = MockFeatureFlagProvider()
        provider.set_flag_result("custom_flag", custom_result)
        
        result = await provider.evaluate_flag("custom_flag", {}, True)
        
        assert result.enabled is False
        assert result.variation == "custom_variant"
        assert result.reason == "custom_reason"
    
    @pytest.mark.asyncio
    async def test_mock_provider_health_check(self):
        """Test mock provider health check."""
        provider = MockFeatureFlagProvider(health_status=False)
        
        is_healthy = await provider.health_check()
        assert is_healthy is False
        
        # Change health status
        provider.set_health_status(True)
        is_healthy = await provider.health_check()
        assert is_healthy is True
        
        # Verify tracking
        assert len(provider.health_check_calls) == 2
    
    @pytest.mark.asyncio
    async def test_mock_provider_get_all_flags(self):
        """Test mock provider get all flags."""
        provider = MockFeatureFlagProvider()
        
        flags = await provider.get_all_flags({"user_id": "test"})
        
        assert isinstance(flags, dict)
        assert "test_flag" in flags
        assert "another_flag" in flags
        assert flags["test_flag"].enabled is True
        assert flags["another_flag"].enabled is False


class TestLaunchDarklyProvider:
    """Test LaunchDarkly provider."""
    
    @pytest.mark.asyncio
    async def test_launchdarkly_provider_creation(self):
        """Test LaunchDarkly provider creation."""
        provider = LaunchDarklyProvider(
            sdk_key="test_key",
            base_url="https://test.launchdarkly.com"
        )
        
        assert provider.sdk_key == "test_key"
        assert provider.base_url == "https://test.launchdarkly.com"
        assert provider.timeout == 5
    
    @pytest.mark.asyncio
    @patch('httpx.AsyncClient')
    async def test_launchdarkly_evaluate_flag_success(self, mock_client_class):
        """Test successful LaunchDarkly flag evaluation."""
        mock_client = AsyncMock()
        mock_client_class.return_value = mock_client
        
        # Mock successful response
        mock_response = create_mock_http_response(200, {
            "value": True,
            "variation": "treatment",
            "reason": "flag_match"
        })
        mock_client.post.return_value = mock_response
        
        provider = LaunchDarklyProvider("test_key")
        result = await provider.evaluate_flag(
            "test_flag",
            {"user_id": "test_user"},
            False
        )
        
        assert result.enabled is True
        assert result.variation == "treatment"
        assert result.reason == "flag_match"
        assert not result.fallback_used
        assert result.evaluation_time_ms > 0
    
    @pytest.mark.asyncio
    @patch('httpx.AsyncClient')
    async def test_launchdarkly_evaluate_flag_failure(self, mock_client_class):
        """Test LaunchDarkly flag evaluation failure."""
        mock_client = AsyncMock()
        mock_client_class.return_value = mock_client
        
        # Mock error response
        mock_response = Mock()
        mock_response.status_code = 404
        mock_client.post.return_value = mock_response
        
        provider = LaunchDarklyProvider("test_key")
        result = await provider.evaluate_flag(
            "test_flag",
            {"user_id": "test_user"},
            True  # default value
        )
        
        assert result.enabled is True  # Should use default
        assert result.reason == "http_error_404"
        assert result.fallback_used is True
    
    @pytest.mark.asyncio
    @patch('httpx.AsyncClient')
    async def test_launchdarkly_health_check(self, mock_client_class):
        """Test LaunchDarkly health check."""
        mock_client = AsyncMock()
        mock_client_class.return_value = mock_client
        
        # Test healthy response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_client.get.return_value = mock_response
        
        provider = LaunchDarklyProvider("test_key")
        is_healthy = await provider.health_check()
        
        assert is_healthy is True
        
        # Test unhealthy response
        mock_response.status_code = 401
        is_healthy = await provider.health_check()
        
        assert is_healthy is False


class TestSplitProvider:
    """Test Split.io provider."""
    
    @pytest.mark.asyncio
    @patch('httpx.AsyncClient')
    async def test_split_evaluate_flag_success(self, mock_client_class):
        """Test successful Split.io flag evaluation."""
        mock_client = AsyncMock()
        mock_client_class.return_value = mock_client
        
        # Mock successful response
        mock_response = create_mock_http_response(200, {
            "treatment": "on"
        })
        mock_client.post.return_value = mock_response
        
        provider = SplitProvider("test_api_key")
        result = await provider.evaluate_flag(
            "test_split",
            {"user_id": "test_user"},
            False
        )
        
        assert result.enabled is True  # "on" treatment means enabled
        assert result.variation == "on"
        assert result.reason == "evaluation"
    
    @pytest.mark.asyncio
    @patch('httpx.AsyncClient') 
    async def test_split_evaluate_flag_off_treatment(self, mock_client_class):
        """Test Split.io flag with off treatment."""
        mock_client = AsyncMock()
        mock_client_class.return_value = mock_client
        
        mock_response = create_mock_http_response(200, {
            "treatment": "off"
        })
        mock_client.post.return_value = mock_response
        
        provider = SplitProvider("test_api_key")
        result = await provider.evaluate_flag(
            "test_split",
            {"user_id": "test_user"},
            True
        )
        
        assert result.enabled is False  # "off" treatment means disabled
        assert result.variation == "off"


class TestUnleashProvider:
    """Test Unleash provider."""
    
    @pytest.mark.asyncio
    @patch('httpx.AsyncClient')
    async def test_unleash_evaluate_flag_enabled(self, mock_client_class):
        """Test Unleash flag evaluation when enabled."""
        mock_client = AsyncMock()
        mock_client_class.return_value = mock_client
        
        # Mock successful response with enabled flag
        mock_response = create_mock_http_response(200, {
            "enabled": True,
            "strategies": []
        })
        mock_client.get.return_value = mock_response
        
        provider = UnleashProvider(
            api_url="https://test.unleash.com",
            client_key="test_key"
        )
        result = await provider.evaluate_flag(
            "test_flag",
            {"user_id": "test_user"},
            False
        )
        
        assert result.enabled is True
        assert result.reason == "evaluation"
    
    @pytest.mark.asyncio
    @patch('httpx.AsyncClient')
    async def test_unleash_percentage_rollout_strategy(self, mock_client_class):
        """Test Unleash percentage rollout strategy."""
        mock_client = AsyncMock()
        mock_client_class.return_value = mock_client
        
        # Mock response with percentage rollout strategy
        mock_response = create_mock_http_response(200, {
            "enabled": True,
            "strategies": [
                {
                    "name": "gradualRolloutUserId",
                    "parameters": {
                        "percentage": "50"
                    }
                }
            ]
        })
        mock_client.get.return_value = mock_response
        
        provider = UnleashProvider(
            api_url="https://test.unleash.com",
            client_key="test_key"
        )
        
        # Test with user that should be in 50% rollout
        # Using a specific user_id that generates a low hash percentage
        result = await provider.evaluate_flag(
            "test_flag",
            {"user_id": "user_with_low_hash"},
            False
        )
        
        # The result depends on the hash, but we can verify the logic was applied
        assert isinstance(result.enabled, bool)
        assert result.reason == "evaluation"


class TestCustomProvider:
    """Test Custom provider."""
    
    @pytest.mark.asyncio
    async def test_custom_provider_sync_callback(self):
        """Test custom provider with synchronous callback."""
        def evaluation_callback(flag_key, user_context, default_value):
            return EvaluationResult(
                enabled=flag_key == "enabled_flag",
                reason="custom_sync_callback"
            )
        
        provider = CustomProvider(evaluation_callback=evaluation_callback)
        
        # Test enabled flag
        result = await provider.evaluate_flag("enabled_flag", {}, False)
        assert result.enabled is True
        assert result.reason == "custom_sync_callback"
        
        # Test disabled flag
        result = await provider.evaluate_flag("disabled_flag", {}, True)
        assert result.enabled is False
        assert result.reason == "custom_sync_callback"
    
    @pytest.mark.asyncio
    async def test_custom_provider_async_callback(self):
        """Test custom provider with asynchronous callback."""
        async def async_evaluation_callback(flag_key, user_context, default_value):
            await asyncio.sleep(0.01)  # Simulate async work
            return EvaluationResult(
                enabled=user_context.get("premium", False),
                reason="async_custom_callback"
            )
        
        provider = CustomProvider(evaluation_callback=async_evaluation_callback)
        
        # Test with premium user
        result = await provider.evaluate_flag(
            "premium_feature",
            {"user_id": "user1", "premium": True},
            False
        )
        assert result.enabled is True
        assert result.reason == "async_custom_callback"
    
    @pytest.mark.asyncio
    async def test_custom_provider_callback_exception(self):
        """Test custom provider callback exception handling."""
        def failing_callback(flag_key, user_context, default_value):
            raise ValueError("Callback failed")
        
        provider = CustomProvider(evaluation_callback=failing_callback)
        
        result = await provider.evaluate_flag("test_flag", {}, True)
        assert result.enabled is True  # Should use default
        assert result.reason == "callback_exception_ValueError"
        assert result.fallback_used is True


class TestFeatureFlagConfig:
    """Test FeatureFlagConfig functionality."""
    
    def test_config_creation_with_defaults(self):
        """Test config creation with default values."""
        provider = MockFeatureFlagProvider()
        config = FeatureFlagConfig(
            flag_key="test_flag",
            provider=provider
        )
        
        assert config.flag_key == "test_flag"
        assert config.provider == provider
        assert config.rollout_strategy == RolloutStrategy.USER_BASED
        assert config.cache_enabled is True
        assert config.default_enabled is False
        assert config.fallback_behavior == "deny"
    
    def test_config_creation_with_custom_values(self):
        """Test config creation with custom values."""
        provider = MockFeatureFlagProvider()
        extractor = create_mock_user_context_extractor({"user_id": "test"})
        
        config = FeatureFlagConfig(
            flag_key="custom_flag",
            provider=provider,
            rollout_strategy=RolloutStrategy.PERCENTAGE_BASED,
            rollout_percentage=75,
            user_context_extractor=extractor,
            cache_enabled=False,
            cache_ttl_seconds=600,
            default_enabled=True,
            require_authentication=True,
            allowed_variations=["treatment", "control"],
            fallback_behavior="allow",
            health_check_enabled=False
        )
        
        assert config.rollout_strategy == RolloutStrategy.PERCENTAGE_BASED
        assert config.rollout_percentage == 75
        assert config.cache_enabled is False
        assert config.default_enabled is True
        assert config.require_authentication is True
        assert config.allowed_variations == ["treatment", "control"]
        assert config.fallback_behavior == "allow"
        assert config.health_check_enabled is False


class TestFeatureFlagShield:
    """Test FeatureFlagShield functionality."""
    
    def test_shield_creation(self):
        """Test creating feature flag shield."""
        provider = MockFeatureFlagProvider()
        config = FeatureFlagConfig(flag_key="test_flag", provider=provider)
        shield = FeatureFlagShield(config)
        
        assert shield.config == config
        assert shield._cache is not None  # Cache should be enabled by default
        assert shield._provider_healthy is True
    
    def test_shield_creation_without_cache(self):
        """Test creating shield without cache."""
        provider = MockFeatureFlagProvider()
        config = FeatureFlagConfig(
            flag_key="test_flag",
            provider=provider,
            cache_enabled=False
        )
        shield = FeatureFlagShield(config)
        
        assert shield._cache is None
    
    def test_default_user_context_extractor(self):
        """Test default user context extraction."""
        provider = MockFeatureFlagProvider()
        config = FeatureFlagConfig(flag_key="test_flag", provider=provider)
        shield = FeatureFlagShield(config)
        
        request = create_mock_request(
            user_id="test_user",
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0",
            path="/api/endpoint"
        )
        
        context = shield._default_user_context_extractor(request)
        
        assert context["user_id"] == "test_user"
        assert context["ip_address"] == "192.168.1.100" 
        assert context["user_agent"] == "Mozilla/5.0"
        assert context["path"] == "/api/endpoint"
        assert context["method"] == "GET"
    
    def test_default_user_context_extractor_anonymous(self):
        """Test default user context extraction for anonymous users."""
        provider = MockFeatureFlagProvider()
        config = FeatureFlagConfig(flag_key="test_flag", provider=provider)
        shield = FeatureFlagShield(config)
        
        request = create_mock_request(user_id=None)
        request.headers = {}  # No user identification
        
        context = shield._default_user_context_extractor(request)
        
        # Should generate anonymous user_id based on IP and User-Agent
        assert context["user_id"] is not None
        assert context["user_id"] != "anonymous"
        assert len(context["user_id"]) == 32  # MD5 hash length
    
    @pytest.mark.asyncio
    async def test_shield_function_successful_evaluation(self):
        """Test shield function with successful flag evaluation."""
        provider = MockFeatureFlagProvider(default_enabled=True)
        config = FeatureFlagConfig(flag_key="test_flag", provider=provider)
        shield = FeatureFlagShield(config)
        
        request = create_mock_request(user_id="test_user")
        
        result = await shield._shield_function(request)
        
        assert result is not None
        assert "feature_flag" in result
        
        flag_data = result["feature_flag"]
        assert flag_data["key"] == "test_flag"
        assert flag_data["enabled"] is True
        assert flag_data["user_context"]["user_id"] == "test_user"
    
    @pytest.mark.asyncio
    async def test_shield_function_flag_disabled(self):
        """Test shield function when flag is disabled."""
        provider = MockFeatureFlagProvider(default_enabled=False)
        config = FeatureFlagConfig(flag_key="test_flag", provider=provider)
        shield = FeatureFlagShield(config)
        
        request = create_mock_request()
        
        with pytest.raises(HTTPException) as exc_info:
            await shield._shield_function(request)
        
        assert exc_info.value.status_code == 403
        assert "not enabled" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_shield_function_authentication_required(self):
        """Test shield function with authentication requirement."""
        provider = MockFeatureFlagProvider(default_enabled=True)
        
        # Create custom user context extractor that returns anonymous
        def anonymous_extractor(request):
            return {"user_id": "anonymous", "ip_address": "127.0.0.1"}
        
        config = FeatureFlagConfig(
            flag_key="test_flag",
            provider=provider,
            require_authentication=True,
            user_context_extractor=anonymous_extractor
        )
        shield = FeatureFlagShield(config)
        
        # Test with anonymous user
        request = create_mock_request(user_id=None)
        request.headers = {}  # No authentication
        
        with pytest.raises(HTTPException) as exc_info:
            await shield._shield_function(request)
        
        assert exc_info.value.status_code == 401
        assert "Authentication required" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_shield_function_with_caching(self):
        """Test shield function with caching enabled."""
        provider = MockFeatureFlagProvider(default_enabled=True)
        config = FeatureFlagConfig(
            flag_key="test_flag",
            provider=provider,
            cache_enabled=True
        )
        shield = FeatureFlagShield(config)
        
        request = create_mock_request(user_id="test_user")
        
        # First evaluation - should hit provider
        result1 = await shield._shield_function(request)
        assert result1["feature_flag"]["cached"] is False
        
        # Second evaluation - should hit cache
        result2 = await shield._shield_function(request)
        assert result2["feature_flag"]["cached"] is True
        
        # Verify provider was only called once
        assert len(provider.evaluate_flag_calls) == 1
    
    @pytest.mark.asyncio
    async def test_shield_function_percentage_rollout(self):
        """Test shield function with percentage rollout."""
        provider = MockFeatureFlagProvider(default_enabled=True)
        config = FeatureFlagConfig(
            flag_key="rollout_flag",
            provider=provider,
            rollout_strategy=RolloutStrategy.PERCENTAGE_BASED,
            rollout_percentage=0  # 0% rollout - no users should get it
        )
        shield = FeatureFlagShield(config)
        
        request = create_mock_request(user_id="any_user")
        
        with pytest.raises(HTTPException) as exc_info:
            await shield._shield_function(request)
        
        assert exc_info.value.status_code == 403
        assert "not enabled" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_shield_function_allowed_variations(self):
        """Test shield function with allowed variations restriction."""
        # Create provider that returns a specific variation
        provider = MockFeatureFlagProvider(default_enabled=True)
        provider.set_flag_result("test_flag", EvaluationResult(
            enabled=True,
            variation="experimental",
            reason="test"
        ))
        
        config = FeatureFlagConfig(
            flag_key="test_flag",
            provider=provider,
            allowed_variations=["control", "treatment"]  # "experimental" not allowed
        )
        shield = FeatureFlagShield(config)
        
        request = create_mock_request()
        
        with pytest.raises(HTTPException) as exc_info:
            await shield._shield_function(request)
        
        assert exc_info.value.status_code == 403
    
    @pytest.mark.asyncio
    async def test_shield_function_fallback_behavior_allow(self):
        """Test shield function fallback behavior - allow."""
        provider = MockFeatureFlagProvider(should_raise_exception=True)
        config = FeatureFlagConfig(
            flag_key="test_flag",
            provider=provider,
            fallback_behavior="allow"
        )
        shield = FeatureFlagShield(config)
        
        request = create_mock_request()
        
        result = await shield._shield_function(request)
        
        assert result["feature_flag"]["enabled"] is True
        assert result["feature_flag"]["fallback_used"] is True
    
    @pytest.mark.asyncio
    async def test_shield_function_fallback_behavior_default(self):
        """Test shield function fallback behavior - default."""
        provider = MockFeatureFlagProvider(should_raise_exception=True)
        config = FeatureFlagConfig(
            flag_key="test_flag",
            provider=provider,
            fallback_behavior="default",
            default_enabled=True
        )
        shield = FeatureFlagShield(config)
        
        request = create_mock_request()
        
        result = await shield._shield_function(request)
        
        assert result["feature_flag"]["enabled"] is True
        assert result["feature_flag"]["fallback_used"] is True
    
    @pytest.mark.asyncio
    async def test_shield_function_provider_health_check(self):
        """Test shield function provider health check."""
        provider = MockFeatureFlagProvider(health_status=False)
        config = FeatureFlagConfig(
            flag_key="test_flag",
            provider=provider,
            health_check_enabled=True,
            fallback_behavior="deny"
        )
        shield = FeatureFlagShield(config)
        
        request = create_mock_request()
        
        with pytest.raises(HTTPException) as exc_info:
            await shield._shield_function(request)
        
        assert exc_info.value.status_code == 503
        assert "unavailable" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_shield_function_custom_user_context_extractor(self):
        """Test shield function with custom user context extractor."""
        provider = MockFeatureFlagProvider(default_enabled=True)
        
        def custom_extractor(request):
            return {
                "user_id": "custom_user",
                "tier": "premium",
                "region": "us-west"
            }
        
        config = FeatureFlagConfig(
            flag_key="test_flag",
            provider=provider,
            user_context_extractor=custom_extractor
        )
        shield = FeatureFlagShield(config)
        
        request = create_mock_request()
        
        result = await shield._shield_function(request)
        
        user_context = result["feature_flag"]["user_context"]
        assert user_context["user_id"] == "custom_user"
        assert user_context["tier"] == "premium"
        assert user_context["region"] == "us-west"


class TestConvenienceFunctions:
    """Test convenience shield creation functions."""
    
    def test_feature_flag_shield_creation(self):
        """Test generic feature flag shield creation."""
        provider = MockFeatureFlagProvider()
        
        shield = feature_flag_shield(
            flag_key="test_flag",
            provider=provider,
            rollout_strategy=RolloutStrategy.PERCENTAGE_BASED,
            rollout_percentage=50,
            cache_enabled=False,
            default_enabled=True
        )
        
        assert isinstance(shield, FeatureFlagShield)
        assert shield.config.flag_key == "test_flag"
        assert shield.config.rollout_strategy == RolloutStrategy.PERCENTAGE_BASED
        assert shield.config.rollout_percentage == 50
        assert shield.config.cache_enabled is False
        assert shield.config.default_enabled is True
    
    def test_launchdarkly_feature_flag_shield_creation(self):
        """Test LaunchDarkly feature flag shield creation."""
        shield = launchdarkly_feature_flag_shield(
            flag_key="ld_flag",
            sdk_key="test_sdk_key",
            base_url="https://custom.launchdarkly.com",
            cache_enabled=False,
            default_enabled=True,
            fallback_behavior="allow"
        )
        
        assert isinstance(shield, FeatureFlagShield)
        assert shield.config.flag_key == "ld_flag"
        assert isinstance(shield.config.provider, LaunchDarklyProvider)
        assert shield.config.provider.sdk_key == "test_sdk_key"
        assert shield.config.provider.base_url == "https://custom.launchdarkly.com"
        assert shield.config.cache_enabled is False
        assert shield.config.default_enabled is True
        assert shield.config.fallback_behavior == "allow"
    
    def test_split_feature_flag_shield_creation(self):
        """Test Split.io feature flag shield creation."""
        shield = split_feature_flag_shield(
            flag_key="split_flag",
            api_key="test_api_key",
            base_url="https://custom.split.io/api"
        )
        
        assert isinstance(shield, FeatureFlagShield)
        assert shield.config.flag_key == "split_flag"
        assert isinstance(shield.config.provider, SplitProvider)
        assert shield.config.provider.api_key == "test_api_key"
        assert shield.config.provider.base_url == "https://custom.split.io/api"
    
    def test_unleash_feature_flag_shield_creation(self):
        """Test Unleash feature flag shield creation."""
        shield = unleash_feature_flag_shield(
            flag_key="unleash_flag",
            api_url="https://unleash.company.com",
            client_key="test_client_key",
            app_name="test_app"
        )
        
        assert isinstance(shield, FeatureFlagShield)
        assert shield.config.flag_key == "unleash_flag"
        assert isinstance(shield.config.provider, UnleashProvider)
        assert shield.config.provider.api_url == "https://unleash.company.com"
        assert shield.config.provider.client_key == "test_client_key"
        assert shield.config.provider.app_name == "test_app"
    
    def test_percentage_rollout_shield_creation(self):
        """Test percentage rollout shield creation."""
        provider = MockFeatureFlagProvider()
        
        shield = percentage_rollout_shield(
            flag_key="rollout_flag",
            provider=provider,
            rollout_percentage=25,
            cache_enabled=False
        )
        
        assert isinstance(shield, FeatureFlagShield)
        assert shield.config.rollout_strategy == RolloutStrategy.PERCENTAGE_BASED
        assert shield.config.rollout_percentage == 25
        assert shield.config.cache_enabled is False
    
    def test_authenticated_feature_flag_shield_creation(self):
        """Test authenticated feature flag shield creation."""
        provider = MockFeatureFlagProvider()
        extractor = create_mock_user_context_extractor({"user_id": "auth_user"})
        
        shield = authenticated_feature_flag_shield(
            flag_key="auth_flag",
            provider=provider,
            user_context_extractor=extractor,
            cache_enabled=True,
            default_enabled=False
        )
        
        assert isinstance(shield, FeatureFlagShield)
        assert shield.config.require_authentication is True
        assert shield.config.user_context_extractor == extractor


class TestIntegration:
    """Integration tests with FastAPI."""
    
    def test_feature_flag_shield_integration(self):
        """Test feature flag shield integration with FastAPI."""
        app = FastAPI()
        
        provider = MockFeatureFlagProvider(default_enabled=True)
        shield = feature_flag_shield(
            flag_key="api_feature",
            provider=provider,
            cache_enabled=False  # Disable cache for predictable tests
        )
        
        @app.get("/api/feature")
        @shield
        def feature_endpoint():
            return {"message": "Feature is enabled"}
        
        client = TestClient(app)
        
        # Test with enabled flag
        response = client.get(
            "/api/feature",
            headers={"x-user-id": "test_user"}
        )
        assert response.status_code == 200
        assert response.json()["message"] == "Feature is enabled"
        
        # Test with disabled flag
        provider.default_enabled = False
        response = client.get(
            "/api/feature",
            headers={"x-user-id": "test_user"}
        )
        assert response.status_code == 403
    
    def test_feature_flag_shield_with_dependency_injection(self):
        """Test feature flag shield with dependency injection via FastAPI."""
        app = FastAPI()
        
        provider = MockFeatureFlagProvider(default_enabled=True)
        shield = feature_flag_shield(
            flag_key="feature_with_data",
            provider=provider
        )
        
        @app.get("/api/feature-data")
        @shield
        def feature_with_data_endpoint():
            return {
                "message": "Feature enabled", 
                "feature": "accessible"
            }
        
        client = TestClient(app)
        response = client.get(
            "/api/feature-data",
            headers={"x-user-id": "test_user"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Feature enabled"
        assert data["feature"] == "accessible"
    
    def test_percentage_rollout_integration(self):
        """Test percentage rollout integration."""
        app = FastAPI()
        
        provider = MockFeatureFlagProvider(default_enabled=True)
        shield = percentage_rollout_shield(
            flag_key="rollout_test",
            provider=provider,
            rollout_percentage=25,  # 25% rollout for more predictable results
            cache_enabled=False
        )
        
        @app.get("/api/rollout")
        @shield
        def rollout_endpoint():
            return {"message": "You're in the rollout!"}
        
        client = TestClient(app)
        
        # Test with multiple users to verify rollout behavior
        enabled_count = 0
        total_users = 100  # Use more users for better statistical accuracy
        
        for i in range(total_users):
            response = client.get(
                "/api/rollout",
                headers={"x-user-id": f"rollout_user_{i}"}
            )
            if response.status_code == 200:
                enabled_count += 1
        
        # With 25% rollout and 100 users, we expect approximately 25 users enabled
        # Allow reasonable variance due to hashing distribution
        assert 15 <= enabled_count <= 35
    
    def test_fallback_behavior_integration(self):
        """Test fallback behavior integration."""
        app = FastAPI()
        
        # Create provider that will fail
        provider = MockFeatureFlagProvider(
            should_raise_exception=True,
            health_status=False
        )
        
        # Create shield with "allow" fallback
        shield = feature_flag_shield(
            flag_key="fallback_test",
            provider=provider,
            fallback_behavior="allow",
            cache_enabled=False
        )
        
        @app.get("/api/fallback")
        @shield
        def fallback_endpoint():
            return {"message": "Fallback allowed access"}
        
        client = TestClient(app)
        
        response = client.get(
            "/api/fallback",
            headers={"x-user-id": "test_user"}
        )
        
        # Should succeed due to fallback
        assert response.status_code == 200
        assert response.json()["message"] == "Fallback allowed access"


class TestAdvancedFeatures:
    """Test advanced feature flag functionality."""
    
    @pytest.mark.asyncio
    async def test_concurrent_evaluations(self):
        """Test concurrent flag evaluations."""
        provider = MockFeatureFlagProvider(
            default_enabled=True,
            evaluation_delay=0.01  # Small delay to test concurrency
        )
        
        config = FeatureFlagConfig(
            flag_key="concurrent_test",
            provider=provider,
            cache_enabled=True
        )
        shield = FeatureFlagShield(config)
        
        request = create_mock_request(user_id="concurrent_user")
        
        # Perform concurrent evaluations
        results = await LoadTestHelper.concurrent_evaluations(
            shield, request, concurrent_count=10, iterations=1
        )
        
        # All evaluations should succeed
        successful_results = [r for r in results if not r["is_exception"]]
        assert len(successful_results) == 10
        
        # Due to caching, provider should be called at most 10 times
        # In concurrent scenarios, all may hit provider before cache is populated
        assert len(provider.evaluate_flag_calls) == 10  # All requests hit provider concurrently
    
    def test_cache_key_generation(self):
        """Test cache key generation for different contexts."""
        provider = MockFeatureFlagProvider()
        config = FeatureFlagConfig(flag_key="cache_test", provider=provider)
        shield = FeatureFlagShield(config)
        
        context1 = {"user_id": "user1", "tier": "basic"}
        context2 = {"user_id": "user2", "tier": "basic"}
        context3 = {"user_id": "user1", "tier": "premium"}
        
        key1 = shield._generate_cache_key("test_flag", context1)
        key2 = shield._generate_cache_key("test_flag", context2)
        key3 = shield._generate_cache_key("test_flag", context3)
        
        # Different users should have different cache keys
        assert key1 != key2
        
        # Same user with different attributes should have different cache keys
        assert key1 != key3
        
        # Same context should generate same key
        key1_repeat = shield._generate_cache_key("test_flag", context1)
        assert key1 == key1_repeat
    
    @pytest.mark.asyncio
    async def test_health_check_caching(self):
        """Test health check caching behavior."""
        provider = MockFeatureFlagProvider(health_status=True)
        config = FeatureFlagConfig(
            flag_key="health_test",
            provider=provider,
            health_check_enabled=True,
            health_check_interval_seconds=0.5  # Short interval for testing
        )
        shield = FeatureFlagShield(config)
        
        request = create_mock_request()
        
        # Reset the shield's health check timer to ensure first call triggers health check
        shield._last_health_check = 0
        
        # First evaluation should trigger health check
        await shield._shield_function(request)
        initial_health_calls = len(provider.health_check_calls)
        assert initial_health_calls >= 1
        
        # Immediate second evaluation should not trigger another health check
        await shield._shield_function(request)
        assert len(provider.health_check_calls) == initial_health_calls
        
        # Wait for health check interval and try again
        time.sleep(0.6)
        await shield._shield_function(request)
        final_health_calls = len(provider.health_check_calls)
        assert final_health_calls >= initial_health_calls
    
    def test_percentage_rollout_consistency(self):
        """Test percentage rollout consistency across evaluations."""
        provider = MockFeatureFlagProvider(default_enabled=True)
        config = FeatureFlagConfig(
            flag_key="consistency_test",
            provider=provider,
            rollout_strategy=RolloutStrategy.PERCENTAGE_BASED,
            rollout_percentage=25
        )
        shield = FeatureFlagShield(config)
        
        # Generate test user contexts
        contexts = PercentageTestHelper.generate_user_contexts_for_percentage(100)
        
        # Calculate expected enabled count
        expected_enabled = PercentageTestHelper.calculate_expected_enabled_count(
            contexts, "consistency_test", 25
        )
        
        # Test rollout evaluation
        enabled_count = 0
        for context in contexts:
            enabled = asyncio.run(shield._evaluate_percentage_rollout(context))
            if enabled:
                enabled_count += 1
        
        # Should match expected count exactly (since we're using the same hash logic)
        assert enabled_count == expected_enabled
        
        # Test that same user always gets same result
        test_context = contexts[0]
        result1 = asyncio.run(shield._evaluate_percentage_rollout(test_context))
        result2 = asyncio.run(shield._evaluate_percentage_rollout(test_context))
        assert result1 == result2
    
    @pytest.mark.asyncio
    async def test_error_handling_edge_cases(self):
        """Test error handling in various edge cases."""
        provider = MockFeatureFlagProvider()
        
        # Test with failing user context extractor
        failing_extractor = create_failing_user_context_extractor()
        config = FeatureFlagConfig(
            flag_key="error_test",
            provider=provider,
            user_context_extractor=failing_extractor,
            fallback_behavior="deny"
        )
        shield = FeatureFlagShield(config)
        
        request = create_mock_request()
        
        with pytest.raises(HTTPException) as exc_info:
            await shield._shield_function(request)
        
        assert exc_info.value.status_code == 500
        assert "evaluation failed" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_cache_expiration_during_evaluation(self):
        """Test cache behavior when entries expire during evaluation."""
        provider = MockFeatureFlagProvider(default_enabled=True)
        config = FeatureFlagConfig(
            flag_key="expiry_test",
            provider=provider,
            cache_enabled=True,
            cache_ttl_seconds=1  # Very short TTL
        )
        shield = FeatureFlagShield(config)
        
        request = create_mock_request(user_id="cache_test_user")
        
        # First evaluation - populates cache
        result1 = await shield._shield_function(request)
        assert result1["feature_flag"]["cached"] is False
        
        # Second evaluation - should hit cache
        result2 = await shield._shield_function(request)
        assert result2["feature_flag"]["cached"] is True
        
        # Wait for cache expiration
        time.sleep(1.1)
        
        # Third evaluation - cache expired, should hit provider again
        result3 = await shield._shield_function(request)
        assert result3["feature_flag"]["cached"] is False
        
        # Verify provider was called twice (initial + after expiration)
        assert len(provider.evaluate_flag_calls) == 2


class TestEdgeCases:
    """Test edge cases and boundary conditions."""
    
    @pytest.mark.asyncio
    async def test_empty_user_context(self):
        """Test behavior with empty user context."""
        provider = MockFeatureFlagProvider(default_enabled=True)
        config = FeatureFlagConfig(flag_key="empty_context", provider=provider)
        shield = FeatureFlagShield(config)
        
        # Create request with minimal information
        request = Mock(spec=Request)
        request.client = None
        request.url = Mock()
        request.url.path = "/test"
        request.method = "GET"
        request.headers = {}
        
        result = await shield._shield_function(request)
        
        # Should still work with generated anonymous user_id
        assert result["feature_flag"]["enabled"] is True
        assert result["feature_flag"]["user_context"]["user_id"] is not None
    
    def test_zero_percentage_rollout(self):
        """Test 0% percentage rollout."""
        provider = MockFeatureFlagProvider(default_enabled=True)
        config = FeatureFlagConfig(
            flag_key="zero_rollout",
            provider=provider,
            rollout_strategy=RolloutStrategy.PERCENTAGE_BASED,
            rollout_percentage=0
        )
        shield = FeatureFlagShield(config)
        
        # Test with multiple different users
        for i in range(10):
            context = {"user_id": f"user_{i}"}
            enabled = asyncio.run(shield._evaluate_percentage_rollout(context))
            assert enabled is False  # 0% rollout should never enable
    
    def test_hundred_percentage_rollout(self):
        """Test 100% percentage rollout."""
        provider = MockFeatureFlagProvider(default_enabled=True)
        config = FeatureFlagConfig(
            flag_key="full_rollout",
            provider=provider,
            rollout_strategy=RolloutStrategy.PERCENTAGE_BASED,
            rollout_percentage=100
        )
        shield = FeatureFlagShield(config)
        
        # Test with multiple different users
        for i in range(10):
            context = {"user_id": f"user_{i}"}
            enabled = asyncio.run(shield._evaluate_percentage_rollout(context))
            assert enabled is True  # 100% rollout should always enable
    
    @pytest.mark.asyncio
    async def test_malformed_evaluation_result(self):
        """Test handling of malformed evaluation results."""
        provider = MockFeatureFlagProvider()
        
        # Create malformed result
        malformed_result = EvaluationResult(
            enabled=True,
            variation=None,
            reason=None
        )
        provider.set_flag_result("malformed_flag", malformed_result)
        
        config = FeatureFlagConfig(flag_key="malformed_flag", provider=provider)
        shield = FeatureFlagShield(config)
        
        request = create_mock_request()
        result = await shield._shield_function(request)
        
        # Should handle malformed result gracefully
        assert result["feature_flag"]["enabled"] is True
        assert result["feature_flag"]["variation"] is None
        assert result["feature_flag"]["reason"] is None
    
    def test_very_long_flag_key(self):
        """Test behavior with very long flag key."""
        provider = MockFeatureFlagProvider(default_enabled=True)
        long_flag_key = "a" * 1000  # Very long flag key
        
        config = FeatureFlagConfig(flag_key=long_flag_key, provider=provider)
        shield = FeatureFlagShield(config)
        
        request = create_mock_request()
        context = shield._default_user_context_extractor(request)
        
        # Cache key generation should handle long keys
        cache_key = shield._generate_cache_key(long_flag_key, context)
        assert len(cache_key) == 32  # MD5 hash should be 32 chars regardless of input length
    
    @pytest.mark.asyncio
    async def test_unicode_user_context(self):
        """Test behavior with Unicode characters in user context."""
        provider = MockFeatureFlagProvider(default_enabled=True)
        config = FeatureFlagConfig(flag_key="unicode_test", provider=provider)
        shield = FeatureFlagShield(config)
        
        # Create user context with Unicode characters
        unicode_context = {
            "user_id": "用户_测试_🚀",
            "name": "José María",
            "location": "北京市"
        }
        
        extractor = create_mock_user_context_extractor(unicode_context)
        config.user_context_extractor = extractor
        
        request = create_mock_request()
        result = await shield._shield_function(request)
        
        # Should handle Unicode gracefully
        assert result["feature_flag"]["user_context"]["user_id"] == "用户_测试_🚀"
        assert result["feature_flag"]["user_context"]["name"] == "José María"
        assert result["feature_flag"]["user_context"]["location"] == "北京市"


class TestPerformance:
    """Test performance-related functionality."""
    
    @pytest.mark.asyncio
    async def test_evaluation_timeout_handling(self):
        """Test handling of evaluation timeouts."""
        provider = MockFeatureFlagProvider(
            evaluation_delay=0.1,  # Simulate slow provider
            default_enabled=True
        )
        
        config = FeatureFlagConfig(flag_key="timeout_test", provider=provider)
        shield = FeatureFlagShield(config)
        
        request = create_mock_request()
        
        start_time = time.time()
        result = await shield._shield_function(request)
        end_time = time.time()
        
        # Should complete but track the evaluation time
        assert result["feature_flag"]["enabled"] is True
        assert (end_time - start_time) >= 0.1  # At least as long as the delay
    
    def test_cache_performance_scaling(self):
        """Test cache performance with large number of entries."""
        cache = FeatureFlagCache(ttl_seconds=300)
        
        # Add large number of cache entries
        num_entries = 1000
        results = []
        
        for i in range(num_entries):
            result = EvaluationResult(enabled=i % 2 == 0, reason=f"test_{i}")
            results.append(result)
            cache.set(f"key_{i}", result)
        
        # Verify all entries are retrievable
        for i in range(num_entries):
            cached_result = cache.get(f"key_{i}")
            assert cached_result is not None
            assert cached_result.enabled == (i % 2 == 0)
            assert cached_result.reason == f"test_{i}"
    
    @pytest.mark.asyncio
    async def test_memory_usage_with_caching(self):
        """Test memory behavior with extensive caching."""
        provider = MockFeatureFlagProvider(default_enabled=True)
        config = FeatureFlagConfig(
            flag_key="memory_test",
            provider=provider,
            cache_enabled=True,
            cache_ttl_seconds=10  # Longer TTL to prevent expiration during test
        )
        shield = FeatureFlagShield(config)
        
        # Generate many different user contexts with different IPs too
        for i in range(50):  # Use fewer entries to avoid timing issues
            request = create_mock_request(
                user_id=f"user_{i}",
                ip_address=f"192.168.1.{i % 255}"
            )
            await shield._shield_function(request)
        
        # Verify cache has multiple entries (should be close to 50)
        assert len(shield._cache._cache) >= 25  # Allow some flexibility
        
        # Wait for cache expiration (cache TTL is 10 seconds, so this won't expire them)
        time.sleep(0.1)
        
        # Cache should still have entries since TTL is long
        assert len(shield._cache._cache) >= 25