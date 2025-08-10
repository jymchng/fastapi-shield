"""Feature flag shield for FastAPI Shield.

This module provides feature flag integration to control access to endpoints
and features through popular feature flag services like LaunchDarkly, Split,
and Unleash. Supports user-based evaluation, percentage rollouts, caching,
and fallback mechanisms.
"""

import asyncio
import hashlib
import json
import time
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, Optional, Union, List, Callable
from threading import Lock

import httpx
from fastapi import HTTPException, Request, Response, status

from fastapi_shield.shield import Shield, shield


class RolloutStrategy(str, Enum):
    """Feature flag rollout strategies."""
    USER_BASED = "user_based"
    PERCENTAGE_BASED = "percentage_based"
    ATTRIBUTE_BASED = "attribute_based"
    SEGMENT_BASED = "segment_based"


class FeatureFlagProvider(str, Enum):
    """Supported feature flag providers."""
    LAUNCHDARKLY = "launchdarkly"
    SPLIT = "split"
    UNLEASH = "unleash"
    CUSTOM = "custom"


class EvaluationResult:
    """Result of a feature flag evaluation."""
    
    def __init__(
        self,
        enabled: bool,
        variation: Any = None,
        reason: str = "evaluation",
        cached: bool = False,
        fallback_used: bool = False,
        evaluation_time_ms: float = 0.0,
    ):
        self.enabled = enabled
        self.variation = variation
        self.reason = reason
        self.cached = cached
        self.fallback_used = fallback_used
        self.evaluation_time_ms = evaluation_time_ms
        self.timestamp = datetime.utcnow()


class FeatureFlagCache:
    """In-memory cache for feature flag evaluations."""
    
    def __init__(self, ttl_seconds: int = 300):  # 5 minute default TTL
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._lock = Lock()
        self.ttl_seconds = ttl_seconds
    
    def get(self, cache_key: str) -> Optional[EvaluationResult]:
        """Get cached evaluation result."""
        with self._lock:
            if cache_key in self._cache:
                entry = self._cache[cache_key]
                if time.time() - entry["timestamp"] < self.ttl_seconds:
                    result = entry["result"]
                    result.cached = True
                    return result
                else:
                    # Remove expired entry
                    del self._cache[cache_key]
            return None
    
    def set(self, cache_key: str, result: EvaluationResult) -> None:
        """Cache evaluation result."""
        with self._lock:
            self._cache[cache_key] = {
                "result": result,
                "timestamp": time.time()
            }
    
    def clear(self) -> None:
        """Clear all cached entries."""
        with self._lock:
            self._cache.clear()
    
    def evict_expired(self) -> None:
        """Remove expired entries from cache."""
        with self._lock:
            current_time = time.time()
            expired_keys = [
                key for key, entry in self._cache.items()
                if current_time - entry["timestamp"] >= self.ttl_seconds
            ]
            for key in expired_keys:
                del self._cache[key]


class FeatureFlagProvider(ABC):
    """Abstract base class for feature flag providers."""
    
    @abstractmethod
    async def evaluate_flag(
        self,
        flag_key: str,
        user_context: Dict[str, Any],
        default_value: Any = False
    ) -> EvaluationResult:
        """Evaluate a feature flag for the given user context."""
        pass
    
    @abstractmethod
    async def get_all_flags(self, user_context: Dict[str, Any]) -> Dict[str, EvaluationResult]:
        """Get all feature flags for the given user context."""
        pass
    
    @abstractmethod
    async def health_check(self) -> bool:
        """Check if the provider service is healthy."""
        pass


class LaunchDarklyProvider(FeatureFlagProvider):
    """LaunchDarkly feature flag provider."""
    
    def __init__(
        self,
        sdk_key: str,
        base_url: str = "https://app.launchdarkly.com",
        timeout: int = 5
    ):
        self.sdk_key = sdk_key
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self._client = httpx.AsyncClient(timeout=timeout)
    
    async def evaluate_flag(
        self,
        flag_key: str,
        user_context: Dict[str, Any],
        default_value: Any = False
    ) -> EvaluationResult:
        """Evaluate feature flag via LaunchDarkly REST API."""
        start_time = time.time()
        
        try:
            headers = {
                "Authorization": f"api_key {self.sdk_key}",
                "Content-Type": "application/json"
            }
            
            # Transform user context to LaunchDarkly format
            user_data = {
                "key": user_context.get("user_id", "anonymous"),
                **user_context
            }
            
            url = f"{self.base_url}/api/v2/flags/{flag_key}/evaluate"
            
            response = await self._client.post(
                url,
                json={"user": user_data},
                headers=headers
            )
            
            if response.status_code == 200:
                data = response.json()
                evaluation_time = (time.time() - start_time) * 1000
                
                return EvaluationResult(
                    enabled=data.get("value", default_value),
                    variation=data.get("variation"),
                    reason=data.get("reason", "evaluation"),
                    evaluation_time_ms=evaluation_time
                )
            else:
                return EvaluationResult(
                    enabled=default_value,
                    reason=f"http_error_{response.status_code}",
                    fallback_used=True
                )
                
        except Exception as e:
            return EvaluationResult(
                enabled=default_value,
                reason=f"exception_{type(e).__name__}",
                fallback_used=True,
                evaluation_time_ms=(time.time() - start_time) * 1000
            )
    
    async def get_all_flags(self, user_context: Dict[str, Any]) -> Dict[str, EvaluationResult]:
        """Get all flags for user context."""
        try:
            headers = {
                "Authorization": f"api_key {self.sdk_key}",
                "Content-Type": "application/json"
            }
            
            user_data = {
                "key": user_context.get("user_id", "anonymous"),
                **user_context
            }
            
            url = f"{self.base_url}/api/v2/flags/evaluate"
            
            response = await self._client.post(
                url,
                json={"user": user_data},
                headers=headers
            )
            
            if response.status_code == 200:
                data = response.json()
                results = {}
                
                for flag_key, flag_data in data.items():
                    results[flag_key] = EvaluationResult(
                        enabled=flag_data.get("value", False),
                        variation=flag_data.get("variation"),
                        reason=flag_data.get("reason", "evaluation")
                    )
                
                return results
            
        except Exception:
            pass
        
        return {}
    
    async def health_check(self) -> bool:
        """Check LaunchDarkly service health."""
        try:
            headers = {"Authorization": f"api_key {self.sdk_key}"}
            response = await self._client.get(
                f"{self.base_url}/api/v2/projects",
                headers=headers
            )
            return response.status_code == 200
        except Exception:
            return False


class SplitProvider(FeatureFlagProvider):
    """Split.io feature flag provider."""
    
    def __init__(
        self,
        api_key: str,
        base_url: str = "https://sdk.split.io/api",
        timeout: int = 5
    ):
        self.api_key = api_key
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self._client = httpx.AsyncClient(timeout=timeout)
    
    async def evaluate_flag(
        self,
        flag_key: str,
        user_context: Dict[str, Any],
        default_value: Any = False
    ) -> EvaluationResult:
        """Evaluate feature flag via Split.io REST API."""
        start_time = time.time()
        
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            user_key = user_context.get("user_id", "anonymous")
            
            url = f"{self.base_url}/client/getTreatment"
            
            response = await self._client.post(
                url,
                json={
                    "key": user_key,
                    "splitName": flag_key,
                    "attributes": user_context
                },
                headers=headers
            )
            
            if response.status_code == 200:
                data = response.json()
                treatment = data.get("treatment", "control")
                evaluation_time = (time.time() - start_time) * 1000
                
                return EvaluationResult(
                    enabled=treatment == "on",
                    variation=treatment,
                    reason="evaluation",
                    evaluation_time_ms=evaluation_time
                )
            else:
                return EvaluationResult(
                    enabled=default_value,
                    reason=f"http_error_{response.status_code}",
                    fallback_used=True
                )
                
        except Exception as e:
            return EvaluationResult(
                enabled=default_value,
                reason=f"exception_{type(e).__name__}",
                fallback_used=True,
                evaluation_time_ms=(time.time() - start_time) * 1000
            )
    
    async def get_all_flags(self, user_context: Dict[str, Any]) -> Dict[str, EvaluationResult]:
        """Get all flags for user context."""
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            user_key = user_context.get("user_id", "anonymous")
            
            url = f"{self.base_url}/client/getTreatments"
            
            response = await self._client.post(
                url,
                json={
                    "key": user_key,
                    "attributes": user_context
                },
                headers=headers
            )
            
            if response.status_code == 200:
                data = response.json()
                results = {}
                
                for flag_key, treatment in data.items():
                    results[flag_key] = EvaluationResult(
                        enabled=treatment == "on",
                        variation=treatment,
                        reason="evaluation"
                    )
                
                return results
            
        except Exception:
            pass
        
        return {}
    
    async def health_check(self) -> bool:
        """Check Split.io service health."""
        try:
            headers = {"Authorization": f"Bearer {self.api_key}"}
            response = await self._client.get(
                f"{self.base_url}/version",
                headers=headers
            )
            return response.status_code == 200
        except Exception:
            return False


class UnleashProvider(FeatureFlagProvider):
    """Unleash feature flag provider."""
    
    def __init__(
        self,
        api_url: str,
        client_key: str,
        app_name: str = "fastapi-shield",
        timeout: int = 5
    ):
        self.api_url = api_url.rstrip('/')
        self.client_key = client_key
        self.app_name = app_name
        self.timeout = timeout
        self._client = httpx.AsyncClient(timeout=timeout)
    
    async def evaluate_flag(
        self,
        flag_key: str,
        user_context: Dict[str, Any],
        default_value: Any = False
    ) -> EvaluationResult:
        """Evaluate feature flag via Unleash API."""
        start_time = time.time()
        
        try:
            headers = {
                "Authorization": self.client_key,
                "Content-Type": "application/json",
                "UNLEASH-APPNAME": self.app_name
            }
            
            # Simple percentage-based evaluation for Unleash
            user_id = user_context.get("user_id", "anonymous")
            
            # Hash user ID to get consistent percentage
            hash_value = hashlib.md5(f"{flag_key}{user_id}".encode()).hexdigest()
            percentage = int(hash_value[:8], 16) % 100
            
            url = f"{self.api_url}/api/client/features/{flag_key}"
            
            response = await self._client.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                enabled = data.get("enabled", False)
                
                # Apply strategies if enabled
                if enabled and "strategies" in data:
                    for strategy in data["strategies"]:
                        if strategy.get("name") == "gradualRolloutUserId":
                            rollout_percentage = int(strategy.get("parameters", {}).get("percentage", 0))
                            enabled = percentage < rollout_percentage
                            break
                
                evaluation_time = (time.time() - start_time) * 1000
                
                return EvaluationResult(
                    enabled=enabled,
                    reason="evaluation",
                    evaluation_time_ms=evaluation_time
                )
            else:
                return EvaluationResult(
                    enabled=default_value,
                    reason=f"http_error_{response.status_code}",
                    fallback_used=True
                )
                
        except Exception as e:
            return EvaluationResult(
                enabled=default_value,
                reason=f"exception_{type(e).__name__}",
                fallback_used=True,
                evaluation_time_ms=(time.time() - start_time) * 1000
            )
    
    async def get_all_flags(self, user_context: Dict[str, Any]) -> Dict[str, EvaluationResult]:
        """Get all flags for user context."""
        try:
            headers = {
                "Authorization": self.client_key,
                "Content-Type": "application/json",
                "UNLEASH-APPNAME": self.app_name
            }
            
            response = await self._client.get(
                f"{self.api_url}/api/client/features",
                headers=headers
            )
            
            if response.status_code == 200:
                data = response.json()
                results = {}
                
                for feature in data.get("features", []):
                    flag_key = feature["name"]
                    result = await self.evaluate_flag(flag_key, user_context, False)
                    results[flag_key] = result
                
                return results
            
        except Exception:
            pass
        
        return {}
    
    async def health_check(self) -> bool:
        """Check Unleash service health."""
        try:
            headers = {"Authorization": self.client_key}
            response = await self._client.get(
                f"{self.api_url}/api/client/features",
                headers=headers
            )
            return response.status_code == 200
        except Exception:
            return False


class CustomProvider(FeatureFlagProvider):
    """Custom feature flag provider using callback functions."""
    
    def __init__(
        self,
        evaluation_callback: Callable[[str, Dict[str, Any], Any], EvaluationResult],
        flags_callback: Optional[Callable[[Dict[str, Any]], Dict[str, EvaluationResult]]] = None,
        health_callback: Optional[Callable[[], bool]] = None
    ):
        self.evaluation_callback = evaluation_callback
        self.flags_callback = flags_callback
        self.health_callback = health_callback
    
    async def evaluate_flag(
        self,
        flag_key: str,
        user_context: Dict[str, Any],
        default_value: Any = False
    ) -> EvaluationResult:
        """Evaluate feature flag using custom callback."""
        try:
            if asyncio.iscoroutinefunction(self.evaluation_callback):
                return await self.evaluation_callback(flag_key, user_context, default_value)
            else:
                return self.evaluation_callback(flag_key, user_context, default_value)
        except Exception as e:
            return EvaluationResult(
                enabled=default_value,
                reason=f"callback_exception_{type(e).__name__}",
                fallback_used=True
            )
    
    async def get_all_flags(self, user_context: Dict[str, Any]) -> Dict[str, EvaluationResult]:
        """Get all flags using custom callback."""
        if not self.flags_callback:
            return {}
        
        try:
            if asyncio.iscoroutinefunction(self.flags_callback):
                return await self.flags_callback(user_context)
            else:
                return self.flags_callback(user_context)
        except Exception:
            return {}
    
    async def health_check(self) -> bool:
        """Check health using custom callback."""
        if not self.health_callback:
            return True
        
        try:
            if asyncio.iscoroutinefunction(self.health_callback):
                return await self.health_callback()
            else:
                return self.health_callback()
        except Exception:
            return False


class FeatureFlagConfig:
    """Configuration for feature flag shield."""
    
    def __init__(
        self,
        flag_key: str,
        provider: FeatureFlagProvider,
        rollout_strategy: RolloutStrategy = RolloutStrategy.USER_BASED,
        rollout_percentage: Optional[int] = None,
        user_context_extractor: Optional[Callable[[Request], Dict[str, Any]]] = None,
        cache_enabled: bool = True,
        cache_ttl_seconds: int = 300,
        default_enabled: bool = False,
        require_authentication: bool = False,
        allowed_variations: Optional[List[Any]] = None,
        fallback_behavior: str = "deny",  # "deny", "allow", "default"
        health_check_enabled: bool = True,
        health_check_interval_seconds: int = 60
    ):
        self.flag_key = flag_key
        self.provider = provider
        self.rollout_strategy = rollout_strategy
        self.rollout_percentage = rollout_percentage
        self.user_context_extractor = user_context_extractor
        self.cache_enabled = cache_enabled
        self.cache_ttl_seconds = cache_ttl_seconds
        self.default_enabled = default_enabled
        self.require_authentication = require_authentication
        self.allowed_variations = allowed_variations or []
        self.fallback_behavior = fallback_behavior
        self.health_check_enabled = health_check_enabled
        self.health_check_interval_seconds = health_check_interval_seconds


class FeatureFlagShield(Shield):
    """Feature flag shield for endpoint access control."""
    
    def __init__(self, config: FeatureFlagConfig):
        self.config = config
        self._cache = FeatureFlagCache(ttl_seconds=config.cache_ttl_seconds) if config.cache_enabled else None
        self._last_health_check = 0
        self._provider_healthy = True
        
        super().__init__(self._shield_function)
    
    def _default_user_context_extractor(self, request: Request) -> Dict[str, Any]:
        """Default user context extractor."""
        context = {
            "ip_address": request.client.host if request.client else "unknown",
            "user_agent": request.headers.get("user-agent", ""),
            "path": request.url.path,
            "method": request.method,
        }
        
        # Try to extract user ID from common headers
        user_id = (
            request.headers.get("x-user-id") or
            request.headers.get("user-id") or
            (request.headers.get("authorization", "").split(" ")[-1] if 
             request.headers.get("authorization") else None) or
            "anonymous"
        )
        
        if user_id and user_id != "anonymous":
            context["user_id"] = user_id
        else:
            # Generate consistent anonymous ID based on IP and User-Agent
            anonymous_key = f"{context['ip_address']}_{context['user_agent']}"
            context["user_id"] = hashlib.md5(anonymous_key.encode()).hexdigest()
        
        return context
    
    def _generate_cache_key(self, flag_key: str, user_context: Dict[str, Any]) -> str:
        """Generate cache key for evaluation result."""
        context_str = json.dumps(user_context, sort_keys=True)
        cache_data = f"{flag_key}:{context_str}"
        return hashlib.md5(cache_data.encode()).hexdigest()
    
    async def _check_provider_health(self) -> bool:
        """Check provider health if enough time has passed."""
        current_time = time.time()
        
        if (current_time - self._last_health_check) >= self.config.health_check_interval_seconds:
            self._last_health_check = current_time
            
            if self.config.health_check_enabled:
                try:
                    self._provider_healthy = await self.config.provider.health_check()
                except Exception:
                    self._provider_healthy = False
        
        return self._provider_healthy
    
    async def _evaluate_percentage_rollout(self, user_context: Dict[str, Any]) -> bool:
        """Evaluate percentage-based rollout."""
        if self.config.rollout_percentage is None:
            return True
        
        user_id = user_context.get("user_id", "anonymous")
        
        # Generate consistent hash for user and flag
        hash_input = f"{self.config.flag_key}:{user_id}"
        hash_value = hashlib.md5(hash_input.encode()).hexdigest()
        user_percentage = int(hash_value[:8], 16) % 100
        
        return user_percentage < self.config.rollout_percentage
    
    async def _shield_function(self, request: Request) -> Optional[Dict[str, Any]]:
        """Main shield function for feature flag evaluation."""
        try:
            # Extract user context
            if self.config.user_context_extractor:
                user_context = self.config.user_context_extractor(request)
            else:
                user_context = self._default_user_context_extractor(request)
            
            # Check if authentication is required but not present
            if self.config.require_authentication:
                user_id = user_context.get("user_id", "anonymous")
                if user_id == "anonymous" or not user_id:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Authentication required for feature flag evaluation"
                    )
            
            # Generate cache key
            cache_key = None
            if self._cache:
                cache_key = self._generate_cache_key(self.config.flag_key, user_context)
                
                # Try to get from cache first
                cached_result = self._cache.get(cache_key)
                if cached_result:
                    if not cached_result.enabled:
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail=f"Feature '{self.config.flag_key}' is not enabled (cached)"
                        )
                    return {
                        "feature_flag": {
                            "key": self.config.flag_key,
                            "enabled": cached_result.enabled,
                            "variation": cached_result.variation,
                            "reason": cached_result.reason,
                            "cached": True,
                            "user_context": user_context
                        }
                    }
            
            # Check provider health
            provider_healthy = await self._check_provider_health()
            
            # Evaluate feature flag
            evaluation_result = None
            
            if provider_healthy:
                try:
                    evaluation_result = await self.config.provider.evaluate_flag(
                        self.config.flag_key,
                        user_context,
                        self.config.default_enabled
                    )
                except Exception:
                    evaluation_result = None
            
            # Handle fallback scenarios
            if not evaluation_result or evaluation_result.fallback_used:
                if self.config.fallback_behavior == "deny":
                    raise HTTPException(
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                        detail="Feature flag service unavailable"
                    )
                elif self.config.fallback_behavior == "allow":
                    evaluation_result = EvaluationResult(
                        enabled=True,
                        reason="fallback_allow",
                        fallback_used=True
                    )
                else:  # "default"
                    evaluation_result = EvaluationResult(
                        enabled=self.config.default_enabled,
                        reason="fallback_default",
                        fallback_used=True
                    )
            
            # Apply percentage rollout if configured
            if (evaluation_result.enabled and 
                self.config.rollout_strategy == RolloutStrategy.PERCENTAGE_BASED):
                
                percentage_enabled = await self._evaluate_percentage_rollout(user_context)
                if not percentage_enabled:
                    evaluation_result = EvaluationResult(
                        enabled=False,
                        reason="percentage_rollout_excluded",
                        variation=evaluation_result.variation
                    )
            
            # Check allowed variations if configured
            if (evaluation_result.enabled and 
                self.config.allowed_variations and 
                evaluation_result.variation not in self.config.allowed_variations):
                
                evaluation_result = EvaluationResult(
                    enabled=False,
                    reason="variation_not_allowed",
                    variation=evaluation_result.variation
                )
            
            # Cache the result
            if self._cache and cache_key:
                self._cache.set(cache_key, evaluation_result)
            
            # Check if feature is enabled
            if not evaluation_result.enabled:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Feature '{self.config.flag_key}' is not enabled for this user"
                )
            
            # Return feature flag data for dependency injection
            return {
                "feature_flag": {
                    "key": self.config.flag_key,
                    "enabled": evaluation_result.enabled,
                    "variation": evaluation_result.variation,
                    "reason": evaluation_result.reason,
                    "cached": evaluation_result.cached,
                    "fallback_used": evaluation_result.fallback_used,
                    "evaluation_time_ms": evaluation_result.evaluation_time_ms,
                    "user_context": user_context
                }
            }
            
        except HTTPException:
            raise
        except Exception as e:
            # Handle unexpected errors based on fallback behavior
            if self.config.fallback_behavior == "allow":
                return {
                    "feature_flag": {
                        "key": self.config.flag_key,
                        "enabled": True,
                        "reason": f"exception_fallback_{type(e).__name__}",
                        "fallback_used": True,
                        "user_context": {}
                    }
                }
            else:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Feature flag evaluation failed"
                )


def feature_flag_shield(
    flag_key: str,
    provider: FeatureFlagProvider,
    rollout_strategy: RolloutStrategy = RolloutStrategy.USER_BASED,
    rollout_percentage: Optional[int] = None,
    user_context_extractor: Optional[Callable[[Request], Dict[str, Any]]] = None,
    cache_enabled: bool = True,
    cache_ttl_seconds: int = 300,
    default_enabled: bool = False,
    require_authentication: bool = False,
    allowed_variations: Optional[List[Any]] = None,
    fallback_behavior: str = "deny",
    health_check_enabled: bool = True,
    health_check_interval_seconds: int = 60
) -> FeatureFlagShield:
    """Create a feature flag shield with the specified configuration.
    
    Args:
        flag_key: The feature flag key to evaluate
        provider: The feature flag provider to use
        rollout_strategy: Strategy for rollout (user_based, percentage_based, etc.)
        rollout_percentage: Percentage for rollout (0-100)
        user_context_extractor: Function to extract user context from request
        cache_enabled: Whether to enable caching
        cache_ttl_seconds: Cache TTL in seconds
        default_enabled: Default value when evaluation fails
        require_authentication: Whether authentication is required
        allowed_variations: List of allowed variation values
        fallback_behavior: Behavior when service is unavailable ("deny", "allow", "default")
        health_check_enabled: Whether to perform health checks
        health_check_interval_seconds: Health check interval
    
    Returns:
        FeatureFlagShield instance
    """
    config = FeatureFlagConfig(
        flag_key=flag_key,
        provider=provider,
        rollout_strategy=rollout_strategy,
        rollout_percentage=rollout_percentage,
        user_context_extractor=user_context_extractor,
        cache_enabled=cache_enabled,
        cache_ttl_seconds=cache_ttl_seconds,
        default_enabled=default_enabled,
        require_authentication=require_authentication,
        allowed_variations=allowed_variations,
        fallback_behavior=fallback_behavior,
        health_check_enabled=health_check_enabled,
        health_check_interval_seconds=health_check_interval_seconds
    )
    
    return FeatureFlagShield(config)


def launchdarkly_feature_flag_shield(
    flag_key: str,
    sdk_key: str,
    base_url: str = "https://app.launchdarkly.com",
    cache_enabled: bool = True,
    default_enabled: bool = False,
    fallback_behavior: str = "deny"
) -> FeatureFlagShield:
    """Create a LaunchDarkly feature flag shield."""
    provider = LaunchDarklyProvider(sdk_key=sdk_key, base_url=base_url)
    
    return feature_flag_shield(
        flag_key=flag_key,
        provider=provider,
        cache_enabled=cache_enabled,
        default_enabled=default_enabled,
        fallback_behavior=fallback_behavior
    )


def split_feature_flag_shield(
    flag_key: str,
    api_key: str,
    base_url: str = "https://sdk.split.io/api",
    cache_enabled: bool = True,
    default_enabled: bool = False,
    fallback_behavior: str = "deny"
) -> FeatureFlagShield:
    """Create a Split.io feature flag shield."""
    provider = SplitProvider(api_key=api_key, base_url=base_url)
    
    return feature_flag_shield(
        flag_key=flag_key,
        provider=provider,
        cache_enabled=cache_enabled,
        default_enabled=default_enabled,
        fallback_behavior=fallback_behavior
    )


def unleash_feature_flag_shield(
    flag_key: str,
    api_url: str,
    client_key: str,
    app_name: str = "fastapi-shield",
    cache_enabled: bool = True,
    default_enabled: bool = False,
    fallback_behavior: str = "deny"
) -> FeatureFlagShield:
    """Create an Unleash feature flag shield."""
    provider = UnleashProvider(
        api_url=api_url,
        client_key=client_key,
        app_name=app_name
    )
    
    return feature_flag_shield(
        flag_key=flag_key,
        provider=provider,
        cache_enabled=cache_enabled,
        default_enabled=default_enabled,
        fallback_behavior=fallback_behavior
    )


def percentage_rollout_shield(
    flag_key: str,
    provider: FeatureFlagProvider,
    rollout_percentage: int,
    cache_enabled: bool = True,
    default_enabled: bool = False
) -> FeatureFlagShield:
    """Create a percentage-based rollout feature flag shield."""
    return feature_flag_shield(
        flag_key=flag_key,
        provider=provider,
        rollout_strategy=RolloutStrategy.PERCENTAGE_BASED,
        rollout_percentage=rollout_percentage,
        cache_enabled=cache_enabled,
        default_enabled=default_enabled
    )


def authenticated_feature_flag_shield(
    flag_key: str,
    provider: FeatureFlagProvider,
    user_context_extractor: Callable[[Request], Dict[str, Any]],
    cache_enabled: bool = True,
    default_enabled: bool = False
) -> FeatureFlagShield:
    """Create an authenticated user feature flag shield."""
    return feature_flag_shield(
        flag_key=flag_key,
        provider=provider,
        user_context_extractor=user_context_extractor,
        require_authentication=True,
        cache_enabled=cache_enabled,
        default_enabled=default_enabled
    )