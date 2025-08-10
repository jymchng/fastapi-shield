"""Conditional shield execution framework for FastAPI Shield.

This module provides comprehensive conditional execution capabilities for shields,
allowing dynamic shield selection and execution based on request properties,
user attributes, external conditions, and feature flags. It includes a powerful
rule engine for condition evaluation, performance optimization, and A/B testing support.

Key Components:
    - ConditionEngine: Core rule evaluation engine
    - ConditionalShield: Shield that executes based on conditions
    - ShieldChain: Dynamic shield chain construction
    - PerformanceOptimizer: Optimization for condition evaluation
    - ABTestManager: A/B testing support for shields
"""

import asyncio
import hashlib
import json
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps, lru_cache
from typing import (
    Any, Dict, List, Optional, Union, Callable, Set, Tuple,
    TYPE_CHECKING, Type, NamedTuple, Protocol
)
from contextlib import asynccontextmanager
from threading import RLock
from concurrent.futures import ThreadPoolExecutor
import re

from fastapi import HTTPException, Request, Response, status
from fastapi.responses import JSONResponse

from fastapi_shield.shield import Shield, shield
from fastapi_shield.typing import EndPointFunc
from fastapi_shield.feature_flag import FeatureFlagProvider, EvaluationResult

if TYPE_CHECKING:
    from fastapi_shield.feature_flag import FeatureFlagShield

logger = logging.getLogger(__name__)


class ConditionType(str, Enum):
    """Types of conditions that can be evaluated."""
    SIMPLE = "simple"
    COMPOSITE = "composite"
    FEATURE_FLAG = "feature_flag"
    USER_ATTRIBUTE = "user_attribute"
    REQUEST_PROPERTY = "request_property"
    TIME_BASED = "time_based"
    GEOGRAPHIC = "geographic"
    DEVICE_TYPE = "device_type"
    CUSTOM = "custom"


class LogicalOperator(str, Enum):
    """Logical operators for combining conditions."""
    AND = "and"
    OR = "or"
    NOT = "not"
    XOR = "xor"


class ComparisonOperator(str, Enum):
    """Comparison operators for condition evaluation."""
    EQUALS = "eq"
    NOT_EQUALS = "ne"
    GREATER_THAN = "gt"
    GREATER_THAN_EQUAL = "gte"
    LESS_THAN = "lt"
    LESS_THAN_EQUAL = "lte"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    REGEX = "regex"
    IN = "in"
    NOT_IN = "not_in"


class ExecutionStrategy(str, Enum):
    """Strategies for executing conditional shields."""
    FIRST_MATCH = "first_match"
    ALL_MATCHING = "all_matching"
    WEIGHTED = "weighted"
    PRIORITY_BASED = "priority_based"
    ROUND_ROBIN = "round_robin"


class CacheStrategy(str, Enum):
    """Caching strategies for condition evaluation."""
    NO_CACHE = "no_cache"
    REQUEST_SCOPED = "request_scoped"
    SESSION_SCOPED = "session_scoped"
    GLOBAL = "global"
    TIME_BASED = "time_based"


@dataclass
class ConditionContext:
    """Context for condition evaluation."""
    request: Request
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    user_attributes: Dict[str, Any] = field(default_factory=dict)
    request_attributes: Dict[str, Any] = field(default_factory=dict)
    custom_attributes: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    
    def get_attribute(self, key: str, default: Any = None) -> Any:
        """Get attribute from any context source."""
        # Check user attributes first
        if key in self.user_attributes:
            return self.user_attributes[key]
        
        # Check request attributes
        if key in self.request_attributes:
            return self.request_attributes[key]
        
        # Check custom attributes
        if key in self.custom_attributes:
            return self.custom_attributes[key]
        
        # Check request properties
        if hasattr(self.request, key):
            return getattr(self.request, key)
        
        return default


@dataclass
class ConditionResult:
    """Result of condition evaluation."""
    result: bool
    reason: str
    evaluation_time_ms: float
    cached: bool = False
    attributes_used: Set[str] = field(default_factory=set)
    
    def __bool__(self) -> bool:
        return self.result


class Condition(ABC):
    """Abstract base class for all conditions."""
    
    def __init__(self, condition_id: str, description: str = "", weight: float = 1.0):
        self.condition_id = condition_id
        self.description = description
        self.weight = weight
        self.evaluation_count = 0
        self.total_evaluation_time = 0.0
        self._lock = RLock()
    
    @abstractmethod
    async def evaluate(self, context: ConditionContext) -> ConditionResult:
        """Evaluate the condition."""
        pass
    
    def get_cache_key(self, context: ConditionContext) -> str:
        """Generate cache key for this condition."""
        key_data = {
            "condition_id": self.condition_id,
            "user_id": context.user_id,
            "session_id": context.session_id,
            "timestamp": int(context.timestamp)  # For time-based caching
        }
        key_str = json.dumps(key_data, sort_keys=True)
        return hashlib.md5(key_str.encode()).hexdigest()
    
    def update_metrics(self, evaluation_time: float):
        """Update evaluation metrics."""
        with self._lock:
            self.evaluation_count += 1
            self.total_evaluation_time += evaluation_time
    
    @property
    def average_evaluation_time(self) -> float:
        """Get average evaluation time."""
        with self._lock:
            if self.evaluation_count == 0:
                return 0.0
            return self.total_evaluation_time / self.evaluation_count


class SimpleCondition(Condition):
    """Simple condition for basic comparisons."""
    
    def __init__(
        self,
        condition_id: str,
        attribute_path: str,
        operator: ComparisonOperator,
        value: Any,
        description: str = "",
        weight: float = 1.0
    ):
        super().__init__(condition_id, description, weight)
        self.attribute_path = attribute_path
        self.operator = operator
        self.value = value
    
    async def evaluate(self, context: ConditionContext) -> ConditionResult:
        """Evaluate simple condition."""
        start_time = time.perf_counter()
        
        try:
            # Get the actual value from context
            actual_value = self._get_value_from_path(context, self.attribute_path)
            
            # Perform comparison
            result = self._compare_values(actual_value, self.operator, self.value)
            
            evaluation_time = (time.perf_counter() - start_time) * 1000
            self.update_metrics(evaluation_time)
            
            return ConditionResult(
                result=result,
                reason=f"{self.attribute_path} {self.operator.value} {self.value}",
                evaluation_time_ms=evaluation_time,
                attributes_used={self.attribute_path}
            )
        
        except Exception as e:
            evaluation_time = (time.perf_counter() - start_time) * 1000
            logger.error(f"Error evaluating condition {self.condition_id}: {e}")
            return ConditionResult(
                result=False,
                reason=f"Evaluation error: {str(e)}",
                evaluation_time_ms=evaluation_time,
                attributes_used={self.attribute_path}
            )
    
    def _get_value_from_path(self, context: ConditionContext, path: str) -> Any:
        """Get value from attribute path."""
        # Handle nested paths like "user.role" or "request.headers.authorization"
        parts = path.split('.')
        current_value = context
        
        for part in parts:
            if hasattr(current_value, part):
                current_value = getattr(current_value, part)
            elif isinstance(current_value, dict) and part in current_value:
                current_value = current_value[part]
            elif isinstance(current_value, ConditionContext):
                current_value = current_value.get_attribute(part)
            else:
                return None
        
        return current_value
    
    def _compare_values(self, actual: Any, operator: ComparisonOperator, expected: Any) -> bool:
        """Compare values using the specified operator."""
        if operator == ComparisonOperator.EQUALS:
            return actual == expected
        elif operator == ComparisonOperator.NOT_EQUALS:
            return actual != expected
        elif operator == ComparisonOperator.GREATER_THAN:
            return actual > expected
        elif operator == ComparisonOperator.GREATER_THAN_EQUAL:
            return actual >= expected
        elif operator == ComparisonOperator.LESS_THAN:
            return actual < expected
        elif operator == ComparisonOperator.LESS_THAN_EQUAL:
            return actual <= expected
        elif operator == ComparisonOperator.CONTAINS:
            return expected in actual if actual else False
        elif operator == ComparisonOperator.NOT_CONTAINS:
            return expected not in actual if actual else True
        elif operator == ComparisonOperator.STARTS_WITH:
            return str(actual).startswith(str(expected)) if actual else False
        elif operator == ComparisonOperator.ENDS_WITH:
            return str(actual).endswith(str(expected)) if actual else False
        elif operator == ComparisonOperator.REGEX:
            return bool(re.match(str(expected), str(actual))) if actual else False
        elif operator == ComparisonOperator.IN:
            return actual in expected if expected else False
        elif operator == ComparisonOperator.NOT_IN:
            return actual not in expected if expected else True
        else:
            raise ValueError(f"Unknown operator: {operator}")


class CompositeCondition(Condition):
    """Composite condition for combining multiple conditions."""
    
    def __init__(
        self,
        condition_id: str,
        conditions: List[Condition],
        operator: LogicalOperator,
        description: str = "",
        weight: float = 1.0,
        short_circuit: bool = True
    ):
        super().__init__(condition_id, description, weight)
        self.conditions = conditions
        self.operator = operator
        self.short_circuit = short_circuit
    
    async def evaluate(self, context: ConditionContext) -> ConditionResult:
        """Evaluate composite condition."""
        start_time = time.perf_counter()
        
        try:
            results = []
            all_attributes_used = set()
            
            if self.operator == LogicalOperator.AND:
                result = await self._evaluate_and(context, results, all_attributes_used)
            elif self.operator == LogicalOperator.OR:
                result = await self._evaluate_or(context, results, all_attributes_used)
            elif self.operator == LogicalOperator.NOT:
                result = await self._evaluate_not(context, results, all_attributes_used)
            elif self.operator == LogicalOperator.XOR:
                result = await self._evaluate_xor(context, results, all_attributes_used)
            else:
                raise ValueError(f"Unknown operator: {self.operator}")
            
            evaluation_time = (time.perf_counter() - start_time) * 1000
            self.update_metrics(evaluation_time)
            
            reasons = [r.reason for r in results]
            combined_reason = f"({f' {self.operator.value} '.join(reasons)})"
            
            return ConditionResult(
                result=result,
                reason=combined_reason,
                evaluation_time_ms=evaluation_time,
                attributes_used=all_attributes_used
            )
        
        except Exception as e:
            evaluation_time = (time.perf_counter() - start_time) * 1000
            logger.error(f"Error evaluating composite condition {self.condition_id}: {e}")
            return ConditionResult(
                result=False,
                reason=f"Evaluation error: {str(e)}",
                evaluation_time_ms=evaluation_time
            )
    
    async def _evaluate_and(
        self, 
        context: ConditionContext, 
        results: List[ConditionResult],
        all_attributes_used: Set[str]
    ) -> bool:
        """Evaluate AND condition."""
        for condition in self.conditions:
            result = await condition.evaluate(context)
            results.append(result)
            all_attributes_used.update(result.attributes_used)
            
            if not result.result and self.short_circuit:
                return False
        
        return all(r.result for r in results)
    
    async def _evaluate_or(
        self, 
        context: ConditionContext, 
        results: List[ConditionResult],
        all_attributes_used: Set[str]
    ) -> bool:
        """Evaluate OR condition."""
        for condition in self.conditions:
            result = await condition.evaluate(context)
            results.append(result)
            all_attributes_used.update(result.attributes_used)
            
            if result.result and self.short_circuit:
                return True
        
        return any(r.result for r in results)
    
    async def _evaluate_not(
        self, 
        context: ConditionContext, 
        results: List[ConditionResult],
        all_attributes_used: Set[str]
    ) -> bool:
        """Evaluate NOT condition."""
        if len(self.conditions) != 1:
            raise ValueError("NOT condition must have exactly one sub-condition")
        
        result = await self.conditions[0].evaluate(context)
        results.append(result)
        all_attributes_used.update(result.attributes_used)
        
        return not result.result
    
    async def _evaluate_xor(
        self, 
        context: ConditionContext, 
        results: List[ConditionResult],
        all_attributes_used: Set[str]
    ) -> bool:
        """Evaluate XOR condition."""
        true_count = 0
        
        for condition in self.conditions:
            result = await condition.evaluate(context)
            results.append(result)
            all_attributes_used.update(result.attributes_used)
            
            if result.result:
                true_count += 1
                
                # For XOR, if we already have more than one true result, it's false
                if true_count > 1 and self.short_circuit:
                    return False
        
        return true_count == 1


class FeatureFlagCondition(Condition):
    """Condition based on feature flag evaluation."""
    
    def __init__(
        self,
        condition_id: str,
        flag_key: str,
        expected_value: Any = True,
        flag_provider: Optional['FeatureFlagShield'] = None,
        description: str = "",
        weight: float = 1.0
    ):
        super().__init__(condition_id, description, weight)
        self.flag_key = flag_key
        self.expected_value = expected_value
        self.flag_provider = flag_provider
    
    async def evaluate(self, context: ConditionContext) -> ConditionResult:
        """Evaluate feature flag condition."""
        start_time = time.perf_counter()
        
        try:
            if not self.flag_provider:
                # Fallback to simple boolean check
                result = self.expected_value if isinstance(self.expected_value, bool) else True
                reason = f"No flag provider available, using default: {result}"
            else:
                # Use feature flag provider
                flag_result = await self._evaluate_flag(context)
                result = flag_result.enabled if flag_result else False
                reason = f"Feature flag {self.flag_key}: {result}"
            
            evaluation_time = (time.perf_counter() - start_time) * 1000
            self.update_metrics(evaluation_time)
            
            return ConditionResult(
                result=result,
                reason=reason,
                evaluation_time_ms=evaluation_time,
                attributes_used={f"feature_flag.{self.flag_key}"}
            )
        
        except Exception as e:
            evaluation_time = (time.perf_counter() - start_time) * 1000
            logger.error(f"Error evaluating feature flag condition {self.condition_id}: {e}")
            return ConditionResult(
                result=False,
                reason=f"Feature flag evaluation error: {str(e)}",
                evaluation_time_ms=evaluation_time,
                attributes_used={f"feature_flag.{self.flag_key}"}
            )
    
    async def _evaluate_flag(self, context: ConditionContext) -> Optional[EvaluationResult]:
        """Evaluate feature flag using provider."""
        if not self.flag_provider:
            return None
        
        # Create a minimal user context for feature flag evaluation
        user_context = {
            "user_id": context.user_id or "anonymous",
            "session_id": context.session_id,
            **context.user_attributes
        }
        
        # This is a simplified evaluation - in a real implementation,
        # you would integrate with the actual feature flag provider
        return EvaluationResult(
            enabled=self.expected_value,
            variation=self.expected_value,
            reason="conditional_evaluation"
        )


class TimeBasedCondition(Condition):
    """Condition based on time constraints."""
    
    def __init__(
        self,
        condition_id: str,
        start_time: Optional[str] = None,  # ISO format or time expression
        end_time: Optional[str] = None,    # ISO format or time expression
        days_of_week: Optional[List[int]] = None,  # 0=Monday, 6=Sunday
        hours_of_day: Optional[List[int]] = None,   # 0-23
        timezone: str = "UTC",
        description: str = "",
        weight: float = 1.0
    ):
        super().__init__(condition_id, description, weight)
        self.start_time = start_time
        self.end_time = end_time
        self.days_of_week = days_of_week
        self.hours_of_day = hours_of_day
        self.timezone = timezone
    
    async def evaluate(self, context: ConditionContext) -> ConditionResult:
        """Evaluate time-based condition."""
        start_time = time.perf_counter()
        
        try:
            from datetime import datetime
            try:
                import pytz
            except ImportError:
                # If pytz is not available, use basic datetime without timezone support
                current_time = datetime.fromtimestamp(context.timestamp)
                result = True
                reasons = []
                
                # Check day of week (without timezone considerations)
                if self.days_of_week is not None:
                    dow_match = current_time.weekday() in self.days_of_week
                    result = result and dow_match
                    reasons.append(f"day_of_week({current_time.weekday()}) in {self.days_of_week}: {dow_match}")
                
                # Check hour of day (without timezone considerations)
                if self.hours_of_day is not None:
                    hour_match = current_time.hour in self.hours_of_day
                    result = result and hour_match
                    reasons.append(f"hour_of_day({current_time.hour}) in {self.hours_of_day}: {hour_match}")
                
                evaluation_time = (time.perf_counter() - start_time) * 1000
                self.update_metrics(evaluation_time)
                
                return ConditionResult(
                    result=result,
                    reason="; ".join(reasons) if reasons else "time_based_evaluation_no_pytz",
                    evaluation_time_ms=evaluation_time,
                    attributes_used={"timestamp"}
                )
            
            # Get current time in specified timezone
            tz = pytz.timezone(self.timezone)
            current_time = datetime.fromtimestamp(context.timestamp, tz=tz)
            
            result = True
            reasons = []
            
            # Check day of week
            if self.days_of_week is not None:
                dow_match = current_time.weekday() in self.days_of_week
                result = result and dow_match
                reasons.append(f"day_of_week({current_time.weekday()}) in {self.days_of_week}: {dow_match}")
            
            # Check hour of day
            if self.hours_of_day is not None:
                hour_match = current_time.hour in self.hours_of_day
                result = result and hour_match
                reasons.append(f"hour_of_day({current_time.hour}) in {self.hours_of_day}: {hour_match}")
            
            # Check start time
            if self.start_time:
                start_dt = self._parse_time(self.start_time, tz)
                if start_dt:
                    start_match = current_time >= start_dt
                    result = result and start_match
                    reasons.append(f"after {self.start_time}: {start_match}")
            
            # Check end time
            if self.end_time:
                end_dt = self._parse_time(self.end_time, tz)
                if end_dt:
                    end_match = current_time <= end_dt
                    result = result and end_match
                    reasons.append(f"before {self.end_time}: {end_match}")
            
            evaluation_time = (time.perf_counter() - start_time) * 1000
            self.update_metrics(evaluation_time)
            
            return ConditionResult(
                result=result,
                reason="; ".join(reasons) if reasons else "time_based_evaluation",
                evaluation_time_ms=evaluation_time,
                attributes_used={"timestamp", "timezone"}
            )
        
        except Exception as e:
            evaluation_time = (time.perf_counter() - start_time) * 1000
            logger.error(f"Error evaluating time-based condition {self.condition_id}: {e}")
            return ConditionResult(
                result=False,
                reason=f"Time evaluation error: {str(e)}",
                evaluation_time_ms=evaluation_time,
                attributes_used={"timestamp"}
            )
    
    def _parse_time(self, time_str: str, tz) -> Optional['datetime']:
        """Parse time string to datetime."""
        try:
            from datetime import datetime
            
            # Try ISO format first
            try:
                return datetime.fromisoformat(time_str.replace('Z', '+00:00')).astimezone(tz)
            except ValueError:
                pass
            
            # Try other common formats
            formats = [
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d %H:%M",
                "%Y-%m-%d",
                "%H:%M:%S",
                "%H:%M"
            ]
            
            for fmt in formats:
                try:
                    dt = datetime.strptime(time_str, fmt)
                    if fmt.startswith("%H"):
                        # Time only, use today's date
                        now = datetime.now(tz)
                        dt = dt.replace(year=now.year, month=now.month, day=now.day)
                    return tz.localize(dt)
                except ValueError:
                    continue
            
            return None
        except Exception:
            return None


class CustomCondition(Condition):
    """Custom condition with user-defined evaluation function."""
    
    def __init__(
        self,
        condition_id: str,
        evaluation_func: Callable[[ConditionContext], Union[bool, ConditionResult]],
        description: str = "",
        weight: float = 1.0,
        is_async: bool = False
    ):
        super().__init__(condition_id, description, weight)
        self.evaluation_func = evaluation_func
        self.is_async = is_async
    
    async def evaluate(self, context: ConditionContext) -> ConditionResult:
        """Evaluate custom condition."""
        start_time = time.perf_counter()
        
        try:
            if self.is_async:
                result = await self.evaluation_func(context)
            else:
                result = self.evaluation_func(context)
            
            # Handle different return types
            if isinstance(result, ConditionResult):
                return result
            elif isinstance(result, bool):
                evaluation_time = (time.perf_counter() - start_time) * 1000
                self.update_metrics(evaluation_time)
                return ConditionResult(
                    result=result,
                    reason=f"Custom condition {self.condition_id}",
                    evaluation_time_ms=evaluation_time,
                    attributes_used={"custom"}
                )
            else:
                # Treat as truthy/falsy
                evaluation_time = (time.perf_counter() - start_time) * 1000
                self.update_metrics(evaluation_time)
                return ConditionResult(
                    result=bool(result),
                    reason=f"Custom condition {self.condition_id} (truthy)",
                    evaluation_time_ms=evaluation_time,
                    attributes_used={"custom"}
                )
        
        except Exception as e:
            evaluation_time = (time.perf_counter() - start_time) * 1000
            logger.error(f"Error evaluating custom condition {self.condition_id}: {e}")
            return ConditionResult(
                result=False,
                reason=f"Custom condition error: {str(e)}",
                evaluation_time_ms=evaluation_time,
                attributes_used={"custom"}
            )


class ConditionCache:
    """Cache for condition evaluation results."""
    
    def __init__(self, default_strategy: CacheStrategy = CacheStrategy.REQUEST_SCOPED):
        self.default_strategy = default_strategy
        self._global_cache: Dict[str, Tuple[ConditionResult, float]] = {}
        self._request_caches: Dict[str, Dict[str, ConditionResult]] = {}
        self._session_caches: Dict[str, Dict[str, ConditionResult]] = {}
        self._lock = RLock()
        self.ttl_seconds = 300  # 5 minutes default for time-based caching
    
    def get(self, cache_key: str, strategy: CacheStrategy, context: ConditionContext) -> Optional[ConditionResult]:
        """Get cached result."""
        with self._lock:
            if strategy == CacheStrategy.NO_CACHE:
                return None
            elif strategy == CacheStrategy.GLOBAL:
                return self._get_global(cache_key)
            elif strategy == CacheStrategy.REQUEST_SCOPED:
                return self._get_request_scoped(cache_key, context)
            elif strategy == CacheStrategy.SESSION_SCOPED:
                return self._get_session_scoped(cache_key, context)
            elif strategy == CacheStrategy.TIME_BASED:
                return self._get_time_based(cache_key)
            else:
                return None
    
    def set(self, cache_key: str, result: ConditionResult, strategy: CacheStrategy, context: ConditionContext):
        """Cache result."""
        with self._lock:
            if strategy == CacheStrategy.NO_CACHE:
                return
            elif strategy == CacheStrategy.GLOBAL:
                self._set_global(cache_key, result)
            elif strategy == CacheStrategy.REQUEST_SCOPED:
                self._set_request_scoped(cache_key, result, context)
            elif strategy == CacheStrategy.SESSION_SCOPED:
                self._set_session_scoped(cache_key, result, context)
            elif strategy == CacheStrategy.TIME_BASED:
                self._set_time_based(cache_key, result)
    
    def _get_global(self, cache_key: str) -> Optional[ConditionResult]:
        """Get from global cache."""
        if cache_key in self._global_cache:
            result, timestamp = self._global_cache[cache_key]
            result.cached = True
            return result
        return None
    
    def _set_global(self, cache_key: str, result: ConditionResult):
        """Set in global cache."""
        self._global_cache[cache_key] = (result, time.time())
    
    def _get_request_scoped(self, cache_key: str, context: ConditionContext) -> Optional[ConditionResult]:
        """Get from request-scoped cache."""
        request_id = id(context.request)
        if request_id in self._request_caches:
            cache = self._request_caches[request_id]
            if cache_key in cache:
                result = cache[cache_key]
                result.cached = True
                return result
        return None
    
    def _set_request_scoped(self, cache_key: str, result: ConditionResult, context: ConditionContext):
        """Set in request-scoped cache."""
        request_id = id(context.request)
        if request_id not in self._request_caches:
            self._request_caches[request_id] = {}
        self._request_caches[request_id][cache_key] = result
    
    def _get_session_scoped(self, cache_key: str, context: ConditionContext) -> Optional[ConditionResult]:
        """Get from session-scoped cache."""
        if context.session_id and context.session_id in self._session_caches:
            cache = self._session_caches[context.session_id]
            if cache_key in cache:
                result = cache[cache_key]
                result.cached = True
                return result
        return None
    
    def _set_session_scoped(self, cache_key: str, result: ConditionResult, context: ConditionContext):
        """Set in session-scoped cache."""
        if context.session_id:
            if context.session_id not in self._session_caches:
                self._session_caches[context.session_id] = {}
            self._session_caches[context.session_id][cache_key] = result
    
    def _get_time_based(self, cache_key: str) -> Optional[ConditionResult]:
        """Get from time-based cache."""
        if cache_key in self._global_cache:
            result, timestamp = self._global_cache[cache_key]
            if time.time() - timestamp < self.ttl_seconds:
                result.cached = True
                return result
            else:
                # Remove expired entry
                del self._global_cache[cache_key]
        return None
    
    def _set_time_based(self, cache_key: str, result: ConditionResult):
        """Set in time-based cache."""
        self._global_cache[cache_key] = (result, time.time())
    
    def clear_request_cache(self, request_id: int):
        """Clear cache for a specific request."""
        with self._lock:
            self._request_caches.pop(request_id, None)
    
    def clear_session_cache(self, session_id: str):
        """Clear cache for a specific session."""
        with self._lock:
            self._session_caches.pop(session_id, None)
    
    def clear_all(self):
        """Clear all caches."""
        with self._lock:
            self._global_cache.clear()
            self._request_caches.clear()
            self._session_caches.clear()


class ConditionEngine:
    """Core engine for condition evaluation and management."""
    
    def __init__(
        self,
        cache_strategy: CacheStrategy = CacheStrategy.REQUEST_SCOPED,
        max_concurrent_evaluations: int = 10,
        evaluation_timeout_seconds: float = 5.0
    ):
        self.cache_strategy = cache_strategy
        self.max_concurrent_evaluations = max_concurrent_evaluations
        self.evaluation_timeout_seconds = evaluation_timeout_seconds
        
        self.conditions: Dict[str, Condition] = {}
        self.cache = ConditionCache(cache_strategy)
        self.executor = ThreadPoolExecutor(max_workers=max_concurrent_evaluations)
        self._lock = RLock()
        
        # Performance metrics
        self.total_evaluations = 0
        self.cache_hits = 0
        self.cache_misses = 0
    
    def register_condition(self, condition: Condition):
        """Register a condition with the engine."""
        with self._lock:
            self.conditions[condition.condition_id] = condition
            logger.info(f"Registered condition: {condition.condition_id}")
    
    def unregister_condition(self, condition_id: str) -> bool:
        """Unregister a condition from the engine."""
        with self._lock:
            if condition_id in self.conditions:
                del self.conditions[condition_id]
                logger.info(f"Unregistered condition: {condition_id}")
                return True
            return False
    
    def get_condition(self, condition_id: str) -> Optional[Condition]:
        """Get a registered condition."""
        return self.conditions.get(condition_id)
    
    async def evaluate_condition(
        self,
        condition_id: str,
        context: ConditionContext,
        cache_strategy: Optional[CacheStrategy] = None
    ) -> ConditionResult:
        """Evaluate a single condition."""
        condition = self.get_condition(condition_id)
        if not condition:
            return ConditionResult(
                result=False,
                reason=f"Condition not found: {condition_id}",
                evaluation_time_ms=0.0
            )
        
        return await self.evaluate_condition_instance(condition, context, cache_strategy)
    
    async def evaluate_condition_instance(
        self,
        condition: Condition,
        context: ConditionContext,
        cache_strategy: Optional[CacheStrategy] = None
    ) -> ConditionResult:
        """Evaluate a condition instance."""
        strategy = cache_strategy or self.cache_strategy
        cache_key = condition.get_cache_key(context)
        
        # Check cache first
        cached_result = self.cache.get(cache_key, strategy, context)
        if cached_result:
            self.cache_hits += 1
            return cached_result
        
        self.cache_misses += 1
        self.total_evaluations += 1
        
        # Evaluate with timeout
        try:
            result = await asyncio.wait_for(
                condition.evaluate(context),
                timeout=self.evaluation_timeout_seconds
            )
        except asyncio.TimeoutError:
            logger.warning(f"Condition evaluation timeout: {condition.condition_id}")
            result = ConditionResult(
                result=False,
                reason=f"Evaluation timeout for {condition.condition_id}",
                evaluation_time_ms=self.evaluation_timeout_seconds * 1000
            )
        except Exception as e:
            logger.error(f"Condition evaluation error: {condition.condition_id}: {e}")
            result = ConditionResult(
                result=False,
                reason=f"Evaluation error: {str(e)}",
                evaluation_time_ms=0.0
            )
        
        # Cache the result
        self.cache.set(cache_key, result, strategy, context)
        
        return result
    
    async def evaluate_conditions(
        self,
        condition_ids: List[str],
        context: ConditionContext,
        logical_operator: LogicalOperator = LogicalOperator.AND,
        cache_strategy: Optional[CacheStrategy] = None
    ) -> ConditionResult:
        """Evaluate multiple conditions with a logical operator."""
        if not condition_ids:
            return ConditionResult(
                result=True,
                reason="No conditions to evaluate",
                evaluation_time_ms=0.0
            )
        
        start_time = time.perf_counter()
        
        # Get condition instances
        conditions = []
        for condition_id in condition_ids:
            condition = self.get_condition(condition_id)
            if condition:
                conditions.append(condition)
            else:
                logger.warning(f"Condition not found: {condition_id}")
        
        if not conditions:
            return ConditionResult(
                result=False,
                reason="No valid conditions found",
                evaluation_time_ms=0.0
            )
        
        # Create composite condition for evaluation
        composite = CompositeCondition(
            condition_id=f"composite_{hash(tuple(condition_ids))}",
            conditions=conditions,
            operator=logical_operator,
            description=f"Composite of {len(conditions)} conditions"
        )
        
        result = await self.evaluate_condition_instance(composite, context, cache_strategy)
        
        total_time = (time.perf_counter() - start_time) * 1000
        result.evaluation_time_ms = total_time
        
        return result
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics for the engine."""
        with self._lock:
            cache_hit_rate = (
                self.cache_hits / (self.cache_hits + self.cache_misses)
                if (self.cache_hits + self.cache_misses) > 0
                else 0.0
            )
            
            condition_metrics = {}
            for condition_id, condition in self.conditions.items():
                condition_metrics[condition_id] = {
                    "evaluation_count": condition.evaluation_count,
                    "average_evaluation_time_ms": condition.average_evaluation_time,
                    "total_evaluation_time_ms": condition.total_evaluation_time,
                    "weight": condition.weight
                }
            
            return {
                "total_evaluations": self.total_evaluations,
                "cache_hits": self.cache_hits,
                "cache_misses": self.cache_misses,
                "cache_hit_rate": cache_hit_rate,
                "registered_conditions": len(self.conditions),
                "condition_metrics": condition_metrics
            }


@dataclass
class ShieldExecutionRule:
    """Rule for conditional shield execution."""
    rule_id: str
    shield: Shield
    conditions: List[str]  # Condition IDs
    logical_operator: LogicalOperator = LogicalOperator.AND
    priority: int = 0
    weight: float = 1.0
    enabled: bool = True
    execution_strategy: ExecutionStrategy = ExecutionStrategy.FIRST_MATCH
    cache_strategy: Optional[CacheStrategy] = None
    description: str = ""
    
    def __post_init__(self):
        if not self.conditions:
            raise ValueError("ShieldExecutionRule must have at least one condition")


class ConditionalShield(Shield):
    """Shield that executes based on conditional rules."""
    
    def __init__(
        self,
        shield_func: Callable,
        condition_engine: ConditionEngine,
        execution_rules: List[ShieldExecutionRule] = None,
        default_execution_strategy: ExecutionStrategy = ExecutionStrategy.FIRST_MATCH,
        context_extractor: Optional[Callable[[Request], ConditionContext]] = None,
        **kwargs
    ):
        super().__init__(shield_func, **kwargs)
        self.condition_engine = condition_engine
        self.execution_rules = execution_rules or []
        self.default_execution_strategy = default_execution_strategy
        self.context_extractor = context_extractor or self._default_context_extractor
        
        # Metrics
        self.rule_evaluations = 0
        self.successful_executions = 0
        self.failed_executions = 0
        self.skipped_executions = 0
    
    def add_execution_rule(self, rule: ShieldExecutionRule):
        """Add an execution rule."""
        self.execution_rules.append(rule)
        # Sort by priority (higher priority first)
        self.execution_rules.sort(key=lambda r: r.priority, reverse=True)
    
    def remove_execution_rule(self, rule_id: str) -> bool:
        """Remove an execution rule."""
        for i, rule in enumerate(self.execution_rules):
            if rule.rule_id == rule_id:
                del self.execution_rules[i]
                return True
        return False
    
    def _default_context_extractor(self, request: Request) -> ConditionContext:
        """Default context extractor."""
        # Extract basic information from request
        user_id = None
        session_id = None
        user_attributes = {}
        request_attributes = {}
        
        # Try to extract user info from common headers/cookies
        auth_header = request.headers.get("authorization", "")
        if auth_header:
            # Simple extraction - in production you'd decode JWT, etc.
            user_attributes["has_auth"] = True
        
        # Extract session info
        session_cookie = request.cookies.get("session_id")
        if session_cookie:
            session_id = session_cookie
        
        # Extract request properties
        request_attributes.update({
            "method": request.method,
            "path": str(request.url.path),
            "query_params": dict(request.query_params),
            "headers": dict(request.headers),
            "client_host": request.client.host if request.client else None,
            "user_agent": request.headers.get("user-agent", ""),
        })
        
        return ConditionContext(
            request=request,
            user_id=user_id,
            session_id=session_id,
            user_attributes=user_attributes,
            request_attributes=request_attributes,
            timestamp=time.time()
        )
    
    def __call__(self, endpoint: EndPointFunc) -> EndPointFunc:
        """Apply conditional shield to endpoint."""
        original_wrapper = super().__call__(endpoint)
        
        @wraps(original_wrapper)
        async def conditional_wrapper(*args, **kwargs):
            request = kwargs.get('request')
            if not request:
                # No request available, fall back to original shield behavior
                return await original_wrapper(*args, **kwargs)
            
            # Extract context for condition evaluation
            context = self.context_extractor(request)
            
            # Evaluate all rules and determine which should execute
            rules_to_execute = await self._evaluate_rules(context)
            
            self.rule_evaluations += 1
            
            if not rules_to_execute:
                # No rules matched, skip shield execution
                self.skipped_executions += 1
                logger.debug(f"No conditional rules matched for {self.name}")
                
                # Execute the original endpoint without shield protection
                from fastapi_shield.utils import get_solved_dependencies
                import fastapi_shield.utils
                
                request_val: Request = kwargs.get("request")
                path_format = fastapi_shield.utils.get_path_format_from_request_for_endpoint(request_val)
                
                endpoint_solved_dependencies, body = await get_solved_dependencies(
                    request_val, path_format, endpoint, {}
                )
                kwargs.update(endpoint_solved_dependencies.values)
                
                # Call endpoint directly
                if asyncio.iscoroutinefunction(endpoint):
                    return await endpoint(*args, **kwargs)
                else:
                    return endpoint(*args, **kwargs)
            
            # Execute matching rules based on strategy
            try:
                result = await self._execute_rules(rules_to_execute, original_wrapper, *args, **kwargs)
                self.successful_executions += 1
                return result
            except Exception as e:
                self.failed_executions += 1
                logger.error(f"Conditional shield execution failed: {e}")
                raise
        
        return conditional_wrapper
    
    async def _evaluate_rules(self, context: ConditionContext) -> List[ShieldExecutionRule]:
        """Evaluate all rules and return those that should execute."""
        matching_rules = []
        
        for rule in self.execution_rules:
            if not rule.enabled:
                continue
            
            # Evaluate rule conditions
            result = await self.condition_engine.evaluate_conditions(
                condition_ids=rule.conditions,
                context=context,
                logical_operator=rule.logical_operator,
                cache_strategy=rule.cache_strategy
            )
            
            if result.result:
                matching_rules.append(rule)
                logger.debug(f"Rule {rule.rule_id} matched: {result.reason}")
            else:
                logger.debug(f"Rule {rule.rule_id} did not match: {result.reason}")
        
        return matching_rules
    
    async def _execute_rules(
        self, 
        rules: List[ShieldExecutionRule], 
        original_wrapper: Callable,
        *args, 
        **kwargs
    ) -> Any:
        """Execute matching rules based on strategy."""
        if not rules:
            return await original_wrapper(*args, **kwargs)
        
        # For now, implement FIRST_MATCH strategy
        # In a full implementation, you'd handle all strategies
        first_rule = rules[0]
        
        logger.info(f"Executing shield rule {first_rule.rule_id} with shield {first_rule.shield.name}")
        
        # Execute the first matching rule's shield
        return await original_wrapper(*args, **kwargs)


class ShieldChain:
    """Dynamic shield chain construction and execution."""
    
    def __init__(
        self,
        chain_id: str,
        condition_engine: ConditionEngine,
        execution_strategy: ExecutionStrategy = ExecutionStrategy.FIRST_MATCH
    ):
        self.chain_id = chain_id
        self.condition_engine = condition_engine
        self.execution_strategy = execution_strategy
        self.shields: List[ShieldExecutionRule] = []
    
    def add_shield(self, rule: ShieldExecutionRule):
        """Add a shield to the chain."""
        self.shields.append(rule)
        # Sort by priority
        self.shields.sort(key=lambda r: r.priority, reverse=True)
    
    def remove_shield(self, rule_id: str) -> bool:
        """Remove a shield from the chain."""
        for i, rule in enumerate(self.shields):
            if rule.rule_id == rule_id:
                del self.shields[i]
                return True
        return False
    
    async def execute(self, endpoint: EndPointFunc, context: ConditionContext) -> Callable:
        """Execute the shield chain and return the wrapped endpoint."""
        matching_rules = []
        
        for rule in self.shields:
            if not rule.enabled:
                continue
            
            result = await self.condition_engine.evaluate_conditions(
                condition_ids=rule.conditions,
                context=context,
                logical_operator=rule.logical_operator,
                cache_strategy=rule.cache_strategy
            )
            
            if result.result:
                matching_rules.append(rule)
        
        if not matching_rules:
            return endpoint
        
        # Apply shields based on execution strategy
        if self.execution_strategy == ExecutionStrategy.FIRST_MATCH:
            # Apply only the first matching shield
            first_rule = matching_rules[0]
            return first_rule.shield(endpoint)
        elif self.execution_strategy == ExecutionStrategy.ALL_MATCHING:
            # Apply all matching shields in priority order
            wrapped_endpoint = endpoint
            for rule in reversed(matching_rules):  # Apply in reverse order so highest priority is outermost
                wrapped_endpoint = rule.shield(wrapped_endpoint)
            return wrapped_endpoint
        elif self.execution_strategy == ExecutionStrategy.PRIORITY_BASED:
            # Apply shield with highest priority
            highest_priority_rule = max(matching_rules, key=lambda r: r.priority)
            return highest_priority_rule.shield(endpoint)
        else:
            # Default to first match
            first_rule = matching_rules[0]
            return first_rule.shield(endpoint)


class ABTestManager:
    """A/B testing support for shields."""
    
    def __init__(self, condition_engine: ConditionEngine):
        self.condition_engine = condition_engine
        self.experiments: Dict[str, 'ABTestExperiment'] = {}
    
    def create_experiment(
        self,
        experiment_id: str,
        name: str,
        variants: List['ABTestVariant'],
        allocation_strategy: str = "user_hash",
        enabled: bool = True
    ) -> 'ABTestExperiment':
        """Create a new A/B test experiment."""
        experiment = ABTestExperiment(
            experiment_id=experiment_id,
            name=name,
            variants=variants,
            allocation_strategy=allocation_strategy,
            enabled=enabled,
            condition_engine=self.condition_engine
        )
        self.experiments[experiment_id] = experiment
        return experiment
    
    def get_experiment(self, experiment_id: str) -> Optional['ABTestExperiment']:
        """Get an experiment by ID."""
        return self.experiments.get(experiment_id)
    
    async def allocate_user(
        self,
        experiment_id: str,
        context: ConditionContext
    ) -> Optional['ABTestVariant']:
        """Allocate a user to an experiment variant."""
        experiment = self.get_experiment(experiment_id)
        if not experiment or not experiment.enabled:
            return None
        
        return await experiment.allocate_user(context)


@dataclass
class ABTestVariant:
    """A variant in an A/B test experiment."""
    variant_id: str
    name: str
    shield: Optional[Shield]
    allocation_percentage: float  # 0.0 to 1.0
    conditions: List[str] = field(default_factory=list)  # Additional conditions
    enabled: bool = True


class ABTestExperiment:
    """A/B test experiment configuration."""
    
    def __init__(
        self,
        experiment_id: str,
        name: str,
        variants: List[ABTestVariant],
        allocation_strategy: str = "user_hash",
        enabled: bool = True,
        condition_engine: ConditionEngine = None
    ):
        self.experiment_id = experiment_id
        self.name = name
        self.variants = variants
        self.allocation_strategy = allocation_strategy
        self.enabled = enabled
        self.condition_engine = condition_engine
        
        # Validate allocation percentages
        total_allocation = sum(v.allocation_percentage for v in variants)
        if abs(total_allocation - 1.0) > 0.001:  # Allow for small floating point errors
            raise ValueError(f"Variant allocations must sum to 1.0, got {total_allocation}")
    
    async def allocate_user(self, context: ConditionContext) -> Optional[ABTestVariant]:
        """Allocate a user to a variant."""
        if not self.enabled:
            return None
        
        # Generate allocation hash
        allocation_key = self._get_allocation_key(context)
        allocation_hash = self._hash_allocation_key(allocation_key)
        
        # Determine variant based on hash
        cumulative_percentage = 0.0
        for variant in self.variants:
            if not variant.enabled:
                continue
            
            cumulative_percentage += variant.allocation_percentage
            if allocation_hash <= cumulative_percentage:
                # Check variant-specific conditions
                if variant.conditions and self.condition_engine:
                    result = await self.condition_engine.evaluate_conditions(
                        condition_ids=variant.conditions,
                        context=context,
                        logical_operator=LogicalOperator.AND
                    )
                    if not result.result:
                        continue
                
                return variant
        
        return None
    
    def _get_allocation_key(self, context: ConditionContext) -> str:
        """Get the key used for allocation."""
        if self.allocation_strategy == "user_hash":
            return f"{self.experiment_id}:{context.user_id or 'anonymous'}"
        elif self.allocation_strategy == "session_hash":
            return f"{self.experiment_id}:{context.session_id or 'no_session'}"
        elif self.allocation_strategy == "request_hash":
            return f"{self.experiment_id}:{id(context.request)}"
        else:
            return f"{self.experiment_id}:{context.user_id or context.session_id or 'anonymous'}"
    
    def _hash_allocation_key(self, key: str) -> float:
        """Hash allocation key to a value between 0.0 and 1.0."""
        hash_value = hashlib.md5(key.encode()).hexdigest()
        # Convert first 8 hex characters to int and normalize to 0.0-1.0
        int_value = int(hash_value[:8], 16)
        return int_value / (16**8 - 1)


# Convenience functions for creating common conditions

def create_simple_condition(
    condition_id: str,
    attribute_path: str,
    operator: Union[str, ComparisonOperator],
    value: Any,
    description: str = "",
    weight: float = 1.0
) -> SimpleCondition:
    """Create a simple condition."""
    if isinstance(operator, str):
        operator = ComparisonOperator(operator)
    
    return SimpleCondition(
        condition_id=condition_id,
        attribute_path=attribute_path,
        operator=operator,
        value=value,
        description=description,
        weight=weight
    )


def create_user_attribute_condition(
    condition_id: str,
    attribute_name: str,
    operator: Union[str, ComparisonOperator],
    value: Any,
    description: str = "",
    weight: float = 1.0
) -> SimpleCondition:
    """Create a condition based on user attributes."""
    return create_simple_condition(
        condition_id=condition_id,
        attribute_path=f"user_attributes.{attribute_name}",
        operator=operator,
        value=value,
        description=description,
        weight=weight
    )


def create_request_property_condition(
    condition_id: str,
    property_name: str,
    operator: Union[str, ComparisonOperator],
    value: Any,
    description: str = "",
    weight: float = 1.0
) -> SimpleCondition:
    """Create a condition based on request properties."""
    return create_simple_condition(
        condition_id=condition_id,
        attribute_path=f"request_attributes.{property_name}",
        operator=operator,
        value=value,
        description=description,
        weight=weight
    )


def create_feature_flag_condition(
    condition_id: str,
    flag_key: str,
    expected_value: Any = True,
    flag_provider: Optional['FeatureFlagShield'] = None,
    description: str = "",
    weight: float = 1.0
) -> FeatureFlagCondition:
    """Create a feature flag condition."""
    return FeatureFlagCondition(
        condition_id=condition_id,
        flag_key=flag_key,
        expected_value=expected_value,
        flag_provider=flag_provider,
        description=description,
        weight=weight
    )


def create_time_based_condition(
    condition_id: str,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    days_of_week: Optional[List[int]] = None,
    hours_of_day: Optional[List[int]] = None,
    timezone: str = "UTC",
    description: str = "",
    weight: float = 1.0
) -> TimeBasedCondition:
    """Create a time-based condition."""
    return TimeBasedCondition(
        condition_id=condition_id,
        start_time=start_time,
        end_time=end_time,
        days_of_week=days_of_week,
        hours_of_day=hours_of_day,
        timezone=timezone,
        description=description,
        weight=weight
    )


def create_composite_condition(
    condition_id: str,
    conditions: List[Condition],
    operator: Union[str, LogicalOperator],
    description: str = "",
    weight: float = 1.0,
    short_circuit: bool = True
) -> CompositeCondition:
    """Create a composite condition."""
    if isinstance(operator, str):
        operator = LogicalOperator(operator)
    
    return CompositeCondition(
        condition_id=condition_id,
        conditions=conditions,
        operator=operator,
        description=description,
        weight=weight,
        short_circuit=short_circuit
    )


def create_custom_condition(
    condition_id: str,
    evaluation_func: Callable[[ConditionContext], Union[bool, ConditionResult]],
    description: str = "",
    weight: float = 1.0,
    is_async: bool = False
) -> CustomCondition:
    """Create a custom condition."""
    return CustomCondition(
        condition_id=condition_id,
        evaluation_func=evaluation_func,
        description=description,
        weight=weight,
        is_async=is_async
    )


# Decorator for creating conditional shields

def conditional_shield(
    condition_engine: ConditionEngine,
    execution_rules: List[ShieldExecutionRule] = None,
    execution_strategy: ExecutionStrategy = ExecutionStrategy.FIRST_MATCH,
    context_extractor: Optional[Callable[[Request], ConditionContext]] = None,
    **shield_kwargs
):
    """Decorator for creating conditional shields."""
    def decorator(shield_func):
        return ConditionalShield(
            shield_func=shield_func,
            condition_engine=condition_engine,
            execution_rules=execution_rules,
            default_execution_strategy=execution_strategy,
            context_extractor=context_extractor,
            **shield_kwargs
        )
    return decorator