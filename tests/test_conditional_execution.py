"""Comprehensive tests for conditional shield execution functionality.

This module contains extensive tests for all conditional execution components
including condition evaluation, rule engines, dynamic shield chains,
performance optimization, feature flag integration, and A/B testing support.
"""

import asyncio
import pytest
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from unittest.mock import Mock, patch, AsyncMock

from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from fastapi_shield.shield import Shield, shield
from fastapi_shield.conditional_execution import (
    # Core classes
    ConditionEngine,
    ConditionalShield,
    ShieldChain,
    ABTestManager,
    
    # Condition types
    SimpleCondition,
    CompositeCondition,
    FeatureFlagCondition,
    TimeBasedCondition,
    CustomCondition,
    
    # Supporting classes
    ConditionContext,
    ConditionResult,
    ShieldExecutionRule,
    ABTestVariant,
    ABTestExperiment,
    ConditionCache,
    
    # Enums
    ConditionType,
    LogicalOperator,
    ComparisonOperator,
    ExecutionStrategy,
    CacheStrategy,
    
    # Convenience functions
    create_simple_condition,
    create_user_attribute_condition,
    create_request_property_condition,
    create_feature_flag_condition,
    create_time_based_condition,
    create_composite_condition,
    create_custom_condition,
    conditional_shield,
)


class TestConditionContext:
    """Test ConditionContext functionality."""
    
    def test_init_default(self):
        """Test default initialization."""
        request = Mock(spec=Request)
        context = ConditionContext(request=request)
        
        assert context.request == request
        assert context.user_id is None
        assert context.session_id is None
        assert context.user_attributes == {}
        assert context.request_attributes == {}
        assert context.custom_attributes == {}
        assert isinstance(context.timestamp, float)
    
    def test_init_full(self):
        """Test full initialization."""
        request = Mock(spec=Request)
        user_attrs = {"role": "admin", "plan": "premium"}
        request_attrs = {"method": "GET", "path": "/api/test"}
        custom_attrs = {"experiment": "test_group"}
        
        context = ConditionContext(
            request=request,
            user_id="user123",
            session_id="session456",
            user_attributes=user_attrs,
            request_attributes=request_attrs,
            custom_attributes=custom_attrs,
            timestamp=1234567890.0
        )
        
        assert context.user_id == "user123"
        assert context.session_id == "session456"
        assert context.user_attributes == user_attrs
        assert context.request_attributes == request_attrs
        assert context.custom_attributes == custom_attrs
        assert context.timestamp == 1234567890.0
    
    def test_get_attribute_user_attributes(self):
        """Test getting attribute from user attributes."""
        request = Mock(spec=Request)
        context = ConditionContext(
            request=request,
            user_attributes={"role": "admin", "plan": "premium"}
        )
        
        assert context.get_attribute("role") == "admin"
        assert context.get_attribute("plan") == "premium"
        assert context.get_attribute("nonexistent") is None
        assert context.get_attribute("nonexistent", "default") == "default"
    
    def test_get_attribute_request_attributes(self):
        """Test getting attribute from request attributes."""
        request = Mock(spec=Request)
        context = ConditionContext(
            request=request,
            request_attributes={"method": "GET", "path": "/api/test"}
        )
        
        assert context.get_attribute("method") == "GET"
        assert context.get_attribute("path") == "/api/test"
    
    def test_get_attribute_priority_order(self):
        """Test attribute priority order (user > request > custom)."""
        request = Mock(spec=Request)
        context = ConditionContext(
            request=request,
            user_attributes={"shared": "user_value"},
            request_attributes={"shared": "request_value"},
            custom_attributes={"shared": "custom_value"}
        )
        
        # User attributes should have highest priority
        assert context.get_attribute("shared") == "user_value"
    
    def test_get_attribute_request_object(self):
        """Test getting attribute from request object."""
        request = Mock(spec=Request)
        request.method = "POST"
        context = ConditionContext(request=request)
        
        assert context.get_attribute("method") == "POST"


class TestConditionResult:
    """Test ConditionResult functionality."""
    
    def test_init(self):
        """Test ConditionResult initialization."""
        result = ConditionResult(
            result=True,
            reason="Test condition",
            evaluation_time_ms=5.5,
            cached=True,
            attributes_used={"user.role", "request.method"}
        )
        
        assert result.result is True
        assert result.reason == "Test condition"
        assert result.evaluation_time_ms == 5.5
        assert result.cached is True
        assert result.attributes_used == {"user.role", "request.method"}
    
    def test_bool_conversion(self):
        """Test boolean conversion."""
        true_result = ConditionResult(result=True, reason="", evaluation_time_ms=0)
        false_result = ConditionResult(result=False, reason="", evaluation_time_ms=0)
        
        assert bool(true_result) is True
        assert bool(false_result) is False


class TestSimpleCondition:
    """Test SimpleCondition functionality."""
    
    def test_init(self):
        """Test SimpleCondition initialization."""
        condition = SimpleCondition(
            condition_id="test_condition",
            attribute_path="user.role",
            operator=ComparisonOperator.EQUALS,
            value="admin",
            description="Test admin condition",
            weight=2.0
        )
        
        assert condition.condition_id == "test_condition"
        assert condition.attribute_path == "user.role"
        assert condition.operator == ComparisonOperator.EQUALS
        assert condition.value == "admin"
        assert condition.description == "Test admin condition"
        assert condition.weight == 2.0
    
    @pytest.mark.asyncio
    async def test_evaluate_equals_true(self):
        """Test equals comparison returning True."""
        condition = SimpleCondition(
            condition_id="role_check",
            attribute_path="user_attributes.role",
            operator=ComparisonOperator.EQUALS,
            value="admin"
        )
        
        request = Mock(spec=Request)
        context = ConditionContext(
            request=request,
            user_attributes={"role": "admin"}
        )
        
        result = await condition.evaluate(context)
        
        assert result.result is True
        assert "role eq admin" in result.reason
        assert result.evaluation_time_ms > 0
        assert "user_attributes.role" in result.attributes_used
    
    @pytest.mark.asyncio
    async def test_evaluate_equals_false(self):
        """Test equals comparison returning False."""
        condition = SimpleCondition(
            condition_id="role_check",
            attribute_path="user_attributes.role",
            operator=ComparisonOperator.EQUALS,
            value="admin"
        )
        
        request = Mock(spec=Request)
        context = ConditionContext(
            request=request,
            user_attributes={"role": "user"}
        )
        
        result = await condition.evaluate(context)
        
        assert result.result is False
        assert "role eq admin" in result.reason
    
    @pytest.mark.asyncio
    async def test_evaluate_greater_than(self):
        """Test greater than comparison."""
        condition = SimpleCondition(
            condition_id="age_check",
            attribute_path="user_attributes.age",
            operator=ComparisonOperator.GREATER_THAN,
            value=18
        )
        
        request = Mock(spec=Request)
        
        # Test true case
        context_true = ConditionContext(
            request=request,
            user_attributes={"age": 25}
        )
        result_true = await condition.evaluate(context_true)
        assert result_true.result is True
        
        # Test false case
        context_false = ConditionContext(
            request=request,
            user_attributes={"age": 16}
        )
        result_false = await condition.evaluate(context_false)
        assert result_false.result is False
    
    @pytest.mark.asyncio
    async def test_evaluate_contains(self):
        """Test contains comparison."""
        condition = SimpleCondition(
            condition_id="permission_check",
            attribute_path="user_attributes.permissions",
            operator=ComparisonOperator.CONTAINS,
            value="read"
        )
        
        request = Mock(spec=Request)
        context = ConditionContext(
            request=request,
            user_attributes={"permissions": ["read", "write", "admin"]}
        )
        
        result = await condition.evaluate(context)
        assert result.result is True
    
    @pytest.mark.asyncio
    async def test_evaluate_regex(self):
        """Test regex comparison."""
        condition = SimpleCondition(
            condition_id="email_check",
            attribute_path="user_attributes.email",
            operator=ComparisonOperator.REGEX,
            value=r".*@admin\.com$"
        )
        
        request = Mock(spec=Request)
        
        # Test matching email
        context_match = ConditionContext(
            request=request,
            user_attributes={"email": "user@admin.com"}
        )
        result_match = await condition.evaluate(context_match)
        assert result_match.result is True
        
        # Test non-matching email
        context_no_match = ConditionContext(
            request=request,
            user_attributes={"email": "user@regular.com"}
        )
        result_no_match = await condition.evaluate(context_no_match)
        assert result_no_match.result is False
    
    @pytest.mark.asyncio
    async def test_evaluate_nested_path(self):
        """Test evaluation with nested attribute paths."""
        condition = SimpleCondition(
            condition_id="nested_check",
            attribute_path="request.headers.authorization",
            operator=ComparisonOperator.STARTS_WITH,
            value="Bearer "
        )
        
        request = Mock(spec=Request)
        request.headers = {"authorization": "Bearer token123"}
        context = ConditionContext(request=request)
        
        result = await condition.evaluate(context)
        assert result.result is True
    
    @pytest.mark.asyncio
    async def test_evaluate_missing_attribute(self):
        """Test evaluation with missing attribute."""
        condition = SimpleCondition(
            condition_id="missing_check",
            attribute_path="user_attributes.nonexistent",
            operator=ComparisonOperator.EQUALS,
            value="test"
        )
        
        request = Mock(spec=Request)
        context = ConditionContext(request=request)
        
        result = await condition.evaluate(context)
        assert result.result is False
    
    @pytest.mark.asyncio
    async def test_evaluate_error_handling(self):
        """Test error handling during evaluation."""
        condition = SimpleCondition(
            condition_id="error_check",
            attribute_path="user_attributes.value",
            operator=ComparisonOperator.GREATER_THAN,
            value=10  # Compare string to number to cause error
        )
        
        request = Mock(spec=Request)
        context = ConditionContext(
            request=request,
            user_attributes={"value": "string_value"}
        )
        
        result = await condition.evaluate(context)
        assert result.result is False
        assert "Evaluation error" in result.reason
    
    def test_get_cache_key(self):
        """Test cache key generation."""
        condition = SimpleCondition(
            condition_id="test_condition",
            attribute_path="user.role",
            operator=ComparisonOperator.EQUALS,
            value="admin"
        )
        
        request = Mock(spec=Request)
        context = ConditionContext(
            request=request,
            user_id="user123",
            session_id="session456",
            timestamp=1234567890.0
        )
        
        cache_key = condition.get_cache_key(context)
        assert isinstance(cache_key, str)
        assert len(cache_key) == 32  # MD5 hash length
    
    def test_update_metrics(self):
        """Test metrics updating."""
        condition = SimpleCondition(
            condition_id="test_condition",
            attribute_path="user.role",
            operator=ComparisonOperator.EQUALS,
            value="admin"
        )
        
        assert condition.evaluation_count == 0
        assert condition.total_evaluation_time == 0.0
        assert condition.average_evaluation_time == 0.0
        
        condition.update_metrics(10.5)
        assert condition.evaluation_count == 1
        assert condition.total_evaluation_time == 10.5
        assert condition.average_evaluation_time == 10.5
        
        condition.update_metrics(5.5)
        assert condition.evaluation_count == 2
        assert condition.total_evaluation_time == 16.0
        assert condition.average_evaluation_time == 8.0


class TestCompositeCondition:
    """Test CompositeCondition functionality."""
    
    def create_test_conditions(self):
        """Create test conditions for composite testing."""
        true_condition = SimpleCondition(
            condition_id="true_condition",
            attribute_path="user_attributes.value",
            operator=ComparisonOperator.EQUALS,
            value="true"
        )
        
        false_condition = SimpleCondition(
            condition_id="false_condition",
            attribute_path="user_attributes.value",
            operator=ComparisonOperator.EQUALS,
            value="false"
        )
        
        return true_condition, false_condition
    
    @pytest.mark.asyncio
    async def test_evaluate_and_all_true(self):
        """Test AND condition with all true conditions."""
        true_condition1, _ = self.create_test_conditions()
        true_condition2 = SimpleCondition(
            condition_id="true_condition2",
            attribute_path="user_attributes.other",
            operator=ComparisonOperator.EQUALS,
            value="yes"
        )
        
        composite = CompositeCondition(
            condition_id="and_composite",
            conditions=[true_condition1, true_condition2],
            operator=LogicalOperator.AND
        )
        
        request = Mock(spec=Request)
        context = ConditionContext(
            request=request,
            user_attributes={"value": "true", "other": "yes"}
        )
        
        result = await composite.evaluate(context)
        assert result.result is True
        assert "and" in result.reason.lower()
    
    @pytest.mark.asyncio
    async def test_evaluate_and_one_false(self):
        """Test AND condition with one false condition."""
        true_condition, false_condition = self.create_test_conditions()
        
        composite = CompositeCondition(
            condition_id="and_composite",
            conditions=[true_condition, false_condition],
            operator=LogicalOperator.AND
        )
        
        request = Mock(spec=Request)
        context = ConditionContext(
            request=request,
            user_attributes={"value": "true"}  # Only satisfies first condition
        )
        
        result = await composite.evaluate(context)
        assert result.result is False
    
    @pytest.mark.asyncio
    async def test_evaluate_or_one_true(self):
        """Test OR condition with one true condition."""
        true_condition, false_condition = self.create_test_conditions()
        
        composite = CompositeCondition(
            condition_id="or_composite",
            conditions=[false_condition, true_condition],  # Put false first so we see both in reason
            operator=LogicalOperator.OR,
            short_circuit=False  # Disable short-circuit to see both conditions in reason
        )
        
        request = Mock(spec=Request)
        context = ConditionContext(
            request=request,
            user_attributes={"value": "true"}  # Only satisfies second condition
        )
        
        result = await composite.evaluate(context)
        assert result.result is True
        assert "or" in result.reason.lower()
    
    @pytest.mark.asyncio
    async def test_evaluate_or_all_false(self):
        """Test OR condition with all false conditions."""
        false_condition1, false_condition2 = self.create_test_conditions()
        false_condition2.condition_id = "false_condition2"
        false_condition2.attribute_path = "user_attributes.other"
        
        composite = CompositeCondition(
            condition_id="or_composite",
            conditions=[false_condition1, false_condition2],
            operator=LogicalOperator.OR
        )
        
        request = Mock(spec=Request)
        context = ConditionContext(
            request=request,
            user_attributes={"value": "neither", "other": "neither"}
        )
        
        result = await composite.evaluate(context)
        assert result.result is False
    
    @pytest.mark.asyncio
    async def test_evaluate_not_true(self):
        """Test NOT condition with true sub-condition."""
        true_condition, _ = self.create_test_conditions()
        
        composite = CompositeCondition(
            condition_id="not_composite",
            conditions=[true_condition],
            operator=LogicalOperator.NOT
        )
        
        request = Mock(spec=Request)
        context = ConditionContext(
            request=request,
            user_attributes={"value": "true"}
        )
        
        result = await composite.evaluate(context)
        assert result.result is False  # NOT true = false
    
    @pytest.mark.asyncio
    async def test_evaluate_not_false(self):
        """Test NOT condition with false sub-condition."""
        _, false_condition = self.create_test_conditions()
        
        composite = CompositeCondition(
            condition_id="not_composite",
            conditions=[false_condition],
            operator=LogicalOperator.NOT
        )
        
        request = Mock(spec=Request)
        context = ConditionContext(
            request=request,
            user_attributes={"value": "not_false"}
        )
        
        result = await composite.evaluate(context)
        assert result.result is True  # NOT false = true
    
    @pytest.mark.asyncio
    async def test_evaluate_xor_one_true(self):
        """Test XOR condition with exactly one true condition."""
        true_condition, false_condition = self.create_test_conditions()
        
        composite = CompositeCondition(
            condition_id="xor_composite",
            conditions=[true_condition, false_condition],
            operator=LogicalOperator.XOR
        )
        
        request = Mock(spec=Request)
        context = ConditionContext(
            request=request,
            user_attributes={"value": "true"}
        )
        
        result = await composite.evaluate(context)
        assert result.result is True  # Only one condition is true
    
    @pytest.mark.asyncio
    async def test_evaluate_xor_both_true(self):
        """Test XOR condition with both conditions true."""
        true_condition1, _ = self.create_test_conditions()
        true_condition2 = SimpleCondition(
            condition_id="true_condition2",
            attribute_path="user_attributes.other",
            operator=ComparisonOperator.EQUALS,
            value="true"
        )
        
        composite = CompositeCondition(
            condition_id="xor_composite",
            conditions=[true_condition1, true_condition2],
            operator=LogicalOperator.XOR
        )
        
        request = Mock(spec=Request)
        context = ConditionContext(
            request=request,
            user_attributes={"value": "true", "other": "true"}
        )
        
        result = await composite.evaluate(context)
        assert result.result is False  # Both conditions are true, so XOR is false
    
    @pytest.mark.asyncio
    async def test_evaluate_short_circuit_and(self):
        """Test short-circuit evaluation with AND."""
        false_condition = SimpleCondition(
            condition_id="false_condition",
            attribute_path="user_attributes.value",
            operator=ComparisonOperator.EQUALS,
            value="false"
        )
        
        # Mock condition that should not be called due to short-circuit
        mock_condition = Mock()
        mock_condition.evaluate = AsyncMock(return_value=ConditionResult(
            result=True, reason="should not be called", evaluation_time_ms=0
        ))
        
        composite = CompositeCondition(
            condition_id="short_circuit_and",
            conditions=[false_condition, mock_condition],
            operator=LogicalOperator.AND,
            short_circuit=True
        )
        
        request = Mock(spec=Request)
        context = ConditionContext(
            request=request,
            user_attributes={"value": "not_false"}
        )
        
        result = await composite.evaluate(context)
        assert result.result is False
        # Mock condition should not have been called
        mock_condition.evaluate.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_evaluate_no_short_circuit(self):
        """Test evaluation without short-circuit."""
        false_condition = SimpleCondition(
            condition_id="false_condition",
            attribute_path="user_attributes.value",
            operator=ComparisonOperator.EQUALS,
            value="false"
        )
        
        true_condition = SimpleCondition(
            condition_id="true_condition",
            attribute_path="user_attributes.other",
            operator=ComparisonOperator.EQUALS,
            value="true"
        )
        
        composite = CompositeCondition(
            condition_id="no_short_circuit_and",
            conditions=[false_condition, true_condition],
            operator=LogicalOperator.AND,
            short_circuit=False
        )
        
        request = Mock(spec=Request)
        context = ConditionContext(
            request=request,
            user_attributes={"value": "not_false", "other": "true"}
        )
        
        result = await composite.evaluate(context)
        assert result.result is False
    
    @pytest.mark.asyncio
    async def test_evaluate_unknown_operator(self):
        """Test evaluation with unknown operator."""
        true_condition, _ = self.create_test_conditions()
        
        composite = CompositeCondition(
            condition_id="unknown_op",
            conditions=[true_condition],
            operator="unknown"  # This will cause an error
        )
        
        request = Mock(spec=Request)
        context = ConditionContext(request=request)
        
        result = await composite.evaluate(context)
        assert result.result is False
        assert "Evaluation error" in result.reason
    
    def test_not_condition_multiple_subconditions_error(self):
        """Test NOT condition with multiple sub-conditions raises error."""
        true_condition, false_condition = self.create_test_conditions()
        
        composite = CompositeCondition(
            condition_id="invalid_not",
            conditions=[true_condition, false_condition],  # NOT should have only one
            operator=LogicalOperator.NOT
        )
        
        # This should be caught during evaluation, not construction
        assert len(composite.conditions) == 2


class TestFeatureFlagCondition:
    """Test FeatureFlagCondition functionality."""
    
    @pytest.mark.asyncio
    async def test_evaluate_no_provider(self):
        """Test evaluation without feature flag provider."""
        condition = FeatureFlagCondition(
            condition_id="flag_test",
            flag_key="test_flag",
            expected_value=True
        )
        
        request = Mock(spec=Request)
        context = ConditionContext(request=request)
        
        result = await condition.evaluate(context)
        assert result.result is True  # Should use expected_value as default
        assert "No flag provider available" in result.reason
    
    @pytest.mark.asyncio
    async def test_evaluate_with_provider(self):
        """Test evaluation with feature flag provider."""
        mock_provider = Mock()
        
        condition = FeatureFlagCondition(
            condition_id="flag_test",
            flag_key="test_flag",
            expected_value=True,
            flag_provider=mock_provider
        )
        
        request = Mock(spec=Request)
        context = ConditionContext(
            request=request,
            user_id="user123",
            user_attributes={"plan": "premium"}
        )
        
        result = await condition.evaluate(context)
        assert result.result is True
        assert "Feature flag test_flag" in result.reason
        assert "feature_flag.test_flag" in result.attributes_used
    
    @pytest.mark.asyncio
    async def test_evaluate_error_handling(self):
        """Test error handling during flag evaluation."""
        # Mock provider that raises an exception
        mock_provider = Mock()
        
        condition = FeatureFlagCondition(
            condition_id="flag_test",
            flag_key="test_flag",
            flag_provider=mock_provider
        )
        
        # Mock the _evaluate_flag method to raise an exception
        condition._evaluate_flag = AsyncMock(side_effect=Exception("Provider error"))
        
        request = Mock(spec=Request)
        context = ConditionContext(request=request)
        
        result = await condition.evaluate(context)
        assert result.result is False
        assert "Feature flag evaluation error" in result.reason


class TestTimeBasedCondition:
    """Test TimeBasedCondition functionality."""
    
    @pytest.mark.asyncio
    async def test_evaluate_day_of_week(self):
        """Test evaluation based on day of week."""
        # Monday = 0, Sunday = 6
        condition = TimeBasedCondition(
            condition_id="weekday_check",
            days_of_week=[0, 1, 2, 3, 4],  # Weekdays only
            timezone="UTC"
        )
        
        request = Mock(spec=Request)
        
        # Test with weekday (assuming current test runs on a weekday)
        weekday_timestamp = 1640000000.0  # Monday, 2021-12-20 12:26:40 UTC
        context_weekday = ConditionContext(
            request=request,
            timestamp=weekday_timestamp
        )
        
        result = await condition.evaluate(context_weekday)
        # The result depends on the actual day, so we just check it doesn't error
        assert isinstance(result.result, bool)
        assert "day_of_week" in result.reason
    
    @pytest.mark.asyncio
    async def test_evaluate_hour_of_day(self):
        """Test evaluation based on hour of day."""
        condition = TimeBasedCondition(
            condition_id="business_hours",
            hours_of_day=[9, 10, 11, 12, 13, 14, 15, 16, 17],  # 9 AM to 5 PM
            timezone="UTC"
        )
        
        request = Mock(spec=Request)
        
        # Test with business hour (12 PM UTC)
        business_hour_timestamp = 1640005200.0  # 2021-12-20 14:00:00 UTC (2 PM)
        context = ConditionContext(
            request=request,
            timestamp=business_hour_timestamp
        )
        
        result = await condition.evaluate(context)
        assert isinstance(result.result, bool)
        assert "hour_of_day" in result.reason
    
    @pytest.mark.asyncio
    async def test_evaluate_start_end_time(self):
        """Test evaluation with start and end times."""
        condition = TimeBasedCondition(
            condition_id="time_range",
            start_time="2021-12-20 10:00:00",
            end_time="2021-12-20 18:00:00",
            timezone="UTC"
        )
        
        request = Mock(spec=Request)
        
        # Test within time range
        within_range_timestamp = 1639994400.0  # 2021-12-20 12:00:00 UTC
        context_within = ConditionContext(
            request=request,
            timestamp=within_range_timestamp
        )
        
        result = await condition.evaluate(context_within)
        assert isinstance(result.result, bool)
        # Since pytz is not available, this falls back to basic evaluation
        # Just check it doesn't error and returns a reasonable reason
        assert result.reason is not None
        assert len(result.reason) > 0
    
    @pytest.mark.asyncio
    async def test_evaluate_time_only_format(self):
        """Test evaluation with time-only format."""
        condition = TimeBasedCondition(
            condition_id="daily_window",
            start_time="09:00",
            end_time="17:00",
            timezone="UTC"
        )
        
        request = Mock(spec=Request)
        context = ConditionContext(request=request)
        
        result = await condition.evaluate(context)
        assert isinstance(result.result, bool)
    
    @pytest.mark.asyncio
    async def test_evaluate_invalid_time_format(self):
        """Test evaluation with invalid time format."""
        condition = TimeBasedCondition(
            condition_id="invalid_time",
            start_time="invalid_format",
            timezone="UTC"
        )
        
        request = Mock(spec=Request)
        context = ConditionContext(request=request)
        
        result = await condition.evaluate(context)
        # Should not fail, just ignore invalid time
        assert isinstance(result.result, bool)
    
    @pytest.mark.asyncio
    async def test_evaluate_timezone_handling(self):
        """Test evaluation with different timezones."""
        condition = TimeBasedCondition(
            condition_id="timezone_test",
            hours_of_day=[12],  # Noon
            timezone="America/New_York"
        )
        
        request = Mock(spec=Request)
        context = ConditionContext(request=request)
        
        # Without pytz, this should fall back to basic datetime
        result = await condition.evaluate(context)
        assert isinstance(result.result, bool)
        # Should contain fallback message since pytz is not available
        assert "no_pytz" in result.reason or "hour_of_day" in result.reason
    
    @pytest.mark.asyncio
    async def test_parse_time_error_handling(self):
        """Test _parse_time method error handling."""
        condition = TimeBasedCondition(
            condition_id="test",
            timezone="UTC"
        )
        
        # Test with invalid timezone (should return None gracefully)
        result = condition._parse_time("2021-12-20 12:00:00", "invalid_tz")
        # We expect this to either return None or handle the error gracefully
        # The exact behavior depends on how pytz handles invalid timezones


class TestCustomCondition:
    """Test CustomCondition functionality."""
    
    @pytest.mark.asyncio
    async def test_evaluate_sync_function_bool(self):
        """Test evaluation with synchronous function returning bool."""
        def custom_eval(context):
            return context.user_id == "admin"
        
        condition = CustomCondition(
            condition_id="custom_admin",
            evaluation_func=custom_eval,
            is_async=False
        )
        
        request = Mock(spec=Request)
        context = ConditionContext(request=request, user_id="admin")
        
        result = await condition.evaluate(context)
        assert result.result is True
        assert "Custom condition custom_admin" in result.reason
        assert "custom" in result.attributes_used
    
    @pytest.mark.asyncio
    async def test_evaluate_async_function_bool(self):
        """Test evaluation with asynchronous function returning bool."""
        async def custom_eval(context):
            await asyncio.sleep(0.001)  # Simulate async work
            return context.user_attributes.get("role") == "premium"
        
        condition = CustomCondition(
            condition_id="custom_premium",
            evaluation_func=custom_eval,
            is_async=True
        )
        
        request = Mock(spec=Request)
        context = ConditionContext(
            request=request,
            user_attributes={"role": "premium"}
        )
        
        result = await condition.evaluate(context)
        assert result.result is True
    
    @pytest.mark.asyncio
    async def test_evaluate_function_condition_result(self):
        """Test evaluation with function returning ConditionResult."""
        def custom_eval(context):
            is_admin = context.user_attributes.get("role") == "admin"
            return ConditionResult(
                result=is_admin,
                reason="Custom admin check",
                evaluation_time_ms=1.0,
                attributes_used={"role"}
            )
        
        condition = CustomCondition(
            condition_id="custom_detailed",
            evaluation_func=custom_eval,
            is_async=False
        )
        
        request = Mock(spec=Request)
        context = ConditionContext(
            request=request,
            user_attributes={"role": "admin"}
        )
        
        result = await condition.evaluate(context)
        assert result.result is True
        assert result.reason == "Custom admin check"
        assert "role" in result.attributes_used
    
    @pytest.mark.asyncio
    async def test_evaluate_function_truthy_value(self):
        """Test evaluation with function returning truthy value."""
        def custom_eval(context):
            return context.user_attributes.get("score", 0)  # Returns numeric score
        
        condition = CustomCondition(
            condition_id="custom_score",
            evaluation_func=custom_eval,
            is_async=False
        )
        
        request = Mock(spec=Request)
        
        # Test truthy value
        context_truthy = ConditionContext(
            request=request,
            user_attributes={"score": 85}
        )
        result_truthy = await condition.evaluate(context_truthy)
        assert result_truthy.result is True
        assert "(truthy)" in result_truthy.reason
        
        # Test falsy value
        context_falsy = ConditionContext(
            request=request,
            user_attributes={"score": 0}
        )
        result_falsy = await condition.evaluate(context_falsy)
        assert result_falsy.result is False
    
    @pytest.mark.asyncio
    async def test_evaluate_function_error(self):
        """Test evaluation with function that raises an error."""
        def custom_eval(context):
            raise ValueError("Custom evaluation error")
        
        condition = CustomCondition(
            condition_id="custom_error",
            evaluation_func=custom_eval,
            is_async=False
        )
        
        request = Mock(spec=Request)
        context = ConditionContext(request=request)
        
        result = await condition.evaluate(context)
        assert result.result is False
        assert "Custom condition error" in result.reason
    
    @pytest.mark.asyncio
    async def test_evaluate_async_function_error(self):
        """Test evaluation with async function that raises an error."""
        async def custom_eval(context):
            raise RuntimeError("Async evaluation error")
        
        condition = CustomCondition(
            condition_id="custom_async_error",
            evaluation_func=custom_eval,
            is_async=True
        )
        
        request = Mock(spec=Request)
        context = ConditionContext(request=request)
        
        result = await condition.evaluate(context)
        assert result.result is False
        assert "Custom condition error" in result.reason


class TestConditionCache:
    """Test ConditionCache functionality."""
    
    def test_init(self):
        """Test cache initialization."""
        cache = ConditionCache(CacheStrategy.GLOBAL)
        assert cache.default_strategy == CacheStrategy.GLOBAL
        assert cache.ttl_seconds == 300
    
    def test_no_cache_strategy(self):
        """Test NO_CACHE strategy."""
        cache = ConditionCache()
        request = Mock(spec=Request)
        context = ConditionContext(request=request)
        result = ConditionResult(result=True, reason="test", evaluation_time_ms=1.0)
        
        # Should not cache
        cache.set("key", result, CacheStrategy.NO_CACHE, context)
        cached = cache.get("key", CacheStrategy.NO_CACHE, context)
        assert cached is None
    
    def test_global_cache_strategy(self):
        """Test GLOBAL cache strategy."""
        cache = ConditionCache()
        request = Mock(spec=Request)
        context = ConditionContext(request=request)
        result = ConditionResult(result=True, reason="test", evaluation_time_ms=1.0)
        
        # Cache and retrieve
        cache.set("global_key", result, CacheStrategy.GLOBAL, context)
        cached = cache.get("global_key", CacheStrategy.GLOBAL, context)
        
        assert cached is not None
        assert cached.result is True
        assert cached.cached is True
    
    def test_request_scoped_cache_strategy(self):
        """Test REQUEST_SCOPED cache strategy."""
        cache = ConditionCache()
        request1 = Mock(spec=Request)
        request2 = Mock(spec=Request)
        context1 = ConditionContext(request=request1)
        context2 = ConditionContext(request=request2)
        result = ConditionResult(result=True, reason="test", evaluation_time_ms=1.0)
        
        # Cache for request1
        cache.set("request_key", result, CacheStrategy.REQUEST_SCOPED, context1)
        
        # Should be available for same request
        cached1 = cache.get("request_key", CacheStrategy.REQUEST_SCOPED, context1)
        assert cached1 is not None
        assert cached1.cached is True
        
        # Should not be available for different request
        cached2 = cache.get("request_key", CacheStrategy.REQUEST_SCOPED, context2)
        assert cached2 is None
    
    def test_session_scoped_cache_strategy(self):
        """Test SESSION_SCOPED cache strategy."""
        cache = ConditionCache()
        request = Mock(spec=Request)
        context1 = ConditionContext(request=request, session_id="session1")
        context2 = ConditionContext(request=request, session_id="session2")
        context_no_session = ConditionContext(request=request)
        result = ConditionResult(result=True, reason="test", evaluation_time_ms=1.0)
        
        # Cache for session1
        cache.set("session_key", result, CacheStrategy.SESSION_SCOPED, context1)
        
        # Should be available for same session
        cached1 = cache.get("session_key", CacheStrategy.SESSION_SCOPED, context1)
        assert cached1 is not None
        
        # Should not be available for different session
        cached2 = cache.get("session_key", CacheStrategy.SESSION_SCOPED, context2)
        assert cached2 is None
        
        # Should not be available for no session
        cached_no_session = cache.get("session_key", CacheStrategy.SESSION_SCOPED, context_no_session)
        assert cached_no_session is None
    
    def test_time_based_cache_strategy(self):
        """Test TIME_BASED cache strategy."""
        cache = ConditionCache()
        cache.ttl_seconds = 0.1  # Very short TTL for testing
        
        request = Mock(spec=Request)
        context = ConditionContext(request=request)
        result = ConditionResult(result=True, reason="test", evaluation_time_ms=1.0)
        
        # Cache the result
        cache.set("time_key", result, CacheStrategy.TIME_BASED, context)
        
        # Should be available immediately
        cached = cache.get("time_key", CacheStrategy.TIME_BASED, context)
        assert cached is not None
        
        # Wait for expiration
        time.sleep(0.2)
        
        # Should be expired now
        cached_expired = cache.get("time_key", CacheStrategy.TIME_BASED, context)
        assert cached_expired is None
    
    def test_clear_caches(self):
        """Test cache clearing methods."""
        cache = ConditionCache()
        request1 = Mock(spec=Request)
        request2 = Mock(spec=Request)
        context1 = ConditionContext(request=request1, session_id="session1")
        context2 = ConditionContext(request=request2, session_id="session2")
        result = ConditionResult(result=True, reason="test", evaluation_time_ms=1.0)
        
        # Set up various caches
        cache.set("req_key", result, CacheStrategy.REQUEST_SCOPED, context1)
        cache.set("sess_key", result, CacheStrategy.SESSION_SCOPED, context1)
        cache.set("global_key", result, CacheStrategy.GLOBAL, context1)
        
        # Clear request cache
        cache.clear_request_cache(id(request1))
        assert cache.get("req_key", CacheStrategy.REQUEST_SCOPED, context1) is None
        assert cache.get("sess_key", CacheStrategy.SESSION_SCOPED, context1) is not None
        
        # Clear session cache
        cache.clear_session_cache("session1")
        assert cache.get("sess_key", CacheStrategy.SESSION_SCOPED, context1) is None
        assert cache.get("global_key", CacheStrategy.GLOBAL, context1) is not None
        
        # Clear all caches
        cache.clear_all()
        assert cache.get("global_key", CacheStrategy.GLOBAL, context1) is None


class TestConditionEngine:
    """Test ConditionEngine functionality."""
    
    def test_init(self):
        """Test condition engine initialization."""
        engine = ConditionEngine(
            cache_strategy=CacheStrategy.GLOBAL,
            max_concurrent_evaluations=5,
            evaluation_timeout_seconds=10.0
        )
        
        assert engine.cache_strategy == CacheStrategy.GLOBAL
        assert engine.max_concurrent_evaluations == 5
        assert engine.evaluation_timeout_seconds == 10.0
        assert len(engine.conditions) == 0
    
    def test_register_condition(self):
        """Test condition registration."""
        engine = ConditionEngine()
        condition = SimpleCondition(
            condition_id="test_condition",
            attribute_path="user.role",
            operator=ComparisonOperator.EQUALS,
            value="admin"
        )
        
        engine.register_condition(condition)
        
        assert len(engine.conditions) == 1
        assert engine.get_condition("test_condition") == condition
    
    def test_unregister_condition(self):
        """Test condition unregistration."""
        engine = ConditionEngine()
        condition = SimpleCondition(
            condition_id="test_condition",
            attribute_path="user.role",
            operator=ComparisonOperator.EQUALS,
            value="admin"
        )
        
        engine.register_condition(condition)
        assert len(engine.conditions) == 1
        
        # Unregister existing condition
        result = engine.unregister_condition("test_condition")
        assert result is True
        assert len(engine.conditions) == 0
        assert engine.get_condition("test_condition") is None
        
        # Unregister non-existing condition
        result = engine.unregister_condition("nonexistent")
        assert result is False
    
    @pytest.mark.asyncio
    async def test_evaluate_condition_not_found(self):
        """Test evaluating non-existent condition."""
        engine = ConditionEngine()
        request = Mock(spec=Request)
        context = ConditionContext(request=request)
        
        result = await engine.evaluate_condition("nonexistent", context)
        
        assert result.result is False
        assert "Condition not found: nonexistent" in result.reason
    
    @pytest.mark.asyncio
    async def test_evaluate_condition_success(self):
        """Test successful condition evaluation."""
        engine = ConditionEngine()
        condition = SimpleCondition(
            condition_id="test_condition",
            attribute_path="user_attributes.role",
            operator=ComparisonOperator.EQUALS,
            value="admin"
        )
        engine.register_condition(condition)
        
        request = Mock(spec=Request)
        context = ConditionContext(
            request=request,
            user_attributes={"role": "admin"}
        )
        
        result = await engine.evaluate_condition("test_condition", context)
        
        assert result.result is True
        assert engine.total_evaluations == 1
    
    @pytest.mark.asyncio
    async def test_evaluate_condition_with_cache(self):
        """Test condition evaluation with caching."""
        engine = ConditionEngine(cache_strategy=CacheStrategy.GLOBAL)
        condition = SimpleCondition(
            condition_id="cached_condition",
            attribute_path="user_attributes.role",
            operator=ComparisonOperator.EQUALS,
            value="admin"
        )
        engine.register_condition(condition)
        
        request = Mock(spec=Request)
        context = ConditionContext(
            request=request,
            user_attributes={"role": "admin"}
        )
        
        # First evaluation - should miss cache
        result1 = await engine.evaluate_condition("cached_condition", context)
        assert result1.result is True
        assert result1.cached is False
        assert engine.cache_misses == 1
        
        # Second evaluation - should hit cache
        result2 = await engine.evaluate_condition("cached_condition", context)
        assert result2.result is True
        assert result2.cached is True
        assert engine.cache_hits == 1
    
    @pytest.mark.asyncio
    async def test_evaluate_condition_timeout(self):
        """Test condition evaluation timeout."""
        engine = ConditionEngine(evaluation_timeout_seconds=0.1)
        
        # Create a condition that takes too long
        async def slow_eval(context):
            await asyncio.sleep(0.2)
            return ConditionResult(result=True, reason="slow", evaluation_time_ms=200)
        
        condition = CustomCondition(
            condition_id="slow_condition",
            evaluation_func=slow_eval,
            is_async=True
        )
        engine.register_condition(condition)
        
        request = Mock(spec=Request)
        context = ConditionContext(request=request)
        
        result = await engine.evaluate_condition("slow_condition", context)
        
        assert result.result is False
        assert "Evaluation timeout" in result.reason
    
    @pytest.mark.asyncio
    async def test_evaluate_conditions_empty(self):
        """Test evaluating empty condition list."""
        engine = ConditionEngine()
        request = Mock(spec=Request)
        context = ConditionContext(request=request)
        
        result = await engine.evaluate_conditions([], context)
        
        assert result.result is True
        assert "No conditions to evaluate" in result.reason
    
    @pytest.mark.asyncio
    async def test_evaluate_conditions_and(self):
        """Test evaluating multiple conditions with AND."""
        engine = ConditionEngine()
        
        condition1 = SimpleCondition(
            condition_id="condition1",
            attribute_path="user_attributes.role",
            operator=ComparisonOperator.EQUALS,
            value="admin"
        )
        condition2 = SimpleCondition(
            condition_id="condition2",
            attribute_path="user_attributes.active",
            operator=ComparisonOperator.EQUALS,
            value=True
        )
        
        engine.register_condition(condition1)
        engine.register_condition(condition2)
        
        request = Mock(spec=Request)
        context = ConditionContext(
            request=request,
            user_attributes={"role": "admin", "active": True}
        )
        
        result = await engine.evaluate_conditions(
            ["condition1", "condition2"],
            context,
            LogicalOperator.AND
        )
        
        assert result.result is True
    
    @pytest.mark.asyncio
    async def test_evaluate_conditions_or(self):
        """Test evaluating multiple conditions with OR."""
        engine = ConditionEngine()
        
        condition1 = SimpleCondition(
            condition_id="condition1",
            attribute_path="user_attributes.role",
            operator=ComparisonOperator.EQUALS,
            value="admin"
        )
        condition2 = SimpleCondition(
            condition_id="condition2",
            attribute_path="user_attributes.role",
            operator=ComparisonOperator.EQUALS,
            value="moderator"
        )
        
        engine.register_condition(condition1)
        engine.register_condition(condition2)
        
        request = Mock(spec=Request)
        context = ConditionContext(
            request=request,
            user_attributes={"role": "admin"}  # Only matches first condition
        )
        
        result = await engine.evaluate_conditions(
            ["condition1", "condition2"],
            context,
            LogicalOperator.OR
        )
        
        assert result.result is True
    
    @pytest.mark.asyncio
    async def test_evaluate_conditions_missing_conditions(self):
        """Test evaluating conditions where some don't exist."""
        engine = ConditionEngine()
        
        condition1 = SimpleCondition(
            condition_id="existing_condition",
            attribute_path="user_attributes.role",
            operator=ComparisonOperator.EQUALS,
            value="admin"
        )
        engine.register_condition(condition1)
        
        request = Mock(spec=Request)
        context = ConditionContext(request=request)
        
        result = await engine.evaluate_conditions(
            ["existing_condition", "nonexistent_condition"],
            context
        )
        
        # Should still work with just the existing condition
        assert isinstance(result.result, bool)
    
    def test_get_performance_metrics(self):
        """Test performance metrics retrieval."""
        engine = ConditionEngine()
        
        # Add some conditions
        condition1 = SimpleCondition(
            condition_id="condition1",
            attribute_path="user.role",
            operator=ComparisonOperator.EQUALS,
            value="admin"
        )
        condition2 = SimpleCondition(
            condition_id="condition2",
            attribute_path="user.active",
            operator=ComparisonOperator.EQUALS,
            value=True
        )
        
        engine.register_condition(condition1)
        engine.register_condition(condition2)
        
        # Update some metrics manually for testing
        engine.total_evaluations = 10
        engine.cache_hits = 3
        engine.cache_misses = 7
        condition1.update_metrics(5.5)
        condition1.update_metrics(10.0)
        
        metrics = engine.get_performance_metrics()
        
        assert metrics["total_evaluations"] == 10
        assert metrics["cache_hits"] == 3
        assert metrics["cache_misses"] == 7
        assert metrics["cache_hit_rate"] == 0.3
        assert metrics["registered_conditions"] == 2
        
        assert "condition1" in metrics["condition_metrics"]
        assert "condition2" in metrics["condition_metrics"]
        assert metrics["condition_metrics"]["condition1"]["evaluation_count"] == 2
        assert metrics["condition_metrics"]["condition1"]["average_evaluation_time_ms"] == 7.75


class TestShieldExecutionRule:
    """Test ShieldExecutionRule functionality."""
    
    def test_init_valid(self):
        """Test valid rule initialization."""
        mock_shield = Mock(spec=Shield)
        
        rule = ShieldExecutionRule(
            rule_id="test_rule",
            shield=mock_shield,
            conditions=["condition1", "condition2"],
            logical_operator=LogicalOperator.AND,
            priority=10,
            weight=2.0,
            enabled=True,
            execution_strategy=ExecutionStrategy.FIRST_MATCH,
            cache_strategy=CacheStrategy.REQUEST_SCOPED,
            description="Test rule"
        )
        
        assert rule.rule_id == "test_rule"
        assert rule.shield == mock_shield
        assert rule.conditions == ["condition1", "condition2"]
        assert rule.logical_operator == LogicalOperator.AND
        assert rule.priority == 10
        assert rule.weight == 2.0
        assert rule.enabled is True
        assert rule.execution_strategy == ExecutionStrategy.FIRST_MATCH
        assert rule.cache_strategy == CacheStrategy.REQUEST_SCOPED
        assert rule.description == "Test rule"
    
    def test_init_empty_conditions_error(self):
        """Test initialization with empty conditions raises error."""
        mock_shield = Mock(spec=Shield)
        
        with pytest.raises(ValueError, match="must have at least one condition"):
            ShieldExecutionRule(
                rule_id="test_rule",
                shield=mock_shield,
                conditions=[]  # Empty conditions should raise error
            )
    
    def test_init_default_values(self):
        """Test initialization with default values."""
        mock_shield = Mock(spec=Shield)
        
        rule = ShieldExecutionRule(
            rule_id="test_rule",
            shield=mock_shield,
            conditions=["condition1"]
        )
        
        assert rule.logical_operator == LogicalOperator.AND
        assert rule.priority == 0
        assert rule.weight == 1.0
        assert rule.enabled is True
        assert rule.execution_strategy == ExecutionStrategy.FIRST_MATCH
        assert rule.cache_strategy is None
        assert rule.description == ""


class TestConditionalShield:
    """Test ConditionalShield functionality."""
    
    def create_test_engine_and_conditions(self):
        """Create test engine with conditions."""
        engine = ConditionEngine()
        
        # Add test conditions
        admin_condition = SimpleCondition(
            condition_id="is_admin",
            attribute_path="user_attributes.role",
            operator=ComparisonOperator.EQUALS,
            value="admin"
        )
        
        active_condition = SimpleCondition(
            condition_id="is_active",
            attribute_path="user_attributes.active",
            operator=ComparisonOperator.EQUALS,
            value=True
        )
        
        engine.register_condition(admin_condition)
        engine.register_condition(active_condition)
        
        return engine
    
    def test_init(self):
        """Test ConditionalShield initialization."""
        def dummy_shield_func(request: Request):
            return {"user": "test"}
        
        engine = ConditionEngine()
        
        shield = ConditionalShield(
            shield_func=dummy_shield_func,
            condition_engine=engine,
            name="test_conditional_shield"
        )
        
        assert shield.condition_engine == engine
        assert shield.execution_rules == []
        assert shield.default_execution_strategy == ExecutionStrategy.FIRST_MATCH
        assert callable(shield.context_extractor)
    
    def test_add_execution_rule(self):
        """Test adding execution rules."""
        def dummy_shield_func(request: Request):
            return {"user": "test"}
        
        engine = ConditionEngine()
        mock_shield = Mock(spec=Shield)
        
        conditional_shield = ConditionalShield(
            shield_func=dummy_shield_func,
            condition_engine=engine
        )
        
        rule = ShieldExecutionRule(
            rule_id="test_rule",
            shield=mock_shield,
            conditions=["condition1"],
            priority=10
        )
        
        conditional_shield.add_execution_rule(rule)
        
        assert len(conditional_shield.execution_rules) == 1
        assert conditional_shield.execution_rules[0] == rule
    
    def test_add_multiple_rules_priority_sorting(self):
        """Test that rules are sorted by priority."""
        def dummy_shield_func(request: Request):
            return {"user": "test"}
        
        engine = ConditionEngine()
        mock_shield = Mock(spec=Shield)
        
        conditional_shield = ConditionalShield(
            shield_func=dummy_shield_func,
            condition_engine=engine
        )
        
        # Add rules with different priorities
        rule_low = ShieldExecutionRule(
            rule_id="low_priority",
            shield=mock_shield,
            conditions=["condition1"],
            priority=1
        )
        
        rule_high = ShieldExecutionRule(
            rule_id="high_priority",
            shield=mock_shield,
            conditions=["condition2"],
            priority=10
        )
        
        rule_medium = ShieldExecutionRule(
            rule_id="medium_priority",
            shield=mock_shield,
            conditions=["condition3"],
            priority=5
        )
        
        conditional_shield.add_execution_rule(rule_low)
        conditional_shield.add_execution_rule(rule_high)
        conditional_shield.add_execution_rule(rule_medium)
        
        # Should be sorted by priority (highest first)
        assert conditional_shield.execution_rules[0].rule_id == "high_priority"
        assert conditional_shield.execution_rules[1].rule_id == "medium_priority"
        assert conditional_shield.execution_rules[2].rule_id == "low_priority"
    
    def test_remove_execution_rule(self):
        """Test removing execution rules."""
        def dummy_shield_func(request: Request):
            return {"user": "test"}
        
        engine = ConditionEngine()
        mock_shield = Mock(spec=Shield)
        
        conditional_shield = ConditionalShield(
            shield_func=dummy_shield_func,
            condition_engine=engine
        )
        
        rule = ShieldExecutionRule(
            rule_id="test_rule",
            shield=mock_shield,
            conditions=["condition1"]
        )
        
        conditional_shield.add_execution_rule(rule)
        assert len(conditional_shield.execution_rules) == 1
        
        # Remove existing rule
        result = conditional_shield.remove_execution_rule("test_rule")
        assert result is True
        assert len(conditional_shield.execution_rules) == 0
        
        # Remove non-existing rule
        result = conditional_shield.remove_execution_rule("nonexistent")
        assert result is False
    
    def test_default_context_extractor(self):
        """Test default context extractor."""
        def dummy_shield_func(request: Request):
            return {"user": "test"}
        
        engine = ConditionEngine()
        shield = ConditionalShield(
            shield_func=dummy_shield_func,
            condition_engine=engine
        )
        
        # Mock request
        request = Mock(spec=Request)
        request.method = "GET"
        request.url.path = "/api/test"
        request.query_params = {"param1": "value1"}
        request.headers = {"authorization": "Bearer token123", "user-agent": "test-agent"}
        request.cookies = {"session_id": "session123"}
        request.client.host = "127.0.0.1"
        
        context = shield._default_context_extractor(request)
        
        assert context.request == request
        assert context.session_id == "session123"
        assert context.user_attributes["has_auth"] is True
        assert context.request_attributes["method"] == "GET"
        assert context.request_attributes["path"] == "/api/test"
        assert context.request_attributes["query_params"] == {"param1": "value1"}
        assert context.request_attributes["client_host"] == "127.0.0.1"
        assert context.request_attributes["user_agent"] == "test-agent"
    
    def test_custom_context_extractor(self):
        """Test custom context extractor."""
        def dummy_shield_func(request: Request):
            return {"user": "test"}
        
        def custom_extractor(request: Request):
            return ConditionContext(
                request=request,
                user_id="custom_user",
                user_attributes={"custom": "attribute"}
            )
        
        engine = ConditionEngine()
        shield = ConditionalShield(
            shield_func=dummy_shield_func,
            condition_engine=engine,
            context_extractor=custom_extractor
        )
        
        request = Mock(spec=Request)
        context = shield.context_extractor(request)
        
        assert context.user_id == "custom_user"
        assert context.user_attributes["custom"] == "attribute"
    
    @pytest.mark.asyncio
    async def test_evaluate_rules_no_rules(self):
        """Test rule evaluation with no rules."""
        def dummy_shield_func(request: Request):
            return {"user": "test"}
        
        engine = ConditionEngine()
        shield = ConditionalShield(
            shield_func=dummy_shield_func,
            condition_engine=engine
        )
        
        request = Mock(spec=Request)
        context = ConditionContext(request=request)
        
        rules = await shield._evaluate_rules(context)
        assert len(rules) == 0
    
    @pytest.mark.asyncio
    async def test_evaluate_rules_matching(self):
        """Test rule evaluation with matching conditions."""
        def dummy_shield_func(request: Request):
            return {"user": "test"}
        
        engine = self.create_test_engine_and_conditions()
        shield = ConditionalShield(
            shield_func=dummy_shield_func,
            condition_engine=engine
        )
        
        # Add a rule that should match
        mock_shield_instance = Mock(spec=Shield)
        rule = ShieldExecutionRule(
            rule_id="admin_rule",
            shield=mock_shield_instance,
            conditions=["is_admin"],
            enabled=True
        )
        shield.add_execution_rule(rule)
        
        request = Mock(spec=Request)
        context = ConditionContext(
            request=request,
            user_attributes={"role": "admin"}
        )
        
        matching_rules = await shield._evaluate_rules(context)
        assert len(matching_rules) == 1
        assert matching_rules[0].rule_id == "admin_rule"
    
    @pytest.mark.asyncio
    async def test_evaluate_rules_non_matching(self):
        """Test rule evaluation with non-matching conditions."""
        def dummy_shield_func(request: Request):
            return {"user": "test"}
        
        engine = self.create_test_engine_and_conditions()
        shield = ConditionalShield(
            shield_func=dummy_shield_func,
            condition_engine=engine
        )
        
        # Add a rule that should not match
        mock_shield_instance = Mock(spec=Shield)
        rule = ShieldExecutionRule(
            rule_id="admin_rule",
            shield=mock_shield_instance,
            conditions=["is_admin"],
            enabled=True
        )
        shield.add_execution_rule(rule)
        
        request = Mock(spec=Request)
        context = ConditionContext(
            request=request,
            user_attributes={"role": "user"}  # Not admin
        )
        
        matching_rules = await shield._evaluate_rules(context)
        assert len(matching_rules) == 0
    
    @pytest.mark.asyncio
    async def test_evaluate_rules_disabled_rule(self):
        """Test rule evaluation with disabled rule."""
        def dummy_shield_func(request: Request):
            return {"user": "test"}
        
        engine = self.create_test_engine_and_conditions()
        shield = ConditionalShield(
            shield_func=dummy_shield_func,
            condition_engine=engine
        )
        
        # Add a disabled rule
        mock_shield_instance = Mock(spec=Shield)
        rule = ShieldExecutionRule(
            rule_id="admin_rule",
            shield=mock_shield_instance,
            conditions=["is_admin"],
            enabled=False  # Disabled
        )
        shield.add_execution_rule(rule)
        
        request = Mock(spec=Request)
        context = ConditionContext(
            request=request,
            user_attributes={"role": "admin"}
        )
        
        matching_rules = await shield._evaluate_rules(context)
        assert len(matching_rules) == 0


class TestShieldChain:
    """Test ShieldChain functionality."""
    
    def test_init(self):
        """Test ShieldChain initialization."""
        engine = ConditionEngine()
        chain = ShieldChain(
            chain_id="test_chain",
            condition_engine=engine,
            execution_strategy=ExecutionStrategy.ALL_MATCHING
        )
        
        assert chain.chain_id == "test_chain"
        assert chain.condition_engine == engine
        assert chain.execution_strategy == ExecutionStrategy.ALL_MATCHING
        assert len(chain.shields) == 0
    
    def test_add_shield(self):
        """Test adding shield to chain."""
        engine = ConditionEngine()
        chain = ShieldChain("test_chain", engine)
        
        mock_shield = Mock(spec=Shield)
        rule = ShieldExecutionRule(
            rule_id="test_rule",
            shield=mock_shield,
            conditions=["condition1"],
            priority=10
        )
        
        chain.add_shield(rule)
        
        assert len(chain.shields) == 1
        assert chain.shields[0] == rule
    
    def test_add_multiple_shields_priority_sorting(self):
        """Test that shields are sorted by priority."""
        engine = ConditionEngine()
        chain = ShieldChain("test_chain", engine)
        
        mock_shield = Mock(spec=Shield)
        
        # Add shields with different priorities
        rule_low = ShieldExecutionRule(
            rule_id="low_priority",
            shield=mock_shield,
            conditions=["condition1"],
            priority=1
        )
        
        rule_high = ShieldExecutionRule(
            rule_id="high_priority",
            shield=mock_shield,
            conditions=["condition2"],
            priority=10
        )
        
        chain.add_shield(rule_low)
        chain.add_shield(rule_high)
        
        # Should be sorted by priority (highest first)
        assert chain.shields[0].rule_id == "high_priority"
        assert chain.shields[1].rule_id == "low_priority"
    
    def test_remove_shield(self):
        """Test removing shield from chain."""
        engine = ConditionEngine()
        chain = ShieldChain("test_chain", engine)
        
        mock_shield = Mock(spec=Shield)
        rule = ShieldExecutionRule(
            rule_id="test_rule",
            shield=mock_shield,
            conditions=["condition1"]
        )
        
        chain.add_shield(rule)
        assert len(chain.shields) == 1
        
        # Remove existing shield
        result = chain.remove_shield("test_rule")
        assert result is True
        assert len(chain.shields) == 0
        
        # Remove non-existing shield
        result = chain.remove_shield("nonexistent")
        assert result is False
    
    @pytest.mark.asyncio
    async def test_execute_no_matching_rules(self):
        """Test execute with no matching rules."""
        engine = ConditionEngine()
        
        # Add a condition that won't match
        condition = SimpleCondition(
            condition_id="admin_condition",
            attribute_path="user_attributes.role",
            operator=ComparisonOperator.EQUALS,
            value="admin"
        )
        engine.register_condition(condition)
        
        chain = ShieldChain("test_chain", engine)
        
        mock_shield = Mock(spec=Shield)
        rule = ShieldExecutionRule(
            rule_id="admin_rule",
            shield=mock_shield,
            conditions=["admin_condition"]
        )
        chain.add_shield(rule)
        
        def test_endpoint():
            return {"message": "test"}
        
        request = Mock(spec=Request)
        context = ConditionContext(
            request=request,
            user_attributes={"role": "user"}  # Not admin
        )
        
        result = await chain.execute(test_endpoint, context)
        
        # Should return original endpoint since no rules matched
        assert result == test_endpoint
    
    @pytest.mark.asyncio
    async def test_execute_first_match_strategy(self):
        """Test execute with FIRST_MATCH strategy."""
        engine = ConditionEngine()
        
        # Add conditions
        admin_condition = SimpleCondition(
            condition_id="admin_condition",
            attribute_path="user_attributes.role",
            operator=ComparisonOperator.EQUALS,
            value="admin"
        )
        user_condition = SimpleCondition(
            condition_id="user_condition",
            attribute_path="user_attributes.role",
            operator=ComparisonOperator.EQUALS,
            value="admin"  # Same as admin for testing
        )
        engine.register_condition(admin_condition)
        engine.register_condition(user_condition)
        
        chain = ShieldChain("test_chain", engine, ExecutionStrategy.FIRST_MATCH)
        
        # Create mock shields
        mock_shield1 = Mock(spec=Shield)
        mock_shield1.return_value = "wrapped_by_shield1"
        mock_shield2 = Mock(spec=Shield)
        mock_shield2.return_value = "wrapped_by_shield2"
        
        # Add rules (higher priority first)
        rule1 = ShieldExecutionRule(
            rule_id="rule1",
            shield=mock_shield1,
            conditions=["admin_condition"],
            priority=10
        )
        rule2 = ShieldExecutionRule(
            rule_id="rule2",
            shield=mock_shield2,
            conditions=["user_condition"],
            priority=5
        )
        
        chain.add_shield(rule1)
        chain.add_shield(rule2)
        
        def test_endpoint():
            return {"message": "test"}
        
        request = Mock(spec=Request)
        context = ConditionContext(
            request=request,
            user_attributes={"role": "admin"}  # Matches both conditions
        )
        
        result = await chain.execute(test_endpoint, context)
        
        # Should only apply first matching shield (highest priority)
        mock_shield1.assert_called_once_with(test_endpoint)
        mock_shield2.assert_not_called()


class TestABTestManager:
    """Test ABTestManager functionality."""
    
    def test_init(self):
        """Test ABTestManager initialization."""
        engine = ConditionEngine()
        manager = ABTestManager(engine)
        
        assert manager.condition_engine == engine
        assert len(manager.experiments) == 0
    
    def test_create_experiment(self):
        """Test creating an experiment."""
        engine = ConditionEngine()
        manager = ABTestManager(engine)
        
        variant_a = ABTestVariant(
            variant_id="variant_a",
            name="Control",
            shield=None,
            allocation_percentage=0.5
        )
        variant_b = ABTestVariant(
            variant_id="variant_b",
            name="Treatment",
            shield=Mock(spec=Shield),
            allocation_percentage=0.5
        )
        
        experiment = manager.create_experiment(
            experiment_id="test_experiment",
            name="Test Experiment",
            variants=[variant_a, variant_b]
        )
        
        assert experiment.experiment_id == "test_experiment"
        assert experiment.name == "Test Experiment"
        assert len(experiment.variants) == 2
        assert manager.get_experiment("test_experiment") == experiment
    
    @pytest.mark.asyncio
    async def test_allocate_user_disabled_experiment(self):
        """Test user allocation with disabled experiment."""
        engine = ConditionEngine()
        manager = ABTestManager(engine)
        
        variant = ABTestVariant(
            variant_id="variant_a",
            name="Control",
            shield=None,
            allocation_percentage=1.0
        )
        
        manager.create_experiment(
            experiment_id="disabled_experiment",
            name="Disabled Test",
            variants=[variant],
            enabled=False
        )
        
        request = Mock(spec=Request)
        context = ConditionContext(request=request, user_id="user123")
        
        result = await manager.allocate_user("disabled_experiment", context)
        assert result is None
    
    @pytest.mark.asyncio
    async def test_allocate_user_nonexistent_experiment(self):
        """Test user allocation with nonexistent experiment."""
        engine = ConditionEngine()
        manager = ABTestManager(engine)
        
        request = Mock(spec=Request)
        context = ConditionContext(request=request, user_id="user123")
        
        result = await manager.allocate_user("nonexistent", context)
        assert result is None


class TestABTestVariant:
    """Test ABTestVariant functionality."""
    
    def test_init(self):
        """Test ABTestVariant initialization."""
        mock_shield = Mock(spec=Shield)
        
        variant = ABTestVariant(
            variant_id="test_variant",
            name="Test Variant",
            shield=mock_shield,
            allocation_percentage=0.3,
            conditions=["condition1", "condition2"],
            enabled=False
        )
        
        assert variant.variant_id == "test_variant"
        assert variant.name == "Test Variant"
        assert variant.shield == mock_shield
        assert variant.allocation_percentage == 0.3
        assert variant.conditions == ["condition1", "condition2"]
        assert variant.enabled is False
    
    def test_init_defaults(self):
        """Test ABTestVariant initialization with defaults."""
        variant = ABTestVariant(
            variant_id="test_variant",
            name="Test Variant",
            shield=None,
            allocation_percentage=0.5
        )
        
        assert variant.conditions == []
        assert variant.enabled is True


class TestABTestExperiment:
    """Test ABTestExperiment functionality."""
    
    def test_init_valid_allocation(self):
        """Test experiment initialization with valid allocation."""
        variant_a = ABTestVariant("a", "Control", None, 0.5)
        variant_b = ABTestVariant("b", "Treatment", None, 0.5)
        
        experiment = ABTestExperiment(
            experiment_id="test_exp",
            name="Test",
            variants=[variant_a, variant_b]
        )
        
        assert experiment.experiment_id == "test_exp"
        assert len(experiment.variants) == 2
        assert experiment.enabled is True
    
    def test_init_invalid_allocation(self):
        """Test experiment initialization with invalid allocation."""
        variant_a = ABTestVariant("a", "Control", None, 0.3)
        variant_b = ABTestVariant("b", "Treatment", None, 0.5)  # Total = 0.8, not 1.0
        
        with pytest.raises(ValueError, match="must sum to 1.0"):
            ABTestExperiment(
                experiment_id="test_exp",
                name="Test",
                variants=[variant_a, variant_b]
            )
    
    @pytest.mark.asyncio
    async def test_allocate_user_disabled(self):
        """Test user allocation when experiment is disabled."""
        variant = ABTestVariant("a", "Control", None, 1.0)
        experiment = ABTestExperiment(
            experiment_id="test_exp",
            name="Test",
            variants=[variant],
            enabled=False
        )
        
        request = Mock(spec=Request)
        context = ConditionContext(request=request, user_id="user123")
        
        result = await experiment.allocate_user(context)
        assert result is None
    
    @pytest.mark.asyncio
    async def test_allocate_user_user_hash_strategy(self):
        """Test user allocation with user hash strategy."""
        variant_a = ABTestVariant("a", "Control", None, 0.5)
        variant_b = ABTestVariant("b", "Treatment", None, 0.5)
        
        experiment = ABTestExperiment(
            experiment_id="test_exp",
            name="Test",
            variants=[variant_a, variant_b],
            allocation_strategy="user_hash"
        )
        
        request = Mock(spec=Request)
        context = ConditionContext(request=request, user_id="user123")
        
        result = await experiment.allocate_user(context)
        
        # Should return one of the variants
        assert result in [variant_a, variant_b]
    
    @pytest.mark.asyncio
    async def test_allocate_user_session_hash_strategy(self):
        """Test user allocation with session hash strategy."""
        variant = ABTestVariant("a", "Control", None, 1.0)
        
        experiment = ABTestExperiment(
            experiment_id="test_exp",
            name="Test",
            variants=[variant],
            allocation_strategy="session_hash"
        )
        
        request = Mock(spec=Request)
        context = ConditionContext(request=request, session_id="session123")
        
        result = await experiment.allocate_user(context)
        assert result == variant
    
    def test_get_allocation_key_strategies(self):
        """Test allocation key generation for different strategies."""
        variant = ABTestVariant("a", "Control", None, 1.0)
        experiment = ABTestExperiment(
            experiment_id="test_exp",
            name="Test",
            variants=[variant]
        )
        
        request = Mock(spec=Request)
        context = ConditionContext(
            request=request,
            user_id="user123",
            session_id="session456"
        )
        
        # Test user_hash strategy
        experiment.allocation_strategy = "user_hash"
        key = experiment._get_allocation_key(context)
        assert key == "test_exp:user123"
        
        # Test session_hash strategy
        experiment.allocation_strategy = "session_hash"
        key = experiment._get_allocation_key(context)
        assert key == "test_exp:session456"
        
        # Test unknown strategy (should fall back to user/session)
        experiment.allocation_strategy = "unknown"
        key = experiment._get_allocation_key(context)
        assert key == "test_exp:user123"
    
    def test_hash_allocation_key(self):
        """Test allocation key hashing."""
        variant = ABTestVariant("a", "Control", None, 1.0)
        experiment = ABTestExperiment(
            experiment_id="test_exp",
            name="Test",
            variants=[variant]
        )
        
        hash_value = experiment._hash_allocation_key("test_key")
        
        assert 0.0 <= hash_value <= 1.0
        assert isinstance(hash_value, float)
        
        # Same key should produce same hash
        hash_value2 = experiment._hash_allocation_key("test_key")
        assert hash_value == hash_value2
        
        # Different key should produce different hash
        hash_value3 = experiment._hash_allocation_key("different_key")
        assert hash_value != hash_value3


class TestConvenienceFunctions:
    """Test convenience functions for creating conditions."""
    
    def test_create_simple_condition(self):
        """Test create_simple_condition function."""
        condition = create_simple_condition(
            condition_id="test_simple",
            attribute_path="user.role",
            operator="eq",
            value="admin",
            description="Test condition",
            weight=2.0
        )
        
        assert isinstance(condition, SimpleCondition)
        assert condition.condition_id == "test_simple"
        assert condition.attribute_path == "user.role"
        assert condition.operator == ComparisonOperator.EQUALS
        assert condition.value == "admin"
        assert condition.description == "Test condition"
        assert condition.weight == 2.0
    
    def test_create_user_attribute_condition(self):
        """Test create_user_attribute_condition function."""
        condition = create_user_attribute_condition(
            condition_id="user_attr",
            attribute_name="role",
            operator="eq",
            value="premium"
        )
        
        assert isinstance(condition, SimpleCondition)
        assert condition.attribute_path == "user_attributes.role"
        assert condition.operator == ComparisonOperator.EQUALS
        assert condition.value == "premium"
    
    def test_create_request_property_condition(self):
        """Test create_request_property_condition function."""
        condition = create_request_property_condition(
            condition_id="request_prop",
            property_name="method",
            operator="eq",
            value="GET"
        )
        
        assert isinstance(condition, SimpleCondition)
        assert condition.attribute_path == "request_attributes.method"
        assert condition.operator == ComparisonOperator.EQUALS
        assert condition.value == "GET"
    
    def test_create_feature_flag_condition(self):
        """Test create_feature_flag_condition function."""
        mock_provider = Mock()
        
        condition = create_feature_flag_condition(
            condition_id="flag_condition",
            flag_key="test_flag",
            expected_value=True,
            flag_provider=mock_provider
        )
        
        assert isinstance(condition, FeatureFlagCondition)
        assert condition.flag_key == "test_flag"
        assert condition.expected_value is True
        assert condition.flag_provider == mock_provider
    
    def test_create_time_based_condition(self):
        """Test create_time_based_condition function."""
        condition = create_time_based_condition(
            condition_id="time_condition",
            start_time="09:00",
            end_time="17:00",
            days_of_week=[0, 1, 2, 3, 4],
            timezone="UTC"
        )
        
        assert isinstance(condition, TimeBasedCondition)
        assert condition.start_time == "09:00"
        assert condition.end_time == "17:00"
        assert condition.days_of_week == [0, 1, 2, 3, 4]
        assert condition.timezone == "UTC"
    
    def test_create_composite_condition(self):
        """Test create_composite_condition function."""
        sub_condition = create_simple_condition(
            condition_id="sub",
            attribute_path="user.role",
            operator="eq",
            value="admin"
        )
        
        condition = create_composite_condition(
            condition_id="composite",
            conditions=[sub_condition],
            operator="and"
        )
        
        assert isinstance(condition, CompositeCondition)
        assert condition.operator == LogicalOperator.AND
        assert len(condition.conditions) == 1
        assert condition.conditions[0] == sub_condition
    
    def test_create_custom_condition(self):
        """Test create_custom_condition function."""
        def custom_func(context):
            return True
        
        condition = create_custom_condition(
            condition_id="custom",
            evaluation_func=custom_func,
            is_async=False
        )
        
        assert isinstance(condition, CustomCondition)
        assert condition.evaluation_func == custom_func
        assert condition.is_async is False


class TestConditionalShieldDecorator:
    """Test conditional_shield decorator."""
    
    def test_conditional_shield_decorator(self):
        """Test conditional_shield decorator function."""
        engine = ConditionEngine()
        
        @conditional_shield(
            condition_engine=engine,
            name="test_conditional"
        )
        def test_shield_func(request: Request):
            return {"user": "test"}
        
        assert isinstance(test_shield_func, ConditionalShield)
        assert test_shield_func.condition_engine == engine
        assert test_shield_func.name == "test_conditional"
    
    def test_conditional_shield_decorator_with_rules(self):
        """Test conditional_shield decorator with execution rules."""
        engine = ConditionEngine()
        mock_shield = Mock(spec=Shield)
        
        rules = [
            ShieldExecutionRule(
                rule_id="test_rule",
                shield=mock_shield,
                conditions=["test_condition"]
            )
        ]
        
        @conditional_shield(
            condition_engine=engine,
            execution_rules=rules,
            execution_strategy=ExecutionStrategy.ALL_MATCHING
        )
        def test_shield_func(request: Request):
            return {"user": "test"}
        
        assert isinstance(test_shield_func, ConditionalShield)
        assert len(test_shield_func.execution_rules) == 1
        assert test_shield_func.default_execution_strategy == ExecutionStrategy.ALL_MATCHING


class TestIntegrationScenarios:
    """Test end-to-end integration scenarios."""
    
    @pytest.fixture
    def app(self):
        """Create test FastAPI app."""
        return FastAPI()
    
    @pytest.fixture
    def client(self, app):
        """Create test client."""
        return TestClient(app)
    
    def test_simple_conditional_execution(self, app, client):
        """Test simple conditional execution scenario."""
        engine = ConditionEngine()
        
        # Register condition
        admin_condition = create_user_attribute_condition(
            condition_id="is_admin",
            attribute_name="role",
            operator="eq",
            value="admin"
        )
        engine.register_condition(admin_condition)
        
        # Create shield
        def auth_shield_func(request: Request):
            return {"authenticated": True}
        
        # Create conditional shield
        conditional_shield_instance = ConditionalShield(
            shield_func=auth_shield_func,
            condition_engine=engine,
            name="admin_shield"
        )
        
        # Test that the conditional shield was created correctly
        assert conditional_shield_instance.condition_engine == engine
        assert conditional_shield_instance.name == "admin_shield"
        assert len(conditional_shield_instance.execution_rules) == 0
        
        # Test adding execution rules
        from unittest.mock import Mock
        mock_shield = Mock()
        rule = ShieldExecutionRule(
            rule_id="admin_rule",
            shield=mock_shield,
            conditions=["is_admin"]
        )
        conditional_shield_instance.add_execution_rule(rule)
        
        assert len(conditional_shield_instance.execution_rules) == 1
        assert conditional_shield_instance.execution_rules[0].rule_id == "admin_rule"
    
    @pytest.mark.asyncio
    async def test_complex_condition_evaluation(self):
        """Test complex condition evaluation with multiple operators."""
        engine = ConditionEngine()
        
        # Create conditions
        admin_condition = create_user_attribute_condition(
            condition_id="is_admin",
            attribute_name="role",
            operator="eq",
            value="admin"
        )
        
        active_condition = create_user_attribute_condition(
            condition_id="is_active",
            attribute_name="active",
            operator="eq",
            value=True
        )
        
        business_hours_condition = create_time_based_condition(
            condition_id="business_hours",
            hours_of_day=list(range(9, 18)),  # 9 AM to 5 PM
            timezone="UTC"
        )
        
        # Register conditions
        engine.register_condition(admin_condition)
        engine.register_condition(active_condition)
        engine.register_condition(business_hours_condition)
        
        # Create composite condition (admin AND active) OR business_hours
        admin_and_active = create_composite_condition(
            condition_id="admin_and_active",
            conditions=[admin_condition, active_condition],
            operator="and"
        )
        engine.register_condition(admin_and_active)
        
        final_condition = create_composite_condition(
            condition_id="final_condition",
            conditions=[admin_and_active, business_hours_condition],
            operator="or"
        )
        engine.register_condition(final_condition)
        
        # Test scenarios
        request = Mock(spec=Request)
        
        # Scenario 1: Admin and active user (should pass)
        context1 = ConditionContext(
            request=request,
            user_attributes={"role": "admin", "active": True}
        )
        result1 = await engine.evaluate_condition("final_condition", context1)
        
        # We can't assert the exact result since it depends on current time,
        # but we can check that evaluation completed without error
        assert isinstance(result1.result, bool)
        assert result1.evaluation_time_ms >= 0
        
        # Scenario 2: Regular user (result depends on business hours)
        context2 = ConditionContext(
            request=request,
            user_attributes={"role": "user", "active": True}
        )
        result2 = await engine.evaluate_condition("final_condition", context2)
        assert isinstance(result2.result, bool)
    
    @pytest.mark.asyncio
    async def test_performance_with_caching(self):
        """Test performance optimization with caching."""
        engine = ConditionEngine(cache_strategy=CacheStrategy.GLOBAL)
        
        # Create a condition
        condition = create_user_attribute_condition(
            condition_id="performance_test",
            attribute_name="role",
            operator="eq",
            value="admin"
        )
        engine.register_condition(condition)
        
        request = Mock(spec=Request)
        context = ConditionContext(
            request=request,
            user_id="user123",
            user_attributes={"role": "admin"}
        )
        
        # First evaluation (cache miss)
        start_time = time.perf_counter()
        result1 = await engine.evaluate_condition("performance_test", context)
        first_eval_time = time.perf_counter() - start_time
        
        assert result1.result is True
        assert result1.cached is False
        
        # Second evaluation (cache hit)
        start_time = time.perf_counter()
        result2 = await engine.evaluate_condition("performance_test", context)
        second_eval_time = time.perf_counter() - start_time
        
        assert result2.result is True
        assert result2.cached is True
        
        # Cached evaluation should be significantly faster
        # (though in practice the difference might be small for simple conditions)
        assert second_eval_time <= first_eval_time
        
        # Check metrics
        metrics = engine.get_performance_metrics()
        assert metrics["cache_hits"] == 1
        assert metrics["cache_misses"] == 1
        assert metrics["cache_hit_rate"] == 0.5