"""Tests for request preprocessing system."""

import asyncio
import json
import re
import pytest
import time
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import Request, Response
from fastapi.datastructures import Headers, QueryParams
from starlette.responses import RedirectResponse

from fastapi_shield.request_preprocessing import (
    # Enums
    PreprocessingAction, PreprocessingPriority, TransformationScope, BodyFormat,
    
    # Data classes
    PreprocessingResult, HeaderRule, BodyTransformation, URLRewriteRule,
    QueryParamRule, PreprocessingConfig,
    
    # Core classes
    RequestPreprocessor, HeaderManipulator, BodyTransformer, URLRewriter,
    QueryParamManipulator, ConditionalPreprocessor, PreprocessingPipeline,
    PreprocessingShield,
    
    # Convenience functions
    create_header_security_preprocessor, create_cors_preprocessor,
    create_json_validator_preprocessor, create_url_normalizer_preprocessor,
    create_api_version_preprocessor, create_preprocessing_pipeline,
    setup_preprocessing_middleware
)

from tests.mocks.request_preprocessing_mocks import (
    MockRequest, MockResponse, MockHeaderManipulator, MockBodyTransformer,
    MockURLRewriter, MockQueryParamManipulator, MockPreprocessingPipeline,
    MockRequestPreprocessor, MockFailingPreprocessor,
    create_mock_request, create_mock_json_request, create_mock_form_request,
    create_test_preprocessing_pipeline, create_test_header_rules,
    create_test_body_transformations, create_test_url_rewrite_rules,
    create_test_query_param_rules, PerformanceTestHelper,
    create_large_request_body, create_complex_json_body
)


class TestPreprocessingEnums:
    """Test preprocessing enumerations."""
    
    def test_preprocessing_action_values(self):
        """Test preprocessing action enum values."""
        assert PreprocessingAction.CONTINUE == "continue"
        assert PreprocessingAction.REDIRECT == "redirect"
        assert PreprocessingAction.BLOCK == "block"
        assert PreprocessingAction.MODIFY == "modify"
        assert PreprocessingAction.FORWARD == "forward"
    
    def test_preprocessing_priority_values(self):
        """Test preprocessing priority enum values."""
        assert PreprocessingPriority.LOWEST == 1
        assert PreprocessingPriority.LOW == 25
        assert PreprocessingPriority.NORMAL == 50
        assert PreprocessingPriority.HIGH == 75
        assert PreprocessingPriority.HIGHEST == 100
    
    def test_transformation_scope_values(self):
        """Test transformation scope enum values."""
        assert TransformationScope.HEADERS == "headers"
        assert TransformationScope.BODY == "body"
        assert TransformationScope.URL == "url"
        assert TransformationScope.QUERY_PARAMS == "query_params"
        assert TransformationScope.PATH == "path"
        assert TransformationScope.METHOD == "method"
        assert TransformationScope.ALL == "all"
    
    def test_body_format_values(self):
        """Test body format enum values."""
        assert BodyFormat.JSON == "json"
        assert BodyFormat.XML == "xml"
        assert BodyFormat.FORM == "form"
        assert BodyFormat.TEXT == "text"
        assert BodyFormat.BINARY == "binary"
        assert BodyFormat.MULTIPART == "multipart"


class TestPreprocessingDataClasses:
    """Test preprocessing data classes."""
    
    def test_preprocessing_result_creation(self):
        """Test creating preprocessing result."""
        result = PreprocessingResult(action=PreprocessingAction.CONTINUE)
        
        assert result.action == PreprocessingAction.CONTINUE
        assert result.modified_request is None
        assert result.redirect_url is None
        assert result.response is None
        assert result.metadata == {}
        assert "processing_time_ms" in result.performance_metrics
        assert "memory_usage_bytes" in result.performance_metrics
        assert "transformations_applied" in result.performance_metrics
    
    def test_preprocessing_result_with_data(self):
        """Test preprocessing result with data."""
        request = create_mock_request()
        response = MockResponse(status_code=302)
        metadata = {"test": "data"}
        metrics = {"custom_metric": 42}
        
        result = PreprocessingResult(
            action=PreprocessingAction.REDIRECT,
            modified_request=request,
            redirect_url="/redirected",
            response=response,
            metadata=metadata,
            performance_metrics=metrics
        )
        
        assert result.action == PreprocessingAction.REDIRECT
        assert result.modified_request == request
        assert result.redirect_url == "/redirected"
        assert result.response == response
        assert result.metadata == metadata
        assert result.performance_metrics["custom_metric"] == 42
    
    def test_header_rule_creation(self):
        """Test creating header rule."""
        rule = HeaderRule(
            action="add",
            header_name="X-Test",
            header_value="test-value"
        )
        
        assert rule.action == "add"
        assert rule.header_name == "X-Test"
        assert rule.header_value == "test-value"
        assert rule.condition is None
        assert rule.pattern is None
        assert rule.replacement is None
        assert rule.case_sensitive is True
    
    def test_body_transformation_creation(self):
        """Test creating body transformation."""
        def transform_func(data):
            return data
        
        transformation = BodyTransformation(
            source_format=BodyFormat.JSON,
            target_format=BodyFormat.JSON,
            transformation_function=transform_func
        )
        
        assert transformation.source_format == BodyFormat.JSON
        assert transformation.target_format == BodyFormat.JSON
        assert transformation.transformation_function == transform_func
        assert transformation.condition is None
        assert transformation.preserve_encoding is True
        assert transformation.max_size_bytes is None
    
    def test_url_rewrite_rule_creation(self):
        """Test creating URL rewrite rule."""
        pattern = re.compile(r"/old/(.*)")
        rule = URLRewriteRule(
            pattern=pattern,
            replacement="/new/\\1",
            redirect=True,
            permanent=True
        )
        
        assert rule.pattern == pattern
        assert rule.replacement == "/new/\\1"
        assert rule.redirect is True
        assert rule.permanent is True
        assert rule.condition is None
        assert rule.preserve_query is True
        assert rule.case_sensitive is True
    
    def test_query_param_rule_creation(self):
        """Test creating query param rule."""
        rule = QueryParamRule(
            action="add",
            param_name="version",
            param_value="v1"
        )
        
        assert rule.action == "add"
        assert rule.param_name == "version"
        assert rule.param_value == "v1"
        assert rule.condition is None
        assert rule.pattern is None
        assert rule.replacement is None
    
    def test_preprocessing_config_creation(self):
        """Test creating preprocessing config."""
        config = PreprocessingConfig(
            max_processing_time_ms=500.0,
            max_body_size_bytes=1024 * 1024,
            enable_caching=False
        )
        
        assert config.enabled is True
        assert config.max_processing_time_ms == 500.0
        assert config.max_body_size_bytes == 1024 * 1024
        assert config.enable_caching is False
        assert config.cache_ttl_seconds == 300
        assert config.enable_metrics is True
        assert config.enable_logging is True
        assert config.fail_on_error is False
        assert config.priority == PreprocessingPriority.NORMAL
        assert TransformationScope.ALL in config.scopes


class TestMockClasses:
    """Test mock classes functionality."""
    
    def test_mock_request_creation(self):
        """Test creating mock request."""
        request = create_mock_request(
            method="POST",
            path="/api/test",
            query_params={"param": "value"},
            headers={"Content-Type": "application/json"},
            body=b'{"test": "data"}'
        )
        
        assert request.method == "POST"
        assert request.url.path == "/api/test"
        assert dict(request.query_params) == {"param": "value"}
        assert request.headers["content-type"] == "application/json"
        assert request._body == b'{"test": "data"}'
    
    @pytest.mark.asyncio
    async def test_mock_request_body_methods(self):
        """Test mock request body methods."""
        json_data = {"test": "data", "number": 42}
        request = create_mock_json_request(data=json_data)
        
        # Test body method
        body = await request.body()
        assert json.loads(body.decode()) == json_data
        
        # Test json method
        parsed_json = await request.json()
        assert parsed_json == json_data
    
    def test_mock_response_creation(self):
        """Test creating mock response."""
        response = MockResponse(
            content={"message": "success"},
            status_code=201,
            headers={"Location": "/created"},
            media_type="application/json"
        )
        
        assert response.content == {"message": "success"}
        assert response.status_code == 201
        assert response.headers["Location"] == "/created"
        assert response.media_type == "application/json"
    
    @pytest.mark.asyncio
    async def test_mock_header_manipulator(self):
        """Test mock header manipulator."""
        manipulator = MockHeaderManipulator()
        
        # Test normal processing
        request = create_mock_request()
        result = await manipulator.process(request)
        assert result.action == PreprocessingAction.CONTINUE
        assert manipulator.metrics["requests_processed"] == 1
        
        # Test blocking
        request = create_mock_request(headers={"mock-block": "true"})
        result = await manipulator.process(request)
        assert result.action == PreprocessingAction.BLOCK
        assert manipulator.metrics["requests_blocked"] == 1
        
        # Test modification
        request = create_mock_request(headers={"mock-modify": "true"})
        result = await manipulator.process(request)
        assert result.action == PreprocessingAction.MODIFY
        assert result.modified_request is not None
        assert manipulator.metrics["requests_modified"] == 1
    
    @pytest.mark.asyncio
    async def test_mock_body_transformer(self):
        """Test mock body transformer."""
        transformer = MockBodyTransformer()
        
        # Test normal processing
        request = create_mock_request(body=b"normal body")
        result = await transformer.process(request)
        assert result.action == PreprocessingAction.CONTINUE
        
        # Test transformation
        request = create_mock_request(body=b"mock-transform data")
        result = await transformer.process(request)
        assert result.action == PreprocessingAction.MODIFY
        assert result.modified_request is not None
        
        # Verify transformed body
        transformed_body = await result.modified_request.body()
        assert b"transformed" in transformed_body
    
    @pytest.mark.asyncio
    async def test_mock_url_rewriter(self):
        """Test mock URL rewriter."""
        rewriter = MockURLRewriter()
        
        # Test normal processing
        request = create_mock_request(path="/normal")
        result = await rewriter.process(request)
        assert result.action == PreprocessingAction.CONTINUE
        
        # Test redirection
        request = create_mock_request(path="/mock-redirect/test")
        result = await rewriter.process(request)
        assert result.action == PreprocessingAction.REDIRECT
        assert result.redirect_url == "/redirected"
        assert result.response is not None
        
        # Test rewriting
        request = create_mock_request(path="/mock-rewrite/test")
        result = await rewriter.process(request)
        assert result.action == PreprocessingAction.MODIFY
        assert result.modified_request.url.path == "/rewritten/test"
    
    @pytest.mark.asyncio
    async def test_mock_query_param_manipulator(self):
        """Test mock query param manipulator."""
        manipulator = MockQueryParamManipulator()
        
        # Test normal processing
        request = create_mock_request(query_params={"normal": "param"})
        result = await manipulator.process(request)
        assert result.action == PreprocessingAction.CONTINUE
        
        # Test modification
        request = create_mock_request(query_params={"mock-modify": "true"})
        result = await manipulator.process(request)
        assert result.action == PreprocessingAction.MODIFY
        assert "modified=true" in str(result.modified_request.query_params)
    
    @pytest.mark.asyncio
    async def test_mock_preprocessing_pipeline(self):
        """Test mock preprocessing pipeline."""
        pipeline = MockPreprocessingPipeline()
        
        # Add mock processors
        pipeline.add_processor(MockHeaderManipulator())
        pipeline.add_processor(MockBodyTransformer())
        
        # Test normal processing
        request = create_mock_request()
        result = await pipeline.process(request)
        assert result.action == PreprocessingAction.CONTINUE
        
        # Test blocking
        request = create_mock_request(path="/mock-block")
        result = await pipeline.process(request)
        assert result.action == PreprocessingAction.BLOCK
        
        # Test metrics
        metrics = pipeline.get_metrics()
        assert metrics["pipeline_name"] == "MockPipeline"
        assert metrics["processor_count"] == 2
        assert "pipeline_metrics" in metrics


class TestHeaderManipulator:
    """Test header manipulator functionality."""
    
    @pytest.mark.asyncio
    async def test_header_manipulator_creation(self):
        """Test creating header manipulator."""
        manipulator = HeaderManipulator(
            name="TestManipulator",
            priority=PreprocessingPriority.HIGH,
            enabled=True
        )
        
        assert manipulator.name == "TestManipulator"
        assert manipulator.priority == PreprocessingPriority.HIGH
        assert manipulator.enabled is True
        assert len(manipulator.rules) == 0
    
    @pytest.mark.asyncio
    async def test_add_header_rule(self):
        """Test adding header rules."""
        manipulator = HeaderManipulator()
        
        manipulator.add_header_rule(
            action="add",
            header_name="X-Test",
            header_value="test-value"
        )
        
        assert len(manipulator.rules) == 1
        rule = manipulator.rules[0]
        assert rule.action == "add"
        assert rule.header_name == "X-Test"
        assert rule.header_value == "test-value"
    
    @pytest.mark.asyncio
    async def test_header_add_operation(self):
        """Test header add operation."""
        manipulator = HeaderManipulator()
        manipulator.add_header_rule("add", "X-Added", "added-value")
        
        request = create_mock_request()
        result = await manipulator.process(request)
        
        assert result.action == PreprocessingAction.MODIFY
        assert result.modified_request is not None
        
        # Check added header (case-insensitive)
        headers = dict(result.modified_request.headers)
        assert headers.get("x-added") == "added-value"
    
    @pytest.mark.asyncio
    async def test_header_remove_operation(self):
        """Test header remove operation."""
        manipulator = HeaderManipulator()
        manipulator.add_header_rule("remove", "X-Remove-Me")
        
        request = create_mock_request(headers={"X-Remove-Me": "remove-this"})
        result = await manipulator.process(request)
        
        assert result.action == PreprocessingAction.MODIFY
        assert result.modified_request is not None
        
        # Check removed header
        headers = dict(result.modified_request.headers)
        assert "x-remove-me" not in headers
    
    @pytest.mark.asyncio
    async def test_header_modify_operation(self):
        """Test header modify operation."""
        manipulator = HeaderManipulator()
        manipulator.add_header_rule(
            "modify", "X-Modify-Me",
            pattern=r"old",
            replacement="new"
        )
        
        request = create_mock_request(headers={"X-Modify-Me": "old-value"})
        result = await manipulator.process(request)
        
        assert result.action == PreprocessingAction.MODIFY
        assert result.modified_request is not None
        
        # Check modified header
        headers = dict(result.modified_request.headers)
        assert headers.get("x-modify-me") == "new-value"
    
    @pytest.mark.asyncio
    async def test_header_replace_operation(self):
        """Test header replace operation."""
        manipulator = HeaderManipulator()
        manipulator.add_header_rule("replace", "X-Replace-Me", "new-value")
        
        request = create_mock_request(headers={"X-Replace-Me": "old-value"})
        result = await manipulator.process(request)
        
        assert result.action == PreprocessingAction.MODIFY
        assert result.modified_request is not None
        
        # Check replaced header
        headers = dict(result.modified_request.headers)
        assert headers.get("x-replace-me") == "new-value"
    
    @pytest.mark.asyncio
    async def test_header_conditional_rule(self):
        """Test header rule with condition."""
        manipulator = HeaderManipulator()
        
        # Add rule that only applies when User-Agent contains "test"
        def has_test_agent(headers: Headers) -> bool:
            user_agent = headers.get("user-agent", "")
            return "test" in user_agent.lower()
        
        manipulator.add_header_rule(
            "add", "X-Test-Agent", "detected",
            condition=has_test_agent
        )
        
        # Test with matching condition
        request = create_mock_request(headers={"User-Agent": "test-browser"})
        result = await manipulator.process(request)
        assert result.action == PreprocessingAction.MODIFY
        headers = dict(result.modified_request.headers)
        assert headers.get("x-test-agent") == "detected"
        
        # Test without matching condition
        request = create_mock_request(headers={"User-Agent": "normal-browser"})
        result = await manipulator.process(request)
        assert result.action == PreprocessingAction.CONTINUE
    
    @pytest.mark.asyncio
    async def test_header_manipulator_disabled(self):
        """Test disabled header manipulator."""
        manipulator = HeaderManipulator(enabled=False)
        manipulator.add_header_rule("add", "X-Test", "value")
        
        request = create_mock_request()
        result = await manipulator.process(request)
        
        assert result.action == PreprocessingAction.CONTINUE
        assert manipulator.metrics["requests_processed"] == 0
    
    @pytest.mark.asyncio
    async def test_header_manipulator_metrics(self):
        """Test header manipulator metrics."""
        manipulator = HeaderManipulator()
        manipulator.add_header_rule("add", "X-Test", "value")
        
        # Process some requests
        for _ in range(3):
            request = create_mock_request()
            await manipulator.process(request)
        
        metrics = manipulator.get_metrics()
        assert metrics["requests_processed"] == 3
        assert metrics["requests_modified"] == 3
        assert metrics["total_processing_time_ms"] > 0
        
        # Reset metrics
        manipulator.reset_metrics()
        metrics = manipulator.get_metrics()
        assert metrics["requests_processed"] == 0
        assert metrics["requests_modified"] == 0
        assert metrics["total_processing_time_ms"] == 0.0


class TestBodyTransformer:
    """Test body transformer functionality."""
    
    @pytest.mark.asyncio
    async def test_body_transformer_creation(self):
        """Test creating body transformer."""
        transformer = BodyTransformer(
            name="TestTransformer",
            priority=PreprocessingPriority.LOW,
            enabled=True,
            max_body_size=1024
        )
        
        assert transformer.name == "TestTransformer"
        assert transformer.priority == PreprocessingPriority.LOW
        assert transformer.enabled is True
        assert transformer.max_body_size == 1024
        assert len(transformer.transformations) == 0
    
    @pytest.mark.asyncio
    async def test_json_transformation(self):
        """Test JSON transformation."""
        transformer = BodyTransformer()
        
        def uppercase_values(data: dict) -> dict:
            return {k: v.upper() if isinstance(v, str) else v for k, v in data.items()}
        
        transformer.add_json_transformation(uppercase_values)
        
        request = create_mock_json_request(data={"name": "test", "value": "data"})
        result = await transformer.process(request)
        
        assert result.action == PreprocessingAction.MODIFY
        assert result.modified_request is not None
        
        # Check transformed body
        body = await result.modified_request.body()
        transformed_data = json.loads(body.decode())
        assert transformed_data["name"] == "TEST"
        assert transformed_data["value"] == "DATA"
    
    @pytest.mark.asyncio
    async def test_text_transformation(self):
        """Test text transformation."""
        transformer = BodyTransformer()
        
        def uppercase_text(text: str) -> str:
            return text.upper()
        
        transformation = BodyTransformation(
            source_format=BodyFormat.TEXT,
            target_format=BodyFormat.TEXT,
            transformation_function=uppercase_text
        )
        transformer.add_transformation(transformation)
        
        request = create_mock_request(body="hello world")
        result = await transformer.process(request)
        
        assert result.action == PreprocessingAction.MODIFY
        assert result.modified_request is not None
        
        # Check transformed body
        body = await result.modified_request.body()
        assert body.decode() == "HELLO WORLD"
    
    @pytest.mark.asyncio
    async def test_form_transformation(self):
        """Test form data transformation."""
        transformer = BodyTransformer()
        
        def add_timestamp(form_data: dict) -> dict:
            form_data["timestamp"] = ["2023-01-01T00:00:00Z"]
            return form_data
        
        transformation = BodyTransformation(
            source_format=BodyFormat.FORM,
            target_format=BodyFormat.FORM,
            transformation_function=add_timestamp
        )
        transformer.add_transformation(transformation)
        
        request = create_mock_form_request(data={"name": "test"})
        result = await transformer.process(request)
        
        assert result.action == PreprocessingAction.MODIFY
        assert result.modified_request is not None
        
        # Check transformed body
        body = await result.modified_request.body()
        assert b"timestamp=2023-01-01T00%3A00%3A00Z" in body
    
    @pytest.mark.asyncio
    async def test_conditional_transformation(self):
        """Test conditional transformation."""
        transformer = BodyTransformer()
        
        def only_if_contains_test(body: bytes) -> bool:
            return b"test" in body
        
        def uppercase_json(data: dict) -> dict:
            return {k: v.upper() if isinstance(v, str) else v for k, v in data.items()}
        
        transformer.add_json_transformation(uppercase_json, condition=only_if_contains_test)
        
        # Test with condition met
        request = create_mock_json_request(data={"name": "test"})
        result = await transformer.process(request)
        assert result.action == PreprocessingAction.MODIFY
        
        # Test with condition not met
        request = create_mock_json_request(data={"name": "other"})
        result = await transformer.process(request)
        assert result.action == PreprocessingAction.CONTINUE
    
    @pytest.mark.asyncio
    async def test_body_size_limit(self):
        """Test body size limit enforcement."""
        transformer = BodyTransformer(max_body_size=100)
        transformer.add_json_transformation(lambda x: x)
        
        # Create request with large body
        large_body = create_large_request_body(1)  # 1KB
        request = create_mock_request(body=large_body)
        result = await transformer.process(request)
        
        # Should skip transformation due to size limit
        assert result.action == PreprocessingAction.CONTINUE
    
    @pytest.mark.asyncio
    async def test_transformation_error_handling(self):
        """Test transformation error handling."""
        transformer = BodyTransformer()
        
        def failing_transform(data: dict) -> dict:
            raise ValueError("Transformation failed")
        
        transformer.add_json_transformation(failing_transform)
        
        request = create_mock_json_request(data={"test": "data"})
        result = await transformer.process(request)
        
        # Should continue despite error
        assert result.action == PreprocessingAction.CONTINUE
        assert transformer.metrics["errors_encountered"] == 1
    
    @pytest.mark.asyncio
    async def test_empty_body_handling(self):
        """Test handling of empty request body."""
        transformer = BodyTransformer()
        transformer.add_json_transformation(lambda x: x)
        
        request = create_mock_request(method="GET", body=b"")
        result = await transformer.process(request)
        
        assert result.action == PreprocessingAction.CONTINUE
    
    @pytest.mark.asyncio
    async def test_multiple_transformations(self):
        """Test multiple transformations on same body."""
        transformer = BodyTransformer()
        
        def add_field1(data: dict) -> dict:
            data["field1"] = "added1"
            return data
        
        def add_field2(data: dict) -> dict:
            data["field2"] = "added2"
            return data
        
        transformer.add_json_transformation(add_field1)
        transformer.add_json_transformation(add_field2)
        
        request = create_mock_json_request(data={"original": "data"})
        result = await transformer.process(request)
        
        assert result.action == PreprocessingAction.MODIFY
        
        # Check both transformations applied
        body = await result.modified_request.body()
        transformed_data = json.loads(body.decode())
        assert transformed_data["field1"] == "added1"
        assert transformed_data["field2"] == "added2"
        assert transformed_data["original"] == "data"


class TestURLRewriter:
    """Test URL rewriter functionality."""
    
    @pytest.mark.asyncio
    async def test_url_rewriter_creation(self):
        """Test creating URL rewriter."""
        rewriter = URLRewriter(
            name="TestRewriter",
            priority=PreprocessingPriority.HIGH,
            enabled=True
        )
        
        assert rewriter.name == "TestRewriter"
        assert rewriter.priority == PreprocessingPriority.HIGH
        assert rewriter.enabled is True
        assert len(rewriter.rules) == 0
    
    @pytest.mark.asyncio
    async def test_path_rewriting(self):
        """Test path rewriting without redirect."""
        rewriter = URLRewriter()
        rewriter.add_rewrite_rule(
            pattern=r"^/old-api/(.*)$",
            replacement="/new-api/\\1",
            redirect=False
        )
        
        request = create_mock_request(path="/old-api/users/123")
        result = await rewriter.process(request)
        
        assert result.action == PreprocessingAction.MODIFY
        assert result.modified_request is not None
        assert result.modified_request.url.path == "/new-api/users/123"
    
    @pytest.mark.asyncio
    async def test_redirect_rewriting(self):
        """Test redirect rewriting."""
        rewriter = URLRewriter()
        rewriter.add_rewrite_rule(
            pattern=r"^/redirect-me/(.*)$",
            replacement="/redirected/\\1",
            redirect=True,
            permanent=False
        )
        
        request = create_mock_request(path="/redirect-me/test")
        result = await rewriter.process(request)
        
        assert result.action == PreprocessingAction.REDIRECT
        assert result.redirect_url == "/redirected/test"
        assert result.response is not None
        assert result.response.status_code == 302
    
    @pytest.mark.asyncio
    async def test_permanent_redirect(self):
        """Test permanent redirect rewriting."""
        rewriter = URLRewriter()
        rewriter.add_rewrite_rule(
            pattern=r"^/old-site/(.*)$",
            replacement="/new-site/\\1",
            redirect=True,
            permanent=True
        )
        
        request = create_mock_request(path="/old-site/page")
        result = await rewriter.process(request)
        
        assert result.action == PreprocessingAction.REDIRECT
        assert result.redirect_url == "/new-site/page"
        assert result.response.status_code == 301
    
    @pytest.mark.asyncio
    async def test_query_preservation(self):
        """Test query parameter preservation in redirects."""
        rewriter = URLRewriter()
        rewriter.add_rewrite_rule(
            pattern=r"^/old/(.*)$",
            replacement="/new/\\1",
            redirect=True,
            preserve_query=True
        )
        
        request = create_mock_request(
            path="/old/page",
            query_params={"param1": "value1", "param2": "value2"}
        )
        result = await rewriter.process(request)
        
        assert result.action == PreprocessingAction.REDIRECT
        assert "param1=value1" in result.redirect_url
        assert "param2=value2" in result.redirect_url
    
    @pytest.mark.asyncio
    async def test_conditional_rewriting(self):
        """Test conditional URL rewriting."""
        rewriter = URLRewriter()
        
        def only_for_api(path: str) -> bool:
            return "/api/" in path
        
        rewriter.add_rewrite_rule(
            pattern=r"^/api/v1/(.*)$",
            replacement="/api/v2/\\1",
            condition=only_for_api
        )
        
        # Test with condition met
        request = create_mock_request(path="/api/v1/users")
        result = await rewriter.process(request)
        assert result.action == PreprocessingAction.MODIFY
        assert result.modified_request.url.path == "/api/v2/users"
        
        # Test with condition not met
        request = create_mock_request(path="/web/v1/users")
        result = await rewriter.process(request)
        assert result.action == PreprocessingAction.CONTINUE
    
    @pytest.mark.asyncio
    async def test_case_insensitive_rewriting(self):
        """Test case-insensitive URL rewriting."""
        rewriter = URLRewriter()
        rewriter.add_rewrite_rule(
            pattern=r"^/OLD/(.*)$",
            replacement="/new/\\1",
            case_sensitive=False
        )
        
        request = create_mock_request(path="/old/test")
        result = await rewriter.process(request)
        
        assert result.action == PreprocessingAction.MODIFY
        assert result.modified_request.url.path == "/new/test"
    
    @pytest.mark.asyncio
    async def test_no_matching_rule(self):
        """Test behavior when no rules match."""
        rewriter = URLRewriter()
        rewriter.add_rewrite_rule(
            pattern=r"^/api/(.*)$",
            replacement="/v1/api/\\1"
        )
        
        request = create_mock_request(path="/web/page")
        result = await rewriter.process(request)
        
        assert result.action == PreprocessingAction.CONTINUE
        assert result.modified_request is None
    
    @pytest.mark.asyncio
    async def test_multiple_rules_first_match_wins(self):
        """Test that first matching rule wins."""
        rewriter = URLRewriter()
        
        # Add rules in order
        rewriter.add_rewrite_rule(
            pattern=r"^/test/(.*)$",
            replacement="/first/\\1"
        )
        rewriter.add_rewrite_rule(
            pattern=r"^/test/(.*)$",
            replacement="/second/\\1"
        )
        
        request = create_mock_request(path="/test/page")
        result = await rewriter.process(request)
        
        assert result.action == PreprocessingAction.MODIFY
        assert result.modified_request.url.path == "/first/page"


class TestQueryParamManipulator:
    """Test query parameter manipulator functionality."""
    
    @pytest.mark.asyncio
    async def test_query_param_manipulator_creation(self):
        """Test creating query param manipulator."""
        manipulator = QueryParamManipulator(
            name="TestManipulator",
            priority=PreprocessingPriority.LOW,
            enabled=True
        )
        
        assert manipulator.name == "TestManipulator"
        assert manipulator.priority == PreprocessingPriority.LOW
        assert manipulator.enabled is True
        assert len(manipulator.rules) == 0
    
    @pytest.mark.asyncio
    async def test_add_query_param(self):
        """Test adding query parameter."""
        manipulator = QueryParamManipulator()
        manipulator.add_param_rule("add", "version", "v1")
        
        request = create_mock_request(query_params={"existing": "param"})
        result = await manipulator.process(request)
        
        assert result.action == PreprocessingAction.MODIFY
        assert result.modified_request is not None
        
        # Check added parameter
        params = dict(result.modified_request.query_params)
        assert params["version"] == "v1"
        assert params["existing"] == "param"
    
    @pytest.mark.asyncio
    async def test_remove_query_param(self):
        """Test removing query parameter."""
        manipulator = QueryParamManipulator()
        manipulator.add_param_rule("remove", "remove_me")
        
        request = create_mock_request(query_params={"keep": "this", "remove_me": "gone"})
        result = await manipulator.process(request)
        
        assert result.action == PreprocessingAction.MODIFY
        assert result.modified_request is not None
        
        # Check removed parameter
        params = dict(result.modified_request.query_params)
        assert "remove_me" not in params
        assert params["keep"] == "this"
    
    @pytest.mark.asyncio
    async def test_modify_query_param(self):
        """Test modifying query parameter."""
        manipulator = QueryParamManipulator()
        manipulator.add_param_rule(
            "modify", "version",
            pattern=r"v(\d+)",
            replacement="version_\\1"
        )
        
        request = create_mock_request(query_params={"version": "v2"})
        result = await manipulator.process(request)
        
        assert result.action == PreprocessingAction.MODIFY
        assert result.modified_request is not None
        
        # Check modified parameter
        params = dict(result.modified_request.query_params)
        assert params["version"] == "version_2"
    
    @pytest.mark.asyncio
    async def test_replace_query_param(self):
        """Test replacing query parameter."""
        manipulator = QueryParamManipulator()
        manipulator.add_param_rule("replace", "format", "json")
        
        request = create_mock_request(query_params={"format": "xml"})
        result = await manipulator.process(request)
        
        assert result.action == PreprocessingAction.MODIFY
        assert result.modified_request is not None
        
        # Check replaced parameter
        params = dict(result.modified_request.query_params)
        assert params["format"] == "json"
    
    @pytest.mark.asyncio
    async def test_conditional_param_manipulation(self):
        """Test conditional parameter manipulation."""
        manipulator = QueryParamManipulator()
        
        def has_api_key(params: QueryParams) -> bool:
            return "api_key" in params
        
        manipulator.add_param_rule(
            "add", "authenticated", "true",
            condition=has_api_key
        )
        
        # Test with condition met
        request = create_mock_request(query_params={"api_key": "secret"})
        result = await manipulator.process(request)
        assert result.action == PreprocessingAction.MODIFY
        params = dict(result.modified_request.query_params)
        assert params["authenticated"] == "true"
        
        # Test with condition not met
        request = create_mock_request(query_params={"other": "param"})
        result = await manipulator.process(request)
        assert result.action == PreprocessingAction.CONTINUE
    
    @pytest.mark.asyncio
    async def test_multiple_param_operations(self):
        """Test multiple parameter operations."""
        manipulator = QueryParamManipulator()
        manipulator.add_param_rule("add", "source", "api")
        manipulator.add_param_rule("remove", "debug")
        manipulator.add_param_rule("replace", "format", "json")
        
        request = create_mock_request(query_params={
            "format": "xml",
            "debug": "true",
            "existing": "param"
        })
        result = await manipulator.process(request)
        
        assert result.action == PreprocessingAction.MODIFY
        assert result.modified_request is not None
        
        # Check all operations applied
        params = dict(result.modified_request.query_params)
        assert params["source"] == "api"  # added
        assert "debug" not in params  # removed
        assert params["format"] == "json"  # replaced
        assert params["existing"] == "param"  # preserved
    
    @pytest.mark.asyncio
    async def test_no_param_changes(self):
        """Test when no parameter changes are made."""
        manipulator = QueryParamManipulator()
        manipulator.add_param_rule("remove", "nonexistent")
        
        request = create_mock_request(query_params={"existing": "param"})
        result = await manipulator.process(request)
        
        assert result.action == PreprocessingAction.CONTINUE


class TestConditionalPreprocessor:
    """Test conditional preprocessor functionality."""
    
    @pytest.mark.asyncio
    async def test_conditional_processor_creation(self):
        """Test creating conditional preprocessor."""
        processor = ConditionalPreprocessor(
            name="TestConditional",
            priority=PreprocessingPriority.HIGH,
            enabled=True
        )
        
        assert processor.name == "TestConditional"
        assert processor.priority == PreprocessingPriority.HIGH
        assert processor.enabled is True
        assert len(processor.conditional_processors) == 0
    
    @pytest.mark.asyncio
    async def test_add_conditional_processor(self):
        """Test adding conditional processors."""
        processor = ConditionalPreprocessor()
        
        # Create condition and sub-processor
        def is_json_request(request: Request) -> bool:
            return "json" in request.headers.get("content-type", "")
        
        json_processor = MockRequestPreprocessor(
            name="JSONProcessor",
            mock_action=PreprocessingAction.MODIFY
        )
        
        processor.add_conditional_processor(is_json_request, json_processor)
        
        assert len(processor.conditional_processors) == 1
    
    @pytest.mark.asyncio
    async def test_conditional_processing_match(self):
        """Test conditional processing when condition matches."""
        processor = ConditionalPreprocessor()
        
        def is_post_request(request: Request) -> bool:
            return request.method == "POST"
        
        post_processor = MockRequestPreprocessor(
            name="POSTProcessor",
            mock_action=PreprocessingAction.MODIFY
        )
        
        processor.add_conditional_processor(is_post_request, post_processor)
        
        # Test with POST request (condition matches)
        request = create_mock_request(method="POST")
        result = await processor.process(request)
        
        assert result.action == PreprocessingAction.MODIFY
        assert len(post_processor.process_calls) == 1
        assert processor.metrics["requests_modified"] == 1
    
    @pytest.mark.asyncio
    async def test_conditional_processing_no_match(self):
        """Test conditional processing when no condition matches."""
        processor = ConditionalPreprocessor()
        
        def is_post_request(request: Request) -> bool:
            return request.method == "POST"
        
        post_processor = MockRequestPreprocessor(
            name="POSTProcessor",
            mock_action=PreprocessingAction.MODIFY
        )
        
        processor.add_conditional_processor(is_post_request, post_processor)
        
        # Test with GET request (condition doesn't match)
        request = create_mock_request(method="GET")
        result = await processor.process(request)
        
        assert result.action == PreprocessingAction.CONTINUE
        assert len(post_processor.process_calls) == 0
        assert processor.metrics["requests_modified"] == 0
    
    @pytest.mark.asyncio
    async def test_multiple_conditional_processors(self):
        """Test multiple conditional processors."""
        processor = ConditionalPreprocessor()
        
        def is_api_request(request: Request) -> bool:
            return request.url.path.startswith("/api/")
        
        def is_json_request(request: Request) -> bool:
            return "json" in request.headers.get("content-type", "")
        
        api_processor = MockRequestPreprocessor(
            name="APIProcessor",
            mock_action=PreprocessingAction.MODIFY
        )
        
        json_processor = MockRequestPreprocessor(
            name="JSONProcessor",
            mock_action=PreprocessingAction.BLOCK
        )
        
        processor.add_conditional_processor(is_api_request, api_processor)
        processor.add_conditional_processor(is_json_request, json_processor)
        
        # Test request that matches first condition
        request = create_mock_request(path="/api/users")
        result = await processor.process(request)
        
        assert result.action == PreprocessingAction.MODIFY
        assert len(api_processor.process_calls) == 1
        assert len(json_processor.process_calls) == 0  # First match wins
    
    @pytest.mark.asyncio
    async def test_conditional_processor_error_handling(self):
        """Test error handling in conditional processor."""
        processor = ConditionalPreprocessor()
        
        def always_true(request: Request) -> bool:
            return True
        
        failing_processor = MockFailingPreprocessor(
            name="FailingProcessor",
            exception_to_raise=RuntimeError("Test error")
        )
        
        processor.add_conditional_processor(always_true, failing_processor)
        
        request = create_mock_request()
        result = await processor.process(request)
        
        # Should continue despite error
        assert result.action == PreprocessingAction.CONTINUE
        assert processor.metrics["errors_encountered"] == 1


class TestPreprocessingPipeline:
    """Test preprocessing pipeline functionality."""
    
    @pytest.mark.asyncio
    async def test_pipeline_creation(self):
        """Test creating preprocessing pipeline."""
        config = PreprocessingConfig(enable_caching=False)
        pipeline = PreprocessingPipeline("TestPipeline", config)
        
        assert pipeline.name == "TestPipeline"
        assert pipeline.config == config
        assert len(pipeline.processors) == 0
        assert len(pipeline.cache) == 0
    
    @pytest.mark.asyncio
    async def test_add_remove_processors(self):
        """Test adding and removing processors."""
        pipeline = PreprocessingPipeline()
        
        processor1 = MockRequestPreprocessor("Proc1", PreprocessingPriority.HIGH)
        processor2 = MockRequestPreprocessor("Proc2", PreprocessingPriority.LOW)
        
        # Add processors
        pipeline.add_processor(processor1)
        pipeline.add_processor(processor2)
        
        assert len(pipeline.processors) == 2
        # Should be sorted by priority (high first)
        assert pipeline.processors[0].priority == PreprocessingPriority.HIGH
        assert pipeline.processors[1].priority == PreprocessingPriority.LOW
        
        # Remove processor
        removed = pipeline.remove_processor("Proc1")
        assert removed is True
        assert len(pipeline.processors) == 1
        
        # Try to remove non-existent processor
        removed = pipeline.remove_processor("NonExistent")
        assert removed is False
    
    @pytest.mark.asyncio
    async def test_get_processor(self):
        """Test getting processor by name."""
        pipeline = PreprocessingPipeline()
        processor = MockRequestPreprocessor("TestProc")
        pipeline.add_processor(processor)
        
        # Get existing processor
        found = pipeline.get_processor("TestProc")
        assert found == processor
        
        # Get non-existent processor
        not_found = pipeline.get_processor("NonExistent")
        assert not_found is None
    
    @pytest.mark.asyncio
    async def test_pipeline_processing_order(self):
        """Test pipeline processing order by priority."""
        pipeline = PreprocessingPipeline()
        
        # Add processors in random order
        low_proc = MockRequestPreprocessor("Low", PreprocessingPriority.LOW)
        high_proc = MockRequestPreprocessor("High", PreprocessingPriority.HIGH)
        normal_proc = MockRequestPreprocessor("Normal", PreprocessingPriority.NORMAL)
        
        pipeline.add_processor(normal_proc)
        pipeline.add_processor(low_proc)
        pipeline.add_processor(high_proc)
        
        request = create_mock_request()
        await pipeline.process(request)
        
        # Verify processing order (highest priority first)
        assert len(high_proc.process_calls) == 1
        assert len(normal_proc.process_calls) == 1
        assert len(low_proc.process_calls) == 1
    
    @pytest.mark.asyncio
    async def test_pipeline_early_termination_block(self):
        """Test pipeline early termination on block action."""
        pipeline = PreprocessingPipeline()
        
        blocking_proc = MockRequestPreprocessor(
            "Blocker", 
            PreprocessingPriority.HIGH,
            mock_action=PreprocessingAction.BLOCK
        )
        normal_proc = MockRequestPreprocessor("Normal", PreprocessingPriority.LOW)
        
        pipeline.add_processor(blocking_proc)
        pipeline.add_processor(normal_proc)
        
        request = create_mock_request()
        result = await pipeline.process(request)
        
        assert result.action == PreprocessingAction.BLOCK
        assert len(blocking_proc.process_calls) == 1
        assert len(normal_proc.process_calls) == 0  # Should not be called
    
    @pytest.mark.asyncio
    async def test_pipeline_early_termination_redirect(self):
        """Test pipeline early termination on redirect action."""
        pipeline = PreprocessingPipeline()
        
        redirecting_proc = MockRequestPreprocessor(
            "Redirector",
            PreprocessingPriority.HIGH,
            mock_action=PreprocessingAction.REDIRECT
        )
        normal_proc = MockRequestPreprocessor("Normal", PreprocessingPriority.LOW)
        
        pipeline.add_processor(redirecting_proc)
        pipeline.add_processor(normal_proc)
        
        request = create_mock_request()
        result = await pipeline.process(request)
        
        assert result.action == PreprocessingAction.REDIRECT
        assert len(redirecting_proc.process_calls) == 1
        assert len(normal_proc.process_calls) == 0  # Should not be called
    
    @pytest.mark.asyncio
    async def test_pipeline_request_modification_chain(self):
        """Test request modification chain through pipeline."""
        pipeline = PreprocessingPipeline()
        
        # Create processors that modify requests
        modifier1 = MockRequestPreprocessor(
            "Modifier1",
            PreprocessingPriority.HIGH,
            mock_action=PreprocessingAction.MODIFY
        )
        modifier2 = MockRequestPreprocessor(
            "Modifier2", 
            PreprocessingPriority.LOW,
            mock_action=PreprocessingAction.MODIFY
        )
        
        pipeline.add_processor(modifier1)
        pipeline.add_processor(modifier2)
        
        request = create_mock_request()
        result = await pipeline.process(request)
        
        assert result.action == PreprocessingAction.MODIFY
        assert result.modified_request is not None
        assert len(modifier1.process_calls) == 1
        assert len(modifier2.process_calls) == 1
    
    @pytest.mark.asyncio
    async def test_pipeline_caching(self):
        """Test pipeline caching functionality."""
        config = PreprocessingConfig(enable_caching=True)
        pipeline = PreprocessingPipeline(config=config)
        
        processor = MockRequestPreprocessor(
            "CachedProcessor",
            mock_action=PreprocessingAction.MODIFY
        )
        pipeline.add_processor(processor)
        
        request = create_mock_request()
        
        # First request should process and cache
        result1 = await pipeline.process(request)
        assert result1.action == PreprocessingAction.MODIFY
        assert len(processor.process_calls) == 1
        assert pipeline.pipeline_metrics["cache_misses"] == 1
        
        # Second identical request should use cache
        result2 = await pipeline.process(request)
        assert result2.action == PreprocessingAction.MODIFY
        assert len(processor.process_calls) == 1  # Not called again
        assert pipeline.pipeline_metrics["cache_hits"] == 1
    
    @pytest.mark.asyncio
    async def test_pipeline_disabled_processor(self):
        """Test pipeline with disabled processor."""
        pipeline = PreprocessingPipeline()
        
        disabled_proc = MockRequestPreprocessor("Disabled", enabled=False)
        enabled_proc = MockRequestPreprocessor("Enabled", enabled=True)
        
        pipeline.add_processor(disabled_proc)
        pipeline.add_processor(enabled_proc)
        
        request = create_mock_request()
        await pipeline.process(request)
        
        assert len(disabled_proc.process_calls) == 0
        assert len(enabled_proc.process_calls) == 1
    
    @pytest.mark.asyncio
    async def test_pipeline_metrics(self):
        """Test pipeline metrics collection."""
        pipeline = PreprocessingPipeline()
        processor = MockRequestPreprocessor("TestProc")
        pipeline.add_processor(processor)
        
        # Process some requests
        for _ in range(3):
            request = create_mock_request()
            await pipeline.process(request)
        
        metrics = pipeline.get_metrics()
        assert metrics["pipeline_name"] == "DefaultPipeline"
        assert metrics["pipeline_metrics"]["requests_processed"] == 3
        assert metrics["processor_count"] == 1
        assert len(metrics["processors"]) == 1
    
    @pytest.mark.asyncio
    async def test_pipeline_cache_operations(self):
        """Test pipeline cache operations."""
        config = PreprocessingConfig(enable_caching=True)
        pipeline = PreprocessingPipeline(config=config)
        
        processor = MockRequestPreprocessor("CacheTestProc")
        pipeline.add_processor(processor)
        
        # Add some cached results
        request = create_mock_request()
        await pipeline.process(request)
        
        assert len(pipeline.cache) > 0
        
        # Clear cache
        pipeline.clear_cache()
        assert len(pipeline.cache) == 0
    
    @pytest.mark.asyncio
    async def test_pipeline_error_handling(self):
        """Test pipeline error handling."""
        config = PreprocessingConfig(fail_on_error=False)
        pipeline = PreprocessingPipeline(config=config)
        
        failing_proc = MockFailingPreprocessor("FailingProc")
        normal_proc = MockRequestPreprocessor("NormalProc")
        
        pipeline.add_processor(failing_proc)
        pipeline.add_processor(normal_proc)
        
        request = create_mock_request()
        result = await pipeline.process(request)
        
        # Should continue despite error
        assert result.action == PreprocessingAction.CONTINUE
        assert pipeline.pipeline_metrics["pipeline_errors"] == 1
    
    @pytest.mark.asyncio
    async def test_pipeline_reset_metrics(self):
        """Test pipeline metrics reset."""
        pipeline = PreprocessingPipeline()
        processor = MockRequestPreprocessor("TestProc")
        pipeline.add_processor(processor)
        
        # Process request to generate metrics
        request = create_mock_request()
        await pipeline.process(request)
        
        # Verify metrics exist
        assert pipeline.pipeline_metrics["requests_processed"] > 0
        assert processor.metrics["requests_processed"] > 0
        
        # Reset metrics
        pipeline.reset_metrics()
        
        # Verify metrics reset
        assert pipeline.pipeline_metrics["requests_processed"] == 0
        assert processor.metrics["requests_processed"] == 0


class TestPreprocessingShield:
    """Test preprocessing shield functionality."""
    
    @pytest.mark.asyncio
    async def test_preprocessing_shield_creation(self):
        """Test creating preprocessing shield."""
        pipeline = MockPreprocessingPipeline()
        shield = PreprocessingShield(pipeline, name="TestShield")
        
        assert shield.pipeline == pipeline
        assert shield.name == "TestShield"
        assert shield.auto_error is True
    
    @pytest.mark.asyncio
    async def test_shield_continue_action(self):
        """Test shield with continue action."""
        pipeline = MockPreprocessingPipeline()
        shield = PreprocessingShield(pipeline)
        
        request = create_mock_request()
        result = await shield._preprocess_request(request)
        
        assert result == request  # Should return original request
    
    @pytest.mark.asyncio
    async def test_shield_modify_action(self):
        """Test shield with modify action."""
        pipeline = MockPreprocessingPipeline()
        
        # Mock pipeline to return modify action
        modified_request = create_mock_request(headers={"X-Modified": "true"})
        
        async def mock_process(request):
            return PreprocessingResult(
                action=PreprocessingAction.MODIFY,
                modified_request=modified_request
            )
        
        pipeline.process = mock_process
        
        shield = PreprocessingShield(pipeline)
        request = create_mock_request()
        result = await shield._preprocess_request(request)
        
        assert result == modified_request
    
    @pytest.mark.asyncio
    async def test_shield_block_action(self):
        """Test shield with block action."""
        pipeline = MockPreprocessingPipeline()
        
        # Mock pipeline to return block action
        async def mock_process(request):
            return PreprocessingResult(action=PreprocessingAction.BLOCK)
        
        pipeline.process = mock_process
        
        shield = PreprocessingShield(pipeline)
        request = create_mock_request()
        result = await shield._preprocess_request(request)
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_shield_block_with_response(self):
        """Test shield with block action and custom response."""
        pipeline = MockPreprocessingPipeline()
        
        block_response = MockResponse(status_code=403, content="Forbidden")
        
        async def mock_process(request):
            return PreprocessingResult(
                action=PreprocessingAction.BLOCK,
                response=block_response
            )
        
        pipeline.process = mock_process
        
        shield = PreprocessingShield(pipeline)
        request = create_mock_request()
        result = await shield._preprocess_request(request)
        
        assert result == block_response
    
    @pytest.mark.asyncio
    async def test_shield_redirect_action(self):
        """Test shield with redirect action."""
        pipeline = MockPreprocessingPipeline()
        
        redirect_response = RedirectResponse(url="/redirected")
        
        async def mock_process(request):
            return PreprocessingResult(
                action=PreprocessingAction.REDIRECT,
                response=redirect_response
            )
        
        pipeline.process = mock_process
        
        shield = PreprocessingShield(pipeline)
        request = create_mock_request()
        result = await shield._preprocess_request(request)
        
        assert result == redirect_response
    
    @pytest.mark.asyncio
    async def test_shield_redirect_with_url_only(self):
        """Test shield with redirect action and URL only."""
        pipeline = MockPreprocessingPipeline()
        
        async def mock_process(request):
            return PreprocessingResult(
                action=PreprocessingAction.REDIRECT,
                redirect_url="/redirected"
            )
        
        pipeline.process = mock_process
        
        shield = PreprocessingShield(pipeline)
        request = create_mock_request()
        result = await shield._preprocess_request(request)
        
        assert isinstance(result, RedirectResponse)
        assert result.headers["location"] == "/redirected"


class TestConvenienceFunctions:
    """Test convenience functions for creating preprocessors."""
    
    def test_create_header_security_preprocessor(self):
        """Test creating security headers preprocessor."""
        processor = create_header_security_preprocessor()
        
        assert processor.name == "SecurityHeaders"
        assert processor.priority == PreprocessingPriority.HIGH
        assert len(processor.rules) >= 4  # At least security headers
        
        # Check for security headers
        rule_actions = [rule.action for rule in processor.rules]
        rule_headers = [rule.header_name for rule in processor.rules]
        
        assert "add" in rule_actions
        assert "remove" in rule_actions
        assert "X-Content-Type-Options" in rule_headers
        assert "X-Frame-Options" in rule_headers
    
    def test_create_cors_preprocessor(self):
        """Test creating CORS preprocessor."""
        allowed_origins = ["https://example.com", "https://app.example.com"]
        allowed_methods = ["GET", "POST"]
        allowed_headers = ["Content-Type"]
        
        processor = create_cors_preprocessor(
            allowed_origins=allowed_origins,
            allowed_methods=allowed_methods,
            allowed_headers=allowed_headers
        )
        
        assert processor.name == "CORS"
        assert processor.priority == PreprocessingPriority.HIGH
        assert len(processor.rules) >= 4  # CORS headers
        
        # Check CORS rules exist
        rule_headers = [rule.header_name for rule in processor.rules]
        assert "Access-Control-Allow-Origin" in rule_headers
        assert "Access-Control-Allow-Methods" in rule_headers
        assert "Access-Control-Allow-Headers" in rule_headers
    
    def test_create_json_validator_preprocessor(self):
        """Test creating JSON validator preprocessor."""
        schema = {"type": "object", "properties": {"name": {"type": "string"}}}
        processor = create_json_validator_preprocessor(schema)
        
        assert processor.name == "JSONValidator"
        assert processor.priority == PreprocessingPriority.NORMAL
        assert len(processor.transformations) >= 1
    
    def test_create_url_normalizer_preprocessor(self):
        """Test creating URL normalizer preprocessor."""
        processor = create_url_normalizer_preprocessor()
        
        assert processor.name == "URLNormalizer"
        assert processor.priority == PreprocessingPriority.HIGHEST
        assert len(processor.rules) >= 2  # Double slash and trailing slash rules
    
    def test_create_api_version_preprocessor(self):
        """Test creating API version preprocessor."""
        processor = create_api_version_preprocessor("v2")
        
        assert processor.name == "APIVersion"
        assert processor.priority == PreprocessingPriority.HIGH
        assert len(processor.rules) >= 1
    
    def test_create_preprocessing_pipeline(self):
        """Test creating preprocessing pipeline with options."""
        pipeline = create_preprocessing_pipeline(
            security_headers=True,
            cors_origins=["https://example.com"],
            url_normalization=True,
            api_versioning="v1"
        )
        
        assert pipeline.name == "CommonPreprocessing"
        assert len(pipeline.processors) >= 4  # All enabled options
        
        # Check processors exist
        processor_names = [p.name for p in pipeline.processors]
        assert "URLNormalizer" in processor_names
        assert "SecurityHeaders" in processor_names
        assert "CORS" in processor_names
        assert "APIVersion" in processor_names


class TestRealWorldScenarios:
    """Test real-world preprocessing scenarios."""
    
    @pytest.mark.asyncio
    async def test_api_security_preprocessing(self):
        """Test API security preprocessing scenario."""
        pipeline = PreprocessingPipeline("APISecurityPipeline")
        
        # Add security processors
        pipeline.add_processor(create_header_security_preprocessor())
        pipeline.add_processor(create_cors_preprocessor(["https://trusted.com"]))
        
        # Test request
        request = create_mock_request(
            method="POST",
            headers={"Origin": "https://trusted.com"}
        )
        
        result = await pipeline.process(request)
        
        assert result.action == PreprocessingAction.MODIFY
        assert result.modified_request is not None
        
        # Check security headers added
        headers = dict(result.modified_request.headers)
        assert "x-content-type-options" in headers
        assert "x-frame-options" in headers
    
    @pytest.mark.asyncio
    async def test_api_versioning_and_routing(self):
        """Test API versioning and routing preprocessing."""
        pipeline = PreprocessingPipeline("VersioningPipeline")
        
        # Add URL rewriter for versioning
        rewriter = URLRewriter()
        rewriter.add_rewrite_rule(
            pattern=r"^/api/(.*)$",
            replacement="/api/v1/\\1"
        )
        pipeline.add_processor(rewriter)
        
        # Add version parameter processor
        pipeline.add_processor(create_api_version_preprocessor("v1"))
        
        request = create_mock_request(path="/api/users")
        result = await pipeline.process(request)
        
        assert result.action == PreprocessingAction.MODIFY
        assert result.modified_request.url.path == "/api/v1/users"
        assert "version=v1" in str(result.modified_request.query_params)
    
    @pytest.mark.asyncio
    async def test_legacy_api_redirection(self):
        """Test legacy API redirection scenario."""
        pipeline = PreprocessingPipeline("LegacyRedirection")
        
        rewriter = URLRewriter()
        rewriter.add_rewrite_rule(
            pattern=r"^/old-api/(.*)$",
            replacement="/api/v2/\\1",
            redirect=True,
            permanent=True
        )
        pipeline.add_processor(rewriter)
        
        request = create_mock_request(path="/old-api/users/123")
        result = await pipeline.process(request)
        
        assert result.action == PreprocessingAction.REDIRECT
        assert result.redirect_url == "/api/v2/users/123"
        assert result.response.status_code == 301
    
    @pytest.mark.asyncio
    async def test_json_payload_transformation(self):
        """Test JSON payload transformation scenario."""
        pipeline = PreprocessingPipeline("JSONTransformation")
        
        transformer = BodyTransformer()
        
        def normalize_user_data(data: dict) -> dict:
            # Normalize user data format
            if "userName" in data:
                data["username"] = data.pop("userName")
            if "emailAddr" in data:
                data["email"] = data.pop("emailAddr")
            return data
        
        transformer.add_json_transformation(normalize_user_data)
        pipeline.add_processor(transformer)
        
        request = create_mock_json_request(
            data={"userName": "john_doe", "emailAddr": "john@example.com"}
        )
        result = await pipeline.process(request)
        
        assert result.action == PreprocessingAction.MODIFY
        
        body = await result.modified_request.body()
        normalized_data = json.loads(body.decode())
        assert "username" in normalized_data
        assert "email" in normalized_data
        assert "userName" not in normalized_data
        assert "emailAddr" not in normalized_data
    
    @pytest.mark.asyncio
    async def test_mobile_api_preprocessing(self):
        """Test mobile API preprocessing scenario."""
        pipeline = PreprocessingPipeline("MobileAPI")
        
        # Add mobile-specific header processor
        mobile_headers = HeaderManipulator(name="MobileHeaders")
        
        def is_mobile_request(headers):
            user_agent = headers.get("user-agent", "").lower()
            return any(mobile in user_agent for mobile in ["mobile", "android", "iphone"])
        
        mobile_headers.add_header_rule(
            "add", "X-Mobile-Optimized", "true",
            condition=is_mobile_request
        )
        
        # Add mobile-specific query params
        mobile_params = QueryParamManipulator(name="MobileParams")
        mobile_params.add_param_rule(
            "add", "mobile", "true",
            condition=lambda params: "mobile" not in params
        )
        
        pipeline.add_processor(mobile_headers)
        pipeline.add_processor(mobile_params)
        
        request = create_mock_request(
            headers={"User-Agent": "Mobile Safari"}
        )
        result = await pipeline.process(request)
        
        assert result.action == PreprocessingAction.MODIFY
        
        # Check mobile optimizations applied
        headers = dict(result.modified_request.headers)
        params = dict(result.modified_request.query_params)
        assert headers.get("x-mobile-optimized") == "true"
        assert params.get("mobile") == "true"


class TestPerformanceAndStress:
    """Test performance and stress scenarios."""
    
    @pytest.mark.asyncio
    async def test_large_request_processing(self):
        """Test processing of large requests."""
        transformer = BodyTransformer(max_body_size=2 * 1024 * 1024)  # 2MB limit
        
        def simple_transform(data: dict) -> dict:
            return data
        
        transformer.add_json_transformation(simple_transform)
        
        # Create large JSON request
        large_data = create_complex_json_body(depth=3, items_per_level=20)
        request = create_mock_json_request(data=large_data)
        
        helper = PerformanceTestHelper()
        helper.start_timing()
        
        result = await transformer.process(request)
        
        helper.stop_timing()
        
        # Should process successfully
        assert result.action in [PreprocessingAction.CONTINUE, PreprocessingAction.MODIFY]
        assert helper.get_duration_ms() < 1000  # Should complete within 1 second
    
    @pytest.mark.asyncio
    async def test_concurrent_processing(self):
        """Test concurrent request processing."""
        pipeline = create_preprocessing_pipeline(
            security_headers=True,
            url_normalization=True
        )
        
        async def process_request(request_id: int):
            request = create_mock_request(
                path=f"/api/test/{request_id}",
                headers={"X-Request-ID": str(request_id)}
            )
            return await pipeline.process(request)
        
        # Process requests concurrently
        tasks = [process_request(i) for i in range(10)]
        results = await asyncio.gather(*tasks)
        
        # All should complete successfully
        assert len(results) == 10
        for result in results:
            assert result.action in [
                PreprocessingAction.CONTINUE, 
                PreprocessingAction.MODIFY
            ]
    
    @pytest.mark.asyncio
    async def test_pipeline_with_many_processors(self):
        """Test pipeline with many processors."""
        pipeline = PreprocessingPipeline("StressTestPipeline")
        
        # Add many processors
        for i in range(50):
            processor = MockRequestPreprocessor(
                f"Processor{i}",
                PreprocessingPriority.NORMAL
            )
            pipeline.add_processor(processor)
        
        request = create_mock_request()
        
        helper = PerformanceTestHelper()
        helper.start_timing()
        
        result = await pipeline.process(request)
        
        helper.stop_timing()
        
        assert result.action == PreprocessingAction.CONTINUE
        assert helper.get_duration_ms() < 500  # Should complete reasonably fast
    
    @pytest.mark.asyncio
    async def test_memory_usage_stability(self):
        """Test memory usage stability during processing."""
        pipeline = create_preprocessing_pipeline()
        
        helper = PerformanceTestHelper()
        helper.measure_memory("start")
        
        # Process many requests
        for i in range(100):
            request = create_mock_request(path=f"/test/{i}")
            await pipeline.process(request)
            
            if i % 10 == 0:  # Measure every 10 requests
                helper.measure_memory(f"iteration_{i}")
        
        helper.measure_memory("end")
        
        # Memory usage should be stable (not growing significantly)
        memory_growth = helper.get_memory_diff("start", "end")
        # Allow some growth but not excessive (less than 50MB)
        assert memory_growth < 50 * 1024 * 1024
    
    @pytest.mark.asyncio 
    async def test_cache_effectiveness(self):
        """Test preprocessing cache effectiveness."""
        config = PreprocessingConfig(enable_caching=True)
        pipeline = PreprocessingPipeline("CacheTestPipeline", config)
        
        processor = MockRequestPreprocessor("TestProcessor")
        pipeline.add_processor(processor)
        
        request = create_mock_request()
        
        # Process same request multiple times
        for _ in range(10):
            await pipeline.process(request)
        
        # Processor should only be called once due to caching
        assert len(processor.process_calls) == 1
        
        metrics = pipeline.get_metrics()
        assert metrics["pipeline_metrics"]["cache_hits"] == 9
        assert metrics["pipeline_metrics"]["cache_misses"] == 1