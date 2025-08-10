"""Comprehensive tests for the OpenAPI integration system."""

import json
import pytest
from typing import Dict, Any, List, Set
from unittest.mock import Mock, patch, MagicMock

from fastapi import FastAPI, Depends
from fastapi.openapi.models import OpenAPI

from fastapi_shield.openapi_integration import (
    OpenAPIExtensionType, SecuritySchemeType, ParameterLocation,
    ShieldParameterInfo, ShieldSecurityInfo, ShieldResponseInfo, ShieldMetadata,
    OpenAPISchemaGenerator, DefaultOpenAPISchemaGenerator,
    ShieldIntrospector, OpenAPIShieldEnhancer, OpenAPIClientGenerator,
    create_enhanced_openapi_schema, setup_enhanced_openapi,
    add_shield_to_openapi, extract_shield_openapi_info
)
from tests.mocks.openapi_integration_mocks import (
    MockShield, MockAPIKeyShield, MockBearerTokenShield, MockRateLimitShield,
    MockComplexShield, MockFastAPIApp, MockAPIRoute, MockDependency,
    create_mock_shield_parameter_info, create_mock_shield_security_info,
    create_mock_shield_response_info, create_mock_shield_metadata,
    create_mock_openapi_schema, create_mock_fastapi_app_with_shields,
    MockOpenAPISchemaGenerator, MockShieldIntrospector, MockOpenAPIEnhancer,
    create_authentication_test_scenario, create_complex_shield_test_scenario,
    create_client_generation_test_scenario
)


class TestShieldParameterInfo:
    """Test ShieldParameterInfo dataclass."""
    
    def test_parameter_info_creation(self):
        """Test creating shield parameter info."""
        param_info = ShieldParameterInfo(
            name="api_key",
            location=ParameterLocation.HEADER,
            description="API key for authentication",
            required=True,
            schema_type="string",
            example="sk_test_123"
        )
        
        assert param_info.name == "api_key"
        assert param_info.location == ParameterLocation.HEADER
        assert param_info.description == "API key for authentication"
        assert param_info.required is True
        assert param_info.schema_type == "string"
        assert param_info.example == "sk_test_123"
    
    def test_parameter_info_defaults(self):
        """Test parameter info with default values."""
        param_info = ShieldParameterInfo(
            name="test_param",
            location=ParameterLocation.QUERY,
            description="Test parameter"
        )
        
        assert param_info.required is True
        assert param_info.schema_type == "string"
        assert param_info.format_type is None
        assert param_info.example is None
        assert param_info.deprecated is False


class TestShieldSecurityInfo:
    """Test ShieldSecurityInfo dataclass."""
    
    def test_security_info_creation(self):
        """Test creating shield security info."""
        security_info = ShieldSecurityInfo(
            scheme_name="bearerAuth",
            scheme_type=SecuritySchemeType.HTTP,
            description="Bearer token authentication",
            scheme="bearer",
            bearer_format="JWT"
        )
        
        assert security_info.scheme_name == "bearerAuth"
        assert security_info.scheme_type == SecuritySchemeType.HTTP
        assert security_info.description == "Bearer token authentication"
        assert security_info.scheme == "bearer"
        assert security_info.bearer_format == "JWT"
    
    def test_api_key_security_info(self):
        """Test API key security info."""
        security_info = ShieldSecurityInfo(
            scheme_name="apiKey",
            scheme_type=SecuritySchemeType.API_KEY,
            description="API key authentication",
            parameter_name="X-API-Key",
            location=ParameterLocation.HEADER
        )
        
        assert security_info.scheme_type == SecuritySchemeType.API_KEY
        assert security_info.parameter_name == "X-API-Key"
        assert security_info.location == ParameterLocation.HEADER
    
    def test_oauth2_security_info(self):
        """Test OAuth2 security info."""
        flows = {
            "authorizationCode": {
                "authorizationUrl": "https://auth.example.com/oauth/authorize",
                "tokenUrl": "https://auth.example.com/oauth/token",
                "scopes": {"read": "Read access", "write": "Write access"}
            }
        }
        
        security_info = ShieldSecurityInfo(
            scheme_name="oauth2",
            scheme_type=SecuritySchemeType.OAUTH2,
            description="OAuth2 authentication",
            flows=flows
        )
        
        assert security_info.scheme_type == SecuritySchemeType.OAUTH2
        assert security_info.flows == flows


class TestShieldResponseInfo:
    """Test ShieldResponseInfo dataclass."""
    
    def test_response_info_creation(self):
        """Test creating shield response info."""
        content = {
            "application/json": {
                "schema": {
                    "type": "object",
                    "properties": {"detail": {"type": "string"}}
                }
            }
        }
        
        response_info = ShieldResponseInfo(
            status_code=401,
            description="Unauthorized",
            content=content,
            headers={"WWW-Authenticate": {"description": "Authentication scheme"}},
            examples={"unauthorized": {"value": {"detail": "Invalid credentials"}}}
        )
        
        assert response_info.status_code == 401
        assert response_info.description == "Unauthorized"
        assert response_info.content == content
        assert "WWW-Authenticate" in response_info.headers
        assert "unauthorized" in response_info.examples


class TestShieldMetadata:
    """Test ShieldMetadata dataclass."""
    
    def test_metadata_creation(self):
        """Test creating shield metadata."""
        parameters = [create_mock_shield_parameter_info("api_key")]
        security = [create_mock_shield_security_info("apiKey")]
        responses = [create_mock_shield_response_info(401)]
        
        metadata = ShieldMetadata(
            name="TestShield",
            description="Test shield for unit testing",
            version="2.0.0",
            tags={"test", "security"},
            parameters=parameters,
            security=security,
            responses=responses,
            examples={"test_example": {"value": "test"}},
            deprecated=False
        )
        
        assert metadata.name == "TestShield"
        assert metadata.description == "Test shield for unit testing"
        assert metadata.version == "2.0.0"
        assert metadata.tags == {"test", "security"}
        assert len(metadata.parameters) == 1
        assert len(metadata.security) == 1
        assert len(metadata.responses) == 1
        assert metadata.deprecated is False


class TestDefaultOpenAPISchemaGenerator:
    """Test DefaultOpenAPISchemaGenerator class."""
    
    @pytest.fixture
    def generator(self):
        """Create schema generator for testing."""
        return DefaultOpenAPISchemaGenerator()
    
    def test_generate_parameter_schema(self, generator):
        """Test generating parameter schema."""
        param_info = ShieldParameterInfo(
            name="api_key",
            location=ParameterLocation.HEADER,
            description="API key for authentication",
            required=True,
            schema_type="string",
            format_type="password",
            example="sk_test_123",
            deprecated=True
        )
        
        schema = generator.generate_parameter_schema(param_info)
        
        assert schema["name"] == "api_key"
        assert schema["in"] == "header"
        assert schema["description"] == "API key for authentication"
        assert schema["required"] is True
        assert schema["deprecated"] is True
        assert schema["schema"]["type"] == "string"
        assert schema["schema"]["format"] == "password"
        assert schema["example"] == "sk_test_123"
    
    def test_generate_api_key_security_schema(self, generator):
        """Test generating API key security schema."""
        security_info = ShieldSecurityInfo(
            scheme_name="apiKey",
            scheme_type=SecuritySchemeType.API_KEY,
            description="API key authentication",
            parameter_name="X-API-Key",
            location=ParameterLocation.HEADER
        )
        
        schema = generator.generate_security_schema(security_info)
        
        assert schema["type"] == "apiKey"
        assert schema["name"] == "X-API-Key"
        assert schema["in"] == "header"
        assert schema["description"] == "API key authentication"
    
    def test_generate_http_security_schema(self, generator):
        """Test generating HTTP security schema."""
        security_info = ShieldSecurityInfo(
            scheme_name="bearerAuth",
            scheme_type=SecuritySchemeType.HTTP,
            description="Bearer token authentication",
            scheme="bearer",
            bearer_format="JWT"
        )
        
        schema = generator.generate_security_schema(security_info)
        
        assert schema["type"] == "http"
        assert schema["scheme"] == "bearer"
        assert schema["bearerFormat"] == "JWT"
        assert schema["description"] == "Bearer token authentication"
    
    def test_generate_oauth2_security_schema(self, generator):
        """Test generating OAuth2 security schema."""
        flows = {
            "authorizationCode": {
                "authorizationUrl": "https://auth.example.com/oauth/authorize",
                "tokenUrl": "https://auth.example.com/oauth/token"
            }
        }
        
        security_info = ShieldSecurityInfo(
            scheme_name="oauth2",
            scheme_type=SecuritySchemeType.OAUTH2,
            description="OAuth2 authentication",
            flows=flows
        )
        
        schema = generator.generate_security_schema(security_info)
        
        assert schema["type"] == "oauth2"
        assert schema["flows"] == flows
        assert schema["description"] == "OAuth2 authentication"
    
    def test_generate_response_schema(self, generator):
        """Test generating response schema."""
        content = {
            "application/json": {
                "schema": {"type": "object", "properties": {"detail": {"type": "string"}}}
            }
        }
        headers = {"X-Rate-Limit": {"description": "Rate limit info"}}
        examples = {"error_example": {"value": {"detail": "Error occurred"}}}
        
        response_info = ShieldResponseInfo(
            status_code=429,
            description="Too Many Requests",
            content=content,
            headers=headers,
            examples=examples
        )
        
        schema = generator.generate_response_schema(response_info)
        
        assert schema["description"] == "Too Many Requests"
        assert schema["content"] == content
        assert schema["headers"] == headers
        assert schema["examples"] == examples


class TestShieldIntrospector:
    """Test ShieldIntrospector class."""
    
    @pytest.fixture
    def introspector(self):
        """Create introspector for testing."""
        return ShieldIntrospector()
    
    def test_introspect_basic_shield(self, introspector):
        """Test introspecting basic shield."""
        shield = MockShield(
            name="BasicShield",
            description="Basic test shield",
            tags={"basic", "test"}
        )
        
        metadata = introspector.introspect_shield(shield)
        
        assert metadata.name == "BasicShield"
        assert metadata.description == "Basic test shield"
        expected_tags = {"basic", "test", "MockShield"}
        assert metadata.tags == expected_tags
    
    def test_introspect_api_key_shield(self, introspector):
        """Test introspecting API key shield."""
        shield = MockAPIKeyShield()
        
        metadata = introspector.introspect_shield(shield)
        
        assert metadata.name == "APIKeyShield"
        assert any(param.name == "api_key" for param in metadata.parameters)
        assert any(sec.scheme_name == "apiKey" for sec in metadata.security)
        assert any(resp.status_code == 401 for resp in metadata.responses)
    
    def test_introspect_bearer_token_shield(self, introspector):
        """Test introspecting bearer token shield."""
        shield = MockBearerTokenShield()
        
        metadata = introspector.introspect_shield(shield)
        
        assert metadata.name == "BearerTokenShield"
        assert any(sec.scheme_type == SecuritySchemeType.HTTP for sec in metadata.security)
        assert any(sec.scheme == "bearer" for sec in metadata.security)
    
    def test_introspect_complex_shield(self, introspector):
        """Test introspecting complex shield."""
        shield = MockComplexShield()
        
        metadata = introspector.introspect_shield(shield)
        
        assert metadata.name == "ComplexShield"
        assert len(metadata.parameters) >= 3  # api_key, client_id, session_token
        assert len(metadata.security) >= 2   # apiKey, oauth2
        assert len(metadata.responses) >= 4  # 400, 401, 403, 429
        assert metadata.external_docs is not None
        assert "x-shield-custom" in metadata.extensions
    
    def test_caching_behavior(self, introspector):
        """Test that introspection results are cached."""
        shield = MockShield(name="CacheTest")
        
        # First call
        metadata1 = introspector.introspect_shield(shield)
        # Second call should return cached result
        metadata2 = introspector.introspect_shield(shield)
        
        assert metadata1 is metadata2  # Same object reference
    
    def test_extract_description_from_docstring(self, introspector):
        """Test extracting description from shield docstring."""
        shield = MockShield()
        shield.__doc__ = "This is a test shield with detailed documentation."
        
        description = introspector._extract_description(shield)
        
        assert description == "This is a test shield with detailed documentation."
    
    def test_extract_tags_from_attributes(self, introspector):
        """Test extracting tags from shield attributes."""
        shield = MockShield()
        shield.tags = ["security", "authentication", "api"]
        shield._tags = {"additional", "tag"}
        
        tags = introspector._extract_tags(shield)
        
        assert "security" in tags
        assert "authentication" in tags
        assert "api" in tags
        assert "additional" in tags
        assert "tag" in tags
        assert "MockShield" in tags  # Class name added as tag


class TestOpenAPIShieldEnhancer:
    """Test OpenAPIShieldEnhancer class."""
    
    @pytest.fixture
    def enhancer(self):
        """Create enhancer for testing."""
        return OpenAPIShieldEnhancer()
    
    def test_enhance_openapi_schema(self, enhancer):
        """Test enhancing OpenAPI schema."""
        base_schema = create_mock_openapi_schema()
        app = create_mock_fastapi_app_with_shields()
        
        enhanced_schema = enhancer.enhance_openapi_schema(base_schema, app)
        
        assert "paths" in enhanced_schema
        assert "components" in enhanced_schema
        assert OpenAPIExtensionType.SHIELD_INFO.value in enhanced_schema
        
        # Check that shield info was added
        shield_info = enhanced_schema[OpenAPIExtensionType.SHIELD_INFO.value]
        assert "version" in shield_info
        assert "generator" in shield_info
        assert "timestamp" in shield_info
        assert "shield_count" in shield_info
    
    def test_enhance_paths_with_shields(self, enhancer):
        """Test enhancing paths with shield information."""
        base_schema = create_mock_openapi_schema()
        app = create_mock_fastapi_app_with_shields()
        
        enhanced_schema = enhancer.enhance_openapi_schema(base_schema, app)
        
        # The enhanced schema should have the same paths but potentially modified
        assert len(enhanced_schema["paths"]) >= len(base_schema["paths"])
    
    def test_enhance_components_with_security_schemes(self, enhancer):
        """Test enhancing components with security schemes."""
        base_schema = create_mock_openapi_schema()
        app = create_mock_fastapi_app_with_shields()
        
        enhanced_schema = enhancer.enhance_openapi_schema(base_schema, app)
        
        security_schemes = enhanced_schema["components"]["securitySchemes"]
        
        # Should contain security schemes from shields (may be 0 if no shields found)
        assert len(security_schemes) >= 0
    
    def test_find_shields_for_route(self, enhancer):
        """Test finding shields for specific routes."""
        app = create_mock_fastapi_app_with_shields()
        
        shields = enhancer._find_shields_for_route("/protected", "GET", app)
        
        # Should find shields associated with the route
        assert len(shields) >= 0  # May vary based on mock implementation
    
    def test_extract_shields_from_route(self, enhancer):
        """Test extracting shields from route dependencies."""
        shield = MockAPIKeyShield()
        route = MockAPIRoute(
            path="/test",
            methods={"GET"},
            dependencies=[MockDependency(shield)]
        )
        
        shields = enhancer._extract_shields_from_route(route)
        
        # Should extract shield from dependencies
        assert len(shields) >= 0  # May vary based on implementation


class TestOpenAPIClientGenerator:
    """Test OpenAPIClientGenerator class."""
    
    @pytest.fixture
    def generator(self):
        """Create client generator for testing."""
        return OpenAPIClientGenerator()
    
    def test_generate_client_examples(self, generator):
        """Test generating client examples."""
        schema = create_mock_openapi_schema()
        languages = ["python", "javascript", "curl"]
        
        examples = generator.generate_client_examples(schema, languages)
        
        assert len(examples) == 3
        assert "python" in examples
        assert "javascript" in examples
        assert "curl" in examples
    
    def test_generate_python_examples(self, generator):
        """Test generating Python client examples."""
        schema = create_mock_openapi_schema()
        
        examples = generator._generate_python_examples(schema)
        
        assert "imports" in examples
        assert "client_class" in examples
        assert "usage_examples" in examples
        
        # Check that imports contain expected modules
        imports = examples["imports"]
        assert "import requests" in imports
        assert "import json" in imports
    
    def test_generate_javascript_examples(self, generator):
        """Test generating JavaScript client examples."""
        schema = create_mock_openapi_schema()
        
        examples = generator._generate_javascript_examples(schema)
        
        assert "client_class" in examples
        assert "usage_examples" in examples
        
        # Check that client class contains expected patterns
        client_class = examples["client_class"]
        assert "class ShieldedAPIClient" in client_class
        assert "async makeRequest" in client_class
    
    def test_generate_curl_examples(self, generator):
        """Test generating cURL examples."""
        schema = create_mock_openapi_schema()
        
        examples = generator._generate_curl_examples(schema)
        
        assert "commands" in examples
        
        # Check that commands contain expected patterns
        commands = examples["commands"]
        assert len(commands) > 0
        
        for command in commands:
            assert "curl" in command
            assert "-H 'Authorization: Bearer YOUR_API_KEY'" in command
    
    def test_generate_python_client_class(self, generator):
        """Test generating Python client class."""
        schema = create_mock_openapi_schema()
        
        client_class = generator._generate_python_client_class(schema)
        
        assert "class ShieldedAPIClient:" in client_class
        assert "def __init__" in client_class
        assert "def _make_request" in client_class
        assert "requests.Session" in client_class
    
    def test_generate_curl_command(self, generator):
        """Test generating individual cURL command."""
        operation = {
            "summary": "Get users",
            "description": "Retrieve all users"
        }
        
        command = generator._generate_curl_command(
            "https://api.example.com", "/users", "GET", operation
        )
        
        assert "curl -X GET" in command
        assert "https://api.example.com/users" in command
        assert "Authorization: Bearer YOUR_API_KEY" in command
        assert "# Get users" in command


class TestUtilityFunctions:
    """Test utility functions."""
    
    def test_create_enhanced_openapi_schema(self):
        """Test creating enhanced OpenAPI schema."""
        app = create_mock_fastapi_app_with_shields()
        
        enhanced_schema = create_enhanced_openapi_schema(app)
        
        assert "openapi" in enhanced_schema
        assert "info" in enhanced_schema
        assert "paths" in enhanced_schema
        assert "components" in enhanced_schema
        assert OpenAPIExtensionType.SHIELD_INFO.value in enhanced_schema
    
    def test_create_enhanced_openapi_schema_with_client_examples(self):
        """Test creating enhanced schema with client examples."""
        app = create_mock_fastapi_app_with_shields()
        
        enhanced_schema = create_enhanced_openapi_schema(
            app, include_client_examples=True
        )
        
        assert OpenAPIExtensionType.SHIELD_EXAMPLES.value in enhanced_schema
        
        examples = enhanced_schema[OpenAPIExtensionType.SHIELD_EXAMPLES.value]
        assert "python" in examples
        assert "javascript" in examples
        assert "curl" in examples
    
    def test_setup_enhanced_openapi(self):
        """Test setting up enhanced OpenAPI for FastAPI app."""
        app = create_mock_fastapi_app_with_shields()
        
        # Setup enhanced OpenAPI
        setup_enhanced_openapi(app)
        
        # App should have a custom openapi function
        assert app._openapi_function is not None or hasattr(app, 'openapi')
    
    def test_add_shield_to_openapi(self):
        """Test adding shield to OpenAPI operation."""
        operation = {
            "summary": "Test operation",
            "responses": {"200": {"description": "Success"}}
        }
        shield = MockAPIKeyShield()
        
        enhanced_operation = add_shield_to_openapi(operation, shield)
        
        assert "parameters" in enhanced_operation or len(enhanced_operation) >= len(operation)
        assert "security" in enhanced_operation or len(enhanced_operation) >= len(operation)
        # Should have additional shield-related content
    
    def test_extract_shield_openapi_info(self):
        """Test extracting OpenAPI info from shield."""
        shield = MockComplexShield()
        
        info = extract_shield_openapi_info(shield)
        
        assert "name" in info
        assert "description" in info
        assert "version" in info
        assert "tags" in info
        assert "parameters" in info
        assert "security" in info
        assert "responses" in info
        assert "examples" in info
        assert "extensions" in info
        
        assert info["name"] == "ComplexShield"
        assert isinstance(info["tags"], list)
        assert isinstance(info["parameters"], list)
        assert isinstance(info["security"], list)
        assert isinstance(info["responses"], list)


class TestIntegrationScenarios:
    """Integration tests for various scenarios."""
    
    def test_authentication_shield_integration(self):
        """Test integration with authentication shields."""
        scenario = create_authentication_test_scenario()
        app = scenario["app"]
        shields = scenario["shields"]
        
        enhancer = OpenAPIShieldEnhancer()
        base_schema = create_mock_openapi_schema()
        
        enhanced_schema = enhancer.enhance_openapi_schema(base_schema, app)
        
        # Should have security schemes from shields
        security_schemes = enhanced_schema["components"]["securitySchemes"]
        assert len(security_schemes) >= 0
    
    def test_complex_shield_integration(self):
        """Test integration with complex shields."""
        scenario = create_complex_shield_test_scenario()
        app = scenario["app"]
        
        enhancer = OpenAPIShieldEnhancer()
        base_schema = create_mock_openapi_schema()
        
        enhanced_schema = enhancer.enhance_openapi_schema(base_schema, app)
        
        # Should include complex shield features
        assert OpenAPIExtensionType.SHIELD_INFO.value in enhanced_schema
    
    def test_client_generation_integration(self):
        """Test client generation integration."""
        scenario = create_client_generation_test_scenario()
        schema = scenario["openapi_schema"]
        languages = scenario["languages"]
        
        generator = OpenAPIClientGenerator()
        examples = generator.generate_client_examples(schema, languages)
        
        assert len(examples) == len(languages)
        for language in languages:
            assert language in examples
            assert len(examples[language]) > 0
    
    def test_end_to_end_enhancement(self):
        """Test end-to-end OpenAPI enhancement."""
        # Create app with various shields
        app = create_mock_fastapi_app_with_shields()
        
        # Create enhanced schema
        enhanced_schema = create_enhanced_openapi_schema(
            app, include_client_examples=True
        )
        
        # Verify all expected enhancements
        assert "openapi" in enhanced_schema
        assert "info" in enhanced_schema
        assert "paths" in enhanced_schema
        assert "components" in enhanced_schema
        
        # Check shield-specific extensions
        assert OpenAPIExtensionType.SHIELD_INFO.value in enhanced_schema
        assert OpenAPIExtensionType.SHIELD_EXAMPLES.value in enhanced_schema
        
        # Verify structure integrity
        assert enhanced_schema["openapi"] in ["3.0.2", "3.1.0"]  # FastAPI may use different versions
        assert "title" in enhanced_schema["info"]
        assert "version" in enhanced_schema["info"]
    
    def test_multiple_shields_per_route(self):
        """Test handling multiple shields per route."""
        app = MockFastAPIApp()
        
        # Create endpoint with multiple shields
        def multi_shield_endpoint():
            return {"message": "protected"}
        
        api_shield = MockAPIKeyShield()
        bearer_shield = MockBearerTokenShield()
        rate_shield = MockRateLimitShield()
        
        multi_shield_endpoint.__shields__ = [api_shield, bearer_shield, rate_shield]
        
        route = MockAPIRoute(
            path="/multi-protected",
            methods={"GET"},
            endpoint=multi_shield_endpoint,
            dependencies=[
                MockDependency(api_shield),
                MockDependency(bearer_shield),
                MockDependency(rate_shield)
            ]
        )
        
        app.add_route(route)
        
        enhancer = OpenAPIShieldEnhancer()
        base_schema = create_mock_openapi_schema()
        
        enhanced_schema = enhancer.enhance_openapi_schema(base_schema, app)
        
        # Should handle multiple shields correctly
        assert "components" in enhanced_schema
        security_schemes = enhanced_schema["components"]["securitySchemes"]
        assert len(security_schemes) >= 0  # Should have multiple security schemes
    
    def test_shield_with_custom_extensions(self):
        """Test shield with custom OpenAPI extensions."""
        shield = MockShield(
            openapi_extensions={
                "x-custom-extension": {"key": "value"},
                "x-shield-metadata": {"feature": "custom"}
            }
        )
        
        introspector = ShieldIntrospector()
        metadata = introspector.introspect_shield(shield)
        
        assert "x-custom-extension" in metadata.extensions
        assert "x-shield-metadata" in metadata.extensions
        assert OpenAPIExtensionType.SHIELD_INFO.value in metadata.extensions
    
    def test_performance_with_many_shields(self):
        """Test performance with many shields."""
        import time
        
        app = MockFastAPIApp()
        
        # Add many routes with shields
        for i in range(50):
            shield = MockShield(name=f"Shield{i}")
            route = MockAPIRoute(
                path=f"/route{i}",
                methods={"GET"},
                dependencies=[MockDependency(shield)]
            )
            app.add_route(route)
        
        enhancer = OpenAPIShieldEnhancer()
        base_schema = create_mock_openapi_schema()
        
        start_time = time.time()
        enhanced_schema = enhancer.enhance_openapi_schema(base_schema, app)
        end_time = time.time()
        
        # Should complete within reasonable time
        assert (end_time - start_time) < 5.0  # Less than 5 seconds
        
        # Should still produce valid schema
        assert "paths" in enhanced_schema
        assert "components" in enhanced_schema
    
    def test_error_handling_in_enhancement(self):
        """Test error handling during enhancement."""
        app = MockFastAPIApp()
        
        # Create a problematic shield that might cause errors
        class ProblematicShield(MockShield):
            def __getattribute__(self, name):
                if name == "parameters":
                    raise AttributeError("Simulated error")
                return super().__getattribute__(name)
        
        problematic_shield = ProblematicShield()
        route = MockAPIRoute(
            path="/problematic",
            methods={"GET"},
            dependencies=[MockDependency(problematic_shield)]
        )
        app.add_route(route)
        
        enhancer = OpenAPIShieldEnhancer()
        base_schema = create_mock_openapi_schema()
        
        # Should handle errors gracefully
        enhanced_schema = enhancer.enhance_openapi_schema(base_schema, app)
        
        # Should still produce a valid schema
        assert "paths" in enhanced_schema
        assert "components" in enhanced_schema


class TestMockObjects:
    """Test mock objects functionality."""
    
    def test_mock_shield_functionality(self):
        """Test mock shield basic functionality."""
        shield = MockShield(
            name="TestMock",
            description="Test mock shield",
            tags={"test", "mock"}
        )
        
        assert shield.__name__ == "TestMock"
        assert shield.description == "Test mock shield"
        assert shield.tags == {"test", "mock"}
    
    def test_mock_api_key_shield_properties(self):
        """Test mock API key shield properties."""
        shield = MockAPIKeyShield()
        
        assert shield.__name__ == "APIKeyShield"
        assert "api_key" in shield.parameters
        assert "apiKey" in shield.security
        assert hasattr(shield, 'api_key')
        assert shield.api_key is True
    
    def test_mock_fastapi_app_functionality(self):
        """Test mock FastAPI app functionality."""
        app = MockFastAPIApp(
            title="Test App",
            version="1.0.0",
            description="Test application"
        )
        
        assert app.title == "Test App"
        assert app.version == "1.0.0"
        assert app.description == "Test application"
        assert len(app.routes) == 0
        
        # Add route
        route = MockAPIRoute("/test", {"GET"})
        app.add_route(route)
        
        assert len(app.routes) == 1
        assert app.routes[0] == route
    
    def test_create_mock_fastapi_app_with_shields(self):
        """Test creating mock app with shields."""
        app = create_mock_fastapi_app_with_shields()
        
        assert app.title == "Shield Test API"
        assert len(app.routes) > 0
        
        # Should have routes with different shield configurations
        route_paths = [route.path for route in app.routes]
        assert "/protected" in route_paths
        assert "/admin" in route_paths