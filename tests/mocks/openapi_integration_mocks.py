"""Mock classes for OpenAPI integration testing."""

import inspect
from typing import Any, Dict, List, Optional, Set, Callable
from unittest.mock import Mock, MagicMock
from datetime import datetime

from fastapi import FastAPI, Depends
from fastapi.routing import APIRoute, APIRouter

from fastapi_shield.openapi_integration import (
    ShieldParameterInfo, ShieldSecurityInfo, ShieldResponseInfo,
    ShieldMetadata, ParameterLocation, SecuritySchemeType,
    OpenAPIExtensionType
)
from fastapi_shield.shield import Shield


class MockShield(Shield):
    """Mock shield for testing OpenAPI integration."""
    
    def __init__(
        self,
        name: str = "MockShield",
        description: str = "Mock shield for testing",
        tags: Optional[Set[str]] = None,
        parameters: Optional[Dict[str, Any]] = None,
        security: Optional[Dict[str, Any]] = None,
        responses: Optional[Dict[str, Any]] = None,
        examples: Optional[Dict[str, Any]] = None,
        openapi_extensions: Optional[Dict[str, Any]] = None,
        external_docs: Optional[Dict[str, str]] = None,
        deprecated: bool = False,
        version: str = "1.0.0"
    ):
        # Create a mock shield function first
        def mock_shield_func(request, *args, **kwargs):
            return {"shield": name, "status": "passed"}
        
        super().__init__(mock_shield_func)
        self.__name__ = name
        self.__doc__ = description
        self.description = description
        self.tags = tags or {"mock", "test"}
        self.parameters = parameters or {}
        self.security = security or {}
        self.responses = responses or {}
        self.examples = examples or {}
        self.openapi_extensions = openapi_extensions or {}
        self.external_docs = external_docs
        self.__deprecated__ = deprecated
        self.__version__ = version
        
        # Mock shield function
        self.shield_func = self._mock_shield_function
    
    def _mock_shield_function(
        self,
        request,
        api_key: Optional[str] = None,
        user_id: Optional[str] = None
    ):
        """Mock shield function with parameters."""
        return {"shield": self.__name__, "status": "passed"}
    
    async def __call__(self, request, *args, **kwargs):
        """Mock shield execution."""
        return await self.shield_func(request, *args, **kwargs)


class MockAPIKeyShield(MockShield):
    """Mock API key shield."""
    
    def __init__(self, **kwargs):
        super().__init__(
            name="APIKeyShield",
            description="API Key authentication shield",
            parameters={
                "api_key": {
                    "location": "header",
                    "description": "API key for authentication",
                    "required": True,
                    "type": "string",
                    "example": "sk_test_123"
                }
            },
            security={
                "apiKey": {
                    "type": "apiKey",
                    "name": "X-API-Key",
                    "in": "header",
                    "description": "API key authentication"
                }
            },
            responses={
                "401": {
                    "description": "Invalid API key",
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "detail": {"type": "string"}
                                }
                            }
                        }
                    }
                }
            },
            **kwargs
        )
        self.api_key = True  # Flag for introspection


class MockBearerTokenShield(MockShield):
    """Mock bearer token shield."""
    
    def __init__(self, **kwargs):
        super().__init__(
            name="BearerTokenShield",
            description="Bearer token authentication shield",
            security={
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT",
                    "description": "Bearer token authentication"
                }
            },
            responses={
                "401": {
                    "description": "Invalid or expired token",
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "detail": {"type": "string"},
                                    "expired": {"type": "boolean"}
                                }
                            }
                        }
                    }
                }
            },
            **kwargs
        )
        self.bearer_token = True  # Flag for introspection


class MockRateLimitShield(MockShield):
    """Mock rate limit shield."""
    
    def __init__(self, **kwargs):
        super().__init__(
            name="RateLimitShield",
            description="Rate limiting shield",
            parameters={
                "x_rate_limit_window": {
                    "location": "header",
                    "description": "Rate limit window in seconds",
                    "required": False,
                    "type": "integer",
                    "example": 3600
                }
            },
            responses={
                "429": {
                    "description": "Rate limit exceeded",
                    "headers": {
                        "X-RateLimit-Limit": {
                            "description": "Request limit per window",
                            "schema": {"type": "integer"}
                        },
                        "X-RateLimit-Remaining": {
                            "description": "Remaining requests in window",
                            "schema": {"type": "integer"}
                        },
                        "Retry-After": {
                            "description": "Seconds until window resets",
                            "schema": {"type": "integer"}
                        }
                    },
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "detail": {"type": "string"},
                                    "retry_after": {"type": "integer"}
                                }
                            }
                        }
                    }
                }
            },
            examples={
                "rate_limit_exceeded": {
                    "summary": "Rate limit exceeded example",
                    "value": {
                        "detail": "Rate limit exceeded. Try again in 60 seconds.",
                        "retry_after": 60
                    }
                }
            },
            **kwargs
        )


class MockComplexShield(MockShield):
    """Mock complex shield with multiple features."""
    
    def __init__(self, **kwargs):
        super().__init__(
            name="ComplexShield",
            description="Complex shield with multiple authentication methods and parameters",
            tags={"complex", "multi-auth", "validation"},
            parameters={
                "api_key": {
                    "location": "header",
                    "description": "Primary API key",
                    "required": True,
                    "type": "string"
                },
                "client_id": {
                    "location": "query",
                    "description": "OAuth2 client ID",
                    "required": False,
                    "type": "string"
                },
                "session_token": {
                    "location": "cookie",
                    "description": "Session token",
                    "required": False,
                    "type": "string"
                }
            },
            security={
                "apiKey": {
                    "type": "apiKey",
                    "name": "X-API-Key",
                    "in": "header"
                },
                "oauth2": {
                    "type": "oauth2",
                    "flows": {
                        "authorizationCode": {
                            "authorizationUrl": "https://auth.example.com/oauth/authorize",
                            "tokenUrl": "https://auth.example.com/oauth/token",
                            "scopes": {
                                "read": "Read access",
                                "write": "Write access"
                            }
                        }
                    }
                }
            },
            responses={
                "400": {
                    "description": "Validation error",
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "detail": {"type": "string"},
                                    "validation_errors": {
                                        "type": "array",
                                        "items": {"type": "string"}
                                    }
                                }
                            }
                        }
                    }
                },
                "401": {"description": "Authentication failed"},
                "403": {"description": "Insufficient permissions"},
                "429": {"description": "Rate limit exceeded"}
            },
            openapi_extensions={
                "x-shield-custom": {
                    "validation_rules": ["email", "phone"],
                    "caching_enabled": True,
                    "audit_logging": True
                }
            },
            external_docs={
                "description": "Complex Shield Documentation",
                "url": "https://docs.example.com/shields/complex"
            },
            **kwargs
        )


class MockFastAPIApp:
    """Mock FastAPI application for testing."""
    
    def __init__(
        self,
        title: str = "Test API",
        version: str = "1.0.0",
        description: str = "Test API with shields"
    ):
        self.title = title
        self.version = version
        self.description = description
        self.routes = []
        self.openapi_tags = []
        self.servers = []
        self.openapi_schema = None
        self._openapi_function = None
    
    def add_route(self, route: 'MockAPIRoute'):
        """Add a route to the app."""
        self.routes.append(route)
    
    def openapi(self):
        """Get OpenAPI schema."""
        if self._openapi_function:
            return self._openapi_function()
        return self.openapi_schema


class MockAPIRoute:
    """Mock API route for testing."""
    
    def __init__(
        self,
        path: str,
        methods: Set[str],
        endpoint: Optional[Callable] = None,
        dependencies: Optional[List[Any]] = None,
        name: Optional[str] = None
    ):
        self.path = path
        self.methods = methods
        self.endpoint = endpoint or self._default_endpoint
        self.dependencies = dependencies or []
        self.name = name or f"route_{path.replace('/', '_')}"
        
        # Add shields to endpoint if they exist
        if hasattr(self.endpoint, '__shields__'):
            self.__shields__ = self.endpoint.__shields__
    
    def _default_endpoint(self):
        """Default endpoint function."""
        return {"message": "success"}


class MockDependency:
    """Mock dependency for testing."""
    
    def __init__(self, dependency: Any):
        self.dependency = dependency


def create_mock_shield_parameter_info(
    name: str = "test_param",
    location: ParameterLocation = ParameterLocation.QUERY,
    description: str = "Test parameter",
    **kwargs
) -> ShieldParameterInfo:
    """Create mock shield parameter info."""
    return ShieldParameterInfo(
        name=name,
        location=location,
        description=description,
        **kwargs
    )


def create_mock_shield_security_info(
    scheme_name: str = "test_security",
    scheme_type: SecuritySchemeType = SecuritySchemeType.API_KEY,
    description: str = "Test security scheme",
    **kwargs
) -> ShieldSecurityInfo:
    """Create mock shield security info."""
    return ShieldSecurityInfo(
        scheme_name=scheme_name,
        scheme_type=scheme_type,
        description=description,
        **kwargs
    )


def create_mock_shield_response_info(
    status_code: int = 401,
    description: str = "Unauthorized",
    **kwargs
) -> ShieldResponseInfo:
    """Create mock shield response info."""
    return ShieldResponseInfo(
        status_code=status_code,
        description=description,
        **kwargs
    )


def create_mock_shield_metadata(
    name: str = "MockShield",
    description: str = "Mock shield metadata",
    **kwargs
) -> ShieldMetadata:
    """Create mock shield metadata."""
    return ShieldMetadata(
        name=name,
        description=description,
        **kwargs
    )


def create_mock_openapi_schema() -> Dict[str, Any]:
    """Create mock OpenAPI schema."""
    return {
        "openapi": "3.0.2",
        "info": {
            "title": "Test API",
            "version": "1.0.0",
            "description": "Test API with shields"
        },
        "paths": {
            "/users": {
                "get": {
                    "summary": "Get users",
                    "operationId": "get_users",
                    "responses": {
                        "200": {
                            "description": "Successful response",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": {
                                            "type": "object",
                                            "properties": {
                                                "id": {"type": "integer"},
                                                "name": {"type": "string"}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                "post": {
                    "summary": "Create user",
                    "operationId": "create_user",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "name": {"type": "string"},
                                        "email": {"type": "string"}
                                    },
                                    "required": ["name", "email"]
                                }
                            }
                        }
                    },
                    "responses": {
                        "201": {
                            "description": "User created",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "id": {"type": "integer"},
                                            "name": {"type": "string"},
                                            "email": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/users/{user_id}": {
                "get": {
                    "summary": "Get user by ID",
                    "operationId": "get_user",
                    "parameters": [
                        {
                            "name": "user_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer"}
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "User found",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "id": {"type": "integer"},
                                            "name": {"type": "string"},
                                            "email": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        },
                        "404": {
                            "description": "User not found"
                        }
                    }
                }
            }
        },
        "components": {
            "schemas": {},
            "securitySchemes": {}
        }
    }


def create_mock_fastapi_app_with_shields() -> MockFastAPIApp:
    """Create mock FastAPI app with shields."""
    app = MockFastAPIApp(
        title="Shield Test API",
        version="2.0.0",
        description="Test API with comprehensive shield protection"
    )
    
    # Create mock endpoints with shields
    def protected_endpoint():
        return {"message": "protected resource"}
    
    def admin_endpoint():
        return {"message": "admin resource"}
    
    # Add shields to endpoints
    api_shield = MockAPIKeyShield()
    bearer_shield = MockBearerTokenShield()
    complex_shield = MockComplexShield()
    
    protected_endpoint.__shields__ = [api_shield]
    admin_endpoint.__shields__ = [bearer_shield, complex_shield]
    
    # Create routes
    protected_route = MockAPIRoute(
        path="/protected",
        methods={"GET"},
        endpoint=protected_endpoint,
        dependencies=[MockDependency(api_shield)]
    )
    
    admin_route = MockAPIRoute(
        path="/admin",
        methods={"GET", "POST"},
        endpoint=admin_endpoint,
        dependencies=[MockDependency(bearer_shield), MockDependency(complex_shield)]
    )
    
    rate_limited_route = MockAPIRoute(
        path="/rate-limited",
        methods={"GET"},
        dependencies=[MockDependency(MockRateLimitShield())]
    )
    
    app.add_route(protected_route)
    app.add_route(admin_route)
    app.add_route(rate_limited_route)
    
    return app


class MockOpenAPISchemaGenerator:
    """Mock OpenAPI schema generator for testing."""
    
    def __init__(self):
        self.generate_parameter_calls = []
        self.generate_security_calls = []
        self.generate_response_calls = []
    
    def generate_parameter_schema(self, param_info: ShieldParameterInfo) -> Dict[str, Any]:
        """Mock generate parameter schema."""
        self.generate_parameter_calls.append(param_info)
        return {
            "name": param_info.name,
            "in": param_info.location.value,
            "description": param_info.description,
            "required": param_info.required,
            "schema": {"type": param_info.schema_type}
        }
    
    def generate_security_schema(self, security_info: ShieldSecurityInfo) -> Dict[str, Any]:
        """Mock generate security schema."""
        self.generate_security_calls.append(security_info)
        return {
            "type": security_info.scheme_type.value,
            "description": security_info.description
        }
    
    def generate_response_schema(self, response_info: ShieldResponseInfo) -> Dict[str, Any]:
        """Mock generate response schema."""
        self.generate_response_calls.append(response_info)
        return {
            "description": response_info.description
        }


class MockShieldIntrospector:
    """Mock shield introspector for testing."""
    
    def __init__(self):
        self.introspect_calls = []
        self.mock_metadata = {}
    
    def introspect_shield(self, shield: Shield) -> ShieldMetadata:
        """Mock introspect shield."""
        self.introspect_calls.append(shield)
        
        shield_id = self._get_shield_id(shield)
        if shield_id in self.mock_metadata:
            return self.mock_metadata[shield_id]
        
        # Return default metadata
        return ShieldMetadata(
            name=getattr(shield, '__name__', 'MockShield'),
            description=getattr(shield, '__doc__', 'Mock shield'),
            tags=getattr(shield, 'tags', {'mock'}),
            parameters=[
                ShieldParameterInfo(
                    name="mock_param",
                    location=ParameterLocation.QUERY,
                    description="Mock parameter"
                )
            ],
            security=[
                ShieldSecurityInfo(
                    scheme_name="mockAuth",
                    scheme_type=SecuritySchemeType.API_KEY,
                    description="Mock authentication"
                )
            ],
            responses=[
                ShieldResponseInfo(
                    status_code=401,
                    description="Mock unauthorized response"
                )
            ]
        )
    
    def set_mock_metadata(self, shield: Shield, metadata: ShieldMetadata):
        """Set mock metadata for a shield."""
        shield_id = self._get_shield_id(shield)
        self.mock_metadata[shield_id] = metadata
    
    def _get_shield_id(self, shield: Shield) -> str:
        """Get shield ID."""
        return f"{shield.__class__.__module__}.{shield.__class__.__name__}_{id(shield)}"


class MockOpenAPIEnhancer:
    """Mock OpenAPI enhancer for testing."""
    
    def __init__(self):
        self.enhance_calls = []
        self.enhanced_schemas = {}
    
    def enhance_openapi_schema(
        self,
        openapi_schema: Dict[str, Any],
        app: MockFastAPIApp
    ) -> Dict[str, Any]:
        """Mock enhance OpenAPI schema."""
        self.enhance_calls.append((openapi_schema, app))
        
        # Return enhanced schema
        enhanced = openapi_schema.copy()
        enhanced[OpenAPIExtensionType.SHIELD_INFO.value] = {
            "version": "1.0.0",
            "generator": "Mock FastAPI-Shield OpenAPI Integration",
            "timestamp": datetime.now().isoformat(),
            "shield_count": len(app.routes)
        }
        
        return enhanced


# Helper functions for creating test scenarios
def create_authentication_test_scenario() -> Dict[str, Any]:
    """Create test scenario focused on authentication."""
    return {
        "app": create_mock_fastapi_app_with_shields(),
        "shields": [
            MockAPIKeyShield(),
            MockBearerTokenShield()
        ],
        "expected_security_schemes": {
            "apiKey": {
                "type": "apiKey",
                "name": "X-API-Key",
                "in": "header"
            },
            "bearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT"
            }
        }
    }


def create_complex_shield_test_scenario() -> Dict[str, Any]:
    """Create test scenario with complex shields."""
    return {
        "app": create_mock_fastapi_app_with_shields(),
        "shields": [MockComplexShield()],
        "expected_parameters": [
            {
                "name": "api_key",
                "in": "header",
                "required": True,
                "schema": {"type": "string"}
            },
            {
                "name": "client_id",
                "in": "query",
                "required": False,
                "schema": {"type": "string"}
            }
        ],
        "expected_responses": {
            "400": {"description": "Validation error"},
            "401": {"description": "Authentication failed"},
            "403": {"description": "Insufficient permissions"}
        }
    }


def create_client_generation_test_scenario() -> Dict[str, Any]:
    """Create test scenario for client generation."""
    return {
        "openapi_schema": create_mock_openapi_schema(),
        "languages": ["python", "javascript", "curl"],
        "expected_examples": {
            "python": {
                "imports": ["import requests"],
                "client_class": "class ShieldedAPIClient:",
                "usage_examples": ["client = ShieldedAPIClient"]
            },
            "javascript": {
                "client_class": "class ShieldedAPIClient {",
                "usage_examples": ["const client = new ShieldedAPIClient"]
            },
            "curl": {
                "commands": ["curl -X GET"]
            }
        }
    }