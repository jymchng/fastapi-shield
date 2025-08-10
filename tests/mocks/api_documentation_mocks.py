"""Mock classes and utilities for API documentation shield testing."""

import json
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Callable
from unittest.mock import Mock, AsyncMock

from fastapi import FastAPI, Request
from fastapi.responses import Response

from fastapi_shield.api_documentation import (
    DocumentationFilter,
    DocumentationRenderer,
    UserContext,
    DocumentationTheme,
    DocumentationVersion,
    DocumentationFormat,
    AccessLevel,
    DocumentationScope,
    APIDocumentationConfig
)


class MockRequest:
    """Mock FastAPI request for testing."""
    
    def __init__(
        self,
        path: str = "/docs",
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        query_params: Optional[Dict[str, str]] = None,
        client_host: str = "127.0.0.1"
    ):
        self.url = Mock()
        self.url.path = path
        self.method = method
        self.headers = headers or {}
        
        # Mock dict-like behavior for headers
        class HeaderDict(dict):
            def get(self, key, default=None):
                return super().get(key, default)
        
        self.headers = HeaderDict(self.headers)
        # Mock dict-like behavior for query params
        class QueryDict(dict):
            def get(self, key, default=None):
                return super().get(key, default)
        
        self.query_params = QueryDict(query_params or {})
        self.client = Mock()
        self.client.host = client_host
    
    def __repr__(self):
        return f"MockRequest({self.method} {self.url.path})"


class MockFastAPIApp:
    """Mock FastAPI application for testing."""
    
    def __init__(
        self,
        title: str = "Test API",
        version: str = "1.0.0",
        description: str = "Test API Description",
        openapi_version: str = "3.0.2"
    ):
        self.title = title
        self.version = version
        self.description = description
        self.openapi_version = openapi_version
        self.routes = []
        self.openapi_schema = None
    
    def add_route(self, path: str, methods: List[str], tags: Optional[List[str]] = None):
        """Add a mock route for testing."""
        route = Mock()
        route.path = path
        route.methods = set(methods)
        route.tags = tags or []
        route.operation_id = f"{methods[0].lower()}_{path.replace('/', '_').strip('_')}"
        self.routes.append(route)
    
    def set_openapi_schema(self, schema: Dict[str, Any]):
        """Set custom OpenAPI schema for testing."""
        self.openapi_schema = schema


class MockDocumentationFilter(DocumentationFilter):
    """Mock documentation filter for testing."""
    
    def __init__(self):
        self.include_path_calls = []
        self.include_schema_calls = []
        self.filter_operation_calls = []
        self.path_results = {}
        self.schema_results = {}
        self.operation_filters = {}
    
    def should_include_path(self, path: str, method: str, operation: Dict[str, Any], user_context: UserContext) -> bool:
        """Mock path inclusion check."""
        call_info = {
            'path': path,
            'method': method,
            'operation': operation,
            'user_context': user_context
        }
        self.include_path_calls.append(call_info)
        
        key = f"{method.upper()}:{path}"
        return self.path_results.get(key, True)
    
    def should_include_schema(self, schema_name: str, schema_def: Dict[str, Any], user_context: UserContext) -> bool:
        """Mock schema inclusion check."""
        call_info = {
            'schema_name': schema_name,
            'schema_def': schema_def,
            'user_context': user_context
        }
        self.include_schema_calls.append(call_info)
        
        return self.schema_results.get(schema_name, True)
    
    def filter_operation(self, operation: Dict[str, Any], user_context: UserContext) -> Dict[str, Any]:
        """Mock operation filtering."""
        call_info = {
            'operation': operation,
            'user_context': user_context
        }
        self.filter_operation_calls.append(call_info)
        
        # Apply any configured filters
        filtered_op = deepcopy(operation)
        for filter_func in self.operation_filters.values():
            filtered_op = filter_func(filtered_op, user_context)
        
        return filtered_op
    
    def set_path_result(self, method: str, path: str, result: bool):
        """Set result for path inclusion check."""
        key = f"{method.upper()}:{path}"
        self.path_results[key] = result
    
    def set_schema_result(self, schema_name: str, result: bool):
        """Set result for schema inclusion check."""
        self.schema_results[schema_name] = result
    
    def add_operation_filter(self, name: str, filter_func: Callable):
        """Add operation filter function."""
        self.operation_filters[name] = filter_func
    
    def reset(self):
        """Reset mock state."""
        self.include_path_calls = []
        self.include_schema_calls = []
        self.filter_operation_calls = []


class MockDocumentationRenderer(DocumentationRenderer):
    """Mock documentation renderer for testing."""
    
    def __init__(self, format_type: DocumentationFormat):
        self.format_type = format_type
        self.render_calls = []
        self.custom_response = None
        self.should_fail = False
        self.failure_message = "Mock renderer failure"
    
    def render(self, openapi_spec: Dict[str, Any], theme: DocumentationTheme,
              user_context: UserContext, version: Optional[DocumentationVersion] = None) -> Response:
        """Mock documentation rendering."""
        call_info = {
            'openapi_spec': openapi_spec,
            'theme': theme,
            'user_context': user_context,
            'version': version,
            'format_type': self.format_type
        }
        self.render_calls.append(call_info)
        
        if self.should_fail:
            raise Exception(self.failure_message)
        
        if self.custom_response:
            return self.custom_response
        
        # Default mock responses
        if self.format_type == DocumentationFormat.OPENAPI_JSON:
            from fastapi.responses import JSONResponse
            return JSONResponse(content=openapi_spec)
        elif self.format_type == DocumentationFormat.SWAGGER_UI:
            from fastapi.responses import HTMLResponse
            return HTMLResponse(content="<html><body>Mock Swagger UI</body></html>")
        elif self.format_type == DocumentationFormat.REDOC:
            from fastapi.responses import HTMLResponse
            return HTMLResponse(content="<html><body>Mock ReDoc</body></html>")
        else:
            from fastapi.responses import Response
            return Response(content="Mock Documentation", media_type="text/plain")
    
    def set_custom_response(self, response: Response):
        """Set custom response for testing."""
        self.custom_response = response
    
    def set_should_fail(self, should_fail: bool, message: str = "Mock renderer failure"):
        """Configure renderer to fail for testing."""
        self.should_fail = should_fail
        self.failure_message = message
    
    def reset(self):
        """Reset mock state."""
        self.render_calls = []
        self.custom_response = None
        self.should_fail = False


class DocumentationTestHelper:
    """Helper class for documentation shield testing."""
    
    @staticmethod
    def create_user_context(
        user_id: Optional[str] = "test_user",
        roles: Optional[Set[str]] = None,
        permissions: Optional[Set[str]] = None,
        authenticated: bool = True,
        ip_address: str = "127.0.0.1",
        user_agent: str = "test-agent"
    ) -> UserContext:
        """Create user context for testing."""
        return UserContext(
            user_id=user_id,
            roles=roles or set(),
            permissions=permissions or set(),
            authenticated=authenticated,
            ip_address=ip_address,
            user_agent=user_agent
        )
    
    @staticmethod
    def create_admin_user_context() -> UserContext:
        """Create admin user context for testing."""
        return DocumentationTestHelper.create_user_context(
            user_id="admin_user",
            roles={"admin", "developer"},
            permissions={"read_all_docs", "write_docs", "admin_access", "write_users"}
        )
    
    @staticmethod
    def create_readonly_user_context() -> UserContext:
        """Create readonly user context for testing."""
        return DocumentationTestHelper.create_user_context(
            user_id="readonly_user",
            roles={"readonly"},
            permissions={"read_public_docs"}
        )
    
    @staticmethod
    def create_anonymous_user_context() -> UserContext:
        """Create anonymous user context for testing."""
        return DocumentationTestHelper.create_user_context(
            user_id=None,
            authenticated=False,
            roles=set(),
            permissions=set()
        )
    
    @staticmethod
    def create_developer_user_context() -> UserContext:
        """Create developer user context for testing."""
        return DocumentationTestHelper.create_user_context(
            user_id="developer_user",
            roles={"developer", "tester"},
            permissions={"read_all_docs", "test_api"}
        )
    
    @staticmethod
    def create_sample_openapi_spec() -> Dict[str, Any]:
        """Create sample OpenAPI specification for testing."""
        return {
            "openapi": "3.0.2",
            "info": {
                "title": "Test API",
                "description": "Test API for documentation shield testing",
                "version": "1.0.0"
            },
            "servers": [
                {
                    "url": "https://api.example.com/v1",
                    "description": "Production server"
                }
            ],
            "paths": {
                "/users": {
                    "get": {
                        "tags": ["users"],
                        "summary": "List users",
                        "description": "Get list of all users",
                        "operationId": "listUsers",
                        "responses": {
                            "200": {
                                "description": "List of users",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "array",
                                            "items": {"$ref": "#/components/schemas/User"}
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "post": {
                        "tags": ["users"],
                        "summary": "Create user",
                        "description": "Create a new user",
                        "operationId": "createUser",
                        "x-required-permissions": ["write_users"],
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/UserCreate"}
                                }
                            }
                        },
                        "responses": {
                            "201": {
                                "description": "User created",
                                "content": {
                                    "application/json": {
                                        "schema": {"$ref": "#/components/schemas/User"}
                                    }
                                }
                            },
                            "400": {
                                "description": "Validation error"
                            }
                        }
                    }
                },
                "/users/{user_id}": {
                    "get": {
                        "tags": ["users"],
                        "summary": "Get user",
                        "description": "Get user by ID",
                        "operationId": "getUser",
                        "parameters": [
                            {
                                "name": "user_id",
                                "in": "path",
                                "required": True,
                                "schema": {"type": "string"}
                            }
                        ],
                        "responses": {
                            "200": {
                                "description": "User details",
                                "content": {
                                    "application/json": {
                                        "schema": {"$ref": "#/components/schemas/User"}
                                    }
                                }
                            },
                            "404": {
                                "description": "User not found"
                            }
                        }
                    }
                },
                "/admin/settings": {
                    "get": {
                        "tags": ["admin"],
                        "summary": "Get admin settings",
                        "description": "Get administrative settings",
                        "operationId": "getAdminSettings",
                        "x-required-permissions": ["admin_access"],
                        "responses": {
                            "200": {
                                "description": "Admin settings",
                                "content": {
                                    "application/json": {
                                        "schema": {"$ref": "#/components/schemas/AdminSettings"}
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "components": {
                "schemas": {
                    "User": {
                        "type": "object",
                        "required": ["id", "username", "email"],
                        "properties": {
                            "id": {"type": "string"},
                            "username": {"type": "string"},
                            "email": {"type": "string", "format": "email"},
                            "created_at": {"type": "string", "format": "date-time"},
                            "is_admin": {"type": "boolean"}
                        }
                    },
                    "UserCreate": {
                        "type": "object",
                        "required": ["username", "email"],
                        "properties": {
                            "username": {"type": "string"},
                            "email": {"type": "string", "format": "email"},
                            "password": {"type": "string", "minLength": 8}
                        }
                    },
                    "AdminSettings": {
                        "type": "object",
                        "x-required-permissions": ["admin_access"],
                        "properties": {
                            "maintenance_mode": {"type": "boolean"},
                            "max_users": {"type": "integer"},
                            "secret_key": {"type": "string"}
                        }
                    }
                }
            },
            "tags": [
                {
                    "name": "users",
                    "description": "User management operations"
                },
                {
                    "name": "admin",
                    "description": "Administrative operations"
                }
            ]
        }
    
    @staticmethod
    def create_theme(name: str = "test", **kwargs) -> DocumentationTheme:
        """Create documentation theme for testing."""
        return DocumentationTheme(
            name=name,
            primary_color=kwargs.get("primary_color", "#2196F3"),
            secondary_color=kwargs.get("secondary_color", "#757575"),
            background_color=kwargs.get("background_color", "#ffffff"),
            text_color=kwargs.get("text_color", "#333333"),
            accent_color=kwargs.get("accent_color", "#ff9800"),
            font_family=kwargs.get("font_family", "Arial, sans-serif"),
            logo_url=kwargs.get("logo_url"),
            favicon_url=kwargs.get("favicon_url"),
            custom_css=kwargs.get("custom_css"),
            custom_js=kwargs.get("custom_js"),
            swagger_ui_config=kwargs.get("swagger_ui_config", {}),
            redoc_config=kwargs.get("redoc_config", {})
        )
    
    @staticmethod
    def create_version(
        version: str = "1.0.0",
        title: Optional[str] = None,
        description: Optional[str] = None,
        deprecated: bool = False
    ) -> DocumentationVersion:
        """Create documentation version for testing."""
        return DocumentationVersion(
            version=version,
            title=title,
            description=description,
            deprecated=deprecated,
            release_date=datetime.now(timezone.utc) if not deprecated else None
        )
    
    @staticmethod
    def create_role_mappings() -> Dict[str, Dict[str, Any]]:
        """Create role mappings for testing."""
        return {
            "admin": {
                "paths": [".*"],  # All paths
                "methods": ["GET", "POST", "PUT", "DELETE", "PATCH"],
                "schemas": [".*"],  # All schemas
                "hide_fields": [],
                "hide_responses": []
            },
            "developer": {
                "paths": [r"/users.*", r"/api.*"],
                "methods": ["GET", "POST", "PUT"],
                "schemas": ["User", "UserCreate"],
                "hide_fields": ["secret_key"],
                "hide_responses": ["500"]
            },
            "readonly": {
                "paths": [r"/users.*"],
                "methods": ["GET"],
                "schemas": ["User"],
                "hide_fields": ["secret_key", "password"],
                "hide_responses": ["400", "500"]
            }
        }
    
    @staticmethod
    def create_permission_mappings() -> Dict[str, Dict[str, Any]]:
        """Create permission mappings for testing."""
        return {
            "read_all_docs": {
                "paths": [".*"]
            },
            "read_public_docs": {
                "paths": [r"/users.*", r"/public.*"]
            },
            "admin_access": {
                "paths": [r"/admin.*", r"/settings.*"]
            },
            "write_users": {
                "paths": [r"/users.*"]
            }
        }
    
    @staticmethod
    def create_tag_mappings() -> Dict[str, Set[str]]:
        """Create tag mappings for testing."""
        return {
            "admin": {"admin", "system"},
            "developer": {"users", "api", "development"},
            "readonly": {"public", "users"},
            "read_all_docs": {"users", "admin", "api", "system"},
            "read_public_docs": {"public", "users"}
        }


class AccessControlTestScenario:
    """Test scenario for access control testing."""
    
    def __init__(
        self,
        name: str,
        user_context: UserContext,
        expected_access: bool,
        expected_paths: Optional[Set[str]] = None,
        expected_schemas: Optional[Set[str]] = None,
        description: str = ""
    ):
        self.name = name
        self.user_context = user_context
        self.expected_access = expected_access
        self.expected_paths = expected_paths or set()
        self.expected_schemas = expected_schemas or set()
        self.description = description
    
    def __repr__(self):
        return f"AccessControlTestScenario({self.name})"


class DocumentationFilterTestHelper:
    """Helper for testing documentation filters."""
    
    @staticmethod
    def create_access_scenarios() -> List[AccessControlTestScenario]:
        """Create test scenarios for access control."""
        return [
            AccessControlTestScenario(
                name="admin_full_access",
                user_context=DocumentationTestHelper.create_admin_user_context(),
                expected_access=True,
                expected_paths={"/users", "/users/{user_id}", "/admin/settings"},
                expected_schemas={"User", "UserCreate", "AdminSettings"},
                description="Admin should have full access to all documentation"
            ),
            AccessControlTestScenario(
                name="developer_partial_access",
                user_context=DocumentationTestHelper.create_developer_user_context(),
                expected_access=True,
                expected_paths={"/users", "/users/{user_id}"},
                expected_schemas={"User", "UserCreate"},
                description="Developer should have access to user-related documentation"
            ),
            AccessControlTestScenario(
                name="readonly_limited_access",
                user_context=DocumentationTestHelper.create_readonly_user_context(),
                expected_access=True,
                expected_paths={"/users", "/users/{user_id}"},
                expected_schemas={"User"},
                description="Readonly user should have limited read access"
            ),
            AccessControlTestScenario(
                name="anonymous_no_access",
                user_context=DocumentationTestHelper.create_anonymous_user_context(),
                expected_access=False,
                expected_paths=set(),
                expected_schemas=set(),
                description="Anonymous user should have no access to protected documentation"
            )
        ]


class ThemeTestHelper:
    """Helper for testing documentation themes."""
    
    @staticmethod
    def create_test_themes() -> Dict[str, DocumentationTheme]:
        """Create test themes."""
        return {
            "corporate": DocumentationTestHelper.create_theme(
                name="corporate",
                primary_color="#003366",
                secondary_color="#666666",
                background_color="#f8f9fa",
                logo_url="https://example.com/logo.png",
                custom_css=".custom-header { color: #003366; }"
            ),
            "dark": DocumentationTestHelper.create_theme(
                name="dark",
                primary_color="#bb86fc",
                secondary_color="#03dac6",
                background_color="#121212",
                text_color="#ffffff"
            ),
            "minimal": DocumentationTestHelper.create_theme(
                name="minimal",
                primary_color="#000000",
                secondary_color="#ffffff",
                background_color="#ffffff",
                font_family="monospace"
            )
        }


class VersionTestHelper:
    """Helper for testing documentation versions."""
    
    @staticmethod
    def create_test_versions() -> Dict[str, DocumentationVersion]:
        """Create test versions."""
        return {
            "v1": DocumentationTestHelper.create_version(
                version="1.0.0",
                title="API v1.0",
                description="First stable version"
            ),
            "v2": DocumentationTestHelper.create_version(
                version="2.0.0",
                title="API v2.0",
                description="Second major version with breaking changes"
            ),
            "v1-deprecated": DocumentationTestHelper.create_version(
                version="1.5.0",
                title="API v1.5 (Deprecated)",
                description="Deprecated version, use v2.0 instead",
                deprecated=True
            )
        }


class AnalyticsTestHelper:
    """Helper for testing analytics functionality."""
    
    @staticmethod
    def simulate_access_pattern(
        analytics,
        patterns: List[Dict[str, Any]]
    ):
        """Simulate access patterns for analytics testing."""
        for pattern in patterns:
            user_context = pattern['user_context']
            format_type = pattern['format_type']
            endpoint = pattern.get('endpoint')
            success = pattern.get('success', True)
            count = pattern.get('count', 1)
            
            for _ in range(count):
                analytics.record_access(user_context, format_type, endpoint, success)


class PerformanceTestHelper:
    """Helper for performance testing."""
    
    @staticmethod
    def create_large_openapi_spec(num_paths: int = 100, num_schemas: int = 50) -> Dict[str, Any]:
        """Create large OpenAPI spec for performance testing."""
        spec = DocumentationTestHelper.create_sample_openapi_spec()
        
        # Add many paths
        for i in range(num_paths):
            path = f"/resource{i}"
            spec["paths"][path] = {
                "get": {
                    "tags": [f"resource{i % 10}"],
                    "summary": f"Get resource {i}",
                    "operationId": f"getResource{i}",
                    "responses": {
                        "200": {
                            "description": f"Resource {i} details",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": f"#/components/schemas/Resource{i}"}
                                }
                            }
                        }
                    }
                }
            }
        
        # Add many schemas
        for i in range(num_schemas):
            schema_name = f"Resource{i}"
            spec["components"]["schemas"][schema_name] = {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "name": {"type": "string"},
                    f"field_{i}": {"type": "string"},
                    "created_at": {"type": "string", "format": "date-time"}
                }
            }
        
        return spec
    
    @staticmethod
    def measure_filter_performance(
        doc_filter: DocumentationFilter,
        spec: Dict[str, Any],
        user_context: UserContext,
        iterations: int = 100
    ) -> Dict[str, float]:
        """Measure filter performance."""
        import time
        
        start_time = time.time()
        
        for _ in range(iterations):
            for path, methods in spec.get("paths", {}).items():
                for method, operation in methods.items():
                    if method.upper() in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                        doc_filter.should_include_path(path, method, operation, user_context)
                        doc_filter.filter_operation(operation, user_context)
            
            for schema_name, schema_def in spec.get("components", {}).get("schemas", {}).items():
                doc_filter.should_include_schema(schema_name, schema_def, user_context)
        
        end_time = time.time()
        total_time = end_time - start_time
        
        return {
            "total_time_seconds": total_time,
            "average_time_per_iteration": total_time / iterations,
            "iterations": iterations
        }


class SecurityTestHelper:
    """Helper for security testing."""
    
    @staticmethod
    def create_malicious_requests() -> List[MockRequest]:
        """Create malicious requests for security testing."""
        return [
            # Path traversal attempts
            MockRequest(path="/docs/../../../etc/passwd"),
            MockRequest(path="/docs/..%2F..%2F..%2Fetc%2Fpasswd"),
            
            # XSS attempts in query parameters
            MockRequest(
                path="/docs",
                query_params={"format": "<script>alert('xss')</script>"}
            ),
            
            # SQL injection attempts
            MockRequest(
                path="/docs",
                query_params={"version": "1'; DROP TABLE users; --"}
            ),
            
            # Header injection
            MockRequest(
                path="/docs",
                headers={
                    "User-Agent": "Mozilla/5.0\r\nX-Injected-Header: malicious"
                }
            ),
            
            # Large payload
            MockRequest(
                path="/docs",
                query_params={"data": "A" * 10000}
            )
        ]
    
    @staticmethod
    def create_privilege_escalation_scenarios() -> List[Dict[str, Any]]:
        """Create privilege escalation test scenarios."""
        return [
            {
                "name": "readonly_accessing_admin",
                "user_context": DocumentationTestHelper.create_readonly_user_context(),
                "requested_format": DocumentationFormat.OPENAPI_JSON,
                "malicious_params": {"admin": "true", "bypass": "1"}
            },
            {
                "name": "anonymous_with_fake_auth",
                "user_context": DocumentationTestHelper.create_anonymous_user_context(),
                "requested_format": DocumentationFormat.SWAGGER_UI,
                "malicious_headers": {"Authorization": "Bearer fake_token"}
            }
        ]