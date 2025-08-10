"""OpenAPI integration for FastAPI Shield.

This module provides comprehensive OpenAPI integration capabilities including
enhanced schema generation, shield documentation, security scheme integration,
and client SDK generation support.
"""

import inspect
import json
import logging
import re
import uuid
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import (
    Any, Dict, List, Optional, Set, Type, Union, Callable, Tuple,
    get_type_hints, get_origin, get_args
)
from urllib.parse import urljoin

from fastapi import FastAPI, Request, Response, Depends
from fastapi.openapi.models import (
    OpenAPI, Info, PathItem, Operation, Parameter, RequestBody, Response as OpenAPIResponse,
    SecurityScheme, Components, Schema, Reference, Example,
    Server, Tag, ExternalDocumentation, Contact, License
)
from fastapi.openapi.utils import get_openapi
from fastapi.routing import APIRoute
from fastapi.security.base import SecurityBase
from pydantic import BaseModel, Field
from starlette.routing import Route

from fastapi_shield.shield import Shield

logger = logging.getLogger(__name__)


class OpenAPIExtensionType(str, Enum):
    """Types of OpenAPI extensions."""
    SHIELD_INFO = "x-shield-info"
    SHIELD_SECURITY = "x-shield-security"
    SHIELD_VALIDATION = "x-shield-validation"
    SHIELD_METADATA = "x-shield-metadata"
    SHIELD_EXAMPLES = "x-shield-examples"
    SHIELD_RESPONSES = "x-shield-responses"
    SHIELD_PARAMETERS = "x-shield-parameters"


class SecuritySchemeType(str, Enum):
    """Security scheme types for shields."""
    API_KEY = "apiKey"
    HTTP = "http"
    OAUTH2 = "oauth2"
    OPEN_ID_CONNECT = "openIdConnect"
    SHIELD_CUSTOM = "x-shield-custom"


class ParameterLocation(str, Enum):
    """Parameter locations."""
    QUERY = "query"
    HEADER = "header"
    PATH = "path"
    COOKIE = "cookie"


@dataclass
class ShieldParameterInfo:
    """Information about shield parameters for OpenAPI."""
    name: str
    location: ParameterLocation
    description: str
    required: bool = True
    schema_type: str = "string"
    format_type: Optional[str] = None
    example: Any = None
    examples: Optional[Dict[str, Any]] = None
    deprecated: bool = False
    allow_empty_value: bool = False
    style: Optional[str] = None
    explode: Optional[bool] = None


@dataclass
class ShieldSecurityInfo:
    """Security information for shields."""
    scheme_name: str
    scheme_type: SecuritySchemeType
    description: str
    parameter_name: Optional[str] = None
    location: Optional[ParameterLocation] = None
    scheme: Optional[str] = None
    bearer_format: Optional[str] = None
    flows: Optional[Dict[str, Any]] = None
    open_id_connect_url: Optional[str] = None
    extensions: Optional[Dict[str, Any]] = None


@dataclass
class ShieldResponseInfo:
    """Response information for shields."""
    status_code: int
    description: str
    content: Optional[Dict[str, Any]] = None
    headers: Optional[Dict[str, Any]] = None
    examples: Optional[Dict[str, Any]] = None


@dataclass
class ShieldMetadata:
    """Metadata for shields in OpenAPI."""
    name: str
    description: str
    version: str = "1.0.0"
    tags: Set[str] = field(default_factory=set)
    parameters: List[ShieldParameterInfo] = field(default_factory=list)
    security: List[ShieldSecurityInfo] = field(default_factory=list)
    responses: List[ShieldResponseInfo] = field(default_factory=list)
    examples: Dict[str, Any] = field(default_factory=dict)
    extensions: Dict[str, Any] = field(default_factory=dict)
    deprecated: bool = False
    external_docs: Optional[Dict[str, str]] = None


class OpenAPISchemaGenerator(ABC):
    """Abstract base class for OpenAPI schema generators."""
    
    @abstractmethod
    def generate_parameter_schema(self, param_info: ShieldParameterInfo) -> Dict[str, Any]:
        """Generate parameter schema."""
        pass
    
    @abstractmethod
    def generate_security_schema(self, security_info: ShieldSecurityInfo) -> Dict[str, Any]:
        """Generate security schema."""
        pass
    
    @abstractmethod
    def generate_response_schema(self, response_info: ShieldResponseInfo) -> Dict[str, Any]:
        """Generate response schema."""
        pass


class DefaultOpenAPISchemaGenerator(OpenAPISchemaGenerator):
    """Default implementation of OpenAPI schema generator."""
    
    def generate_parameter_schema(self, param_info: ShieldParameterInfo) -> Dict[str, Any]:
        """Generate parameter schema."""
        schema = {
            "name": param_info.name,
            "in": param_info.location.value,
            "description": param_info.description,
            "required": param_info.required,
            "deprecated": param_info.deprecated,
            "allowEmptyValue": param_info.allow_empty_value,
            "schema": {
                "type": param_info.schema_type
            }
        }
        
        if param_info.format_type:
            schema["schema"]["format"] = param_info.format_type
        
        if param_info.example is not None:
            schema["example"] = param_info.example
        
        if param_info.examples:
            schema["examples"] = param_info.examples
        
        if param_info.style:
            schema["style"] = param_info.style
        
        if param_info.explode is not None:
            schema["explode"] = param_info.explode
        
        return schema
    
    def generate_security_schema(self, security_info: ShieldSecurityInfo) -> Dict[str, Any]:
        """Generate security schema."""
        schema = {
            "type": security_info.scheme_type.value,
            "description": security_info.description
        }
        
        if security_info.scheme_type == SecuritySchemeType.API_KEY:
            schema["name"] = security_info.parameter_name
            schema["in"] = security_info.location.value
        
        elif security_info.scheme_type == SecuritySchemeType.HTTP:
            schema["scheme"] = security_info.scheme
            if security_info.bearer_format:
                schema["bearerFormat"] = security_info.bearer_format
        
        elif security_info.scheme_type == SecuritySchemeType.OAUTH2:
            schema["flows"] = security_info.flows or {}
        
        elif security_info.scheme_type == SecuritySchemeType.OPEN_ID_CONNECT:
            schema["openIdConnectUrl"] = security_info.open_id_connect_url
        
        if security_info.extensions:
            schema.update(security_info.extensions)
        
        return schema
    
    def generate_response_schema(self, response_info: ShieldResponseInfo) -> Dict[str, Any]:
        """Generate response schema."""
        schema = {
            "description": response_info.description
        }
        
        if response_info.content:
            schema["content"] = response_info.content
        
        if response_info.headers:
            schema["headers"] = response_info.headers
        
        if response_info.examples:
            schema["examples"] = response_info.examples
        
        return schema


class ShieldIntrospector:
    """Introspects shields to extract OpenAPI metadata."""
    
    def __init__(self):
        self._shield_cache: Dict[str, ShieldMetadata] = {}
        self._type_mapping = {
            str: "string",
            int: "integer",
            float: "number",
            bool: "boolean",
            list: "array",
            dict: "object"
        }
    
    def introspect_shield(self, shield: Shield) -> ShieldMetadata:
        """Introspect a shield to extract metadata."""
        shield_id = self._get_shield_id(shield)
        
        if shield_id in self._shield_cache:
            return self._shield_cache[shield_id]
        
        metadata = ShieldMetadata(
            name=getattr(shield, '__name__', shield_id),
            description=self._extract_description(shield),
            tags=self._extract_tags(shield),
            parameters=self._extract_parameters(shield),
            security=self._extract_security_info(shield),
            responses=self._extract_responses(shield),
            examples=self._extract_examples(shield),
            extensions=self._extract_extensions(shield),
            deprecated=getattr(shield, '__deprecated__', False),
            external_docs=self._extract_external_docs(shield)
        )
        
        self._shield_cache[shield_id] = metadata
        return metadata
    
    def _get_shield_id(self, shield: Shield) -> str:
        """Get unique identifier for shield."""
        return f"{shield.__class__.__module__}.{shield.__class__.__name__}_{id(shield)}"
    
    def _extract_description(self, shield: Shield) -> str:
        """Extract description from shield."""
        # Try various sources for description
        if hasattr(shield, '__doc__') and shield.__doc__:
            return shield.__doc__.strip()
        
        if hasattr(shield, 'description'):
            return str(shield.description)
        
        if hasattr(shield, '_description'):
            return str(shield._description)
        
        return f"Shield: {shield.__class__.__name__}"
    
    def _extract_tags(self, shield: Shield) -> Set[str]:
        """Extract tags from shield."""
        tags = set()
        
        if hasattr(shield, 'tags'):
            if isinstance(shield.tags, (list, set, tuple)):
                tags.update(str(tag) for tag in shield.tags)
            else:
                tags.add(str(shield.tags))
        
        if hasattr(shield, '_tags'):
            if isinstance(shield._tags, (list, set, tuple)):
                tags.update(str(tag) for tag in shield._tags)
            else:
                tags.add(str(shield._tags))
        
        # Add class name as a tag
        tags.add(shield.__class__.__name__)
        
        return tags
    
    def _extract_parameters(self, shield: Shield) -> List[ShieldParameterInfo]:
        """Extract parameters from shield."""
        parameters = []
        
        # Try to get parameters from shield attributes
        if hasattr(shield, 'parameters'):
            params = shield.parameters
            if isinstance(params, dict):
                for name, param_config in params.items():
                    parameters.append(self._create_parameter_info(name, param_config))
        
        # Try to extract from shield function signature
        if hasattr(shield, 'shield_func') and callable(shield.shield_func):
            sig_params = self._extract_signature_parameters(shield.shield_func)
            parameters.extend(sig_params)
        
        return parameters
    
    def _create_parameter_info(self, name: str, config: Any) -> ShieldParameterInfo:
        """Create parameter info from configuration."""
        if isinstance(config, dict):
            return ShieldParameterInfo(
                name=name,
                location=ParameterLocation(config.get('location', 'query')),
                description=config.get('description', f'Parameter: {name}'),
                required=config.get('required', True),
                schema_type=config.get('type', 'string'),
                format_type=config.get('format'),
                example=config.get('example'),
                examples=config.get('examples')
            )
        else:
            return ShieldParameterInfo(
                name=name,
                location=ParameterLocation.QUERY,
                description=f'Parameter: {name}',
                schema_type=self._get_type_string(type(config))
            )
    
    def _extract_signature_parameters(self, func: Callable) -> List[ShieldParameterInfo]:
        """Extract parameters from function signature."""
        parameters = []
        
        try:
            signature = inspect.signature(func)
            type_hints = get_type_hints(func)
            
            for param_name, param in signature.parameters.items():
                if param_name in ('self', 'request', 'response'):
                    continue
                
                param_type = type_hints.get(param_name, str)
                param_info = ShieldParameterInfo(
                    name=param_name,
                    location=self._infer_parameter_location(param_name),
                    description=f'Parameter: {param_name}',
                    required=param.default == inspect.Parameter.empty,
                    schema_type=self._get_type_string(param_type),
                    example=param.default if param.default != inspect.Parameter.empty else None
                )
                parameters.append(param_info)
        
        except Exception as e:
            logger.warning(f"Could not extract parameters from {func}: {e}")
        
        return parameters
    
    def _infer_parameter_location(self, param_name: str) -> ParameterLocation:
        """Infer parameter location from name."""
        name_lower = param_name.lower()
        
        if 'header' in name_lower or name_lower.startswith('x_'):
            return ParameterLocation.HEADER
        elif 'cookie' in name_lower:
            return ParameterLocation.COOKIE
        else:
            return ParameterLocation.QUERY
    
    def _get_type_string(self, param_type: Type) -> str:
        """Get OpenAPI type string for Python type."""
        origin = get_origin(param_type)
        if origin:
            param_type = origin
        
        return self._type_mapping.get(param_type, "string")
    
    def _extract_security_info(self, shield: Shield) -> List[ShieldSecurityInfo]:
        """Extract security information from shield."""
        security_info = []
        
        if hasattr(shield, 'security'):
            security_config = shield.security
            if isinstance(security_config, dict):
                for scheme_name, scheme_config in security_config.items():
                    info = self._create_security_info(scheme_name, scheme_config)
                    security_info.append(info)
            elif isinstance(security_config, list):
                for i, scheme_config in enumerate(security_config):
                    scheme_name = f"security_{i}"
                    info = self._create_security_info(scheme_name, scheme_config)
                    security_info.append(info)
        
        # Check for common security patterns
        if hasattr(shield, 'api_key'):
            security_info.append(ShieldSecurityInfo(
                scheme_name="apiKey",
                scheme_type=SecuritySchemeType.API_KEY,
                description="API Key authentication",
                parameter_name="api_key",
                location=ParameterLocation.HEADER
            ))
        
        if hasattr(shield, 'bearer_token'):
            security_info.append(ShieldSecurityInfo(
                scheme_name="bearerAuth",
                scheme_type=SecuritySchemeType.HTTP,
                description="Bearer token authentication",
                scheme="bearer",
                bearer_format="JWT"
            ))
        
        return security_info
    
    def _create_security_info(self, scheme_name: str, config: Any) -> ShieldSecurityInfo:
        """Create security info from configuration."""
        if isinstance(config, dict):
            return ShieldSecurityInfo(
                scheme_name=scheme_name,
                scheme_type=SecuritySchemeType(config.get('type', 'apiKey')),
                description=config.get('description', f'Security scheme: {scheme_name}'),
                parameter_name=config.get('name'),
                location=ParameterLocation(config.get('in', 'header')) if config.get('in') else None,
                scheme=config.get('scheme'),
                bearer_format=config.get('bearerFormat'),
                flows=config.get('flows'),
                open_id_connect_url=config.get('openIdConnectUrl'),
                extensions=config.get('extensions')
            )
        else:
            return ShieldSecurityInfo(
                scheme_name=scheme_name,
                scheme_type=SecuritySchemeType.API_KEY,
                description=f'Security scheme: {scheme_name}'
            )
    
    def _extract_responses(self, shield: Shield) -> List[ShieldResponseInfo]:
        """Extract response information from shield."""
        responses = []
        
        if hasattr(shield, 'responses'):
            response_config = shield.responses
            if isinstance(response_config, dict):
                for status_code, response_info in response_config.items():
                    info = self._create_response_info(int(status_code), response_info)
                    responses.append(info)
        
        # Add default responses
        responses.extend(self._get_default_responses())
        
        return responses
    
    def _create_response_info(self, status_code: int, config: Any) -> ShieldResponseInfo:
        """Create response info from configuration."""
        if isinstance(config, dict):
            return ShieldResponseInfo(
                status_code=status_code,
                description=config.get('description', f'Response {status_code}'),
                content=config.get('content'),
                headers=config.get('headers'),
                examples=config.get('examples')
            )
        else:
            return ShieldResponseInfo(
                status_code=status_code,
                description=str(config)
            )
    
    def _get_default_responses(self) -> List[ShieldResponseInfo]:
        """Get default shield responses."""
        return [
            ShieldResponseInfo(
                status_code=401,
                description="Unauthorized - Shield authentication failed",
                content={
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "detail": {"type": "string"},
                                "shield": {"type": "string"}
                            }
                        }
                    }
                }
            ),
            ShieldResponseInfo(
                status_code=403,
                description="Forbidden - Shield authorization failed",
                content={
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "detail": {"type": "string"},
                                "shield": {"type": "string"}
                            }
                        }
                    }
                }
            ),
            ShieldResponseInfo(
                status_code=429,
                description="Too Many Requests - Shield rate limit exceeded",
                content={
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
            )
        ]
    
    def _extract_examples(self, shield: Shield) -> Dict[str, Any]:
        """Extract examples from shield."""
        examples = {}
        
        if hasattr(shield, 'examples'):
            shield_examples = shield.examples
            if isinstance(shield_examples, dict):
                examples.update(shield_examples)
        
        return examples
    
    def _extract_extensions(self, shield: Shield) -> Dict[str, Any]:
        """Extract OpenAPI extensions from shield."""
        extensions = {}
        
        if hasattr(shield, 'openapi_extensions'):
            shield_extensions = shield.openapi_extensions
            if isinstance(shield_extensions, dict):
                extensions.update(shield_extensions)
        
        # Add shield-specific extensions
        extensions[OpenAPIExtensionType.SHIELD_INFO.value] = {
            "shield_class": shield.__class__.__name__,
            "shield_module": shield.__class__.__module__,
            "shield_version": getattr(shield, '__version__', '1.0.0')
        }
        
        return extensions
    
    def _extract_external_docs(self, shield: Shield) -> Optional[Dict[str, str]]:
        """Extract external documentation from shield."""
        if hasattr(shield, 'external_docs'):
            return shield.external_docs
        
        return None


class OpenAPIShieldEnhancer:
    """Enhances OpenAPI documentation with shield information."""
    
    def __init__(
        self,
        schema_generator: Optional[OpenAPISchemaGenerator] = None,
        introspector: Optional[ShieldIntrospector] = None
    ):
        self.schema_generator = schema_generator or DefaultOpenAPISchemaGenerator()
        self.introspector = introspector or ShieldIntrospector()
        self._enhanced_routes: Dict[str, Dict[str, Any]] = {}
    
    def enhance_openapi_schema(
        self,
        openapi_schema: Dict[str, Any],
        app: FastAPI
    ) -> Dict[str, Any]:
        """Enhance OpenAPI schema with shield information."""
        enhanced_schema = openapi_schema.copy()
        
        # Enhance paths
        if 'paths' in enhanced_schema:
            enhanced_schema['paths'] = self._enhance_paths(
                enhanced_schema['paths'], app
            )
        
        # Enhance components
        if 'components' not in enhanced_schema:
            enhanced_schema['components'] = {}
        
        enhanced_schema['components'] = self._enhance_components(
            enhanced_schema['components'], app
        )
        
        # Add shield-specific extensions
        enhanced_schema.update(self._get_global_extensions(app))
        
        return enhanced_schema
    
    def _enhance_paths(
        self,
        paths: Dict[str, Any],
        app: FastAPI
    ) -> Dict[str, Any]:
        """Enhance path items with shield information."""
        enhanced_paths = {}
        
        for path, path_item in paths.items():
            enhanced_path_item = path_item.copy()
            
            for method, operation in path_item.items():
                if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE']:
                    enhanced_operation = self._enhance_operation(
                        operation, path, method, app
                    )
                    enhanced_path_item[method] = enhanced_operation
            
            enhanced_paths[path] = enhanced_path_item
        
        return enhanced_paths
    
    def _enhance_operation(
        self,
        operation: Dict[str, Any],
        path: str,
        method: str,
        app: FastAPI
    ) -> Dict[str, Any]:
        """Enhance operation with shield information."""
        enhanced_operation = operation.copy()
        
        # Find shields for this route
        shields = self._find_shields_for_route(path, method, app)
        
        if not shields:
            return enhanced_operation
        
        # Enhance parameters
        shield_parameters = []
        shield_security = []
        shield_responses = {}
        shield_extensions = {}
        
        for shield in shields:
            metadata = self.introspector.introspect_shield(shield)
            
            # Add parameters
            for param_info in metadata.parameters:
                param_schema = self.schema_generator.generate_parameter_schema(param_info)
                shield_parameters.append(param_schema)
            
            # Add security requirements
            for security_info in metadata.security:
                shield_security.append({security_info.scheme_name: []})
            
            # Add responses
            for response_info in metadata.responses:
                response_schema = self.schema_generator.generate_response_schema(response_info)
                shield_responses[str(response_info.status_code)] = response_schema
            
            # Add extensions
            shield_extensions.update(metadata.extensions)
        
        # Merge with existing operation
        if shield_parameters:
            if 'parameters' not in enhanced_operation:
                enhanced_operation['parameters'] = []
            enhanced_operation['parameters'].extend(shield_parameters)
        
        if shield_security:
            if 'security' not in enhanced_operation:
                enhanced_operation['security'] = []
            enhanced_operation['security'].extend(shield_security)
        
        if shield_responses:
            if 'responses' not in enhanced_operation:
                enhanced_operation['responses'] = {}
            enhanced_operation['responses'].update(shield_responses)
        
        if shield_extensions:
            enhanced_operation.update(shield_extensions)
        
        return enhanced_operation
    
    def _find_shields_for_route(
        self,
        path: str,
        method: str,
        app: FastAPI
    ) -> List[Shield]:
        """Find shields associated with a route."""
        shields = []
        
        for route in app.routes:
            if isinstance(route, APIRoute):
                route_path = getattr(route, 'path', '')
                route_methods = getattr(route, 'methods', set())
                
                if self._path_matches(path, route_path) and method.upper() in route_methods:
                    # Check for shields in route dependencies
                    shields.extend(self._extract_shields_from_route(route))
        
        return shields
    
    def _path_matches(self, openapi_path: str, route_path: str) -> bool:
        """Check if OpenAPI path matches route path."""
        # Convert FastAPI path parameters to OpenAPI format
        converted_route_path = re.sub(r'\{([^}]+)\}', r'{\1}', route_path)
        return openapi_path == converted_route_path
    
    def _extract_shields_from_route(self, route: APIRoute) -> List[Shield]:
        """Extract shields from route dependencies."""
        shields = []
        
        # Check route dependencies
        if hasattr(route, 'dependencies'):
            for dependency in route.dependencies:
                shield = self._extract_shield_from_dependency(dependency)
                if shield:
                    shields.append(shield)
        
        # Check endpoint dependencies
        if hasattr(route, 'endpoint'):
            endpoint_shields = self._extract_shields_from_endpoint(route.endpoint)
            shields.extend(endpoint_shields)
        
        return shields
    
    def _extract_shield_from_dependency(self, dependency: Depends) -> Optional[Shield]:
        """Extract shield from dependency."""
        if hasattr(dependency, 'dependency'):
            dep_func = dependency.dependency
            if isinstance(dep_func, Shield):
                return dep_func
            elif hasattr(dep_func, 'shield'):
                return dep_func.shield
        
        return None
    
    def _extract_shields_from_endpoint(self, endpoint: Callable) -> List[Shield]:
        """Extract shields from endpoint function."""
        shields = []
        
        # Check for shield decorators
        if hasattr(endpoint, '__shields__'):
            shields.extend(endpoint.__shields__)
        
        # Check function annotations
        try:
            signature = inspect.signature(endpoint)
            for param in signature.parameters.values():
                if isinstance(param.default, Shield):
                    shields.append(param.default)
        except Exception:
            pass
        
        return shields
    
    def _enhance_components(
        self,
        components: Dict[str, Any],
        app: FastAPI
    ) -> Dict[str, Any]:
        """Enhance components with shield security schemes."""
        enhanced_components = components.copy()
        
        if 'securitySchemes' not in enhanced_components:
            enhanced_components['securitySchemes'] = {}
        
        # Collect all security schemes from shields
        for route in app.routes:
            if isinstance(route, APIRoute):
                shields = self._extract_shields_from_route(route)
                for shield in shields:
                    metadata = self.introspector.introspect_shield(shield)
                    for security_info in metadata.security:
                        security_schema = self.schema_generator.generate_security_schema(security_info)
                        enhanced_components['securitySchemes'][security_info.scheme_name] = security_schema
        
        return enhanced_components
    
    def _get_global_extensions(self, app: FastAPI) -> Dict[str, Any]:
        """Get global OpenAPI extensions for shields."""
        return {
            OpenAPIExtensionType.SHIELD_INFO.value: {
                "version": "1.0.0",
                "generator": "FastAPI-Shield OpenAPI Integration",
                "timestamp": datetime.now().isoformat(),
                "shield_count": self._count_shields(app)
            }
        }
    
    def _count_shields(self, app: FastAPI) -> int:
        """Count total number of shields in the app."""
        shield_count = 0
        
        for route in app.routes:
            if isinstance(route, APIRoute):
                shields = self._extract_shields_from_route(route)
                shield_count += len(shields)
        
        return shield_count


class OpenAPIClientGenerator:
    """Generates client SDK documentation and examples."""
    
    def __init__(self, enhancer: Optional[OpenAPIShieldEnhancer] = None):
        self.enhancer = enhancer or OpenAPIShieldEnhancer()
        self._client_examples: Dict[str, Dict[str, Any]] = {}
    
    def generate_client_examples(
        self,
        openapi_schema: Dict[str, Any],
        languages: Optional[List[str]] = None
    ) -> Dict[str, Dict[str, Any]]:
        """Generate client examples for different languages."""
        if languages is None:
            languages = ['python', 'javascript', 'curl']
        
        examples = {}
        
        for language in languages:
            examples[language] = self._generate_language_examples(
                openapi_schema, language
            )
        
        return examples
    
    def _generate_language_examples(
        self,
        schema: Dict[str, Any],
        language: str
    ) -> Dict[str, Any]:
        """Generate examples for a specific language."""
        if language == 'python':
            return self._generate_python_examples(schema)
        elif language == 'javascript':
            return self._generate_javascript_examples(schema)
        elif language == 'curl':
            return self._generate_curl_examples(schema)
        else:
            return {}
    
    def _generate_python_examples(self, schema: Dict[str, Any]) -> Dict[str, Any]:
        """Generate Python client examples."""
        examples = {
            "imports": [
                "import requests",
                "import json",
                "from typing import Optional, Dict, Any"
            ],
            "client_class": self._generate_python_client_class(schema),
            "usage_examples": self._generate_python_usage_examples(schema)
        }
        
        return examples
    
    def _generate_python_client_class(self, schema: Dict[str, Any]) -> str:
        """Generate Python client class."""
        class_template = '''
class ShieldedAPIClient:
    def __init__(self, base_url: str, api_key: Optional[str] = None):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.session = requests.Session()
        if api_key:
            self.session.headers.update({'Authorization': f'Bearer {api_key}'})
    
    def _make_request(
        self, 
        method: str, 
        path: str, 
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, Any]] = None
    ) -> requests.Response:
        url = f"{self.base_url}{path}"
        request_headers = self.session.headers.copy()
        if headers:
            request_headers.update(headers)
        
        response = self.session.request(
            method=method,
            url=url,
            params=params,
            json=json_data,
            headers=request_headers
        )
        response.raise_for_status()
        return response
'''
        
        # Add method stubs for each path
        paths = schema.get('paths', {})
        for path, path_item in paths.items():
            for method, operation in path_item.items():
                if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                    method_template = self._generate_python_method(path, method, operation)
                    class_template += f"\n{method_template}"
        
        return class_template
    
    def _generate_python_method(
        self, 
        path: str, 
        method: str, 
        operation: Dict[str, Any]
    ) -> str:
        """Generate Python method for an operation."""
        operation_id = operation.get('operationId', f"{method}_{path.replace('/', '_')}")
        method_name = operation_id.lower()
        
        return f'''
    def {method_name}(self, **kwargs) -> Dict[str, Any]:
        """
        {operation.get('summary', f'{method.upper()} {path}')}
        
        {operation.get('description', '')}
        """
        return self._make_request('{method.upper()}', '{path}', **kwargs).json()'''
    
    def _generate_python_usage_examples(self, schema: Dict[str, Any]) -> List[str]:
        """Generate Python usage examples."""
        examples = [
            '''
# Initialize client
client = ShieldedAPIClient('https://api.example.com', api_key='your-api-key')

# Example API calls with shield protection
try:
    response = client.get_protected_resource()
    print(response)
except requests.exceptions.HTTPError as e:
    if e.response.status_code == 401:
        print("Authentication failed - check your API key")
    elif e.response.status_code == 403:
        print("Authorization failed - insufficient permissions")
    elif e.response.status_code == 429:
        print("Rate limit exceeded - please wait before retrying")
'''
        ]
        
        return examples
    
    def _generate_javascript_examples(self, schema: Dict[str, Any]) -> Dict[str, Any]:
        """Generate JavaScript client examples."""
        examples = {
            "client_class": r'''
class ShieldedAPIClient {
    constructor(baseUrl, apiKey = null) {
        this.baseUrl = baseUrl.replace(/\/$/, '');
        this.apiKey = apiKey;
    }
    
    async makeRequest(method, path, options = {}) {
        const url = `${this.baseUrl}${path}`;
        const headers = {
            'Content-Type': 'application/json',
            ...options.headers
        };
        
        if (this.apiKey) {
            headers['Authorization'] = `Bearer ${this.apiKey}`;
        }
        
        const response = await fetch(url, {
            method: method.toUpperCase(),
            headers,
            ...options
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        return response.json();
    }
}
''',
            "usage_examples": [
                '''
// Initialize client
const client = new ShieldedAPIClient('https://api.example.com', 'your-api-key');

// Example API calls with shield protection
try {
    const response = await client.makeRequest('GET', '/protected-resource');
    console.log(response);
} catch (error) {
    console.error('API call failed:', error.message);
}
'''
            ]
        }
        
        return examples
    
    def _generate_curl_examples(self, schema: Dict[str, Any]) -> Dict[str, Any]:
        """Generate cURL examples."""
        examples = {"commands": []}
        
        base_url = "https://api.example.com"
        
        paths = schema.get('paths', {})
        for path, path_item in paths.items():
            for method, operation in path_item.items():
                if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                    curl_command = self._generate_curl_command(
                        base_url, path, method, operation
                    )
                    examples["commands"].append(curl_command)
        
        return examples
    
    def _generate_curl_command(
        self,
        base_url: str,
        path: str,
        method: str,
        operation: Dict[str, Any]
    ) -> str:
        """Generate cURL command for an operation."""
        command = f"curl -X {method.upper()}"
        
        # Add headers
        command += " -H 'Content-Type: application/json'"
        command += " -H 'Authorization: Bearer YOUR_API_KEY'"
        
        # Add data for POST/PUT requests
        if method.upper() in ['POST', 'PUT', 'PATCH']:
            command += " -d '{\"key\": \"value\"}'"
        
        # Add URL
        command += f" '{base_url}{path}'"
        
        # Add comment
        comment = operation.get('summary', f'{method.upper()} {path}')
        return f"# {comment}\n{command}"


def create_enhanced_openapi_schema(
    app: FastAPI,
    enhancer: Optional[OpenAPIShieldEnhancer] = None,
    include_client_examples: bool = True
) -> Dict[str, Any]:
    """Create enhanced OpenAPI schema with shield information."""
    # Get base OpenAPI schema
    base_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
        tags=app.openapi_tags,
        servers=app.servers
    )
    
    # Enhance with shield information
    if enhancer is None:
        enhancer = OpenAPIShieldEnhancer()
    
    enhanced_schema = enhancer.enhance_openapi_schema(base_schema, app)
    
    # Add client examples if requested
    if include_client_examples:
        client_generator = OpenAPIClientGenerator(enhancer)
        client_examples = client_generator.generate_client_examples(enhanced_schema)
        enhanced_schema[OpenAPIExtensionType.SHIELD_EXAMPLES.value] = client_examples
    
    return enhanced_schema


def setup_enhanced_openapi(
    app: FastAPI,
    enhancer: Optional[OpenAPIShieldEnhancer] = None,
    include_client_examples: bool = True
) -> None:
    """Set up enhanced OpenAPI for FastAPI app."""
    def custom_openapi():
        if app.openapi_schema:
            return app.openapi_schema
        
        openapi_schema = create_enhanced_openapi_schema(
            app, enhancer, include_client_examples
        )
        app.openapi_schema = openapi_schema
        return app.openapi_schema
    
    app.openapi = custom_openapi


# Utility functions for common use cases
def add_shield_to_openapi(
    operation: Dict[str, Any],
    shield: Shield,
    introspector: Optional[ShieldIntrospector] = None,
    schema_generator: Optional[OpenAPISchemaGenerator] = None
) -> Dict[str, Any]:
    """Add shield information to an OpenAPI operation."""
    if introspector is None:
        introspector = ShieldIntrospector()
    
    if schema_generator is None:
        schema_generator = DefaultOpenAPISchemaGenerator()
    
    metadata = introspector.introspect_shield(shield)
    enhanced_operation = operation.copy()
    
    # Add parameters
    shield_parameters = []
    for param_info in metadata.parameters:
        param_schema = schema_generator.generate_parameter_schema(param_info)
        shield_parameters.append(param_schema)
    
    if shield_parameters:
        if 'parameters' not in enhanced_operation:
            enhanced_operation['parameters'] = []
        enhanced_operation['parameters'].extend(shield_parameters)
    
    # Add security
    shield_security = []
    for security_info in metadata.security:
        shield_security.append({security_info.scheme_name: []})
    
    if shield_security:
        if 'security' not in enhanced_operation:
            enhanced_operation['security'] = []
        enhanced_operation['security'].extend(shield_security)
    
    # Add responses
    for response_info in metadata.responses:
        response_schema = schema_generator.generate_response_schema(response_info)
        if 'responses' not in enhanced_operation:
            enhanced_operation['responses'] = {}
        enhanced_operation['responses'][str(response_info.status_code)] = response_schema
    
    # Add extensions
    enhanced_operation.update(metadata.extensions)
    
    return enhanced_operation


def extract_shield_openapi_info(shield: Shield) -> Dict[str, Any]:
    """Extract OpenAPI information from a shield."""
    introspector = ShieldIntrospector()
    metadata = introspector.introspect_shield(shield)
    
    schema_generator = DefaultOpenAPISchemaGenerator()
    
    info = {
        "name": metadata.name,
        "description": metadata.description,
        "version": metadata.version,
        "tags": list(metadata.tags),
        "deprecated": metadata.deprecated,
        "parameters": [
            schema_generator.generate_parameter_schema(param)
            for param in metadata.parameters
        ],
        "security": [
            schema_generator.generate_security_schema(security)
            for security in metadata.security
        ],
        "responses": [
            {
                "status_code": resp.status_code,
                **schema_generator.generate_response_schema(resp)
            }
            for resp in metadata.responses
        ],
        "examples": metadata.examples,
        "extensions": metadata.extensions
    }
    
    if metadata.external_docs:
        info["external_docs"] = metadata.external_docs
    
    return info