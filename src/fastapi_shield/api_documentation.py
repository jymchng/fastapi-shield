"""API Documentation shield for FastAPI Shield.

This module provides comprehensive API documentation access control and
personalization functionality. It includes role-based access control,
version-specific documentation generation, custom theming and branding,
and integration with popular documentation tools like Swagger UI and ReDoc.
"""

import json
import re
from abc import ABC, abstractmethod
from collections import defaultdict
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Callable, Union, Pattern, Tuple
import logging
from urllib.parse import urlparse

from fastapi import HTTPException, Request, Response, status
from fastapi.openapi.utils import get_openapi
from fastapi.responses import HTMLResponse, JSONResponse

from fastapi_shield.shield import Shield


class DocumentationFormat(str, Enum):
    """Supported documentation formats."""
    OPENAPI_JSON = "openapi_json"
    OPENAPI_YAML = "openapi_yaml"
    SWAGGER_UI = "swagger_ui"
    REDOC = "redoc"
    RAPIDOC = "rapidoc"
    STOPLIGHT_ELEMENTS = "stoplight_elements"
    CUSTOM_HTML = "custom_html"
    MARKDOWN = "markdown"


class AccessLevel(str, Enum):
    """Access levels for API documentation."""
    PUBLIC = "public"           # No authentication required
    AUTHENTICATED = "authenticated"  # Must be authenticated
    ROLE_BASED = "role_based"   # Based on user roles
    PERMISSION_BASED = "permission_based"  # Based on specific permissions
    CUSTOM = "custom"           # Custom access control logic


class DocumentationScope(str, Enum):
    """Scope of documentation access."""
    FULL = "full"               # Full API documentation
    FILTERED = "filtered"       # Filtered based on permissions
    ENDPOINT_SPECIFIC = "endpoint_specific"  # Specific endpoints only
    TAG_BASED = "tag_based"     # Based on OpenAPI tags
    CUSTOM = "custom"           # Custom scope definition


@dataclass
class DocumentationTheme:
    """Theme configuration for documentation."""
    name: str
    primary_color: str = "#1976d2"
    secondary_color: str = "#424242"
    background_color: str = "#ffffff"
    text_color: str = "#212121"
    accent_color: str = "#ff9800"
    font_family: str = "Roboto, sans-serif"
    logo_url: Optional[str] = None
    favicon_url: Optional[str] = None
    custom_css: Optional[str] = None
    custom_js: Optional[str] = None
    swagger_ui_config: Dict[str, Any] = field(default_factory=dict)
    redoc_config: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DocumentationVersion:
    """Version configuration for API documentation."""
    version: str
    title: Optional[str] = None
    description: Optional[str] = None
    deprecated: bool = False
    release_date: Optional[datetime] = None
    changelog_url: Optional[str] = None
    spec_modifications: Dict[str, Any] = field(default_factory=dict)
    access_overrides: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class UserContext:
    """User context for documentation access control."""
    user_id: Optional[str] = None
    roles: Set[str] = field(default_factory=set)
    permissions: Set[str] = field(default_factory=set)
    groups: Set[str] = field(default_factory=set)
    attributes: Dict[str, Any] = field(default_factory=dict)
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    authenticated: bool = False
    
    def has_role(self, role: str) -> bool:
        """Check if user has a specific role."""
        return role in self.roles
    
    def has_permission(self, permission: str) -> bool:
        """Check if user has a specific permission."""
        return permission in self.permissions
    
    def has_any_role(self, roles: Set[str]) -> bool:
        """Check if user has any of the specified roles."""
        return bool(self.roles.intersection(roles))
    
    def has_any_permission(self, permissions: Set[str]) -> bool:
        """Check if user has any of the specified permissions."""
        return bool(self.permissions.intersection(permissions))
    
    def in_group(self, group: str) -> bool:
        """Check if user is in a specific group."""
        return group in self.groups


class DocumentationFilter(ABC):
    """Abstract base class for documentation filtering."""
    
    @abstractmethod
    def should_include_path(self, path: str, method: str, operation: Dict[str, Any], user_context: UserContext) -> bool:
        """Check if a path/method should be included in documentation."""
        pass
    
    @abstractmethod
    def should_include_schema(self, schema_name: str, schema_def: Dict[str, Any], user_context: UserContext) -> bool:
        """Check if a schema should be included in documentation."""
        pass
    
    @abstractmethod
    def filter_operation(self, operation: Dict[str, Any], user_context: UserContext) -> Dict[str, Any]:
        """Filter operation details based on user context."""
        pass


class RoleBasedDocumentationFilter(DocumentationFilter):
    """Role-based documentation filter."""
    
    def __init__(self, role_mappings: Dict[str, Dict[str, Any]]):
        """
        Initialize with role mappings.
        
        Args:
            role_mappings: Dict mapping roles to their allowed paths/operations
        """
        self.role_mappings = role_mappings
    
    def should_include_path(self, path: str, method: str, operation: Dict[str, Any], user_context: UserContext) -> bool:
        """Check if path should be included based on user roles."""
        if not user_context.roles:
            return False
        
        for role in user_context.roles:
            if role in self.role_mappings:
                role_config = self.role_mappings[role]
                
                # Check path patterns
                allowed_paths = role_config.get('paths', [])
                for pattern in allowed_paths:
                    if re.match(pattern, path):
                        # Check method
                        allowed_methods = role_config.get('methods', ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
                        if method.upper() in [m.upper() for m in allowed_methods]:
                            return True
        
        return False
    
    def should_include_schema(self, schema_name: str, schema_def: Dict[str, Any], user_context: UserContext) -> bool:
        """Check if schema should be included based on user roles."""
        if not user_context.roles:
            return False
        
        for role in user_context.roles:
            if role in self.role_mappings:
                role_config = self.role_mappings[role]
                
                # Check schema patterns
                allowed_schemas = role_config.get('schemas', ['.*'])  # Default to all schemas
                for pattern in allowed_schemas:
                    if re.match(pattern, schema_name):
                        return True
        
        return False
    
    def filter_operation(self, operation: Dict[str, Any], user_context: UserContext) -> Dict[str, Any]:
        """Filter operation details based on user roles."""
        filtered_operation = deepcopy(operation)
        
        # Remove sensitive information based on roles
        for role in user_context.roles:
            if role in self.role_mappings:
                role_config = self.role_mappings[role]
                
                # Hide fields
                hidden_fields = role_config.get('hide_fields', [])
                self._remove_fields(filtered_operation, hidden_fields)
                
                # Hide responses
                hidden_responses = role_config.get('hide_responses', [])
                if 'responses' in filtered_operation:
                    for response_code in hidden_responses:
                        filtered_operation['responses'].pop(str(response_code), None)
        
        return filtered_operation
    
    def _remove_fields(self, obj: Any, fields_to_remove: List[str]):
        """Recursively remove fields from object."""
        if isinstance(obj, dict):
            for field in fields_to_remove:
                obj.pop(field, None)
            
            for value in obj.values():
                self._remove_fields(value, fields_to_remove)
        elif isinstance(obj, list):
            for item in obj:
                self._remove_fields(item, fields_to_remove)


class PermissionBasedDocumentationFilter(DocumentationFilter):
    """Permission-based documentation filter."""
    
    def __init__(self, permission_mappings: Dict[str, Dict[str, Any]]):
        """
        Initialize with permission mappings.
        
        Args:
            permission_mappings: Dict mapping permissions to their allowed operations
        """
        self.permission_mappings = permission_mappings
    
    def should_include_path(self, path: str, method: str, operation: Dict[str, Any], user_context: UserContext) -> bool:
        """Check if path should be included based on user permissions."""
        # Check if operation has required permissions
        required_permissions = operation.get('x-required-permissions', [])
        if required_permissions:
            if not user_context.has_any_permission(set(required_permissions)):
                return False
        
        # Check permission mappings
        for permission in user_context.permissions:
            if permission in self.permission_mappings:
                perm_config = self.permission_mappings[permission]
                
                # Check path patterns
                allowed_paths = perm_config.get('paths', [])
                for pattern in allowed_paths:
                    if re.match(pattern, path):
                        return True
        
        return False
    
    def should_include_schema(self, schema_name: str, schema_def: Dict[str, Any], user_context: UserContext) -> bool:
        """Check if schema should be included based on permissions."""
        # Check if schema has required permissions
        required_permissions = schema_def.get('x-required-permissions', [])
        if required_permissions:
            return user_context.has_any_permission(set(required_permissions))
        
        return True
    
    def filter_operation(self, operation: Dict[str, Any], user_context: UserContext) -> Dict[str, Any]:
        """Filter operation details based on user permissions."""
        filtered_operation = deepcopy(operation)
        
        # Filter based on field-level permissions
        field_permissions = operation.get('x-field-permissions', {})
        for field, required_perms in field_permissions.items():
            if not user_context.has_any_permission(set(required_perms)):
                # Remove field from all relevant places
                self._remove_field_from_operation(filtered_operation, field)
        
        return filtered_operation
    
    def _remove_field_from_operation(self, operation: Dict[str, Any], field: str):
        """Remove a specific field from operation definition."""
        # This is a simplified implementation
        # In practice, you'd need to traverse the entire OpenAPI spec structure
        if 'requestBody' in operation:
            self._remove_field_from_schema(operation['requestBody'], field)
        
        if 'responses' in operation:
            for response in operation['responses'].values():
                self._remove_field_from_schema(response, field)
    
    def _remove_field_from_schema(self, schema_obj: Dict[str, Any], field: str):
        """Remove field from schema object."""
        if isinstance(schema_obj, dict):
            # Remove from properties
            if 'content' in schema_obj:
                for content_type in schema_obj['content'].values():
                    if 'schema' in content_type:
                        self._remove_field_from_schema_recursive(content_type['schema'], field)
            
            self._remove_field_from_schema_recursive(schema_obj, field)
    
    def _remove_field_from_schema_recursive(self, schema: Dict[str, Any], field: str):
        """Recursively remove field from schema."""
        if 'properties' in schema and field in schema['properties']:
            del schema['properties'][field]
        
        # Remove from required fields
        if 'required' in schema and field in schema['required']:
            schema['required'].remove(field)
        
        # Handle nested schemas
        if 'properties' in schema:
            for prop_schema in schema['properties'].values():
                if isinstance(prop_schema, dict):
                    self._remove_field_from_schema_recursive(prop_schema, field)


class TagBasedDocumentationFilter(DocumentationFilter):
    """Tag-based documentation filter."""
    
    def __init__(self, allowed_tags: Dict[str, Set[str]]):
        """
        Initialize with allowed tags per role/permission.
        
        Args:
            allowed_tags: Dict mapping roles/permissions to allowed tags
        """
        self.allowed_tags = allowed_tags
    
    def should_include_path(self, path: str, method: str, operation: Dict[str, Any], user_context: UserContext) -> bool:
        """Check if path should be included based on operation tags."""
        operation_tags = set(operation.get('tags', []))
        
        # Get allowed tags for user
        user_allowed_tags = set()
        for role in user_context.roles:
            if role in self.allowed_tags:
                user_allowed_tags.update(self.allowed_tags[role])
        
        for permission in user_context.permissions:
            if permission in self.allowed_tags:
                user_allowed_tags.update(self.allowed_tags[permission])
        
        # Check if operation has any allowed tags
        return bool(operation_tags.intersection(user_allowed_tags)) if operation_tags else False
    
    def should_include_schema(self, schema_name: str, schema_def: Dict[str, Any], user_context: UserContext) -> bool:
        """Check if schema should be included (always true for tag-based filtering)."""
        return True
    
    def filter_operation(self, operation: Dict[str, Any], user_context: UserContext) -> Dict[str, Any]:
        """Filter operation (no changes for tag-based filtering)."""
        return operation


class CustomDocumentationFilter(DocumentationFilter):
    """Custom documentation filter with user-defined logic."""
    
    def __init__(
        self,
        path_filter: Optional[Callable[[str, str, Dict[str, Any], UserContext], bool]] = None,
        schema_filter: Optional[Callable[[str, Dict[str, Any], UserContext], bool]] = None,
        operation_filter: Optional[Callable[[Dict[str, Any], UserContext], Dict[str, Any]]] = None
    ):
        """
        Initialize with custom filter functions.
        
        Args:
            path_filter: Custom function to determine if path should be included
            schema_filter: Custom function to determine if schema should be included
            operation_filter: Custom function to filter operation details
        """
        self._path_filter = path_filter
        self._schema_filter = schema_filter
        self._operation_filter = operation_filter
    
    def should_include_path(self, path: str, method: str, operation: Dict[str, Any], user_context: UserContext) -> bool:
        """Check if path should be included using custom logic."""
        if self._path_filter:
            return self._path_filter(path, method, operation, user_context)
        return True
    
    def should_include_schema(self, schema_name: str, schema_def: Dict[str, Any], user_context: UserContext) -> bool:
        """Check if schema should be included using custom logic."""
        if self._schema_filter:
            return self._schema_filter(schema_name, schema_def, user_context)
        return True
    
    def filter_operation(self, operation: Dict[str, Any], user_context: UserContext) -> Dict[str, Any]:
        """Filter operation using custom logic."""
        if self._operation_filter:
            return self._operation_filter(operation, user_context)
        return operation


class DocumentationRenderer(ABC):
    """Abstract base class for documentation renderers."""
    
    @abstractmethod
    def render(self, openapi_spec: Dict[str, Any], theme: DocumentationTheme, 
              user_context: UserContext, version: Optional[DocumentationVersion] = None) -> Response:
        """Render documentation in the specified format."""
        pass


class SwaggerUIRenderer(DocumentationRenderer):
    """Swagger UI documentation renderer."""
    
    def render(self, openapi_spec: Dict[str, Any], theme: DocumentationTheme,
              user_context: UserContext, version: Optional[DocumentationVersion] = None) -> Response:
        """Render Swagger UI documentation."""
        swagger_config = {
            'deepLinking': True,
            'displayRequestDuration': True,
            'docExpansion': 'list',
            'filter': True,
            'showExtensions': True,
            'showCommonExtensions': True,
            'tryItOutEnabled': True,
            **theme.swagger_ui_config
        }
        
        # Generate HTML with theme
        html_content = self._generate_swagger_html(openapi_spec, theme, swagger_config)
        
        return HTMLResponse(content=html_content)
    
    def _generate_swagger_html(self, spec: Dict[str, Any], theme: DocumentationTheme, config: Dict[str, Any]) -> str:
        """Generate Swagger UI HTML."""
        spec_json = json.dumps(spec, indent=2)
        config_json = json.dumps(config, indent=2)
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{spec.get('info', {}).get('title', 'API Documentation')}</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@latest/swagger-ui.css" />
    {f'<link rel="icon" type="image/png" href="{theme.favicon_url}" />' if theme.favicon_url else ''}
    <style>
        :root {{
            --swagger-ui-primary: {theme.primary_color};
            --swagger-ui-secondary: {theme.secondary_color};
            --swagger-ui-background: {theme.background_color};
            --swagger-ui-text: {theme.text_color};
            --swagger-ui-accent: {theme.accent_color};
        }}
        
        body {{
            margin: 0;
            padding: 0;
            font-family: {theme.font_family};
            background-color: var(--swagger-ui-background);
            color: var(--swagger-ui-text);
        }}
        
        .swagger-ui .topbar {{
            background-color: var(--swagger-ui-primary);
        }}
        
        .swagger-ui .info hgroup.main a {{
            color: var(--swagger-ui-primary);
        }}
        
        .swagger-ui .btn.authorize {{
            background-color: var(--swagger-ui-accent);
            border-color: var(--swagger-ui-accent);
        }}
        
        .swagger-ui .btn.execute {{
            background-color: var(--swagger-ui-primary);
            border-color: var(--swagger-ui-primary);
        }}
        
        {theme.custom_css or ''}
    </style>
    {f'<script>{theme.custom_js}</script>' if theme.custom_js else ''}
</head>
<body>
    <div id="swagger-ui"></div>
    
    <script src="https://unpkg.com/swagger-ui-dist@latest/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@latest/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {{
            const ui = SwaggerUIBundle({{
                spec: {spec_json},
                dom_id: '#swagger-ui',
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout",
                ...{config_json}
            }});
            
            window.ui = ui;
        }};
    </script>
</body>
</html>
        """.strip()
        
        return html


class ReDocRenderer(DocumentationRenderer):
    """ReDoc documentation renderer."""
    
    def render(self, openapi_spec: Dict[str, Any], theme: DocumentationTheme,
              user_context: UserContext, version: Optional[DocumentationVersion] = None) -> Response:
        """Render ReDoc documentation."""
        redoc_config = {
            'scrollYOffset': 60,
            'hideDownloadButton': False,
            'disableSearch': False,
            'hideHostname': False,
            'expandResponses': '200,201',
            'pathInMiddlePanel': True,
            **theme.redoc_config
        }
        
        html_content = self._generate_redoc_html(openapi_spec, theme, redoc_config)
        
        return HTMLResponse(content=html_content)
    
    def _generate_redoc_html(self, spec: Dict[str, Any], theme: DocumentationTheme, config: Dict[str, Any]) -> str:
        """Generate ReDoc HTML."""
        spec_json = json.dumps(spec, indent=2)
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{spec.get('info', {}).get('title', 'API Documentation')}</title>
    {f'<link rel="icon" type="image/png" href="{theme.favicon_url}" />' if theme.favicon_url else ''}
    <style>
        body {{
            margin: 0;
            padding: 0;
            font-family: {theme.font_family};
        }}
        
        {theme.custom_css or ''}
    </style>
</head>
<body>
    <div id="redoc-container"></div>
    
    <script src="https://cdn.jsdelivr.net/npm/redoc@latest/bundles/redoc.standalone.js"></script>
    <script>
        Redoc.init({spec_json}, {{
            theme: {{
                colors: {{
                    primary: {{
                        main: '{theme.primary_color}'
                    }},
                    success: {{
                        main: '{theme.accent_color}'
                    }},
                    text: {{
                        primary: '{theme.text_color}'
                    }}
                }},
                typography: {{
                    fontFamily: '{theme.font_family}'
                }}
            }},
            ...{json.dumps(config, indent=2)}
        }}, document.getElementById('redoc-container'));
    </script>
    {f'<script>{theme.custom_js}</script>' if theme.custom_js else ''}
</body>
</html>
        """.strip()
        
        return html


class OpenAPIJSONRenderer(DocumentationRenderer):
    """OpenAPI JSON specification renderer."""
    
    def render(self, openapi_spec: Dict[str, Any], theme: DocumentationTheme,
              user_context: UserContext, version: Optional[DocumentationVersion] = None) -> Response:
        """Render OpenAPI JSON specification."""
        return JSONResponse(content=openapi_spec)


class OpenAPIYAMLRenderer(DocumentationRenderer):
    """OpenAPI YAML specification renderer."""
    
    def render(self, openapi_spec: Dict[str, Any], theme: DocumentationTheme,
              user_context: UserContext, version: Optional[DocumentationVersion] = None) -> Response:
        """Render OpenAPI YAML specification."""
        try:
            import yaml
            yaml_content = yaml.dump(openapi_spec, default_flow_style=False, sort_keys=False)
            return Response(content=yaml_content, media_type="application/x-yaml")
        except ImportError:
            # Fallback to JSON if PyYAML is not available
            return JSONResponse(content=openapi_spec)


class MarkdownRenderer(DocumentationRenderer):
    """Markdown documentation renderer."""
    
    def render(self, openapi_spec: Dict[str, Any], theme: DocumentationTheme,
              user_context: UserContext, version: Optional[DocumentationVersion] = None) -> Response:
        """Render Markdown documentation."""
        markdown_content = self._generate_markdown(openapi_spec, theme)
        return Response(content=markdown_content, media_type="text/markdown")
    
    def _generate_markdown(self, spec: Dict[str, Any], theme: DocumentationTheme) -> str:
        """Generate Markdown documentation from OpenAPI spec."""
        info = spec.get('info', {})
        paths = spec.get('paths', {})
        
        markdown_parts = []
        
        # Title and description
        title = info.get('title', 'API Documentation')
        markdown_parts.append(f"# {title}")
        
        if 'description' in info:
            markdown_parts.append(f"\n{info['description']}")
        
        if 'version' in info:
            markdown_parts.append(f"\n**Version:** {info['version']}")
        
        # Base information
        if 'servers' in spec:
            markdown_parts.append("\n## Servers")
            for server in spec['servers']:
                url = server.get('url', '')
                description = server.get('description', '')
                markdown_parts.append(f"- `{url}` - {description}")
        
        # Paths/Endpoints
        markdown_parts.append("\n## Endpoints")
        
        for path, methods in paths.items():
            markdown_parts.append(f"\n### {path}")
            
            for method, operation in methods.items():
                if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']:
                    summary = operation.get('summary', '')
                    description = operation.get('description', '')
                    
                    markdown_parts.append(f"\n#### {method.upper()}")
                    
                    if summary:
                        markdown_parts.append(f"\n**Summary:** {summary}")
                    
                    if description:
                        markdown_parts.append(f"\n**Description:** {description}")
                    
                    # Parameters
                    if 'parameters' in operation:
                        markdown_parts.append("\n**Parameters:**")
                        for param in operation['parameters']:
                            name = param.get('name', '')
                            in_location = param.get('in', '')
                            required = " (required)" if param.get('required', False) else ""
                            param_description = param.get('description', '')
                            markdown_parts.append(f"- `{name}` in {in_location}{required} - {param_description}")
                    
                    # Responses
                    if 'responses' in operation:
                        markdown_parts.append("\n**Responses:**")
                        for code, response in operation['responses'].items():
                            response_description = response.get('description', '')
                            markdown_parts.append(f"- `{code}` - {response_description}")
        
        return "\n".join(markdown_parts)


@dataclass
class APIDocumentationConfig:
    """Configuration for API documentation shield."""
    
    access_level: AccessLevel = AccessLevel.PUBLIC
    allowed_formats: Set[DocumentationFormat] = field(
        default_factory=lambda: {DocumentationFormat.SWAGGER_UI, DocumentationFormat.OPENAPI_JSON}
    )
    default_format: DocumentationFormat = DocumentationFormat.SWAGGER_UI
    default_theme: DocumentationTheme = field(default_factory=lambda: DocumentationTheme("default"))
    custom_themes: Dict[str, DocumentationTheme] = field(default_factory=dict)
    documentation_filters: List[DocumentationFilter] = field(default_factory=list)
    custom_renderers: Dict[DocumentationFormat, DocumentationRenderer] = field(default_factory=dict)
    versions: Dict[str, DocumentationVersion] = field(default_factory=dict)
    default_version: Optional[str] = None
    user_context_extractor: Optional[Callable[[Request], UserContext]] = None
    access_control_callback: Optional[Callable[[UserContext, DocumentationFormat], bool]] = None
    spec_modifications: Dict[str, Any] = field(default_factory=dict)
    enable_caching: bool = True
    cache_ttl_seconds: int = 300
    enable_analytics: bool = True
    rate_limit_per_minute: Optional[int] = None
    allowed_origins: Optional[List[str]] = None
    enable_cors: bool = True
    custom_headers: Dict[str, str] = field(default_factory=dict)
    
    def __post_init__(self):
        """Post-initialization setup."""
        # Ensure default renderers are available
        if not self.custom_renderers:
            self.custom_renderers = {}
        
        # Add default renderers if not provided
        default_renderers = {
            DocumentationFormat.SWAGGER_UI: SwaggerUIRenderer(),
            DocumentationFormat.REDOC: ReDocRenderer(),
            DocumentationFormat.OPENAPI_JSON: OpenAPIJSONRenderer(),
            DocumentationFormat.OPENAPI_YAML: OpenAPIYAMLRenderer(),
            DocumentationFormat.MARKDOWN: MarkdownRenderer(),
        }
        
        for format_type, renderer in default_renderers.items():
            if format_type not in self.custom_renderers:
                self.custom_renderers[format_type] = renderer


class DocumentationAnalytics:
    """Analytics tracking for documentation access."""
    
    def __init__(self):
        self.access_count = defaultdict(int)
        self.format_usage = defaultdict(int)
        self.user_access = defaultdict(int)
        self.endpoint_views = defaultdict(int)
        self.error_count = defaultdict(int)
        self.access_history = []
    
    def record_access(self, user_context: UserContext, format_type: DocumentationFormat,
                     endpoint: Optional[str] = None, success: bool = True):
        """Record documentation access event."""
        timestamp = datetime.now(timezone.utc)
        
        self.access_count['total'] += 1
        self.format_usage[format_type] += 1
        
        if user_context.user_id:
            self.user_access[user_context.user_id] += 1
        
        if endpoint:
            self.endpoint_views[endpoint] += 1
        
        if not success:
            self.error_count['total'] += 1
        
        # Keep limited history
        self.access_history.append({
            'timestamp': timestamp,
            'user_id': user_context.user_id,
            'format': format_type,
            'endpoint': endpoint,
            'success': success,
            'ip_address': user_context.ip_address,
            'user_agent': user_context.user_agent
        })
        
        # Keep only recent entries
        if len(self.access_history) > 1000:
            # Keep the last 500 entries
            from collections import deque
            self.access_history = deque(list(self.access_history)[-500:], maxlen=100)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get documentation access statistics."""
        return {
            'total_access_count': self.access_count['total'],
            'format_usage': dict(self.format_usage),
            'unique_users': len(self.user_access),
            'most_viewed_endpoints': dict(sorted(
                self.endpoint_views.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]),
            'error_count': self.error_count['total'],
            'recent_access_count': len([
                access for access in self.access_history
                if (datetime.now(timezone.utc) - access['timestamp']).total_seconds() < 3600
            ])
        }


class APIDocumentationShield(Shield):
    """API Documentation shield for controlling and personalizing API documentation access."""
    
    def __init__(self, config: APIDocumentationConfig, app=None):
        """
        Initialize the API documentation shield.
        
        Args:
            config: Configuration for documentation access control
            app: FastAPI application instance (for extracting OpenAPI spec)
        """
        self.config = config
        self.app = app
        self.analytics = DocumentationAnalytics()
        self._spec_cache: Dict[str, Tuple[Dict[str, Any], datetime]] = {}
        self._logger = logging.getLogger(__name__)
        
        super().__init__(self._shield_function)
    
    def _extract_user_context(self, request: Request) -> UserContext:
        """Extract user context from request."""
        if self.config.user_context_extractor:
            return self.config.user_context_extractor(request)
        
        # Default user context extraction
        client_host = getattr(request.client, "host", "unknown") if request.client else "unknown"
        user_agent = request.headers.get("User-Agent", "unknown")
        
        # Basic authentication detection
        auth_header = request.headers.get("Authorization")
        authenticated = bool(auth_header)
        
        return UserContext(
            ip_address=client_host,
            user_agent=user_agent,
            authenticated=authenticated
        )
    
    def _check_access(self, user_context: UserContext, format_type: DocumentationFormat) -> bool:
        """Check if user has access to documentation in specified format."""
        # Custom access control callback
        if self.config.access_control_callback:
            return self.config.access_control_callback(user_context, format_type)
        
        # Built-in access control
        if self.config.access_level == AccessLevel.PUBLIC:
            return True
        
        if self.config.access_level == AccessLevel.AUTHENTICATED:
            return user_context.authenticated
        
        if self.config.access_level == AccessLevel.ROLE_BASED:
            return bool(user_context.roles)
        
        if self.config.access_level == AccessLevel.PERMISSION_BASED:
            return bool(user_context.permissions)
        
        return False
    
    def _get_openapi_spec(self, version: Optional[str] = None) -> Dict[str, Any]:
        """Get OpenAPI specification, optionally for specific version."""
        cache_key = version or "default"
        
        # Check cache
        if self.config.enable_caching and cache_key in self._spec_cache:
            spec, cached_time = self._spec_cache[cache_key]
            if (datetime.now(timezone.utc) - cached_time).total_seconds() < self.config.cache_ttl_seconds:
                return spec
        
        # Generate or retrieve spec
        if self.app:
            spec = get_openapi(
                title=self.app.title,
                version=self.app.version,
                openapi_version=self.app.openapi_version,
                description=self.app.description,
                routes=self.app.routes,
            )
        else:
            # Fallback minimal spec
            spec = {
                "openapi": "3.0.2",
                "info": {
                    "title": "API Documentation",
                    "version": "1.0.0"
                },
                "paths": {}
            }
        
        # Apply version-specific modifications
        if version and version in self.config.versions:
            version_config = self.config.versions[version]
            
            # Update info
            if version_config.title:
                spec["info"]["title"] = version_config.title
            if version_config.description:
                spec["info"]["description"] = version_config.description
            
            spec["info"]["version"] = version_config.version
            
            # Apply spec modifications
            for path, modifications in version_config.spec_modifications.items():
                self._apply_modifications(spec, path, modifications)
        
        # Apply global spec modifications
        for path, modifications in self.config.spec_modifications.items():
            self._apply_modifications(spec, path, modifications)
        
        # Cache the spec
        if self.config.enable_caching:
            self._spec_cache[cache_key] = (spec, datetime.now(timezone.utc))
        
        return spec
    
    def _apply_modifications(self, spec: Dict[str, Any], path: str, modifications: Dict[str, Any]):
        """Apply modifications to OpenAPI spec at specified path."""
        # Simple dot-notation path traversal
        parts = path.split('.')
        current = spec
        
        for part in parts[:-1]:
            if part not in current:
                current[part] = {}
            current = current[part]
        
        # Apply modifications
        final_key = parts[-1]
        if isinstance(modifications, dict) and final_key in current and isinstance(current[final_key], dict):
            current[final_key].update(modifications)
        else:
            current[final_key] = modifications
    
    def _filter_spec(self, spec: Dict[str, Any], user_context: UserContext) -> Dict[str, Any]:
        """Filter OpenAPI spec based on user context and filters."""
        if not self.config.documentation_filters:
            return spec
        
        filtered_spec = deepcopy(spec)
        
        # Filter paths
        if 'paths' in filtered_spec:
            filtered_paths = {}
            
            for path, methods in filtered_spec['paths'].items():
                filtered_methods = {}
                
                for method, operation in methods.items():
                    if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']:
                        # Check if path should be included
                        should_include = True
                        for doc_filter in self.config.documentation_filters:
                            if not doc_filter.should_include_path(path, method, operation, user_context):
                                should_include = False
                                break
                        
                        if should_include:
                            # Filter operation details
                            filtered_operation = operation
                            for doc_filter in self.config.documentation_filters:
                                filtered_operation = doc_filter.filter_operation(filtered_operation, user_context)
                            
                            filtered_methods[method] = filtered_operation
                    else:
                        # Keep non-HTTP method entries (like parameters)
                        filtered_methods[method] = operation
                
                if filtered_methods:
                    filtered_paths[path] = filtered_methods
            
            filtered_spec['paths'] = filtered_paths
        
        # Filter schemas/components
        if 'components' in filtered_spec and 'schemas' in filtered_spec['components']:
            filtered_schemas = {}
            
            for schema_name, schema_def in filtered_spec['components']['schemas'].items():
                should_include = True
                for doc_filter in self.config.documentation_filters:
                    if not doc_filter.should_include_schema(schema_name, schema_def, user_context):
                        should_include = False
                        break
                
                if should_include:
                    filtered_schemas[schema_name] = schema_def
            
            filtered_spec['components']['schemas'] = filtered_schemas
        
        return filtered_spec
    
    def _get_theme(self, user_context: UserContext) -> DocumentationTheme:
        """Get theme based on user context."""
        # Check for user-specific theme preferences
        if hasattr(user_context, 'attributes') and 'preferred_theme' in user_context.attributes:
            theme_name = user_context.attributes['preferred_theme']
            if theme_name in self.config.custom_themes:
                return self.config.custom_themes[theme_name]
        
        # Check role-based themes
        for role in user_context.roles:
            if f"role_{role}" in self.config.custom_themes:
                return self.config.custom_themes[f"role_{role}"]
        
        return self.config.default_theme
    
    def _determine_format(self, request: Request) -> DocumentationFormat:
        """Determine desired documentation format from request."""
        # Check query parameter
        format_param = request.query_params.get('format', '').lower()
        format_mapping = {
            'json': DocumentationFormat.OPENAPI_JSON,
            'yaml': DocumentationFormat.OPENAPI_YAML,
            'yml': DocumentationFormat.OPENAPI_YAML,
            'swagger': DocumentationFormat.SWAGGER_UI,
            'redoc': DocumentationFormat.REDOC,
            'markdown': DocumentationFormat.MARKDOWN,
            'md': DocumentationFormat.MARKDOWN,
        }
        
        if format_param in format_mapping:
            return format_mapping[format_param]
        
        # Check Accept header
        accept_header = request.headers.get('accept', '').lower()
        if 'application/json' in accept_header and 'text/html' not in accept_header:
            return DocumentationFormat.OPENAPI_JSON
        elif 'application/x-yaml' in accept_header or 'text/yaml' in accept_header:
            return DocumentationFormat.OPENAPI_YAML
        elif 'text/markdown' in accept_header:
            return DocumentationFormat.MARKDOWN
        
        # Check path-based format
        path = request.url.path
        if path.endswith('.json'):
            return DocumentationFormat.OPENAPI_JSON
        elif path.endswith('.yaml') or path.endswith('.yml'):
            return DocumentationFormat.OPENAPI_YAML
        elif path.endswith('.md'):
            return DocumentationFormat.MARKDOWN
        elif 'redoc' in path:
            return DocumentationFormat.REDOC
        
        return self.config.default_format
    
    def _apply_cors_headers(self, response: Response):
        """Apply CORS headers to response."""
        if self.config.enable_cors:
            allowed_origins = self.config.allowed_origins or ["*"]
            response.headers["Access-Control-Allow-Origin"] = ", ".join(allowed_origins)
            response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    
    async def _shield_function(self, request: Request) -> Optional[Response]:
        """Main shield function for documentation access control."""
        try:
            # Extract user context
            user_context = self._extract_user_context(request)
            
            # Determine requested format
            format_type = self._determine_format(request)
            
            # Check if format is allowed
            if format_type not in self.config.allowed_formats:
                self.analytics.record_access(user_context, format_type, success=False)
                raise HTTPException(
                    status_code=status.HTTP_406_NOT_ACCEPTABLE,
                    detail=f"Documentation format '{format_type}' is not allowed"
                )
            
            # Check access permissions
            if not self._check_access(user_context, format_type):
                self.analytics.record_access(user_context, format_type, success=False)
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access to documentation is forbidden"
                )
            
            # Rate limiting check
            if self.config.rate_limit_per_minute:
                # Simple rate limiting based on IP
                # In production, you'd want a more sophisticated implementation
                pass
            
            # Get requested version
            version = request.query_params.get('version')
            if version and version not in self.config.versions and version != self.config.default_version:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Documentation version '{version}' not found"
                )
            
            # Get OpenAPI specification
            spec = self._get_openapi_spec(version)
            
            # Filter specification based on user context
            filtered_spec = self._filter_spec(spec, user_context)
            
            # Get theme
            theme = self._get_theme(user_context)
            
            # Get version config
            version_config = None
            if version and version in self.config.versions:
                version_config = self.config.versions[version]
            
            # Render documentation
            if format_type in self.config.custom_renderers:
                renderer = self.config.custom_renderers[format_type]
                response = renderer.render(filtered_spec, theme, user_context, version_config)
            else:
                # Fallback to JSON
                response = JSONResponse(content=filtered_spec)
            
            # Apply custom headers
            for header, value in self.config.custom_headers.items():
                response.headers[header] = value
            
            # Apply CORS headers
            self._apply_cors_headers(response)
            
            # Record analytics
            if self.config.enable_analytics:
                endpoint = request.url.path
                self.analytics.record_access(user_context, format_type, endpoint, success=True)
            
            return response
            
        except HTTPException:
            raise
        except Exception as e:
            self._logger.error(f"Error generating documentation: {e}")
            if self.config.enable_analytics:
                self.analytics.record_access(user_context, format_type, success=False)
            
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error generating documentation"
            )
    
    def get_analytics(self) -> Dict[str, Any]:
        """Get documentation access analytics."""
        return self.analytics.get_statistics()
    
    def clear_cache(self):
        """Clear the OpenAPI spec cache."""
        self._spec_cache.clear()
    
    def add_theme(self, name: str, theme: DocumentationTheme):
        """Add a custom theme."""
        self.config.custom_themes[name] = theme
    
    def add_version(self, name: str, version: DocumentationVersion):
        """Add a documentation version."""
        self.config.versions[name] = version
    
    def add_filter(self, doc_filter: DocumentationFilter):
        """Add a documentation filter."""
        self.config.documentation_filters.append(doc_filter)


# Convenience functions for creating documentation shields

def public_documentation_shield(
    app=None,
    allowed_formats: Optional[Set[DocumentationFormat]] = None,
    default_format: DocumentationFormat = DocumentationFormat.SWAGGER_UI,
    theme: Optional[DocumentationTheme] = None
) -> APIDocumentationShield:
    """Create a public API documentation shield.
    
    Args:
        app: FastAPI application instance
        allowed_formats: Allowed documentation formats
        default_format: Default documentation format
        theme: Custom theme for documentation
    
    Returns:
        APIDocumentationShield instance
    """
    config = APIDocumentationConfig(
        access_level=AccessLevel.PUBLIC,
        allowed_formats=allowed_formats or {DocumentationFormat.SWAGGER_UI, DocumentationFormat.OPENAPI_JSON},
        default_format=default_format,
        default_theme=theme or DocumentationTheme("public")
    )
    
    return APIDocumentationShield(config, app)


def role_based_documentation_shield(
    app=None,
    role_mappings: Optional[Dict[str, Dict[str, Any]]] = None,
    allowed_formats: Optional[Set[DocumentationFormat]] = None,
    user_context_extractor: Optional[Callable[[Request], UserContext]] = None
) -> APIDocumentationShield:
    """Create a role-based API documentation shield.
    
    Args:
        app: FastAPI application instance
        role_mappings: Role-to-access mappings
        allowed_formats: Allowed documentation formats
        user_context_extractor: Function to extract user context from request
    
    Returns:
        APIDocumentationShield instance
    """
    filters = []
    if role_mappings:
        filters.append(RoleBasedDocumentationFilter(role_mappings))
    
    config = APIDocumentationConfig(
        access_level=AccessLevel.ROLE_BASED,
        allowed_formats=allowed_formats or {DocumentationFormat.SWAGGER_UI, DocumentationFormat.OPENAPI_JSON},
        documentation_filters=filters,
        user_context_extractor=user_context_extractor
    )
    
    return APIDocumentationShield(config, app)


def permission_based_documentation_shield(
    app=None,
    permission_mappings: Optional[Dict[str, Dict[str, Any]]] = None,
    allowed_formats: Optional[Set[DocumentationFormat]] = None,
    user_context_extractor: Optional[Callable[[Request], UserContext]] = None
) -> APIDocumentationShield:
    """Create a permission-based API documentation shield.
    
    Args:
        app: FastAPI application instance
        permission_mappings: Permission-to-access mappings
        allowed_formats: Allowed documentation formats
        user_context_extractor: Function to extract user context from request
    
    Returns:
        APIDocumentationShield instance
    """
    filters = []
    if permission_mappings:
        filters.append(PermissionBasedDocumentationFilter(permission_mappings))
    
    config = APIDocumentationConfig(
        access_level=AccessLevel.PERMISSION_BASED,
        allowed_formats=allowed_formats or {DocumentationFormat.SWAGGER_UI, DocumentationFormat.OPENAPI_JSON},
        documentation_filters=filters,
        user_context_extractor=user_context_extractor
    )
    
    return APIDocumentationShield(config, app)


def tag_based_documentation_shield(
    app=None,
    allowed_tags: Optional[Dict[str, Set[str]]] = None,
    user_context_extractor: Optional[Callable[[Request], UserContext]] = None
) -> APIDocumentationShield:
    """Create a tag-based API documentation shield.
    
    Args:
        app: FastAPI application instance
        allowed_tags: Allowed tags per role/permission
        user_context_extractor: Function to extract user context from request
    
    Returns:
        APIDocumentationShield instance
    """
    filters = []
    if allowed_tags:
        filters.append(TagBasedDocumentationFilter(allowed_tags))
    
    config = APIDocumentationConfig(
        access_level=AccessLevel.ROLE_BASED,
        documentation_filters=filters,
        user_context_extractor=user_context_extractor
    )
    
    return APIDocumentationShield(config, app)


def versioned_documentation_shield(
    app=None,
    versions: Optional[Dict[str, DocumentationVersion]] = None,
    default_version: Optional[str] = None,
    access_level: AccessLevel = AccessLevel.PUBLIC
) -> APIDocumentationShield:
    """Create a versioned API documentation shield.
    
    Args:
        app: FastAPI application instance
        versions: Available documentation versions
        default_version: Default version to serve
        access_level: Access control level
    
    Returns:
        APIDocumentationShield instance
    """
    config = APIDocumentationConfig(
        access_level=access_level,
        versions=versions or {},
        default_version=default_version
    )
    
    return APIDocumentationShield(config, app)


def themed_documentation_shield(
    app=None,
    themes: Optional[Dict[str, DocumentationTheme]] = None,
    default_theme: Optional[DocumentationTheme] = None,
    access_level: AccessLevel = AccessLevel.PUBLIC
) -> APIDocumentationShield:
    """Create a themed API documentation shield.
    
    Args:
        app: FastAPI application instance
        themes: Available custom themes
        default_theme: Default theme to use
        access_level: Access control level
    
    Returns:
        APIDocumentationShield instance
    """
    config = APIDocumentationConfig(
        access_level=access_level,
        custom_themes=themes or {},
        default_theme=default_theme or DocumentationTheme("themed")
    )
    
    return APIDocumentationShield(config, app)


def comprehensive_documentation_shield(
    app=None,
    access_level: AccessLevel = AccessLevel.ROLE_BASED,
    role_mappings: Optional[Dict[str, Dict[str, Any]]] = None,
    permission_mappings: Optional[Dict[str, Dict[str, Any]]] = None,
    allowed_tags: Optional[Dict[str, Set[str]]] = None,
    versions: Optional[Dict[str, DocumentationVersion]] = None,
    themes: Optional[Dict[str, DocumentationTheme]] = None,
    allowed_formats: Optional[Set[DocumentationFormat]] = None,
    user_context_extractor: Optional[Callable[[Request], UserContext]] = None,
    enable_analytics: bool = True,
    enable_caching: bool = True,
    rate_limit_per_minute: Optional[int] = None
) -> APIDocumentationShield:
    """Create a comprehensive API documentation shield with all features.
    
    Args:
        app: FastAPI application instance
        access_level: Access control level
        role_mappings: Role-to-access mappings
        permission_mappings: Permission-to-access mappings
        allowed_tags: Allowed tags per role/permission
        versions: Available documentation versions
        themes: Available custom themes
        allowed_formats: Allowed documentation formats
        user_context_extractor: Function to extract user context
        enable_analytics: Enable access analytics
        enable_caching: Enable specification caching
        rate_limit_per_minute: Rate limit per minute per IP
    
    Returns:
        APIDocumentationShield instance
    """
    filters = []
    
    if role_mappings:
        filters.append(RoleBasedDocumentationFilter(role_mappings))
    
    if permission_mappings:
        filters.append(PermissionBasedDocumentationFilter(permission_mappings))
    
    if allowed_tags:
        filters.append(TagBasedDocumentationFilter(allowed_tags))
    
    config = APIDocumentationConfig(
        access_level=access_level,
        allowed_formats=allowed_formats or {
            DocumentationFormat.SWAGGER_UI,
            DocumentationFormat.REDOC,
            DocumentationFormat.OPENAPI_JSON,
            DocumentationFormat.OPENAPI_YAML
        },
        documentation_filters=filters,
        versions=versions or {},
        custom_themes=themes or {},
        user_context_extractor=user_context_extractor,
        enable_analytics=enable_analytics,
        enable_caching=enable_caching,
        rate_limit_per_minute=rate_limit_per_minute
    )
    
    return APIDocumentationShield(config, app)