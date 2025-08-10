"""JSON Schema validation shield for FastAPI Shield.

This module provides comprehensive JSON Schema validation capabilities beyond
Pydantic validation, supporting JSON Schema Draft 7 and 2019-09 specifications.
It includes custom validation keywords, detailed error reporting with JSON pointers,
schema registry integration, and performance optimizations.
"""

import asyncio
import json
import re
import time
from abc import ABC, abstractmethod
from collections import defaultdict
from datetime import datetime, date
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, Callable, Set, Pattern
from urllib.parse import urlparse, urljoin
from dataclasses import dataclass, field

from fastapi import HTTPException, Request, Response, status

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    httpx = None
    HTTPX_AVAILABLE = False

try:
    import jsonschema
    from jsonschema import Draft7Validator, Draft201909Validator, validators
    from jsonschema.exceptions import ValidationError, SchemaError
    JSONSCHEMA_AVAILABLE = True
except ImportError:
    jsonschema = None
    Draft7Validator = None
    Draft201909Validator = None
    validators = None
    ValidationError = None
    SchemaError = None
    JSONSCHEMA_AVAILABLE = False

from fastapi_shield.shield import Shield


class JSONSchemaDraft(str, Enum):
    """Supported JSON Schema draft versions."""
    DRAFT_7 = "draft7"
    DRAFT_2019_09 = "draft2019-09"


class ValidationErrorSeverity(str, Enum):
    """Validation error severity levels."""
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass
class ValidationErrorDetail:
    """Detailed validation error information."""
    message: str
    path: str  # JSON pointer path
    schema_path: str  # Schema path
    instance: Any
    validator: str
    validator_value: Any
    severity: ValidationErrorSeverity = ValidationErrorSeverity.ERROR
    custom_message: Optional[str] = None
    error_code: Optional[str] = None


@dataclass
class ValidationResult:
    """JSON schema validation result."""
    valid: bool
    errors: List[ValidationErrorDetail] = field(default_factory=list)
    warnings: List[ValidationErrorDetail] = field(default_factory=list)
    validation_time_ms: float = 0.0
    schema_id: Optional[str] = None


class SchemaFormat:
    """Custom format validators for JSON Schema."""
    
    @staticmethod
    def validate_email(instance: str) -> bool:
        """Validate email format."""
        if not isinstance(instance, str):
            return False
        # More restrictive email pattern that rejects consecutive dots
        pattern = r'^[a-zA-Z0-9!#$%&\'*+/=?^_`{|}~-]+(?:\.[a-zA-Z0-9!#$%&\'*+/=?^_`{|}~-]+)*@(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$'
        return bool(re.match(pattern, instance))
    
    @staticmethod
    def validate_uri(instance: str) -> bool:
        """Validate URI format."""
        if not isinstance(instance, str):
            return False
        try:
            result = urlparse(instance)
            # Allow scheme without netloc for some URI schemes like mailto
            return bool(result.scheme and (result.netloc or result.path))
        except Exception:
            return False
    
    @staticmethod
    def validate_datetime(instance: str) -> bool:
        """Validate ISO 8601 datetime format."""
        if not isinstance(instance, str):
            return False
        try:
            # Must have time component for datetime
            if 'T' not in instance:
                return False
            datetime.fromisoformat(instance.replace('Z', '+00:00'))
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_date(instance: str) -> bool:
        """Validate ISO 8601 date format."""
        if not isinstance(instance, str):
            return False
        try:
            date.fromisoformat(instance)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_time(instance: str) -> bool:
        """Validate ISO 8601 time format."""
        if not isinstance(instance, str):
            return False
        try:
            datetime.strptime(instance, '%H:%M:%S')
            return True
        except ValueError:
            try:
                datetime.strptime(instance, '%H:%M:%S.%f')
                return True
            except ValueError:
                return False
    
    @staticmethod
    def validate_ipv4(instance: str) -> bool:
        """Validate IPv4 address format."""
        if not isinstance(instance, str):
            return False
        try:
            parts = instance.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                if not (0 <= int(part) <= 255):
                    return False
            return True
        except (ValueError, AttributeError):
            return False
    
    @staticmethod
    def validate_ipv6(instance: str) -> bool:
        """Validate IPv6 address format."""
        if not isinstance(instance, str):
            return False
        try:
            import ipaddress
            ipaddress.IPv6Address(instance)
            return True
        except (ValueError, ImportError):
            return False
    
    @staticmethod
    def validate_uuid(instance: str) -> bool:
        """Validate UUID format."""
        if not isinstance(instance, str):
            return False
        try:
            import uuid
            uuid.UUID(instance)
            return True
        except (ValueError, ImportError):
            return False
    
    @staticmethod
    def validate_regex(instance: str) -> bool:
        """Validate regex pattern format."""
        if not isinstance(instance, str):
            return False
        try:
            re.compile(instance)
            return True
        except re.error:
            return False


class CustomKeyword:
    """Custom JSON Schema keyword implementation."""
    
    def __init__(self, name: str, validator: Callable[[Any, Any, Any, Any], None]):
        self.name = name
        self.validator = validator


class SchemaRegistry:
    """Registry for JSON schemas with remote loading support."""
    
    def __init__(self, base_url: Optional[str] = None, timeout: int = 10):
        self.schemas: Dict[str, Dict[str, Any]] = {}
        self.base_url = base_url
        self.timeout = timeout
        self._client = httpx.AsyncClient(timeout=timeout) if HTTPX_AVAILABLE else None
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._loading_cache: Dict[str, Any] = {}  # Prevent circular loading
    
    def register_schema(self, schema_id: str, schema: Dict[str, Any]) -> None:
        """Register a schema in the registry."""
        self.schemas[schema_id] = schema
        self._cache[schema_id] = schema
    
    def get_schema(self, schema_id: str) -> Optional[Dict[str, Any]]:
        """Get a schema from the registry."""
        if schema_id in self._cache:
            return self._cache[schema_id]
        
        if schema_id in self.schemas:
            schema = self.schemas[schema_id]
            self._cache[schema_id] = schema
            return schema
        
        return None
    
    async def load_schema(self, schema_id: str) -> Optional[Dict[str, Any]]:
        """Load a schema from remote URL or local registry."""
        if schema_id in self._cache:
            return self._cache[schema_id]
        
        if schema_id in self._loading_cache:
            return self._loading_cache[schema_id]
        
        # Try local registry first
        if schema_id in self.schemas:
            schema = self.schemas[schema_id]
            self._cache[schema_id] = schema
            return schema
        
        # Try loading from URL
        if self._is_url(schema_id) and self._client:
            try:
                self._loading_cache[schema_id] = None  # Mark as loading
                response = await self._client.get(schema_id)
                response.raise_for_status()
                
                schema = response.json()
                self._cache[schema_id] = schema
                del self._loading_cache[schema_id]  # Remove loading marker
                return schema
            except Exception:
                if schema_id in self._loading_cache:
                    del self._loading_cache[schema_id]
                return None
        
        # Try relative URL resolution
        if self.base_url and not self._is_url(schema_id):
            full_url = urljoin(self.base_url, schema_id)
            return await self.load_schema(full_url)
        
        return None
    
    def _is_url(self, uri: str) -> bool:
        """Check if string is a valid URL."""
        try:
            result = urlparse(uri)
            return result.scheme in ('http', 'https')
        except Exception:
            return False
    
    def clear_cache(self) -> None:
        """Clear the schema cache."""
        self._cache.clear()
        self._loading_cache.clear()


class ErrorMessageFormatter:
    """Custom error message formatter for validation errors."""
    
    def __init__(self):
        self.custom_messages: Dict[str, str] = {}
        self.path_templates: Dict[str, str] = {}
    
    def add_custom_message(self, validator: str, message_template: str) -> None:
        """Add custom message template for validator."""
        self.custom_messages[validator] = message_template
    
    def add_path_template(self, path_pattern: str, message_template: str) -> None:
        """Add message template for specific JSON path patterns."""
        self.path_templates[path_pattern] = message_template
    
    def format_error(self, error: ValidationError, custom_data: Optional[Dict[str, Any]] = None) -> str:
        """Format validation error with custom message."""
        validator = error.validator
        path = self._format_json_pointer(error.absolute_path)
        
        # Check for path-specific templates first
        for pattern, template in self.path_templates.items():
            if self._matches_path_pattern(path, pattern):
                return self._render_template(template, error, custom_data)
        
        # Check for validator-specific templates
        if validator in self.custom_messages:
            template = self.custom_messages[validator]
            return self._render_template(template, error, custom_data)
        
        # Use default error message
        return error.message
    
    def _format_json_pointer(self, path: List[Union[str, int]]) -> str:
        """Format path as JSON pointer."""
        if not path:
            return "/"
        
        pointer_parts = []
        for part in path:
            if isinstance(part, int):
                pointer_parts.append(str(part))
            else:
                # Escape special characters for JSON pointer
                escaped = str(part).replace("~", "~0").replace("/", "~1")
                pointer_parts.append(escaped)
        
        return "/" + "/".join(pointer_parts)
    
    def _matches_path_pattern(self, path: str, pattern: str) -> bool:
        """Check if path matches pattern (simple glob-like matching)."""
        # Convert glob pattern to regex
        regex_pattern = pattern.replace("*", "[^/]*").replace("**", ".*")
        regex_pattern = f"^{regex_pattern}$"
        
        try:
            return bool(re.match(regex_pattern, path))
        except re.error:
            return False
    
    def _render_template(self, template: str, error: ValidationError, custom_data: Optional[Dict[str, Any]] = None) -> str:
        """Render message template with error data."""
        context = {
            'validator': error.validator,
            'validator_value': error.validator_value,
            'instance': error.instance,
            'path': self._format_json_pointer(error.absolute_path),
            'schema_path': self._format_json_pointer(error.schema_path),
            'message': error.message
        }
        
        if custom_data:
            context.update(custom_data)
        
        try:
            return template.format(**context)
        except (KeyError, ValueError):
            return error.message


class JSONSchemaValidator:
    """Advanced JSON Schema validator with custom features."""
    
    def __init__(
        self,
        schema: Dict[str, Any],
        draft: JSONSchemaDraft = JSONSchemaDraft.DRAFT_7,
        schema_registry: Optional[SchemaRegistry] = None,
        error_formatter: Optional[ErrorMessageFormatter] = None,
        custom_formats: Optional[Dict[str, Callable[[str], bool]]] = None,
        custom_keywords: Optional[List[CustomKeyword]] = None,
        strict_mode: bool = True,
        collect_warnings: bool = False
    ):
        if not JSONSCHEMA_AVAILABLE:
            raise ImportError("jsonschema library is required for JSON Schema validation")
        
        self.schema = schema
        self.draft = draft
        self.schema_registry = schema_registry or SchemaRegistry()
        self.error_formatter = error_formatter or ErrorMessageFormatter()
        self.strict_mode = strict_mode
        self.collect_warnings = collect_warnings
        
        # Set up custom formats
        self.custom_formats = custom_formats or {}
        self._setup_default_formats()
        
        # Set up custom keywords
        self.custom_keywords = custom_keywords or []
        
        # Create validator instance
        self._validator = self._create_validator()
    
    def _setup_default_formats(self) -> None:
        """Set up default format validators."""
        default_formats = {
            'email': SchemaFormat.validate_email,
            'uri': SchemaFormat.validate_uri,
            'datetime': SchemaFormat.validate_datetime,
            'date': SchemaFormat.validate_date,
            'time': SchemaFormat.validate_time,
            'ipv4': SchemaFormat.validate_ipv4,
            'ipv6': SchemaFormat.validate_ipv6,
            'uuid': SchemaFormat.validate_uuid,
            'regex': SchemaFormat.validate_regex,
        }
        
        # Merge with custom formats, custom formats take precedence
        for name, validator in default_formats.items():
            if name not in self.custom_formats:
                self.custom_formats[name] = validator
    
    def _create_validator(self) -> Any:
        """Create jsonschema validator instance with custom features."""
        # Choose validator class based on draft
        if self.draft == JSONSchemaDraft.DRAFT_2019_09:
            validator_class = Draft201909Validator
        else:
            validator_class = Draft7Validator
        
        # Create format checker with custom formats
        format_checker = jsonschema.FormatChecker()
        
        for format_name, format_validator in self.custom_formats.items():
            format_checker.checks(format_name)(format_validator)
        
        # Set up schema resolver for registry
        resolver = None
        if self.schema_registry and self.schema_registry.schemas:
            store = {}
            for schema_id, schema_content in self.schema_registry.schemas.items():
                store[schema_id] = schema_content
            
            resolver = jsonschema.RefResolver.from_schema(
                self.schema,
                store=store
            )
        
        # Create extended validator class with custom keywords
        extended_validator = validator_class
        
        if self.custom_keywords:
            all_validators = dict(validator_class.META_SCHEMA.get('properties', {}).get('properties', {}).keys())
            
            for custom_keyword in self.custom_keywords:
                def make_keyword_validator(keyword):
                    def keyword_validator(validator, value, instance, schema):
                        yield from keyword.validator(validator, value, instance, schema)
                    return keyword_validator
                
                all_validators[custom_keyword.name] = make_keyword_validator(custom_keyword)
            
            extended_validator = validators.create(
                meta_schema=validator_class.META_SCHEMA,
                validators=all_validators
            )
        
        # Create validator instance
        return extended_validator(
            self.schema,
            resolver=resolver,
            format_checker=format_checker
        )
    
    def validate(self, instance: Any, context: Optional[Dict[str, Any]] = None) -> ValidationResult:
        """Validate instance against schema."""
        start_time = time.time()
        
        try:
            errors = []
            warnings = []
            
            # Perform validation
            validation_errors = list(self._validator.iter_errors(instance))
            
            for error in validation_errors:
                error_detail = self._create_error_detail(error, context)
                
                if self.collect_warnings and self._is_warning(error):
                    error_detail.severity = ValidationErrorSeverity.WARNING
                    warnings.append(error_detail)
                else:
                    errors.append(error_detail)
            
            validation_time = (time.time() - start_time) * 1000
            
            return ValidationResult(
                valid=len(errors) == 0,
                errors=errors,
                warnings=warnings,
                validation_time_ms=validation_time,
                schema_id=self.schema.get('$id')
            )
            
        except SchemaError as e:
            # Schema itself is invalid
            validation_time = (time.time() - start_time) * 1000
            
            return ValidationResult(
                valid=False,
                errors=[ValidationErrorDetail(
                    message=f"Invalid schema: {str(e)}",
                    path="",
                    schema_path="",
                    instance=instance,
                    validator="schema",
                    validator_value=None,
                    severity=ValidationErrorSeverity.ERROR,
                    error_code="INVALID_SCHEMA"
                )],
                validation_time_ms=validation_time
            )
        
        except Exception as e:
            # Unexpected validation error
            validation_time = (time.time() - start_time) * 1000
            
            return ValidationResult(
                valid=False,
                errors=[ValidationErrorDetail(
                    message=f"Validation error: {str(e)}",
                    path="",
                    schema_path="",
                    instance=instance,
                    validator="unknown",
                    validator_value=None,
                    severity=ValidationErrorSeverity.ERROR,
                    error_code="VALIDATION_ERROR"
                )],
                validation_time_ms=validation_time
            )
    
    def _create_error_detail(self, error: ValidationError, context: Optional[Dict[str, Any]]) -> ValidationErrorDetail:
        """Create detailed error information from validation error."""
        path = self.error_formatter._format_json_pointer(error.absolute_path)
        schema_path = self.error_formatter._format_json_pointer(error.schema_path)
        
        custom_message = self.error_formatter.format_error(error, context)
        
        return ValidationErrorDetail(
            message=error.message,
            path=path,
            schema_path=schema_path,
            instance=error.instance,
            validator=error.validator,
            validator_value=error.validator_value,
            custom_message=custom_message if custom_message != error.message else None,
            error_code=self._get_error_code(error)
        )
    
    def _is_warning(self, error: ValidationError) -> bool:
        """Determine if validation error should be treated as warning."""
        # Define warning conditions
        warning_validators = {'deprecated', 'examples', 'title', 'description'}
        return error.validator in warning_validators
    
    def _get_error_code(self, error: ValidationError) -> str:
        """Get error code for validation error."""
        validator_codes = {
            'type': 'TYPE_MISMATCH',
            'required': 'REQUIRED_PROPERTY',
            'minimum': 'VALUE_TOO_SMALL',
            'maximum': 'VALUE_TOO_LARGE',
            'minLength': 'STRING_TOO_SHORT',
            'maxLength': 'STRING_TOO_LONG',
            'pattern': 'PATTERN_MISMATCH',
            'format': 'FORMAT_INVALID',
            'enum': 'ENUM_MISMATCH',
            'const': 'CONST_MISMATCH',
            'uniqueItems': 'DUPLICATE_ITEMS',
            'minItems': 'ARRAY_TOO_SHORT',
            'maxItems': 'ARRAY_TOO_LONG',
            'minProperties': 'TOO_FEW_PROPERTIES',
            'maxProperties': 'TOO_MANY_PROPERTIES',
            'additionalProperties': 'ADDITIONAL_PROPERTY',
            'additionalItems': 'ADDITIONAL_ITEM',
        }
        
        return validator_codes.get(error.validator, 'VALIDATION_ERROR')


class ValidationCache:
    """Cache for validation results to improve performance."""
    
    def __init__(self, max_size: int = 1000, ttl_seconds: int = 3600):
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._timestamps: Dict[str, float] = {}
    
    def _generate_key(self, schema_hash: str, instance: Any) -> str:
        """Generate cache key for schema and instance."""
        instance_str = json.dumps(instance, sort_keys=True, default=str)
        instance_hash = str(hash(instance_str))
        return f"{schema_hash}:{instance_hash}"
    
    def get(self, schema_hash: str, instance: Any) -> Optional[ValidationResult]:
        """Get cached validation result."""
        key = self._generate_key(schema_hash, instance)
        
        if key not in self._cache:
            return None
        
        # Check TTL
        if time.time() - self._timestamps[key] > self.ttl_seconds:
            del self._cache[key]
            del self._timestamps[key]
            return None
        
        cached_data = self._cache[key]
        
        # Reconstruct ValidationResult
        return ValidationResult(
            valid=cached_data['valid'],
            errors=[
                ValidationErrorDetail(**error_data) 
                for error_data in cached_data['errors']
            ],
            warnings=[
                ValidationErrorDetail(**warning_data)
                for warning_data in cached_data['warnings']
            ],
            validation_time_ms=cached_data['validation_time_ms'],
            schema_id=cached_data['schema_id']
        )
    
    def set(self, schema_hash: str, instance: Any, result: ValidationResult) -> None:
        """Cache validation result."""
        key = self._generate_key(schema_hash, instance)
        
        # Clean cache if at max size
        if len(self._cache) >= self.max_size:
            self._evict_oldest()
        
        # Serialize ValidationResult
        cached_data = {
            'valid': result.valid,
            'errors': [
                {
                    'message': error.message,
                    'path': error.path,
                    'schema_path': error.schema_path,
                    'instance': error.instance,
                    'validator': error.validator,
                    'validator_value': error.validator_value,
                    'severity': error.severity,
                    'custom_message': error.custom_message,
                    'error_code': error.error_code
                }
                for error in result.errors
            ],
            'warnings': [
                {
                    'message': warning.message,
                    'path': warning.path,
                    'schema_path': warning.schema_path,
                    'instance': warning.instance,
                    'validator': warning.validator,
                    'validator_value': warning.validator_value,
                    'severity': warning.severity,
                    'custom_message': warning.custom_message,
                    'error_code': warning.error_code
                }
                for warning in result.warnings
            ],
            'validation_time_ms': result.validation_time_ms,
            'schema_id': result.schema_id
        }
        
        self._cache[key] = cached_data
        self._timestamps[key] = time.time()
    
    def _evict_oldest(self) -> None:
        """Evict oldest entry from cache."""
        if not self._timestamps:
            return
        
        oldest_key = min(self._timestamps.keys(), key=lambda k: self._timestamps[k])
        del self._cache[oldest_key]
        del self._timestamps[oldest_key]
    
    def clear(self) -> None:
        """Clear the cache."""
        self._cache.clear()
        self._timestamps.clear()


class JSONSchemaValidationConfig:
    """Configuration for JSON schema validation shield."""
    
    def __init__(
        self,
        schema: Optional[Dict[str, Any]] = None,
        schema_file: Optional[str] = None,
        schema_url: Optional[str] = None,
        schema_registry: Optional[SchemaRegistry] = None,
        draft: JSONSchemaDraft = JSONSchemaDraft.DRAFT_7,
        validate_request_body: bool = True,
        validate_query_params: bool = False,
        validate_path_params: bool = False,
        validate_headers: bool = False,
        strict_mode: bool = True,
        collect_warnings: bool = False,
        custom_formats: Optional[Dict[str, Callable[[str], bool]]] = None,
        custom_keywords: Optional[List[CustomKeyword]] = None,
        error_formatter: Optional[ErrorMessageFormatter] = None,
        enable_caching: bool = True,
        cache_size: int = 1000,
        cache_ttl_seconds: int = 3600,
        validation_timeout_seconds: float = 5.0,
        on_validation_error: Optional[Callable[[ValidationResult, Request], None]] = None,
        include_warnings_in_response: bool = False,
        custom_error_responses: Optional[Dict[str, Dict[str, Any]]] = None
    ):
        self.schema = schema
        self.schema_file = schema_file
        self.schema_url = schema_url
        self.schema_registry = schema_registry or SchemaRegistry()
        self.draft = draft
        self.validate_request_body = validate_request_body
        self.validate_query_params = validate_query_params
        self.validate_path_params = validate_path_params
        self.validate_headers = validate_headers
        self.strict_mode = strict_mode
        self.collect_warnings = collect_warnings
        self.custom_formats = custom_formats or {}
        self.custom_keywords = custom_keywords or []
        self.error_formatter = error_formatter or ErrorMessageFormatter()
        self.enable_caching = enable_caching
        self.cache_size = cache_size
        self.cache_ttl_seconds = cache_ttl_seconds
        self.validation_timeout_seconds = validation_timeout_seconds
        self.on_validation_error = on_validation_error
        self.include_warnings_in_response = include_warnings_in_response
        self.custom_error_responses = custom_error_responses or {}


class JSONSchemaValidationShield(Shield):
    """JSON Schema validation shield for comprehensive data validation."""
    
    def __init__(self, config: JSONSchemaValidationConfig):
        if not JSONSCHEMA_AVAILABLE:
            raise ImportError(
                "jsonschema library is required. Install with: pip install jsonschema"
            )
        
        self.config = config
        self.schema: Optional[Dict[str, Any]] = None
        self.validator: Optional[JSONSchemaValidator] = None
        self.cache: Optional[ValidationCache] = None
        
        # Initialize cache if enabled
        if config.enable_caching:
            self.cache = ValidationCache(
                max_size=config.cache_size,
                ttl_seconds=config.cache_ttl_seconds
            )
        
        super().__init__(self._shield_function)
    
    async def _initialize_schema(self) -> None:
        """Initialize schema from various sources."""
        if self.schema is not None:
            return  # Already initialized
        
        if self.config.schema:
            self.schema = self.config.schema
        elif self.config.schema_file:
            self.schema = await self._load_schema_file(self.config.schema_file)
        elif self.config.schema_url:
            self.schema = await self._load_schema_url(self.config.schema_url)
        else:
            raise ValueError("No schema provided in configuration")
        
        if not self.schema:
            raise ValueError("Failed to load schema")
        
        # Create validator
        self.validator = JSONSchemaValidator(
            schema=self.schema,
            draft=self.config.draft,
            schema_registry=self.config.schema_registry,
            error_formatter=self.config.error_formatter,
            custom_formats=self.config.custom_formats,
            custom_keywords=self.config.custom_keywords,
            strict_mode=self.config.strict_mode,
            collect_warnings=self.config.collect_warnings
        )
    
    async def _load_schema_file(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Load schema from file."""
        try:
            path = Path(file_path)
            if not path.exists():
                raise FileNotFoundError(f"Schema file not found: {file_path}")
            
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            raise ValueError(f"Failed to load schema file {file_path}: {str(e)}")
    
    async def _load_schema_url(self, schema_url: str) -> Optional[Dict[str, Any]]:
        """Load schema from URL."""
        try:
            return await self.config.schema_registry.load_schema(schema_url)
        except Exception:
            return None
    
    def _generate_schema_hash(self) -> str:
        """Generate hash for current schema for caching."""
        if not self.schema:
            return ""
        
        schema_str = json.dumps(self.schema, sort_keys=True)
        return str(hash(schema_str))
    
    async def _validate_request_body(self, request: Request) -> Optional[ValidationResult]:
        """Validate request body against schema."""
        if not self.config.validate_request_body:
            return None
        
        try:
            # Get request body
            body_bytes = await request.body()
            if not body_bytes:
                return None  # No body to validate
            
            body_data = json.loads(body_bytes.decode('utf-8'))
            
            # Perform validation
            return await self._validate_data(body_data, "request_body")
            
        except json.JSONDecodeError as e:
            return ValidationResult(
                valid=False,
                errors=[ValidationErrorDetail(
                    message=f"Invalid JSON: {str(e)}",
                    path="",
                    schema_path="",
                    instance=None,
                    validator="json",
                    validator_value=None,
                    error_code="INVALID_JSON"
                )]
            )
        except Exception as e:
            return ValidationResult(
                valid=False,
                errors=[ValidationErrorDetail(
                    message=f"Request body validation error: {str(e)}",
                    path="",
                    schema_path="",
                    instance=None,
                    validator="request",
                    validator_value=None,
                    error_code="REQUEST_ERROR"
                )]
            )
    
    async def _validate_query_params(self, request: Request) -> Optional[ValidationResult]:
        """Validate query parameters against schema."""
        if not self.config.validate_query_params:
            return None
        
        query_params = dict(request.query_params)
        if not query_params:
            return None
        
        return await self._validate_data(query_params, "query_params")
    
    async def _validate_path_params(self, request: Request) -> Optional[ValidationResult]:
        """Validate path parameters against schema."""
        if not self.config.validate_path_params:
            return None
        
        path_params = getattr(request, 'path_params', {})
        if not path_params:
            return None
        
        return await self._validate_data(path_params, "path_params")
    
    async def _validate_headers(self, request: Request) -> Optional[ValidationResult]:
        """Validate headers against schema."""
        if not self.config.validate_headers:
            return None
        
        headers = dict(request.headers)
        if not headers:
            return None
        
        return await self._validate_data(headers, "headers")
    
    async def _validate_data(self, data: Any, context_type: str) -> ValidationResult:
        """Validate data against schema with caching."""
        if not self.validator:
            return ValidationResult(
                valid=False,
                errors=[ValidationErrorDetail(
                    message="Schema validator not initialized",
                    path="",
                    schema_path="",
                    instance=data,
                    validator="initialization",
                    validator_value=None,
                    error_code="VALIDATOR_ERROR"
                )]
            )
        
        # Check cache if enabled
        if self.cache:
            schema_hash = self._generate_schema_hash()
            cached_result = self.cache.get(schema_hash, data)
            if cached_result:
                return cached_result
        
        # Perform validation with timeout
        try:
            import asyncio
            
            async def validate_with_timeout():
                context = {"type": context_type}
                return self.validator.validate(data, context)
            
            result = await asyncio.wait_for(
                validate_with_timeout(),
                timeout=self.config.validation_timeout_seconds
            )
            
            # Cache result if enabled
            if self.cache:
                schema_hash = self._generate_schema_hash()
                self.cache.set(schema_hash, data, result)
            
            return result
            
        except asyncio.TimeoutError:
            return ValidationResult(
                valid=False,
                errors=[ValidationErrorDetail(
                    message=f"Validation timeout after {self.config.validation_timeout_seconds} seconds",
                    path="",
                    schema_path="",
                    instance=data,
                    validator="timeout",
                    validator_value=None,
                    error_code="VALIDATION_TIMEOUT"
                )]
            )
    
    def _create_error_response(self, results: List[ValidationResult]) -> Dict[str, Any]:
        """Create error response from validation results."""
        all_errors = []
        all_warnings = []
        
        for result in results:
            all_errors.extend(result.errors)
            all_warnings.extend(result.warnings)
        
        error_response = {
            "error": "JSON Schema validation failed",
            "validation_errors": [
                {
                    "message": error.custom_message or error.message,
                    "path": error.path,
                    "schema_path": error.schema_path,
                    "validator": error.validator,
                    "validator_value": error.validator_value,
                    "instance": error.instance,
                    "error_code": error.error_code,
                    "severity": error.severity.value
                }
                for error in all_errors
            ]
        }
        
        if self.config.include_warnings_in_response and all_warnings:
            error_response["validation_warnings"] = [
                {
                    "message": warning.custom_message or warning.message,
                    "path": warning.path,
                    "schema_path": warning.schema_path,
                    "validator": warning.validator,
                    "validator_value": warning.validator_value,
                    "instance": warning.instance,
                    "error_code": warning.error_code,
                    "severity": warning.severity.value
                }
                for warning in all_warnings
            ]
        
        # Check for custom error responses
        if all_errors:
            first_error_code = all_errors[0].error_code
            if first_error_code in self.config.custom_error_responses:
                custom_response = self.config.custom_error_responses[first_error_code]
                error_response.update(custom_response)
        
        return error_response
    
    async def _shield_function(self, request: Request) -> Optional[Dict[str, Any]]:
        """Main shield function for JSON schema validation."""
        try:
            # Initialize schema if not already done
            await self._initialize_schema()
            
            # Collect validation results
            validation_results = []
            
            # Validate different parts of request
            validators = [
                self._validate_request_body(request),
                self._validate_query_params(request),
                self._validate_path_params(request),
                self._validate_headers(request)
            ]
            
            # Run all validations
            results = await asyncio.gather(*validators, return_exceptions=True)
            
            for result in results:
                if isinstance(result, Exception):
                    # Handle validation exceptions
                    validation_results.append(ValidationResult(
                        valid=False,
                        errors=[ValidationErrorDetail(
                            message=f"Validation error: {str(result)}",
                            path="",
                            schema_path="",
                            instance=None,
                            validator="exception",
                            validator_value=None,
                            error_code="VALIDATION_EXCEPTION"
                        )]
                    ))
                elif result is not None:
                    validation_results.append(result)
            
            # Check if any validation failed
            failed_results = [r for r in validation_results if not r.valid]
            
            if failed_results:
                # Call error callback if configured
                if self.config.on_validation_error:
                    for result in failed_results:
                        try:
                            self.config.on_validation_error(result, request)
                        except Exception:
                            pass  # Don't let callback errors break validation
                
                # Create error response
                error_response = self._create_error_response(failed_results)
                
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=error_response
                )
            
            # Return validation metadata for successful validation
            return {
                "json_schema_validation": {
                    "schema_id": self.schema.get('$id') if self.schema else None,
                    "draft": self.config.draft.value,
                    "validation_results": len(validation_results),
                    "warnings": sum(len(r.warnings) for r in validation_results),
                    "total_validation_time_ms": sum(r.validation_time_ms for r in validation_results)
                }
            }
            
        except HTTPException:
            raise
        except Exception as e:
            # Handle unexpected errors
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "error": "JSON Schema validation failed",
                    "message": f"Unexpected validation error: {str(e)}",
                    "error_code": "VALIDATION_SYSTEM_ERROR"
                }
            )


# Convenience functions for creating shields

def json_schema_validation_shield(
    schema: Optional[Dict[str, Any]] = None,
    schema_file: Optional[str] = None,
    schema_url: Optional[str] = None,
    draft: JSONSchemaDraft = JSONSchemaDraft.DRAFT_7,
    validate_request_body: bool = True,
    strict_mode: bool = True,
    enable_caching: bool = True
) -> JSONSchemaValidationShield:
    """Create a JSON schema validation shield with basic configuration.
    
    Args:
        schema: JSON schema dictionary
        schema_file: Path to schema file
        schema_url: URL to load schema from
        draft: JSON Schema draft version
        validate_request_body: Whether to validate request body
        strict_mode: Enable strict validation mode
        enable_caching: Enable validation result caching
    
    Returns:
        JSONSchemaValidationShield instance
    """
    config = JSONSchemaValidationConfig(
        schema=schema,
        schema_file=schema_file,
        schema_url=schema_url,
        draft=draft,
        validate_request_body=validate_request_body,
        strict_mode=strict_mode,
        enable_caching=enable_caching
    )
    
    return JSONSchemaValidationShield(config)


def comprehensive_json_validation_shield(
    schema: Dict[str, Any],
    validate_all: bool = True,
    custom_formats: Optional[Dict[str, Callable[[str], bool]]] = None,
    custom_error_messages: Optional[Dict[str, str]] = None,
    collect_warnings: bool = True,
    enable_caching: bool = True
) -> JSONSchemaValidationShield:
    """Create a comprehensive JSON schema validation shield.
    
    Args:
        schema: JSON schema dictionary
        validate_all: Validate all request parts (body, params, headers)
        custom_formats: Custom format validators
        custom_error_messages: Custom error message templates
        collect_warnings: Whether to collect validation warnings
        enable_caching: Enable validation result caching
    
    Returns:
        JSONSchemaValidationShield instance
    """
    error_formatter = ErrorMessageFormatter()
    
    if custom_error_messages:
        for validator, message in custom_error_messages.items():
            error_formatter.add_custom_message(validator, message)
    
    config = JSONSchemaValidationConfig(
        schema=schema,
        validate_request_body=True,
        validate_query_params=validate_all,
        validate_path_params=validate_all,
        validate_headers=validate_all,
        custom_formats=custom_formats,
        error_formatter=error_formatter,
        collect_warnings=collect_warnings,
        enable_caching=enable_caching,
        include_warnings_in_response=collect_warnings
    )
    
    return JSONSchemaValidationShield(config)


def draft7_validation_shield(
    schema: Dict[str, Any],
    enable_caching: bool = True
) -> JSONSchemaValidationShield:
    """Create JSON Schema Draft 7 validation shield.
    
    Args:
        schema: JSON schema dictionary
        enable_caching: Enable validation result caching
    
    Returns:
        JSONSchemaValidationShield instance
    """
    return json_schema_validation_shield(
        schema=schema,
        draft=JSONSchemaDraft.DRAFT_7,
        enable_caching=enable_caching
    )


def draft201909_validation_shield(
    schema: Dict[str, Any],
    enable_caching: bool = True
) -> JSONSchemaValidationShield:
    """Create JSON Schema Draft 2019-09 validation shield.
    
    Args:
        schema: JSON schema dictionary
        enable_caching: Enable validation result caching
    
    Returns:
        JSONSchemaValidationShield instance
    """
    return json_schema_validation_shield(
        schema=schema,
        draft=JSONSchemaDraft.DRAFT_2019_09,
        enable_caching=enable_caching
    )


def file_schema_validation_shield(
    schema_file: str,
    draft: JSONSchemaDraft = JSONSchemaDraft.DRAFT_7,
    enable_caching: bool = True
) -> JSONSchemaValidationShield:
    """Create validation shield loading schema from file.
    
    Args:
        schema_file: Path to JSON schema file
        draft: JSON Schema draft version
        enable_caching: Enable validation result caching
    
    Returns:
        JSONSchemaValidationShield instance
    """
    return json_schema_validation_shield(
        schema_file=schema_file,
        draft=draft,
        enable_caching=enable_caching
    )


def url_schema_validation_shield(
    schema_url: str,
    draft: JSONSchemaDraft = JSONSchemaDraft.DRAFT_7,
    enable_caching: bool = True
) -> JSONSchemaValidationShield:
    """Create validation shield loading schema from URL.
    
    Args:
        schema_url: URL to load JSON schema from
        draft: JSON Schema draft version
        enable_caching: Enable validation result caching
    
    Returns:
        JSONSchemaValidationShield instance
    """
    return json_schema_validation_shield(
        schema_url=schema_url,
        draft=draft,
        enable_caching=enable_caching
    )