"""Mock classes and utilities for JSON Schema validation shield testing."""

import json
import time
from typing import Any, Dict, List, Optional, Callable
from unittest.mock import Mock, AsyncMock

from fastapi_shield.json_schema_validation import (
    JSONSchemaValidator,
    SchemaRegistry,
    ErrorMessageFormatter,
    ValidationCache,
    ValidationResult,
    ValidationErrorDetail,
    ValidationErrorSeverity,
    JSONSchemaDraft
)


class MockSchemaRegistry:
    """Mock schema registry for testing."""
    
    def __init__(self):
        self.schemas: Dict[str, Dict[str, Any]] = {}
        self.loaded_schemas: List[str] = []
        self.load_failures: List[str] = []
        self.should_fail_loading: bool = False
    
    def register_schema(self, schema_id: str, schema: Dict[str, Any]) -> None:
        """Mock register schema."""
        self.schemas[schema_id] = schema
    
    def get_schema(self, schema_id: str) -> Optional[Dict[str, Any]]:
        """Mock get schema."""
        return self.schemas.get(schema_id)
    
    async def load_schema(self, schema_id: str) -> Optional[Dict[str, Any]]:
        """Mock load schema."""
        self.loaded_schemas.append(schema_id)
        
        if self.should_fail_loading:
            self.load_failures.append(schema_id)
            return None
        
        # Return schema if exists
        if schema_id in self.schemas:
            return self.schemas[schema_id]
        
        # Mock loading from URL
        if schema_id.startswith('http'):
            mock_schema = {
                "$id": schema_id,
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "age": {"type": "integer", "minimum": 0}
                }
            }
            self.schemas[schema_id] = mock_schema
            return mock_schema
        
        return None
    
    def clear_cache(self) -> None:
        """Mock clear cache."""
        pass
    
    def reset_tracking(self):
        """Reset call tracking."""
        self.loaded_schemas = []
        self.load_failures = []


class MockErrorMessageFormatter:
    """Mock error message formatter for testing."""
    
    def __init__(self):
        self.custom_messages: Dict[str, str] = {}
        self.path_templates: Dict[str, str] = {}
        self.format_calls: List[Dict[str, Any]] = []
    
    def add_custom_message(self, validator: str, message_template: str) -> None:
        """Mock add custom message."""
        self.custom_messages[validator] = message_template
    
    def add_path_template(self, path_pattern: str, message_template: str) -> None:
        """Mock add path template."""
        self.path_templates[path_pattern] = message_template
    
    def format_error(self, error, custom_data: Optional[Dict[str, Any]] = None) -> str:
        """Mock format error."""
        self.format_calls.append({
            'error': error,
            'custom_data': custom_data,
            'timestamp': time.time()
        })
        
        # Return custom message if available
        validator = getattr(error, 'validator', 'unknown')
        if validator in self.custom_messages:
            return self.custom_messages[validator].format(
                validator=validator,
                instance=getattr(error, 'instance', None),
                validator_value=getattr(error, 'validator_value', None)
            )
        
        return getattr(error, 'message', 'Mock validation error')
    
    def _format_json_pointer(self, path) -> str:
        """Mock JSON pointer formatting."""
        if not path:
            return "/"
        return "/" + "/".join(str(p) for p in path)
    
    def reset_tracking(self):
        """Reset call tracking."""
        self.format_calls = []


class MockValidationCache:
    """Mock validation cache for testing."""
    
    def __init__(self, max_size: int = 100, ttl_seconds: int = 300):
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.get_calls: List[Dict[str, Any]] = []
        self.set_calls: List[Dict[str, Any]] = []
        self.hit_count = 0
        self.miss_count = 0
    
    def get(self, schema_hash: str, instance: Any) -> Optional[ValidationResult]:
        """Mock cache get."""
        key = self._generate_key(schema_hash, instance)
        self.get_calls.append({
            'schema_hash': schema_hash,
            'instance': instance,
            'key': key,
            'timestamp': time.time()
        })
        
        if key in self.cache:
            self.hit_count += 1
            cached_data = self.cache[key]
            return ValidationResult(
                valid=cached_data['valid'],
                errors=cached_data['errors'],
                warnings=cached_data.get('warnings', []),
                validation_time_ms=cached_data.get('validation_time_ms', 0.0)
            )
        
        self.miss_count += 1
        return None
    
    def set(self, schema_hash: str, instance: Any, result: ValidationResult) -> None:
        """Mock cache set."""
        key = self._generate_key(schema_hash, instance)
        self.set_calls.append({
            'schema_hash': schema_hash,
            'instance': instance,
            'result': result,
            'key': key,
            'timestamp': time.time()
        })
        
        self.cache[key] = {
            'valid': result.valid,
            'errors': result.errors,
            'warnings': result.warnings,
            'validation_time_ms': result.validation_time_ms
        }
    
    def clear(self) -> None:
        """Mock cache clear."""
        self.cache.clear()
    
    def _generate_key(self, schema_hash: str, instance: Any) -> str:
        """Mock cache key generation."""
        instance_str = json.dumps(instance, sort_keys=True, default=str)
        return f"{schema_hash}:{hash(instance_str)}"
    
    def reset_tracking(self):
        """Reset call tracking."""
        self.get_calls = []
        self.set_calls = []
        self.hit_count = 0
        self.miss_count = 0


class MockJSONSchemaValidator:
    """Mock JSON Schema validator for testing."""
    
    def __init__(
        self,
        schema: Dict[str, Any],
        draft: JSONSchemaDraft = JSONSchemaDraft.DRAFT_7,
        should_validate: bool = True,
        validation_errors: Optional[List[ValidationErrorDetail]] = None,
        validation_warnings: Optional[List[ValidationErrorDetail]] = None,
        validation_time_ms: float = 5.0
    ):
        self.schema = schema
        self.draft = draft
        self.should_validate = should_validate
        self.validation_errors = validation_errors or []
        self.validation_warnings = validation_warnings or []
        self.validation_time_ms = validation_time_ms
        
        # Tracking
        self.validate_calls: List[Dict[str, Any]] = []
    
    def validate(self, instance: Any, context: Optional[Dict[str, Any]] = None) -> ValidationResult:
        """Mock validation."""
        self.validate_calls.append({
            'instance': instance,
            'context': context,
            'timestamp': time.time()
        })
        
        # Return predetermined result
        return ValidationResult(
            valid=self.should_validate and len(self.validation_errors) == 0,
            errors=self.validation_errors.copy(),
            warnings=self.validation_warnings.copy(),
            validation_time_ms=self.validation_time_ms,
            schema_id=self.schema.get('$id')
        )
    
    def add_validation_error(self, error: ValidationErrorDetail):
        """Add validation error for testing."""
        self.validation_errors.append(error)
    
    def add_validation_warning(self, warning: ValidationErrorDetail):
        """Add validation warning for testing."""
        self.validation_warnings.append(warning)
    
    def reset_tracking(self):
        """Reset call tracking."""
        self.validate_calls = []


def create_mock_validation_error(
    message: str = "Mock validation error",
    path: str = "/field",
    validator: str = "type",
    validator_value: Any = "string",
    instance: Any = 123,
    severity: ValidationErrorSeverity = ValidationErrorSeverity.ERROR,
    error_code: str = "TYPE_MISMATCH"
) -> ValidationErrorDetail:
    """Create a mock validation error detail."""
    return ValidationErrorDetail(
        message=message,
        path=path,
        schema_path=f"/properties{path}/type",
        instance=instance,
        validator=validator,
        validator_value=validator_value,
        severity=severity,
        error_code=error_code
    )


def create_mock_validation_result(
    valid: bool = True,
    errors: Optional[List[ValidationErrorDetail]] = None,
    warnings: Optional[List[ValidationErrorDetail]] = None,
    validation_time_ms: float = 10.0,
    schema_id: Optional[str] = None
) -> ValidationResult:
    """Create a mock validation result."""
    return ValidationResult(
        valid=valid,
        errors=errors or [],
        warnings=warnings or [],
        validation_time_ms=validation_time_ms,
        schema_id=schema_id
    )


def create_test_schema(
    schema_type: str = "object",
    properties: Optional[Dict[str, Any]] = None,
    required: Optional[List[str]] = None,
    additional_properties: bool = False,
    schema_id: Optional[str] = None
) -> Dict[str, Any]:
    """Create a test JSON schema."""
    schema = {
        "type": schema_type,
        "additionalProperties": additional_properties
    }
    
    if schema_id:
        schema["$id"] = schema_id
    
    if properties:
        schema["properties"] = properties
    
    if required:
        schema["required"] = required
    
    return schema


def create_user_schema() -> Dict[str, Any]:
    """Create a typical user validation schema."""
    return create_test_schema(
        properties={
            "name": {
                "type": "string",
                "minLength": 1,
                "maxLength": 100
            },
            "email": {
                "type": "string",
                "format": "email"
            },
            "age": {
                "type": "integer",
                "minimum": 0,
                "maximum": 150
            },
            "is_active": {
                "type": "boolean"
            },
            "tags": {
                "type": "array",
                "items": {"type": "string"},
                "uniqueItems": True
            }
        },
        required=["name", "email"],
        schema_id="https://example.com/schemas/user.json"
    )


def create_product_schema() -> Dict[str, Any]:
    """Create a product validation schema."""
    return create_test_schema(
        properties={
            "id": {
                "type": "string",
                "format": "uuid"
            },
            "name": {
                "type": "string",
                "minLength": 1
            },
            "price": {
                "type": "number",
                "minimum": 0
            },
            "category": {
                "type": "string",
                "enum": ["electronics", "clothing", "books", "home"]
            },
            "in_stock": {
                "type": "boolean"
            },
            "metadata": {
                "type": "object",
                "additionalProperties": True
            }
        },
        required=["id", "name", "price", "category"],
        schema_id="https://example.com/schemas/product.json"
    )


def create_complex_nested_schema() -> Dict[str, Any]:
    """Create a complex nested schema for testing."""
    return {
        "$id": "https://example.com/schemas/complex.json",
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties": {
            "user": {
                "$ref": "https://example.com/schemas/user.json"
            },
            "orders": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string", "format": "uuid"},
                        "products": {
                            "type": "array",
                            "items": {
                                "$ref": "https://example.com/schemas/product.json"
                            },
                            "minItems": 1
                        },
                        "total": {
                            "type": "number",
                            "minimum": 0
                        },
                        "created_at": {
                            "type": "string",
                            "format": "datetime"
                        }
                    },
                    "required": ["id", "products", "total", "created_at"]
                }
            },
            "preferences": {
                "type": "object",
                "properties": {
                    "theme": {
                        "type": "string",
                        "enum": ["light", "dark", "auto"]
                    },
                    "notifications": {
                        "type": "object",
                        "properties": {
                            "email": {"type": "boolean"},
                            "push": {"type": "boolean"},
                            "sms": {"type": "boolean"}
                        },
                        "additionalProperties": False
                    }
                }
            }
        },
        "required": ["user", "orders"],
        "additionalProperties": False
    }


def create_test_data_valid() -> Dict[str, Any]:
    """Create valid test data that matches user schema."""
    return {
        "name": "John Doe",
        "email": "john@example.com",
        "age": 30,
        "is_active": True,
        "tags": ["developer", "python", "fastapi"]
    }


def create_test_data_invalid() -> Dict[str, Any]:
    """Create invalid test data for testing validation errors."""
    return {
        "name": "",  # Too short
        "email": "invalid-email",  # Invalid format
        "age": -5,  # Below minimum
        "is_active": "yes",  # Wrong type
        "tags": ["duplicate", "duplicate"]  # Not unique
    }


class LoadTestHelper:
    """Helper for load testing JSON schema validation."""
    
    @staticmethod
    def generate_test_instances(count: int, valid_ratio: float = 0.8) -> List[Dict[str, Any]]:
        """Generate multiple test instances for load testing."""
        instances = []
        valid_count = int(count * valid_ratio)
        
        for i in range(count):
            if i < valid_count:
                # Generate valid instance
                instance = {
                    "name": f"User {i}",
                    "email": f"user{i}@example.com",
                    "age": 25 + (i % 50),
                    "is_active": i % 2 == 0,
                    "tags": [f"tag{j}" for j in range(i % 5)]
                }
            else:
                # Generate invalid instance
                instance = {
                    "name": "",  # Invalid
                    "email": f"invalid-email-{i}",  # Invalid format
                    "age": -1,  # Invalid range
                    "is_active": "invalid",  # Wrong type
                }
            
            instances.append(instance)
        
        return instances
    
    @staticmethod
    async def concurrent_validations(
        validator: JSONSchemaValidator,
        instances: List[Any],
        concurrent_count: int = 10
    ) -> List[ValidationResult]:
        """Perform concurrent validations."""
        import asyncio
        
        async def validate_instance(instance):
            return validator.validate(instance)
        
        tasks = [validate_instance(instance) for instance in instances[:concurrent_count]]
        return await asyncio.gather(*tasks, return_exceptions=True)


class TimingHelper:
    """Helper for testing timing-related functionality."""
    
    @staticmethod
    def measure_validation_performance(
        validator: JSONSchemaValidator,
        instances: List[Any]
    ) -> Dict[str, float]:
        """Measure validation performance metrics."""
        start_time = time.time()
        
        validation_times = []
        valid_count = 0
        error_count = 0
        
        for instance in instances:
            instance_start = time.time()
            result = validator.validate(instance)
            instance_end = time.time()
            
            validation_times.append((instance_end - instance_start) * 1000)
            
            if result.valid:
                valid_count += 1
            else:
                error_count += 1
        
        end_time = time.time()
        
        return {
            'total_time_ms': (end_time - start_time) * 1000,
            'average_time_ms': sum(validation_times) / len(validation_times),
            'min_time_ms': min(validation_times),
            'max_time_ms': max(validation_times),
            'valid_count': valid_count,
            'error_count': error_count,
            'total_instances': len(instances)
        }


class ValidationHelper:
    """Helper for validating test results."""
    
    @staticmethod
    def assert_validation_result(
        result: ValidationResult,
        expected_valid: bool,
        expected_error_count: Optional[int] = None,
        expected_warning_count: Optional[int] = None,
        expected_error_codes: Optional[List[str]] = None
    ):
        """Assert validation result properties."""
        assert result.valid == expected_valid
        
        if expected_error_count is not None:
            assert len(result.errors) == expected_error_count
        
        if expected_warning_count is not None:
            assert len(result.warnings) == expected_warning_count
        
        if expected_error_codes:
            actual_codes = [error.error_code for error in result.errors]
            for code in expected_error_codes:
                assert code in actual_codes
        
        assert result.validation_time_ms >= 0
    
    @staticmethod
    def assert_error_detail(
        error: ValidationErrorDetail,
        expected_validator: Optional[str] = None,
        expected_path: Optional[str] = None,
        expected_severity: Optional[ValidationErrorSeverity] = None,
        expected_code: Optional[str] = None
    ):
        """Assert validation error detail properties."""
        assert isinstance(error.message, str)
        assert len(error.message) > 0
        
        if expected_validator:
            assert error.validator == expected_validator
        
        if expected_path:
            assert error.path == expected_path
        
        if expected_severity:
            assert error.severity == expected_severity
        
        if expected_code:
            assert error.error_code == expected_code
    
    @staticmethod
    def find_error_by_path(errors: List[ValidationErrorDetail], path: str) -> Optional[ValidationErrorDetail]:
        """Find validation error by JSON pointer path."""
        for error in errors:
            if error.path == path:
                return error
        return None
    
    @staticmethod
    def find_error_by_validator(errors: List[ValidationErrorDetail], validator: str) -> Optional[ValidationErrorDetail]:
        """Find validation error by validator type."""
        for error in errors:
            if error.validator == validator:
                return error
        return None