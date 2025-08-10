"""Input validation shield for FastAPI Shield.

This module provides input validation and sanitization functionality to prevent
various attack vectors and ensure data quality. Supports custom validation rules,
data transformation, and integration with FastAPI's validation system.
"""

import html
import re
import urllib.parse
from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Pattern, Union

from fastapi import HTTPException, Request, status
from pydantic import BaseModel, ValidationError

from fastapi_shield.shield import Shield, shield


class ValidationRule(BaseModel):
    """Configuration for a validation rule."""
    name: str
    field_path: str  # e.g., "query.username", "body.email", "headers.content-type"
    validator: Union[str, Callable[[Any], bool]]  # Built-in validator name or custom function
    transform: Optional[Union[str, Callable[[Any], Any]]] = None  # Built-in transform or custom function
    required: bool = True
    error_message: Optional[str] = None
    allow_empty: bool = False


class SanitizationType(str, Enum):
    """Built-in sanitization types."""
    XSS = "xss"
    SQL_INJECTION = "sql_injection"
    HTML = "html"
    URL = "url"
    WHITESPACE = "whitespace"
    ALPHANUMERIC = "alphanumeric"
    EMAIL = "email"
    PHONE = "phone"


class ValidationType(str, Enum):
    """Built-in validation types."""
    EMAIL = "email"
    URL = "url"
    PHONE = "phone"
    CREDIT_CARD = "credit_card"
    UUID = "uuid"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    REGEX = "regex"
    LENGTH = "length"
    RANGE = "range"
    CUSTOM = "custom"


class InputSanitizer:
    """Collection of built-in input sanitization methods."""
    
    # Common XSS patterns
    XSS_PATTERNS = [
        re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
        re.compile(r'javascript:', re.IGNORECASE),
        re.compile(r'on\w+\s*=', re.IGNORECASE),
        re.compile(r'<iframe[^>]*>.*?</iframe>', re.IGNORECASE | re.DOTALL),
        re.compile(r'<object[^>]*>.*?</object>', re.IGNORECASE | re.DOTALL),
        re.compile(r'<embed[^>]*>', re.IGNORECASE),
        re.compile(r'<link[^>]*>', re.IGNORECASE),
        re.compile(r'<meta[^>]*>', re.IGNORECASE),
        re.compile(r'expression\s*\(', re.IGNORECASE),
        re.compile(r'vbscript:', re.IGNORECASE),
        re.compile(r'data:text/html', re.IGNORECASE),
    ]
    
    # SQL injection patterns
    SQL_INJECTION_PATTERNS = [
        re.compile(r"(\s|^)(union|select|insert|update|delete|drop|create|alter|exec|execute|sp_)", re.IGNORECASE),
        re.compile(r"(--|\#|/\*|\*/)", re.IGNORECASE),
        re.compile(r"(;\s*\w+)", re.IGNORECASE),
        re.compile(r"'(\s*or\s*|\s*and\s*)", re.IGNORECASE),
    ]
    
    @staticmethod
    def sanitize_xss(value: str) -> str:
        """Remove XSS attack vectors from string."""
        if not isinstance(value, str):
            return value
        
        sanitized = value
        
        # First remove dangerous patterns
        for pattern in InputSanitizer.XSS_PATTERNS:
            sanitized = pattern.sub('', sanitized)
        
        # Then HTML escape the remaining content
        sanitized = html.escape(sanitized)
        
        return sanitized
    
    @staticmethod
    def sanitize_sql_injection(value: str) -> str:
        """Remove SQL injection attack vectors."""
        if not isinstance(value, str):
            return value
        
        sanitized = value
        for pattern in InputSanitizer.SQL_INJECTION_PATTERNS:
            sanitized = pattern.sub('', sanitized)
        
        return sanitized
    
    @staticmethod
    def sanitize_html(value: str) -> str:
        """HTML escape the value."""
        if not isinstance(value, str):
            return value
        return html.escape(value)
    
    @staticmethod
    def sanitize_url(value: str) -> str:
        """URL encode the value."""
        if not isinstance(value, str):
            return value
        return urllib.parse.quote(value, safe='')
    
    @staticmethod
    def sanitize_whitespace(value: str) -> str:
        """Trim whitespace and normalize spaces."""
        if not isinstance(value, str):
            return value
        return ' '.join(value.split())
    
    @staticmethod
    def sanitize_alphanumeric(value: str) -> str:
        """Keep only alphanumeric characters."""
        if not isinstance(value, str):
            return value
        return re.sub(r'[^a-zA-Z0-9]', '', value)
    
    @staticmethod
    def sanitize_email(value: str) -> str:
        """Sanitize email address."""
        if not isinstance(value, str):
            return value
        # Remove dangerous characters but keep valid email characters including +
        return re.sub(r'[^a-zA-Z0-9@._+-]', '', value.lower().strip())
    
    @staticmethod
    def sanitize_phone(value: str) -> str:
        """Sanitize phone number."""
        if not isinstance(value, str):
            return value
        # Keep only digits, spaces, hyphens, parentheses, and plus
        return re.sub(r'[^0-9\s\-\(\)\+]', '', value)


class InputValidator:
    """Collection of built-in input validation methods."""
    
    EMAIL_PATTERN = re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    )
    
    URL_PATTERN = re.compile(
        r'^https?://(?:[-\w.])+(?:\:[0-9]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:\#(?:[\w.])*)?)?$'
    )
    
    PHONE_PATTERN = re.compile(
        r'^\+?[1-9]\d{7,14}$'  # E.164 format, minimum 8 digits after country code
    )
    
    CREDIT_CARD_PATTERN = re.compile(
        r'^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})$'
    )
    
    UUID_PATTERN = re.compile(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
        re.IGNORECASE
    )
    
    IPV4_PATTERN = re.compile(
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    )
    
    IPV6_PATTERN = re.compile(
        r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$'
    )
    
    @staticmethod
    def validate_email(value: str) -> bool:
        """Validate email format."""
        if not isinstance(value, str):
            return False
        return bool(InputValidator.EMAIL_PATTERN.match(value))
    
    @staticmethod
    def validate_url(value: str) -> bool:
        """Validate URL format."""
        if not isinstance(value, str):
            return False
        return bool(InputValidator.URL_PATTERN.match(value))
    
    @staticmethod
    def validate_phone(value: str) -> bool:
        """Validate phone number format."""
        if not isinstance(value, str):
            return False
        # Remove common formatting characters
        clean_phone = re.sub(r'[^\d+]', '', value)
        return bool(InputValidator.PHONE_PATTERN.match(clean_phone))
    
    @staticmethod
    def validate_credit_card(value: str) -> bool:
        """Validate credit card number format."""
        if not isinstance(value, str):
            return False
        # Remove spaces and hyphens
        clean_card = re.sub(r'[\s-]', '', value)
        return bool(InputValidator.CREDIT_CARD_PATTERN.match(clean_card))
    
    @staticmethod
    def validate_uuid(value: str) -> bool:
        """Validate UUID format."""
        if not isinstance(value, str):
            return False
        return bool(InputValidator.UUID_PATTERN.match(value))
    
    @staticmethod
    def validate_ipv4(value: str) -> bool:
        """Validate IPv4 address."""
        if not isinstance(value, str):
            return False
        return bool(InputValidator.IPV4_PATTERN.match(value))
    
    @staticmethod
    def validate_ipv6(value: str) -> bool:
        """Validate IPv6 address."""
        if not isinstance(value, str):
            return False
        return bool(InputValidator.IPV6_PATTERN.match(value))
    
    @staticmethod
    def validate_regex(value: str, pattern: Union[str, Pattern]) -> bool:
        """Validate against custom regex pattern."""
        if not isinstance(value, str):
            return False
        if isinstance(pattern, str):
            pattern = re.compile(pattern)
        return bool(pattern.match(value))
    
    @staticmethod
    def validate_length(value: str, min_length: int = 0, max_length: int = None) -> bool:
        """Validate string length."""
        if not isinstance(value, str):
            return False
        length = len(value)
        if length < min_length:
            return False
        if max_length is not None and length > max_length:
            return False
        return True
    
    @staticmethod
    def validate_range(value: Union[int, float], min_value: Union[int, float] = None, 
                      max_value: Union[int, float] = None) -> bool:
        """Validate numeric range."""
        if not isinstance(value, (int, float)):
            return False
        if min_value is not None and value < min_value:
            return False
        if max_value is not None and value > max_value:
            return False
        return True


class InputValidationShield:
    """Input validation and sanitization shield."""
    
    def __init__(
        self,
        validation_rules: List[ValidationRule] = None,
        sanitization_rules: Dict[str, Union[str, Callable]] = None,
        auto_sanitize: bool = True,
        strict_mode: bool = False,
        allow_extra_fields: bool = True,
        custom_validators: Dict[str, Callable] = None,
        custom_sanitizers: Dict[str, Callable] = None,
    ):
        """Initialize input validation shield.
        
        Args:
            validation_rules: List of validation rules to apply
            sanitization_rules: Dict mapping field paths to sanitization methods
            auto_sanitize: Automatically sanitize common attack vectors
            strict_mode: Raise error for any validation failure
            allow_extra_fields: Allow fields not covered by rules
            custom_validators: Custom validation functions
            custom_sanitizers: Custom sanitization functions
        """
        self.validation_rules = validation_rules or []
        self.sanitization_rules = sanitization_rules or {}
        self.auto_sanitize = auto_sanitize
        self.strict_mode = strict_mode
        self.allow_extra_fields = allow_extra_fields
        self.custom_validators = custom_validators or {}
        self.custom_sanitizers = custom_sanitizers or {}
        
        # Built-in sanitizers mapping
        self.builtin_sanitizers = {
            SanitizationType.XSS: InputSanitizer.sanitize_xss,
            SanitizationType.SQL_INJECTION: InputSanitizer.sanitize_sql_injection,
            SanitizationType.HTML: InputSanitizer.sanitize_html,
            SanitizationType.URL: InputSanitizer.sanitize_url,
            SanitizationType.WHITESPACE: InputSanitizer.sanitize_whitespace,
            SanitizationType.ALPHANUMERIC: InputSanitizer.sanitize_alphanumeric,
            SanitizationType.EMAIL: InputSanitizer.sanitize_email,
            SanitizationType.PHONE: InputSanitizer.sanitize_phone,
        }
        
        # Built-in validators mapping
        self.builtin_validators = {
            ValidationType.EMAIL: InputValidator.validate_email,
            ValidationType.URL: InputValidator.validate_url,
            ValidationType.PHONE: InputValidator.validate_phone,
            ValidationType.CREDIT_CARD: InputValidator.validate_credit_card,
            ValidationType.UUID: InputValidator.validate_uuid,
            ValidationType.IPV4: InputValidator.validate_ipv4,
            ValidationType.IPV6: InputValidator.validate_ipv6,
        }
    
    def _get_field_value(self, request: Request, field_path: str) -> Any:
        """Extract field value from request using dot notation path."""
        parts = field_path.split('.')
        if len(parts) < 2:
            return None
        
        source = parts[0]  # query, body, headers, path
        field_name = '.'.join(parts[1:])
        
        if source == 'query':
            return request.query_params.get(field_name)
        elif source == 'headers':
            return request.headers.get(field_name)
        elif source == 'path':
            return request.path_params.get(field_name)
        elif source == 'body':
            # For body, we would need to parse it first
            # This is a simplified implementation
            return getattr(request, '_body_cache', {}).get(field_name)
        
        return None
    
    def _set_field_value(self, data: Dict, field_path: str, value: Any) -> None:
        """Set field value in data dict using dot notation path."""
        parts = field_path.split('.')
        current = data
        
        # Navigate to the parent container
        for part in parts[:-1]:
            if part not in current:
                current[part] = {}
            current = current[part]
        
        # Set the final value
        current[parts[-1]] = value
    
    def _apply_sanitization(self, value: Any, sanitizer: Union[str, Callable]) -> Any:
        """Apply sanitization to a value."""
        if callable(sanitizer):
            return sanitizer(value)
        
        if sanitizer in self.builtin_sanitizers:
            return self.builtin_sanitizers[sanitizer](value)
        
        if sanitizer in self.custom_sanitizers:
            return self.custom_sanitizers[sanitizer](value)
        
        return value
    
    def _apply_validation(self, value: Any, validator: Union[str, Callable], **kwargs) -> bool:
        """Apply validation to a value."""
        if callable(validator):
            return validator(value)
        
        if validator in self.builtin_validators:
            return self.builtin_validators[validator](value)
        
        if validator in self.custom_validators:
            return self.custom_validators[validator](value)
        
        # Special handling for built-in validators with parameters
        if validator == ValidationType.REGEX:
            pattern = kwargs.get('pattern')
            if pattern:
                return InputValidator.validate_regex(value, pattern)
        elif validator == ValidationType.LENGTH:
            min_length = kwargs.get('min_length', 0)
            max_length = kwargs.get('max_length')
            return InputValidator.validate_length(value, min_length, max_length)
        elif validator == ValidationType.RANGE:
            min_value = kwargs.get('min_value')
            max_value = kwargs.get('max_value')
            return InputValidator.validate_range(value, min_value, max_value)
        
        return True
    
    def _sanitize_request_data(self, request: Request) -> Dict[str, Any]:
        """Sanitize request data according to rules."""
        sanitized_data = {
            'query': dict(request.query_params),
            'headers': dict(request.headers),
            'path': dict(request.path_params),
            'body': getattr(request, '_body_cache', {}),
        }
        
        # Auto-sanitization for common attack vectors
        if self.auto_sanitize:
            for source in ['query', 'headers', 'body']:
                if source in sanitized_data and isinstance(sanitized_data[source], dict):
                    for key, value in sanitized_data[source].items():
                        if isinstance(value, str):
                            # Apply XSS and SQL injection sanitization by default
                            value = InputSanitizer.sanitize_xss(value)
                            value = InputSanitizer.sanitize_sql_injection(value)
                            sanitized_data[source][key] = value
        
        # Apply custom sanitization rules
        for field_path, sanitizer in self.sanitization_rules.items():
            parts = field_path.split('.')
            if len(parts) >= 2:
                source = parts[0]
                field_name = '.'.join(parts[1:])
                
                if source in sanitized_data and field_name in sanitized_data[source]:
                    original_value = sanitized_data[source][field_name]
                    sanitized_value = self._apply_sanitization(original_value, sanitizer)
                    sanitized_data[source][field_name] = sanitized_value
        
        return sanitized_data
    
    def _validate_request_data(self, request: Request, sanitized_data: Dict[str, Any]) -> List[str]:
        """Validate request data according to rules."""
        errors = []
        
        for rule in self.validation_rules:
            # Get the value from sanitized data or original request
            parts = rule.field_path.split('.')
            if len(parts) >= 2:
                source = parts[0]
                field_name = '.'.join(parts[1:])
                
                value = None
                if source in sanitized_data and field_name in sanitized_data[source]:
                    value = sanitized_data[source][field_name]
                
                # Check if field is required and missing
                if rule.required and (value is None or (not rule.allow_empty and value == '')):
                    error_msg = rule.error_message or f"Field '{rule.field_path}' is required"
                    errors.append(error_msg)
                    continue
                
                # Skip validation if field is optional and empty
                if not rule.required and (value is None or value == ''):
                    continue
                
                # Apply transformation if specified
                if rule.transform:
                    if callable(rule.transform):
                        value = rule.transform(value)
                    elif rule.transform in self.builtin_sanitizers:
                        value = self.builtin_sanitizers[rule.transform](value)
                    elif rule.transform in self.custom_sanitizers:
                        value = self.custom_sanitizers[rule.transform](value)
                
                # Apply validation
                is_valid = self._apply_validation(value, rule.validator)
                if not is_valid:
                    error_msg = rule.error_message or f"Field '{rule.field_path}' is invalid"
                    errors.append(error_msg)
        
        return errors
    
    def create_shield(self, name: str = "InputValidation") -> Shield:
        """Create a shield instance for input validation."""
        
        async def input_validation_shield(request: Request) -> Optional[Dict[str, Any]]:
            """Input validation shield function."""
            try:
                # Parse body if it exists (simplified implementation)
                if hasattr(request, '_body'):
                    try:
                        # This is a simplified body parsing - in practice you'd want
                        # more sophisticated parsing based on content type
                        import json
                        body = await request.body()
                        if body:
                            request._body_cache = json.loads(body.decode())
                        else:
                            request._body_cache = {}
                    except:
                        request._body_cache = {}
                else:
                    request._body_cache = {}
                
                # Sanitize request data
                sanitized_data = self._sanitize_request_data(request)
                
                # Validate request data
                validation_errors = self._validate_request_data(request, sanitized_data)
                
                if validation_errors:
                    if self.strict_mode:
                        raise HTTPException(
                            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                            detail={
                                "message": "Input validation failed",
                                "errors": validation_errors
                            }
                        )
                    else:
                        # Return validation info but allow request to proceed
                        return {
                            "validation_status": "failed",
                            "validation_errors": validation_errors,
                            "sanitized_data": sanitized_data,
                        }
                
                return {
                    "validation_status": "passed",
                    "sanitized_data": sanitized_data,
                }
                
            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Input validation error: {str(e)}"
                )
        
        return shield(
            input_validation_shield,
            name=name,
            auto_error=True,
        )


# Convenience functions for common validation scenarios
def create_xss_protection_shield(fields: List[str] = None) -> Shield:
    """Create a shield that protects against XSS attacks."""
    sanitization_rules = {}
    if fields:
        for field in fields:
            sanitization_rules[field] = SanitizationType.XSS
    
    shield_instance = InputValidationShield(
        sanitization_rules=sanitization_rules,
        auto_sanitize=True,
    )
    return shield_instance.create_shield("XSSProtection")


def create_sql_injection_protection_shield(fields: List[str] = None) -> Shield:
    """Create a shield that protects against SQL injection attacks."""
    sanitization_rules = {}
    if fields:
        for field in fields:
            sanitization_rules[field] = SanitizationType.SQL_INJECTION
    
    shield_instance = InputValidationShield(
        sanitization_rules=sanitization_rules,
        auto_sanitize=True,
    )
    return shield_instance.create_shield("SQLInjectionProtection")


def create_email_validation_shield(email_fields: List[str]) -> Shield:
    """Create a shield that validates email fields."""
    validation_rules = []
    for field in email_fields:
        validation_rules.append(ValidationRule(
            name=f"email_validation_{field}",
            field_path=field,
            validator=ValidationType.EMAIL,
            transform=SanitizationType.EMAIL,
            error_message=f"Invalid email format in field '{field}'"
        ))
    
    shield_instance = InputValidationShield(
        validation_rules=validation_rules,
        auto_sanitize=True,
    )
    return shield_instance.create_shield("EmailValidation")


def create_length_validation_shield(
    field_lengths: Dict[str, Dict[str, int]]
) -> Shield:
    """Create a shield that validates field lengths.
    
    Args:
        field_lengths: Dict mapping field paths to length constraints
                      e.g., {"query.username": {"min_length": 3, "max_length": 20}}
    """
    validation_rules = []
    for field, constraints in field_lengths.items():
        validation_rules.append(ValidationRule(
            name=f"length_validation_{field}",
            field_path=field,
            validator=ValidationType.LENGTH,
            error_message=f"Invalid length for field '{field}'"
        ))
    
    shield_instance = InputValidationShield(validation_rules=validation_rules)
    return shield_instance.create_shield("LengthValidation")


def input_validation_shield(
    validation_rules: List[ValidationRule] = None,
    sanitization_rules: Dict[str, Union[str, Callable]] = None,
    auto_sanitize: bool = True,
    strict_mode: bool = False,
    name: str = "InputValidation",
) -> Shield:
    """Create an input validation shield with custom configuration.
    
    Args:
        validation_rules: List of validation rules
        sanitization_rules: Dict of sanitization rules  
        auto_sanitize: Enable automatic sanitization
        strict_mode: Fail request on validation errors
        name: Shield name
        
    Returns:
        Shield: Configured input validation shield
        
    Examples:
        ```python
        # Basic XSS protection
        @app.post("/submit")
        @input_validation_shield(auto_sanitize=True)
        def submit_form(data: dict):
            return {"status": "success"}
        
        # Custom validation rules
        rules = [
            ValidationRule(
                name="username_validation",
                field_path="body.username",
                validator=ValidationType.REGEX,
                pattern=r'^[a-zA-Z0-9_]{3,20}$',
                error_message="Username must be 3-20 alphanumeric characters"
            )
        ]
        
        @app.post("/register")
        @input_validation_shield(validation_rules=rules, strict_mode=True)
        def register_user(data: dict):
            return {"status": "registered"}
        ```
    """
    shield_instance = InputValidationShield(
        validation_rules=validation_rules,
        sanitization_rules=sanitization_rules,
        auto_sanitize=auto_sanitize,
        strict_mode=strict_mode,
    )
    return shield_instance.create_shield(name)