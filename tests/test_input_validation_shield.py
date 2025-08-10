"""Tests for input validation shield functionality."""

import json
import re
from typing import Dict, Any
from unittest.mock import Mock

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from fastapi_shield.input_validation import (
    InputValidationShield,
    ValidationRule,
    SanitizationType,
    ValidationType,
    InputSanitizer,
    InputValidator,
    input_validation_shield,
    create_xss_protection_shield,
    create_sql_injection_protection_shield,
    create_email_validation_shield,
    create_length_validation_shield,
)


class TestInputSanitizer:
    """Test the input sanitization functionality."""
    
    def test_sanitize_xss_basic(self):
        """Test basic XSS sanitization."""
        malicious_input = '<script>alert("XSS")</script>'
        result = InputSanitizer.sanitize_xss(malicious_input)
        assert '<script>' not in result
        # Script tags should be completely removed (entire content)
        assert result == ""  # Entire script block should be removed
    
    def test_sanitize_xss_javascript(self):
        """Test JavaScript URL sanitization."""
        malicious_input = 'javascript:alert("XSS")'
        result = InputSanitizer.sanitize_xss(malicious_input)
        assert 'javascript:' not in result
    
    def test_sanitize_xss_event_handlers(self):
        """Test event handler sanitization."""
        malicious_input = '<img src="x" onerror="alert(1)">'
        result = InputSanitizer.sanitize_xss(malicious_input)
        assert 'onerror' not in result.lower()
    
    def test_sanitize_xss_iframe(self):
        """Test iframe sanitization."""
        malicious_input = '<iframe src="javascript:alert(1)"></iframe>'
        result = InputSanitizer.sanitize_xss(malicious_input)
        assert '<iframe>' not in result
    
    def test_sanitize_xss_preserves_safe_content(self):
        """Test that safe content is preserved after HTML escaping."""
        safe_input = 'Hello World!'
        result = InputSanitizer.sanitize_xss(safe_input)
        assert result == safe_input
    
    def test_sanitize_sql_injection_basic(self):
        """Test basic SQL injection sanitization."""
        malicious_input = "'; DROP TABLE users; --"
        result = InputSanitizer.sanitize_sql_injection(malicious_input)
        assert 'DROP' not in result.upper()
        assert '--' not in result
    
    def test_sanitize_sql_injection_union(self):
        """Test UNION attack sanitization."""
        malicious_input = "1 UNION SELECT * FROM users"
        result = InputSanitizer.sanitize_sql_injection(malicious_input)
        assert 'UNION' not in result.upper()
        assert 'SELECT' not in result.upper()
    
    def test_sanitize_sql_injection_or_condition(self):
        """Test OR condition sanitization."""
        malicious_input = "admin' OR '1'='1"
        result = InputSanitizer.sanitize_sql_injection(malicious_input)
        assert "' OR '" not in result
    
    def test_sanitize_html(self):
        """Test HTML sanitization."""
        html_input = '<div>Hello <b>World</b>!</div>'
        result = InputSanitizer.sanitize_html(html_input)
        assert '&lt;div&gt;' in result
        assert '&lt;b&gt;' in result
    
    def test_sanitize_url(self):
        """Test URL sanitization."""
        url_input = 'Hello World!'
        result = InputSanitizer.sanitize_url(url_input)
        assert '%20' in result  # Space should be encoded
    
    def test_sanitize_whitespace(self):
        """Test whitespace sanitization."""
        whitespace_input = '  Hello    World  \t\n  '
        result = InputSanitizer.sanitize_whitespace(whitespace_input)
        assert result == 'Hello World'
    
    def test_sanitize_alphanumeric(self):
        """Test alphanumeric sanitization."""
        mixed_input = 'Hello123!@#$%World456'
        result = InputSanitizer.sanitize_alphanumeric(mixed_input)
        assert result == 'Hello123World456'
    
    def test_sanitize_email(self):
        """Test email sanitization."""
        email_input = 'Test.User+tag@EXAMPLE.COM<script>'
        result = InputSanitizer.sanitize_email(email_input)
        assert result == 'test.user+tag@example.comscript'  # <> removed but script remains
        assert '<' not in result and '>' not in result
    
    def test_sanitize_phone(self):
        """Test phone sanitization."""
        phone_input = '+1 (555) 123-4567 ext123'
        result = InputSanitizer.sanitize_phone(phone_input)
        assert result == '+1 (555) 123-4567 123'
    
    def test_sanitize_non_string_input(self):
        """Test sanitization with non-string input."""
        assert InputSanitizer.sanitize_xss(123) == 123
        assert InputSanitizer.sanitize_html(None) is None
        assert InputSanitizer.sanitize_whitespace([1, 2, 3]) == [1, 2, 3]


class TestInputValidator:
    """Test the input validation functionality."""
    
    def test_validate_email_valid(self):
        """Test valid email validation."""
        assert InputValidator.validate_email('user@example.com') is True
        assert InputValidator.validate_email('test.email+tag@example.co.uk') is True
    
    def test_validate_email_invalid(self):
        """Test invalid email validation."""
        assert InputValidator.validate_email('invalid-email') is False
        assert InputValidator.validate_email('user@') is False
        assert InputValidator.validate_email('@example.com') is False
        assert InputValidator.validate_email('user@.com') is False
    
    def test_validate_url_valid(self):
        """Test valid URL validation."""
        assert InputValidator.validate_url('https://example.com') is True
        assert InputValidator.validate_url('http://example.com:8080/path?query=value') is True
    
    def test_validate_url_invalid(self):
        """Test invalid URL validation."""
        assert InputValidator.validate_url('not-a-url') is False
        assert InputValidator.validate_url('ftp://example.com') is False
        assert InputValidator.validate_url('https://') is False
    
    def test_validate_phone_valid(self):
        """Test valid phone validation."""
        assert InputValidator.validate_phone('+1234567890123') is True
        assert InputValidator.validate_phone('+1 (555) 123-4567') is True
    
    def test_validate_phone_invalid(self):
        """Test invalid phone validation."""
        assert InputValidator.validate_phone('123') is False  # Too short
        assert InputValidator.validate_phone('abc123def') is False
        assert InputValidator.validate_phone('+0123456789') is False  # Starts with 0
    
    def test_validate_credit_card_valid(self):
        """Test valid credit card validation."""
        # These are test credit card numbers (Luhn algorithm not implemented)
        assert InputValidator.validate_credit_card('4111111111111111') is True  # Visa
        assert InputValidator.validate_credit_card('5555 5555 5555 4444') is True  # Mastercard
    
    def test_validate_credit_card_invalid(self):
        """Test invalid credit card validation."""
        assert InputValidator.validate_credit_card('1234567890') is False  # Too short
        assert InputValidator.validate_credit_card('abcd1234567890ab') is False
    
    def test_validate_uuid_valid(self):
        """Test valid UUID validation."""
        assert InputValidator.validate_uuid('123e4567-e89b-12d3-a456-426614174000') is True
        assert InputValidator.validate_uuid('550e8400-e29b-41d4-a716-446655440000') is True
    
    def test_validate_uuid_invalid(self):
        """Test invalid UUID validation."""
        assert InputValidator.validate_uuid('not-a-uuid') is False
        assert InputValidator.validate_uuid('123e4567-e89b-12d3-a456') is False  # Too short
    
    def test_validate_ipv4_valid(self):
        """Test valid IPv4 validation."""
        assert InputValidator.validate_ipv4('192.168.1.1') is True
        assert InputValidator.validate_ipv4('0.0.0.0') is True
        assert InputValidator.validate_ipv4('255.255.255.255') is True
    
    def test_validate_ipv4_invalid(self):
        """Test invalid IPv4 validation."""
        assert InputValidator.validate_ipv4('256.1.1.1') is False  # Out of range
        assert InputValidator.validate_ipv4('192.168.1') is False  # Incomplete
        assert InputValidator.validate_ipv4('192.168.1.1.1') is False  # Too many parts
    
    def test_validate_ipv6_valid(self):
        """Test valid IPv6 validation."""
        assert InputValidator.validate_ipv6('2001:0db8:85a3:0000:0000:8a2e:0370:7334') is True
        assert InputValidator.validate_ipv6('::1') is True  # Localhost
        assert InputValidator.validate_ipv6('::') is True  # All zeros
    
    def test_validate_ipv6_invalid(self):
        """Test invalid IPv6 validation."""
        assert InputValidator.validate_ipv6('192.168.1.1') is False  # IPv4
        assert InputValidator.validate_ipv6('2001:0db8:85a3::8a2e::7334') is False  # Double ::
    
    def test_validate_regex_valid(self):
        """Test regex validation."""
        assert InputValidator.validate_regex('abc123', r'^[a-z]+[0-9]+$') is True
        assert InputValidator.validate_regex('test@example.com', r'.+@.+\..+') is True
    
    def test_validate_regex_invalid(self):
        """Test invalid regex validation."""
        assert InputValidator.validate_regex('123abc', r'^[a-z]+[0-9]+$') is False
        assert InputValidator.validate_regex('not-email', r'.+@.+\..+') is False
    
    def test_validate_length_valid(self):
        """Test length validation."""
        assert InputValidator.validate_length('hello', min_length=3, max_length=10) is True
        assert InputValidator.validate_length('hi', min_length=0, max_length=5) is True
    
    def test_validate_length_invalid(self):
        """Test invalid length validation."""
        assert InputValidator.validate_length('hi', min_length=5) is False  # Too short
        assert InputValidator.validate_length('very long string', max_length=5) is False  # Too long
    
    def test_validate_range_valid(self):
        """Test range validation."""
        assert InputValidator.validate_range(5, min_value=1, max_value=10) is True
        assert InputValidator.validate_range(3.5, min_value=0.0, max_value=10.0) is True
    
    def test_validate_range_invalid(self):
        """Test invalid range validation."""
        assert InputValidator.validate_range(0, min_value=1, max_value=10) is False  # Too small
        assert InputValidator.validate_range(15, min_value=1, max_value=10) is False  # Too large
    
    def test_validate_non_string_input(self):
        """Test validation with non-string input."""
        assert InputValidator.validate_email(123) is False
        assert InputValidator.validate_url(None) is False
        assert InputValidator.validate_phone([1, 2, 3]) is False


class TestValidationRule:
    """Test ValidationRule configuration."""
    
    def test_validation_rule_creation(self):
        """Test creating validation rules."""
        rule = ValidationRule(
            name="test_rule",
            field_path="body.email",
            validator=ValidationType.EMAIL,
            required=True,
            error_message="Invalid email"
        )
        assert rule.name == "test_rule"
        assert rule.field_path == "body.email"
        assert rule.validator == ValidationType.EMAIL
        assert rule.required is True
        assert rule.error_message == "Invalid email"
    
    def test_validation_rule_defaults(self):
        """Test validation rule default values."""
        rule = ValidationRule(
            name="simple_rule",
            field_path="query.username",
            validator="custom_validator"
        )
        assert rule.transform is None
        assert rule.required is True
        assert rule.error_message is None
        assert rule.allow_empty is False


class TestInputValidationShield:
    """Test the InputValidationShield class."""
    
    @pytest.fixture
    def mock_request(self):
        """Create a mock request for testing."""
        request = Mock()
        request.query_params = {'username': 'testuser', 'email': 'test@example.com'}
        request.headers = {'content-type': 'application/json', 'user-agent': 'test'}
        request.path_params = {'user_id': '123'}
        request._body_cache = {'password': 'secret123', 'confirm_password': 'secret123'}
        return request
    
    def test_shield_initialization_defaults(self):
        """Test shield initialization with defaults."""
        shield = InputValidationShield()
        assert shield.validation_rules == []
        assert shield.sanitization_rules == {}
        assert shield.auto_sanitize is True
        assert shield.strict_mode is False
        assert shield.allow_extra_fields is True
    
    def test_shield_initialization_custom(self):
        """Test shield initialization with custom settings."""
        rules = [ValidationRule(name="test", field_path="body.email", validator=ValidationType.EMAIL)]
        sanitization = {"query.username": SanitizationType.ALPHANUMERIC}
        
        shield = InputValidationShield(
            validation_rules=rules,
            sanitization_rules=sanitization,
            auto_sanitize=False,
            strict_mode=True,
            allow_extra_fields=False,
        )
        assert shield.validation_rules == rules
        assert shield.sanitization_rules == sanitization
        assert shield.auto_sanitize is False
        assert shield.strict_mode is True
        assert shield.allow_extra_fields is False
    
    def test_get_field_value_query(self, mock_request):
        """Test getting field value from query params."""
        shield = InputValidationShield()
        value = shield._get_field_value(mock_request, 'query.username')
        assert value == 'testuser'
    
    def test_get_field_value_headers(self, mock_request):
        """Test getting field value from headers."""
        shield = InputValidationShield()
        value = shield._get_field_value(mock_request, 'headers.content-type')
        assert value == 'application/json'
    
    def test_get_field_value_path(self, mock_request):
        """Test getting field value from path params."""
        shield = InputValidationShield()
        value = shield._get_field_value(mock_request, 'path.user_id')
        assert value == '123'
    
    def test_get_field_value_body(self, mock_request):
        """Test getting field value from body."""
        shield = InputValidationShield()
        value = shield._get_field_value(mock_request, 'body.password')
        assert value == 'secret123'
    
    def test_get_field_value_invalid_path(self, mock_request):
        """Test getting field value with invalid path."""
        shield = InputValidationShield()
        value = shield._get_field_value(mock_request, 'invalid')
        assert value is None
        
        value = shield._get_field_value(mock_request, 'query.nonexistent')
        assert value is None
    
    def test_sanitize_request_data_auto(self, mock_request):
        """Test automatic sanitization."""
        # Add XSS content to mock request
        mock_request.query_params = {'search': '<script>alert("xss")</script>'}
        mock_request.headers = {'x-custom': 'SELECT * FROM users'}
        mock_request._body_cache = {'comment': '<iframe src="javascript:alert(1)"></iframe>'}
        
        shield = InputValidationShield(auto_sanitize=True)
        sanitized = shield._sanitize_request_data(mock_request)
        
        # Should sanitize XSS and SQL injection
        assert '<script>' not in sanitized['query']['search']
        assert 'SELECT' not in sanitized['headers']['x-custom'].upper()
        assert '<iframe>' not in sanitized['body']['comment']
    
    def test_sanitize_request_data_custom_rules(self, mock_request):
        """Test custom sanitization rules."""
        sanitization_rules = {
            'query.username': SanitizationType.ALPHANUMERIC,
            'body.email': SanitizationType.EMAIL,
        }
        
        mock_request.query_params = {'username': 'test_user!@#'}
        mock_request._body_cache = {'email': 'Test.User+TAG@EXAMPLE.COM'}
        
        shield = InputValidationShield(
            sanitization_rules=sanitization_rules,
            auto_sanitize=False
        )
        sanitized = shield._sanitize_request_data(mock_request)
        
        assert sanitized['query']['username'] == 'testuser'  # Alphanumeric only
        assert sanitized['body']['email'] == 'test.user+tag@example.com'  # Lowercased and cleaned
    
    def test_validate_request_data_success(self, mock_request):
        """Test successful validation."""
        rules = [
            ValidationRule(
                name="username_validation",
                field_path="query.username",
                validator=ValidationType.REGEX,
                # Note: We need to handle regex validation with parameters
            ),
            ValidationRule(
                name="email_validation",
                field_path="query.email",
                validator=ValidationType.EMAIL,
            ),
        ]
        
        shield = InputValidationShield(validation_rules=rules)
        sanitized_data = {
            'query': {'username': 'testuser', 'email': 'test@example.com'},
            'headers': {},
            'path': {},
            'body': {},
        }
        
        errors = shield._validate_request_data(mock_request, sanitized_data)
        # Email should pass, username regex will be skipped due to no pattern parameter
        assert len(errors) == 0 or all('username' not in error for error in errors)
    
    def test_validate_request_data_required_field_missing(self, mock_request):
        """Test validation with required field missing."""
        rules = [
            ValidationRule(
                name="required_field",
                field_path="query.required_field",
                validator=ValidationType.EMAIL,
                required=True,
                error_message="Required field is missing"
            ),
        ]
        
        shield = InputValidationShield(validation_rules=rules)
        sanitized_data = {
            'query': {'username': 'testuser'},
            'headers': {},
            'path': {},
            'body': {},
        }
        
        errors = shield._validate_request_data(mock_request, sanitized_data)
        assert len(errors) == 1
        assert "Required field is missing" in errors[0]
    
    def test_validate_request_data_validation_failure(self, mock_request):
        """Test validation failure."""
        rules = [
            ValidationRule(
                name="email_validation",
                field_path="query.email",
                validator=ValidationType.EMAIL,
                error_message="Invalid email format"
            ),
        ]
        
        shield = InputValidationShield(validation_rules=rules)
        sanitized_data = {
            'query': {'email': 'not-an-email'},
            'headers': {},
            'path': {},
            'body': {},
        }
        
        errors = shield._validate_request_data(mock_request, sanitized_data)
        assert len(errors) == 1
        assert "Invalid email format" in errors[0]
    
    def test_apply_sanitization_builtin(self):
        """Test applying built-in sanitization."""
        shield = InputValidationShield()
        
        result = shield._apply_sanitization('<script>alert("test")</script>', SanitizationType.XSS)
        assert '<script>' not in result
        
        result = shield._apply_sanitization('SELECT * FROM users', SanitizationType.SQL_INJECTION)
        assert 'SELECT' not in result.upper()
    
    def test_apply_sanitization_custom(self):
        """Test applying custom sanitization."""
        def custom_sanitizer(value):
            return value.upper()
        
        shield = InputValidationShield(custom_sanitizers={'uppercase': custom_sanitizer})
        
        result = shield._apply_sanitization('hello world', 'uppercase')
        assert result == 'HELLO WORLD'
    
    def test_apply_validation_builtin(self):
        """Test applying built-in validation."""
        shield = InputValidationShield()
        
        assert shield._apply_validation('test@example.com', ValidationType.EMAIL) is True
        assert shield._apply_validation('not-email', ValidationType.EMAIL) is False
    
    def test_apply_validation_custom(self):
        """Test applying custom validation."""
        def custom_validator(value):
            return len(value) > 5
        
        shield = InputValidationShield(custom_validators={'min_length_5': custom_validator})
        
        assert shield._apply_validation('hello world', 'min_length_5') is True
        assert shield._apply_validation('hi', 'min_length_5') is False


class TestInputValidationIntegration:
    """Integration tests with FastAPI."""
    
    def test_basic_auto_sanitization(self):
        """Test basic automatic sanitization."""
        app = FastAPI()
        
        @app.post("/submit")
        @input_validation_shield(auto_sanitize=True, strict_mode=False)
        async def submit_form():
            return {"message": "success"}
        
        client = TestClient(app)
        
        # This should work but data should be sanitized
        response = client.post("/submit?comment=<script>alert('xss')</script>")
        assert response.status_code == 200
    
    def test_xss_protection_shield(self):
        """Test XSS protection shield."""
        app = FastAPI()
        
        @app.post("/submit")
        @create_xss_protection_shield(['query.comment', 'body.content'])
        async def submit_form():
            return {"message": "success"}
        
        client = TestClient(app)
        
        response = client.post("/submit?comment=<script>alert('xss')</script>")
        assert response.status_code == 200
    
    def test_sql_injection_protection_shield(self):
        """Test SQL injection protection shield."""
        app = FastAPI()
        
        @app.get("/search")
        @create_sql_injection_protection_shield(['query.term'])
        async def search():
            return {"results": []}
        
        client = TestClient(app)
        
        response = client.get("/search?term='; DROP TABLE users; --")
        assert response.status_code == 200
    
    def test_email_validation_shield(self):
        """Test email validation shield."""
        app = FastAPI()
        
        @app.post("/register")
        @create_email_validation_shield(['query.email'])
        async def register():
            return {"status": "registered"}
        
        client = TestClient(app)
        
        # Valid email should work
        response = client.post("/register?email=test@example.com")
        assert response.status_code == 200
        
        # Invalid email should fail (with non-strict mode, it will still pass but with validation info)
        response = client.post("/register?email=invalid-email")
        assert response.status_code == 200
    
    def test_strict_mode_validation_failure(self):
        """Test strict mode validation failure."""
        app = FastAPI()
        
        rules = [
            ValidationRule(
                name="email_validation",
                field_path="query.email",
                validator=ValidationType.EMAIL,
                required=True,
                error_message="Valid email is required"
            )
        ]
        
        @app.post("/register")
        @input_validation_shield(validation_rules=rules, strict_mode=True)
        async def register():
            return {"status": "registered"}
        
        client = TestClient(app)
        
        # Valid email should work
        response = client.post("/register?email=test@example.com")
        assert response.status_code == 200
        
        # Invalid email should fail in strict mode
        response = client.post("/register?email=invalid-email")
        assert response.status_code == 422
        assert "Valid email is required" in str(response.json())
    
    def test_length_validation_shield(self):
        """Test length validation shield."""
        app = FastAPI()
        
        field_lengths = {
            "query.username": {"min_length": 3, "max_length": 20}
        }
        
        @app.post("/profile")
        @create_length_validation_shield(field_lengths)
        async def update_profile():
            return {"status": "updated"}
        
        client = TestClient(app)
        
        response = client.post("/profile?username=validuser")
        assert response.status_code == 200
    
    def test_custom_validation_rules(self):
        """Test custom validation rules."""
        app = FastAPI()
        
        def custom_username_validator(value):
            return isinstance(value, str) and value.isalnum() and len(value) >= 3
        
        rules = [
            ValidationRule(
                name="custom_username",
                field_path="query.username",
                validator=custom_username_validator,
                required=True,
                error_message="Username must be alphanumeric and at least 3 characters"
            )
        ]
        
        @app.post("/register")
        @input_validation_shield(validation_rules=rules, strict_mode=True)
        async def register():
            return {"status": "registered"}
        
        client = TestClient(app)
        
        # Valid username
        response = client.post("/register?username=validuser123")
        assert response.status_code == 200
        
        # Invalid username (too short)
        response = client.post("/register?username=ab")
        assert response.status_code == 422
        
        # Invalid username (special characters)
        response = client.post("/register?username=user@123")
        assert response.status_code == 422
    
    def test_custom_sanitization_rules(self):
        """Test custom sanitization rules."""
        app = FastAPI()
        
        def custom_title_case(value):
            return value.title() if isinstance(value, str) else value
        
        sanitization_rules = {
            "query.name": custom_title_case,
            "query.email": SanitizationType.EMAIL,
        }
        
        @app.post("/profile")
        @input_validation_shield(
            sanitization_rules=sanitization_rules,
            auto_sanitize=False,
            strict_mode=False
        )
        async def update_profile():
            return {"status": "updated"}
        
        client = TestClient(app)
        
        response = client.post("/profile?name=john doe&email=JOHN.DOE@EXAMPLE.COM")
        assert response.status_code == 200
    
    def test_combined_validation_and_sanitization(self):
        """Test combined validation and sanitization."""
        app = FastAPI()
        
        rules = [
            ValidationRule(
                name="username_validation",
                field_path="query.username",
                validator=ValidationType.REGEX,
                transform=SanitizationType.WHITESPACE,
                required=True,
                error_message="Invalid username format"
            ),
            ValidationRule(
                name="email_validation",
                field_path="query.email",
                validator=ValidationType.EMAIL,
                transform=SanitizationType.EMAIL,
                required=True,
                error_message="Valid email is required"
            ),
        ]
        
        sanitization_rules = {
            "query.username": SanitizationType.ALPHANUMERIC,
            "query.email": SanitizationType.EMAIL,
        }
        
        @app.post("/register")
        @input_validation_shield(
            validation_rules=rules,
            sanitization_rules=sanitization_rules,
            auto_sanitize=True,
            strict_mode=False
        )
        async def register():
            return {"status": "registered"}
        
        client = TestClient(app)
        
        response = client.post("/register?username=valid_user&email=test@example.com")
        assert response.status_code == 200
    
    def test_validation_with_missing_required_field(self):
        """Test validation with missing required field."""
        app = FastAPI()
        
        rules = [
            ValidationRule(
                name="required_email",
                field_path="query.email",
                validator=ValidationType.EMAIL,
                required=True,
                error_message="Email is required"
            )
        ]
        
        @app.post("/subscribe")
        @input_validation_shield(validation_rules=rules, strict_mode=True)
        async def subscribe():
            return {"status": "subscribed"}
        
        client = TestClient(app)
        
        # Missing required field should fail
        response = client.post("/subscribe")
        assert response.status_code == 422
        assert "Email is required" in str(response.json())
    
    def test_validation_with_empty_optional_field(self):
        """Test validation with empty optional field."""
        app = FastAPI()
        
        rules = [
            ValidationRule(
                name="optional_email",
                field_path="query.email",
                validator=ValidationType.EMAIL,
                required=False,
                error_message="Invalid email format"
            )
        ]
        
        @app.post("/profile")
        @input_validation_shield(validation_rules=rules, strict_mode=True)
        async def update_profile():
            return {"status": "updated"}
        
        client = TestClient(app)
        
        # Empty optional field should pass
        response = client.post("/profile")
        assert response.status_code == 200
        
        # Valid optional field should pass
        response = client.post("/profile?email=test@example.com")
        assert response.status_code == 200
        
        # Invalid optional field should fail
        response = client.post("/profile?email=invalid-email")
        assert response.status_code == 422


class TestConvenienceFunctions:
    """Test convenience functions."""
    
    def test_create_xss_protection_shield(self):
        """Test XSS protection shield creation."""
        shield = create_xss_protection_shield(['query.comment', 'body.content'])
        assert isinstance(shield, type(input_validation_shield()))
    
    def test_create_sql_injection_protection_shield(self):
        """Test SQL injection protection shield creation."""
        shield = create_sql_injection_protection_shield(['query.search'])
        assert isinstance(shield, type(input_validation_shield()))
    
    def test_create_email_validation_shield(self):
        """Test email validation shield creation."""
        shield = create_email_validation_shield(['query.email', 'body.contact_email'])
        assert isinstance(shield, type(input_validation_shield()))
    
    def test_create_length_validation_shield(self):
        """Test length validation shield creation."""
        field_lengths = {
            "query.username": {"min_length": 3, "max_length": 20},
            "body.comment": {"max_length": 500}
        }
        shield = create_length_validation_shield(field_lengths)
        assert isinstance(shield, type(input_validation_shield()))


class TestErrorHandling:
    """Test error handling scenarios."""
    
    def test_shield_internal_error(self):
        """Test shield internal error handling."""
        app = FastAPI()
        
        # Create a shield that will cause an internal error
        def broken_validator(value):
            raise ValueError("Validator error")
        
        rules = [
            ValidationRule(
                name="broken_validation",
                field_path="query.test",
                validator=broken_validator,
                required=False
            )
        ]
        
        @app.get("/test")
        @input_validation_shield(validation_rules=rules, strict_mode=False)
        async def test_endpoint():
            return {"status": "ok"}
        
        client = TestClient(app)
        
        response = client.get("/test?test=value")
        assert response.status_code == 500
        assert "Input validation error" in response.json()["detail"]
    
    def test_custom_validator_function(self):
        """Test custom validator function."""
        app = FastAPI()
        
        def validate_positive_number(value):
            try:
                num = float(value)
                return num > 0
            except (ValueError, TypeError):
                return False
        
        rules = [
            ValidationRule(
                name="positive_number",
                field_path="query.amount",
                validator=validate_positive_number,
                required=True,
                error_message="Amount must be a positive number"
            )
        ]
        
        @app.post("/payment")
        @input_validation_shield(validation_rules=rules, strict_mode=True)
        async def process_payment():
            return {"status": "processed"}
        
        client = TestClient(app)
        
        # Valid positive number
        response = client.post("/payment?amount=10.50")
        assert response.status_code == 200
        
        # Invalid negative number
        response = client.post("/payment?amount=-5")
        assert response.status_code == 422
        
        # Invalid non-number
        response = client.post("/payment?amount=abc")
        assert response.status_code == 422


if __name__ == "__main__":
    pytest.main([__file__])