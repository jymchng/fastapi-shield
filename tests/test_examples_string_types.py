import pytest
from fastapi.testclient import TestClient
from fastapi import Body, FastAPI, Header, Path, Form, HTTPException, Depends, status, Request
from fastapi_shield import shield, ShieldedDepends
from typing import NewType, Dict
from pydantic import BaseModel, EmailStr, constr, HttpUrl, StringConstraints
import re
import html


class TestBasicStringValidation:
    """Tests for basic string validation as shown in string-types.md"""
    
    def setup_method(self):
        """Setup the FastAPI app for each test"""
        app = FastAPI()
        
        @shield(
            name="API Key Validator",
            exception_to_raise_if_fail=HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key format"
            )
        )
        def api_key_validator(x_api_key: str = Header()):
            """Validate that the API key follows the required format"""
            # Example pattern: must be alphanumeric, 32 characters
            pattern = re.compile(r'^[a-zA-Z0-9]{32}$')
            
            if pattern.match(x_api_key):
                return x_api_key
            return None
        
        @app.get("/protected")
        @api_key_validator
        async def protected_endpoint():
            return {"message": "Access granted"}
            
        self.app = app
        self.client = TestClient(app)
    
    def test_valid_api_key(self):
        """Test with a valid API key"""
        valid_key = "a" * 32
        response = self.client.get("/protected", headers={"x-api-key": valid_key})
        assert response.status_code == 200
        assert response.json() == {"message": "Access granted"}
    
    def test_invalid_api_key_format(self):
        """Test with an invalid API key format"""
        invalid_key = "abc123"  # Too short
        response = self.client.get("/protected", headers={"x-api-key": invalid_key})
        assert response.status_code == 401
        assert response.json() == {"detail": "Invalid API key format"}
    
    def test_missing_api_key(self):
        """Test without an API key"""
        response = self.client.get("/protected")
        assert response.status_code == 422  # Validation error for missing header


class TestCustomStringTypes:
    """Tests for custom string types using NewType as shown in string-types.md"""
    
    def setup_method(self):
        """Setup the FastAPI app for each test"""
        app = FastAPI()
        
        # Define custom string types
        ApiKey = NewType("ApiKey", str)
        BearerToken = NewType("BearerToken", str)
        EmailAddress = NewType("EmailAddress", str)
        
        # Validation functions
        def is_valid_api_key(value: str) -> bool:
            return bool(re.match(r'^[a-zA-Z0-9]{32}$', value))
        
        def is_valid_bearer_token(value: str) -> bool:
            # JWT typically starts with "eyJ" after removing "Bearer "
            if value.startswith("Bearer "):
                token = value[7:]
                return token.startswith("eyJ") and "." in token
            return False
        
        def is_valid_email(value: str) -> bool:
            return bool(re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value))
        
        # Shield factories for each type
        def api_key_shield():
            @shield(name="API Key Shield")
            def validator(x_api_key: str = Header()):
                if is_valid_api_key(x_api_key):
                    return ApiKey(x_api_key)
                return None
            return validator
        
        def bearer_token_shield():
            @shield(name="Bearer Token Shield")
            def validator(authorization: str = Header()):
                if is_valid_bearer_token(authorization):
                    return BearerToken(authorization)
                return None
            return validator
        
        def email_shield():
            @shield(name="Email Shield") 
            def validator(email: str = Header()):
                if is_valid_email(email):
                    return EmailAddress(email)
                return None
            return validator
        
        @app.get("/api-key-protected")
        @api_key_shield()
        async def api_key_endpoint():
            return {"message": "API key validated"}
        
        @app.get("/jwt-protected")
        @bearer_token_shield()
        async def jwt_endpoint():
            return {"message": "Bearer token validated"}
        
        @app.get("/email-protected")
        @email_shield()
        async def email_endpoint():
            return {"message": "Email validated"}
            
        self.app = app
        self.client = TestClient(app)
    
    def test_valid_api_key(self):
        """Test with a valid API key"""
        valid_key = "a" * 32
        response = self.client.get("/api-key-protected", headers={"x-api-key": valid_key})
        assert response.status_code == 200
        assert response.json() == {"message": "API key validated"}
    
    def test_invalid_api_key(self):
        """Test with an invalid API key"""
        invalid_key = "invalid"
        response = self.client.get("/api-key-protected", headers={"x-api-key": invalid_key})
        assert response.status_code == 500  # Default shield error
    
    def test_valid_bearer_token(self):
        """Test with a valid bearer token"""
        valid_token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        response = self.client.get("/jwt-protected", headers={"authorization": valid_token})
        assert response.status_code == 200
        assert response.json() == {"message": "Bearer token validated"}
    
    def test_invalid_bearer_token(self):
        """Test with an invalid bearer token"""
        invalid_token = "Bearer invalid-token"
        response = self.client.get("/jwt-protected", headers={"authorization": invalid_token})
        assert response.status_code == 500  # Default shield error
    
    def test_valid_email(self):
        """Test with a valid email"""
        valid_email = "user@example.com"
        response = self.client.get("/email-protected", headers={"email": valid_email})
        assert response.status_code == 200
        assert response.json() == {"message": "Email validated"}
    
    def test_invalid_email(self):
        """Test with an invalid email"""
        invalid_email = "not-an-email"
        response = self.client.get("/email-protected", headers={"email": invalid_email})
        assert response.status_code == 500  # Default shield error


class TestPydanticStringValidation:
    """Tests for Pydantic string validation as shown in string-types.md"""
    
    def setup_method(self):
        """Setup the FastAPI app for each test"""
        app = FastAPI()
        
        try:
            # Some environments might not have all Pydantic features
            class UserInput(BaseModel):
                username: constr(min_length=3, max_length=20, pattern=r'^[a-zA-Z0-9_]+$')
                email: EmailStr
                website: HttpUrl
                bio: constr(max_length=200)
            
            @shield(name="User Input Validator")
            def validate_user_input(user: UserInput = Body()):
                """Shield that validates user input using Pydantic"""
                # If we get here, Pydantic has already validated the input
                # Return the user object for the endpoint to use
                return user
            
            @app.post("/users")
            @validate_user_input
            async def create_user(validated_user: UserInput = ShieldedDepends(lambda user: user)):
                # Check if dict() method exists (Pydantic v1) or model_dump() (Pydantic v2)
                if hasattr(validated_user, "model_dump"):
                    user_dict = validated_user.model_dump()
                else:
                    user_dict = validated_user.dict()
                
                return {
                    "message": "User created successfully",
                    "user": user_dict
                }
                
            self.pydantic_available = True
        except (ImportError, AttributeError) as e:
            # Skip tests if Pydantic features are not available
            print(f"Pydantic test skipped due to: {str(e)}")
            self.pydantic_available = False
            
        self.app = app
        self.client = TestClient(app)
    
    def test_valid_user_input(self):
        """Test with valid user input"""
        if not self.pydantic_available:
            pytest.skip("Pydantic features not available")
            
        valid_input = {
            "username": "johndoe",
            "email": "john@example.com",
            "website": "https://example.com",
            "bio": "This is my bio"
        }
        response = self.client.post("/users", json=valid_input)
        assert response.status_code == 200, response.json()
        assert response.json()["message"] == "User created successfully"
        assert response.json()["user"]["username"] == "johndoe"
    
    def test_invalid_username(self):
        """Test with invalid username"""
        if not self.pydantic_available:
            pytest.skip("Pydantic features not available")
            
        invalid_input = {
            "username": "j",  # Too short
            "email": "john@example.com",
            "website": "https://example.com",
            "bio": "This is my bio"
        }
        response = self.client.post("/users", json=invalid_input)
        assert response.status_code == 422  # Pydantic validation error
        assert response.json()["detail"] == [{'type': 'string_too_short', 'loc': ['body', 'username'], 'msg': 'String should have at least 3 characters', 'input': 'j', 'ctx': {'min_length': 3}}]
    
    def test_invalid_email(self):
        """Test with invalid email"""
        if not self.pydantic_available:
            pytest.skip("Pydantic features not available")
            
        invalid_input = {
            "username": "johndoe",
            "email": "not-an-email",
            "website": "https://example.com",
            "bio": "This is my bio"
        }
        response = self.client.post("/users", json=invalid_input)
        assert response.status_code == 422  # Pydantic validation error
        assert response.json()["detail"] ==  [{'type': 'value_error', 'loc': ['body', 'email'], 'msg': 'value is not a valid email address: An email address must have an @-sign.', 'input': 'not-an-email', 'ctx': {'reason': 'An email address must have an @-sign.'}}]


class TestStringTransformation:
    """Tests for string transformation as shown in string-types.md"""
    
    def setup_method(self):
        """Setup the FastAPI app for each test"""
        app = FastAPI()
        
        @shield(name="HTML Sanitizer")
        def sanitize_html_input(content: str = Form()):
            """Shield that sanitizes HTML content to prevent XSS attacks"""
            if not content:
                return None
            
            # Escape HTML special characters
            sanitized = html.escape(content)
            
            # Return the sanitized content directly
            return sanitized
        
        @app.post("/comments")
        @sanitize_html_input
        async def create_comment(sanitized_content: str = ShieldedDepends(lambda content: content)):
            # Use the sanitized content
            return {
                "message": "Comment created",
                "content": sanitized_content
            }
            
        self.app = app
        self.client = TestClient(app)
    
    def test_sanitize_html(self):
        """Test HTML sanitization"""
        html_content = "<script>alert('XSS')</script><b>Hello</b>"
        response = self.client.post(
            "/comments", 
            data={"content": html_content}
        )
        assert response.status_code == 200
        assert response.json()["message"] == "Comment created"
        assert response.json()["content"] == "&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;&lt;b&gt;Hello&lt;/b&gt;"
    
    def test_empty_content(self):
        """Test with empty content"""
        response = self.client.post(
            "/comments", 
            data={"content": ""}
        )
        assert response.status_code == 500  # Shield rejects empty content


class TestRegexValidation:
    """Tests for regex validation as shown in string-types.md"""
    
    def setup_method(self):
        """Setup the FastAPI app for each test"""
        app = FastAPI()
        
        def regex_shield(pattern: str, error_message: str):
            """Factory function to create shields that validate strings against a regex pattern"""
            compiled_pattern = re.compile(pattern)
            
            @shield(
                name=f"Regex Shield ({pattern})",
                exception_to_raise_if_fail=HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=error_message
                )
            )
            def validator(request: Request):
                # Get path parameter from request path directly
                path = request.path_params.get("username") or request.path_params.get("product_id")
                if path and compiled_pattern.match(path):
                    return path
                return None
                
            return validator
        
        # Create specialized shields
        username_shield = regex_shield(
            pattern=r'^[a-zA-Z0-9_]{3,20}$',
            error_message="Username must be 3-20 alphanumeric characters or underscores"
        )
        
        product_id_shield = regex_shield(
            pattern=r'^PROD-[A-Z0-9]{10}$',
            error_message="Product ID must be in format PROD-XXXXXXXXXX (10 alphanumeric characters)"
        )
        
        @app.get("/users/{username}")
        @username_shield
        async def get_user(username: str):
            return {"message": f"Valid username: {username}"}
        
        @app.get("/products/{product_id}")
        @product_id_shield
        async def get_product(product_id: str):
            return {"message": f"Valid product ID: {product_id}"}
            
        self.app = app
        self.client = TestClient(app)
    
    def test_valid_username(self):
        """Test with a valid username"""
        response = self.client.get("/users/johndoe123")
        assert response.status_code == 200
        assert response.json() == {"message": "Valid username: johndoe123"}
    
    def test_invalid_username(self):
        """Test with an invalid username"""
        response = self.client.get("/users/j")  # Too short
        assert response.status_code == 400
        assert response.json() == {"detail": "Username must be 3-20 alphanumeric characters or underscores"}
        
        response = self.client.get("/users/user-with-hyphens")  # Contains hyphens
        assert response.status_code == 400
        assert response.json() == {"detail": "Username must be 3-20 alphanumeric characters or underscores"}
    
    def test_valid_product_id(self):
        """Test with a valid product ID"""
        response = self.client.get("/products/PROD-1234567890")
        assert response.status_code == 200
        assert response.json() == {"message": "Valid product ID: PROD-1234567890"}
    
    def test_invalid_product_id(self):
        """Test with an invalid product ID"""
        response = self.client.get("/products/PRODUCT-123")  # Wrong format
        assert response.status_code == 400
        assert response.json() == {"detail": "Product ID must be in format PROD-XXXXXXXXXX (10 alphanumeric characters)"}
        
        response = self.client.get("/products/prod-1234567890")  # Lowercase
        assert response.status_code == 400
        assert response.json() == {"detail": "Product ID must be in format PROD-XXXXXXXXXX (10 alphanumeric characters)"} 