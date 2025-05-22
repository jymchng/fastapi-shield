<!-- Examples Tested -->

# String Types

FastAPI Shield provides special support for working with string types in your shields and endpoints.

## String Validation in Shields

When working with string inputs in shields, you often need to validate them against specific patterns or rules. FastAPI Shield integrates well with FastAPI's validation mechanisms.

### Basic String Validation

```python
from fastapi import FastAPI, Header, HTTPException, status
from fastapi_shield import shield
import re

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
```

## Working with String Types

Python's typing system allows you to create more specific string types using `NewType` from the `typing` module. FastAPI Shield works well with these custom string types.

### Creating Custom String Types

```python
from typing import NewType
from fastapi import FastAPI, Header
from fastapi_shield import shield
import re

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

app = FastAPI()

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
```

## Using Pydantic for String Validation

Pydantic provides powerful validation capabilities for strings that can be used with FastAPI Shield:

```python
from fastapi import FastAPI, Body
from fastapi_shield import shield, ShieldedDepends
from pydantic import BaseModel, EmailStr, constr, HttpUrl
from typing import Dict

app = FastAPI()

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
    # Handle both Pydantic v1 and v2
    if hasattr(validated_user, "model_dump"):
        user_dict = validated_user.model_dump()
    else:
        user_dict = validated_user.dict()
    
    return {
        "message": "User created successfully",
        "user": user_dict
    }
```

## String Transformation

Shields can also transform string inputs before they reach your endpoint:

```python
from fastapi import FastAPI, Form, HTTPException, status
from fastapi_shield import shield, ShieldedDepends
import html

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
```

## Custom String Validation with Regular Expressions

For more complex string validation, you can use regular expressions with the Request object:

```python
from fastapi import FastAPI, Request, HTTPException, status
from fastapi_shield import shield
import re

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
```

These patterns provide powerful ways to work with string types in your FastAPI Shield applications. The examples above demonstrate the recommended approach to handle different string validation and transformation scenarios. 