# Security Best Practices

This guide outlines best practices for securing your FastAPI applications using FastAPI Shield.

## General Security Principles

When implementing security with FastAPI Shield, follow these core principles:

1. **Defense in Depth**: Apply multiple layers of security shields
2. **Least Privilege**: Restrict access to only what's necessary
3. **Secure by Default**: Start with maximum security and relax as needed
4. **Fail Securely**: Always fail closed, not open

## Secure Authentication

Authentication is the process of verifying who a user is. FastAPI Shield provides robust tools for implementing authentication:

```python
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi_shield import shield, ShieldedDepends
from typing import Optional
import jwt

app = FastAPI()

# Authentication shield as a decorator
@shield(
    name="Authenticate User",
    exception_to_raise_if_fail=HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"}
    )
)
def authenticate_user(authorization: str = Depends()):
    if not authorization or not authorization.startswith("Bearer "):
        return None
        
    token = authorization.replace("Bearer ", "")
    
    try:
        # Verify JWT token
        payload = jwt.decode(
            token, 
            "YOUR_SECRET_KEY",  # Store this securely!
            algorithms=["HS256"]
        )
        user_id = payload.get("sub")
        if not user_id:
            return None
            
        # Return authenticated user data
        return {"user_id": user_id, "payload": payload}
    except jwt.PyJWTError:
        return None

# Protected endpoint
@app.get("/protected-resource")
@authenticate_user
def protected_resource(user: dict = ShieldedDepends(authenticate_user)):
    return {"message": f"Hello user {user['user_id']}"}
```

## Content Security

Sanitize user-generated content to prevent XSS and other injection attacks:

```python
from fastapi import FastAPI, Depends
from fastapi_shield import shield, ShieldedDepends
from typing import Optional
import re
import html

app = FastAPI()

# Content sanitization shield
@shield(name="Sanitize Comment")
def sanitize_comment(comment: str):
    # Strip potentially dangerous HTML
    sanitized = html.escape(comment)
    
    # Limit comment length
    if len(sanitized) > 1000:
        sanitized = sanitized[:1000] + "..."
        
    # Additional validation rules
    if re.search(r'(script|javascript|eval\(|<iframe)', comment, re.IGNORECASE):
        return None
        
    return sanitized

# Create comment endpoint
@app.post("/comments")
def create_comment(clean_comment: str = ShieldedDepends(sanitize_comment)):
    # Store sanitized comment
    db.comments.add(clean_comment)
    return {"status": "Comment added successfully"}
```

## Input Validation

Validate all inputs before processing:

```python
from fastapi import FastAPI, Depends, HTTPException
from fastapi_shield import shield, ShieldedDepends
from pydantic import BaseModel, EmailStr, validator
import re

class RegistrationData(BaseModel):
    username: str
    email: EmailStr
    password: str
    
    @validator('username')
    def username_must_be_valid(cls, v):
        if not v or not re.match(r'^[a-zA-Z0-9_-]{3,16}$', v):
            raise ValueError('Invalid username format')
        return v
        
    @validator('password')
    def password_must_be_strong(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain an uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain a lowercase letter')
        if not re.search(r'[0-9]', v):
            raise ValueError('Password must contain a number')
        return v

@shield(
    name="Validate Registration",
    exception_to_raise_if_fail=HTTPException(
        status_code=400,
        detail="Invalid registration data"
    )
)
def validate_registration(registration: RegistrationData):
    # Check if username already exists (example)
    existing_user = db.users.find_by_username(registration.username)
    if existing_user:
        return None
        
    # Check if email already exists
    existing_email = db.users.find_by_email(registration.email)
    if existing_email:
        return None
        
    return registration

@app.post("/register")
@validate_registration
def register_user(registration: RegistrationData = ShieldedDepends(validate_registration)):
    # Process valid registration
    hashed_password = hash_password(registration.password)
    user_id = db.users.create(
        username=registration.username,
        email=registration.email,
        password=hashed_password
    )
    return {"status": "success", "user_id": user_id}
```

## Rate Limiting

Protect against abuse by implementing rate limits:

```python
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi_shield import shield, ShieldedDepends
import time
from collections import defaultdict

# Simple in-memory rate limiter (use Redis in production)
request_counts = defaultdict(list)

@shield(
    name="Rate Limit",
    exception_to_raise_if_fail=HTTPException(
        status_code=429,
        detail="Too many requests",
        headers={"Retry-After": "60"}
    )
)
def rate_limit(request: Request):
    client_ip = request.client.host
    now = time.time()
    
    # Remove old requests
    request_counts[client_ip] = [t for t in request_counts[client_ip] if t > now - 60]
    
    # Check if too many requests
    if len(request_counts[client_ip]) >= 20:  # 20 requests per minute
        return None
        
    # Add current request
    request_counts[client_ip].append(now)
    
    return client_ip

@app.post("/api/submit")
@rate_limit
def submit_data(client_ip: str = ShieldedDepends(rate_limit), data: dict = None):
    # Process the submission
    return {"status": "Data received successfully"}
```

## Secure API Key Management

Protect API keys with proper shield validation:

```python
from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi_shield import shield, ShieldedDepends
import secrets

app = FastAPI()

# Maintain keys securely (use a database in production)
valid_api_keys = {
    "client1": "sk_test_abcdefghijklmnopqrstuvwxyz123456",
    "client2": "sk_test_zyxwvutsrqponmlkjihgfedcba654321"
}

@shield(
    name="Validate API Key",
    exception_to_raise_if_fail=HTTPException(
        status_code=401,
        detail="Invalid API key"
    )
)
def validate_api_key(api_key: str = Header(...)):
    # Check if API key exists and is valid
    for client, key in valid_api_keys.items():
        # Use constant-time comparison to prevent timing attacks
        if secrets.compare_digest(api_key, key):
            return {"client_id": client, "api_key": api_key}
    
    return None

@app.get("/api/data")
@validate_api_key
def get_data(api_client: dict = ShieldedDepends(validate_api_key)):
    # Retrieve data for the authenticated client
    return {
        "client": api_client["client_id"],
        "data": f"Secure data for {api_client['client_id']}"
    }
```

## SQL Injection Prevention

Use parameterized queries and validate inputs to prevent SQL injection:

```python
from fastapi import FastAPI, Depends, HTTPException
from fastapi_shield import shield, ShieldedDepends
import re
import sqlite3

app = FastAPI()

# Connect to database (use async DB with SQLAlchemy in production)
def get_db():
    conn = sqlite3.connect("example.db")
    conn.row_factory = sqlite3.Row
    return conn

@shield(
    name="SQL Safe User ID",
    exception_to_raise_if_fail=HTTPException(
        status_code=400,
        detail="Invalid user ID"
    )
)
def validate_user_id(user_id: str):
    # Only allow numeric user IDs
    if not user_id or not re.match(r'^\d+$', user_id):
        return None
    return user_id

@app.get("/users/{user_id}")
@validate_user_id
def get_user(user_id: str = ShieldedDepends(validate_user_id)):
    db = get_db()
    # Use parameterized query to prevent SQL injection
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    return dict(user)
```

## Secure File Handling

Validate file uploads to prevent attacks:

```python
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File
from fastapi_shield import shield, ShieldedDepends
import magic
import os

app = FastAPI()

@shield(
    name="Validate File",
    exception_to_raise_if_fail=HTTPException(
        status_code=400,
        detail="Invalid file"
    )
)
async def validate_file(file: UploadFile = File(...)):
    # Check file size (limit to 5MB)
    content = await file.read()
    await file.seek(0)  # Reset file position after reading
    
    if len(content) > 5 * 1024 * 1024:  # 5MB
        return None
        
    # Check MIME type with python-magic
    mime = magic.Magic(mime=True)
    file_type = mime.from_buffer(content)
    
    # Allow only certain file types
    allowed_types = ["image/jpeg", "image/png", "application/pdf"]
    if file_type not in allowed_types:
        return None
        
    # Check file extension matches content
    filename = file.filename
    ext = os.path.splitext(filename)[1].lower()
    
    valid_extensions = {
        "image/jpeg": [".jpg", ".jpeg"],
        "image/png": [".png"],
        "application/pdf": [".pdf"]
    }
    
    if ext not in valid_extensions.get(file_type, []):
        return None
        
    return file

@app.post("/upload")
@validate_file
async def upload_file(file: UploadFile = ShieldedDepends(validate_file)):
    # Process the validated file
    file_location = f"uploads/{file.filename}"
    with open(file_location, "wb") as f:
        file_content = await file.read()
        f.write(file_content)
        
    return {"filename": file.filename, "status": "File saved successfully"}
```

## CSRF Protection

Implement Cross-Site Request Forgery protection:

```python
from fastapi import FastAPI, Depends, HTTPException, Cookie, Request, Form
from fastapi_shield import shield, ShieldedDepends
import secrets
import time

app = FastAPI()

# Store tokens (use Redis in production)
csrf_tokens = {}

# Generate a token and set as cookie
@app.get("/get-csrf-token")
def get_csrf_token(request: Request):
    token = secrets.token_hex(32)
    expiry = time.time() + 3600  # 1 hour
    csrf_tokens[token] = expiry
    
    response = {"status": "success"}
    response.set_cookie(
        key="csrf_token",
        value=token,
        httponly=True,
        secure=True,
        samesite="strict"
    )
    return response

@shield(
    name="CSRF Protection",
    exception_to_raise_if_fail=HTTPException(
        status_code=403,
        detail="CSRF token validation failed"
    )
)
def validate_csrf(
    csrf_token_cookie: str = Cookie(None),
    csrf_token_header: str = Header(None)
):
    # No token provided
    if not csrf_token_cookie or not csrf_token_header:
        return None
        
    # Tokens don't match
    if csrf_token_cookie != csrf_token_header:
        return None
        
    # Token expired or invalid
    expiry = csrf_tokens.get(csrf_token_cookie)
    if not expiry or expiry < time.time():
        return None
        
    return csrf_token_cookie

@app.post("/submit-form")
@validate_csrf
def submit_form(
    csrf_token: str = ShieldedDepends(validate_csrf),
    name: str = Form(...),
    email: str = Form(...)
):
    # Process the validated form submission
    return {"status": "Form submitted successfully"}
```

## Security Checklist

Use this checklist when implementing security with FastAPI Shield:

- ✅ Use shields as decorators, not as function calls
- ✅ Give descriptive names to your shields for better debugging
- ✅ Layer multiple shields for defense in depth
- ✅ Return None from shields that fail validation
- ✅ Raise specific HTTP exceptions with clear error messages
- ✅ Use proper typing with NewType for type safety
- ✅ Implement rate limiting for public endpoints
- ✅ Validate all user inputs with appropriate shields
- ✅ Use secure password storage with Argon2, bcrypt, or PBKDF2
- ✅ Implement proper CORS policies
- ✅ Set secure cookie attributes
- ✅ Apply contextual authorization (object-level permissions)
- ✅ Log security events and monitor for suspicious activity
- ✅ Use ShieldedDepends for proper dependency injection
- ✅ Keep security shields in separate modules for reusability

By following these best practices, you can create FastAPI applications that are both functional and secure, leveraging FastAPI Shield's powerful protection mechanisms. 