<!--Examples tested-->

# Security Best Practices

This guide outlines best practices for securing your FastAPI applications using FastAPI Shield, based on real-world patterns and proven implementations.

## General Security Principles

When implementing security with FastAPI Shield, follow these core principles:

1. **Defense in Depth**: Apply multiple layers of security shields
2. **Least Privilege**: Restrict access to only what's necessary
3. **Secure by Default**: Start with maximum security and relax as needed
4. **Fail Securely**: Always fail closed, not open

## Secure Authentication

Authentication is the process of verifying who a user is. FastAPI Shield provides robust tools for implementing authentication using the decorator pattern.

### JWT Authentication

```python
from fastapi import FastAPI, Header, HTTPException, status
from fastapi_shield import shield, ShieldedDepends
import jwt
from jwt.exceptions import PyJWTError

app = FastAPI()

# Configuration
JWT_SECRET = "your-secret-key"  # Store this securely!
JWT_ALGORITHM = "HS256"

@shield(
    name="JWT Authentication",
    exception_to_raise_if_fail=HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"}
    )
)
def jwt_auth_shield(authorization: str = Header()) -> dict:
    """Validate JWT token and return decoded payload"""
    if not authorization.startswith("Bearer "):
        return None
    
    token = authorization.replace("Bearer ", "")
    
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except PyJWTError:
        return None

# Protected endpoint
@app.get("/protected")
@jwt_auth_shield
async def protected_endpoint(
    payload: dict = ShieldedDepends(lambda payload: payload)
):
    return {
        "message": "Access granted",
        "user": payload.get("sub"),
        "roles": payload.get("roles", [])
    }
```

### Basic Authentication

```python
import secrets
import base64
from fastapi import Header, HTTPException, status
from fastapi_shield import shield, ShieldedDepends

# Mock user database (use proper database in production)
USERS = {
    "admin": "strongpassword",
    "user": "userpassword",
}

@shield(
    name="Basic Authentication",
    exception_to_raise_if_fail=HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Basic"}
    )
)
def basic_auth_shield(authorization: str = Header()) -> str:
    """Validate basic authentication credentials"""
    if not authorization or not authorization.startswith("Basic "):
        return None
    
    auth_data = authorization.replace("Basic ", "")
    try:
        decoded = base64.b64decode(auth_data).decode("ascii")
        username, password = decoded.split(":")
    except Exception:
        return None
    
    # Validate username format
    if len(username) < 3:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username must be at least 3 characters"
        )
    
    # Validate password format
    if len(password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters"
        )
    
    # Check credentials
    if username not in USERS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username",
            headers={"WWW-Authenticate": "Basic"}
        )
    
    # Use constant-time comparison to prevent timing attacks
    if not secrets.compare_digest(password, USERS[username]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid password",
            headers={"WWW-Authenticate": "Basic"}
        )
    
    return username

@app.get("/secure-data")
@basic_auth_shield
async def get_secure_data(
    username: str = ShieldedDepends(lambda username: username)
):
    return {"message": f"Hello {username}", "data": "Sensitive information"}
```

## Role-Based Access Control (RBAC)

Implement sophisticated authorization using shield chaining and factory patterns.

```python
from fastapi import FastAPI, Header, HTTPException
from fastapi_shield import shield, ShieldedDepends

app = FastAPI()

# User database with roles
USERS = {
    "admin_token": {"user_id": "admin", "roles": ["admin", "user"]},
    "editor_token": {"user_id": "editor", "roles": ["editor", "user"]},
    "user_token": {"user_id": "user1", "roles": ["user"]},
}

@shield(name="Authentication")
def auth_shield(api_token: str = Header()) -> dict:
    """Authenticate the user and return user data"""
    if api_token in USERS:
        return USERS[api_token]
    return None

def role_shield(required_roles: list[str]):
    """Factory function to create a role-checking shield"""
    
    @shield(
        name=f"Role Check ({', '.join(required_roles)})",
        exception_to_raise_if_fail=HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied. Required roles: {', '.join(required_roles)}"
        )
    )
    def check_role(user_data: dict = ShieldedDepends(lambda user: user)) -> dict:
        """Check if the user has any of the required roles"""
        user_roles = user_data.get("roles", [])
        if any(role in required_roles for role in user_roles):
            return user_data
        return None
    
    return check_role

# Create specific role shields
admin_shield = role_shield(["admin"])
editor_shield = role_shield(["admin", "editor"])
user_shield = role_shield(["admin", "editor", "user"])

@app.get("/admin")
@auth_shield
@admin_shield
async def admin_endpoint(
    user: dict = ShieldedDepends(lambda user: user)
):
    return {"message": "Admin endpoint", "user": user["user_id"]}

@app.get("/editor")
@auth_shield
@editor_shield
async def editor_endpoint(
    user: dict = ShieldedDepends(lambda user: user)
):
    return {"message": "Editor endpoint", "user": user["user_id"]}

@app.get("/user")
@auth_shield
@user_shield
async def user_endpoint(
    user: dict = ShieldedDepends(lambda user: user)
):
    return {"message": "User endpoint", "user": user["user_id"]}
```

## Rate Limiting

Protect against abuse by implementing rate limits using shield patterns.

```python
import time
from collections import defaultdict
from fastapi import Request, HTTPException, status
from fastapi_shield import shield

# In-memory storage (use Redis in production)
request_counts = defaultdict(list)

@shield(
    name="Rate Limiter",
    exception_to_raise_if_fail=HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="Rate limit exceeded. Maximum 5 requests per second.",
        headers={"Retry-After": "1"}
    )
)
def rate_limit_shield(request: Request) -> bool:
    """Limit requests based on client IP"""
    client_ip = request.client.host
    now = time.time()
    window_seconds = 1
    max_requests = 5
    
    # Remove expired timestamps
    request_counts[client_ip] = [
        ts for ts in request_counts[client_ip] 
        if now - ts < window_seconds
    ]
    
    # Check if rate limit is exceeded
    if len(request_counts[client_ip]) >= max_requests:
        return None
    
    # Add current timestamp and allow request
    request_counts[client_ip].append(now)
    return True

@app.get("/api/data")
@rate_limit_shield
async def get_data():
    return {"message": "Data retrieved successfully"}
```

## IP Restriction

Restrict access based on client IP addresses for internal APIs.

```python
from fastapi import Request, HTTPException, status
from fastapi_shield import shield, ShieldedDepends

# List of allowed IP addresses
ALLOWED_IPS = ["127.0.0.1", "::1", "192.168.1.0/24"]

@shield(
    name="IP Restriction",
    exception_to_raise_if_fail=HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Access denied by IP restriction"
    )
)
def ip_restriction_shield(request: Request) -> dict:
    """Shield that allows only specific IP addresses"""
    client_ip = request.client.host
    
    if client_ip in ALLOWED_IPS:
        return {"client_ip": client_ip}
    return None

@app.get("/internal-api")
@ip_restriction_shield
async def internal_api(
    ip_info: dict = ShieldedDepends(lambda info: info)
):
    return {
        "message": "Internal API endpoint",
        "client_ip": ip_info["client_ip"]
    }
```

## Input Validation and Sanitization

Validate and sanitize all inputs to prevent injection attacks.

```python
import re
import html
from fastapi import HTTPException, status
from fastapi_shield import shield, ShieldedDepends
from pydantic import BaseModel, EmailStr, validator

class UserRegistration(BaseModel):
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
    name="Input Validation",
    exception_to_raise_if_fail=HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Invalid input data"
    )
)
def validate_registration_shield(registration: UserRegistration) -> UserRegistration:
    """Validate registration data"""
    # Additional business logic validation
    if registration.username.lower() in ['admin', 'root', 'system']:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username not allowed"
        )
    
    return registration

@shield(name="Content Sanitization")
def sanitize_comment_shield(comment: str) -> str:
    """Sanitize user-generated content"""
    # Strip potentially dangerous HTML
    sanitized = html.escape(comment)
    
    # Limit comment length
    if len(sanitized) > 1000:
        sanitized = sanitized[:1000] + "..."
    
    # Block dangerous patterns
    if re.search(r'(script|javascript|eval\(|<iframe)', comment, re.IGNORECASE):
        return None
    
    return sanitized

@app.post("/register")
@validate_registration_shield
async def register_user(
    registration: UserRegistration = ShieldedDepends(lambda reg: reg)
):
    # Process validated registration
    return {"status": "User registered successfully"}

@app.post("/comments")
@sanitize_comment_shield
async def create_comment(
    clean_comment: str = ShieldedDepends(lambda comment: comment)
):
    # Store sanitized comment
    return {"status": "Comment added", "comment": clean_comment}
```

## Secure File Handling

Validate file uploads to prevent malicious file attacks.

```python
from fastapi import UploadFile, File, HTTPException, status
from fastapi_shield import shield, ShieldedDepends
import magic
import os

@shield(
    name="File Validation",
    exception_to_raise_if_fail=HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Invalid file upload"
    )
)
async def validate_file_shield(file: UploadFile = File(...)) -> UploadFile:
    """Validate uploaded file for security"""
    # Check file size (limit to 5MB)
    content = await file.read()
    await file.seek(0)  # Reset file position
    
    if len(content) > 5 * 1024 * 1024:  # 5MB
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="File too large. Maximum size is 5MB"
        )
    
    # Check MIME type
    mime = magic.Magic(mime=True)
    file_type = mime.from_buffer(content)
    
    # Allow only certain file types
    allowed_types = ["image/jpeg", "image/png", "application/pdf", "text/plain"]
    if file_type not in allowed_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File type {file_type} not allowed"
        )
    
    # Check file extension matches content
    filename = file.filename
    ext = os.path.splitext(filename)[1].lower()
    
    valid_extensions = {
        "image/jpeg": [".jpg", ".jpeg"],
        "image/png": [".png"],
        "application/pdf": [".pdf"],
        "text/plain": [".txt"]
    }
    
    if ext not in valid_extensions.get(file_type, []):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File extension doesn't match content type"
        )
    
    return file

@app.post("/upload")
@validate_file_shield
async def upload_file(
    file: UploadFile = ShieldedDepends(lambda file: file)
):
    # Process the validated file
    return {
        "filename": file.filename,
        "content_type": file.content_type,
        "status": "File uploaded successfully"
    }
```

## API Key Management

Secure API key validation with proper error handling.

```python
import secrets
from fastapi import Header, HTTPException, status, Depends
from fastapi_shield import shield, ShieldedDepends

# Mock API key database (use proper database in production)
API_KEYS = {
    "sk_test_abcdefghijklmnopqrstuvwxyz123456": {
        "client_id": "client1",
        "permissions": ["read", "write"],
        "active": True
    },
    "sk_test_zyxwvutsrqponmlkjihgfedcba654321": {
        "client_id": "client2", 
        "permissions": ["read", "write", "admin"],
        "active": True
    }
}

@shield(
    name="API Key Validation",
    exception_to_raise_if_fail=HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API key",
        headers={"WWW-Authenticate": "ApiKey"}
    )
)
def validate_api_key_shield(x_api_key: str = Header()) -> dict:
    """Validate API key and return client information"""
    # Check if API key exists
    for key, data in API_KEYS.items():
        # Use constant-time comparison to prevent timing attacks
        if secrets.compare_digest(x_api_key, key):
            if not data.get("active", False):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="API key is inactive"
                )
            return data
    
    return None

def require_permission(permission: str):
    """Factory function for permission-based shields"""
    
    @shield(
        name=f"Permission Check ({permission})",
        exception_to_raise_if_fail=HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission '{permission}' required"
        )
    )
    def permission_shield(
        client_data: dict = ShieldedDepends(lambda data: data)
    ) -> dict:
        """Check if client has required permission"""
        client_permissions = client_data.get("permissions", [])
        if permission in client_permissions:
            return client_data
        return None
    
    return permission_shield

# Create permission shields
read_permission = require_permission("read")
write_permission = require_permission("write")
admin_permission = require_permission("admin")

@app.get("/api/data")
@validate_api_key_shield
@read_permission
async def get_data(
    client: dict = ShieldedDepends(lambda data: data)
):
    return {
        "data": "Sensitive information",
        "client": client["client_id"]
    }

@app.post("/api/data")
@validate_api_key_shield
@write_permission
async def create_data(
    client: dict = ShieldedDepends(lambda data: data)
):
    return {
        "status": "Data created",
        "client": client["client_id"]
    }
```

## Multi-Factor Authentication (MFA)

Implement MFA for enhanced security.

```python
import jwt
from datetime import datetime, timedelta
from fastapi import Header, HTTPException, status
from fastapi_shield import shield, ShieldedDepends

SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"

# Mock user database with MFA settings
USERS_DB = {
    "user1": {
        "username": "user1",
        "mfa_enabled": True,
        "roles": ["user"]
    },
    "admin1": {
        "username": "admin1", 
        "mfa_enabled": True,
        "roles": ["admin", "user"]
    }
}

@shield(
    name="JWT MFA Authentication",
    exception_to_raise_if_fail=HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
        headers={"WWW-Authenticate": "Bearer"}
    )
)
def jwt_mfa_shield(authorization: str = Header()) -> dict:
    """Validate JWT token with MFA verification"""
    if not authorization or not authorization.startswith("Bearer "):
        return None
    
    token = authorization.replace("Bearer ", "")
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        mfa_verified = payload.get("mfa_verified", False)
        
        if username is None or username not in USERS_DB:
            return None
        
        user = USERS_DB[username]
        
        # If MFA is enabled but not verified, require MFA
        if user["mfa_enabled"] and not mfa_verified:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="MFA verification required",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        return user
    except jwt.PyJWTError:
        return None

@app.get("/secure-endpoint")
@jwt_mfa_shield
async def secure_endpoint(
    user: dict = ShieldedDepends(lambda user: user)
):
    return {
        "message": "Access granted to secure endpoint",
        "user": user["username"],
        "mfa_verified": True
    }
```

## Security Monitoring and Logging

Implement security monitoring using shields.

```python
import time
import logging
from fastapi import Request, HTTPException
from fastapi_shield import shield, ShieldedDepends

# Configure security logger
security_logger = logging.getLogger("security")
security_logger.setLevel(logging.INFO)

@shield(name="Security Monitor")
async def security_monitor_shield(request: Request) -> dict:
    """Monitor and log security-relevant request information"""
    start_time = time.time()
    
    security_info = {
        "timestamp": start_time,
        "method": request.method,
        "path": request.url.path,
        "client_ip": request.client.host,
        "user_agent": request.headers.get("user-agent", "unknown"),
        "referer": request.headers.get("referer", ""),
        "content_length": request.headers.get("content-length", "0")
    }
    
    # Log security event
    security_logger.info(
        f"Request: {security_info['method']} {security_info['path']} "
        f"from {security_info['client_ip']}"
    )
    
    # Check for suspicious patterns
    suspicious_patterns = [
        "script", "javascript", "eval(", "<iframe", "union select",
        "../", "etc/passwd", "cmd.exe"
    ]
    
    path_lower = request.url.path.lower()
    if any(pattern in path_lower for pattern in suspicious_patterns):
        security_logger.warning(
            f"Suspicious request detected: {security_info['path']} "
            f"from {security_info['client_ip']}"
        )
    
    return security_info

@app.get("/monitored-endpoint")
@security_monitor_shield
async def monitored_endpoint(
    security_info: dict = ShieldedDepends(lambda info: info)
):
    return {
        "message": "Request processed",
        "request_id": security_info["timestamp"]
    }
```

## Security Best Practices Checklist

When implementing security with FastAPI Shield, follow this checklist:

### Shield Implementation
- ✅ Use shields as decorators, not as function calls
- ✅ Give descriptive names to your shields for better debugging
- ✅ Return `None` from shields that fail validation
- ✅ Use specific HTTP exceptions with clear error messages
- ✅ Implement proper error handling within shields

### Authentication & Authorization
- ✅ Use constant-time comparison for credentials (`secrets.compare_digest`)
- ✅ Implement proper JWT validation with expiration checks
- ✅ Use shield chaining for complex authorization requirements
- ✅ Implement role-based access control with factory patterns
- ✅ Store secrets securely using environment variables

### Input Validation
- ✅ Validate all user inputs with appropriate shields
- ✅ Sanitize user-generated content to prevent XSS
- ✅ Use Pydantic models for structured data validation
- ✅ Implement file upload validation for security

### Rate Limiting & Protection
- ✅ Implement rate limiting for public endpoints
- ✅ Use IP restrictions for internal APIs
- ✅ Monitor and log security events
- ✅ Implement proper CORS policies

### Dependency Injection
- ✅ Use `ShieldedDepends(lambda data: data)` for accessing shield data
- ✅ Layer multiple shields for defense in depth
- ✅ Keep shields focused and single-purpose
- ✅ Use shield factories for reusability

### Error Handling
- ✅ Configure appropriate HTTP status codes for different failures
- ✅ Provide clear error messages without exposing sensitive information
- ✅ Log security events for monitoring and auditing
- ✅ Fail securely by default

By following these patterns and best practices, you can create FastAPI applications that are both functional and secure, leveraging FastAPI Shield's powerful protection mechanisms in a maintainable and scalable way. 