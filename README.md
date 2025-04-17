# FastAPI Shield

[![PyPI version](https://img.shields.io/pypi/v/fastapi-shield.svg)](https://pypi.org/project/fastapi-shield/)
[![Python Versions](https://img.shields.io/pypi/pyversions/fastapi-shield.svg)](https://pypi.org/project/fastapi-shield/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI Status](https://img.shields.io/github/workflow/status/author/fastapi-shield/ci)](https://github.com/author/fastapi-shield/actions)
[![Documentation](https://img.shields.io/badge/docs-latest-brightgreen.svg)](https://fastapi-shield.readthedocs.io)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![codecov](https://codecov.io/gh/author/fastapi-shield/branch/main/graph/badge.svg)](https://codecov.io/gh/author/fastapi-shield)

A powerful, flexible authentication and authorization framework for FastAPI applications.

## 🛡️ Overview

FastAPI Shield provides a declarative, dependency-based approach to securing FastAPI endpoints. It extends FastAPI's dependency injection system to support:

- Token-based authentication
- Role-based access control
- Automatic dependency resolution
- Nested security dependencies
- Type-safe authentication flows

## ⚙️ Installation

```bash
pip install fastapi-shield
```

## 🚀 Quick Start

Here's a simple example showing how to secure an endpoint with FastAPI Shield:

```python
from fastapi import FastAPI, Request, Header
from fastapi_shield.shield import Shield, ShieldedDepends, AuthenticationStatus
from pydantic import BaseModel
from typing import Tuple, Optional

# Define a User model
class User(BaseModel):
    username: str
    email: str
    roles: list[str] = ["user"]

# Sample database
USERS_DB = {
    "username1": User(
        username="authenticated_user1",
        email="user1@example.com",
        roles=["user", "admin"],
    ),
    "username2": User(
        username="authenticated_user2",
        email="user2@example.com",
    ),
}

# Authentication function
def get_auth_status(request: Request) -> Tuple[AuthenticationStatus, str]:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return AuthenticationStatus.UNAUTHENTICATED, ""
    
    token = auth_header[len("Bearer "):]
    
    # Validate token (replace with your actual validation logic)
    if token in ["valid_token1", "valid_token2"]:
        return AuthenticationStatus.AUTHENTICATED, token
    return AuthenticationStatus.UNAUTHENTICATED, ""

# User retrieval function
def get_username(token: str) -> Optional[str]:
    if token == "valid_token1":
        return "username1"
    if token == "valid_token2":
        return "username2"
    return None

def get_user(token: str) -> User:
    if token == "valid_token1":
        return USERS_DB["username1"]
    return USERS_DB["username2"]

# Create a FastAPI app
app = FastAPI()

# Create a shield with the authentication function
auth_shield = Shield(get_auth_status)

# Protected endpoint
@app.get("/protected")
@auth_shield
async def protected_endpoint(request: Request, user: User = ShieldedDepends(get_user)):
    return {
        "message": "This is a protected endpoint",
        "user": user
    }

# Unprotected endpoint
@app.get("/public")
async def public_endpoint():
    return {"message": "This is a public endpoint"}
```

## 🔒 Authentication Flow

FastAPI Shield's authentication flow:

1. When a request hits a protected endpoint, the shield's authentication function is called
2. If authentication succeeds, the function returns `AuthenticationStatus.AUTHENTICATED` and the credential
3. The credential is passed to shielded dependencies marked with `ShieldedDepends`
4. If authentication fails, a 401 Unauthorized response is returned

## 🔑 Advanced Usage

### Role-Based Access Control

Role-based access control is easily implemented by stacking shields:

```python
from fastapi import FastAPI, Request, Depends
from fastapi_shield.shield import Shield, ShieldedDepends, AuthenticationStatus

# Get user from username
def get_user_from_username(username: str, db: dict = Depends(lambda: USERS_DB)) -> User:
    return db.get(username)

# Get user roles from token
def from_token_get_roles(token: str) -> list[str]:
    if token == "valid_token1":
        return ["user", "admin"]
    if token == "valid_token2":
        return ["user"]
    return []

# Get username from token
def from_token_get_username(token: str) -> str:
    if token == "valid_token1":
        return "username1"
    if token == "valid_token2":
        return "username2"
    return None

# Create a role-based shield
def roles_shield(required_roles: list[str]):
    def decorator(
        username: str = ShieldedDepends(from_token_get_username),
        user_roles: list[str] = ShieldedDepends(from_token_get_roles),
    ):
        for role in user_roles:
            if role in required_roles:
                return True, username
        return False, ""

    return Shield(decorator)

# Create the FastAPI app and authentication shield
app = FastAPI()
auth_shield = Shield(get_auth_status)

# Endpoint requiring admin role
@app.get("/admin")
@auth_shield
@roles_shield(["admin"])
async def admin_endpoint(request: Request, user: User = ShieldedDepends(get_user_from_username)):
    return {"message": "Admin endpoint", "user": user}

# Endpoint requiring only user role
@app.get("/user")
@auth_shield
@roles_shield(["user"])
async def user_endpoint(request: Request, user: User = ShieldedDepends(get_user_from_username)):
    return {"message": "User endpoint", "user": user}
```

### Alternative Authentication Methods

You can define different authentication methods for different endpoints:

```python
# API key authentication
def get_auth_status_from_header(
    *, x_api_token: str = Header(),
) -> Tuple[AuthenticationStatus, str]:
    # Validate API token
    if x_api_token in ["valid_token1", "valid_token2"]:
        return AuthenticationStatus.AUTHENTICATED, x_api_token
    return AuthenticationStatus.UNAUTHENTICATED, ""

# Create API key shield
api_shield = Shield(get_auth_status_from_header)

# API key protected endpoint
@app.get("/api-endpoint")
@api_shield
async def api_endpoint(x_api_token: str = Header(), user: User = ShieldedDepends(get_user)):
    return {
        "x-api-token": x_api_token,
        "user": user,
        "message": "API protected endpoint"
    }
```

## 📚 Nested Shielded Dependencies

FastAPI Shield truly shines with nested dependencies. Dependencies marked with `ShieldedDepends` are only evaluated if authentication succeeds:

```python
from fastapi import Depends

# Database dependency
def get_db():
    # In a real app, this would return a database connection
    return {
        "username1": User(username="user1", email="user1@example.com", roles=["admin"]),
        "username2": User(username="user2", email="user2@example.com"),
    }

# Get user with database dependency
def get_user_with_db(username: str, db = Depends(get_db)) -> User:
    return db.get(username)

# This endpoint uses nested dependencies
@app.get("/profile")
@auth_shield
async def profile_endpoint(
    request: Request,
    # First ShieldedDepends gets username from the token
    # Second ShieldedDepends uses that username to get the user from db
    user: User = ShieldedDepends(lambda username: get_user_with_db(
        username, 
        ShieldedDepends(from_token_get_username)
    )),
):
    return {"user": user}
```

## 🧩 API Reference

### `Shield`

The primary decorator for protecting endpoints:

```python
Shield(
    shield_func: Callable[[T], Tuple[Union[AuthenticationStatus, bool], U]],
    exception_to_raise_if_fail: HTTPException = HTTPException(status_code=401, detail="Unauthorized")
)
```

### `ShieldedDepends`

A dependency that only executes when authentication is successful:

```python
ShieldedDepends(
    shielded_dependency: Optional[Callable[..., Any]] = None
)
```

### `AuthenticationStatus`

An enum representing authentication status:

```python
class AuthenticationStatus(Enum):
    AUTHENTICATED = "AUTHENTICATED"
    UNAUTHENTICATED = "UNAUTHENTICATED"
```

## 🧪 Testing

Testing protected endpoints is straightforward with FastAPI's TestClient:

```python
from fastapi.testclient import TestClient

def test_protected_endpoint():
    client = TestClient(app)
    
    # Unauthorized request
    response = client.get("/protected")
    assert response.status_code == 401
    
    # Authorized request
    response = client.get(
        "/protected", 
        headers={"Authorization": "Bearer valid_token1"}
    )
    assert response.status_code == 200
    assert response.json() == {
        "user": {
            "username": "authenticated_user1",
            "email": "user1@example.com",
            "roles": ["user", "admin"],
        },
        "message": "This is a protected endpoint",
    }
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
