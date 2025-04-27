# Testing FastAPI Shield Applications

This guide covers strategies for effectively testing applications that use FastAPI Shield, ensuring that your shields provide robust validation and security without hindering testability.

## Introduction to Testing with FastAPI Shield

Testing applications that use FastAPI Shield requires specific strategies to address its runtime type checking and validation mechanisms. This guide will help you create comprehensive test suites that verify both your shields and the endpoints that use them.

## Unit Testing Shields

Shields should be tested in isolation to verify their validation logic:

```python
import pytest
from fastapi_shield import shield
from pydantic import ValidationError

# Shield to test
@shield(name="PositiveIntegerShield")
def validate_positive_integer(value: int):
    if value <= 0:
        raise ValueError("Value must be positive")
    return value

# Unit tests for the shield
def test_positive_integer_shield_success():
    # Test valid input
    result = validate_positive_integer(5)
    assert result == 5

def test_positive_integer_shield_failure():
    # Test invalid input
    with pytest.raises(ValueError) as exc_info:
        validate_positive_integer(0)
    assert "Value must be positive" in str(exc_info.value)

    with pytest.raises(ValueError) as exc_info:
        validate_positive_integer(-10)
    assert "Value must be positive" in str(exc_info.value)

# Test type validation 
def test_positive_integer_shield_type_checking():
    with pytest.raises(ValueError) as exc_info:
        validate_positive_integer("not an integer")
    # The exact error message may vary depending on FastAPI Shield's internals
    assert "int type expected" in str(exc_info.value).lower() or "not a valid integer" in str(exc_info.value).lower()
```

## Testing Shield Composition

When testing shields that depend on other shields, test both the individual shields and their composition:

```python
from fastapi_shield import shield, ShieldedDepends
from typing import Dict

# Base shields
@shield(name="UserIdValidator")
def validate_user_id(user_id: int):
    if user_id <= 0:
        raise ValueError("User ID must be positive")
    return user_id

@shield(name="RoleValidator")
def validate_role(role: str):
    valid_roles = ["admin", "user", "guest"]
    if role not in valid_roles:
        raise ValueError(f"Role must be one of: {', '.join(valid_roles)}")
    return role

# Composite shield
@shield(name="UserValidator")
def validate_user(
    user_data: Dict[str, any],
    validated_user_id = ShieldedDepends(validate_user_id),
    validated_role = ShieldedDepends(validate_role)
):
    # Additional validation
    if validated_role == "admin" and user_data.get("department") is None:
        raise ValueError("Admin users must have a department")
    
    return {
        "user_id": validated_user_id,
        "role": validated_role,
        "department": user_data.get("department")
    }

# Test the composite shield
def test_user_validator_success():
    user_data = {"department": "Engineering"}
    result = validate_user(user_data, 1, "admin")
    assert result == {
        "user_id": 1,
        "role": "admin",
        "department": "Engineering"
    }

def test_user_validator_missing_department():
    user_data = {}
    with pytest.raises(ValueError) as exc_info:
        validate_user(user_data, 1, "admin")
    assert "Admin users must have a department" in str(exc_info.value)

def test_user_validator_invalid_user_id():
    user_data = {"department": "Engineering"}
    with pytest.raises(ValueError) as exc_info:
        validate_user(user_data, -1, "admin")
    assert "User ID must be positive" in str(exc_info.value)

def test_user_validator_invalid_role():
    user_data = {"department": "Engineering"}
    with pytest.raises(ValueError) as exc_info:
        validate_user(user_data, 1, "superuser")
    assert "Role must be one of" in str(exc_info.value)
```

## Integration Testing with FastAPI TestClient

FastAPI provides a TestClient that allows testing your API endpoints, including those protected by shields:

```python
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from fastapi_shield import shield, ShieldedDepends

app = FastAPI()

# Shield for API key validation
@shield(name="ApiKeyValidator")
def validate_api_key(api_key: str):
    valid_keys = ["test-key-1", "test-key-2"]
    if api_key not in valid_keys:
        raise ValueError("Invalid API key")
    return api_key

# Shield for payload validation
@shield(name="PayloadValidator")
def validate_payload(data: dict):
    if not data.get("name"):
        raise ValueError("Name is required")
    return data

# Endpoint with shields
@app.post("/items/")
async def create_item(
    api_key: str = ShieldedDepends(validate_api_key),
    payload: dict = ShieldedDepends(validate_payload)
):
    return {"status": "success", "name": payload["name"], "key_used": api_key}

# Create a test client
client = TestClient(app)

# Test the endpoint
def test_create_item_success():
    response = client.post(
        "/items/",
        json={"name": "Test Item"},
        headers={"api-key": "test-key-1"}
    )
    assert response.status_code == 200
    assert response.json() == {
        "status": "success",
        "name": "Test Item",
        "key_used": "test-key-1"
    }

def test_create_item_invalid_api_key():
    response = client.post(
        "/items/",
        json={"name": "Test Item"},
        headers={"api-key": "invalid-key"}
    )
    assert response.status_code == 422  # Validation error

def test_create_item_invalid_payload():
    response = client.post(
        "/items/",
        json={},  # Missing name
        headers={"api-key": "test-key-1"}
    )
    assert response.status_code == 422  # Validation error
```

## Testing with Authentication Shields

Testing endpoints that use authentication shields requires special handling:

```python
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from fastapi.testclient import TestClient
from fastapi_shield import shield, ShieldedDepends
from typing import Optional

app = FastAPI()

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Mock user database
fake_users_db = {
    "testuser": {
        "username": "testuser",
        "email": "test@example.com",
        "full_name": "Test User",
        "roles": ["user"]
    },
    "adminuser": {
        "username": "adminuser",
        "email": "admin@example.com",
        "full_name": "Admin User",
        "roles": ["admin", "user"]
    }
}

# Shield for token validation and user lookup
@shield(name="TokenValidator")
def validate_token(token: str = Depends(oauth2_scheme)) -> str:
    # In a real application, verify the token signature and expiration
    # For testing, just check if the token exists in our fake db
    if token not in fake_users_db:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token

# Shield to get the current user
@shield(name="CurrentUser")
def get_current_user(token: str = ShieldedDepends(validate_token)):
    user = fake_users_db[token]
    return user

# Shield to check for admin role
@shield(name="AdminOnly")
def validate_admin(user: dict = ShieldedDepends(get_current_user)):
    if "admin" not in user["roles"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    return user

# Public endpoint
@app.get("/users/me/")
async def read_users_me(current_user: dict = ShieldedDepends(get_current_user)):
    return current_user

# Admin-only endpoint
@app.get("/admin/")
async def admin_endpoint(admin_user: dict = ShieldedDepends(validate_admin)):
    return {"message": "Admin access granted", "user": admin_user["username"]}

client = TestClient(app)

# Test authenticated endpoint as regular user
def test_read_users_me():
    response = client.get(
        "/users/me/",
        headers={"Authorization": "Bearer testuser"}
    )
    assert response.status_code == 200
    assert response.json()["username"] == "testuser"

# Test admin endpoint as regular user (should fail)
def test_admin_endpoint_as_user():
    response = client.get(
        "/admin/",
        headers={"Authorization": "Bearer testuser"}
    )
    assert response.status_code == 403

# Test admin endpoint as admin
def test_admin_endpoint_as_admin():
    response = client.get(
        "/admin/",
        headers={"Authorization": "Bearer adminuser"}
    )
    assert response.status_code == 200
    assert response.json()["message"] == "Admin access granted"

# Test with no authentication
def test_unauthorized():
    response = client.get("/users/me/")
    assert response.status_code == 401
```

## Mocking Shields for Testing

Sometimes you may want to bypass shield validation in tests to focus on testing other parts of your application. You can do this by creating mock shields or overriding dependencies:

```python
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from fastapi_shield import shield, ShieldedDepends
from unittest.mock import patch

app = FastAPI()

# Expensive shield with database lookups
@shield(name="DatabaseValidator")
def validate_with_database(item_id: int):
    # In a real application, this would query a database
    # For testing, we'll mock this
    return item_id

@app.get("/items/{item_id}")
async def get_item(validated_id: int = ShieldedDepends(validate_with_database)):
    return {"item_id": validated_id, "name": f"Item {validated_id}"}

# Method 1: Override the dependency for testing
def get_test_client_with_override():
    app.dependency_overrides[validate_with_database] = lambda item_id: item_id
    client = TestClient(app)
    yield client
    app.dependency_overrides = {}

def test_get_item_with_override():
    client = next(get_test_client_with_override())
    response = client.get("/items/123")
    assert response.status_code == 200
    assert response.json() == {"item_id": 123, "name": "Item 123"}

# Method 2: Using unittest.mock to patch the shield
def test_get_item_with_mock():
    with patch("__main__.validate_with_database", return_value=123):
        client = TestClient(app)
        response = client.get("/items/999")  # The actual ID doesn't matter here
        assert response.status_code == 200
        assert response.json() == {"item_id": 123, "name": "Item 123"}
```

## Parameterized Testing for Shields

Use pytest's parameterize feature to test shields with multiple inputs:

```python
import pytest
from fastapi_shield import shield

@shield(name="StringLengthValidator")
def validate_string_length(value: str, min_length: int = 1, max_length: int = 100):
    if len(value) < min_length:
        raise ValueError(f"String must be at least {min_length} characters")
    if len(value) > max_length:
        raise ValueError(f"String must be at most {max_length} characters")
    return value

@pytest.mark.parametrize("value,min_length,max_length,should_pass", [
    ("test", 1, 10, True),
    ("", 1, 10, False),
    ("this is a long string", 5, 10, False),
    ("a", 1, 1, True),
    ("ab", 1, 1, False),
])
def test_string_length_validator(value, min_length, max_length, should_pass):
    if should_pass:
        result = validate_string_length(value, min_length, max_length)
        assert result == value
    else:
        with pytest.raises(ValueError):
            validate_string_length(value, min_length, max_length)
```

## Testing Asynchronous Shields

FastAPI Shield supports asynchronous shields, which require special testing approaches:

```python
import pytest
import asyncio
from fastapi_shield import shield

@shield(name="AsyncValidator")
async def async_validator(value: str):
    # Simulate async operation (e.g., database lookup)
    await asyncio.sleep(0.1)
    
    if not value:
        raise ValueError("Value cannot be empty")
    return value.upper()

# Test asynchronous shield
@pytest.mark.asyncio
async def test_async_validator_success():
    result = await async_validator("hello")
    assert result == "HELLO"

@pytest.mark.asyncio
async def test_async_validator_failure():
    with pytest.raises(ValueError) as exc_info:
        await async_validator("")
    assert "Value cannot be empty" in str(exc_info.value)
```

## Performance Testing of Shields

Testing the performance impact of shields:

```python
import time
import statistics
from fastapi_shield import shield

@shield(name="SimpleShield")
def simple_shield(value: int):
    return value

@shield(name="ComplexShield")
def complex_shield(value: int):
    # Simulate more complex validation
    time.sleep(0.001)  # 1ms operation
    for _ in range(1000):
        _ = value * 2
    return value

def test_shield_performance():
    iterations = 100
    
    # Test simple shield
    simple_times = []
    for _ in range(iterations):
        start = time.time()
        simple_shield(42)
        end = time.time()
        simple_times.append((end - start) * 1000)  # Convert to ms
    
    # Test complex shield
    complex_times = []
    for _ in range(iterations):
        start = time.time()
        complex_shield(42)
        end = time.time()
        complex_times.append((end - start) * 1000)  # Convert to ms
    
    # Calculate statistics
    simple_avg = statistics.mean(simple_times)
    complex_avg = statistics.mean(complex_times)
    
    print(f"Simple shield average execution time: {simple_avg:.2f}ms")
    print(f"Complex shield average execution time: {complex_avg:.2f}ms")
    
    # Set performance thresholds based on your requirements
    assert simple_avg < 1.0, "Simple shield is too slow"
    # Complex shield includes an intentional 1ms delay
    assert complex_avg < 5.0, "Complex shield is too slow"
```

## Testing Best Practices

Here are some best practices to follow when testing FastAPI Shield applications:

1. **Isolate Shield Tests**: Test shields in isolation before testing them within endpoints.

2. **Test Error Cases**: Verify that shields reject invalid inputs with appropriate error messages.

3. **Test Type Validation**: Ensure that shields properly enforce type checking.

4. **Mock External Dependencies**: Use mocking to avoid dependencies on external services during tests.

5. **Test Performance**: Monitor the performance impact of shields, especially for complex validation logic.

6. **Use Fixtures**: Create pytest fixtures for common shields to reuse across tests.

7. **Test Shield Composition**: Verify that composed shields work correctly together.

8. **Test Bypass Mechanisms**: If your application allows bypassing shields in certain contexts, test those mechanisms.

9. **Test with Real Data**: Include tests with realistic data to uncover edge cases.

10. **Continuous Integration**: Run shield tests as part of your CI pipeline to catch regressions.

## Using Pytest Fixtures for Shield Testing

Create reusable shield test fixtures:

```python
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from fastapi_shield import shield, ShieldedDepends

# Common shields for testing
@shield(name="AdminCheck")
def admin_shield(user_role: str):
    if user_role != "admin":
        raise ValueError("Admin access required")
    return user_role

# App with shields for testing
@pytest.fixture
def test_app():
    app = FastAPI()
    
    @app.get("/admin-only")
    async def admin_endpoint(role: str = ShieldedDepends(admin_shield)):
        return {"access": "granted", "role": role}
    
    return app

@pytest.fixture
def client(test_app):
    return TestClient(test_app)

# Tests using fixtures
def test_admin_access(client):
    response = client.get("/admin-only?user_role=admin")
    assert response.status_code == 200
    assert response.json() == {"access": "granted", "role": "admin"}

def test_non_admin_access(client):
    response = client.get("/admin-only?user_role=user")
    assert response.status_code == 422  # Validation error
```

## Conclusion

Testing FastAPI Shield applications requires attention to both the shields themselves and how they integrate with your API endpoints. By following the strategies in this guide, you can ensure your shields provide robust validation and security without compromising the testability of your application.

Remember that well-tested shields not only verify security but also serve as documentation for the validation rules your API enforces, helping both developers and users understand the expected inputs and behaviors. 