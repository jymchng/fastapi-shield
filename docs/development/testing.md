# Testing Guide

This guide covers the testing strategies and tools used in FastAPI Shield, and how to create and run tests when contributing to the project.

## Testing Philosophy

FastAPI Shield follows these principles for testing:

1. **Comprehensive Coverage**: Aim for high test coverage across all components
2. **Test Types**: Include unit, integration, and performance tests
3. **Type Safety**: Ensure type annotations are correct through type checking tests
4. **Documentation Verification**: Validate that code examples in documentation work

## Test Structure

Tests are organized in the `tests/` directory with the following structure:

```
tests/
├── conftest.py              # Shared pytest fixtures
├── unit/                    # Unit tests
│   ├── core/                # Core component tests
│   ├── interceptors/        # Interceptor tests
│   └── validation/          # Validation tests
├── integration/             # Integration tests
│   ├── fastapi/             # FastAPI integration tests
│   └── pydantic/            # Pydantic integration tests
├── performance/             # Performance benchmarks
├── typing/                  # Type checking tests
└── doc_examples/            # Tests for documentation examples
```

## Setting Up the Test Environment

To run the tests, you need to install the development dependencies:

```bash
# Using pip
pip install -e ".[dev]"

# Using uv
uv pip install -e ".[dev]"

# Using poetry
poetry install --extras dev
```

## Running Tests

### Using pytest directly

```bash
# Run all tests
pytest

# Run specific test module
pytest tests/unit/core/test_shield.py

# Run specific test
pytest tests/unit/core/test_shield.py::test_shield_validation
```

### Using nox

```bash
# Run all test sessions
nox -s tests

# Run with specific Python version
nox -s tests-3.9
```

## Test Fixtures

FastAPI Shield provides several pytest fixtures in `conftest.py` to simplify testing:

```python
@pytest.fixture
def test_app():
    """Create a test FastAPI application."""
    app = FastAPI()
    return app

@pytest.fixture
def async_client(test_app):
    """Create an async test client."""
    return AsyncClient(app=test_app, base_url="http://test")

@pytest.fixture
def example_shield():
    """Create an example shield for testing."""
    UserId = NewType("UserId", int)
    validated_user_id = shield(UserId)
    return validated_user_id
```

## Writing Unit Tests

Unit tests focus on testing individual components in isolation:

```python
def test_shield_validation():
    """Test shield validation logic."""
    # Create a shield with a validation function
    def validate_positive(value):
        if value <= 0:
            raise ValueError("Value must be positive")
        return value
    
    PositiveInt = NewType("PositiveInt", int)
    positive_int = shield(PositiveInt, validators=[validate_positive])
    
    # Test valid input
    assert positive_int(5) == 5
    
    # Test invalid input
    with pytest.raises(ValueError):
        positive_int(-1)
```

## Writing Integration Tests

Integration tests verify that FastAPI Shield integrates correctly with FastAPI:

```python
async def test_shield_in_endpoint(async_client, example_shield):
    """Test using a shield in a FastAPI endpoint."""
    app = async_client.app
    
    @app.get("/test/{user_id}")
    async def test_endpoint(user_id: example_shield):
        return {"user_id": user_id}
    
    # Test valid input
    response = await async_client.get("/test/123")
    assert response.status_code == 200
    assert response.json() == {"user_id": 123}
    
    # Test invalid input
    response = await async_client.get("/test/invalid")
    assert response.status_code == 422
```

## Performance Testing

Performance tests measure the overhead introduced by FastAPI Shield:

```python
def test_shield_performance(benchmark):
    """Benchmark shield performance."""
    UserId = NewType("UserId", int)
    validated_user_id = shield(UserId)
    
    # Benchmark the shield's validation performance
    result = benchmark(validated_user_id, 123)
    assert result == 123
```

## Type Checking Tests

Type checking tests ensure that shield types work correctly with static type checkers:

```python
def test_shield_typing():
    """Test shield typing with mypy."""
    # This test is run by mypy during CI
    UserId = NewType("UserId", int)
    validated_user_id = shield(UserId)
    
    # This should type check correctly
    user_id: UserId = validated_user_id(123)
    
    # This should fail type checking
    # user_id: str = validated_user_id(123)  # mypy error
```

## Testing with Different Python Versions

FastAPI Shield supports Python 3.9+ and tests across multiple Python versions:

```bash
# Using nox to test on multiple Python versions
nox -s tests
```

## Mocking Dependencies

When testing shields that depend on external services, use mocking:

```python
@pytest.fixture
def mock_auth_service():
    """Create a mock authentication service."""
    class MockAuthService:
        def verify_token(self, token):
            if token == "valid_token":
                return {"user_id": 123}
            raise ValueError("Invalid token")
    
    return MockAuthService()

def test_auth_shield(mock_auth_service):
    """Test authentication shield with mock service."""
    Token = NewType("Token", str)
    token_shield = shield(
        Token,
        validators=[lambda t: mock_auth_service.verify_token(t)]
    )
    
    # Test valid token
    assert token_shield("valid_token") == "valid_token"
    
    # Test invalid token
    with pytest.raises(ValueError):
        token_shield("invalid_token")
```

## Testing Async Code

FastAPI Shield includes asynchronous components that require special testing:

```python
async def test_async_interceptor():
    """Test an asynchronous interceptor."""
    class TestInterceptor(Interceptor):
        async def before(self, *args, **kwargs):
            return {"modified": True}
    
    interceptor = TestInterceptor()
    result = await interceptor.before()
    assert result == {"modified": True}
```

## Test Coverage

FastAPI Shield aims for high test coverage:

```bash
# Generate coverage report
pytest --cov=fastapi_shield

# Generate HTML coverage report
pytest --cov=fastapi_shield --cov-report=html
```

Coverage reports are available in the `.coverage` file and the `htmlcov/` directory.

## Continuous Integration

Tests are run automatically on every push and pull request:

1. Tests run on multiple Python versions (3.9, 3.10, 3.11)
2. Linting and type checking are performed
3. Coverage reports are generated
4. Documentation examples are verified

## Tips for Effective Testing

1. **Isolate Tests**: Each test should focus on one behavior
2. **Use Fixtures**: Create reusable components with pytest fixtures
3. **Test Edge Cases**: Include tests for boundary and error conditions
4. **Keep Tests Fast**: Optimize test performance for quick feedback
5. **Test Asynchronously**: Use `pytest-asyncio` for testing async code
6. **Mock External Dependencies**: Use `unittest.mock` or `pytest-mock`
7. **Parametrize Tests**: Use `pytest.mark.parametrize` for multiple test cases 