from fastapi import FastAPI, Header, HTTPException, Depends
from fastapi_shield import shield
from fastapi.testclient import TestClient

app = FastAPI()


class FakeDB:
    def __init__(self):
        self.data = {}

    def get_data(self, key: str):
        return self.data.get(key)

    async def close(self):
        pass


async def connect_to_database():
    """Establish database connection"""
    print("Opening database connection")  # This happens for EVERY request!
    # In a real app, this might create a connection pool or session

    # Return a Fake DB
    return FakeDB()


counter = 0


def count_get_db_connection_calls():
    """Count the number of times get_db_connection is called"""
    global counter
    counter += 1
    return counter


async def get_db_connection():
    """Establish database connection"""
    print("Opening database connection")  # Only happens if shields pass!
    _ = count_get_db_connection_calls()
    db = await connect_to_database()
    try:
        yield db
    finally:
        print("Closing database connection")
        await db.close()


@shield(
    name="API Key Auth",
    exception_to_raise_if_fail=HTTPException(status_code=401, detail="Invalid API key"),
)
def api_key_shield(api_key: str = Header()):
    """Shield that validates API keys"""
    print("Verifying API key")
    if api_key != "valid_key":
        return None  # Shield fails, endpoint never executes
    return {"user_id": "user123"}


@shield(
    name="Rate Limiter",
    exception_to_raise_if_fail=HTTPException(
        status_code=429, detail="Rate limit exceeded"
    ),
)
def rate_limit_shield():
    """Simple rate limiting shield"""
    print("Checking rate limit")
    # Rate limiting logic here
    return True  # Changed to True to allow requests to proceed


@app.get("/user-data")
@rate_limit_shield
@api_key_shield
async def get_user_data(db: FakeDB = Depends(get_db_connection)):
    print("Executing endpoint logic")
    # Database connection is only established if both shields pass
    return {"message": "User data retrieved"}


client = TestClient(app)


def test_no_api_key():
    """Test that requests without API key are rejected"""
    response = client.get("/user-data")
    assert response.status_code == 422  # Validation error for missing required header


def test_invalid_api_key():
    """Test that requests with invalid API key are rejected without calling db connection"""
    global counter
    counter = 0
    response = client.get("/user-data", headers={"api-key": "wrong_key"})
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid API key"}
    assert counter == 0  # DB connection should not be called when shield fails


def test_valid_api_key():
    """Test that requests with valid API key are processed"""
    global counter
    counter = 0
    response = client.get("/user-data", headers={"api-key": "valid_key"})
    assert response.status_code == 200
    assert response.json() == {"message": "User data retrieved"}
    assert counter == 1  # DB connection should be called once


def test_db_connection_lazy_loading():
    """Test that db connection is only created when shields pass"""
    global counter
    counter = 0

    # Test with valid API key - both shields pass
    response = client.get("/user-data", headers={"api-key": "valid_key"})
    assert response.status_code == 200
    assert counter == 1  # DB connection should be called

    counter = 0
    # Test with invalid API key - API key shield fails
    response = client.get("/user-data", headers={"api-key": "wrong_key"})
    assert response.status_code == 401
    assert counter == 0  # DB connection should not be called


def test_custom_shield_with_error():
    """Test a custom shield that raises an explicit error"""

    # Create a new endpoint with a shield that raises an exception
    @shield(
        name="Error Shield",
        exception_to_raise_if_fail=HTTPException(status_code=500, detail="Error"),
    )
    def error_shield():
        return None  # Shield fails, will raise exception_to_raise_if_fail

    @app.get("/error-endpoint")
    @error_shield
    async def error_endpoint():
        return {"message": "This should not be reached"}

    # Test the endpoint
    response = client.get("/error-endpoint")
    assert response.status_code == 500
    assert response.json() == {"detail": "Error"}


def test_shield_with_dependencies():
    """Test shields that have dependencies"""

    # Create a shield that depends on a value
    @shield(
        name="Dependency Shield",
        exception_to_raise_if_fail=HTTPException(status_code=403, detail="Forbidden"),
    )
    def dependency_shield(value=Depends(lambda: "test_value")):
        return value == "test_value"

    # Apply the shield to an endpoint
    @app.get("/dependency-route")
    @dependency_shield
    async def dependency_route():
        return {"message": "Shield with dependency passed"}

    # Test that the endpoint works
    response = client.get("/dependency-route")
    assert response.status_code == 200
    assert response.json() == {"message": "Shield with dependency passed"}


def test_multiple_shields():
    """Test that multiple shields can be applied to the same endpoint"""

    # Create multiple shields
    @shield(
        name="Shield 1",
        exception_to_raise_if_fail=HTTPException(
            status_code=401, detail="Shield 1 failed"
        ),
    )
    def shield1():
        return True

    @shield(
        name="Shield 2",
        exception_to_raise_if_fail=HTTPException(
            status_code=403, detail="Shield 2 failed"
        ),
    )
    def shield2():
        return True

    # Apply both shields to an endpoint
    @app.get("/multiple-shields")
    @shield1
    @shield2
    async def multiple_shields_route():
        return {"message": "Multiple shields passed"}

    # Test that the endpoint works when all shields pass
    response = client.get("/multiple-shields")
    assert response.status_code == 200
    assert response.json() == {"message": "Multiple shields passed"}


# python -m pytest examples/lazy_depends_two.py -v
