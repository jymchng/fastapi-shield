from fastapi import FastAPI, Depends, Header, HTTPException, Request
from fastapi.testclient import TestClient
from slowapi import Limiter
from slowapi.util import get_remote_address

app = FastAPI()
limiter = Limiter(key_func=get_remote_address)


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
    print("Opening database connection")  # This happens for EVERY request!
    # In a real app, this might create a connection pool or session
    _ = count_get_db_connection_calls()
    db = await connect_to_database()
    try:
        yield db
    finally:
        print("Closing database connection")
        await db.close()


async def verify_api_key(api_key: str = Header()):
    """Verify API key is valid"""
    print("Verifying API key")
    if api_key != "valid_key":
        raise HTTPException(status_code=401, detail="Invalid API key")
    return {"user_id": "user123"}


@app.get("/user-data")
@limiter.limit("5/minute")  # Rate limit applied first
async def get_user_data(
    request: Request,
    user_data=Depends(verify_api_key),  # Authentication check
    db: FakeDB = Depends(get_db_connection),  # Database connection established
):
    print("Executing endpoint logic")
    # Only now do we use the database connection
    return {"message": "User data retrieved"}


# Tests

client = TestClient(app)


def test_no_api_key():
    """Test that requests without API key are rejected"""
    response = client.get("/user-data")
    assert response.status_code == 422  # Validation error for missing required header


def test_invalid_api_key():
    """Test that requests with invalid API key are rejected"""
    response = client.get("/user-data", headers={"api-key": "wrong_key"})
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid API key"}


def test_valid_api_key():
    """Test that requests with valid API key are accepted"""
    response = client.get("/user-data", headers={"api-key": "valid_key"})
    assert response.status_code == 200
    assert response.json() == {"message": "User data retrieved"}


def test_rate_limiting():
    """Test that rate limiting is applied"""
    global counter
    counter = 0

    # Make 6 requests (exceeding the 5/minute limit)
    client = TestClient(app)
    for _ in range(4):
        response = client.get("/user-data", headers={"api-key": "valid_key"})
        assert response.status_code == 200

    # The 6th request should be rate limited
    response = client.get("/user-data", headers={"api-key": "valid_key"})
    assert response.status_code == 429  # Too Many Requests

    # Test `print` get called 5 times
    assert counter == 5


# python -m pytest examples/lazy_depends_one.py
