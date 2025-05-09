import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI, Query, HTTPException, status
from fastapi_shield import shield, ShieldedDepends
from typing import Optional


# Request Validation Shield Example App
def create_app():
    app = FastAPI()

    @shield(
        name="Parameters Validator",
        exception_to_raise_if_fail=HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid parameters"
        ),
    )
    def validate_parameters(
        page: int = Query(1),
        per_page: int = Query(10, ge=1, le=100),
        sort_by: Optional[str] = Query(None),
    ):
        """Validate and normalize query parameters"""
        valid_sort_fields = ["created_at", "updated_at", "name"]

        # Create normalized parameters
        normalized = {
            "page": max(1, page),  # Ensure page is at least 1
            "per_page": max(
                1, min(per_page, 100)
            ),  # Ensure per_page is between 1 and 100
            "sort_by": sort_by if sort_by in valid_sort_fields else "created_at",
        }

        return normalized

    @app.get("/items")
    @validate_parameters
    async def list_items(params=ShieldedDepends(lambda params: params)):
        # Use validated and normalized parameters
        return {
            "items": [f"Item {i}" for i in range(1, 6)],
            "pagination": {
                "page": params["page"],
                "per_page": params["per_page"],
                "sort_by": params["sort_by"],
            },
        }

    return app


@pytest.fixture
def client():
    app = create_app()
    return TestClient(app)


def test_default_parameters(client):
    """Test endpoint with default parameters"""
    response = client.get("/items")
    assert response.status_code == 200
    data = response.json()
    assert len(data["items"]) == 5
    assert data["pagination"] == {"page": 1, "per_page": 10, "sort_by": "created_at"}


def test_custom_valid_parameters(client):
    """Test endpoint with custom valid parameters"""
    response = client.get("/items?page=2&per_page=20&sort_by=updated_at")
    assert response.status_code == 200
    data = response.json()
    assert data["pagination"] == {"page": 2, "per_page": 20, "sort_by": "updated_at"}


def test_parameter_normalization(client):
    """Test that parameters are normalized correctly"""
    # Test per_page clamping to maximum
    response = client.get("/items?per_page=200")
    assert response.status_code == 422, f"Response: {response.json()}"
    assert response.json() == {
        "detail": [
            {
                "type": "less_than_equal",
                "loc": ["query", "per_page"],
                "msg": "Input should be less than or equal to 100",
                "input": "200",
                "ctx": {"le": 100},
            }
        ]
    }

    # Test page minimum value
    response = client.get("/items?page=-5")
    assert response.status_code == 200, f"Response: {response.json()}"
    assert response.json()["pagination"]["page"] == 1

    # Test invalid sort_by fallback
    response = client.get("/items?sort_by=invalid_field")
    assert response.status_code == 200, f"Response: {response.json()}"
    assert response.json()["pagination"]["sort_by"] == "created_at"


def test_valid_sort_fields(client):
    """Test with each valid sort field"""
    valid_fields = ["created_at", "updated_at", "name"]
    for field in valid_fields:
        response = client.get(f"/items?sort_by={field}")
        assert response.status_code == 200, f"Response: {response.json()}"
        assert response.json()["pagination"]["sort_by"] == field
