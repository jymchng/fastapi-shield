import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI, Path, Response, status
from fastapi_shield import shield
import json


# Shield with Custom Response Example App
def create_app():
    app = FastAPI()

    # Fake user database with subscription plans
    USER_DB = {
        "user1": {"subscription": "free"},
        "user2": {"subscription": "premium"},
        "user3": {"subscription": "enterprise"},
        "user4": {"subscription": "unlimited"},
    }

    @shield(
        name="Feature Flag Shield",
        auto_error=False,
        default_response_to_return_if_fail=Response(
            content='{"message": "This feature is not available in your subscription plan"}',
            media_type="application/json",
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
        ),
    )
    def feature_flag_shield(user_id: str = Path(...)):
        """Check if the user's subscription plan includes the feature"""

        # Get user's subscription plan from the database
        user_data = USER_DB.get(user_id, {"subscription": "free"})
        subscription_plan = user_data["subscription"]

        # Check if user has a premium plan
        premium_plans = ["premium", "enterprise", "unlimited"]
        if subscription_plan in premium_plans:
            return subscription_plan
        return None

    @app.get("/premium-feature/{user_id}")
    @feature_flag_shield
    async def premium_feature():
        return {"message": "Welcome to the premium feature!"}

    return app


@pytest.fixture
def client():
    app = create_app()
    return TestClient(app)


def test_premium_user_access(client):
    """Test premium feature access for premium users"""
    # Test with premium subscription
    response = client.get("/premium-feature/user2")
    assert response.status_code == 200
    assert response.json() == {"message": "Welcome to the premium feature!"}

    # Test with enterprise subscription
    response = client.get("/premium-feature/user3")
    assert response.status_code == 200
    assert response.json() == {"message": "Welcome to the premium feature!"}

    # Test with unlimited subscription
    response = client.get("/premium-feature/user4")
    assert response.status_code == 200
    assert response.json() == {"message": "Welcome to the premium feature!"}


def test_free_user_denied_access(client):
    """Test premium feature access for free users"""
    # Test with free subscription
    response = client.get("/premium-feature/user1")
    assert response.status_code == 402  # Payment Required
    assert response.json() == {
        "message": "This feature is not available in your subscription plan"
    }


def test_unknown_user_denied_access(client):
    """Test premium feature access for unknown users (should default to free)"""
    # Test with unknown user
    response = client.get("/premium-feature/unknown_user")
    assert response.status_code == 402  # Payment Required
    assert response.json() == {
        "message": "This feature is not available in your subscription plan"
    }
