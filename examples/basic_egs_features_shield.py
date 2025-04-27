from fastapi import FastAPI, Path, Response, status
from fastapi_shield import shield

# Fake user database with subscription plans
USER_DB = {
    "user1": {"subscription": "free"},
    "user2": {"subscription": "premium"},
    "user3": {"subscription": "enterprise"},
    "user4": {"subscription": "unlimited"}
}

app = FastAPI()

@shield(
    name="Feature Flag Shield",
    auto_error=False,
    default_response_to_return_if_fail=Response(
        content='{"message": "This feature is not available in your subscription plan"}',
        media_type="application/json",
        status_code=status.HTTP_402_PAYMENT_REQUIRED
    )
)
def feature_flag_shield(user_id: str=Path()):
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

if __name__ == "__main__":
    # uv run python examples/basic_egs_features_shield.py
    from fastapi.testclient import TestClient
    
    client = TestClient(app)
    response = client.get("/premium-feature/user1")
    print(response.json())
    response = client.get("/premium-feature/user2")
    print(response.json())
    response = client.get("/premium-feature/user3")
    print(response.json())
    response = client.get("/premium-feature/user4")
    print(response.json())
    
    # {'message': 'This feature is not available in your subscription plan'}
    # {'message': 'Welcome to the premium feature!'}
    # {'message': 'Welcome to the premium feature!'}
    # {'message': 'Welcome to the premium feature!'}