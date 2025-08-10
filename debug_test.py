import asyncio
from tests.mocks.middleware_bridge_mocks import (
    MiddlewareTestScenarios, MockReceive, MiddlewareTestHelper, MockSend, MockASGIApp,
    MockMiddlewareConfig
)
from src.fastapi_shield.middleware_bridge import ASGIShieldMiddleware

async def debug_test():
    """Debug the exact failing test."""
    scenario = MiddlewareTestScenarios.create_permission_scenario()
    shield = scenario["shield"]
    
    config = MockMiddlewareConfig.create_basic_config(shield)
    app = MockASGIApp()
    middleware = ASGIShieldMiddleware(app, config)
    
    # Test user request to admin endpoint (should be blocked)
    user_scope = scenario["user_request"].scope
    print("User scope:", user_scope)
    
    send = await MiddlewareTestHelper.run_asgi_middleware(
        middleware, user_scope, MockReceive(), MockSend()
    )
    
    print("Status code returned:", send.get_status_code())
    print("Messages:", send.messages)
    print("App calls:", len(app.calls))
    
    # Check what the MiddlewareTestHelper.run_asgi_middleware actually does
    print("Expected: 403, Actual:", send.get_status_code())

if __name__ == "__main__":
    asyncio.run(debug_test())