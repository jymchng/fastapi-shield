import asyncio
from fastapi import Request
from tests.mocks.middleware_bridge_mocks import (
    MiddlewareTestScenarios, MockReceive, MiddlewareTestHelper, MockSend, MockASGIApp,
    MockMiddlewareConfig
)
from src.fastapi_shield.middleware_bridge import ASGIShieldMiddleware

async def debug_permission():
    scenario = MiddlewareTestScenarios.create_permission_scenario()
    shield = scenario["shield"]
    
    # Test user request to admin endpoint (should be blocked)
    user_request = scenario["user_request"]
    
    print("User request scope headers:", user_request.scope["headers"])
    
    # Create real request from scope
    real_request = Request(user_request.scope, MockReceive())
    
    print("Real request headers dict:", dict(real_request.headers))
    print("x-user-role header:", real_request.headers.get("x-user-role"))
    print("Path:", real_request.url.path)
    print("Method:", real_request.method)
    
    # Test the shield function directly
    result = await shield._guard_func(real_request)
    print("Shield result:", result)
    
    # Now test through middleware
    config = MockMiddlewareConfig.create_basic_config(shield)
    app = MockASGIApp()
    middleware = ASGIShieldMiddleware(app, config)
    
    scope = user_request.scope
    receive = MockReceive()
    send = MockSend()
    
    print("\nTesting through middleware...")
    await middleware(scope, receive, send)
    
    print("Final response status:", send.get_status_code())
    print("App was called:", len(app.calls) > 0)
    print("Send messages:", len(send.messages))

if __name__ == "__main__":
    asyncio.run(debug_permission())