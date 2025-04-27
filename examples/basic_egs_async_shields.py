from fastapi import FastAPI, Header, HTTPException, status
from fastapi_shield import shield
import asyncio

app = FastAPI()

async def validate_token_async(token: str) -> bool:
    """Simulate an asynchronous token validation process"""
    await asyncio.sleep(0.1)  # Simulate external API call
    return token.startswith("valid_")

@shield(
    name="Async Auth Shield",
    exception_to_raise_if_fail=HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication token"
    )
)
async def async_auth_shield(auth_token: str = Header()):
    """Asynchronous shield for token validation"""
    # Simulate calling an external authentication service
    is_valid = await validate_token_async(auth_token)
    
    if is_valid:
        return {"token": auth_token, "validated": True}
    return None

@app.get("/async-protected")
@async_auth_shield
async def async_protected_endpoint():
    return {"message": "Protected by async shield"}

if __name__ == "__main__":
    from fastapi.testclient import TestClient
    
    client = TestClient(app)
    response = client.get("/async-protected", headers={"Auth-Token": "valid_token"})
    print(response.json())