from fastapi import FastAPI, Depends, Header
from fastapi_shield import shield
from functools import lru_cache
from pydantic_settings import BaseSettings
from fastapi.testclient import TestClient


class SecuritySettings(BaseSettings):
    """Security settings that can be loaded from environment variables"""

    enable_auth: bool = True
    admin_token: str = "admin_token"
    required_role: str = "admin"

    class Config:
        env_prefix = "SECURITY_"


@lru_cache()
def get_security_settings():
    """Cache the settings object"""
    return SecuritySettings()


def create_auth_shield():
    """Create an authentication shield based on settings"""

    @shield(name="Auth Shield")
    def auth_shield(
        settings: SecuritySettings = Depends(get_security_settings),
        api_token: str = Header(),
    ):
        if not settings.enable_auth:
            # Skip auth check if disabled
            return {"auth_skipped": True}

        if api_token == settings.admin_token:
            return {"role": settings.required_role}
        return None

    return auth_shield


app = FastAPI()


@app.get("/admin")
@create_auth_shield()
async def admin_endpoint():
    return {"message": "Admin endpoint"}


# python -m pytest examples/custom_initialization_one.py

# Tests

client = TestClient(app)


def test_admin_endpoint():
    response = client.get("/admin", headers={"API-Token": "admin_token"})
    assert response.status_code == 200, response.json()
    assert response.json() == {"message": "Admin endpoint"}


def test_admin_endpoint_without_token():
    response = client.get("/admin")
    assert response.status_code == 422, response.json()
    assert response.json() == {
        "detail": [
            {
                "input": None,
                "loc": [
                    "header",
                    "api-token",
                ],
                "msg": "Field required",
                'type': 'missing',
            }
        ],
    }


def test_admin_endpoint_with_invalid_token():
    response = client.get("/admin", headers={"API-Token": "invalid_token"})
    assert response.status_code == 500, response.json()
    assert response.json() == {
        "detail": "Shield with name `Auth Shield` blocks the request",
    }
