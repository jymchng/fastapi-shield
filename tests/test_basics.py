from fastapi import FastAPI, Header, Request
from fastapi.testclient import TestClient
from fastapi_shield.shield import Shield, ShieldedDepends, AuthenticationStatus
from fastapi import status
from pydantic import BaseModel
from typing import Tuple


class User(BaseModel):
    username: str
    email: str
    roles: list[str] = ["user"]


FAKE_DB_DATA = {
    "username1": User(
        username="authenticated_user1",
        email="authenticated_user1@example.com",
        roles=["user", "admin"],
    ),
    "username2": User(
        username="authenticated_user2",
        email="authenticated_user2@example.com",
    ),
}


def get_username(token: str) -> str:
    return get_user(token).username


def get_user(token: str) -> User:
    if token == "valid_token1":
        print("`get_user` returns `FAKE_DB_DATA['username1']`")
        return FAKE_DB_DATA["username1"]
    print("`get_user` returns `FAKE_DB_DATA['username2']`")
    return FAKE_DB_DATA["username2"]


def validate_token(token: str):
    # Dummy token validation logic
    print("`validate_token::token`: ", token)
    if (token == "valid_token1") or (token == "valid_token2"):
        print("`validate_token` returns `True`")
        return True
    print("`validate_token` returns `False`")
    return False


def get_auth_status_from_header(
    *,
    x_api_token: str = Header(),
) -> Tuple[AuthenticationStatus, str]:
    if validate_token(x_api_token):
        return (AuthenticationStatus.AUTHENTICATED, x_api_token)
    return (AuthenticationStatus.UNAUTHENTICATED, "")


def get_auth_status(
    request: Request,
) -> Tuple[AuthenticationStatus, str]:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return AuthenticationStatus.UNAUTHENTICATED, ""
    token = auth_header[len("Bearer ") :]
    if validate_token(token):
        return (AuthenticationStatus.AUTHENTICATED, token)
    return (AuthenticationStatus.UNAUTHENTICATED, "")


def allowed_user_roles(roles: list[str]):
    def decorator(authenticated_user: User = ShieldedDepends(get_user)):
        print("`allowed_user_roles::authenticated_user`: ", authenticated_user)
        for role in roles:
            if role in authenticated_user.roles:
                return True, ""
        return False, ""

    return decorator


# Define the FastAPI app
app = FastAPI()
auth_shield: Shield = Shield(get_auth_status)
auth_api_shield: Shield = Shield(get_auth_status_from_header)
def roles_shield(roles: list[str]):
    def decorator(authenticated_user: User = ShieldedDepends(get_user)):
        for role in roles:
            if role in authenticated_user.roles:
                return True, ""
        return False, ""
    return decorator


# Unprotected endpoint
@app.get("/unprotected")
async def unprotected_endpoint(user: User = ShieldedDepends(get_user)):
    return {"message": "This is an unprotected endpoint", "user": user}


# Protected endpoint
@app.get("/protected")
@auth_shield
async def protected_endpoint(request: Request, user: User = ShieldedDepends(get_user)):
    return {
        "user": user,
        "message": "This is a protected endpoint",
    }


# Protected endpoint
@app.get("/protected4")
@auth_shield
@roles_shield(["admin"])
async def protected_endpoint4(request: Request, user: User = ShieldedDepends(get_user)):
    return {
        "user": user,
        "message": "This is a protected endpoint",
    }


@app.get("/protected-api")
@auth_api_shield
async def protected_endpoint3(
    x_api_token: Header(), user: User = ShieldedDepends(get_user)
):
    return {
        "x-api-token": x_api_token,
        "user": user,
        "message": "This is a protected endpoint",
    }


# Protected endpoint
@app.get("/protected2")
@auth_shield
async def protected_endpoint2(
    user1: User = ShieldedDepends(get_user),
):
    return {
        "user1": user1,
        "message": "This is a protected endpoint",
    }


# Test cases
def test_endpoints():
    client = TestClient(app)

    # Test unprotected endpoint
    response = client.get("/unprotected")
    assert response.status_code == 200
    assert response.json() == {
        "message": "This is an unprotected endpoint",
        "user": {"authenticated": False, "shielded_dependency": {}},
    }, response.json()

    # Test protected endpoint without token
    response = client.get("/protected")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED, response.status_code
    assert response.json() == {"detail": "Unauthorized"}, response.json()

    response = client.get("/protected2")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED, response.status_code
    assert response.json() == {"detail": "Unauthorized"}, response.json()

    # Test protected endpoint with invalid token
    response = client.get(
        "/protected", headers={"Authorization": "Bearer invalid_token"}
    )
    assert response.status_code == 401, response.status_code
    assert response.json() == {"detail": "Unauthorized"}, response.json()

    response = client.get(
        "/protected2", headers={"Authorization": "Bearer invalid_token"}
    )
    assert response.status_code == 401, response.status_code
    assert response.json() == {"detail": "Unauthorized"}, response.json()

    # Test protected endpoint with valid token
    response = client.get(
        "/protected", headers={"Authorization": "Bearer valid_token1"}
    )
    assert response.status_code == 200, response.status_code
    assert response.json() == {
        "user": {
            "username": "authenticated_user1",
            "email": "authenticated_user1@example.com",
            "roles": ["user", "admin"],
        },
        "message": "This is a protected endpoint",
    }, response.json()

    response = client.get(
        "/protected", headers={"Authorization": "Bearer uinvalid_token1"}
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED, response.status_code
    assert response.json() == {"detail": "Unauthorized"}, response.json()

    response = client.get(
        "/protected2", headers={"Authorization": "Bearer valid_token1"}
    )
    assert response.status_code == 200, response.status_code
    assert response.json() == {
        "user1": {
            "username": "authenticated_user1",
            "email": "authenticated_user1@example.com",
            "roles": ["user", "admin"],
        },
        "message": "This is a protected endpoint",
    }, response.json()

    response = client.get("/protected-api", headers={"X-API-Token": "valid_token1"})
    assert response.status_code == 200, response.status_code
    assert response.json() == {
        "x-api-token": "valid_token1",
        "user": {
            "username": "authenticated_user1",
            "email": "authenticated_user1@example.com",
            "roles": ["user", "admin"],
        },
        "message": "This is a protected endpoint",
    }, response.json()

    response = client.get(
        "/protected4", headers={"Authorization": "Bearer valid_token1"}
    )
    assert response.status_code == 200, response.status_code
    assert response.json() == {
        "user": {
            "username": "authenticated_user1",
            "email": "authenticated_user1@example.com",
            "roles": ["user", "admin"],
        },
        "message": "This is a protected endpoint",
    }, response.json()

    response = client.get("/protected4", headers={"Authorization": "Bear valid_token2"})
    assert response.status_code == status.HTTP_401_UNAUTHORIZED, response.status_code
    assert response.json() == {"detail": "Unauthorized"}, response.json()


test_endpoints()
