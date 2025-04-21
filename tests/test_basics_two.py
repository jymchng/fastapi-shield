from fastapi import Depends, FastAPI, HTTPException, Header, Path, Request
from fastapi.testclient import TestClient
from fastapi_shield import (
    Shield,
    ShieldedDepends,
)
from fastapi import status
from pydantic import BaseModel
from typing import Optional


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


def get_db(
    db: dict[str, User] = Depends(lambda: FAKE_DB_DATA),
    db2: dict[str, User] = Depends(lambda: FAKE_DB_DATA),
) -> dict[str, User]:
    print("`get_db::db`: ", db)
    print("`get_db::db2`: ", db2)
    return db


async def a_get_db(
    db: dict[str, User] = Depends(lambda: FAKE_DB_DATA),
    db2: dict[str, User] = Depends(lambda: FAKE_DB_DATA),
) -> dict[str, User]:
    print("`get_db::db`: ", db)
    print("`get_db::db2`: ", db2)
    return db


def from_token_get_roles(token: str) -> list[str]:
    if token == "valid_token1":
        return ["user", "admin"]
    if token == "valid_token2":
        return ["user"]
    return []


def from_token_get_username(token: str) -> Optional[str]:
    if token == "valid_token1":
        return "username1"
    if token == "valid_token2":
        return "username2"
    return


def get_username(token: str) -> Optional[str]:
    print(f"`get_username::token`: {token}")
    if token == "valid_token1":
        print("`get_username` returns `username1`")
        return "username1"
    if token == "valid_token2":
        print("`get_username` returns `username2`")
        return "username2"
    print("`get_username` returns `None`")
    return


def get_user_with_db(
    username: str, db: dict[str, User] = Depends(a_get_db)
) -> Optional[User]:
    print("`get_user_with_db::db`: ", db)
    print("`get_user_with_db::username`: ", username)
    print("`get_user_with_db::db.get(username)`: ", db.get(username))
    return db.get(username)


def get_user(token: str, q: str) -> User:
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
) -> Optional[str]:
    if validate_token(x_api_token):
        return x_api_token
    return None


def get_auth_status(
    request: Request,
) -> Optional[str]:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    token = auth_header[len("Bearer ") :]
    if validate_token(token):
        return token
    return None


# Define the FastAPI app
app = FastAPI()
auth_shield = Shield(get_auth_status)
auth_api_shield = Shield(get_auth_status_from_header)


def check_username_is_path_param(
    q: str,
    username_from_authentication: str = ShieldedDepends(lambda username: username),
    username: str = Path(),
):
    print(
        f"`check_username_is_path_param::username_from_authentication`: {username_from_authentication}"
    )
    print(f"`check_username_is_path_param::username`: {username}")
    print(f"`check_username_is_path_param::q`: {q}")
    if username_from_authentication != username or q != "LOL":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Not Found: user with username `{username_from_authentication}` is found to be accessing resource that requires `{username}`",
        )
    return username


def roles_shield(roles: list[str]):
    def decorator(
        # `from_token_get_username` is shielded by `auth_shield`
        username: str = ShieldedDepends(
            from_token_get_username,
        ),
        user_roles: list[str] = ShieldedDepends(
            from_token_get_roles,
        ),
    ):
        print("`allowed_user_roles::username`: ", username)
        print("`allowed_user_roles::roles`: ", roles)
        for role in user_roles:
            if role in roles:
                return username
        return None

    return Shield(decorator)


username_shield = Shield(check_username_is_path_param)
admin_only_shield = roles_shield(["admin"])
user_only_shield = roles_shield(["user"])


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


@app.get("/protected-username")
@auth_shield
async def protected_username_endpoint(
    request: Request, username: str = ShieldedDepends(get_username)
):
    return {
        "username": username,
        "message": "This is a protected endpoint",
    }


@app.get("/protected-username-shield/{username}")
@auth_shield
@roles_shield(["admin"])
@username_shield
async def protected_username_shield_endpoint(
    username: str = Path(),
):
    print(f"`protected_username_shield_endpoint::username`: {username}")
    return {
        "username": username,
        "message": "This is a protected endpoint",
    }


# Protected endpoint
@app.get("/protected4")
@auth_shield
@roles_shield(["admin"])
async def protected_endpoint4(
    # `get_user_with_db` is shielded by `admin_only_shield`
    # `get_user_with_db` has two parameters: `username` and `db`
    # `username` passed to `get_user_with_db` from the return value of `shield_func` within `admin_only_shield`
    # `db` passed to `get_user_with_db` as a FastAPI dependency, i.e. `db: dict[str, User] = Depends(a_get_db)`
    user: User = ShieldedDepends(get_user_with_db),
):
    return {
        "user": user,
        "message": "This is a protected endpoint",
    }


# Protected endpoint
@app.get("/protected-by-roles-shield")
@auth_shield
@roles_shield(["admin"])
async def protected_by_roles_shield(
    # `get_user_with_db` is shielded by `admin_only_shield`
    # `get_user_with_db` has two parameters: `username` and `db`
    # `username` passed to `get_user_with_db` from the return value of `shield_func` within `admin_only_shield`
    # `db` passed to `get_user_with_db` as a FastAPI dependency, i.e. `db: dict[str, User] = Depends(a_get_db)`
    user: User = ShieldedDepends(get_user_with_db),
):
    return {
        "user": user,
        "message": "This is a protected endpoint",
    }


@app.get("/protected-api")
@auth_api_shield
def protected_endpoint3(
    x_api_token: str = Header(), user: User = ShieldedDepends(get_user)
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


def test_username_shield():
    client = TestClient(app)
    response = client.get(
        "/protected-username-shield/username1?q=LOL",
        headers={"Authorization": "Bearer valid_token1"},
    )
    assert response.status_code == 200, (response.status_code, response.json())
    assert response.json() == {
        "username": "username1",
        "message": "This is a protected endpoint",
    }, response.json()


def test_username_shield_with_invalid_username_path_param():
    client = TestClient(app)
    response = client.get(
        "/protected-username-shield/username2?q=LOL",
        headers={"Authorization": "Bearer valid_token1"},
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND, (
        response.status_code,
        response.json(),
    )
    assert response.json() == {
        "detail": "Not Found: user with username `username1` is found to be accessing resource that requires `username2`"
    }, response.json()


def test_unprotected_endpoint():
    client = TestClient(app)
    response = client.get("/unprotected")
    assert response.status_code == 200
    assert response.json() == {
        "message": "This is an unprotected endpoint",
        "user": {
            "dependency": {},
            "use_cache": True,
            "scopes": [],
            "shielded_dependency": {},
            "unblocked": False,
        },
    }, response.json()


def test_protected_endpoint_without_token():
    client = TestClient(app)
    response = client.get("/protected")
    assert response.status_code == 500, response.status_code
    assert response.json() == {
        "detail": "Shield with name `unknown` blocks the request"
    }, response.json()


def test_protected2_endpoint_without_token():
    client = TestClient(app)
    response = client.get("/protected2")
    assert response.status_code == 500, response.status_code
    assert response.json() == {
        "detail": "Shield with name `unknown` blocks the request"
    }, response.json()


def test_protected_endpoint_with_invalid_token():
    client = TestClient(app)
    response = client.get(
        "/protected", headers={"Authorization": "Bearer invalid_token"}
    )
    assert response.status_code == 500, response.status_code
    assert response.json() == {
        "detail": "Shield with name `unknown` blocks the request"
    }, response.json()


def test_protected2_endpoint_with_invalid_token():
    client = TestClient(app)
    response = client.get(
        "/protected2", headers={"Authorization": "Bearer invalid_token"}
    )
    assert response.status_code == 500, response.status_code
    assert response.json() == {
        "detail": "Shield with name `unknown` blocks the request"
    }, response.json()


def test_protected_endpoint_with_valid_token():
    client = TestClient(app)
    response = client.get(
        "/protected?q=PROTECTED", headers={"Authorization": "Bearer valid_token1"}
    )
    assert response.status_code == 200, (response.status_code, response.json())
    assert response.json() == {
        "user": {
            "username": "authenticated_user1",
            "email": "authenticated_user1@example.com",
            "roles": ["user", "admin"],
        },
        "message": "This is a protected endpoint",
    }, response.json()


def test_protected_endpoint_with_malformed_token():
    client = TestClient(app)
    response = client.get(
        "/protected?q=PROTECTED", headers={"Authorization": "Bearer uinvalid_token1"}
    )
    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR, (
        response.status_code
    )
    assert response.json() == {
        "detail": "Shield with name `unknown` blocks the request"
    }, response.json()


def test_protected2_endpoint_with_valid_token():
    client = TestClient(app)
    response = client.get(
        "/protected2?q=PROTECTED2", headers={"Authorization": "Bearer valid_token1"}
    )
    assert response.status_code == 200, (response.status_code, response.json())
    assert response.json() == {
        "user1": {
            "username": "authenticated_user1",
            "email": "authenticated_user1@example.com",
            "roles": ["user", "admin"],
        },
        "message": "This is a protected endpoint",
    }, response.json()


def test_protected_api_endpoint_with_api_token():
    client = TestClient(app)
    response = client.get(
        "/protected-api?q=PROTECTED_API", headers={"X-API-Token": "valid_token1"}
    )
    assert response.status_code == 200, (response.status_code, response.json())
    assert response.json() == {
        "x-api-token": "valid_token1",
        "user": {
            "username": "authenticated_user1",
            "email": "authenticated_user1@example.com",
            "roles": ["user", "admin"],
        },
        "message": "This is a protected endpoint",
    }, response.json()


def test_protected4_endpoint_with_admin_user():
    client = TestClient(app)
    response = client.get(
        "/protected4", headers={"Authorization": "Bearer valid_token1"}
    )
    assert response.status_code == 200, (response.status_code, response.json())
    assert response.json() == {
        "user": {
            "username": "authenticated_user1",
            "email": "authenticated_user1@example.com",
            "roles": ["user", "admin"],
        },
        "message": "This is a protected endpoint",
    }, response.json()


def test_protected4_endpoint_with_non_admin_user():
    client = TestClient(app)
    response = client.get(
        "/protected4", headers={"Authorization": "Bearer valid_token2"}
    )
    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR, (
        response.status_code
    )
    assert response.json() == {
        "detail": "Shield with name `unknown` blocks the request"
    }, response.json()


def test_protected_username_endpoint_with_user1():
    client = TestClient(app)
    response = client.get(
        "/protected-username", headers={"Authorization": "Bearer valid_token1"}
    )
    assert response.status_code == 200, response.status_code
    assert response.json() == {
        "username": "username1",
        "message": "This is a protected endpoint",
    }, response.json()


def test_protected_username_endpoint_with_user2():
    client = TestClient(app)
    response = client.get(
        "/protected-username", headers={"Authorization": "Bearer valid_token2"}
    )
    assert response.status_code == 200, response.status_code
    assert response.json() == {
        "username": "username2",
        "message": "This is a protected endpoint",
    }, response.json()


def test_protected_by_roles_shield_endpoint_with_admin_user():
    client = TestClient(app)
    response = client.get(
        "/protected-by-roles-shield", headers={"Authorization": "Bearer valid_token1"}
    )

    assert response.status_code == status.HTTP_200_OK, (
        response.status_code,
        response.json(),
    )
    assert response.json() == {
        "message": "This is a protected endpoint",
        "user": {
            "email": "authenticated_user1@example.com",
            "roles": ["user", "admin"],
            "username": "authenticated_user1",
        },
    }, response.json()


def test_protected_by_roles_shield_endpoint_with_non_admin_user():
    client = TestClient(app)
    response = client.get(
        "/protected-by-roles-shield", headers={"Authorization": "Bearer valid_token2"}
    )
    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR, (
        response.status_code,
        response.json(),
    )
    assert response.json() == {
        "detail": "Shield with name `unknown` blocks the request"
    }, response.json()
