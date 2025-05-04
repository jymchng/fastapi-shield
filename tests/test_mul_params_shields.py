from typing import Any

from fastapi import (
    BackgroundTasks,
    Body,
    Cookie,
    FastAPI,
    Header,
    HTTPException,
    Path,
    Query,
    Response,
)
from fastapi.requests import HTTPConnection
from fastapi.testclient import TestClient
from pydantic import BaseModel

from fastapi_shield.shield import ShieldedDepends, shield


class Product(BaseModel):
    name: str
    price: int


FAKE_USER_DB = {
    "user1": {
        "username": "user1",
        "password": "password1",
        "roles": ["admin", "user"],
    },
    "user2": {
        "username": "user2",
        "password": "password2",
        "roles": ["user"],
    },
    "user3": {
        "username": "user3",
        "password": "password3",
        "roles": ["user"],
    },
}


FAKE_PRODUCT_DB = {
    "product1": Product(name="product1", price=100),
    "product2": Product(name="product2", price=200),
    "product3": Product(name="product3", price=300),
}


async def get_product_db():
    return FAKE_PRODUCT_DB


def validate_token(token: str):
    if token in ("secret1", "secret2", "secret3"):
        return True
    else:
        raise HTTPException(status_code=401, detail="Unauthorized; invalid token")


async def get_db():
    return FAKE_USER_DB


def get_user(username: str):
    return FAKE_USER_DB[username]


def get_payload_from_token(token: str):
    if token in ("secret1", "secret2", "secret3"):
        if token == "secret1":
            return {"username": "user1", "roles": ["admin", "user"]}
        elif token == "secret2":
            return {"username": "user2", "roles": ["user"]}
        elif token == "secret3":
            return {"username": "user3", "roles": ["user"]}
    else:
        raise HTTPException(status_code=401, detail="Unauthorized; token mismatch")


@shield
def auth_required(
    x_api_token: str = Header(),
):
    if validate_token(x_api_token):
        return x_api_token
    else:
        return None


def roles_check(roles: list[str]):
    @shield
    async def decorator(
        authenticated_payload: dict[str, Any] = ShieldedDepends(get_payload_from_token),
    ):
        if any(role in authenticated_payload["roles"] for role in roles):
            return authenticated_payload
        else:
            raise HTTPException(status_code=401, detail="Unauthorized; role mismatch")

    return decorator


@shield
async def username_required(
    authenticated_payload: dict[str, Any] = ShieldedDepends(lambda payload: payload),
    username: str = Path(),
):
    assert authenticated_payload["username"] == "user1"
    if authenticated_payload["username"] == username:
        return username
    else:
        raise HTTPException(status_code=401, detail="Unauthorized; username mismatch")


app = FastAPI()


@app.post("/protected_with_shield/{username}/{product_name}/{big_name}/{big_house}")
@auth_required
@roles_check(["admin"])
@username_required
async def protected(
    g: str,
    username: str,
    product_name: str,
    big_house: int,
    k: int,
    response: Response,
    background_tasks: BackgroundTasks,
    http: HTTPConnection,
    product_three: Product,
    authenticated_user: dict[str, Any] = ShieldedDepends(get_user),
    product: Product = Body(embed=True),
    product_two: Product = Body(embed=True),
    j: str = Query(),
    big_name: str = Path(),
    cookie_data: str = Cookie(...),
):
    assert isinstance(response, Response)
    assert isinstance(background_tasks, BackgroundTasks)
    assert isinstance(http, HTTPConnection)
    assert authenticated_user == get_user(username)
    assert isinstance(authenticated_user, dict)
    assert authenticated_user["username"] == username
    assert authenticated_user["roles"] == ["admin", "user"]

    return {
        "message": "Protected endpoint",
        "username": username,
        "big_house": big_house,
        "g": g,
        "product_name": product_name,
        "k": k,
        "j": j,
        "big_name": big_name,
        "authenticated_user": authenticated_user,
        "product": {"name": product.name, "price": product.price},
        "product_two": {"name": product_two.name, "price": product_two.price},
        "product_three": {"name": product_three.name, "price": product_three.price},
        "cookie_data": cookie_data,
    }


@app.post("/protected_without_shield/{username}/{product_name}/{big_name}/{big_house}")
async def protected(
    g: str,
    username: str,
    product_name: str,
    big_house: int,
    k: int,
    response: Response,
    background_tasks: BackgroundTasks,
    http: HTTPConnection,
    product_three: Product,
    product: Product = Body(embed=True),
    product_two: Product = Body(embed=True),
    j: str = Query(),
    big_name: str = Path(),
    cookie_data: str = Cookie(...),
):
    assert isinstance(response, Response)
    assert isinstance(background_tasks, BackgroundTasks)
    assert isinstance(http, HTTPConnection)

    return {
        "message": "Protected endpoint",
        "username": username,
        "big_house": big_house,
        "g": g,
        "product_name": product_name,
        "k": k,
        "j": j,
        "big_name": big_name,
        "product": {"name": product.name, "price": product.price},
        "product_two": {"name": product_two.name, "price": product_two.price},
        "product_three": {"name": product_three.name, "price": product_three.price},
        "cookie_data": cookie_data,
    }


EXPECTED_JSON_WITH_OR_WITHOUT_SHIELD = {
    "message": "Protected endpoint",
    "username": "user1",
    "big_house": 277,
    "g": "hey",
    "product_name": "big-product",
    "k": 69,
    "j": "big-j",
    "big_name": "big-name",
    "authenticated_user": {
        "username": "user1",
        "password": "password1",
        "roles": ["admin", "user"],
    },
    "product": {"name": "product1", "price": 100},
    "product_two": {"name": "product2", "price": 200},
    "product_three": {"name": "product3", "price": 300},
    "cookie_data": "test_cookie",
}


def test_auth_required_authorized_with_shield():
    client = TestClient(app)

    cookies = {"cookie_data": "test_cookie"}

    # Make the POST request
    response = client.post(
        "/protected_with_shield/user1/big-product/big-name/277?g=hey&k=69&j=big-j",
        headers={"x-api-token": "secret1"},
        cookies=cookies,
        json={
            "product_three": {"name": "product3", "price": 300},
            "product": {"name": "product1", "price": 100},
            "product_two": {"name": "product2", "price": 200},
        },
    )

    # Assert the response
    assert response.status_code == 200, (response.status_code, response.json())
    assert response.json() == EXPECTED_JSON_WITH_OR_WITHOUT_SHIELD


# test user1 cannot access user2 endpoint
def test_user1_cannot_access_user2_endpoint():
    client = TestClient(app)
    cookies = {"cookie_data": "test_cookie"}
    response = client.post(
        "/protected_with_shield/user2/big-product/big-name/277?g=hey&k=69&j=big-j",
        headers={"x-api-token": "secret1"},
        cookies=cookies,
        json={
            "product_three": {"name": "product3", "price": 300},
            "product": {"name": "product1", "price": 100},
            "product_two": {"name": "product2", "price": 200},
        },
    )

    # Assert the response
    assert response.status_code == 401, (response.status_code, response.json())
    assert response.json() == {"detail": "Unauthorized; username mismatch"}


def test_auth_required_authorized_without_shield():
    client = TestClient(app)

    cookies = {"cookie_data": "test_cookie"}

    # Make the POST request
    response = client.post(
        "/protected_without_shield/user1/big-product/big-name/277?g=hey&k=69&j=big-j",
        headers={"x-api-token": "secret1"},
        cookies=cookies,
        json={
            "product_three": {"name": "product3", "price": 300},
            "product": {"name": "product1", "price": 100},
            "product_two": {"name": "product2", "price": 200},
        },
    )

    # Assert the response
    assert response.status_code == 200, (response.status_code, response.json())
    assert response.json() == {
        "message": "Protected endpoint",
        "username": "user1",
        "big_house": 277,
        "g": "hey",
        "product_name": "big-product",
        "k": 69,
        "j": "big-j",
        "big_name": "big-name",
        "product": {"name": "product1", "price": 100},
        "product_two": {"name": "product2", "price": 200},
        "product_three": {"name": "product3", "price": 300},
        "cookie_data": "test_cookie",
    }
