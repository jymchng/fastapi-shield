import os
import sys
from functools import wraps
from inspect import Parameter, signature
from pathlib import Path as PathLibPath

from fastapi import (BackgroundTasks, Body, Cookie, Depends, FastAPI, Form,
                     Header, HTTPException, Path, Query, Request, Response)
from fastapi.requests import HTTPConnection
from fastapi.testclient import TestClient

from fastapi_shield.utils import get_solved_dependencies

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from typing import Callable

from fastapi import (BackgroundTasks, Body, Depends, FastAPI, Header,
                     HTTPException, Path, Request)
from pydantic import BaseModel

from fastapi_shield.consts import (IS_SHIELDED_ENDPOINT_KEY,
                                   SHIELDED_ENDPOINT_KEY)
from fastapi_shield.shield import shield


@shield
# simple shield that will return the `x_api_token` header if the token is valid
# `auth_required` shield will be a decorator
def auth_required_shield(
    # FastAPI will inject the `x_api_token` header into the `auth_required` shield
    x_api_token: str = Header(),
):
    print("`x_api_token`: ", x_api_token)
    if validate_token(x_api_token):
        print("`validate_token(x_api_token)`: ", validate_token(x_api_token))
        return x_api_token
    else:
        print("`validate_token(x_api_token)`: ", validate_token(x_api_token))
        return None


FAKE_USER_DB = {
    "user1": {
        "username": "user1",
        "password": "password1",
    },
    "user2": {
        "username": "user2",
        "password": "password2",
    },
    "user3": {
        "username": "user3",
        "password": "password3",
    },
}


class Product(BaseModel):
    name: str
    price: int


FAKE_PRODUCT_DB = {
    "product1": Product(name="product1", price=100),
    "product2": Product(name="product2", price=200),
    "product3": Product(name="product3", price=300),
}


async def get_product_db():
    return FAKE_PRODUCT_DB


def validate_token(token: str):
    if token == "secret":
        return True
    else:
        raise HTTPException(status_code=401, detail="Invalid token")


async def get_db():
    return FAKE_USER_DB


def get_user(username: str):
    return FAKE_USER_DB[username]


def get_username_from_token(token: str):
    if token == "secret":
        return "user1"
    else:
        raise HTTPException(status_code=401, detail="Unauthenticated User")


app = FastAPI()


@app.post("/")
async def root(
    g: int,
    authorization: str = Header(),
    product: Product = Body(embed=True),
    q: str = Query(),
):
    return {
        "message": f"Hello World; header = `{authorization}`",
        "product": product,
        "g": g,
    }


def auth_required(endpoint: Callable):
    endpoint_params = signature(endpoint).parameters
    dependency_cache = {}

    @wraps(endpoint)
    async def wrapper(*args, **kwargs):
        request: Request = kwargs.get("request")
        db: dict = kwargs.get("db")
        token = request.headers.get("x-authorization")
        print("`wrapper::kwargs`", kwargs)
        print("`wrapper::request.headers`: ", request.headers)
        print("`wrapper::token`: ", token)
        validate_token(token)
        username = get_username_from_token(token)
        if username not in db:
            raise HTTPException(status_code=401, detail="User not found in DB")
        # up til here everything is same as the previous example

        # here's what different, we solve the dependencies for the endpoint
        # and inject the resolved dependencies into the kwargs
        solved_dependencies, body = await get_solved_dependencies(
            request, endpoint, dependency_cache
        )
        print("`wrapper::solved_dependencies`: ", solved_dependencies)
        if solved_dependencies.errors:
            raise HTTPException(status_code=500, detail=solved_dependencies.errors)
        kwargs.update(solved_dependencies.values)
        endpoint_kwargs = {k: v for k, v in kwargs.items() if k in endpoint_params}
        return await endpoint(*args, **endpoint_kwargs)

    # this is a hack to get FastAPI to inject the request object into the wrapper
    wrapper.__signature__ = signature(endpoint).replace(
        parameters=[
            Parameter(
                name="request", kind=Parameter.POSITIONAL_ONLY, annotation=Request
            ),
            Parameter(
                name="db",
                kind=Parameter.POSITIONAL_ONLY,
                annotation=dict,
                default=Depends(get_db),
            ),
            Parameter(
                name="x_authorization",
                kind=Parameter.POSITIONAL_ONLY,
                annotation=str,
                default=Header(alias="X-Authorization", convert_underscores=False),
            ),
        ]
    )

    if not getattr(endpoint, IS_SHIELDED_ENDPOINT_KEY, False):
        setattr(wrapper, SHIELDED_ENDPOINT_KEY, endpoint)
        setattr(wrapper, IS_SHIELDED_ENDPOINT_KEY, True)
    else:
        setattr(wrapper, SHIELDED_ENDPOINT_KEY, endpoint.__shielded_endpoint__)
    return wrapper


@app.post("/baby")
async def root(
    x_authorization: str = Header(),
    product: Product = Body(embed=True),
    q: str = Query(),
):
    return {
        "message": f"Hello World; header = x_authorization = `{x_authorization}`",
        "product": product,
        "g": q,
    }


@app.post("/protected/{username}/{product_name}/{big_name}/{big_house}")
# @auth_required_shield
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
    # files_data: List[UploadFile] = File(...),
    this_is_a_user: str = Form(...),
    this_is_a_password: str = Form(...),
    cookie_data: str = Cookie(...),
):
    # now we no need `request` object
    # we don't need to pass in `db` object

    # the body_param is injected by FastAPI ONLY AFTER the `auth_required` is 'passed'
    assert isinstance(response, Response)
    assert isinstance(background_tasks, BackgroundTasks)
    assert isinstance(http, HTTPConnection)

    # for i, file in enumerate(files_data):
    #     print(
    #         f"File: {file.filename}, Content: {PathLibPath(file.filename).read_text()}"
    #     )

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
        # "file_data": files_data,  # Assuming the file is text-based
        "this_is_a_user": this_is_a_user,
        "this_is_a_password": this_is_a_password,
        "cookie_data": cookie_data,
    }


# def test_auth_required_unauthorized():
#     client = TestClient(app)
#     response = client.post(
#         "/protected/good-f/big-product/big-name/277?g=hey&k=69&j=big-j",
#         headers={"X-Authorization": "secret2"},
#         json={
#             "product": {"name": "product1", "price": 100},
#             "product_two": {"name": "product2", "price": 200},
#             "product_three": {"name": "product3", "price": 300},
#         },
#     )
#     assert response.status_code == 401, (response.status_code, response.json())
#     assert response.json() == {"detail": "Invalid token"}, response.json()


def test_auth_required_authorized():
    client = TestClient(app)

    # Set up the cookie, file, and form data
    cookies = {"cookie_data": "test_cookie"}
    files = [
        ("files_data", open(PathLibPath(__file__).parent / "random_data1.csv", "rb")),
        ("files_data", open(PathLibPath(__file__).parent / "random_data2.csv", "rb")),
    ]
    form_data = {
        "this_is_a_user": "good_user",
        "this_is_a_password": "good_password",
    }

    # Make the POST request
    response = client.post(
        "/protected/good-f/big-product/big-name/277?g=hey&k=69&j=big-j",
        headers={"x-api-token": "secret"},
        cookies=cookies,
        # files=files,
        data=form_data,
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
        "username": "good-f",
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
    }, response.json()


def run_tests():
    test_auth_required_authorized()


run_tests()
