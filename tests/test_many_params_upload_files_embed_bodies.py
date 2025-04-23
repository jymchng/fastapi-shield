import json
import os
import sys
from functools import wraps
from inspect import Parameter, signature
from pathlib import Path as PathLibPath

from fastapi import (BackgroundTasks, Body, Cookie, Depends, FastAPI, File,
                     Form, Header, HTTPException, Path, Query, Request,
                     Response, Security, UploadFile, WebSocket)
from fastapi.requests import HTTPConnection
from fastapi.testclient import TestClient

from fastapi_shield.utils import get_solved_dependencies

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from typing import Any, Callable, List

from fastapi import (BackgroundTasks, Body, Depends, FastAPI, Header,
                     HTTPException, Path, Request)
from pydantic import BaseModel

from fastapi_shield.consts import (IS_SHIELDED_ENDPOINT_KEY,
                                   SHIELDED_ENDPOINT_KEY)
from fastapi_shield.shield import ShieldedDepends, shield


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


@app.post("/protected_with_shield/{username}/{product_name}/{big_name}/{big_house}")
@auth_required_shield
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
    files_data: List[UploadFile] = File(...),
    # this_is_a_user: str = Form(...),
    # this_is_a_password: str = Form(...),
    cookie_data: str = Cookie(...),
):
    assert isinstance(response, Response)
    assert isinstance(background_tasks, BackgroundTasks)
    assert isinstance(http, HTTPConnection)

    for i, file in enumerate(files_data):
        print(f"File {i}: {file.filename}")
        with open(file.filename, "rb") as f:
            assert f.read() == f"This is random data {i + 1} dot csv".encode()

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
        # "this_is_a_user": this_is_a_user,
        # "this_is_a_password": this_is_a_password,
        "files_data": [{"filename": file.filename} for file in files_data],
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
    files_data: List[UploadFile] = File(...),
    # this_is_a_user: str = Form(...),
    # this_is_a_password: str = Form(...),
    cookie_data: str = Cookie(...),
):
    assert isinstance(response, Response)
    assert isinstance(background_tasks, BackgroundTasks)
    assert isinstance(http, HTTPConnection)

    for i, file in enumerate(files_data):
        print(f"File {i}: {file.filename}")
        with open(file.filename, "rb") as f:
            assert f.read() == f"This is random data {i + 1} dot csv".encode()

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
        # "this_is_a_user": this_is_a_user,
        # "this_is_a_password": this_is_a_password,
        "files_data": [{"filename": file.filename} for file in files_data],
        "cookie_data": cookie_data,
    }


EXPECTED_JSON_WITH_OR_WITHOUT_SHIELD = {
    "detail": [
        {
            "type": "missing",
            "loc": ["body", "product_three"],
            "msg": "Field required",
            "input": None,
        },
        {
            "type": "missing",
            "loc": ["body", "product"],
            "msg": "Field required",
            "input": None,
        },
        {
            "type": "missing",
            "loc": ["body", "product_two"],
            "msg": "Field required",
            "input": None,
        },
    ]
}

files = [
    ("files_data", open(PathLibPath(__file__).parent / "random_data1.csv", "rb")),
    ("files_data", open(PathLibPath(__file__).parent / "random_data2.csv", "rb")),
]


def test_auth_required_authorized_with_shield():
    client = TestClient(app)

    cookies = {"cookie_data": "test_cookie"}
    form_data = {
        "this_is_a_user": "good_user",
        "this_is_a_password": "good_password",
    }

    # Make the POST request
    response = client.post(
        "/protected_with_shield/good-f/big-product/big-name/277?g=hey&k=69&j=big-j",
        headers={"x-api-token": "secret"},
        cookies=cookies,
        files=files,
        # data=form_data,
        json={
            "product_three": {"name": "product3", "price": 300},
            "product": {"name": "product1", "price": 100},
            "product_two": {"name": "product2", "price": 200},
        },
    )

    # Assert the response
    assert response.status_code == 422, (response.status_code, response.json())
    assert response.json() == EXPECTED_JSON_WITH_OR_WITHOUT_SHIELD


def test_auth_required_authorized_without_shield():
    client = TestClient(app)

    cookies = {"cookie_data": "test_cookie"}
    form_data = {
        "this_is_a_user": "good_user",
        "this_is_a_password": "good_password",
    }

    # Make the POST request
    response = client.post(
        "/protected_without_shield/good-f/big-product/big-name/277?g=hey&k=69&j=big-j",
        headers={"x-api-token": "secret"},
        cookies=cookies,
        files=files,
        # data=form_data,
        json={
            "product_three": {"name": "product3", "price": 300},
            "product": {"name": "product1", "price": 100},
            "product_two": {"name": "product2", "price": 200},
        },
    )

    # Assert the response
    assert response.status_code == 422, (response.status_code, response.json())
    assert response.json() == EXPECTED_JSON_WITH_OR_WITHOUT_SHIELD
