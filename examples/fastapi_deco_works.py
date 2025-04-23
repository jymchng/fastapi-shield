# /// script
# dependencies = [
#   "fastapi",
#   "httpx",
# ]
# ///


import email.message
import json
import re
from contextlib import AsyncExitStack
from functools import wraps
from inspect import Parameter, signature
from typing import Any, Callable, Optional

from fastapi import Body, Depends, FastAPI, HTTPException, Request, params
from fastapi._compat import ModelField, Undefined
from fastapi.dependencies.models import Dependant
from fastapi.dependencies.utils import (_should_embed_body_fields,
                                        get_body_field, get_dependant,
                                        get_flat_dependant, solve_dependencies)
from fastapi.exceptions import RequestValidationError
from fastapi.routing import compile_path, get_name
from fastapi.testclient import TestClient
from pydantic import BaseModel

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
        raise HTTPException(status_code=401, detail="Unauthorized")


async def get_db():
    return FAKE_USER_DB


def get_user(username: str):
    return FAKE_USER_DB[username]


def get_username_from_token(token: str):
    if token == "secret":
        return "user1"
    else:
        raise HTTPException(status_code=401, detail="Unauthorized")


def generate_unique_id_for_fastapi_shield(dependant: Dependant, path_format: str):
    name = get_name(dependant.call)
    operation_id = f"{name}{path_format}"
    operation_id = re.sub(r"\W", "_", operation_id)
    return operation_id


async def get_body_field_should_embed_from_request(
    dependant: Dependant, path_format: str
) -> tuple[Optional[ModelField], bool]:
    flat_dependant = get_flat_dependant(dependant)
    embed_body_fields = _should_embed_body_fields(flat_dependant.body_params)
    body_field = get_body_field(
        flat_dependant=flat_dependant,
        name=generate_unique_id_for_fastapi_shield(dependant, path_format),
        embed_body_fields=embed_body_fields,
    )
    return body_field, embed_body_fields


async def get_body_from_request(
    request: Request, body_field: Optional[ModelField] = None
):
    body: Any = None
    is_body_form = body_field and isinstance(body_field.field_info, params.Form)
    async with AsyncExitStack() as file_stack:
        try:
            body: Any = None
            if body_field:
                if is_body_form:
                    body = await request.form()
                    file_stack.push_async_callback(body.close)
                else:
                    body_bytes = await request.body()
                    if body_bytes:
                        json_body: Any = Undefined
                        content_type_value = request.headers.get("content-type")
                        if not content_type_value:
                            json_body = await request.json()
                        else:
                            message = email.message.Message()
                            message["content-type"] = content_type_value
                            if message.get_content_maintype() == "application":
                                subtype = message.get_content_subtype()
                                if subtype == "json" or subtype.endswith("+json"):
                                    json_body = await request.json()
                        if json_body != Undefined:
                            body = json_body
                        else:
                            body = body_bytes
        except json.JSONDecodeError as e:
            validation_error = RequestValidationError(
                [
                    {
                        "type": "json_invalid",
                        "loc": ("body", e.pos),
                        "msg": "JSON decode error",
                        "input": {},
                        "ctx": {"error": e.msg},
                    }
                ],
                body=e.doc,
            )
            raise validation_error from e
        except HTTPException:
            # If a middleware raises an HTTPException, it should be raised again
            raise
        except Exception as e:
            http_error = HTTPException(
                status_code=400, detail="There was an error parsing the body"
            )
            raise http_error from e
    return body


async def get_solved_dependencies(
    request: Request,
    endpoint: Callable,
    dependency_cache: dict,
):
    _, path_format, _ = compile_path(request.url.path)
    endpoint_dependant = get_dependant(path=path_format, call=endpoint)
    (
        body_field,
        should_embed_body_fields,
    ) = await get_body_field_should_embed_from_request(endpoint_dependant, path_format)
    body = await get_body_from_request(request, body_field)
    async with AsyncExitStack() as stack:
        endpoint_solved_dependencies = await solve_dependencies(
            request=request,
            dependant=endpoint_dependant,
            async_exit_stack=stack,
            embed_body_fields=should_embed_body_fields,
            body=body,
            dependency_cache=dependency_cache,
        )
    return endpoint_solved_dependencies


app = FastAPI()


@app.get("/")
async def root():
    return {"message": "Hello World"}


def auth_required(endpoint: Callable):
    endpoint_params = signature(endpoint).parameters
    dependency_cache = {}

    @wraps(endpoint)
    async def wrapper(*args, **kwargs):
        request: Request = kwargs.get("request")
        db: dict = kwargs.get("db")
        token = request.headers.get("Authorization")
        validate_token(token)
        username = get_username_from_token(token)
        if username not in db:
            raise HTTPException(status_code=401, detail="Unauthorized")
        # up til here everything is same as the previous example

        # here's what different, we solve the dependencies for the endpoint
        # and inject the resolved dependencies into the kwargs
        solved_dependencies = await get_solved_dependencies(
            request, endpoint, dependency_cache
        )
        if solved_dependencies.errors:
            raise HTTPException(status_code=500, detail="Failed to solve dependencies")
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
        ]
    )
    return wrapper


@app.post("/protected")
@auth_required
async def protected(
    product: Product = Body(embed=True), product_two: Product = Body(embed=True)
):
    # now we no need `request` object
    # we don't need to pass in `db` object

    # the body_param is injected by FastAPI ONLY AFTER the `auth_required` is 'passed'

    print("`product`: ", product)
    print("`product_two`: ", product_two)
    return {
        "message": "Protected endpoint",
        "product": {"name": product.name, "price": product.price},
        "product_two": {"name": product_two.name, "price": product_two.price},
    }


def test_auth_required_unauthorized():
    client = TestClient(app)
    response = client.post(
        "/protected",
        json={
            "product": {"name": "product1", "price": 100},
            "product_two": {"name": "product2", "price": 200},
        },
    )
    assert response.status_code == 401, (response.status_code, response.json())
    assert response.json() == {"detail": "Unauthorized"}


def test_auth_required_authorized():
    client = TestClient(app)
    response = client.post(
        "/protected",
        headers={"Authorization": "secret"},
        json={
            "product": {"name": "product1", "price": 100},
            "product_two": {"name": "product2", "price": 200},
        },
    )
    assert response.status_code == 200, (response.status_code, response.json())
    assert response.json() == {
        "message": "Protected endpoint",
        "product": {"name": "product1", "price": 100},
        "product_two": {"name": "product2", "price": 200},
    }, response.json()


def run_tests():
    for k, fn in globals().items():
        if callable(fn) and k.startswith("test_"):
            print(f"Running test `{k}` in {__file__}")
            fn()


if __name__ == "__main__":
    # uv tool run nox -s run-examples
    run_tests()
