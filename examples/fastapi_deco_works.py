# /// script
# dependencies = [
#   "fastapi",
#   "httpx",
# ]
# ///


from fastapi import Body, FastAPI, HTTPException, Request, Depends
from functools import wraps
from typing import Any, Callable, Optional
from fastapi.testclient import TestClient
from inspect import Parameter, signature

from fastapi.dependencies.utils import get_dependant, solve_dependencies
from fastapi.routing import compile_path
from fastapi.params import Body
from fastapi._compat import Undefined, ModelField


FAKE_DB = {
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


def validate_token(token: str):
    if token == "secret":
        return True
    else:
        raise HTTPException(status_code=401, detail="Unauthorized")


def get_db():
    return FAKE_DB


def get_user(username: str):
    return FAKE_DB[username]


def get_username_from_token(token: str):
    if token == "secret":
        return "user1"
    else:
        raise HTTPException(status_code=401, detail="Unauthorized")


app = FastAPI()


@app.get("/")
async def root():
    return {"message": "Hello World"}


def get_body_from_request(request: Request, body_field: Optional[ModelField]=None):
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
    return body


def auth_required(endpoint: Callable):
    endpoint_params = signature(endpoint).parameters

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
        _, path_format, _ = compile_path(request.url.path)
        endpoint_dependant = get_dependant(path=path_format, call=endpoint)
        endpoint_solved_dependencies = await solve_dependencies(
            request=request,
            dependant=endpoint_dependant,
            async_exit_stack=None,
            embed_body_fields=False,
            body=endpoint_dependant.body_params,
        )
        print("`endpoint_solved_dependencies`: ", endpoint_solved_dependencies)
        if endpoint_solved_dependencies.errors:
            raise HTTPException(status_code=500, detail="Failed to solve dependencies")
        kwargs.update(endpoint_solved_dependencies.values)
        endpoint_kwargs = {k: v for k, v in kwargs.items() if k in endpoint_params}
        return await endpoint(*args, **endpoint_kwargs)

    # this is a hack to get FastAPI to inject the request object into the wrapper
    wrapper.__signature__ = signature(endpoint).replace(
        parameters=[
            Parameter(
                name="request", kind=Parameter.POSITIONAL_ONLY, annotation=Request
            ),
            Parameter(
                name="db", kind=Parameter.POSITIONAL_ONLY, annotation=dict, default=Depends(get_db)
            ),
        ]
    )
    return wrapper


@app.post("/protected")
@auth_required
async def protected(body_param: dict = Body(...)):
    # now we no need `request` object
    # we don't need to pass in `db` object
    
    # the body_param is injected by FastAPI ONLY AFTER the `auth_required` is 'passed'
    return {"message": "Protected endpoint", "body_param": body_param}


def test_auth_required_unauthorized():
    client = TestClient(app)
    response = client.post("/protected", json={"name": "John"})
    assert response.status_code == 401, (response.status_code, response.json())
    assert response.json() == {"detail": "Unauthorized"}


def test_auth_required_authorized():
    client = TestClient(app)
    response = client.post("/protected", headers={"Authorization": "secret"}, json={"name": "John"})
    assert response.status_code == 200, (response.status_code, response.json())
    assert response.json() == {"message": "Protected endpoint", "body_param": {"name": "John"}}


def run_tests():
    for k, fn in globals().items():
        if callable(fn) and k.startswith("test_"):
            print(f"Running test `{k}` in {__file__}")
            fn()


if __name__ == "__main__":
    # uv tool run nox -s run-examples
    run_tests()
