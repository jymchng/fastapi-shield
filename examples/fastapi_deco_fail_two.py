# /// script
# dependencies = [
#   "fastapi",
#   "httpx",
# ]
# ///


from fastapi import FastAPI, HTTPException, Request, Depends
from functools import wraps
from typing import Callable
from fastapi.testclient import TestClient
from inspect import Parameter, signature

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


def auth_required(endpoint: Callable):
    endpoint_params = signature(endpoint).parameters

    @wraps(endpoint)
    async def wrapper(*args, **kwargs):
        # we get the request object from the kwargs which is injected by FastAPI
        request: Request = kwargs.get("request")
        db: dict = kwargs.get("db")
        token = request.headers.get("Authorization")
        # the problem is even before we get to the validation, we have already gotten a `db` object
        # and we have already called `get_db()`
        # which is a waste of resources
        validate_token(token)
        # now we can get the username from the token
        username = get_username_from_token(token)
        if username not in db:
            raise HTTPException(status_code=401, detail="Unauthorized")
        endpoint_kwargs = {k: v for k, v in kwargs.items() if k in endpoint_params}
        return await endpoint(*args, **endpoint_kwargs)

    # this is a hack to get FastAPI to inject the request object into the wrapper
    wrapper.__signature__ = signature(endpoint).replace(
        parameters=[
            Parameter(
                name="request", kind=Parameter.POSITIONAL_ONLY, annotation=Request
            ),
            *signature(endpoint).parameters.values(),
        ]
    )
    return wrapper


@app.get("/protected")
@auth_required
async def protected(db: dict = Depends(get_db)):
    # now we no need `request` object
    # but you'll always need a db object
    # imagine you have to pass in a bazillion arguments to this function
    # and you have to remember to pass in the db object
    return {"message": "Protected endpoint"}


def test_auth_required_unauthorized():
    client = TestClient(app)
    response = client.get("/protected")
    assert response.status_code == 401, (response.status_code, response.json())
    assert response.json() == {"detail": "Unauthorized"}


def test_auth_required_authorized():
    client = TestClient(app)
    response = client.get("/protected", headers={"Authorization": "secret"})
    assert response.status_code == 200, (response.status_code, response.json())
    assert response.json() == {"message": "Protected endpoint"}


def run_tests():
    for k, fn in globals().items():
        if callable(fn) and k.startswith("test_"):
            print(f"Running test `{k}` in {__file__}")
            fn()


if __name__ == "__main__":
    # uv tool run nox -s run-examples
    run_tests()
