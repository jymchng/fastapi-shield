# /// script
# dependencies = [
#   "fastapi",
#   "httpx",
# ]
# ///


from fastapi import FastAPI, HTTPException, Request
from functools import wraps
from typing import Callable
from fastapi.testclient import TestClient

app = FastAPI()


@app.get("/")
async def root():
    return {"message": "Hello World"}


def auth_required(endpoint: Callable):
    @wraps(endpoint)
    async def wrapper(request: Request, *args, **kwargs):
        token = request.headers.get("Authorization")
        if token != "secret":
            raise HTTPException(status_code=401, detail="Unauthorized")
        return await endpoint(request, *args, **kwargs)

    return wrapper


@app.get("/protected")
@auth_required
async def protected(request: Request):
    # works but you'll always need a request object
    # imagine you have to pass in a bazillion arguments to this function
    # and you have to remember to pass in the request object
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
