# /// script
# dependencies = [
#   "fastapi",
#   "uvicorn",
#   "httpx",
# ]
# ///

import sys
import os

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from fastapi import (
    BackgroundTasks,
    Body,
    FastAPI,
    HTTPException,
    Header,
    Path,
    Depends,
)
from typing import Any
from pydantic import BaseModel
from fastapi_shield.shield import ShieldedDepends, patch_shields_for_openapi, shield
from threading import Event

# Create global variables to track task execution
task_results: dict[str, str] = {}
task_events: dict[str, Event] = {}

FAKE_USER_DB = {
    "user1": {
        "username": "user1",
        "password": "password1",
        "roles": ["admin"],
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
            return {"username": "user1", "roles": ["admin"]}
        elif token == "secret2":
            return {"username": "user2", "roles": ["user"]}
        elif token == "secret3":
            return {"username": "user3", "roles": ["user"]}
    else:
        raise HTTPException(status_code=401, detail="Unauthorized; token mismatch")


# Background task function
async def write_log(task_id, message):
    print(f"write_log: {task_id} {message}")
    task_results[task_id] = message
    if task_id in task_events:
        task_events[task_id].set()


@shield
# simple shield that will return the `x_api_token` header if the token is valid
# `auth_required` shield will be a decorator
def auth_required(
    # FastAPI will inject the `x_api_token` header into the `auth_required` shield
    x_api_token: str = Header(),
):
    if validate_token(x_api_token):
        return x_api_token
    return None


# a decorator that returns a shield
def roles_check(roles: list[str]):
    @shield
    # shield can be async
    async def decorator(
        authenticated_payload: dict[str, Any] = ShieldedDepends(get_payload_from_token),
    ):
        if any(role in authenticated_payload["roles"] for role in roles):
            return authenticated_payload
        else:
            raise HTTPException(status_code=401, detail="Unauthorized; role mismatch")

    return decorator


# another shield that returns a shield
@shield
async def username_required(
    authenticated_payload: dict[str, Any] = ShieldedDepends(lambda payload: payload),
    # any dependency can be injected here, e.g. `Path`, `Query`, `Body`, etc.
    username: str = Path(),
):
    if authenticated_payload["username"] == username:
        return authenticated_payload
    else:
        raise HTTPException(status_code=401, detail="Unauthorized; username mismatch")


app = FastAPI()


@app.get("/")
@patch_shields_for_openapi
async def root():
    return {"message": "Hello World"}


os.environ["ENV"] = "PROD"


@app.get("/say-hello/{name}")
@patch_shields_for_openapi(activated_when=os.environ.get("ENV", "LOCAL") == "LOCAL")
@auth_required  # this shield will return the payload if the token is valid
async def name_will_not_appear_in_openapi_as_path_param(name: str):
    # name will NOT appear in the openapi schema, it is a limitation of fastapi-shield
    return {"message": f"Hello {name}"}


os.environ["ENV"] = "LOCAL"


@app.get("/say-hello-with-shield/{name}")
@patch_shields_for_openapi(activated_when=os.environ.get("ENV", "LOCAL") == "LOCAL")
@auth_required  # this shield will return the payload if the token is valid
async def name_will_appear_in_openapi_as_path_param(name: str):
    # name will appear in the openapi schema
    return {"message": f"Hello {name} with shield"}


@app.post("/protected/{username}")
@patch_shields_for_openapi
@auth_required  # this shield will return the payload if the token is valid
@roles_check(["admin"])  # this shield will return the payload if the user is an admin
@username_required  # this shield will return the payload if the username is the same as the username in the path
async def update_product(
    # now we no need `request` object
    # if any of the shield blocks the request, the dependency injection will not happen
    # e.g. `background_tasks` will not be injected if any of the shield blocks the request
    background_tasks: BackgroundTasks,
    # e.g. `product` will not be injected if any of the shield blocks the request
    product: Product = Body(embed=True),
    # simple in memory db, just for demo
    # `product_db` dependency is injected by FastAPI
    # AND it is ONLY injected after the (`auth_required` shield, `roles_check` shield, `username_required` shield) are 'passed'
    product_db: dict[str, Product] = Depends(get_product_db),
):
    # just focus on the BUSINESS LOGIC here
    # update the product in the product_db
    # we don't need to care about the auth and authorization
    # as the shields will take care of it
    product_db[product.name] = product

    # background_tasks is injected by FastAPI
    # AND it is ONLY injected after the (`auth_required` shield, `roles_check` shield, `username_required` shield) are 'passed'
    # if any of the shield blocks the request, the dependency injection will not happen
    # background_task will work as expected
    # Add task to run in background
    task_id = "test_task"
    assert isinstance(background_tasks, BackgroundTasks), (
        "`background_tasks` is not a BackgroundTasks object"
    )
    background_tasks.add_task(
        write_log,
        task_id=task_id,
        message="Background task: Product with name `{}` updated successfully".format(
            product.name
        ),
    )

    # Create event for testing
    task_events[task_id] = Event()
    return {
        "message": "Product with name `{}` updated successfully".format(product.name),
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
