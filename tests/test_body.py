from threading import Event
from typing import Any

import pytest
from fastapi import BackgroundTasks, Body, Depends, FastAPI, Header, HTTPException, Path
from fastapi.testclient import TestClient
from pydantic import BaseModel

from fastapi_shield.shield import ShieldedDepends, shield

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
async def root():
    return {"message": "Hello World"}


@app.post("/protected/{username}")
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


def test_auth_required_unauthorized():
    client = TestClient(app)
    response = client.post(
        "/protected/user1",
        headers={"X-API-TOKEN": "invalid1"},
        json={"product": {"name": "product1", "price": 100}},
    )
    assert response.status_code == 401, (response.status_code, response.json())
    assert response.json() == {"detail": "Unauthorized; invalid token"}, response.json()


@pytest.mark.asyncio
async def test_auth_required_authorized():
    client = TestClient(app)
    response = client.post(
        "/protected/user1",
        headers={"X-API-TOKEN": "secret1"},
        json={"product": {"name": "product1", "price": 100}},
    )
    assert response.status_code == 200, (response.status_code, response.json())
    assert response.json() == {
        "message": "Product with name `product1` updated successfully",
    }, response.json()


def test_auth_required_authorized_with_invalid_username():
    client = TestClient(app)
    response = client.post(
        "/protected/user1",
        headers={"X-API-TOKEN": "secret2"},  # secret2 is the token for username user2
        json={"product": {"name": "product1", "price": 100}},
    )
    assert response.status_code == 401, (response.status_code, response.json())
    assert response.json() == {"detail": "Unauthorized; role mismatch"}, (
        response.json()
    )  # because user2 is not an admin


def test_user1_cannot_access_user2_endpoint():
    client = TestClient(app)
    response = client.post(
        "/protected/user2",
        headers={"X-API-TOKEN": "secret1"},
        json={"product": {"name": "product1", "price": 100}},
    )
    assert response.status_code == 401, (response.status_code, response.json())
    assert response.json() == {"detail": "Unauthorized; username mismatch"}, (
        response.json()
    )


def test_user2_cannot_update_product_for_user2_because_he_is_not_admin():
    client = TestClient(app)
    response = client.post(
        "/protected/user2",
        headers={"X-API-TOKEN": "secret2"},
        json={"product": {"name": "product1", "price": 100}},
    )
    assert response.status_code == 401, (response.status_code, response.json())
    assert response.json() == {"detail": "Unauthorized; role mismatch"}, response.json()


@pytest.mark.skip(reason="Cannot test background task because it is not async")
async def test_background_task_is_executed():
    assert "test_task" in task_events, "Event not created"
    assert task_events["test_task"].wait(3), "Task didn't complete in time"

    assert "test_task" in task_results
    assert (
        "Background task: Product with name `product1` updated successfully"
        in task_results["test_task"]
    )
