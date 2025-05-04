from fastapi import FastAPI, Response
from fastapi_shield import shield
from fastapi.testclient import TestClient

app = FastAPI()


@shield(
    name="Null Shield",
    default_response_to_return_if_fail=Response(
        content="Null Shield", media_type="text/plain", status_code=200
    ),
)
def null_shield():
    return True


fake_items_db = [
    {"item_name": "Foo"},
    {"item_name": "Bar"},
    {"item_name": "Baz"},
    {"item_name": "Qux"},
    {"item_name": "Quux"},
    {"item_name": "Quuz"},
    {"item_name": "Grault"},
    {"item_name": "Garply"},
    {"item_name": "Waldo"},
    {"item_name": "Fred"},
    {"item_name": "Plugh"},
    {"item_name": "Xyzzy"},
    {"item_name": "Thud"},
]


@app.get("/items/{path_name}")
@null_shield
async def read_item(
    path_name: str, skip: int = 0, limit: int = 10, include_name: bool = True
):
    return {
        "items": fake_items_db[skip : skip + limit],
        "path_name": path_name,
        "include_name": include_name,
    }


def test_default_query():
    client = TestClient(app)
    response = client.get("/items/hello")
    assert response.status_code == 200
    assert response.json() == {
        "include_name": True,
        "items": [
            {"item_name": "Foo"},
            {"item_name": "Bar"},
            {"item_name": "Baz"},
            {"item_name": "Qux"},
            {"item_name": "Quux"},
            {"item_name": "Quuz"},
            {"item_name": "Grault"},
            {"item_name": "Garply"},
            {"item_name": "Waldo"},
            {"item_name": "Fred"},
        ],
        "path_name": "hello",
    }


def test_default_query_with_include_name_false():
    client = TestClient(app)
    response = client.get("/items/hello?include_name=false")
    assert response.status_code == 200
    assert response.json() == {
        "include_name": False,
        "items": [
            {"item_name": "Foo"},
            {"item_name": "Bar"},
            {"item_name": "Baz"},
            {"item_name": "Qux"},
            {"item_name": "Quux"},
            {"item_name": "Quuz"},
            {"item_name": "Grault"},
            {"item_name": "Garply"},
            {"item_name": "Waldo"},
            {"item_name": "Fred"},
        ],
        "path_name": "hello",
    }
