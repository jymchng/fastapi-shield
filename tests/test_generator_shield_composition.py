from fastapi import FastAPI
from fastapi.testclient import TestClient

from fastapi_shield import shield


def test_multiple_shields_lifo_teardown():
    app = FastAPI()
    order = []

    @shield(name="A")
    def a():
        order.append("enter:A")
        try:
            yield {"A": True}
        finally:
            order.append("exit:A")

    @shield(name="B")
    def b():
        order.append("enter:B")
        try:
            yield {"B": True}
        finally:
            order.append("exit:B")

    @app.get("/chain")
    @a
    @b
    def chain():
        order.append("endpoint")
        return {"ok": True}

    client = TestClient(app)
    resp = client.get("/chain")
    assert resp.status_code == 200
    assert order == [
        "enter:A",  # outer executes first due to decorator wrapping order
        "enter:B",
        "endpoint",
        "exit:B",   # inner tears down first (LIFO)
        "exit:A",
    ]
