from fastapi import FastAPI, Header, HTTPException, Request, Response, status
from fastapi.testclient import TestClient

from fastapi_shield import shield, ShieldedDepends


def test_auto_error_false_custom_response_and_teardown_runs():
    app = FastAPI()
    flags = {"teardown": False}
    custom_resp = Response("blocked", status_code=418)

    @shield(name="Maybe", auto_error=False, default_response_to_return_if_fail=custom_resp)
    async def maybe():
        try:
            yield None  # falsy -> block
        finally:
            flags["teardown"] = True

    @app.get("/a")
    @maybe
    async def a():
        return {"ok": True}

    client = TestClient(app)
    r = client.get("/a")
    assert r.status_code == 418
    assert r.text == "blocked"
    assert flags["teardown"] is True


def test_custom_exception_raised_on_block_and_teardown_runs():
    app = FastAPI()
    flags = {"teardown": False}

    @shield(name="Auth", exception_to_raise_if_fail=HTTPException(401, "nope"))
    def auth():
        try:
            yield False
        finally:
            flags["teardown"] = True

    @app.get("/b")
    @auth
    def b():  # pragma: no cover
        return {"ok": True}

    client = TestClient(app)
    r = client.get("/b")
    assert r.status_code == 401
    assert r.json()["detail"] == "nope"
    assert flags["teardown"] is True


def test_optional_first_param_not_injected_but_dependency_resolves():
    app = FastAPI()

    def dep(data: dict | None = None):
        # Should be called with no injected shield data since default exists
        return data

    @shield
    def gen():
        try:
            yield {"x": 1}
        finally:
            pass

    @app.get("/c")
    @gen
    def c(val = ShieldedDepends(dep)):
        return {"val": val}

    client = TestClient(app)
    r = client.get("/c")
    assert r.status_code == 200
    assert r.json() == {"val": None}


def test_teardown_runs_when_validation_error_occurs_pre_endpoint():
    app = FastAPI()
    flags = {"teardown": False}

    @shield
    def guard():
        try:
            yield {"ok": True}
        finally:
            flags["teardown"] = True

    @app.get("/d")
    @guard
    def d(required: int):  # missing query param triggers validation error
        return {"ok": True}

    client = TestClient(app)
    r = client.get("/d")
    assert r.status_code == 422
    assert flags["teardown"] is True


def test_http_exception_in_enter_propagates():
    app = FastAPI()

    @shield
    def boom_enter():
        raise HTTPException(409, "conflict")
        yield  # pragma: no cover

    @app.get("/e")
    @boom_enter
    def e():  # pragma: no cover
        return {"ok": True}

    client = TestClient(app)
    r = client.get("/e")
    assert r.status_code == 409
    assert r.json()["detail"] == "conflict"


def test_nested_generators_inner_blocks_outer_teardown_runs():
    app = FastAPI()
    order = []

    @shield(name="Outer")
    def outer():
        order.append("enter:outer")
        try:
            yield {"o": True}
        finally:
            order.append("exit:outer")

    @shield(name="Inner")
    def inner():
        order.append("enter:inner")
        try:
            yield None
        finally:
            order.append("exit:inner")

    @app.get("/f")
    @outer
    @inner
    def f():  # pragma: no cover
        return {"ok": True}

    client = TestClient(app)
    r = client.get("/f")
    assert r.status_code == 500  # default block
    # Decorator wrapping order means outer enters first, then inner; inner blocks; inner teardown then outer teardown
    assert order == [
        "enter:outer",
        "enter:inner",
        "exit:inner",
        "exit:outer",
    ]


def test_guard_parameters_binding_with_header():
    app = FastAPI()

    @shield
    def header_guard(token: str = Header(alias="X-Token")):
        try:
            # allow only specific token
            if token == "abc":
                yield {"ok": True}
            else:
                yield None
        finally:
            pass

    @app.get("/g")
    @header_guard
    def g():
        return {"ok": True}

    client = TestClient(app)
    r1 = client.get("/g", headers={"X-Token": "abc"})
    assert r1.status_code == 200
    r2 = client.get("/g", headers={"X-Token": "nope"})
    assert r2.status_code == 500
