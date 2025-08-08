from time import monotonic

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.testclient import TestClient

from fastapi_shield import shield, ShieldedDepends


def test_async_generator_shield_allows_and_teardown_runs():
    app = FastAPI()
    audit = {"teardown": False, "duration": None}

    @shield(name="Audit")
    async def audit_shield(request: Request):
        start = monotonic()
        try:
            yield {"start": start}
        finally:
            audit["teardown"] = True
            audit["duration"] = monotonic() - start

    @app.get("/ok")
    @audit_shield
    async def ok():
        return {"ok": True}

    client = TestClient(app)
    resp = client.get("/ok")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    assert audit["teardown"] is True
    assert audit["duration"] is not None and audit["duration"] >= 0


def test_async_generator_shield_blocks_on_falsy_enter_and_closes():
    app = FastAPI()
    closed = {"closed": False}

    @shield(name="Blocker")
    async def blocker():
        try:
            yield None  # falsy -> should block
        finally:
            closed["closed"] = True

    @app.get("/blocked")
    @blocker
    async def blocked():  # pragma: no cover - should never run
        return {"ok": False}

    client = TestClient(app)
    resp = client.get("/blocked")
    assert resp.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert "Shield with name `Blocker` blocks the request" in resp.text
    assert closed["closed"] is True


def test_async_generator_enter_exception_wrapped_to_500():
    app = FastAPI()

    @shield(name="Boom")
    async def boom():
        raise RuntimeError("kaboom")
        yield  # pragma: no cover

    @app.get("/x")
    @boom
    async def x():
        return {"ok": True}

    client = TestClient(app)
    resp = client.get("/x")
    assert resp.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert "Shield with name `Boom` failed: kaboom" in resp.text


def test_async_generator_teardown_exception_to_500():
    app = FastAPI()

    @shield(name="TDown")
    async def tdown():
        try:
            yield {"ok": True}
        finally:
            raise ValueError("outch")

    @app.get("/y")
    @tdown
    async def y():
        return {"ok": True}

    client = TestClient(app)
    resp = client.get("/y")
    assert resp.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert "Shield with name `TDown` failed: outch" in resp.text


def test_async_generator_teardown_still_runs_on_endpoint_exception():
    app = FastAPI()
    flags = {"ran": False}

    @shield(name="After")
    async def after():
        try:
            yield {"ok": True}
        finally:
            flags["ran"] = True

    @app.get("/err")
    @after
    async def err():
        raise HTTPException(status_code=418, detail="teapot")

    client = TestClient(app)
    resp = client.get("/err")
    assert resp.status_code == 418
    assert flags["ran"] is True
