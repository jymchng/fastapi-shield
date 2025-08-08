from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from fastapi_shield import shield, ShieldedDepends


def test_sync_generator_resource_acquire_release_and_injection():
    app = FastAPI()
    released = {"released": False}

    def get_resource(info: dict):
        # receives enter value from shield as first param
        return info["res"]

    @shield(name="Resource")
    def resource_shield(request: Request):
        res = {"res": f"R@{id(request)}"}
        try:
            yield res
        finally:
            released["released"] = True

    @app.get("/use")
    @resource_shield
    def use(resource = ShieldedDepends(get_resource)):
        return {"resource": resource}

    client = TestClient(app)
    resp = client.get("/use")
    assert resp.status_code == 200
    assert "resource" in resp.json()
    assert released["released"] is True
