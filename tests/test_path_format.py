from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from fastapi_shield import shield

app = FastAPI()


@shield
def useless_shield():
    return True


@app.get("/")
@useless_shield
@useless_shield
@useless_shield
@useless_shield
@useless_shield
@useless_shield
@useless_shield
@useless_shield
@useless_shield
@useless_shield
@useless_shield
@useless_shield
def endpoint():
    return {"message": "Hello, World!"}


def test_path_format_is_called_only_once():
    # Check if the path format is called only once
    client = TestClient(app)
    with patch(
        "fastapi_shield.utils.get_path_format_from_request_for_endpoint"
    ) as mock_get_path_format:
        mock_get_path_format.return_value = "/"
        response = client.get("/")
        assert response.status_code == 200
        assert response.json() == {"message": "Hello, World!"}
        assert mock_get_path_format.call_count == 1

    assert endpoint.__wrapped__.__shielded_endpoint_path_format__ == "/"
