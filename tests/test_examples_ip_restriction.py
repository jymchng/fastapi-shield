import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI, Request, HTTPException, status
from fastapi_shield import shield
from unittest.mock import patch, MagicMock


# IP Restriction Shield Example App
def create_app(allowed_ips=None):
    app = FastAPI()

    # List of allowed IP addresses
    if allowed_ips is None:
        allowed_ips = ["127.0.0.1", "::1", "192.168.1.1"]

    @shield(
        name="IP Restriction",
        exception_to_raise_if_fail=HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied by IP restriction",
        ),
    )
    def ip_restriction_shield(request: Request):
        """Shield that allows only specific IP addresses"""
        client_ip = request.client.host

        if client_ip in allowed_ips:
            return {"client_ip": client_ip}
        return None

    @app.get("/internal-api")
    @ip_restriction_shield
    async def internal_api():
        return {"message": "Internal API endpoint"}

    @app.get("/")
    async def root():
        return {
            "message": "IP Restriction Example",
            "allowed_ips": allowed_ips,
            "protected_endpoint": "/internal-api",
        }

    return app, allowed_ips


@pytest.fixture
def test_app_and_ips():
    return create_app()


def create_client_with_ip(app, client_ip):
    """Create a TestClient with a mock for the client IP"""
    client = TestClient(app)

    # Save the original send method
    original_send = client.send

    # Create a patched version that modifies the client address
    def patched_send(request, **kwargs):
        # Mock Request.client to return a fixed host
        def get_client_mock(self):
            mock = MagicMock()
            mock.host = client_ip
            return mock

        # Apply the mock
        with patch("starlette.requests.Request.client", property(get_client_mock)):
            return original_send(request, **kwargs)

    # Replace the send method
    client.send = patched_send

    return client


def test_ip_restriction_allowed(test_app_and_ips):
    """Test endpoint access from allowed IP"""
    app, allowed_ips = test_app_and_ips
    for allowed_ip in allowed_ips:
        # Create client with allowed IP
        client = create_client_with_ip(app, allowed_ip)

        # Test access
        response = client.get("/internal-api")
        assert response.status_code == 200
        assert response.json() == {"message": "Internal API endpoint"}


def test_ip_restriction_denied():
    """Test endpoint access from forbidden IP"""
    app, _ = create_app(["192.168.1.1"])

    # Create client with blocked IP
    client = create_client_with_ip(app, "10.0.0.1")

    # Test access
    response = client.get("/internal-api")
    assert response.status_code == 403
    assert response.json() == {"detail": "Access denied by IP restriction"}


def test_public_endpoint_accessible_from_any_ip():
    """Test that public endpoints are accessible from any IP"""
    app, _ = create_app()

    # Test with allowed IP
    client1 = create_client_with_ip(app, "127.0.0.1")
    response1 = client1.get("/")
    assert response1.status_code == 200

    # Test with disallowed IP
    client2 = create_client_with_ip(app, "10.0.0.1")
    response2 = client2.get("/")
    assert response2.status_code == 200
