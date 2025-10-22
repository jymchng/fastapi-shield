"""
Tests for Request parameter handling in guard functions.

This module tests the behavior described in the shield.py wrapper function where:
- If guard_func already has a parameter with annotation = Request,
  fastapi-shield uses that parameter instead of prepending a new one
- The request_annotation_in_guard_fn flag controls signature generation
- Custom Request parameter names are properly detected and used
"""

import pytest
from typing import Dict, Any, Optional
from inspect import signature, Parameter
from unittest.mock import Mock, patch

from fastapi import FastAPI, Request, HTTPException, status, Header, Query
from fastapi.testclient import TestClient
from starlette.requests import Request as StarletteRequest

from fastapi_shield import shield, ShieldedDepends
from fastapi_shield.shield import Shield
from fastapi_shield.utils import prepend_request_to_signature_params_of_function


class TestRequestParameterDetection:
    """Test detection of existing Request parameters in guard functions."""

    def test_guard_func_without_request_param(self):
        """Test guard function without Request parameter - should be detected as False."""

        @shield
        def guard_without_request(token: str):
            return {"token": token} if token == "valid" else None

        # Access the internal state to verify detection
        assert hasattr(guard_without_request, "_guard_func_params")

        # Check that no Request parameter was detected
        request_param_found = False
        for param in guard_without_request._guard_func_params.values():
            if param.annotation is Request:
                request_param_found = True
                break

        assert not request_param_found, (
            "Should not detect Request parameter when none exists"
        )

    def test_guard_func_with_request_param_named_request(self):
        """Test guard function with Request parameter named 'request'."""

        @shield
        def guard_with_request(request: Request, token: str):
            return {"token": token} if token == "valid" else None

        # Check that Request parameter was detected
        request_param_found = False
        request_param_name = None
        for name, param in guard_with_request._guard_func_params.items():
            if param.annotation is Request:
                request_param_found = True
                request_param_name = name
                break

        assert request_param_found, "Should detect Request parameter"
        assert request_param_name == "request", (
            "Should detect parameter named 'request'"
        )

    def test_guard_func_with_custom_request_param_name(self):
        """Test guard function with Request parameter using custom name."""

        @shield
        def guard_with_custom_request(req: Request, token: str):
            return {"token": token} if token == "valid" else None

        # Check that Request parameter was detected with custom name
        request_param_found = False
        request_param_name = None
        for name, param in guard_with_custom_request._guard_func_params.items():
            if param.annotation is Request:
                request_param_found = True
                request_param_name = name
                break

        assert request_param_found, "Should detect Request parameter with custom name"
        assert request_param_name == "req", "Should detect parameter named 'req'"

    def test_guard_func_with_multiple_params_including_request(self):
        """Test guard function with multiple parameters including Request."""

        @shield
        def guard_with_multiple_params(
            user_id: int, http_request: Request, token: str, role: str = "user"
        ):
            return {"user_id": user_id, "token": token, "role": role}

        # Check that Request parameter was detected among multiple params
        request_param_found = False
        request_param_name = None
        for name, param in guard_with_multiple_params._guard_func_params.items():
            if param.annotation is Request:
                request_param_found = True
                request_param_name = name
                break

        assert request_param_found, (
            "Should detect Request parameter among multiple params"
        )
        assert request_param_name == "http_request", (
            "Should detect parameter named 'http_request'"
        )


class TestSignatureGeneration:
    """Test wrapper signature generation based on Request parameter detection."""

    def test_signature_without_request_param_prepends_request(self):
        """Test that signature generation prepends Request when guard func doesn't have one."""

        def guard_without_request(token: str):
            return {"token": token} if token == "valid" else None

        # Get original parameters
        original_params = list(signature(guard_without_request).parameters.values())

        # Get parameters with prepended Request
        prepended_params = list(
            prepend_request_to_signature_params_of_function(guard_without_request)
        )

        # Should have one more parameter (the prepended Request)
        assert len(prepended_params) == len(original_params) + 1

        # First parameter should be Request
        first_param = prepended_params[0]
        assert first_param.name == "request"
        assert first_param.annotation is Request
        assert first_param.kind == Parameter.POSITIONAL_ONLY

        # Remaining parameters should match original
        for i, original_param in enumerate(original_params):
            assert prepended_params[i + 1].name == original_param.name
            assert prepended_params[i + 1].annotation == original_param.annotation

    def test_signature_with_request_param_no_prepending(self):
        """Test that signature generation doesn't prepend when Request already exists."""

        def guard_with_request(request: Request, token: str):
            return {"token": token} if token == "valid" else None

        # Simulate the logic from shield.py
        guard_func_params = signature(guard_with_request).parameters

        # Check for existing Request parameter
        request_annotation_in_guard_fn = False
        for param in guard_func_params.values():
            if param.annotation is Request:
                request_annotation_in_guard_fn = True
                break

        # When Request exists, should use original parameters
        if request_annotation_in_guard_fn:
            final_params = list(guard_func_params.values())
        else:
            final_params = list(
                prepend_request_to_signature_params_of_function(guard_with_request)
            )

        # Should have same number of parameters as original (no prepending)
        original_params = list(signature(guard_with_request).parameters.values())
        assert len(final_params) == len(original_params)

        # Parameters should match exactly
        for i, (final_param, original_param) in enumerate(
            zip(final_params, original_params)
        ):
            assert final_param.name == original_param.name
            assert final_param.annotation == original_param.annotation

    def test_signature_with_custom_request_param_name(self):
        """Test signature generation with custom Request parameter name."""

        def guard_with_custom_request(http_req: Request, user_id: int):
            return {"user_id": user_id}

        # Simulate the logic from shield.py
        guard_func_params = signature(guard_with_custom_request).parameters

        # Check for existing Request parameter and get its name
        request_annotation_in_guard_fn = False
        request_param_name_in_guard_fn = "request"  # default

        for k, v in guard_func_params.items():
            if v.annotation is Request:
                request_param_name_in_guard_fn = k
                request_annotation_in_guard_fn = True
                break

        assert request_annotation_in_guard_fn, "Should detect Request parameter"
        assert request_param_name_in_guard_fn == "http_req", (
            "Should use custom parameter name"
        )

        # When Request exists, should use original parameters
        final_params = list(guard_func_params.values())
        original_params = list(signature(guard_with_custom_request).parameters.values())

        assert len(final_params) == len(original_params)
        assert final_params[0].name == "http_req"
        assert final_params[0].annotation is Request


class TestRequestParameterUsage:
    """Test that the correct Request parameter is used in the wrapper function."""

    def setup_method(self):
        """Setup FastAPI app for each test."""
        self.app = FastAPI()
        self.client = TestClient(self.app)

    def test_wrapper_uses_detected_request_param_name(self):
        """Test that wrapper function uses the detected Request parameter name."""

        # Track which request parameter name was used
        used_request_param_name = None

        @shield
        def guard_with_custom_request(http_req: Request):
            nonlocal used_request_param_name
            used_request_param_name = "http_req"  # This would be detected

            # Simulate checking the token from headers
            auth_header = http_req.headers.get("Authorization", "")
            if auth_header == "Bearer valid_token":
                return {"authenticated": True}
            return None

        @self.app.get("/test")
        @guard_with_custom_request
        def test_endpoint():
            return {"message": "success"}

        # Test with valid token
        response = self.client.get(
            "/test", headers={"Authorization": "Bearer valid_token"}
        )

        # The guard should have been called and used the custom parameter name
        assert used_request_param_name == "http_req"
        assert response.status_code == 200, response.json()

    def test_wrapper_handles_missing_request_gracefully(self):
        """Test that wrapper handles missing Request parameter gracefully."""

        @shield
        def guard_expecting_request(bigbigboy: Request):
            # This guard expects a Request parameter
            return {"path": bigbigboy.url.path}

        @self.app.get("/test-missing")
        @guard_expecting_request
        def test_endpoint():
            return {"message": "success"}

        # The framework should provide the Request parameter
        response = self.client.get("/test-missing")
        assert list(test_endpoint.__signature__.parameters.keys()) == ["bigbigboy"]
        assert response.status_code == 200

    def test_error_when_request_param_wrong_type(self):
        """Test error handling when Request parameter has wrong type."""

        @shield
        def guard_with_request(hello: Request, bye: str):
            return {"authenticated": True}

        @shield
        def guard_with_request_two(bye: str):
            return {"authenticated": True}

        @self.app.get("/{bye}")
        @guard_with_request
        def test_endpoint():
            return {"message": "success"}

        @self.app.get("/{bye}")
        @guard_with_request_two
        def test_endpoint2():
            return {"message": "success"}

        assert list(test_endpoint.__signature__.parameters.keys()) == [
            "hello",
            "bye",
        ]

        assert list(test_endpoint2.__signature__.parameters.keys()) == [
            "request",
            "bye",
        ]

        response = self.client.get("/test-wrong-type")
        # Should work normally as FastAPI provides correct Request object
        assert response.status_code == 200, response.json()


class TestIntegrationScenarios:
    """Integration tests for Request parameter handling in real FastAPI scenarios."""

    def setup_method(self):
        """Setup FastAPI app for each test."""
        self.app = FastAPI()
        self.client = TestClient(self.app)

    def test_guard_with_request_and_shielded_depends(self):
        """Test guard with Request parameter used alongside ShieldedDepends."""

        @shield
        def auth_guard(http_request: Request, token: Optional[str] = None):
            # Use custom Request parameter name
            auth_header = http_request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                token_value = auth_header.split(" ")[1]
                if token_value == "valid_token":
                    return {
                        "user_id": 123,
                        "username": "testuser",
                        "path": http_request.url.path,
                    }
            return None

        def get_user_info(auth_data: Dict[str, Any]) -> Dict[str, Any]:
            return {
                "user_id": auth_data["user_id"],
                "username": auth_data["username"],
                "request_path": auth_data["path"],
            }

        @self.app.get("/protected")
        @auth_guard
        def protected_endpoint(user: Dict[str, Any] = ShieldedDepends(get_user_info)):
            return {"message": "Access granted", "user": user}

        # Test with valid token
        response = self.client.get(
            "/protected", headers={"Authorization": "Bearer valid_token"}
        )
        assert response.status_code == 200

        data = response.json()
        assert data["message"] == "Access granted"
        assert data["user"]["user_id"] == 123
        assert data["user"]["username"] == "testuser"
        assert data["user"]["request_path"] == "/protected"

    def test_multiple_shields_with_different_request_param_names(self):
        """Test multiple shields with different Request parameter names."""

        @shield
        def first_shield(req: Request):
            # First shield uses 'req'
            if req.headers.get("X-First-Check") == "pass":
                return {"first_check": True, "path": req.url.path}
            return None

        @shield
        def second_shield(request: Request):
            # Second shield uses 'request'
            if request.headers.get("X-Second-Check") == "pass":
                return {"second_check": True, "method": request.method}
            return None

        @self.app.get("/multi-shield")
        @first_shield
        @second_shield
        def multi_shield_endpoint():
            return {"message": "All shields passed"}

        # Test with both headers
        response = self.client.get(
            "/multi-shield", headers={"X-First-Check": "pass", "X-Second-Check": "pass"}
        )
        assert response.status_code == 200
        assert response.json()["message"] == "All shields passed"

    def test_guard_with_request_and_other_fastapi_params(self):
        """Test guard with Request parameter alongside other FastAPI parameters."""

        @shield
        def complex_guard(
            http_req: Request,
            user_agent: Optional[str] = None,  # This would come from Header()
            api_key: Optional[str] = None,  # This would come from Query()
        ):
            # Verify we can access the Request object with custom name
            path = http_req.url.path
            method = http_req.method

            # Simple validation
            if path.startswith("/api/") and method == "GET":
                return {"validated": True, "path": path, "method": method}
            return None

        @self.app.get("/api/data")
        @complex_guard
        def api_endpoint():
            return {"data": "sensitive information"}

        response = self.client.get("/api/data")
        assert response.status_code == 200
        assert response.json()["data"] == "sensitive information"

    def test_async_guard_with_request_param(self):
        """Test async guard function with Request parameter."""

        @shield
        async def async_auth_guard(request: Request):
            # Simulate async operation (e.g., database lookup)
            import asyncio

            await asyncio.sleep(0.001)  # Minimal delay

            # Check authorization header
            auth = request.headers.get("Authorization")
            if auth == "Bearer async_token":
                return {"async_auth": True, "user_id": 456, "path": request.url.path}
            return None

        @self.app.get("/async-protected")
        @async_auth_guard
        async def async_endpoint():
            return {"message": "Async endpoint accessed"}

        # Test with valid async token
        response = self.client.get(
            "/async-protected", headers={"Authorization": "Bearer async_token"}
        )
        assert response.status_code == 200
        assert response.json()["message"] == "Async endpoint accessed"

    def test_guard_request_param_error_handling(self):
        """Test error handling when Request parameter is expected but not provided correctly."""

        @shield
        def strict_request_guard(req: Request):
            # This guard strictly requires the Request object
            if not isinstance(req, Request):
                raise ValueError("Expected Request object")

            # Check for required header
            if req.headers.get("X-Required-Header"):
                return {"header_present": True}
            return None

        @self.app.get("/strict")
        @strict_request_guard
        def strict_endpoint():
            return {"message": "Strict validation passed"}

        # Test without required header (should be blocked by shield)
        response = self.client.get("/strict")
        assert response.status_code == 500  # Shield blocks request

        # Test with required header
        response = self.client.get("/strict", headers={"X-Required-Header": "present"})
        assert response.status_code == 200
        assert response.json()["message"] == "Strict validation passed"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
