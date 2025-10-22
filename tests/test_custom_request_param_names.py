import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI, Request, HTTPException, status, Header, Query, Depends
from fastapi_shield import shield, ShieldedDepends
import time
from collections import defaultdict
from typing import Optional, List
import jwt
from datetime import datetime, timedelta
import asyncio


class TestCustomRequestParameterNames:
    """Test that shields work correctly with custom Request parameter names"""

    def test_rate_limiting_with_custom_request_name(self):
        """Test rate limiting shield with custom Request parameter name 'http_request'"""
        app = FastAPI()
        request_counts = defaultdict(list)
        max_requests = 3
        window_seconds = 1

        @shield(
            name="Rate Limiter",
            exception_to_raise_if_fail=HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Maximum {max_requests} requests per {window_seconds} seconds.",
                headers={"Retry-After": str(window_seconds)},
            ),
        )
        def rate_limit_shield(http_request: Request):
            """Limit requests based on client IP - using custom parameter name 'http_request'"""
            client_ip = "127.0.0.1"
            now = time.time()

            # Remove expired timestamps
            request_counts[client_ip] = [
                ts for ts in request_counts[client_ip] if now - ts < window_seconds
            ]

            # Check if rate limit is exceeded
            if len(request_counts[client_ip]) >= max_requests:
                return None

            # Add current timestamp and allow request
            request_counts[client_ip].append(now)
            return True

        @app.get("/rate-limited")
        @rate_limit_shield
        async def rate_limited_endpoint():
            return {"message": "Rate limited endpoint"}

        client = TestClient(app)

        # First few requests should succeed
        for i in range(max_requests):
            response = client.get("/rate-limited")
            assert response.status_code == 200, (
                f"Request {i + 1} failed: {response.json()}"
            )

        # Next request should be rate limited
        response = client.get("/rate-limited")
        assert response.status_code == 429
        assert "Rate limit exceeded" in response.json()["detail"]

    def test_gateway_auth_with_custom_request_name(self):
        """Test gateway authentication with custom Request parameter name 'req'"""
        app = FastAPI()
        JWT_SECRET = "test-secret-key"
        JWT_ALGORITHM = "HS256"

        def create_test_token(user_id: str, roles: Optional[List[str]] = None):
            """Create a test JWT token"""
            payload = {
                "sub": user_id,
                "roles": roles or ["user"],
                "exp": datetime.utcnow() + timedelta(hours=1),
            }
            return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

        @shield(name="Gateway Auth")
        async def gateway_auth_shield(req: Request, authorization: str = Header(None)):
            """Validate JWT token - using custom parameter name 'req'"""
            if not authorization:
                return None

            if not authorization.startswith("Bearer "):
                return None

            token = authorization.replace("Bearer ", "")

            try:
                payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
                # Access request URL to verify Request object is properly passed
                request_url = str(req.url)
                return {
                    "user_id": payload.get("sub"),
                    "roles": payload.get("roles", []),
                    "request_url": request_url,
                }
            except jwt.ExpiredSignatureError:
                return None
            except jwt.InvalidTokenError:
                return None

        @app.get("/protected")
        @gateway_auth_shield
        async def protected_endpoint(
            auth_data=ShieldedDepends(lambda auth_data: auth_data),
        ):
            return {
                "message": "Access granted",
                "user_id": auth_data["user_id"],
                "request_url": auth_data["request_url"],
            }

        client = TestClient(app)

        # Test with valid token
        token = create_test_token("test_user", ["user"])
        response = client.get(
            "/protected", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Access granted"
        assert data["user_id"] == "test_user"
        assert "http://testserver/protected" in data["request_url"]

        # Test without token
        response = client.get("/protected")
        assert response.status_code == 500  # Default shield failure

    def test_request_validation_with_custom_request_name(self):
        """Test request validation with custom Request parameter name 'incoming_request'"""
        app = FastAPI()

        @shield(
            name="Request Validator",
            exception_to_raise_if_fail=HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid request"
            ),
        )
        def validate_request(
            incoming_request: Request,
            user_agent: Optional[str] = Header(None),
            page: int = Query(1, ge=1),
        ):
            """Validate request headers and parameters - using custom parameter name 'incoming_request'"""
            # Check if request has required headers
            if not user_agent:
                return None

            # Access request method to verify Request object is properly passed
            method = incoming_request.method

            # Validate user agent
            if "test" not in user_agent.lower():
                return None

            return {
                "user_agent": user_agent,
                "page": page,
                "method": method,
            }

        @app.get("/validated")
        @validate_request
        async def validated_endpoint(
            validation_data=ShieldedDepends(lambda data: data),
        ):
            return {
                "message": "Request validated",
                "data": validation_data,
            }

        client = TestClient(app)

        # Test with valid request
        response = client.get(
            "/validated?page=2", headers={"User-Agent": "TestClient/1.0"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Request validated"
        assert data["data"]["user_agent"] == "TestClient/1.0"
        assert data["data"]["page"] == 2
        assert data["data"]["method"] == "GET"

        # Test with invalid user agent that doesn't contain 'test'
        response = client.get("/validated", headers={"User-Agent": "InvalidAgent/1.0"})
        assert response.status_code == 400

        # Test with user agent that doesn't contain 'test' (case sensitive)
        response = client.get("/validated", headers={"User-Agent": "Mozilla/5.0"})
        assert response.status_code == 400

    def test_multiple_shields_with_different_request_names(self):
        """Test multiple shields with different custom Request parameter names"""
        app = FastAPI()

        @shield(name="First Shield")
        def first_shield(req1: Request, x_api_key: str = Header()):
            """First shield with custom parameter name 'req1'"""
            if x_api_key == "valid-key":
                return {"api_key": x_api_key, "path": req1.url.path}
            return None

        @shield(name="Second Shield")
        def second_shield(req2: Request, first_data=ShieldedDepends(lambda data: data)):
            """Second shield with custom parameter name 'req2'"""
            # Verify both Request objects work correctly
            if req2.method == "GET" and first_data["api_key"] == "valid-key":
                return {
                    "combined_data": first_data,
                    "method": req2.method,
                    "host": req2.headers.get("host", "unknown"),
                }
            return None

        @app.get("/multi-shield")
        @first_shield
        @second_shield
        async def multi_shield_endpoint(
            combined_data=ShieldedDepends(lambda data: data),
        ):
            return {
                "message": "Multiple shields passed",
                "data": combined_data,
            }

        client = TestClient(app)

        # Test with valid API key
        response = client.get("/multi-shield", headers={"X-API-Key": "valid-key"})

        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Multiple shields passed"
        assert data["data"]["combined_data"]["api_key"] == "valid-key"
        assert data["data"]["method"] == "GET"
        assert "testserver" in data["data"]["host"]

        # Test with invalid API key
        response = client.get("/multi-shield", headers={"X-API-Key": "invalid-key"})
        assert response.status_code == 500  # Default shield failure

    def test_shield_with_request_and_other_dependencies(self):
        """Test shield that combines custom Request parameter with other FastAPI dependencies"""
        app = FastAPI()

        def get_current_time():
            """Dependency that returns current timestamp"""
            return time.time()

        @shield(
            name="Complex Shield",
            exception_to_raise_if_fail=HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Access denied"
            ),
        )
        def complex_shield(
            web_request: Request,
            current_time: float = Depends(get_current_time),
            authorization: Optional[str] = Header(None),
        ):
            """Shield with custom Request parameter name 'web_request' and other dependencies"""
            if not authorization:
                return None

            # Use Request object to get client info
            client_host = web_request.client.host if web_request.client else "unknown"

            # Simple validation
            if authorization == "Bearer valid-token":
                return {
                    "authorized": True,
                    "timestamp": current_time,
                    "client_host": client_host,
                    "path": web_request.url.path,
                }
            return None

        @app.get("/complex")
        @complex_shield
        async def complex_endpoint(shield_data=ShieldedDepends(lambda data: data)):
            return {
                "message": "Complex shield passed",
                "shield_data": shield_data,
            }

        client = TestClient(app)

        # Test with valid authorization
        response = client.get(
            "/complex", headers={"Authorization": "Bearer valid-token"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Complex shield passed"
        assert data["shield_data"]["authorized"] is True
        assert data["shield_data"]["client_host"] == "testclient"
        assert data["shield_data"]["path"] == "/complex"
        assert isinstance(data["shield_data"]["timestamp"], float)

        # Test without authorization
        response = client.get("/complex")
        assert response.status_code == 403
        assert "Access denied" in response.json()["detail"]

    def test_async_shield_with_custom_request_name(self):
        """Test async shield with custom Request parameter name"""
        app = FastAPI()

        @shield(
            name="Async Shield",
            exception_to_raise_if_fail=HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Async validation failed",
            ),
        )
        async def async_shield(http_req: Request, token: str = Header()):
            """Async shield with custom parameter name 'http_req'"""
            # Simulate async operation
            await asyncio.sleep(0.01)

            # Use Request object
            request_method = http_req.method
            request_path = http_req.url.path

            if token == "async-token":
                return {
                    "token": token,
                    "method": request_method,
                    "path": request_path,
                }
            return None

        @app.post("/async-endpoint")
        @async_shield
        async def async_endpoint(async_data=ShieldedDepends(lambda data: data)):
            return {
                "message": "Async shield passed",
                "data": async_data,
            }

        client = TestClient(app)

        # Test with valid token
        response = client.post("/async-endpoint", headers={"Token": "async-token"})

        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Async shield passed"
        assert data["data"]["token"] == "async-token"
        assert data["data"]["method"] == "POST"
        assert data["data"]["path"] == "/async-endpoint"

        # Test with invalid token
        response = client.post("/async-endpoint", headers={"Token": "invalid-token"})
        assert response.status_code == 401
        assert "Async validation failed" in response.json()["detail"]


# Import asyncio for async test
import asyncio
