import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI, Header, HTTPException, Depends, Request, Response
from fastapi_shield import shield, ShieldedDepends
from typing import Optional, Dict, List, Any, NewType
import time
import jwt
import asyncio
from unittest.mock import patch, MagicMock


class TestBasicShieldArchitecture:
    """Tests for basic shield architecture patterns"""

    def setup_method(self):
        """Setup the FastAPI app for each test"""
        app = FastAPI()

        # Basic shield pattern
        @shield(name="Request Logger")
        async def log_request(request: Request) -> Optional[Dict[str, Any]]:
            """Shield that logs request details and returns request metadata"""
            start_time = time.time()

            # Return enriched data that can be used by the endpoint
            return {
                "start_time": start_time,
                "method": request.method,
                "path": request.url.path,
                "client_ip": request.client.host,
            }

        @app.get("/api/data")
        @log_request
        async def get_data(
            request_info: Dict[str, Any] = ShieldedDepends(lambda data: data),
        ):
            """Endpoint that uses logged request information"""
            return {
                "message": "Data retrieved successfully",
                "request_info": request_info,
            }

        self.app = app
        self.client = TestClient(app)

    def test_basic_shield_functionality(self):
        """Test basic shield functionality with request logging"""
        response = self.client.get("/api/data")
        assert response.status_code == 200

        data = response.json()
        assert data["message"] == "Data retrieved successfully"
        assert "request_info" in data

        request_info = data["request_info"]
        assert request_info["method"] == "GET"
        assert request_info["path"] == "/api/data"
        assert "start_time" in request_info
        assert "client_ip" in request_info


class TestShieldChaining:
    """Tests for shield chaining and composition patterns"""

    def setup_method(self):
        """Setup the FastAPI app for each test"""
        app = FastAPI()

        # First shield: JWT Authentication
        @shield(name="JWT Authentication")
        async def jwt_auth_shield(authorization: str = Header()) -> Optional[Dict]:
            """Validates JWT token and extracts payload"""
            if not authorization.startswith("Bearer "):
                return None

            token = authorization.replace("Bearer ", "")

            try:
                # Use test secret key
                payload = jwt.decode(token, "test-secret-key", algorithms=["HS256"])
                return payload
            except jwt.PyJWTError:
                return None

        # Second shield: Role Extraction (depends on first shield)
        @shield(name="Role Extraction")
        async def role_extraction_shield(
            payload: Dict = ShieldedDepends(lambda payload: payload),
        ) -> Optional[Dict]:
            """Extracts user roles and creates user context"""
            if not payload or "user_id" not in payload:
                return None

            user_context = {
                "user_id": payload.get("user_id"),
                "username": payload.get("username"),
                "roles": payload.get("roles", []),
                "permissions": payload.get("permissions", []),
            }

            return user_context

        # Third shield: Role Validation (depends on second shield)
        def require_role(required_role: str):
            """Factory function that creates role-checking shields"""

            @shield(
                name=f"Role Check ({required_role})",
                exception_to_raise_if_fail=HTTPException(
                    status_code=403, detail=f"Role '{required_role}' required"
                ),
            )
            async def role_shield(
                user_context: Dict = ShieldedDepends(lambda user_context: user_context),
            ) -> Optional[Dict]:
                """Shield that checks if user has required role"""
                user_roles = user_context.get("roles", [])
                if required_role in user_roles:
                    return user_context
                return None

            return role_shield

        # Create specific role shields
        admin_role_shield = require_role("admin")
        editor_role_shield = require_role("editor")

        # Endpoints using chained shields
        @app.get("/user-profile")
        @jwt_auth_shield
        @role_extraction_shield
        async def user_profile(
            user: Dict = ShieldedDepends(lambda user_context: user_context),
        ):
            """Endpoint accessible to any authenticated user"""
            return {
                "user_id": user["user_id"],
                "username": user["username"],
                "roles": user["roles"],
            }

        @app.get("/admin-panel")
        @jwt_auth_shield
        @role_extraction_shield
        @admin_role_shield
        async def admin_panel(
            user: Dict = ShieldedDepends(lambda user_context: user_context),
        ):
            """Endpoint accessible only to admin users"""
            return {"message": "Welcome to admin panel", "user": user}

        self.app = app
        self.client = TestClient(app)

    def create_test_token(self, user_id: str, username: str, roles: List[str] = None):
        """Helper to create test JWT tokens"""
        payload = {"user_id": user_id, "username": username, "roles": roles or ["user"]}
        return jwt.encode(payload, "test-secret-key", algorithm="HS256")

    def test_user_profile_with_valid_token(self):
        """Test user profile access with valid token"""
        token = self.create_test_token("user123", "john_doe", ["user"])

        response = self.client.get(
            "/user-profile", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["user_id"] == "user123"
        assert data["username"] == "john_doe"
        assert data["roles"] == ["user"]

    def test_user_profile_with_invalid_token(self):
        """Test user profile access with invalid token"""
        response = self.client.get(
            "/user-profile", headers={"Authorization": "Bearer invalid_token"}
        )

        assert response.status_code == 500  # Shield blocks request

    def test_admin_panel_with_admin_role(self):
        """Test admin panel access with admin role"""
        token = self.create_test_token("admin123", "admin_user", ["admin", "user"])

        response = self.client.get(
            "/admin-panel", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Welcome to admin panel"
        assert data["user"]["user_id"] == "admin123"

    def test_admin_panel_without_admin_role(self):
        """Test admin panel access without admin role"""
        token = self.create_test_token("user123", "regular_user", ["user"])

        response = self.client.get(
            "/admin-panel", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 403
        assert "Role 'admin' required" in response.json()["detail"]

    def test_missing_authorization_header(self):
        """Test access without authorization header"""
        response = self.client.get("/user-profile")
        assert response.status_code == 422  # FastAPI validation error


class TestDatabaseIntegration:
    """Tests for database integration with shields"""

    def setup_method(self):
        """Setup the FastAPI app for each test"""
        app = FastAPI()

        # Mock database dependency
        async def get_database():
            """Simulated database connection"""
            return {
                "api_keys": {
                    "valid_key_123": {
                        "user_id": "user1",
                        "permissions": ["read", "write"],
                        "active": True,
                    },
                    "admin_key_456": {
                        "user_id": "admin1",
                        "permissions": ["read", "write", "admin"],
                        "active": True,
                    },
                    "inactive_key": {
                        "user_id": "user2",
                        "permissions": ["read"],
                        "active": False,
                    },
                },
                "users": {
                    "user1": {"username": "john_doe", "email": "john@example.com"},
                    "admin1": {"username": "admin", "email": "admin@example.com"},
                },
            }

        # Database authentication shield
        @shield(name="Database Auth")
        async def db_auth_shield(
            api_key: str = Header(), db: Dict[str, Any] = Depends(get_database)
        ) -> Optional[Dict]:
            """Shield that validates API key against database"""
            api_keys = db.get("api_keys", {})

            if api_key not in api_keys:
                return None

            key_data = api_keys[api_key]
            if not key_data.get("active", False):
                return None

            return {
                "user_id": key_data["user_id"],
                "permissions": key_data["permissions"],
            }

        # User enrichment function (used with ShieldedDepends)
        async def enrich_user_data(
            auth_data: Dict,  # Comes from shield
            db: Dict[str, Any] = Depends(get_database),  # Database dependency
        ) -> Dict:
            """Function that enriches auth data with user information"""
            user_id = auth_data["user_id"]
            users = db.get("users", {})

            user_info = users.get(user_id, {})

            return {
                **auth_data,
                "username": user_info.get("username"),
                "email": user_info.get("email"),
            }

        @app.get("/user-info")
        @db_auth_shield
        async def get_user_info(user_data: Dict = ShieldedDepends(enrich_user_data)):
            """Endpoint that returns enriched user information"""
            return {
                "user_id": user_data["user_id"],
                "username": user_data["username"],
                "email": user_data["email"],
                "permissions": user_data["permissions"],
            }

        self.app = app
        self.client = TestClient(app)

    def test_valid_api_key_access(self):
        """Test access with valid API key"""
        response = self.client.get("/user-info", headers={"api-key": "valid_key_123"})

        assert response.status_code == 200
        data = response.json()
        assert data["user_id"] == "user1"
        assert data["username"] == "john_doe"
        assert data["email"] == "john@example.com"
        assert data["permissions"] == ["read", "write"]

    def test_admin_api_key_access(self):
        """Test access with admin API key"""
        response = self.client.get("/user-info", headers={"api-key": "admin_key_456"})

        assert response.status_code == 200
        data = response.json()
        assert data["user_id"] == "admin1"
        assert data["username"] == "admin"
        assert "admin" in data["permissions"]

    def test_invalid_api_key(self):
        """Test access with invalid API key"""
        response = self.client.get("/user-info", headers={"api-key": "invalid_key"})

        assert response.status_code == 500  # Shield blocks request

    def test_inactive_api_key(self):
        """Test access with inactive API key"""
        response = self.client.get("/user-info", headers={"api-key": "inactive_key"})

        assert response.status_code == 500  # Shield blocks request

    def test_missing_api_key(self):
        """Test access without API key"""
        response = self.client.get("/user-info")
        assert response.status_code == 422  # FastAPI validation error


class TestShieldFactoryPatterns:
    """Tests for shield factory patterns"""

    def setup_method(self):
        """Setup the FastAPI app for each test"""
        app = FastAPI()

        def create_rate_limit_shield(max_requests: int, window_seconds: int):
            """Factory function that creates rate limiting shields"""

            # In-memory storage for testing
            request_counts = {}

            @shield(
                name=f"Rate Limit ({max_requests}/{window_seconds}s)",
                exception_to_raise_if_fail=HTTPException(
                    status_code=429,
                    detail="Rate limit exceeded",
                    headers={"Retry-After": str(window_seconds)},
                ),
            )
            async def rate_limit_shield(x_client_id: str = Header()) -> Optional[Dict]:
                """Shield that enforces rate limiting per client"""
                current_time = time.time()

                # Clean old entries
                cutoff_time = current_time - window_seconds
                request_counts[x_client_id] = [
                    req_time
                    for req_time in request_counts.get(x_client_id, [])
                    if req_time > cutoff_time
                ]

                # Check rate limit
                client_requests = request_counts.get(x_client_id, [])
                if len(client_requests) >= max_requests:
                    return None

                # Record this request
                client_requests.append(current_time)
                request_counts[x_client_id] = client_requests

                return {
                    "client_id": x_client_id,
                    "requests_made": len(client_requests),
                    "requests_remaining": max_requests - len(client_requests),
                }

            return rate_limit_shield

        def create_feature_flag_shield(feature_name: str):
            """Factory function that creates feature flag shields"""

            # Mock feature flags
            feature_flags = {
                "new_api": {"enabled": True, "allowed_users": ["premium"]},
                "beta_feature": {"enabled": False, "allowed_users": []},
                "admin_feature": {"enabled": True, "allowed_users": ["admin"]},
            }

            @shield(
                name=f"Feature Flag ({feature_name})",
                exception_to_raise_if_fail=HTTPException(
                    status_code=404, detail=f"Feature '{feature_name}' not available"
                ),
            )
            async def feature_flag_shield(
                user_type: str = Header(default="regular"),
            ) -> Optional[Dict]:
                """Shield that checks feature flag availability"""
                flag = feature_flags.get(feature_name)

                if not flag or not flag.get("enabled", False):
                    return None

                allowed_users = flag.get("allowed_users", [])
                if allowed_users and user_type not in allowed_users:
                    return None

                return {
                    "feature": feature_name,
                    "user_type": user_type,
                    "access_granted": True,
                }

            return feature_flag_shield

        # Create shield instances
        api_rate_limit = create_rate_limit_shield(max_requests=3, window_seconds=60)
        new_api_feature = create_feature_flag_shield("new_api")
        beta_feature = create_feature_flag_shield("beta_feature")

        @app.get("/api/limited")
        @api_rate_limit
        async def limited_endpoint(
            rate_info: Dict = ShieldedDepends(lambda info: info),
        ):
            """Endpoint with rate limiting"""
            return {"message": "API call successful", "rate_limit_info": rate_info}

        @app.get("/api/new-feature")
        @new_api_feature
        async def new_feature_endpoint(
            feature_info: Dict = ShieldedDepends(lambda info: info),
        ):
            """Endpoint protected by feature flag"""
            return {"message": "New feature accessed", "feature_info": feature_info}

        @app.get("/api/beta-feature")
        @beta_feature
        async def beta_feature_endpoint(
            feature_info: Dict = ShieldedDepends(lambda info: info),
        ):
            """Endpoint protected by disabled feature flag"""
            return {"message": "Beta feature accessed", "feature_info": feature_info}

        self.app = app
        self.client = TestClient(app)

    def test_rate_limiting_within_limit(self):
        """Test rate limiting within allowed requests"""
        # First request should succeed
        response = self.client.get("/api/limited", headers={"x-client-id": "client1"})

        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "API call successful"
        assert data["rate_limit_info"]["client_id"] == "client1"
        assert data["rate_limit_info"]["requests_made"] == 1

    def test_rate_limiting_exceeds_limit(self):
        """Test rate limiting when exceeding allowed requests"""
        client_id = "client2"

        # Make requests up to the limit
        for i in range(3):
            response = self.client.get(
                "/api/limited", headers={"x-client-id": client_id}
            )
            assert response.status_code == 200

        # Next request should be rate limited
        response = self.client.get("/api/limited", headers={"x-client-id": client_id})

        assert response.status_code == 429
        assert "Rate limit exceeded" in response.json()["detail"]
        assert "Retry-After" in response.headers

    def test_feature_flag_enabled_with_permission(self):
        """Test feature flag access with proper permissions"""
        response = self.client.get("/api/new-feature", headers={"user-type": "premium"})

        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "New feature accessed"
        assert data["feature_info"]["feature"] == "new_api"
        assert data["feature_info"]["user_type"] == "premium"

    def test_feature_flag_enabled_without_permission(self):
        """Test feature flag access without proper permissions"""
        response = self.client.get("/api/new-feature", headers={"user-type": "regular"})

        assert response.status_code == 404
        assert "Feature 'new_api' not available" in response.json()["detail"]

    def test_feature_flag_disabled(self):
        """Test access to disabled feature"""
        response = self.client.get(
            "/api/beta-feature", headers={"user-type": "premium"}
        )

        assert response.status_code == 404
        assert "Feature 'beta_feature' not available" in response.json()["detail"]


class TestConditionalShieldApplication:
    """Tests for conditional shield application"""

    def setup_method(self):
        """Setup the FastAPI app for each test"""
        app = FastAPI()

        @shield(name="Conditional Auth")
        async def conditional_auth_shield(
            request: Request, x_skip_auth: Optional[str] = Header(None)
        ) -> Optional[Dict]:
            """Shield that applies authentication conditionally"""

            # Skip auth for health check endpoints
            if request.url.path in ["/health", "/status"]:
                return {"auth_skipped": True, "reason": "health_check"}

            # Skip auth if special header is present (for testing)
            if x_skip_auth == "development":
                return {"auth_skipped": True, "reason": "development_mode"}

            # Apply normal authentication
            auth_header = request.headers.get("authorization", "")
            if not auth_header.startswith("Bearer "):
                return None

            # Validate token (simplified)
            token = auth_header.replace("Bearer ", "")
            if token == "valid_token":
                return {
                    "auth_skipped": False,
                    "user_id": "authenticated_user",
                    "token": token,
                }

            return None

        @app.get("/api/data")
        @conditional_auth_shield
        async def get_data(auth_info: Dict = ShieldedDepends(lambda info: info)):
            """Endpoint with conditional authentication"""
            return {"message": "Data retrieved", "auth_info": auth_info}

        @app.get("/health")
        @conditional_auth_shield
        async def health_check(auth_info: Dict = ShieldedDepends(lambda info: info)):
            """Health check endpoint (auth skipped)"""
            return {"status": "healthy", "auth_info": auth_info}

        self.app = app
        self.client = TestClient(app)

    def test_health_check_skips_auth(self):
        """Test that health check endpoint skips authentication"""
        response = self.client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["auth_info"]["auth_skipped"] is True
        assert data["auth_info"]["reason"] == "health_check"

    def test_development_mode_skips_auth(self):
        """Test that development mode header skips authentication"""
        response = self.client.get("/api/data", headers={"x-skip-auth": "development"})

        assert response.status_code == 200
        data = response.json()
        assert data["auth_info"]["auth_skipped"] is True
        assert data["auth_info"]["reason"] == "development_mode"

    def test_valid_token_authentication(self):
        """Test normal authentication with valid token"""
        response = self.client.get(
            "/api/data", headers={"authorization": "Bearer valid_token"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["auth_info"]["auth_skipped"] is False
        assert data["auth_info"]["user_id"] == "authenticated_user"

    def test_invalid_token_blocked(self):
        """Test that invalid token is blocked"""
        response = self.client.get(
            "/api/data", headers={"authorization": "Bearer invalid_token"}
        )

        assert response.status_code == 500  # Shield blocks request

    def test_missing_auth_blocked(self):
        """Test that missing authentication is blocked"""
        response = self.client.get("/api/data")

        assert response.status_code == 500  # Shield blocks request


class TestErrorHandlingAndCustomResponses:
    """Tests for error handling and custom responses"""

    def setup_method(self):
        """Setup the FastAPI app for each test"""
        app = FastAPI()

        # Shield with custom error handling
        @shield(
            name="Custom Error Shield",
            exception_to_raise_if_fail=HTTPException(
                status_code=418,
                detail="I'm a teapot - custom error message",
                headers={"X-Custom-Header": "shield-blocked"},
            ),
        )
        async def custom_error_shield(
            test_mode: str = Header(default="normal"),
        ) -> Optional[Dict]:
            """Shield that demonstrates custom error responses"""

            if test_mode == "fail":
                return None  # This will trigger the custom exception

            if test_mode == "error":
                # Shield can raise its own exceptions
                raise HTTPException(
                    status_code=400,
                    detail="Shield internal error",
                    headers={"X-Error-Source": "shield"},
                )

            return {"test_mode": test_mode, "status": "success"}

        # Shield with custom response (no exception)
        @shield(
            name="Custom Response Shield",
            auto_error=False,  # Don't raise exception on failure
            default_response_to_return_if_fail=Response(
                content="Access denied by shield",
                status_code=403,
                headers={"X-Shield-Response": "custom"},
            ),
        )
        async def custom_response_shield(
            access_level: str = Header(default="guest"),
        ) -> Optional[Dict]:
            """Shield that returns custom response instead of raising exception"""

            if access_level in ["admin", "user"]:
                return {"access_level": access_level, "granted": True}

            return None  # This will return the custom response

        @app.get("/test-custom-error")
        @custom_error_shield
        async def test_custom_error(data: Dict = ShieldedDepends(lambda data: data)):
            """Endpoint that tests custom error handling"""
            return {"message": "Success", "data": data}

        @app.get("/test-custom-response")
        @custom_response_shield
        async def test_custom_response(data: Dict = ShieldedDepends(lambda data: data)):
            """Endpoint that tests custom response handling"""
            return {"message": "Access granted", "data": data}

        self.app = app
        self.client = TestClient(app)

    def test_custom_error_success(self):
        """Test successful shield execution"""
        response = self.client.get(
            "/test-custom-error", headers={"test-mode": "normal"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Success"
        assert data["data"]["test_mode"] == "normal"

    def test_custom_error_failure(self):
        """Test custom error response when shield fails"""
        response = self.client.get("/test-custom-error", headers={"test-mode": "fail"})

        assert response.status_code == 418
        assert response.json()["detail"] == "I'm a teapot - custom error message"
        assert response.headers["X-Custom-Header"] == "shield-blocked"

    def test_shield_internal_error(self):
        """Test shield raising its own exception"""
        response = self.client.get("/test-custom-error", headers={"test-mode": "error"})

        assert response.status_code == 400
        assert response.json()["detail"] == "Shield internal error"
        assert response.headers["X-Error-Source"] == "shield"

    def test_custom_response_success(self):
        """Test successful access with custom response shield"""
        response = self.client.get(
            "/test-custom-response", headers={"access-level": "admin"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Access granted"
        assert data["data"]["access_level"] == "admin"

    def test_custom_response_failure(self):
        """Test custom response when shield fails (no exception)"""
        response = self.client.get(
            "/test-custom-response", headers={"access-level": "guest"}
        )

        assert response.status_code == 403
        assert response.text == "Access denied by shield"
        assert response.headers["X-Shield-Response"] == "custom"


class TestPerformanceMonitoring:
    """Tests for performance monitoring and metrics"""

    def setup_method(self):
        """Setup the FastAPI app for each test"""
        app = FastAPI()

        # Performance monitoring shield
        @shield(name="Performance Monitor")
        async def performance_monitor_shield(request: Request) -> Dict:
            """Shield that tracks request performance metrics"""

            start_time = time.time()

            # Simulate some processing
            await asyncio.sleep(0.001)  # 1ms delay

            return {
                "start_time": start_time,
                "method": request.method,
                "path": request.url.path,
                "client_ip": request.client.host,
                "user_agent": request.headers.get("user-agent", "unknown"),
            }

        # Function to calculate and log performance metrics
        async def log_performance_metrics(
            metrics: Dict,  # Comes from shield
            request: Request,  # Additional dependency
        ) -> Dict:
            """Function that calculates and logs performance metrics"""

            current_time = time.time()
            duration = current_time - metrics["start_time"]

            return {**metrics, "duration": duration, "is_slow": duration > 0.1}

        @app.get("/api/monitored")
        @performance_monitor_shield
        async def monitored_endpoint(
            perf_data: Dict = ShieldedDepends(log_performance_metrics),
        ):
            """Endpoint with performance monitoring"""

            # Simulate some work
            await asyncio.sleep(0.01)  # 10ms delay

            return {
                "message": "Operation completed",
                "performance": {
                    "duration": perf_data["duration"],
                    "is_slow": perf_data["is_slow"],
                },
            }

        self.app = app
        self.client = TestClient(app)

    def test_performance_monitoring(self):
        """Test performance monitoring functionality"""
        response = self.client.get("/api/monitored")

        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Operation completed"

        performance = data["performance"]
        assert "duration" in performance
        assert isinstance(performance["duration"], float)
        assert performance["duration"] > 0
        assert isinstance(performance["is_slow"], bool)


class TestBestPracticesPatterns:
    """Tests for best practices patterns"""

    def setup_method(self):
        """Setup the FastAPI app for each test"""
        app = FastAPI()

        # Create specific types for domain
        AuthenticatedUser = NewType("AuthenticatedUser", Dict[str, Any])
        AdminUser = NewType("AdminUser", Dict[str, Any])

        # Single-purpose shields
        @shield(name="Authentication")
        async def auth_shield(token: str = Header()) -> Optional[Dict]:
            """Only handles authentication"""
            if token == "valid_token":
                return {"user_id": "user123", "username": "john_doe"}
            return None

        @shield(name="Authorization")
        async def authz_shield(
            user: Dict = ShieldedDepends(lambda user: user),
        ) -> Optional[Dict]:
            """Only handles authorization"""
            if user and user.get("user_id"):
                return user
            return None

        # Shield factory for reusability
        def create_permission_shield(required_permission: str):
            @shield(name=f"Permission: {required_permission}")
            async def permission_shield(
                user: Dict = ShieldedDepends(lambda user: user),
            ) -> Optional[Dict]:
                user_permissions = user.get("permissions", [])
                if required_permission in user_permissions:
                    return user
                return None

            return permission_shield

        # Robust error handling
        @shield(
            name="Robust Shield",
            exception_to_raise_if_fail=HTTPException(
                status_code=403, detail="Access denied"
            ),
        )
        async def robust_shield(data: str = Header()) -> Optional[Dict]:
            try:
                if data == "valid_data":
                    return {"data": data, "processed": True}
                elif data == "error_data":
                    raise ValueError("Invalid data format")
                else:
                    return None
            except ValueError as e:
                # Handle specific errors
                raise HTTPException(status_code=400, detail=f"Invalid data: {e}")
            except Exception as e:
                # Handle unexpected errors
                raise HTTPException(status_code=500, detail="Internal shield error")

        @app.get("/auth-test")
        @auth_shield
        @authz_shield
        async def auth_test(
            user: AuthenticatedUser = ShieldedDepends(lambda user: user),
        ):
            """Test endpoint for authentication patterns"""
            return {"message": "Authenticated", "user": user}

        @app.get("/robust-test")
        @robust_shield
        async def robust_test(data: Dict = ShieldedDepends(lambda data: data)):
            """Test endpoint for robust error handling"""
            return {"message": "Success", "data": data}

        self.app = app
        self.client = TestClient(app)

    def test_single_purpose_shields_success(self):
        """Test successful authentication and authorization"""
        response = self.client.get("/auth-test", headers={"token": "valid_token"})

        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Authenticated"
        assert data["user"]["user_id"] == "user123"

    def test_single_purpose_shields_auth_failure(self):
        """Test authentication failure"""
        response = self.client.get("/auth-test", headers={"token": "invalid_token"})

        assert response.status_code == 500  # Auth shield blocks

    def test_robust_error_handling_success(self):
        """Test successful robust shield execution"""
        response = self.client.get("/robust-test", headers={"data": "valid_data"})

        assert response.status_code == 200
        data = response.json()
        assert data["data"]["data"] == "valid_data"
        assert data["data"]["processed"] is True

    def test_robust_error_handling_validation_error(self):
        """Test robust shield handling validation errors"""
        response = self.client.get("/robust-test", headers={"data": "error_data"})

        assert response.status_code == 400
        assert "Invalid data" in response.json()["detail"]

    def test_robust_error_handling_access_denied(self):
        """Test robust shield access denied"""
        response = self.client.get("/robust-test", headers={"data": "invalid_data"})

        assert response.status_code == 403
        assert response.json()["detail"] == "Access denied"
