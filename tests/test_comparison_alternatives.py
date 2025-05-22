import pytest
import time
from fastapi import FastAPI, Depends, Header, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from fastapi.testclient import TestClient
from fastapi_shield import shield, ShieldedDepends
import jwt
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass


class TestLazyDependencyResolution:
    """Tests demonstrating the lazy dependency resolution advantage of FastAPI-Shield."""

    def setup_method(self):
        """Setup the FastAPI app with both traditional and shield-based routes."""
        self.app = FastAPI()
        self.db_call_counter = 0

        # Simulate a database connection
        class FakeDB:
            def __init__(self):
                self.data = {"test_key": "test_value"}

            def get_data(self, key: str):
                return self.data.get(key)

            async def close(self):
                pass

        # Database connection dependency that counts calls
        async def get_db_connection():
            """Database connection that counts how many times it's called."""
            self.db_call_counter += 1
            print(f"DB connection created - call #{self.db_call_counter}")
            db = FakeDB()
            try:
                yield db
            finally:
                print("DB connection closed")

        # FastAPI-Shield approach
        @shield(
            name="API Key Shield",
            exception_to_raise_if_fail=HTTPException(
                status_code=401, detail="Invalid API key"
            ),
        )
        def api_key_shield(api_key: str = Header()):
            """Shield that validates API keys."""
            print("Verifying API key with shield")
            if api_key != "valid_key":
                return None  # Shield fails, preventing further execution
            return {"user_id": "user123"}

        @self.app.get("/shield-protected")
        @api_key_shield
        async def shield_endpoint(
            db=Depends(get_db_connection),  # DB connection only created if shield passes
        ):
            """Shield-protected endpoint that only creates DB connection if auth passes."""
            return {"message": "Shield-protected endpoint"}

        self.client = TestClient(self.app)

    def test_shield_valid_key(self):
        """Test that shield approach works with valid key."""
        self.db_call_counter = 0
        response = self.client.get("/shield-protected", headers={"api-key": "valid_key"})
        assert response.status_code == 200
        assert self.db_call_counter == 1

    def test_shield_invalid_key(self):
        """Test that shield approach prevents DB connection with invalid key."""
        self.db_call_counter = 0
        response = self.client.get("/shield-protected", headers={"api-key": "invalid_key"})
        assert response.status_code == 401
        # Shield prevented DB connection from being created
        assert self.db_call_counter == 0


class TestCleanEndpointSignatures:
    """Tests demonstrating the clean endpoint signatures with ShieldedDepends."""

    def setup_method(self):
        """Setup the FastAPI app with both traditional and shield-based approaches."""
        self.app = FastAPI()
        
        # Setup common objects
        oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
        SECRET_KEY = "your-secret-key"
        ALGORITHM = "HS256"
        
        @dataclass
        class User:
            username: str
            email: str
            is_admin: bool
        
        # Mock user database
        USERS = {
            "johndoe": User(username="johndoe", email="john@example.com", is_admin=False),
            "adminuser": User(username="adminuser", email="admin@example.com", is_admin=True)
        }
        
        # Traditional approach
        async def get_current_user(token: str = Depends(oauth2_scheme)):
            """Traditional dependency to extract user from token."""
            try:
                payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
                username = payload.get("sub")
                if username is None or username not in USERS:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid credentials"
                    )
                return USERS[username]
            except jwt.PyJWTError:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token"
                )
        
        async def verify_admin(user: User = Depends(get_current_user)):
            """Traditional dependency to verify admin role."""
            if not user.is_admin:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Admin access required"
                )
            return user
        
        # Traditional endpoint with cluttered signature
        @self.app.get("/traditional/admin")
        async def traditional_admin_endpoint(
            admin_user: User = Depends(verify_admin),
            q: Optional[str] = None,  # Business logic param mixed with auth concerns
            show_details: bool = False  # Business logic param mixed with auth concerns
        ):
            """Traditional endpoint with auth mixed into signature."""
            return {
                "message": "Admin dashboard",
                "admin": admin_user.username,
                "q": q,
                "show_details": show_details
            }
        
        # Shield approach
        @shield(
            name="JWT Auth",
            exception_to_raise_if_fail=HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        )
        def jwt_auth_shield(token: str = Depends(oauth2_scheme)):
            """Shield that authenticates JWT tokens."""
            try:
                payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
                username = payload.get("sub")
                if username is None or username not in USERS:
                    return None
                return USERS[username]
            except jwt.PyJWTError:
                return None
        
        @shield(
            name="Admin Shield",
            exception_to_raise_if_fail=HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required"
            )
        )
        def admin_shield(user: User = ShieldedDepends(lambda user: user)):
            """Shield that verifies admin role."""
            if not user.is_admin:
                return None
            return user
        
        # Shield endpoint with clean signature
        @self.app.get("/shield/admin")
        @jwt_auth_shield
        @admin_shield
        async def shield_admin_endpoint(
            q: Optional[str] = None,  # Only business logic params in signature
            show_details: bool = False,  # Only business logic params in signature
            admin_user: User = ShieldedDepends(lambda user: user)  # Optional access to authenticated user
        ):
            """Shield-protected endpoint with clean signature."""
            return {
                "message": "Admin dashboard",
                "admin": admin_user.username,
                "q": q,
                "show_details": show_details
            }
        
        # Helper function to create JWT tokens for testing
        def create_token(username: str):
            payload = {"sub": username}
            return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
        
        self.create_token = create_token
        self.client = TestClient(self.app)
    
    def test_traditional_endpoint_admin_access(self):
        """Test that traditional endpoint works for admin users."""
        token = self.create_token("adminuser")
        response = self.client.get(
            "/traditional/admin?q=test&show_details=true",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Admin dashboard"
        assert data["admin"] == "adminuser"
        assert data["q"] == "test"
        assert data["show_details"] is True
    
    def test_traditional_endpoint_non_admin_access(self):
        """Test that traditional endpoint blocks non-admin users."""
        token = self.create_token("johndoe")
        response = self.client.get(
            "/traditional/admin",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 403
        assert response.json()["detail"] == "Admin access required"
    
    def test_shield_endpoint_admin_access(self):
        """Test that shield endpoint works for admin users."""
        token = self.create_token("adminuser")
        response = self.client.get(
            "/shield/admin?q=test&show_details=true",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Admin dashboard"
        assert data["admin"] == "adminuser"
        assert data["q"] == "test"
        assert data["show_details"] is True
    
    def test_shield_endpoint_non_admin_access(self):
        """Test that shield endpoint blocks non-admin users."""
        token = self.create_token("johndoe")
        response = self.client.get(
            "/shield/admin",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 403
        assert response.json()["detail"] == "Admin access required"


class TestComposabilityAndReusability:
    """Tests demonstrating shield composability and reusability."""
    
    def setup_method(self):
        """Setup the FastAPI app with composable shields."""
        self.app = FastAPI()
        
        # Reusable shield factory functions
        def role_shield(allowed_roles: List[str], name: str = None):
            """Factory function that creates role-based shields."""
            shield_name = name or f"Role Shield ({','.join(allowed_roles)})"
            
            @shield(
                name=shield_name,
                exception_to_raise_if_fail=HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Required role(s): {', '.join(allowed_roles)}"
                )
            )
            def role_validator(role: str = Header()):
                if role in allowed_roles:
                    return role
                return None
            
            return role_validator
        
        # Rate limiting shield factory
        def rate_limit_shield(max_requests: int, window_seconds: float, name: str = None):
            """Factory function that creates rate limiting shields."""
            shield_name = name or f"Rate Limiter ({max_requests}/{window_seconds}s)"
            # Simple in-memory store for request timestamps
            request_history = {}
            
            @shield(
                name=shield_name,
                exception_to_raise_if_fail=HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Rate limit exceeded: {max_requests} per {window_seconds} seconds"
                )
            )
            def rate_limiter(request: Request):
                client_ip = request.client.host
                now = time.time()
                
                # Get request history for this IP
                if client_ip not in request_history:
                    request_history[client_ip] = []
                
                # Remove old requests outside the window
                request_history[client_ip] = [
                    ts for ts in request_history[client_ip]
                    if now - ts < window_seconds
                ]
                
                # Check if rate limit is exceeded
                if len(request_history[client_ip]) >= max_requests:
                    return None
                
                # Add current request timestamp
                request_history[client_ip].append(now)
                return True
            
            return rate_limiter
        
        # Create reusable shields
        admin_shield = role_shield(["admin"], "Admin Only")
        editor_shield = role_shield(["admin", "editor"], "Editor Access")
        viewer_shield = role_shield(["admin", "editor", "viewer"], "Viewer Access")
        
        # Create rate limit shields
        strict_rate_limit = rate_limit_shield(3, 5, "Strict Rate Limit")
        standard_rate_limit = rate_limit_shield(10, 5, "Standard Rate Limit")
        
        # Apply shields to routes in different combinations
        @self.app.get("/admin")
        @admin_shield
        async def admin_endpoint():
            return {"message": "Admin access granted"}
        
        @self.app.get("/editor")
        @editor_shield
        async def editor_endpoint():
            return {"message": "Editor access granted"}
        
        @self.app.get("/viewer")
        @viewer_shield
        async def viewer_endpoint():
            return {"message": "Viewer access granted"}
        
        @self.app.get("/protected/admin")
        @strict_rate_limit
        @admin_shield
        async def protected_admin_endpoint():
            return {"message": "Protected admin access granted"}
        
        @self.app.get("/protected/editor")
        @standard_rate_limit
        @editor_shield
        async def protected_editor_endpoint():
            return {"message": "Protected editor access granted"}
        
        self.client = TestClient(self.app)
    
    def test_admin_access(self):
        """Test that admin shield allows admin role."""
        response = self.client.get("/admin", headers={"role": "admin"})
        assert response.status_code == 200
        assert response.json()["message"] == "Admin access granted"
    
    def test_admin_access_denied(self):
        """Test that admin shield blocks non-admin roles."""
        response = self.client.get("/admin", headers={"role": "editor"})
        assert response.status_code == 403
        assert "Required role(s): admin" in response.json()["detail"]
    
    def test_editor_access(self):
        """Test that editor shield allows admin and editor roles."""
        # Admin can access editor endpoints
        response = self.client.get("/editor", headers={"role": "admin"})
        assert response.status_code == 200
        
        # Editor can access editor endpoints
        response = self.client.get("/editor", headers={"role": "editor"})
        assert response.status_code == 200
    
    def test_editor_access_denied(self):
        """Test that editor shield blocks viewer role."""
        response = self.client.get("/editor", headers={"role": "viewer"})
        assert response.status_code == 403
        assert "Required role(s): admin, editor" in response.json()["detail"]
    
    def test_viewer_access(self):
        """Test that viewer shield allows admin, editor, and viewer roles."""
        # Admin can access viewer endpoints
        response = self.client.get("/viewer", headers={"role": "admin"})
        assert response.status_code == 200
        
        # Editor can access viewer endpoints
        response = self.client.get("/viewer", headers={"role": "editor"})
        assert response.status_code == 200
        
        # Viewer can access viewer endpoints
        response = self.client.get("/viewer", headers={"role": "viewer"})
        assert response.status_code == 200
    
    def test_rate_limiting(self):
        """Test that rate limiting shields work as expected."""
        # Strict rate limit (3 requests per 5 seconds)
        for _ in range(3):
            response = self.client.get("/protected/admin", headers={"role": "admin"})
            assert response.status_code == 200
        
        # Fourth request should be rate limited
        response = self.client.get("/protected/admin", headers={"role": "admin"})
        assert response.status_code == 429
        assert "Rate limit exceeded" in response.json()["detail"]
        
        # Standard rate limit should allow more requests
        for _ in range(10):
            response = self.client.get("/protected/editor", headers={"role": "editor"})
            assert response.status_code == 200
        
        # Eleventh request should be rate limited
        response = self.client.get("/protected/editor", headers={"role": "editor"})
        assert response.status_code == 429


class TestSeparationOfConcerns:
    """Tests demonstrating separation of concerns with shields."""
    
    def setup_method(self):
        """Setup the FastAPI app with separated security and business logic."""
        self.app = FastAPI()
        
        # Security concerns (authentication and authorization)
        @shield(
            name="Authentication",
            exception_to_raise_if_fail=HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required"
            )
        )
        def auth_shield(token: str = Header()):
            """Handle authentication logic."""
            if token != "valid_token":
                return None
            return {"user_id": "user123", "permissions": ["read", "write"]}
        
        
        def permission_shield(permission: str):
            """Factory function for permission-based shields."""
            
            @shield(
            name="Permission Check",
            exception_to_raise_if_fail=HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Permission denied"
                )
            )
            def validator(auth_data=ShieldedDepends(lambda data: data)):
                if permission not in auth_data["permissions"]:
                    return None
                return auth_data
            
            return validator
        
        # Business logic focused endpoint without security code
        @self.app.get("/data")
        @auth_shield
        @permission_shield("read")
        async def get_data():
            """Pure business logic endpoint."""
            # No security code mixed into this function
            return {"data": "Sensitive information"}
        
        @self.app.post("/data")
        @auth_shield
        @permission_shield("write")
        async def create_data():
            """Pure business logic endpoint for creating data."""
            # No security code mixed into this function
            return {"data": "Data created", "status": "success"}
        
        self.client = TestClient(self.app)
    
    def test_unauthenticated_access(self):
        """Test that endpoints reject unauthenticated requests."""
        response = self.client.get("/data")
        assert response.status_code == 422  # Missing required header
        
        response = self.client.get("/data", headers={"token": "invalid_token"})
        assert response.status_code == 401
        assert response.json()["detail"] == "Authentication required"
    
    def test_authenticated_read_access(self):
        """Test that authenticated users with read permission can access data."""
        response = self.client.get("/data", headers={"token": "valid_token"})
        assert response.status_code == 200
        assert response.json()["data"] == "Sensitive information"
    
    def test_authenticated_write_access(self):
        """Test that authenticated users with write permission can create data."""
        response = self.client.post("/data", headers={"token": "valid_token"})
        assert response.status_code == 200
        assert response.json()["status"] == "success"


class TestErrorHandling:
    """Tests demonstrating the error handling capabilities of shields."""
    
    def setup_method(self):
        """Setup the FastAPI app with various error handling approaches."""
        self.app = FastAPI()
        
        # Shield with custom error message and status code
        @shield(
            name="Custom Error Shield",
            exception_to_raise_if_fail=HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Custom error message",
                headers={"X-Error-Source": "Custom-Shield"}
            )
        )
        def custom_error_shield(api_key: str = Header()):
            """Shield with custom error details."""
            if api_key != "valid_key":
                return None
            return True
        
        # Shield with custom response instead of exception
        from fastapi import Response
        
        @shield(
            name="Custom Response Shield",
            auto_error=False,  # Don't raise exception, return response instead
            default_response_to_return_if_fail=Response(
                content="Access denied with custom response",
                media_type="text/plain",
                status_code=status.HTTP_403_FORBIDDEN,
                headers={"X-Response-Source": "Custom-Shield"}
            )
        )
        def custom_response_shield(api_key: str = Header()):
            """Shield with custom response instead of exception."""
            if api_key != "valid_key":
                return None
            return True
        
        @self.app.get("/custom-error")
        @custom_error_shield
        async def custom_error_endpoint():
            return {"message": "Access granted"}
        
        @self.app.get("/custom-response")
        @custom_response_shield
        async def custom_response_endpoint():
            return {"message": "Access granted"}
        
        self.client = TestClient(self.app)
    
    def test_custom_error_shield(self):
        """Test that custom error shield returns the specified error."""
        response = self.client.get("/custom-error", headers={"api-key": "invalid_key"})
        assert response.status_code == 403
        assert response.json()["detail"] == "Custom error message"
        assert response.headers["X-Error-Source"] == "Custom-Shield"
    
    def test_custom_response_shield(self):
        """Test that custom response shield returns the specified response."""
        response = self.client.get("/custom-response", headers={"api-key": "invalid_key"})
        assert response.status_code == 403
        assert response.text == "Access denied with custom response"
        assert response.headers["X-Response-Source"] == "Custom-Shield"
    
    def test_valid_access(self):
        """Test that shields allow access with valid credentials."""
        response = self.client.get("/custom-error", headers={"api-key": "valid_key"})
        assert response.status_code == 200
        assert response.json()["message"] == "Access granted"
        
        response = self.client.get("/custom-response", headers={"api-key": "valid_key"})
        assert response.status_code == 200
        assert response.json()["message"] == "Access granted" 