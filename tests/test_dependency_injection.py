import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI, Header, HTTPException, Depends, Body, Query
from fastapi_shield import shield, ShieldedDepends
from pydantic import BaseModel, Field, field_validator
from typing import Optional, List, Dict, Any
import asyncio
import time


class TestBasicShieldWithDependencies:
    """Tests for basic shield with dependencies pattern"""

    def setup_method(self):
        """Setup the FastAPI app for each test"""
        app = FastAPI()

        # Mock database
        USERS_DB = {
            "user1": {"username": "user1", "email": "user1@example.com", "roles": ["user"]},
            "admin1": {"username": "admin1", "email": "admin1@example.com", "roles": ["admin", "user"]},
        }

        def get_database():
            """Dependency that provides database access"""
            return USERS_DB

        def validate_token(token: str) -> bool:
            """Helper function to validate tokens"""
            return token in ["valid_user_token", "valid_admin_token"]

        def get_user_from_token(token: str) -> Optional[str]:
            """Helper function to extract username from token"""
            if token == "valid_user_token":
                return "user1"
            elif token == "valid_admin_token":
                return "admin1"
            return None

        # Authentication shield
        @shield(name="Authentication Shield")
        def auth_shield(authorization: str = Header()) -> Optional[str]:
            """Shield that validates authorization header and returns token"""
            if not authorization.startswith("Bearer "):
                return None
            
            token = authorization.replace("Bearer ", "")
            if validate_token(token):
                return token
            return None

        # User data retrieval function (used with ShieldedDepends)
        def get_user_data(
            token: str,  # This comes from the shield
            db: dict = Depends(get_database)  # This is a regular FastAPI dependency
        ) -> dict:
            """Function that gets user data using token from shield and database dependency"""
            username = get_user_from_token(token)
            if username and username in db:
                return db[username]
            raise HTTPException(status_code=404, detail="User not found")

        # Endpoint using shield and ShieldedDepends
        @app.get("/profile")
        @auth_shield
        async def get_profile(
            user: dict = ShieldedDepends(get_user_data)
        ):
            """Endpoint that requires authentication and returns user profile"""
            return {
                "username": user["username"],
                "email": user["email"],
                "roles": user["roles"]
            }

        self.app = app
        self.client = TestClient(app)

    def test_valid_authentication(self):
        """Test successful authentication and data retrieval"""
        response = self.client.get(
            "/profile",
            headers={"Authorization": "Bearer valid_user_token"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "user1"
        assert data["email"] == "user1@example.com"
        assert data["roles"] == ["user"]

    def test_admin_authentication(self):
        """Test admin user authentication"""
        response = self.client.get(
            "/profile",
            headers={"Authorization": "Bearer valid_admin_token"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "admin1"
        assert data["roles"] == ["admin", "user"]

    def test_invalid_token(self):
        """Test invalid token rejection"""
        response = self.client.get(
            "/profile",
            headers={"Authorization": "Bearer invalid_token"}
        )
        assert response.status_code == 500  # Shield blocks request

    def test_malformed_header(self):
        """Test malformed authorization header"""
        response = self.client.get(
            "/profile",
            headers={"Authorization": "invalid_format"}
        )
        assert response.status_code == 500  # Shield blocks request

    def test_missing_header(self):
        """Test missing authorization header"""
        response = self.client.get("/profile")
        assert response.status_code == 422  # FastAPI validation error


class TestShieldCompositionAndChaining:
    """Tests for shield composition and chaining patterns"""

    def setup_method(self):
        """Setup the FastAPI app for each test"""
        app = FastAPI()

        # Authentication shield (first in chain)
        @shield(name="JWT Auth")
        def jwt_auth_shield(authorization: str = Header()) -> Optional[dict]:
            """Validates JWT token and returns payload"""
            if not authorization.startswith("Bearer "):
                return None
            
            token = authorization.replace("Bearer ", "")
            # In real app, decode JWT here
            if token == "valid_jwt_token":
                return {
                    "user_id": "user123",
                    "username": "john_doe",
                    "roles": ["user", "admin"],
                    "permissions": ["read:profile", "write:profile"]
                }
            return None

        # Role validation shield (second in chain)
        def require_role(required_role: str):
            """Factory function that creates role-checking shields"""
            
            @shield(
                name=f"Role Check ({required_role})",
                exception_to_raise_if_fail=HTTPException(
                    status_code=403,
                    detail=f"Role '{required_role}' required"
                )
            )
            def role_shield(
                payload: dict = ShieldedDepends(lambda payload: payload)  # Gets data from previous shield
            ) -> Optional[dict]:
                """Shield that checks if user has required role"""
                user_roles = payload.get("roles", [])
                if required_role in user_roles:
                    return payload
                return None
            
            return role_shield

        # Permission validation shield (third in chain)
        def require_permission(required_permission: str):
            """Factory function that creates permission-checking shields"""
            
            @shield(
                name=f"Permission Check ({required_permission})",
                exception_to_raise_if_fail=HTTPException(
                    status_code=403,
                    detail=f"Permission '{required_permission}' required"
                )
            )
            def permission_shield(
                payload: dict = ShieldedDepends(lambda payload: payload)  # Gets data from previous shield
            ) -> Optional[dict]:
                """Shield that checks if user has required permission"""
                user_permissions = payload.get("permissions", [])
                if required_permission in user_permissions:
                    return payload
                return None
            
            return permission_shield

        # Create specific shield instances
        admin_role_shield = require_role("admin")
        write_permission_shield = require_permission("write:profile")

        # Endpoint with multiple shields
        @app.get("/admin-profile")
        @jwt_auth_shield
        @admin_role_shield
        async def admin_profile(
            user_data: dict = ShieldedDepends(lambda payload: payload)
        ):
            """Endpoint requiring JWT auth and admin role"""
            return {
                "message": "Admin profile access granted",
                "user_id": user_data["user_id"],
                "username": user_data["username"]
            }

        @app.post("/update-profile")
        @jwt_auth_shield
        @write_permission_shield
        async def update_profile(
            profile_data: dict,
            user_data: dict = ShieldedDepends(lambda payload: payload)
        ):
            """Endpoint requiring JWT auth and write permission"""
            return {
                "message": "Profile updated",
                "user_id": user_data["user_id"],
                "updated_data": profile_data
            }

        self.app = app
        self.client = TestClient(app)

    def test_admin_profile_success(self):
        """Test successful admin profile access"""
        response = self.client.get(
            "/admin-profile",
            headers={"Authorization": "Bearer valid_jwt_token"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Admin profile access granted"
        assert data["user_id"] == "user123"
        assert data["username"] == "john_doe"

    def test_admin_profile_no_auth(self):
        """Test admin profile access without authentication"""
        response = self.client.get("/admin-profile")
        assert response.status_code == 422  # Missing header

    def test_admin_profile_invalid_token(self):
        """Test admin profile access with invalid token"""
        response = self.client.get(
            "/admin-profile",
            headers={"Authorization": "Bearer invalid_token"}
        )
        assert response.status_code == 500  # First shield blocks

    def test_update_profile_success(self):
        """Test successful profile update"""
        response = self.client.post(
            "/update-profile",
            headers={"Authorization": "Bearer valid_jwt_token"},
            json={"name": "New Name"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Profile updated"
        assert data["user_id"] == "user123"
        assert data["updated_data"] == {"name": "New Name"}

    def test_update_profile_no_permission(self):
        """Test profile update without write permission"""
        # Create a token without write permission
        app = FastAPI()

        @shield(name="JWT Auth No Write")
        def jwt_auth_no_write_shield(authorization: str = Header()) -> Optional[dict]:
            if not authorization.startswith("Bearer "):
                return None
            
            token = authorization.replace("Bearer ", "")
            if token == "no_write_token":
                return {
                    "user_id": "user456",
                    "username": "limited_user",
                    "roles": ["user"],
                    "permissions": ["read:profile"]  # No write permission
                }
            return None

        def require_permission(required_permission: str):
            @shield(
                name=f"Permission Check ({required_permission})",
                exception_to_raise_if_fail=HTTPException(
                    status_code=403,
                    detail=f"Permission '{required_permission}' required"
                )
            )
            def permission_shield(
                payload: dict = ShieldedDepends(lambda payload: payload)
            ) -> Optional[dict]:
                user_permissions = payload.get("permissions", [])
                if required_permission in user_permissions:
                    return payload
                return None
            
            return permission_shield

        write_permission_shield = require_permission("write:profile")

        @app.post("/update-profile-limited")
        @jwt_auth_no_write_shield
        @write_permission_shield
        async def update_profile_limited(
            profile_data: dict,
            user_data: dict = ShieldedDepends(lambda payload: payload)
        ):
            return {"message": "Should not reach here"}

        client = TestClient(app)
        response = client.post(
            "/update-profile-limited",
            headers={"Authorization": "Bearer no_write_token"},
            json={"name": "New Name"}
        )
        assert response.status_code == 403
        assert "Permission 'write:profile' required" in response.json()["detail"]


class TestPydanticIntegration:
    """Tests for Pydantic model integration with shields"""

    def setup_method(self):
        """Setup the FastAPI app for each test"""
        app = FastAPI()

        # Pydantic models
        class UserInput(BaseModel):
            username: str = Field(..., min_length=3, max_length=20)
            email: str = Field(..., pattern=r'^[^@]+@[^@]+\.[^@]+$')
            full_name: Optional[str] = None
            age: int = Field(..., ge=13, le=120)

        class ValidatedUser(BaseModel):
            username: str
            email: str
            full_name: Optional[str]
            age: int
            is_valid: bool = True
            validation_notes: List[str] = []

        # Shield that validates and transforms user data
        @shield(
            name="User Validator",
            exception_to_raise_if_fail=HTTPException(
                status_code=400,
                detail="User validation failed"
            )
        )
        def validate_user_shield(user_input: UserInput = Body()) -> Optional[ValidatedUser]:
            """Shield that performs additional validation beyond Pydantic"""
            
            # Check for reserved usernames
            reserved_usernames = ["admin", "system", "root", "api"]
            if user_input.username.lower() in reserved_usernames:
                return None
            
            # Check email domain restrictions
            allowed_domains = ["company.com", "partner.org"]
            email_domain = user_input.email.split("@")[1]
            if email_domain not in allowed_domains:
                return None
            
            # Create validated user with additional metadata
            validated_user = ValidatedUser(
                username=user_input.username,
                email=user_input.email,
                full_name=user_input.full_name,
                age=user_input.age,
                validation_notes=["Email domain approved", "Username available"]
            )
            
            return validated_user

        # Function to enrich user data (used with ShieldedDepends)
        def enrich_user_data(validated_user: ValidatedUser) -> dict:
            """Function that enriches validated user data"""
            return {
                "user": validated_user.dict(),
                "account_type": "premium" if validated_user.age >= 18 else "standard",
                "welcome_message": f"Welcome, {validated_user.username}!",
                "next_steps": ["verify_email", "complete_profile"]
            }

        @app.post("/register")
        @validate_user_shield
        async def register_user(
            enriched_data: dict = ShieldedDepends(enrich_user_data)
        ):
            """Endpoint that registers a user with validation and enrichment"""
            return {
                "message": "User registered successfully",
                "data": enriched_data
            }

        self.app = app
        self.client = TestClient(app)

    def test_valid_user_registration(self):
        """Test successful user registration with valid data"""
        user_data = {
            "username": "testuser",
            "email": "test@company.com",
            "full_name": "Test User",
            "age": 25
        }
        response = self.client.post("/register", json=user_data)
        assert response.status_code == 200
        
        data = response.json()
        assert data["message"] == "User registered successfully"
        assert data["data"]["user"]["username"] == "testuser"
        assert data["data"]["account_type"] == "premium"
        assert "Welcome, testuser!" in data["data"]["welcome_message"]

    def test_minor_user_registration(self):
        """Test user registration for minor (under 18)"""
        user_data = {
            "username": "younguser",
            "email": "young@company.com",
            "age": 16
        }
        response = self.client.post("/register", json=user_data)
        assert response.status_code == 200
        
        data = response.json()
        assert data["data"]["account_type"] == "standard"

    def test_reserved_username_blocked(self):
        """Test that reserved usernames are blocked"""
        user_data = {
            "username": "admin",
            "email": "admin@company.com",
            "age": 25
        }
        response = self.client.post("/register", json=user_data)
        assert response.status_code == 400
        assert "User validation failed" in response.json()["detail"]

    def test_invalid_email_domain(self):
        """Test that invalid email domains are blocked"""
        user_data = {
            "username": "testuser",
            "email": "test@gmail.com",
            "age": 25
        }
        response = self.client.post("/register", json=user_data)
        assert response.status_code == 400
        assert "User validation failed" in response.json()["detail"]

    def test_pydantic_validation_errors(self):
        """Test Pydantic validation errors"""
        # Invalid email format
        user_data = {
            "username": "testuser",
            "email": "invalid-email",
            "age": 25
        }
        response = self.client.post("/register", json=user_data)
        assert response.status_code == 422

        # Age too young
        user_data = {
            "username": "testuser",
            "email": "test@company.com",
            "age": 10
        }
        response = self.client.post("/register", json=user_data)
        assert response.status_code == 422

        # Username too short
        user_data = {
            "username": "ab",
            "email": "test@company.com",
            "age": 25
        }
        response = self.client.post("/register", json=user_data)
        assert response.status_code == 422


class TestDatabaseIntegration:
    """Tests for database integration with shields"""

    def setup_method(self):
        """Setup the FastAPI app for each test"""
        app = FastAPI()

        # Mock database
        USERS_DB = {
            "user1": {"id": 1, "username": "user1", "active": True, "role": "user"},
            "admin1": {"id": 2, "username": "admin1", "active": True, "role": "admin"},
            "inactive1": {"id": 3, "username": "inactive1", "active": False, "role": "user"},
        }

        async def get_database():
            """Async database dependency"""
            # Simulate database connection
            await asyncio.sleep(0.01)
            return USERS_DB

        # Authentication shield with database lookup
        @shield(name="Database Auth")
        async def db_auth_shield(
            api_key: str = Header(),
            db: Dict[str, Any] = Depends(get_database)
        ) -> Optional[dict]:
            """Shield that authenticates user against database"""
            
            # Simple API key to username mapping
            api_key_mapping = {
                "user1_key": "user1",
                "admin1_key": "admin1",
                "inactive1_key": "inactive1"
            }
            
            username = api_key_mapping.get(api_key)
            if not username:
                return None
            
            user = db.get(username)
            if not user or not user["active"]:
                return None
            
            return user

        # Function to get user permissions (used with ShieldedDepends)
        async def get_user_permissions(
            user: dict,  # Comes from shield
            db: Dict[str, Any] = Depends(get_database)  # Database dependency
        ) -> dict:
            """Function that retrieves user permissions from database"""
            
            # Mock permission lookup
            permissions_map = {
                "user": ["read:own_data"],
                "admin": ["read:own_data", "read:all_data", "write:all_data"]
            }
            
            permissions = permissions_map.get(user["role"], [])
            
            return {
                "user": user,
                "permissions": permissions,
                "can_read_all": "read:all_data" in permissions,
                "can_write_all": "write:all_data" in permissions
            }

        @app.get("/user-data")
        @db_auth_shield
        async def get_user_data(
            user_info: dict = ShieldedDepends(get_user_permissions)
        ):
            """Endpoint that returns user data based on permissions"""
            
            if user_info["can_read_all"]:
                # Admin can see all users
                return {
                    "message": "All user data",
                    "data": list(USERS_DB.values()),
                    "user": user_info["user"]
                }
            else:
                # Regular user can only see their own data
                return {
                    "message": "Your user data",
                    "data": user_info["user"],
                    "permissions": user_info["permissions"]
                }

        self.app = app
        self.client = TestClient(app)

    def test_admin_access_all_data(self):
        """Test admin can access all user data"""
        response = self.client.get(
            "/user-data",
            headers={"api-key": "admin1_key"}
        )
        assert response.status_code == 200
        
        data = response.json()
        assert data["message"] == "All user data"
        assert len(data["data"]) == 3  # All users in database
        assert data["user"]["username"] == "admin1"

    def test_user_access_own_data(self):
        """Test regular user can only access own data"""
        response = self.client.get(
            "/user-data",
            headers={"api-key": "user1_key"}
        )
        assert response.status_code == 200
        
        data = response.json()
        assert data["message"] == "Your user data"
        assert data["data"]["username"] == "user1"
        assert data["permissions"] == ["read:own_data"]

    def test_inactive_user_blocked(self):
        """Test inactive user is blocked"""
        response = self.client.get(
            "/user-data",
            headers={"api-key": "inactive1_key"}
        )
        assert response.status_code == 500  # Shield blocks request

    def test_invalid_api_key(self):
        """Test invalid API key is rejected"""
        response = self.client.get(
            "/user-data",
            headers={"api-key": "invalid_key"}
        )
        assert response.status_code == 500  # Shield blocks request

    def test_missing_api_key(self):
        """Test missing API key"""
        response = self.client.get("/user-data")
        assert response.status_code == 422  # FastAPI validation error


class TestAdvancedShieldPatterns:
    """Tests for advanced shield patterns"""

    def setup_method(self):
        """Setup the FastAPI app for each test"""
        app = FastAPI()

        # Feature flag shield
        @shield(name="Feature Flag Check")
        def feature_flag_shield(
            feature: str = Query(...),
            user_type: str = Header(default="regular")
        ) -> Optional[dict]:
            """Shield that checks if feature is enabled for user type"""
            
            feature_flags = {
                "beta_feature": ["premium", "admin"],
                "experimental_api": ["admin"],
                "new_ui": ["regular", "premium", "admin"]
            }
            
            allowed_user_types = feature_flags.get(feature, [])
            if user_type in allowed_user_types:
                return {
                    "feature": feature,
                    "user_type": user_type,
                    "access_granted": True
                }
            return None

        @app.get("/feature/{feature_name}")
        @feature_flag_shield
        async def access_feature(
            feature_name: str,
            access_info: dict = ShieldedDepends(lambda info: info)
        ):
            """Endpoint that provides access to features based on user type"""
            return {
                "message": f"Access granted to {access_info['feature']}",
                "user_type": access_info["user_type"],
                "feature_data": f"Data for {feature_name}"
            }

        # Rate limiting shield with custom error
        @shield(
            name="Rate Limit Shield",
            exception_to_raise_if_fail=HTTPException(
                status_code=429,
                detail="Rate limit exceeded",
                headers={"Retry-After": "60"}
            )
        )
        def rate_limit_shield(
            x_client_id: str = Header()
        ) -> Optional[dict]:
            """Shield that implements rate limiting"""
            
            # Mock rate limiting logic
            rate_limits = {
                "client1": {"requests": 5, "window": 60},
                "client2": {"requests": 100, "window": 60}
            }
            
            if x_client_id not in rate_limits:
                return None
            
            # In real implementation, check against Redis or similar
            # For demo, always allow
            return {
                "client_id": x_client_id,
                "rate_limit": rate_limits[x_client_id]
            }

        @app.get("/api/data")
        @rate_limit_shield
        async def get_api_data(
            client_info: dict = ShieldedDepends(lambda info: info)
        ):
            """Rate-limited API endpoint"""
            return {
                "data": "API response data",
                "client": client_info["client_id"],
                "rate_limit": client_info["rate_limit"]
            }

        self.app = app
        self.client = TestClient(app)

    def test_feature_access_regular_user(self):
        """Test regular user accessing allowed feature"""
        response = self.client.get(
            "/feature/new_ui?feature=new_ui",
            headers={"user-type": "regular"}
        )
        assert response.status_code == 200
        
        data = response.json()
        assert data["message"] == "Access granted to new_ui"
        assert data["user_type"] == "regular"

    def test_feature_access_premium_user(self):
        """Test premium user accessing beta feature"""
        response = self.client.get(
            "/feature/beta_feature?feature=beta_feature",
            headers={"user-type": "premium"}
        )
        assert response.status_code == 200
        
        data = response.json()
        assert data["message"] == "Access granted to beta_feature"
        assert data["user_type"] == "premium"

    def test_feature_access_denied(self):
        """Test regular user denied access to premium feature"""
        response = self.client.get(
            "/feature/beta_feature?feature=beta_feature",
            headers={"user-type": "regular"}
        )
        assert response.status_code == 500  # Shield blocks request

    def test_rate_limit_valid_client(self):
        """Test valid client accessing rate-limited endpoint"""
        response = self.client.get(
            "/api/data",
            headers={"x-client-id": "client1"}
        )
        assert response.status_code == 200
        
        data = response.json()
        assert data["data"] == "API response data"
        assert data["client"] == "client1"
        assert data["rate_limit"]["requests"] == 5

    def test_rate_limit_invalid_client(self):
        """Test invalid client blocked by rate limiter"""
        response = self.client.get(
            "/api/data",
            headers={"x-client-id": "invalid_client"}
        )
        assert response.status_code == 429
        assert response.json()["detail"] == "Rate limit exceeded"
        assert response.headers["Retry-After"] == "60"


class TestShieldFactoryPatterns:
    """Tests for shield factory patterns and reusability"""

    def setup_method(self):
        """Setup the FastAPI app for each test"""
        app = FastAPI()

        # Mock user data
        USERS = {
            "user1": {"username": "user1", "roles": ["user"]},
            "admin1": {"username": "admin1", "roles": ["admin", "user"]},
            "editor1": {"username": "editor1", "roles": ["editor", "user"]},
        }

        # Authentication shield
        @shield(name="Auth")
        def auth_shield(user_id: str = Header()) -> Optional[dict]:
            """Basic authentication shield"""
            if user_id in USERS:
                return USERS[user_id]
            return None

        # Shield factory for role requirements
        def require_role(role: str):
            """Factory function that creates role-checking shields"""
            
            @shield(
                name=f"Require {role} Role",
                exception_to_raise_if_fail=HTTPException(
                    status_code=403,
                    detail=f"Role '{role}' required"
                )
            )
            def role_shield(
                user: dict = ShieldedDepends(lambda user: user)
            ) -> Optional[dict]:
                """Shield that checks if user has required role"""
                if role in user.get("roles", []):
                    return user
                return None
            
            return role_shield

        # Create specific role shields
        admin_shield = require_role("admin")
        editor_shield = require_role("editor")

        # Endpoints using factory-created shields
        @app.get("/admin-only")
        @auth_shield
        @admin_shield
        async def admin_only(
            user: dict = ShieldedDepends(lambda user: user)
        ):
            return {"message": "Admin access granted", "user": user["username"]}

        @app.get("/editor-only")
        @auth_shield
        @editor_shield
        async def editor_only(
            user: dict = ShieldedDepends(lambda user: user)
        ):
            return {"message": "Editor access granted", "user": user["username"]}

        @app.get("/user-data")
        @auth_shield
        async def user_data(
            user: dict = ShieldedDepends(lambda user: user)
        ):
            return {"message": "User data", "user": user["username"], "roles": user["roles"]}

        self.app = app
        self.client = TestClient(app)

    def test_admin_access_success(self):
        """Test admin can access admin-only endpoint"""
        response = self.client.get(
            "/admin-only",
            headers={"user-id": "admin1"}
        )
        assert response.status_code == 200
        
        data = response.json()
        assert data["message"] == "Admin access granted"
        assert data["user"] == "admin1"

    def test_admin_access_denied(self):
        """Test non-admin cannot access admin-only endpoint"""
        response = self.client.get(
            "/admin-only",
            headers={"user-id": "user1"}
        )
        assert response.status_code == 403
        assert "Role 'admin' required" in response.json()["detail"]

    def test_editor_access_success(self):
        """Test editor can access editor-only endpoint"""
        response = self.client.get(
            "/editor-only",
            headers={"user-id": "editor1"}
        )
        assert response.status_code == 200
        
        data = response.json()
        assert data["message"] == "Editor access granted"
        assert data["user"] == "editor1"

    def test_editor_access_denied(self):
        """Test non-editor cannot access editor-only endpoint"""
        response = self.client.get(
            "/editor-only",
            headers={"user-id": "user1"}
        )
        assert response.status_code == 403
        assert "Role 'editor' required" in response.json()["detail"]

    def test_user_data_access(self):
        """Test any authenticated user can access user data"""
        response = self.client.get(
            "/user-data",
            headers={"user-id": "user1"}
        )
        assert response.status_code == 200
        
        data = response.json()
        assert data["message"] == "User data"
        assert data["user"] == "user1"
        assert data["roles"] == ["user"]

    def test_unauthenticated_access(self):
        """Test unauthenticated user cannot access any endpoint"""
        response = self.client.get(
            "/user-data",
            headers={"user-id": "nonexistent"}
        )
        assert response.status_code == 500  # Auth shield blocks


class TestErrorHandlingPatterns:
    """Tests for error handling in shields"""

    def setup_method(self):
        """Setup the FastAPI app for each test"""
        app = FastAPI()

        # Shield with custom error handling
        @shield(
            name="Custom Error Shield",
            exception_to_raise_if_fail=HTTPException(
                status_code=418,
                detail="I'm a teapot - custom error",
                headers={"X-Custom-Header": "custom-value"}
            )
        )
        def custom_error_shield(
            test_mode: str = Header(default="normal")
        ) -> Optional[dict]:
            """Shield that demonstrates custom error handling"""
            if test_mode == "fail":
                return None  # This will trigger the custom error
            elif test_mode == "exception":
                raise ValueError("Internal shield error")
            return {"mode": test_mode}

        @app.get("/test-errors")
        @custom_error_shield
        async def test_errors(
            data: dict = ShieldedDepends(lambda data: data)
        ):
            return {"message": "Success", "data": data}

        self.app = app
        self.client = TestClient(app)

    def test_custom_error_response(self):
        """Test custom error response from shield"""
        response = self.client.get(
            "/test-errors",
            headers={"test-mode": "fail"}
        )
        assert response.status_code == 418
        assert response.json()["detail"] == "I'm a teapot - custom error"
        assert response.headers["X-Custom-Header"] == "custom-value"

    def test_shield_internal_exception(self):
        """Test shield internal exception handling"""
        response = self.client.get(
            "/test-errors",
            headers={"test-mode": "exception"}
        )
        assert response.status_code == 500
        assert "Shield with name `Custom Error Shield` failed" in response.json()["detail"]

    def test_successful_shield_execution(self):
        """Test successful shield execution"""
        response = self.client.get(
            "/test-errors",
            headers={"test-mode": "normal"}
        )
        assert response.status_code == 200
        
        data = response.json()
        assert data["message"] == "Success"
        assert data["data"]["mode"] == "normal" 