import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI, Header, HTTPException, status, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi_shield import shield, ShieldedDepends
import jwt
import time
from datetime import datetime, timedelta
from typing import Dict, Optional, List
from pydantic import BaseModel
from unittest.mock import AsyncMock, Mock, patch
import asyncio

# Configuration
JWT_SECRET = "test-secret-key"
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


def create_test_token(
    user_id: str,
    roles: List[str] = None,
    permissions: List[str] = None,
    expired: bool = False,
):
    """Create a test JWT token"""
    payload = {
        "user_id": user_id,
        "roles": roles or [],
        "permissions": permissions or [],
    }

    if expired:
        payload["exp"] = datetime.utcnow() - timedelta(hours=1)
    else:
        payload["exp"] = datetime.utcnow() + timedelta(hours=1)

    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def create_oauth2_token(username: str, roles: List[str] = None, expired: bool = False):
    """Create a test OAuth2 JWT token"""
    payload = {
        "sub": username,
        "roles": roles or ["user"],
    }

    if expired:
        payload["exp"] = datetime.utcnow() - timedelta(hours=1)
    else:
        payload["exp"] = datetime.utcnow() + timedelta(hours=1)

    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


class TestChainedShieldProcessing:
    """Test the Chained Shield Processing pattern from advanced_examples.md"""

    def setup_method(self):
        """Setup the FastAPI app for each test"""
        self.app = FastAPI()

        # AuthData class
        class AuthData:
            """Class to hold authentication data and provide helper methods"""

            def __init__(self, user_id: str, roles: List[str], permissions: List[str]):
                self.user_id = user_id
                self.roles = roles
                self.permissions = permissions

            def has_role(self, role: str) -> bool:
                """Check if user has a specific role"""
                return role in self.roles

            def has_permission(self, permission: str) -> bool:
                """Check if user has a specific permission"""
                return permission in self.permissions

        self.AuthData = AuthData

        # Setup shields
        self.setup_shields()
        self.setup_routes()

        self.client = TestClient(self.app)

    def setup_shields(self):
        """Setup all shields for chained processing"""

        @shield(name="JWT Authentication")
        async def jwt_auth_shield(authorization: str = Header()) -> Optional[Dict]:
            """Validate JWT token and extract payload"""
            if not authorization.startswith("Bearer "):
                return None

            token = authorization.replace("Bearer ", "")

            try:
                payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
                return payload
            except Exception:
                return None

        @shield(name="User Role Extraction")
        async def role_extraction_shield(
            payload=ShieldedDepends(lambda payload: payload),
        ) -> Optional[self.AuthData]:
            """Extract user roles from the JWT payload and create AuthData object"""
            if not payload or "user_id" not in payload:
                return None

            user_id = payload.get("user_id")
            roles = payload.get("roles", [])
            permissions = payload.get("permissions", [])

            return self.AuthData(user_id, roles, permissions)

        def require_role(role: str):
            """Create a shield that requires a specific role"""

            @shield(
                name=f"Role Requirement ({role})",
                exception_to_raise_if_fail=HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Requires role: {role}",
                ),
            )
            async def role_shield(
                auth_data: self.AuthData = ShieldedDepends(lambda auth_data: auth_data),
            ) -> Optional[self.AuthData]:
                if auth_data.has_role(role):
                    return auth_data
                return None

            return role_shield

        def require_permission(permission: str):
            """Create a shield that requires a specific permission"""

            @shield(
                name=f"Permission Requirement ({permission})",
                exception_to_raise_if_fail=HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Requires permission: {permission}",
                ),
            )
            async def permission_shield(
                auth_data: self.AuthData = ShieldedDepends(lambda auth_data: auth_data),
            ) -> Optional[self.AuthData]:
                if auth_data.has_permission(permission):
                    return auth_data
                return None

            return permission_shield

        # Store shields for use in routes
        self.jwt_auth_shield = jwt_auth_shield
        self.role_extraction_shield = role_extraction_shield
        self.require_role = require_role
        self.require_permission = require_permission

    def setup_routes(self):
        """Setup all routes for chained shield testing"""

        @self.app.get("/user-profile")
        @self.jwt_auth_shield
        @self.role_extraction_shield
        async def user_profile(
            auth_data: self.AuthData = ShieldedDepends(lambda auth_data: auth_data),
        ):
            return {
                "user_id": auth_data.user_id,
                "roles": auth_data.roles,
                "permissions": auth_data.permissions,
            }

        @self.app.get("/admin-panel")
        @self.jwt_auth_shield
        @self.role_extraction_shield
        @self.require_role("admin")
        async def admin_panel(
            auth_data: self.AuthData = ShieldedDepends(lambda auth_data: auth_data),
        ):
            return {"message": "Welcome to admin panel", "user_id": auth_data.user_id}

        @self.app.post("/user-management")
        @self.jwt_auth_shield
        @self.role_extraction_shield
        @self.require_permission("manage_users")
        async def user_management(
            auth_data: self.AuthData = ShieldedDepends(lambda auth_data: auth_data),
        ):
            return {
                "message": "User management access granted",
                "user_id": auth_data.user_id,
            }

    def test_user_profile_valid_token(self):
        """Test user profile with valid JWT token"""
        token = create_test_token("user123", ["user"], ["read_profile"])
        headers = {"Authorization": f"Bearer {token}"}

        response = self.client.get("/user-profile", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert data["user_id"] == "user123"
        assert data["roles"] == ["user"]
        assert data["permissions"] == ["read_profile"]

    def test_user_profile_invalid_token(self):
        """Test user profile with invalid JWT token"""
        headers = {"Authorization": "Bearer invalid_token"}

        response = self.client.get("/user-profile", headers=headers)
        assert response.status_code == 500  # JWT auth shield blocks

    def test_user_profile_no_auth(self):
        """Test user profile without authentication"""
        response = self.client.get("/user-profile")
        assert response.status_code == 422, response.json()  # JWT auth shield blocks

    def test_user_profile_malformed_auth(self):
        """Test user profile with malformed auth header"""
        headers = {"Authorization": "InvalidFormat token"}

        response = self.client.get("/user-profile", headers=headers)
        assert response.status_code == 500  # JWT auth shield blocks

    def test_admin_panel_with_admin_role(self):
        """Test admin panel access with admin role"""
        token = create_test_token("admin123", ["admin", "user"], ["admin_access"])
        headers = {"Authorization": f"Bearer {token}"}

        response = self.client.get("/admin-panel", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Welcome to admin panel"
        assert data["user_id"] == "admin123"

    def test_admin_panel_without_admin_role(self):
        """Test admin panel access without admin role"""
        token = create_test_token("user123", ["user"], ["read_profile"])
        headers = {"Authorization": f"Bearer {token}"}

        response = self.client.get("/admin-panel", headers=headers)
        assert response.status_code == 403
        assert "Requires role: admin" in response.json()["detail"]

    def test_user_management_with_permission(self):
        """Test user management with required permission"""
        token = create_test_token("manager123", ["manager"], ["manage_users"])
        headers = {"Authorization": f"Bearer {token}"}

        response = self.client.post("/user-management", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "User management access granted"
        assert data["user_id"] == "manager123"

    def test_user_management_without_permission(self):
        """Test user management without required permission"""
        token = create_test_token("user123", ["user"], ["read_profile"])
        headers = {"Authorization": f"Bearer {token}"}

        response = self.client.post("/user-management", headers=headers)
        assert response.status_code == 403
        assert "Requires permission: manage_users" in response.json()["detail"]

    def test_expired_token(self):
        """Test with expired JWT token"""
        token = create_test_token("user123", ["user"], ["read_profile"], expired=True)
        headers = {"Authorization": f"Bearer {token}"}

        response = self.client.get("/user-profile", headers=headers)
        assert response.status_code == 500  # JWT auth shield blocks

    def test_token_missing_user_id(self):
        """Test with token missing user_id"""
        payload = {
            "roles": ["user"],
            "permissions": ["read_profile"],
            "exp": datetime.utcnow() + timedelta(hours=1),
        }
        token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
        headers = {"Authorization": f"Bearer {token}"}

        response = self.client.get("/user-profile", headers=headers)
        assert response.status_code == 500  # Role extraction shield blocks

    def test_multiple_roles_and_permissions(self):
        """Test user with multiple roles and permissions"""
        token = create_test_token(
            "superuser",
            ["admin", "user", "manager"],
            ["manage_users", "admin_access", "read_profile"],
        )
        headers = {"Authorization": f"Bearer {token}"}

        # Should access admin panel
        response = self.client.get("/admin-panel", headers=headers)
        assert response.status_code == 200

        # Should access user management
        response = self.client.post("/user-management", headers=headers)
        assert response.status_code == 200


class TestDynamicShieldConfiguration:
    """Test the Dynamic Shield Configuration with Database pattern from advanced_examples.md"""

    def setup_method(self):
        """Setup the FastAPI app for each test"""
        self.app = FastAPI()

        # Mock database
        self.mock_db = AsyncMock()
        self.api_keys_data = {}
        self.user_permissions_data = {}

        # Setup models
        class Permission(BaseModel):
            permission: str

        class User(BaseModel):
            id: int
            permissions: List[Permission]

        self.Permission = Permission
        self.User = User

        # Setup shields and routes
        self.setup_shields()
        self.setup_routes()

        self.client = TestClient(self.app)

    def setup_shields(self):
        """Setup database-driven shields"""

        async def get_db():
            """Mock database dependency"""
            return self.mock_db

        @shield(name="Database Auth Shield")
        async def db_auth_shield(api_key: str = Header(), db=Depends(get_db)):
            """Authenticate using API key from database"""
            # Mock database query
            result = self.api_keys_data.get(api_key)
            if not result or not result.get("is_active", False):
                return None

            return {"user_id": result["user_id"], "key": result["key"]}

        @shield(name="Permission Shield")
        async def permission_shield(
            auth_data=ShieldedDepends(lambda auth_data: auth_data), db=Depends(get_db)
        ):
            """Load user permissions from database"""
            if not auth_data:
                return None

            user_id = auth_data["user_id"]

            # Mock database query for permissions
            user_perms = self.user_permissions_data.get(user_id, [])
            permissions = [self.Permission(permission=perm) for perm in user_perms]

            return self.User(id=user_id, permissions=permissions)

        def require_db_permission(required_permission: str):
            """Create a shield that requires a database-stored permission"""

            @shield(
                name=f"DB Permission Requirement ({required_permission})",
                exception_to_raise_if_fail=HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Requires permission: {required_permission}",
                ),
            )
            async def permission_check(
                user: self.User = ShieldedDepends(lambda auth_data: auth_data),
            ):
                user_permissions = [p.permission for p in user.permissions]
                if required_permission in user_permissions:
                    return user
                return None

            return permission_check

        # Store shields for use in routes
        self.db_auth_shield = db_auth_shield
        self.permission_shield = permission_shield
        self.require_db_permission = require_db_permission

    def setup_routes(self):
        """Setup routes for database shield testing"""

        @self.app.get("/db-protected")
        @self.db_auth_shield
        @self.permission_shield
        async def db_protected_endpoint(
            user: self.User = ShieldedDepends(lambda auth_data: auth_data),
        ):
            return {
                "message": "Access granted via database authentication",
                "user_id": user.id,
                "permissions": [p.permission for p in user.permissions],
            }

        @self.app.get("/admin-access")
        @self.db_auth_shield
        @self.permission_shield
        @self.require_db_permission("admin_access")
        async def admin_access_endpoint(
            user: self.User = ShieldedDepends(lambda auth_data: auth_data),
        ):
            return {"message": "Admin access granted", "user_id": user.id}

    def test_valid_api_key_with_permissions(self):
        """Test valid API key with user permissions"""
        # Setup mock data
        self.api_keys_data["valid_key"] = {
            "user_id": 1,
            "key": "valid_key",
            "is_active": True,
        }
        self.user_permissions_data[1] = ["read_data", "write_data"]

        headers = {"api-key": "valid_key"}
        response = self.client.get("/db-protected", headers=headers)

        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Access granted via database authentication"
        assert data["user_id"] == 1
        assert data["permissions"] == ["read_data", "write_data"]

    def test_invalid_api_key(self):
        """Test with invalid API key"""
        headers = {"api-key": "invalid_key"}
        response = self.client.get("/db-protected", headers=headers)
        assert response.status_code == 500  # DB auth shield blocks

    def test_inactive_api_key(self):
        """Test with inactive API key"""
        self.api_keys_data["inactive_key"] = {
            "user_id": 2,
            "key": "inactive_key",
            "is_active": False,
        }

        headers = {"api-key": "inactive_key"}
        response = self.client.get("/db-protected", headers=headers)
        assert response.status_code == 500  # DB auth shield blocks

    def test_admin_access_with_permission(self):
        """Test admin access with required permission"""
        self.api_keys_data["admin_key"] = {
            "user_id": 3,
            "key": "admin_key",
            "is_active": True,
        }
        self.user_permissions_data[3] = ["admin_access", "read_data"]

        headers = {"api-key": "admin_key"}
        response = self.client.get("/admin-access", headers=headers)

        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Admin access granted"
        assert data["user_id"] == 3

    def test_admin_access_without_permission(self):
        """Test admin access without required permission"""
        self.api_keys_data["user_key"] = {
            "user_id": 4,
            "key": "user_key",
            "is_active": True,
        }
        self.user_permissions_data[4] = ["read_data", "write_data"]

        headers = {"api-key": "user_key"}
        response = self.client.get("/admin-access", headers=headers)

        assert response.status_code == 403
        assert "Requires permission: admin_access" in response.json()["detail"]

    def test_no_api_key_header(self):
        """Test without API key header"""
        response = self.client.get("/db-protected")
        assert response.status_code == 422, response.json()  # DB auth shield blocks

    def test_user_without_permissions(self):
        """Test user with no permissions"""
        self.api_keys_data["minimal_key"] = {
            "user_id": 5,
            "key": "minimal_key",
            "is_active": True,
        }
        self.user_permissions_data[5] = []  # No permissions

        headers = {"api-key": "minimal_key"}
        response = self.client.get("/db-protected", headers=headers)

        assert response.status_code == 200
        data = response.json()
        assert data["user_id"] == 5
        assert data["permissions"] == []


class TestOAuth2Integration:
    """Test the OAuth2 Integration pattern from advanced_examples.md"""

    def setup_method(self):
        """Setup the FastAPI app for each test"""
        self.app = FastAPI()

        # OAuth2 configuration
        oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

        # Mock user database
        self.USERS_DB = {
            "johndoe": {
                "username": "johndoe",
                "full_name": "John Doe",
                "email": "john@example.com",
                "hashed_password": "fakehashedsecret",
                "roles": ["user"],
            },
            "alice": {
                "username": "alice",
                "full_name": "Alice Smith",
                "email": "alice@example.com",
                "hashed_password": "fakehashedsecret2",
                "roles": ["user", "admin"],
            },
        }

        # Models
        class Token(BaseModel):
            access_token: str
            token_type: str

        class TokenData(BaseModel):
            username: Optional[str] = None
            roles: list[str] = []

        class User(BaseModel):
            username: str
            email: Optional[str] = None
            full_name: Optional[str] = None
            roles: list[str] = []

        self.Token = Token
        self.TokenData = TokenData
        self.User = User

        # Setup helper functions and shields
        self.setup_helpers()
        self.setup_shields(oauth2_scheme)
        self.setup_routes()

        self.client = TestClient(self.app)

    def setup_helpers(self):
        """Setup helper functions"""

        def verify_password(plain_password, hashed_password):
            """Verify password (simplified for example)"""
            return plain_password == hashed_password

        def get_user(db, username: str):
            """Get user from database"""
            if username in db:
                user_dict = db[username]
                return self.User(**user_dict)
            return None

        def authenticate_user(fake_db, username: str, password: str):
            """Authenticate user"""
            user = get_user(fake_db, username)
            if not user:
                return False
            if not verify_password(password, fake_db[username]["hashed_password"]):
                return False
            return user

        def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
            """Create JWT access token"""
            to_encode = data.copy()
            if expires_delta:
                expire = datetime.utcnow() + expires_delta
            else:
                expire = datetime.utcnow() + timedelta(minutes=15)
            to_encode.update({"exp": expire})
            encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
            return encoded_jwt

        self.verify_password = verify_password
        self.get_user = get_user
        self.authenticate_user = authenticate_user
        self.create_access_token = create_access_token

    def setup_shields(self, oauth2_scheme):
        """Setup OAuth2 shields"""

        @shield(name="OAuth2 Shield")
        async def oauth2_shield(token: str = Depends(oauth2_scheme)):
            """Shield that validates OAuth2 tokens"""
            try:
                payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
                username: str = payload.get("sub")
                if username is None:
                    return None
                token_data = self.TokenData(
                    username=username, roles=payload.get("roles", [])
                )
            except Exception:
                return None

            user = self.get_user(self.USERS_DB, username=token_data.username)
            if user is None:
                return None

            # Return both user and token data
            return {"user": user, "token_data": token_data}

        def require_oauth2_role(role: str):
            """Shield factory for OAuth2 role checking"""

            @shield(
                name=f"OAuth2 Role ({role})",
                exception_to_raise_if_fail=HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Role {role} required",
                ),
            )
            async def role_check(oauth_data=ShieldedDepends(lambda payload: payload)):
                token_data = oauth_data["token_data"]
                if role in token_data.roles:
                    return oauth_data
                return None

            return role_check

        self.oauth2_shield = oauth2_shield
        self.require_oauth2_role = require_oauth2_role

    def setup_routes(self):
        """Setup OAuth2 routes"""

        @self.app.post("/token", response_model=self.Token)
        async def login_for_access_token(
            form_data: OAuth2PasswordRequestForm = Depends(),
        ):
            """OAuth2 token endpoint"""
            user = self.authenticate_user(
                self.USERS_DB, form_data.username, form_data.password
            )
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Incorrect username or password",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            access_token = self.create_access_token(
                data={"sub": user.username, "roles": user.roles},
                expires_delta=access_token_expires,
            )
            return {"access_token": access_token, "token_type": "bearer"}

        @self.app.get("/users/me")
        @self.oauth2_shield
        async def read_users_me(
            oauth_data=ShieldedDepends(lambda oauth_data: oauth_data),
        ):
            """Get current user information"""
            user = oauth_data["user"]
            return user

        @self.app.get("/admin/settings")
        @self.oauth2_shield
        @self.require_oauth2_role("admin")
        async def admin_settings(
            oauth_data=ShieldedDepends(lambda oauth_data: oauth_data),
        ):
            """Admin-only endpoint"""
            return {"message": "Admin settings", "user": oauth_data["user"].username}

    def test_token_generation_valid_credentials(self):
        """Test token generation with valid credentials"""
        form_data = {"username": "johndoe", "password": "fakehashedsecret"}
        response = self.client.post("/token", data=form_data)

        assert response.status_code == 200, response.json()
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

        # Verify token is valid
        token = data["access_token"]
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        assert payload["sub"] == "johndoe"
        assert payload["roles"] == ["user"]

    def test_token_generation_invalid_credentials(self):
        """Test token generation with invalid credentials"""
        form_data = {"username": "johndoe", "password": "wrongpassword"}
        response = self.client.post("/token", data=form_data)

        assert response.status_code == 401
        assert response.json()["detail"] == "Incorrect username or password"

    def test_token_generation_nonexistent_user(self):
        """Test token generation with non-existent user"""
        form_data = {"username": "nonexistent", "password": "secret"}
        response = self.client.post("/token", data=form_data)

        assert response.status_code == 401
        assert response.json()["detail"] == "Incorrect username or password"

    def test_users_me_with_valid_token(self):
        """Test /users/me with valid OAuth2 token"""
        token = create_oauth2_token("johndoe", ["user"])
        headers = {"Authorization": f"Bearer {token}"}

        response = self.client.get("/users/me", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "johndoe"
        assert data["email"] == "john@example.com"
        assert data["full_name"] == "John Doe"
        assert data["roles"] == ["user"]

    def test_users_me_with_invalid_token(self):
        """Test /users/me with invalid token"""
        headers = {"Authorization": "Bearer invalid_token"}

        response = self.client.get("/users/me", headers=headers)
        assert response.status_code == 500  # OAuth2 shield blocks

    def test_users_me_without_token(self):
        """Test /users/me without token"""
        response = self.client.get("/users/me")
        assert response.status_code == 401  # OAuth2 scheme requires token

    def test_admin_settings_with_admin_role(self):
        """Test admin settings with admin role"""
        token = create_oauth2_token("alice", ["user", "admin"])
        headers = {"Authorization": f"Bearer {token}"}

        response = self.client.get("/admin/settings", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Admin settings"
        assert data["user"] == "alice"

    def test_admin_settings_without_admin_role(self):
        """Test admin settings without admin role"""
        token = create_oauth2_token("johndoe", ["user"])
        headers = {"Authorization": f"Bearer {token}"}

        response = self.client.get("/admin/settings", headers=headers)
        assert response.status_code == 403
        assert "Role admin required" in response.json()["detail"]

    def test_expired_oauth2_token(self):
        """Test with expired OAuth2 token"""
        token = create_oauth2_token("johndoe", ["user"], expired=True)
        headers = {"Authorization": f"Bearer {token}"}

        response = self.client.get("/users/me", headers=headers)
        assert response.status_code == 500  # OAuth2 shield blocks

    def test_token_with_no_username(self):
        """Test token without username (sub)"""
        payload = {"roles": ["user"], "exp": datetime.utcnow() + timedelta(hours=1)}
        token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
        headers = {"Authorization": f"Bearer {token}"}

        response = self.client.get("/users/me", headers=headers)
        assert response.status_code == 500  # OAuth2 shield blocks

    def test_token_for_nonexistent_user(self):
        """Test token for non-existent user"""
        token = create_oauth2_token("nonexistent", ["user"])
        headers = {"Authorization": f"Bearer {token}"}

        response = self.client.get("/users/me", headers=headers)
        assert response.status_code == 500  # OAuth2 shield blocks

    def test_malformed_bearer_token(self):
        """Test with malformed bearer token"""
        headers = {"Authorization": "Malformed invalid_token"}

        response = self.client.get("/users/me", headers=headers)
        assert response.status_code == 401  # OAuth2 scheme rejects

    def test_multiple_roles_access(self):
        """Test user with multiple roles"""
        token = create_oauth2_token("alice", ["user", "admin", "manager"])
        headers = {"Authorization": f"Bearer {token}"}

        # Should access regular user endpoint
        response = self.client.get("/users/me", headers=headers)
        assert response.status_code == 200

        # Should access admin endpoint
        response = self.client.get("/admin/settings", headers=headers)
        assert response.status_code == 200


class TestAdvancedErrorHandling:
    """Test advanced error handling scenarios"""

    def setup_method(self):
        """Setup for error handling tests"""
        self.app = FastAPI()

        @shield(name="Error Test Shield")
        async def error_shield(test_mode: str = Header(None)):
            """Shield that can simulate various error conditions"""
            if test_mode == "exception":
                raise ValueError("Simulated shield error")
            elif test_mode == "timeout":
                await asyncio.sleep(0.1)  # Simulate slow operation
                return {"mode": "timeout"}
            elif test_mode == "none":
                return None
            elif test_mode == "valid":
                return {"mode": "valid"}
            else:
                return None

        @self.app.exception_handler(ValueError)
        async def value_error_handler(_: Request, exc: ValueError):
            return JSONResponse(
                status_code=500,
                content={"detail": str(exc)},
            )

        @self.app.get("/error-test")
        @error_shield
        async def error_test_endpoint(data=ShieldedDepends(lambda data: data)):
            return {"message": "Success", "data": data}

        self.client = TestClient(self.app)

    def test_shield_exception_handling(self):
        """Test how shields handle internal exceptions"""
        headers = {"test-mode": "exception"}
        response = self.client.get("/error-test", headers=headers)
        # Should handle exception gracefully
        assert response.status_code == 500

    def test_shield_timeout_handling(self):
        """Test shield with slow operations"""
        headers = {"test-mode": "timeout"}
        response = self.client.get("/error-test", headers=headers)
        assert response.status_code == 200

    def test_shield_none_return(self):
        """Test shield returning None"""
        headers = {"test-mode": "none"}
        response = self.client.get("/error-test", headers=headers)
        assert response.status_code == 500

    def test_shield_valid_return(self):
        """Test shield returning valid data"""
        headers = {"test-mode": "valid"}
        response = self.client.get("/error-test", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Success"
        assert data["data"]["mode"] == "valid"


class TestShieldComposition:
    """Test complex shield composition scenarios"""

    def setup_method(self):
        """Setup for composition tests"""
        self.app = FastAPI()

        @shield(name="Shield A")
        async def shield_a(value_a: str = Header(None)):
            if value_a == "valid_a":
                return {"from_a": "data_a"}
            return None

        @shield(name="Shield B")
        async def shield_b(
            value_b: str = Header(None), data_from_a=ShieldedDepends(lambda data: data)
        ):
            if value_b == "valid_b" and data_from_a:
                return {"from_b": "data_b", "chain_data": data_from_a}
            return None

        @shield(name="Shield C")
        async def shield_c(
            value_c: str = Header(None), data_from_b=ShieldedDepends(lambda data: data)
        ):
            if value_c == "valid_c" and data_from_b:
                return {"from_c": "data_c", "chain_data": data_from_b}
            return None

        @self.app.get("/triple-shield")
        @shield_a
        @shield_b
        @shield_c
        async def triple_shield_endpoint(final_data=ShieldedDepends(lambda data: data)):
            return {"message": "Triple shield success", "final_data": final_data}

        self.client = TestClient(self.app)

    def test_successful_triple_chain(self):
        """Test successful execution through all three shields"""
        headers = {"value-a": "valid_a", "value-b": "valid_b", "value-c": "valid_c"}
        response = self.client.get("/triple-shield", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Triple shield success"
        assert "final_data" in data

    def test_fail_at_first_shield(self):
        """Test failure at first shield in chain"""
        headers = {"value-a": "invalid", "value-b": "valid_b", "value-c": "valid_c"}
        response = self.client.get("/triple-shield", headers=headers)
        assert response.status_code == 500

    def test_fail_at_second_shield(self):
        """Test failure at second shield in chain"""
        headers = {"value-a": "valid_a", "value-b": "invalid", "value-c": "valid_c"}
        response = self.client.get("/triple-shield", headers=headers)
        assert response.status_code == 500

    def test_fail_at_third_shield(self):
        """Test failure at third shield in chain"""
        headers = {"value-a": "valid_a", "value-b": "valid_b", "value-c": "invalid"}
        response = self.client.get("/triple-shield", headers=headers)
        assert response.status_code == 500


if __name__ == "__main__":
    pytest.main([__file__])
