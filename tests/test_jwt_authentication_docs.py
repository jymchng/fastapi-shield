import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI, Header, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi_shield import shield, ShieldedDepends
import jwt
from jwt.exceptions import PyJWTError
from datetime import datetime, timedelta
from typing import Optional, List
from pydantic import BaseModel
from unittest.mock import patch
import os


class TestBasicJWTAuthentication:
    """Tests for Basic JWT Authentication patterns from jwt-authentication.md"""

    def setup_method(self):
        """Setup the FastAPI app for each test"""
        app = FastAPI()

        # Configuration
        JWT_SECRET = "test-secret-key"
        JWT_ALGORITHM = "HS256"

        @shield(
            name="JWT Authentication",
            exception_to_raise_if_fail=HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            ),
        )
        def jwt_auth_shield(authorization: str = Header()) -> dict:
            """Validate JWT token and return decoded payload"""
            if not authorization.startswith("Bearer "):
                return None

            token = authorization.replace("Bearer ", "")

            try:
                payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
                return payload
            except PyJWTError:
                return None

        # Protected endpoint using the shield
        @app.get("/protected")
        @jwt_auth_shield
        async def protected_endpoint(
            payload: dict = ShieldedDepends(lambda payload: payload),
        ):
            return {
                "message": "Access granted",
                "user": payload.get("sub"),
                "roles": payload.get("roles", []),
            }

        self.app = app
        self.client = TestClient(app)
        self.jwt_secret = JWT_SECRET
        self.jwt_algorithm = JWT_ALGORITHM

    def create_test_token(self, sub: str, roles: List[str] = None) -> str:
        """Create a test JWT token"""
        payload = {"sub": sub, "roles": roles or ["user"]}
        return jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_algorithm)

    def test_jwt_authentication_success(self):
        """Test successful JWT authentication"""
        token = self.create_test_token("test_user", ["user", "admin"])

        response = self.client.get(
            "/protected", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Access granted"
        assert data["user"] == "test_user"
        assert data["roles"] == ["user", "admin"]

    def test_jwt_authentication_invalid_token(self):
        """Test JWT authentication with invalid token"""
        response = self.client.get(
            "/protected", headers={"Authorization": "Bearer invalid.token.here"}
        )

        assert response.status_code == 401
        assert "Invalid authentication credentials" in response.json()["detail"]

    def test_jwt_authentication_malformed_header(self):
        """Test JWT authentication with malformed header"""
        response = self.client.get(
            "/protected", headers={"Authorization": "InvalidFormat token"}
        )

        assert response.status_code == 401

    def test_jwt_authentication_missing_header(self):
        """Test JWT authentication without authorization header"""
        response = self.client.get("/protected")
        assert response.status_code == 422  # FastAPI validation error


class TestRoleBasedAccessControl:
    """Tests for Role-Based Access Control patterns from jwt-authentication.md"""

    def setup_method(self):
        """Setup the FastAPI app for each test"""
        app = FastAPI()

        # User database with roles
        USERS = {
            "admin_token": {"user_id": "admin", "roles": ["admin", "user"]},
            "editor_token": {"user_id": "editor", "roles": ["editor", "user"]},
            "user_token": {"user_id": "user1", "roles": ["user"]},
        }

        @shield(name="Authentication")
        def auth_shield(api_token: str = Header()) -> dict:
            """Authenticate the user and return user data"""
            if api_token in USERS:
                return USERS[api_token]
            return None

        def role_shield(required_roles: list[str]):
            """Factory function to create a role-checking shield"""

            @shield(
                name=f"Role Check ({', '.join(required_roles)})",
                exception_to_raise_if_fail=HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Access denied. Required roles: {', '.join(required_roles)}",
                ),
            )
            def check_role(
                user_data: dict = ShieldedDepends(lambda user: user),
            ) -> dict:
                """Check if the user has any of the required roles"""
                user_roles = user_data.get("roles", [])
                if any(role in required_roles for role in user_roles):
                    return user_data
                return None

            return check_role

        # Create specific role shields
        admin_shield = role_shield(["admin"])
        editor_shield = role_shield(["admin", "editor"])
        user_shield = role_shield(["admin", "editor", "user"])

        @app.get("/admin")
        @auth_shield
        @admin_shield
        async def admin_endpoint(user: dict = ShieldedDepends(lambda user: user)):
            return {"message": "Admin endpoint", "user": user["user_id"]}

        @app.get("/editor")
        @auth_shield
        @editor_shield
        async def editor_endpoint(user: dict = ShieldedDepends(lambda user: user)):
            return {"message": "Editor endpoint", "user": user["user_id"]}

        @app.get("/user")
        @auth_shield
        @user_shield
        async def user_endpoint(user: dict = ShieldedDepends(lambda user: user)):
            return {"message": "User endpoint", "user": user["user_id"]}

        self.app = app
        self.client = TestClient(app)

    def test_admin_access_with_admin_token(self):
        """Test admin endpoint access with admin token"""
        response = self.client.get("/admin", headers={"api-token": "admin_token"})
        assert response.status_code == 200
        assert response.json()["message"] == "Admin endpoint"
        assert response.json()["user"] == "admin"

    def test_admin_access_with_editor_token(self):
        """Test admin endpoint access with editor token (should fail)"""
        response = self.client.get("/admin", headers={"api-token": "editor_token"})
        assert response.status_code == 403
        assert "Access denied. Required roles: admin" in response.json()["detail"]

    def test_editor_access_with_admin_token(self):
        """Test editor endpoint access with admin token (should pass)"""
        response = self.client.get("/editor", headers={"api-token": "admin_token"})
        assert response.status_code == 200
        assert response.json()["message"] == "Editor endpoint"

    def test_editor_access_with_editor_token(self):
        """Test editor endpoint access with editor token"""
        response = self.client.get("/editor", headers={"api-token": "editor_token"})
        assert response.status_code == 200
        assert response.json()["message"] == "Editor endpoint"

    def test_user_access_with_all_tokens(self):
        """Test user endpoint access with all token types"""
        tokens = ["admin_token", "editor_token", "user_token"]
        for token in tokens:
            response = self.client.get("/user", headers={"api-token": token})
            assert response.status_code == 200
            assert response.json()["message"] == "User endpoint"


class TestAdvancedJWTAuthentication:
    """Tests for Advanced JWT Authentication with Chained Shields from jwt-authentication.md"""

    def setup_method(self):
        """Setup the FastAPI app for each test"""
        app = FastAPI()

        # Configuration
        JWT_SECRET = "test-secret-key"
        JWT_ALGORITHM = "HS256"

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

        @shield(
            name="JWT Authentication",
            exception_to_raise_if_fail=HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            ),
        )
        async def jwt_auth_shield(authorization: str = Header()) -> Optional[dict]:
            """Validate JWT token and extract payload"""
            if not authorization.startswith("Bearer "):
                return None

            token = authorization.replace("Bearer ", "")

            try:
                payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
                return payload
            except PyJWTError:
                return None

        @shield(
            name="User Role Extraction",
            exception_to_raise_if_fail=HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid user data in token",
            ),
        )
        async def role_extraction_shield(
            payload: dict = ShieldedDepends(lambda payload: payload),
        ) -> Optional[AuthData]:
            """Extract user roles from the JWT payload and create AuthData object"""
            if not payload or "user_id" not in payload:
                return None

            user_id = payload.get("user_id")
            roles = payload.get("roles", [])
            permissions = payload.get("permissions", [])

            return AuthData(user_id, roles, permissions)

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
                auth_data: AuthData = ShieldedDepends(lambda auth_data: auth_data),
            ) -> Optional[AuthData]:
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
                auth_data: AuthData = ShieldedDepends(lambda auth_data: auth_data),
            ) -> Optional[AuthData]:
                if auth_data.has_permission(permission):
                    return auth_data
                return None

            return permission_shield

        # Usage examples
        @app.get("/user-profile")
        @jwt_auth_shield
        @role_extraction_shield
        async def user_profile(
            auth_data: AuthData = ShieldedDepends(lambda auth_data: auth_data),
        ):
            return {
                "user_id": auth_data.user_id,
                "roles": auth_data.roles,
                "permissions": auth_data.permissions,
            }

        @app.get("/admin-panel")
        @jwt_auth_shield
        @role_extraction_shield
        @require_role("admin")
        async def admin_panel(
            auth_data: AuthData = ShieldedDepends(lambda auth_data: auth_data),
        ):
            return {"message": "Welcome to admin panel", "user_id": auth_data.user_id}

        @app.post("/user-management")
        @jwt_auth_shield
        @role_extraction_shield
        @require_permission("manage_users")
        async def user_management(
            auth_data: AuthData = ShieldedDepends(lambda auth_data: auth_data),
        ):
            return {
                "message": "User management access granted",
                "user_id": auth_data.user_id,
            }

        self.app = app
        self.client = TestClient(app)
        self.jwt_secret = JWT_SECRET
        self.jwt_algorithm = JWT_ALGORITHM
        self.AuthData = AuthData

    def create_test_token(
        self, user_id: str, roles: List[str] = None, permissions: List[str] = None
    ) -> str:
        """Create a test JWT token"""
        payload = {
            "user_id": user_id,
            "roles": roles or ["user"],
            "permissions": permissions or [],
        }
        return jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_algorithm)

    def test_user_profile_success(self):
        """Test user profile with valid JWT token"""
        token = self.create_test_token("test_user", ["user"], ["read"])

        response = self.client.get(
            "/user-profile", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["user_id"] == "test_user"
        assert data["roles"] == ["user"]
        assert data["permissions"] == ["read"]

    def test_admin_panel_with_admin_role(self):
        """Test admin panel with admin role"""
        token = self.create_test_token("admin_user", ["admin"], ["manage_users"])

        response = self.client.get(
            "/admin-panel", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Welcome to admin panel"
        assert data["user_id"] == "admin_user"

    def test_admin_panel_without_admin_role(self):
        """Test admin panel without admin role (should fail)"""
        token = self.create_test_token("regular_user", ["user"], ["read"])

        response = self.client.get(
            "/admin-panel", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 403
        assert "Requires role: admin" in response.json()["detail"]

    def test_user_management_with_permission(self):
        """Test user management with required permission"""
        token = self.create_test_token("manager", ["manager"], ["manage_users"])

        response = self.client.post(
            "/user-management", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "User management access granted"
        assert data["user_id"] == "manager"

    def test_user_management_without_permission(self):
        """Test user management without required permission (should fail)"""
        token = self.create_test_token("regular_user", ["user"], ["read"])

        response = self.client.post(
            "/user-management", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 403
        assert "Requires permission: manage_users" in response.json()["detail"]

    def test_invalid_token_authentication(self):
        """Test authentication with invalid token"""
        response = self.client.get(
            "/user-profile", headers={"Authorization": "Bearer invalid.token"}
        )

        assert response.status_code == 401
        assert "Authentication required" in response.json()["detail"]

    def test_token_missing_user_id(self):
        """Test token without required user_id field"""
        payload = {"roles": ["user"], "permissions": ["read"]}
        token = jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_algorithm)

        response = self.client.get(
            "/user-profile", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 401
        assert "Invalid user data in token" in response.json()["detail"]


class TestOAuth2Integration:
    """Tests for OAuth2 Integration patterns from jwt-authentication.md"""

    def setup_method(self):
        """Setup the FastAPI app for each test"""
        app = FastAPI()

        # OAuth2 scheme
        oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

        # Configuration
        SECRET_KEY = "test-secret-key"
        ALGORITHM = "HS256"
        ACCESS_TOKEN_EXPIRE_MINUTES = 30

        # Models
        class Token(BaseModel):
            access_token: str
            token_type: str

        class User(BaseModel):
            username: str
            email: Optional[str] = None
            full_name: Optional[str] = None
            roles: List[str] = []

        # Mock database
        fake_users_db = {
            "johndoe": {
                "username": "johndoe",
                "full_name": "John Doe",
                "email": "johndoe@example.com",
                "hashed_password": "fakehashedsecret",
                "roles": ["user"],
            },
            "alice": {
                "username": "alice",
                "full_name": "Alice Admin",
                "email": "alice@example.com",
                "hashed_password": "fakehashedsecret2",
                "roles": ["admin", "user"],
            },
        }

        def verify_password(plain_password: str, hashed_password: str) -> bool:
            # In production, use proper password hashing
            return plain_password == "secret"

        def authenticate_user(username: str, password: str):
            user = fake_users_db.get(username)
            if not user or not verify_password(password, user["hashed_password"]):
                return False
            return user

        def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
            to_encode = data.copy()
            expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
            to_encode.update({"exp": expire})
            return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

        @shield(
            name="OAuth2 JWT Authentication",
            exception_to_raise_if_fail=HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            ),
        )
        async def oauth2_jwt_shield(token: str = Depends(oauth2_scheme)) -> User:
            """Validate OAuth2 JWT token and return user"""
            try:
                payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
                username: str = payload.get("sub")
                if username is None:
                    return None
            except PyJWTError:
                return None

            user_dict = fake_users_db.get(username)
            if user_dict is None:
                return None

            return User(**user_dict)

        def require_oauth2_role(role: str):
            """Create a shield that requires a specific OAuth2 role"""

            @shield(
                name=f"OAuth2 Role ({role})",
                exception_to_raise_if_fail=HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Role {role} required",
                ),
            )
            async def role_check(
                user: User = ShieldedDepends(lambda user: user),
            ) -> User:
                if role in user.roles:
                    return user
                return None

            return role_check

        # Token endpoint
        @app.post("/token", response_model=Token)
        async def login_for_access_token(
            form_data: OAuth2PasswordRequestForm = Depends(),
        ):
            user = authenticate_user(form_data.username, form_data.password)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Incorrect username or password",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            access_token = create_access_token(
                data={"sub": user["username"]}, expires_delta=access_token_expires
            )

            return {"access_token": access_token, "token_type": "bearer"}

        # Protected endpoints
        @app.get("/users/me")
        @oauth2_jwt_shield
        async def read_users_me(
            user: User = ShieldedDepends(lambda user: user),
        ):
            return user

        @app.get("/admin/settings")
        @oauth2_jwt_shield
        @require_oauth2_role("admin")
        async def admin_settings(
            user: User = ShieldedDepends(lambda user: user),
        ):
            return {"message": "Admin settings", "user": user.username}

        self.app = app
        self.client = TestClient(app)
        self.secret_key = SECRET_KEY
        self.algorithm = ALGORITHM

    def test_token_generation_valid_credentials(self):
        """Test token generation with valid credentials"""
        response = self.client.post(
            "/token", data={"username": "johndoe", "password": "secret"}
        )

        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_token_generation_invalid_credentials(self):
        """Test token generation with invalid credentials"""
        response = self.client.post(
            "/token", data={"username": "johndoe", "password": "wrong"}
        )

        assert response.status_code == 401
        assert "Incorrect username or password" in response.json()["detail"]

    def test_users_me_with_valid_token(self):
        """Test /users/me endpoint with valid token"""
        # First get a token
        token_response = self.client.post(
            "/token", data={"username": "johndoe", "password": "secret"}
        )
        token = token_response.json()["access_token"]

        # Use the token
        response = self.client.get(
            "/users/me", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "johndoe"
        assert data["full_name"] == "John Doe"
        assert data["roles"] == ["user"]

    def test_users_me_with_invalid_token(self):
        """Test /users/me endpoint with invalid token"""
        response = self.client.get(
            "/users/me", headers={"Authorization": "Bearer invalid.token"}
        )

        assert response.status_code == 401
        assert "Could not validate credentials" in response.json()["detail"]

    def test_admin_settings_with_admin_role(self):
        """Test admin settings endpoint with admin role"""
        # Get admin token
        token_response = self.client.post(
            "/token", data={"username": "alice", "password": "secret"}
        )
        token = token_response.json()["access_token"]

        # Access admin endpoint
        response = self.client.get(
            "/admin/settings", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Admin settings"
        assert data["user"] == "alice"

    def test_admin_settings_without_admin_role(self):
        """Test admin settings endpoint without admin role"""
        # Get user token
        token_response = self.client.post(
            "/token", data={"username": "johndoe", "password": "secret"}
        )
        token = token_response.json()["access_token"]

        # Try to access admin endpoint
        response = self.client.get(
            "/admin/settings", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 403
        assert "Role admin required" in response.json()["detail"]


class TestJWTTokenCreation:
    """Tests for JWT Token Creation and Management from jwt-authentication.md"""

    def setup_method(self):
        """Setup JWT token creation functions"""
        self.JWT_SECRET = "test-secret-key"
        self.JWT_ALGORITHM = "HS256"

    def create_jwt_token(
        self,
        user_id: str,
        roles: List[str] = None,
        permissions: List[str] = None,
        expires_delta: Optional[timedelta] = None,
    ) -> str:
        """Create a JWT token with user information"""
        payload = {
            "user_id": user_id,
            "roles": roles or [],
            "permissions": permissions or [],
        }

        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(hours=1)

        payload["exp"] = expire

        return jwt.encode(payload, self.JWT_SECRET, algorithm=self.JWT_ALGORITHM)

    def test_create_admin_token(self):
        """Test creating admin token with roles and permissions"""
        token = self.create_jwt_token(
            user_id="admin_user",
            roles=["admin", "user"],
            permissions=["read", "write", "delete"],
            expires_delta=timedelta(hours=8),
        )

        # Decode and verify
        payload = jwt.decode(token, self.JWT_SECRET, algorithms=[self.JWT_ALGORITHM])
        assert payload["user_id"] == "admin_user"
        assert payload["roles"] == ["admin", "user"]
        assert payload["permissions"] == ["read", "write", "delete"]
        assert "exp" in payload

    def test_create_user_token(self):
        """Test creating user token with basic permissions"""
        token = self.create_jwt_token(
            user_id="regular_user",
            roles=["user"],
            permissions=["read"],
            expires_delta=timedelta(hours=1),
        )

        # Decode and verify
        payload = jwt.decode(token, self.JWT_SECRET, algorithms=[self.JWT_ALGORITHM])
        assert payload["user_id"] == "regular_user"
        assert payload["roles"] == ["user"]
        assert payload["permissions"] == ["read"]

    def test_token_expiration(self):
        """Test token with custom expiration"""
        short_expiry = timedelta(seconds=1)
        token = self.create_jwt_token(user_id="test_user", expires_delta=short_expiry)

        # Token should be valid immediately
        payload = jwt.decode(token, self.JWT_SECRET, algorithms=[self.JWT_ALGORITHM])
        assert payload["user_id"] == "test_user"

        # Wait for expiration and verify it fails
        import time

        time.sleep(2)

        with pytest.raises(jwt.ExpiredSignatureError):
            jwt.decode(token, self.JWT_SECRET, algorithms=[self.JWT_ALGORITHM])


class TestSecureJWTAuthentication:
    """Tests for Secure JWT Authentication patterns from jwt-authentication.md"""

    def setup_method(self):
        """Setup the FastAPI app for secure JWT testing"""
        app = FastAPI()

        JWT_SECRET = "test-secret-key"
        JWT_ALGORITHM = "HS256"

        @shield(
            name="Secure JWT Authentication",
            exception_to_raise_if_fail=HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication failed",
                headers={"WWW-Authenticate": "Bearer"},
            ),
        )
        def secure_jwt_shield(authorization: str = Header()) -> Optional[dict]:
            """Secure JWT validation with proper error handling"""

            # Check authorization header format
            if not authorization or not authorization.startswith("Bearer "):
                return None

            token = authorization.replace("Bearer ", "")

            try:
                # Decode and validate token
                payload = jwt.decode(
                    token,
                    JWT_SECRET,
                    algorithms=[JWT_ALGORITHM],
                    options={"verify_exp": True},  # Ensure expiration is checked
                )

                # Validate required claims
                if not payload.get("user_id"):
                    return None

                # Check token expiration explicitly
                exp = payload.get("exp")
                if exp and datetime.utcnow().timestamp() > exp:
                    return None

                return payload

            except jwt.ExpiredSignatureError:
                # Token has expired
                return None
            except jwt.InvalidTokenError:
                # Token is invalid
                return None
            except Exception:
                # Any other error
                return None

        @app.get("/secure")
        @secure_jwt_shield
        async def secure_endpoint(
            payload: dict = ShieldedDepends(lambda payload: payload),
        ):
            return {"message": "Secure access granted", "user_id": payload["user_id"]}

        self.app = app
        self.client = TestClient(app)
        self.jwt_secret = JWT_SECRET
        self.jwt_algorithm = JWT_ALGORITHM

    def create_test_token(self, user_id: str, expired: bool = False) -> str:
        """Create a test JWT token"""
        payload = {"user_id": user_id}

        if expired:
            payload["exp"] = datetime.utcnow() - timedelta(hours=1)
        else:
            payload["exp"] = datetime.utcnow() + timedelta(hours=1)

        return jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_algorithm)

    def test_secure_jwt_success(self):
        """Test secure JWT authentication with valid token"""
        token = self.create_test_token("test_user")

        response = self.client.get(
            "/secure", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Secure access granted"
        assert data["user_id"] == "test_user"

    def test_secure_jwt_expired_token(self):
        """Test secure JWT authentication with expired token"""
        token = self.create_test_token("test_user", expired=True)

        response = self.client.get(
            "/secure", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 401
        assert "Authentication failed" in response.json()["detail"]

    def test_secure_jwt_missing_user_id(self):
        """Test secure JWT authentication with missing user_id"""
        payload = {"some_field": "value"}
        token = jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_algorithm)

        response = self.client.get(
            "/secure", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 401

    def test_secure_jwt_invalid_token(self):
        """Test secure JWT authentication with invalid token"""
        response = self.client.get(
            "/secure", headers={"Authorization": "Bearer invalid.token.here"}
        )

        assert response.status_code == 401

    def test_secure_jwt_malformed_header(self):
        """Test secure JWT authentication with malformed header"""
        response = self.client.get(
            "/secure", headers={"Authorization": "NotBearer token"}
        )

        assert response.status_code == 401


class TestEnvironmentConfiguration:
    """Tests for Environment Configuration patterns from jwt-authentication.md"""

    def test_environment_configuration_production(self):
        """Test environment configuration validation in production"""
        with patch.dict(
            os.environ, {"ENVIRONMENT": "production", "JWT_SECRET_KEY": ""}
        ):
            with pytest.raises(
                ValueError, match="JWT_SECRET_KEY must be set in production"
            ):
                # Production configuration
                JWT_SECRET = os.getenv("JWT_SECRET_KEY", "fallback-secret-for-dev")
                JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
                ACCESS_TOKEN_EXPIRE_MINUTES = int(
                    os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30")
                )

                # Validate configuration
                if not JWT_SECRET or JWT_SECRET == "fallback-secret-for-dev":
                    if os.getenv("ENVIRONMENT") == "production":
                        raise ValueError("JWT_SECRET_KEY must be set in production")

    def test_environment_configuration_development(self):
        """Test environment configuration in development"""
        with patch.dict(os.environ, {"ENVIRONMENT": "development"}, clear=True):
            # Production configuration
            JWT_SECRET = os.getenv("JWT_SECRET_KEY", "fallback-secret-for-dev")
            JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
            ACCESS_TOKEN_EXPIRE_MINUTES = int(
                os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30")
            )

            # Should not raise in development
            assert JWT_SECRET == "fallback-secret-for-dev"
            assert JWT_ALGORITHM == "HS256"
            assert ACCESS_TOKEN_EXPIRE_MINUTES == 30

    def test_environment_configuration_with_values(self):
        """Test environment configuration with proper values"""
        with patch.dict(
            os.environ,
            {
                "JWT_SECRET_KEY": "production-secret",
                "JWT_ALGORITHM": "HS512",
                "ACCESS_TOKEN_EXPIRE_MINUTES": "60",
            },
        ):
            JWT_SECRET = os.getenv("JWT_SECRET_KEY", "fallback-secret-for-dev")
            JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
            ACCESS_TOKEN_EXPIRE_MINUTES = int(
                os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30")
            )

            assert JWT_SECRET == "production-secret"
            assert JWT_ALGORITHM == "HS512"
            assert ACCESS_TOKEN_EXPIRE_MINUTES == 60


class TestJWTTestingHelpers:
    """Tests for JWT Testing Helper patterns from jwt-authentication.md"""

    def setup_method(self):
        """Setup testing helpers"""
        self.JWT_SECRET = "test-secret-key"
        self.JWT_ALGORITHM = "HS256"

    def create_test_token(self, user_id: str, roles: List[str] = None) -> str:
        """Create a test JWT token"""
        payload = {"user_id": user_id, "roles": roles or ["user"]}
        return jwt.encode(payload, self.JWT_SECRET, algorithm=self.JWT_ALGORITHM)

    def test_create_test_token_helper(self):
        """Test the test token creation helper"""
        token = self.create_test_token("test_user", ["user"])

        # Verify token can be decoded
        payload = jwt.decode(token, self.JWT_SECRET, algorithms=[self.JWT_ALGORITHM])
        assert payload["user_id"] == "test_user"
        assert payload["roles"] == ["user"]

    def test_create_admin_test_token(self):
        """Test creating admin test token"""
        token = self.create_test_token("admin_user", ["admin"])

        # Verify token can be decoded
        payload = jwt.decode(token, self.JWT_SECRET, algorithms=[self.JWT_ALGORITHM])
        assert payload["user_id"] == "admin_user"
        assert payload["roles"] == ["admin"]

    def test_create_test_token_default_roles(self):
        """Test creating test token with default roles"""
        token = self.create_test_token("default_user")

        # Verify token can be decoded
        payload = jwt.decode(token, self.JWT_SECRET, algorithms=[self.JWT_ALGORITHM])
        assert payload["user_id"] == "default_user"
        assert payload["roles"] == ["user"]  # Default role


class TestJWTDocumentationIntegration:
    """Integration tests combining multiple JWT patterns from jwt-authentication.md"""

    def setup_method(self):
        """Setup comprehensive JWT authentication app"""
        app = FastAPI()

        # Configuration
        JWT_SECRET = "test-secret-key"
        JWT_ALGORITHM = "HS256"

        # Basic JWT shield
        @shield(
            name="JWT Authentication",
            exception_to_raise_if_fail=HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            ),
        )
        def jwt_auth_shield(authorization: str = Header()) -> dict:
            if not authorization.startswith("Bearer "):
                return None

            token = authorization.replace("Bearer ", "")

            try:
                payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
                return payload
            except PyJWTError:
                return None

        # Role-based shield
        def require_role(role: str):
            @shield(
                name=f"Role Requirement ({role})",
                exception_to_raise_if_fail=HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Role {role} required",
                ),
            )
            def role_shield(
                payload: dict = ShieldedDepends(lambda payload: payload),
            ) -> dict:
                user_roles = payload.get("roles", [])
                if role in user_roles:
                    return payload
                return None

            return role_shield

        admin_role = require_role("admin")

        @app.get("/multi-layer-endpoint")
        @jwt_auth_shield
        @admin_role
        async def multi_layer_endpoint(
            payload: dict = ShieldedDepends(lambda payload: payload),
        ):
            return {
                "message": "Multi-layer security passed",
                "user": payload.get("sub"),
                "roles": payload.get("roles", []),
            }

        self.app = app
        self.client = TestClient(app)
        self.jwt_secret = JWT_SECRET
        self.jwt_algorithm = JWT_ALGORITHM

    def create_test_token(self, sub: str, roles: List[str] = None) -> str:
        """Create a test JWT token"""
        payload = {"sub": sub, "roles": roles or ["user"]}
        return jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_algorithm)

    def test_multi_layer_security_success(self):
        """Test successful access through multiple security layers"""
        token = self.create_test_token("admin_user", ["admin", "user"])

        response = self.client.get(
            "/multi-layer-endpoint", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Multi-layer security passed"
        assert data["user"] == "admin_user"
        assert "admin" in data["roles"]

    def test_multi_layer_security_auth_failure(self):
        """Test authentication failure in multi-layer security"""
        response = self.client.get(
            "/multi-layer-endpoint", headers={"Authorization": "Bearer invalid.token"}
        )

        assert response.status_code == 401
        assert "Authentication required" in response.json()["detail"]

    def test_multi_layer_security_role_failure(self):
        """Test role authorization failure in multi-layer security"""
        token = self.create_test_token("regular_user", ["user"])

        response = self.client.get(
            "/multi-layer-endpoint", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 403
        assert "Role admin required" in response.json()["detail"]
