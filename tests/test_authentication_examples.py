import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import (
    HTTPBasic,
    HTTPBasicCredentials,
    OAuth2PasswordBearer,
    OAuth2PasswordRequestForm,
)
from fastapi_shield import shield, ShieldedDepends
import secrets
import jwt
from datetime import datetime, timedelta
from passlib.context import CryptContext
from typing import NewType, Optional, List, Dict


class TestBasicAuthentication:
    """Tests for the Basic Authentication pattern from authentication-patterns.md"""

    def setup_method(self):
        """Setup the FastAPI app for each test"""
        app = FastAPI()
        security = HTTPBasic()

        # Define an authenticated user type
        AuthenticatedUser = NewType("AuthenticatedUser", str)

        # Mock user database
        USER_DB = {
            "johndoe": {
                "username": "johndoe",
                "password": "password123",
                "full_name": "John Doe",
            }
        }

        # Shield to authenticate the user
        @shield
        def authenticate_user(
            credentials: HTTPBasicCredentials = Depends(security),
        ) -> AuthenticatedUser:
            username = credentials.username
            password = credentials.password

            user = USER_DB.get(username)
            if not user or not secrets.compare_digest(user["password"], password):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid credentials",
                    headers={"WWW-Authenticate": "Basic"},
                )

            return AuthenticatedUser(username)

        # Use the shield in an endpoint
        @app.get("/profile")
        @authenticate_user
        def get_profile(username: AuthenticatedUser = ShieldedDepends(lambda s: s)):
            user_data = USER_DB.get(str(username))
            return {
                "username": user_data["username"],
                "full_name": user_data["full_name"],
            }

        self.app = app
        self.client = TestClient(app)

    def test_valid_credentials(self):
        """Test with valid credentials"""
        response = self.client.get("/profile", auth=("johndoe", "password123"))
        assert response.status_code == 200
        assert response.json() == {"username": "johndoe", "full_name": "John Doe"}

    def test_invalid_password(self):
        """Test with invalid password"""
        response = self.client.get("/profile", auth=("johndoe", "wrongpassword"))
        assert response.status_code == 401
        assert response.json() == {"detail": "Invalid credentials"}

    def test_invalid_username(self):
        """Test with invalid username"""
        response = self.client.get("/profile", auth=("nonexistent", "password123"))
        assert response.status_code == 401
        assert response.json() == {"detail": "Invalid credentials"}

    def test_no_auth(self):
        """Test without authentication"""
        response = self.client.get("/profile")
        assert response.status_code == 401
        assert "WWW-Authenticate" in response.headers


class TestTokenAuthentication:
    """Tests for the Token-Based Authentication pattern from authentication-patterns.md"""

    def setup_method(self):
        """Setup the FastAPI app for each test"""
        app = FastAPI()
        security = HTTPBearer = pytest.importorskip("fastapi.security").HTTPBearer
        HTTPAuthorizationCredentials = pytest.importorskip(
            "fastapi.security"
        ).HTTPAuthorizationCredentials

        security = HTTPBearer()

        # Secret key for JWT signing
        SECRET_KEY = "your-secret-key"
        ALGORITHM = "HS256"
        ACCESS_TOKEN_EXPIRE_MINUTES = 30

        # Define user models
        class User(BaseModel := pytest.importorskip("pydantic").BaseModel):
            username: str
            email: Optional[str] = None
            full_name: Optional[str] = None

        # Define an authenticated user type
        AuthenticatedUser = NewType("AuthenticatedUser", User)

        # Mock user database
        USER_DB = {
            "johndoe": {
                "username": "johndoe",
                "email": "johndoe@example.com",
                "full_name": "John Doe",
                "password": "password123",
            }
        }

        # Function to create access token
        def create_access_token(data: dict, expires_delta: timedelta = None):
            to_encode = data.copy()
            expire = datetime.utcnow() + (
                expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            )
            to_encode.update({"exp": expire})
            encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
            return encoded_jwt

        # Shield to validate token and authenticate user
        @shield
        def authenticate_token(
            credentials: HTTPAuthorizationCredentials = Depends(security),
        ) -> AuthenticatedUser:
            token = credentials.credentials
            try:
                payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
                username: str = payload.get("sub")
                if username is None:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid token",
                    )

                user_data = USER_DB.get(username)
                if not user_data:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="User not found",
                    )

                user = User(
                    username=user_data["username"],
                    email=user_data["email"],
                    full_name=user_data["full_name"],
                )

                return AuthenticatedUser(user)
            except jwt.PyJWTError:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token",
                )

        # Function to authenticate user and generate token
        @app.post("/token")
        def login(username: str, password: str):
            user = USER_DB.get(username)
            if not user or user["password"] != password:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid credentials",
                )

            access_token = create_access_token(data={"sub": username})

            return {"access_token": access_token, "token_type": "bearer"}

        # Use the shield in an endpoint
        @app.get("/users/me")
        @authenticate_token
        def get_current_user(
            user: AuthenticatedUser = ShieldedDepends(lambda user: user),
        ):
            return user

        self.app = app
        self.client = TestClient(app)
        self.create_access_token = create_access_token

    def test_valid_token(self):
        """Test with valid token"""
        # Create a valid token
        token = self.create_access_token(data={"sub": "johndoe"})

        # Test the endpoint
        response = self.client.get(
            "/users/me", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        assert response.json()["username"] == "johndoe"
        assert response.json()["email"] == "johndoe@example.com"

    def test_invalid_token(self):
        """Test with invalid token"""
        response = self.client.get(
            "/users/me", headers={"Authorization": "Bearer invalid.token.here"}
        )
        assert response.status_code == 401
        assert "Invalid token" in response.json()["detail"]

    def test_token_generation(self):
        """Test token generation"""
        response = self.client.post(
            "/token", params={"username": "johndoe", "password": "password123"}
        )
        assert response.status_code == 200
        assert "access_token" in response.json()
        assert response.json()["token_type"] == "bearer"

    def test_invalid_credentials_for_token(self):
        """Test token generation with invalid credentials"""
        response = self.client.post(
            "/token", params={"username": "johndoe", "password": "wrongpassword"}
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid credentials"


class TestJWTAuthentication:
    """Tests for the JWT Authentication pattern from authentication-patterns.md"""

    def setup_method(self):
        """Setup the FastAPI app for each test"""
        app = FastAPI()

        # OAuth2 and password hashing setup
        oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
        pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

        # Secret key for JWT signing
        SECRET_KEY = "your-secret-key"
        ALGORITHM = "HS256"
        ACCESS_TOKEN_EXPIRE_MINUTES = 30

        # Define user models
        class UserInDB(BaseModel := pytest.importorskip("pydantic").BaseModel):
            username: str
            email: Optional[str] = None
            full_name: Optional[str] = None
            hashed_password: str
            active: bool = True

        class User(BaseModel):
            username: str
            email: Optional[str] = None
            full_name: Optional[str] = None
            active: bool = True

        # Define an authenticated user type
        AuthenticatedUser = NewType("AuthenticatedUser", User)

        # Mock user database with hashed passwords
        USER_DB = {
            "johndoe": {
                "username": "johndoe",
                "email": "johndoe@example.com",
                "full_name": "John Doe",
                "hashed_password": pwd_context.hash("password123"),
                "active": True,
            },
            "inactive": {
                "username": "inactive",
                "email": "inactive@example.com",
                "full_name": "Inactive User",
                "hashed_password": pwd_context.hash("password123"),
                "active": False,
            },
        }

        # Verify password
        def verify_password(plain_password, hashed_password):
            return pwd_context.verify(plain_password, hashed_password)

        # Function to create access token
        def create_access_token(data: dict, expires_delta: timedelta = None):
            to_encode = data.copy()
            expire = datetime.utcnow() + (
                expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            )
            to_encode.update({"exp": expire})
            encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
            return encoded_jwt

        # Shield to validate JWT and authenticate user
        @shield
        def authenticate_jwt(token: str = Depends(oauth2_scheme)) -> AuthenticatedUser:
            credentials_exception = HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )

            try:
                payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
                username: str = payload.get("sub")
                if username is None:
                    raise credentials_exception

                user_data = USER_DB.get(username)
                if not user_data:
                    raise credentials_exception

                user = User(
                    username=user_data["username"],
                    email=user_data["email"],
                    full_name=user_data["full_name"],
                    active=user_data["active"],
                )

                # Check if user is active
                if not user.active:
                    raise HTTPException(status_code=400, detail="Inactive user")

                return AuthenticatedUser(user)
            except jwt.PyJWTError:
                raise credentials_exception

        # Function to authenticate user and generate token
        @app.post("/token")
        def login(form_data: OAuth2PasswordRequestForm = Depends()):
            user = USER_DB.get(form_data.username)
            if not user or not verify_password(
                form_data.password, user["hashed_password"]
            ):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Incorrect username or password",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            access_token = create_access_token(data={"sub": user["username"]})

            return {"access_token": access_token, "token_type": "bearer"}

        # Use the shield in an endpoint
        @app.get("/users/me")
        @authenticate_jwt
        def get_current_user(
            user: AuthenticatedUser = ShieldedDepends(lambda user: user),
        ):
            return user

        self.app = app
        self.client = TestClient(app)
        self.create_access_token = create_access_token

    def test_valid_login(self):
        """Test valid login and token generation"""
        response = self.client.post(
            "/token", data={"username": "johndoe", "password": "password123"}
        )
        assert response.status_code == 200
        assert "access_token" in response.json()
        assert response.json()["token_type"] == "bearer"

    def test_invalid_login(self):
        """Test invalid login"""
        response = self.client.post(
            "/token", data={"username": "johndoe", "password": "wrongpassword"}
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "Incorrect username or password"

    def test_valid_access(self):
        """Test accessing protected endpoint with valid token"""
        # Get token first
        token_response = self.client.post(
            "/token", data={"username": "johndoe", "password": "password123"}
        )
        token = token_response.json()["access_token"]

        # Use token to access endpoint
        response = self.client.get(
            "/users/me", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        assert response.json()["username"] == "johndoe"

    def test_invalid_token_access(self):
        """Test accessing protected endpoint with invalid token"""
        response = self.client.get(
            "/users/me", headers={"Authorization": "Bearer invalid.token.here"}
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "Could not validate credentials"

    def test_inactive_user(self):
        """Test accessing protected endpoint with inactive user"""
        # Create token for inactive user
        token = self.create_access_token(data={"sub": "inactive"})

        # Try to access endpoint
        response = self.client.get(
            "/users/me", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 400
        assert response.json()["detail"] == "Inactive user"


class TestOAuth2Authentication:
    """Tests for the OAuth2 Authentication with Scopes pattern from authentication-patterns.md"""

    def setup_method(self):
        """Setup the FastAPI app for each test"""
        app = FastAPI()

        # OAuth2 and password hashing setup
        oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
        pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

        # Secret key for JWT signing
        SECRET_KEY = "your-secret-key"
        ALGORITHM = "HS256"
        ACCESS_TOKEN_EXPIRE_MINUTES = 30

        # Define user models
        class Token(BaseModel := pytest.importorskip("pydantic").BaseModel):
            access_token: str
            token_type: str

        class TokenData(BaseModel):
            username: str
            scopes: List[str] = []

        class User(BaseModel):
            username: str
            email: Optional[str] = None
            full_name: Optional[str] = None
            scopes: List[str] = []

        # Define an authenticated user type
        AuthenticatedUser = NewType("AuthenticatedUser", User)

        # Mock user database with hashed passwords and scopes
        USER_DB = {
            "johndoe": {
                "username": "johndoe",
                "email": "johndoe@example.com",
                "full_name": "John Doe",
                "hashed_password": pwd_context.hash("password123"),
                "scopes": ["read:profile", "read:items", "write:items"],
            },
            "alice": {
                "username": "alice",
                "email": "alice@example.com",
                "full_name": "Alice Smith",
                "hashed_password": pwd_context.hash("alicepass"),
                "scopes": ["read:profile", "read:items"],
            },
        }

        # Verify password
        def verify_password(plain_password, hashed_password):
            return pwd_context.verify(plain_password, hashed_password)

        # Function to create access token
        def create_access_token(data: dict, expires_delta: timedelta = None):
            to_encode = data.copy()
            expire = datetime.utcnow() + (
                expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            )
            to_encode.update({"exp": expire})
            encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
            return encoded_jwt

        # Shield to validate JWT and authenticate user with scope checking
        def authenticate_with_scopes(required_scopes: List[str] = []):
            @shield
            def inner_auth_shield(token: str = Depends(oauth2_scheme)):
                credentials_exception = HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Could not validate credentials",
                    headers={"WWW-Authenticate": "Bearer"},
                )

                try:
                    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
                    username: str = payload.get("sub")
                    token_scopes: List[str] = payload.get("scopes", [])

                    if username is None:
                        raise credentials_exception

                    token_data = TokenData(username=username, scopes=token_scopes)

                    user_data = USER_DB.get(token_data.username)
                    if not user_data:
                        raise credentials_exception

                    user = User(
                        username=user_data["username"],
                        email=user_data["email"],
                        full_name=user_data["full_name"],
                        scopes=token_data.scopes,
                    )

                    # Check if user has any of the required scopes
                    for scope in required_scopes:
                        if scope in user.scopes:
                            return user

                    # If we reach here, the user doesn't have the required scopes
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Not enough permissions. Required scope: {required_scopes}",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
                except jwt.PyJWTError:
                    raise credentials_exception

            return inner_auth_shield

        # Function to authenticate user and generate token
        @app.post("/token", response_model=Token)
        def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
            user = USER_DB.get(form_data.username)
            if not user or not verify_password(
                form_data.password, user["hashed_password"]
            ):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Incorrect username or password",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            # Filter requested scopes against available scopes
            scopes = [scope for scope in form_data.scopes if scope in user["scopes"]]
            token_data = {"sub": user["username"], "scopes": scopes}

            access_token = create_access_token(data=token_data)

            return {"access_token": access_token, "token_type": "bearer"}

        # Use the shield in endpoints with different scope requirements
        @app.get("/users/me")
        @authenticate_with_scopes(required_scopes=["read:profile"])
        def get_current_user(user=ShieldedDepends(lambda user: user)):
            return user

        @app.get("/items")
        @authenticate_with_scopes(required_scopes=["read:items"])
        def get_items():
            return {
                "items": [{"item_id": 1, "name": "Foo"}, {"item_id": 2, "name": "Bar"}]
            }

        @app.post("/items")
        @authenticate_with_scopes(required_scopes=["write:items"])
        def create_item(item: Dict):
            return {"item_id": 3, **item}

        self.app = app
        self.client = TestClient(app)
        self.create_access_token = create_access_token

    def test_login_with_scopes(self):
        """Test login with specific scopes"""
        response = self.client.post(
            "/token",
            data={
                "username": "johndoe",
                "password": "password123",
                "scope": "read:profile read:items",
            },
        )
        assert response.status_code == 200
        assert "access_token" in response.json()

        # Verify token by using it
        token = response.json()["access_token"]
        profile_response = self.client.get(
            "/users/me", headers={"Authorization": f"Bearer {token}"}
        )
        assert profile_response.status_code == 200

    def test_access_with_correct_scope(self):
        """Test accessing endpoint with correct scope"""
        # Create token with read:items scope
        token = self.create_access_token(
            data={"sub": "alice", "scopes": ["read:items"]}
        )

        # Use token to access items endpoint
        response = self.client.get(
            "/items", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        assert "items" in response.json()

    def test_access_without_required_scope(self):
        """Test accessing endpoint without required scope"""
        # Create token with only read:profile scope
        token = self.create_access_token(
            data={"sub": "alice", "scopes": ["read:profile"]}
        )

        # Try to access items endpoint
        response = self.client.get(
            "/items", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 403
        assert "Not enough permissions" in response.json()["detail"]

    def test_write_access_with_read_only_user(self):
        """Test write access with read-only user"""
        # Create token for alice (who has only read scopes)
        token = self.create_access_token(
            data={"sub": "alice", "scopes": ["read:profile", "read:items"]}
        )

        # Try to create an item
        response = self.client.post(
            "/items",
            json={"name": "New Item"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 403
        assert "Not enough permissions" in response.json()["detail"]

    def test_write_access_with_write_permission(self):
        """Test write access with user having write permission"""
        # Create token for johndoe (who has write:items scope)
        token = self.create_access_token(
            data={"sub": "johndoe", "scopes": ["write:items"]}
        )

        # Create an item
        response = self.client.post(
            "/items",
            json={"name": "New Item"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        assert response.json()["name"] == "New Item"


class TestFlexibleAuthentication:
    """Tests for the Flexible Authentication pattern from authentication-patterns.md"""

    def setup_method(self):
        """Setup the FastAPI app for each test"""
        Cookie = pytest.importorskip("fastapi").Cookie
        Header = pytest.importorskip("fastapi").Header

        app = FastAPI()

        # OAuth2 setup
        oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)

        # Define user models
        class User(BaseModel := pytest.importorskip("pydantic").BaseModel):
            username: str
            email: Optional[str] = None
            auth_method: str

        # Define an authenticated user type
        AuthenticatedUser = NewType("AuthenticatedUser", User)

        # Mock functions for different auth methods
        async def validate_jwt(token: str) -> Optional[User]:
            # In a real app, validate the JWT
            if token == "valid-jwt":
                return User(
                    username="jwt-user", email="jwt@example.com", auth_method="jwt"
                )
            return None

        async def validate_api_key(api_key: str) -> Optional[User]:
            # In a real app, validate the API key
            if api_key == "valid-api-key":
                return User(
                    username="api-key-user",
                    email="apikey@example.com",
                    auth_method="api_key",
                )
            return None

        async def validate_session_cookie(session_id: str) -> Optional[User]:
            # In a real app, validate the session
            if session_id == "valid-session":
                return User(
                    username="cookie-user",
                    email="cookie@example.com",
                    auth_method="cookie",
                )
            return None

        # Shield for flexible authentication
        @shield
        async def authenticate(
            token: Optional[str] = Depends(oauth2_scheme),
            x_api_key: Optional[str] = Header(None),
            session: Optional[str] = Cookie(None),
        ) -> AuthenticatedUser:
            # Try JWT authentication
            if token:
                user = await validate_jwt(token)
                if user:
                    return AuthenticatedUser(user)

            # Try API key authentication
            if x_api_key:
                user = await validate_api_key(x_api_key)
                if user:
                    return AuthenticatedUser(user)

            # Try session cookie authentication
            if session:
                user = await validate_session_cookie(session)
                if user:
                    return AuthenticatedUser(user)

            # If no authentication method succeeded
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Use the shield in an endpoint
        @app.get("/protected")
        @authenticate
        async def protected_route(
            user: AuthenticatedUser = ShieldedDepends(lambda user: user),
        ):
            return {
                "message": f"Hello {user.username}! You are authenticated via {user.auth_method}",
                "user": user,
            }

        self.app = app
        self.client = TestClient(app)

    def test_jwt_authentication(self):
        """Test JWT authentication"""
        response = self.client.get(
            "/protected", headers={"Authorization": "Bearer valid-jwt"}
        )
        assert response.status_code == 200
        assert response.json()["user"]["auth_method"] == "jwt"

    def test_api_key_authentication(self):
        """Test API key authentication"""
        response = self.client.get("/protected", headers={"x-api-key": "valid-api-key"})
        assert response.status_code == 200
        assert response.json()["user"]["auth_method"] == "api_key"

    def test_cookie_authentication(self):
        """Test cookie authentication"""
        response = self.client.get("/protected", cookies={"session": "valid-session"})
        assert response.status_code == 200
        assert response.json()["user"]["auth_method"] == "cookie"

    def test_invalid_credentials(self):
        """Test with invalid credentials for all methods"""
        response = self.client.get(
            "/protected",
            headers={
                "Authorization": "Bearer invalid-jwt",
                "x-api-key": "invalid-api-key",
            },
            cookies={"session": "invalid-session"},
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid authentication credentials"

    def test_authentication_priority(self):
        """Test authentication priority (JWT > API Key > Cookie)"""
        # Provide all three authentication methods, JWT should be used
        response = self.client.get(
            "/protected",
            headers={"Authorization": "Bearer valid-jwt", "x-api-key": "valid-api-key"},
            cookies={"session": "valid-session"},
        )
        assert response.status_code == 200
        assert response.json()["user"]["auth_method"] == "jwt"

        # Invalid JWT but valid API key, should use API key
        response = self.client.get(
            "/protected",
            headers={
                "Authorization": "Bearer invalid-jwt",
                "x-api-key": "valid-api-key",
            },
            cookies={"session": "valid-session"},
        )
        assert response.status_code == 200
        assert response.json()["user"]["auth_method"] == "api_key"
