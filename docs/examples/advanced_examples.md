# Advanced Examples

This section provides advanced examples of using FastAPI Shield for more complex security and validation requirements.

## Chained Shield Processing

Creating shields that work together and pass data between them:

```python
from fastapi import FastAPI, Header, HTTPException, status, Depends
from fastapi_shield import shield, ShieldedDepends
import jwt
from typing import Dict, Optional, List

app = FastAPI()

# Simulated JWT configuration
JWT_SECRET = "your-secret-key"
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
async def role_extraction_shield(payload = ShieldedDepends(jwt_auth_shield)) -> Optional[AuthData]:
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
            detail=f"Requires role: {role}"
        )
    )
    async def role_shield(auth_data: AuthData = ShieldedDepends(role_extraction_shield)) -> Optional[AuthData]:
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
            detail=f"Requires permission: {permission}"
        )
    )
    async def permission_shield(auth_data: AuthData = ShieldedDepends(role_extraction_shield)) -> Optional[AuthData]:
        if auth_data.has_permission(permission):
            return auth_data
        return None
        
    return permission_shield

# Endpoints with chained shield protection
@app.get("/user-profile")
@jwt_auth_shield
@role_extraction_shield
async def user_profile(auth_data: AuthData = ShieldedDepends(role_extraction_shield)):
    return {
        "user_id": auth_data.user_id,
        "roles": auth_data.roles,
        "permissions": auth_data.permissions
    }

@app.get("/admin-panel")
@jwt_auth_shield
@role_extraction_shield
@require_role("admin")
async def admin_panel(auth_data: AuthData = ShieldedDepends(require_role("admin"))):
    return {
        "message": "Welcome to admin panel",
        "user_id": auth_data.user_id
    }

@app.post("/user-management")
@jwt_auth_shield
@role_extraction_shield
@require_permission("manage_users")
async def user_management(auth_data: AuthData = ShieldedDepends(require_permission("manage_users"))):
    return {
        "message": "User management access granted",
        "user_id": auth_data.user_id
    }
```

## Dynamic Shield Configuration with Database

Loading shield configuration from a database:

```python
from fastapi import FastAPI, Depends, Header, HTTPException, status
from fastapi_shield import shield, ShieldedDepends
from sqlalchemy.orm import Session
import databases
import sqlalchemy
from pydantic import BaseModel
from typing import List, Optional

# Database setup (simplified example)
DATABASE_URL = "sqlite:///./shields.db"
database = databases.Database(DATABASE_URL)
metadata = sqlalchemy.MetaData()

# Define tables
api_keys = sqlalchemy.Table(
    "api_keys",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("key", sqlalchemy.String, unique=True),
    sqlalchemy.Column("user_id", sqlalchemy.Integer),
    sqlalchemy.Column("is_active", sqlalchemy.Boolean, default=True),
)

user_permissions = sqlalchemy.Table(
    "user_permissions",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("user_id", sqlalchemy.Integer),
    sqlalchemy.Column("permission", sqlalchemy.String),
)

# Models
class Permission(BaseModel):
    permission: str

class User(BaseModel):
    id: int
    permissions: List[Permission]

app = FastAPI()

# Database dependency
async def get_db():
    await database.connect()
    try:
        yield database
    finally:
        await database.disconnect()

@shield(name="Database Auth Shield")
async def db_auth_shield(api_key: str = Header(), db = Depends(get_db)):
    """Authenticate using API key from database"""
    query = api_keys.select().where(
        sqlalchemy.and_(
            api_keys.c.key == api_key,
            api_keys.c.is_active == True
        )
    )
    
    result = await db.fetch_one(query)
    if not result:
        return None
        
    return {"user_id": result["user_id"], "key": result["key"]}

@shield(name="Permission Shield")
async def permission_shield(auth_data = ShieldedDepends(db_auth_shield), db = Depends(get_db)):
    """Load user permissions from database"""
    if not auth_data:
        return None
        
    user_id = auth_data["user_id"]
    
    query = user_permissions.select().where(
        user_permissions.c.user_id == user_id
    )
    
    results = await db.fetch_all(query)
    
    permissions = [Permission(permission=row["permission"]) for row in results]
    
    return User(id=user_id, permissions=permissions)

def require_db_permission(required_permission: str):
    """Create a shield that requires a database-stored permission"""
    
    @shield(
        name=f"DB Permission Requirement ({required_permission})",
        exception_to_raise_if_fail=HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Requires permission: {required_permission}"
        )
    )
    async def permission_check(user: User = ShieldedDepends(permission_shield)):
        user_permissions = [p.permission for p in user.permissions]
        if required_permission in user_permissions:
            return user
        return None
        
    return permission_check

@app.get("/db-protected")
@db_auth_shield
@permission_shield
async def db_protected_endpoint(user: User = ShieldedDepends(permission_shield)):
    return {
        "message": "Access granted via database authentication",
        "user_id": user.id,
        "permissions": [p.permission for p in user.permissions]
    }

@app.get("/admin-access")
@db_auth_shield
@permission_shield
@require_db_permission("admin_access")
async def admin_access_endpoint(user: User = ShieldedDepends(require_db_permission("admin_access"))):
    return {
        "message": "Admin access granted",
        "user_id": user.id
    }
```

## OAuth2 Integration

Integrating FastAPI Shield with OAuth2 authentication:

```python
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi_shield import shield, ShieldedDepends
from pydantic import BaseModel
from typing import Dict, Optional
import jwt
from datetime import datetime, timedelta

# OAuth2 configuration
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Mock user database
USERS_DB = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "john@example.com",
        "hashed_password": "fakehashedsecret",
        "roles": ["user"]
    },
    "alice": {
        "username": "alice",
        "full_name": "Alice Smith",
        "email": "alice@example.com",
        "hashed_password": "fakehashedsecret2",
        "roles": ["user", "admin"]
    }
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

app = FastAPI()

# Helper functions
def verify_password(plain_password, hashed_password):
    """Verify password (simplified for example)"""
    return plain_password + "notreallyhashed" == hashed_password

def get_user(db, username: str):
    """Get user from database"""
    if username in db:
        user_dict = db[username]
        return User(**user_dict)
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
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """OAuth2 token endpoint"""
    user = authenticate_user(USERS_DB, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "roles": user.roles},
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@shield(name="OAuth2 Shield")
async def oauth2_shield(token: str = Depends(oauth2_scheme)):
    """Shield that validates OAuth2 tokens"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
        token_data = TokenData(username=username, roles=payload.get("roles", []))
    except Exception:
        return None
    
    user = get_user(USERS_DB, username=token_data.username)
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
            detail=f"Role {role} required"
        )
    )
    async def role_check(oauth_data = ShieldedDepends(oauth2_shield)):
        token_data = oauth_data["token_data"]
        if role in token_data.roles:
            return oauth_data
        return None
    
    return role_check

@app.get("/users/me")
@oauth2_shield
async def read_users_me(oauth_data = ShieldedDepends(oauth2_shield)):
    """Get current user information"""
    user = oauth_data["user"]
    return user

@app.get("/admin/settings")
@oauth2_shield
@require_oauth2_role("admin")
async def admin_settings(oauth_data = ShieldedDepends(require_oauth2_role("admin"))):
    """Admin-only endpoint"""
    return {
        "message": "Admin settings",
        "user": oauth_data["user"].username
    }
```

These advanced examples demonstrate how to integrate FastAPI Shield with various authentication systems and create complex authorization flows. 