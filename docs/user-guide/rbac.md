# Role-Based Access Control (RBAC) with FastAPI Shield

Role-Based Access Control (RBAC) is a common access control mechanism that restricts system access to authorized users based on their roles. FastAPI Shield makes implementing RBAC in your FastAPI applications straightforward and type-safe.

## Basic RBAC Implementation

Let's start with a basic RBAC implementation:

```python
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from typing import NewType, List, Optional, Dict
from fastapi_shield import shield
from pydantic import BaseModel
import jwt
from datetime import datetime, timedelta

app = FastAPI()

# JWT configuration
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# User and role models
class Role(BaseModel):
    name: str
    permissions: List[str]

class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None
    roles: List[str] = []

# Define an authenticated user type with role information
AuthenticatedUser = NewType("AuthenticatedUser", User)

# Mock database
roles_db = {
    "admin": Role(
        name="admin",
        permissions=["read:all", "write:all", "delete:all"]
    ),
    "editor": Role(
        name="editor",
        permissions=["read:all", "write:own"]
    ),
    "viewer": Role(
        name="viewer",
        permissions=["read:all"]
    )
}

users_db = {
    "admin_user": {
        "username": "admin_user",
        "email": "admin@example.com",
        "full_name": "Admin User",
        "disabled": False,
        "hashed_password": "fakehashedadmin",
        "roles": ["admin"]
    },
    "editor_user": {
        "username": "editor_user",
        "email": "editor@example.com",
        "full_name": "Editor User",
        "disabled": False,
        "hashed_password": "fakehashededitor",
        "roles": ["editor"]
    },
    "viewer_user": {
        "username": "viewer_user",
        "email": "viewer@example.com",
        "full_name": "Viewer User",
        "disabled": False,
        "hashed_password": "fakehashedviewer",
        "roles": ["viewer"]
    },
    "multi_role_user": {
        "username": "multi_role_user",
        "email": "multi@example.com",
        "full_name": "Multi-Role User",
        "disabled": False,
        "hashed_password": "fakehashedmulti",
        "roles": ["editor", "viewer"]
    }
}

# Authentication functions
def verify_password(plain_password: str, hashed_password: str) -> bool:
    # In a real app, use a proper password verification function
    return f"fakehashed{plain_password}" == hashed_password

def authenticate_user(username: str, password: str) -> Optional[User]:
    if username not in users_db:
        return None
    user_dict = users_db[username]
    if not verify_password(password, user_dict["hashed_password"]):
        return None
    return User(**{k: v for k, v in user_dict.items() if k != "hashed_password"})

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.post("/token")
async def login_for_access_token(username: str, password: str):
    user = authenticate_user(username, password)
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

@shield
async def get_current_user(token: str = Depends(oauth2_scheme)) -> AuthenticatedUser:
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
        roles: List[str] = payload.get("roles", [])
    except jwt.PyJWTError:
        raise credentials_exception
    
    if username not in users_db:
        raise credentials_exception
    
    user_dict = users_db[username]
    user = User(**{k: v for k, v in user_dict.items() if k != "hashed_password"})
    
    if user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    
    return AuthenticatedUser(user)

# RBAC Shield functions
@shield
def require_role(user: AuthenticatedUser, required_role: str) -> None:
    if required_role not in user.roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role {required_role} required"
        )

@shield
def require_any_role(user: AuthenticatedUser, required_roles: List[str]) -> None:
    if not any(role in user.roles for role in required_roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"One of these roles required: {', '.join(required_roles)}"
        )

@shield
def require_all_roles(user: AuthenticatedUser, required_roles: List[str]) -> None:
    if not all(role in user.roles for role in required_roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"All of these roles required: {', '.join(required_roles)}"
        )

@shield
def require_permission(user: AuthenticatedUser, required_permission: str) -> None:
    # Collect all permissions from all user roles
    user_permissions = []
    for role_name in user.roles:
        if role_name in roles_db:
            user_permissions.extend(roles_db[role_name].permissions)
    
    if required_permission not in user_permissions:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission {required_permission} required"
        )

# Protected routes using the RBAC shields
@app.get("/users/me")
async def read_users_me(current_user: AuthenticatedUser = Depends(get_current_user)):
    return current_user

@app.get("/admin-only")
async def admin_only(
    current_user: AuthenticatedUser = Depends(get_current_user),
    _: None = Depends(lambda user=Depends(get_current_user): require_role(user, "admin"))
):
    return {"message": "You have admin access"}

@app.get("/editors-or-admins")
async def editors_or_admins(
    current_user: AuthenticatedUser = Depends(get_current_user),
    _: None = Depends(lambda user=Depends(get_current_user): require_any_role(user, ["admin", "editor"]))
):
    return {"message": "You have editor or admin access"}

@app.get("/write-access")
async def write_access(
    current_user: AuthenticatedUser = Depends(get_current_user),
    _: None = Depends(lambda user=Depends(get_current_user): require_permission(user, "write:all"))
):
    return {"message": "You have write:all permission"}
```

## Advanced RBAC with Hierarchical Roles

Many systems require hierarchical roles, where higher-level roles inherit permissions from lower-level roles. Here's an implementation of hierarchical RBAC:

```python
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from typing import NewType, List, Dict, Optional, Set
from fastapi_shield import shield
from pydantic import BaseModel

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Role model with inheritance
class Role(BaseModel):
    name: str
    permissions: List[str]
    inherits: List[str] = []

# User model
class User(BaseModel):
    username: str
    email: str
    role_names: List[str]

# Define an authenticated user type
AuthenticatedUser = NewType("AuthenticatedUser", User)

# Mock role hierarchy
roles_db: Dict[str, Role] = {
    "super_admin": Role(
        name="super_admin",
        permissions=["manage:system"],
        inherits=["admin"]
    ),
    "admin": Role(
        name="admin",
        permissions=["manage:users"],
        inherits=["manager"]
    ),
    "manager": Role(
        name="manager",
        permissions=["approve:content"],
        inherits=["editor"]
    ),
    "editor": Role(
        name="editor",
        permissions=["create:content", "edit:content"],
        inherits=["viewer"]
    ),
    "viewer": Role(
        name="viewer",
        permissions=["view:content"]
    )
}

# Get all permissions for a role, including inherited permissions
def get_role_permissions(role_name: str, visited: Optional[Set[str]] = None) -> List[str]:
    if visited is None:
        visited = set()
    
    if role_name in visited:
        # Prevent circular dependencies
        return []
    
    visited.add(role_name)
    
    if role_name not in roles_db:
        return []
    
    role = roles_db[role_name]
    permissions = role.permissions.copy()
    
    for inherited_role in role.inherits:
        inherited_permissions = get_role_permissions(inherited_role, visited)
        permissions.extend(inherited_permissions)
    
    return list(set(permissions))  # Remove duplicates

# Get all effective roles for a user, including inherited roles
def get_effective_roles(role_names: List[str]) -> List[str]:
    effective_roles = set(role_names)
    
    for role_name in role_names:
        # Add inherited roles through a breadth-first search
        to_process = [role_name]
        visited = set()
        
        while to_process:
            current_role = to_process.pop(0)
            
            if current_role in visited:
                continue
            
            visited.add(current_role)
            effective_roles.add(current_role)
            
            if current_role in roles_db:
                for inherited_role in roles_db[current_role].inherits:
                    to_process.append(inherited_role)
    
    return list(effective_roles)

# Mock user database
users_db = {
    "super_admin_user": User(
        username="super_admin_user",
        email="super_admin@example.com",
        role_names=["super_admin"]
    ),
    "admin_user": User(
        username="admin_user",
        email="admin@example.com",
        role_names=["admin"]
    ),
    "editor_user": User(
        username="editor_user",
        email="editor@example.com",
        role_names=["editor"]
    ),
    "viewer_user": User(
        username="viewer_user",
        email="viewer@example.com",
        role_names=["viewer"]
    ),
    "custom_user": User(
        username="custom_user",
        email="custom@example.com",
        role_names=["viewer", "manager"]  # Custom combination of roles
    )
}

# Authenticate user (simplified for example)
@shield
async def get_current_user(token: str = Depends(oauth2_scheme)) -> AuthenticatedUser:
    # This is a simplified example, in a real app you would decode and validate the JWT
    if token not in users_db:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    user = users_db[token]
    return AuthenticatedUser(user)

# RBAC shield functions
@shield
def check_permission(user: AuthenticatedUser, required_permission: str) -> None:
    # Get all of the user's roles, including inherited roles
    effective_roles = get_effective_roles(user.role_names)
    
    # Get all permissions from all roles
    all_permissions = []
    for role_name in effective_roles:
        role_permissions = get_role_permissions(role_name)
        all_permissions.extend(role_permissions)
    
    # Check if the required permission is in the list
    if required_permission not in set(all_permissions):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission {required_permission} required"
        )

@shield
def check_role(user: AuthenticatedUser, required_role: str) -> None:
    effective_roles = get_effective_roles(user.role_names)
    
    if required_role not in effective_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role {required_role} required"
        )

# Protected routes
@app.get("/users/me")
async def read_users_me(current_user: AuthenticatedUser = Depends(get_current_user)):
    # Get expanded role information
    effective_roles = get_effective_roles(current_user.role_names)
    
    # Get all permissions
    all_permissions = []
    for role_name in effective_roles:
        role_permissions = get_role_permissions(role_name)
        all_permissions.extend(role_permissions)
    
    return {
        "username": current_user.username,
        "email": current_user.email,
        "assigned_roles": current_user.role_names,
        "effective_roles": effective_roles,
        "permissions": list(set(all_permissions))
    }

@app.get("/system-management")
async def system_management(
    current_user: AuthenticatedUser = Depends(get_current_user),
    _: None = Depends(lambda user=Depends(get_current_user): check_permission(user, "manage:system"))
):
    return {"message": "You can manage the system"}

@app.get("/content-editing")
async def content_editing(
    current_user: AuthenticatedUser = Depends(get_current_user),
    _: None = Depends(lambda user=Depends(get_current_user): check_permission(user, "edit:content"))
):
    return {"message": "You can edit content"}

@app.get("/admin-area")
async def admin_area(
    current_user: AuthenticatedUser = Depends(get_current_user),
    _: None = Depends(lambda user=Depends(get_current_user): check_role(user, "admin"))
):
    return {"message": "You have admin role"}
```

## Dynamic RBAC with Database-Backed Roles

For most real-world applications, you'll want to store roles and permissions in a database and allow for dynamic updates:

```python
from fastapi import FastAPI, Depends, HTTPException, status, Body
from fastapi.security import OAuth2PasswordBearer
from typing import NewType, List, Dict, Optional, Set
from fastapi_shield import shield
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, Integer, String, Table, ForeignKey, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session

app = FastAPI()

# Database setup
SQLALCHEMY_DATABASE_URL = "sqlite:///./rbac.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Association tables for many-to-many relationships
role_permissions = Table(
    "role_permissions",
    Base.metadata,
    Column("role_id", Integer, ForeignKey("roles.id")),
    Column("permission_id", Integer, ForeignKey("permissions.id"))
)

role_inheritance = Table(
    "role_inheritance",
    Base.metadata,
    Column("parent_role_id", Integer, ForeignKey("roles.id")),
    Column("child_role_id", Integer, ForeignKey("roles.id"))
)

user_roles = Table(
    "user_roles",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id")),
    Column("role_id", Integer, ForeignKey("roles.id"))
)

# ORM Models
class Permission(Base):
    __tablename__ = "permissions"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    description = Column(String, nullable=True)

class Role(Base):
    __tablename__ = "roles"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    description = Column(String, nullable=True)
    
    permissions = relationship("Permission", secondary=role_permissions)
    parent_roles = relationship(
        "Role", 
        secondary=role_inheritance,
        primaryjoin=id==role_inheritance.c.child_role_id,
        secondaryjoin=id==role_inheritance.c.parent_role_id,
        backref="child_roles"
    )

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    
    roles = relationship("Role", secondary=user_roles)

# Create the database tables
Base.metadata.create_all(bind=engine)

# Dependency to get the database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Pydantic models for API
class PermissionCreate(BaseModel):
    name: str
    description: Optional[str] = None

class PermissionRead(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    
    class Config:
        orm_mode = True

class RoleCreate(BaseModel):
    name: str
    description: Optional[str] = None
    permission_ids: List[int] = []
    parent_role_ids: List[int] = []

class RoleRead(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    permissions: List[PermissionRead] = []
    
    class Config:
        orm_mode = True

class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    role_ids: List[int] = []

class UserRead(BaseModel):
    id: int
    username: str
    email: str
    roles: List[RoleRead] = []
    
    class Config:
        orm_mode = True

class UserUpdate(BaseModel):
    role_ids: List[int]

# Define an authenticated user type
AuthenticatedUser = NewType("AuthenticatedUser", UserRead)

# Authentication functions
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@shield
async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> AuthenticatedUser:
    # In a real app, you would decode and validate a JWT
    # For this example, we're using the token as the username
    user = db.query(User).filter(User.username == token).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    
    # Convert ORM model to Pydantic model
    user_read = UserRead(
        id=user.id,
        username=user.username,
        email=user.email,
        roles=[
            RoleRead(
                id=role.id,
                name=role.name,
                description=role.description,
                permissions=[
                    PermissionRead(
                        id=perm.id,
                        name=perm.name,
                        description=perm.description
                    ) for perm in role.permissions
                ]
            ) for role in user.roles
        ]
    )
    
    return AuthenticatedUser(user_read)

# Get all roles for a user, including inherited roles
def get_all_roles(user_roles: List[Role], db: Session) -> Set[Role]:
    all_roles = set(user_roles)
    roles_to_process = list(user_roles)
    processed_roles = set()
    
    while roles_to_process:
        current_role = roles_to_process.pop(0)
        
        if current_role.id in processed_roles:
            continue
            
        processed_roles.add(current_role.id)
        all_roles.add(current_role)
        
        for parent_role in current_role.parent_roles:
            if parent_role.id not in processed_roles:
                roles_to_process.append(parent_role)
    
    return all_roles

# Get all permissions for a user from all their roles
def get_all_permissions(roles: List[Role]) -> Set[str]:
    all_permissions = set()
    
    for role in roles:
        for permission in role.permissions:
            all_permissions.add(permission.name)
    
    return all_permissions

# RBAC shield functions
@shield
def require_permission(
    permission_name: str,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> None:
    # Get all roles, including inherited roles
    all_roles = get_all_roles(
        [db.query(Role).get(role.id) for role in current_user.roles], 
        db
    )
    
    # Get all permissions from all roles
    all_permissions = get_all_permissions(all_roles)
    
    if permission_name not in all_permissions:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission {permission_name} required"
        )

# Routes for permission management
@app.post("/permissions/", response_model=PermissionRead)
def create_permission(
    permission: PermissionCreate,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(get_current_user),
    _: None = Depends(lambda: require_permission("manage:permissions"))
):
    db_permission = Permission(name=permission.name, description=permission.description)
    db.add(db_permission)
    db.commit()
    db.refresh(db_permission)
    return db_permission

@app.get("/permissions/", response_model=List[PermissionRead])
def read_permissions(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(get_current_user),
    _: None = Depends(lambda: require_permission("read:permissions"))
):
    permissions = db.query(Permission).offset(skip).limit(limit).all()
    return permissions

# Routes for role management
@app.post("/roles/", response_model=RoleRead)
def create_role(
    role: RoleCreate,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(get_current_user),
    _: None = Depends(lambda: require_permission("manage:roles"))
):
    db_role = Role(name=role.name, description=role.description)
    
    # Add permissions
    if role.permission_ids:
        db_role.permissions = db.query(Permission).filter(
            Permission.id.in_(role.permission_ids)).all()
    
    # Add parent roles
    if role.parent_role_ids:
        db_role.parent_roles = db.query(Role).filter(
            Role.id.in_(role.parent_role_ids)).all()
    
    db.add(db_role)
    db.commit()
    db.refresh(db_role)
    return db_role

@app.get("/roles/", response_model=List[RoleRead])
def read_roles(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(get_current_user),
    _: None = Depends(lambda: require_permission("read:roles"))
):
    roles = db.query(Role).offset(skip).limit(limit).all()
    return roles

# Routes for user management
@app.post("/users/", response_model=UserRead)
def create_user(
    user: UserCreate,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(get_current_user),
    _: None = Depends(lambda: require_permission("manage:users"))
):
    # In a real app, hash the password
    hashed_password = f"fakehashed{user.password}"
    
    db_user = User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password
    )
    
    # Add roles
    if user.role_ids:
        db_user.roles = db.query(Role).filter(Role.id.in_(user.role_ids)).all()
    
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.get("/users/", response_model=List[UserRead])
def read_users(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(get_current_user),
    _: None = Depends(lambda: require_permission("read:users"))
):
    users = db.query(User).offset(skip).limit(limit).all()
    return users

@app.put("/users/{user_id}/roles", response_model=UserRead)
def update_user_roles(
    user_id: int,
    user_update: UserUpdate,
    db: Session = Depends(get_db),
    current_user: AuthenticatedUser = Depends(get_current_user),
    _: None = Depends(lambda: require_permission("manage:users"))
):
    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Update roles
    db_user.roles = db.query(Role).filter(Role.id.in_(user_update.role_ids)).all()
    
    db.commit()
    db.refresh(db_user)
    return db_user

# User profile route - requires authentication but no specific permission
@app.get("/users/me", response_model=UserRead)
def read_users_me(current_user: AuthenticatedUser = Depends(get_current_user)):
    return current_user

# Protected route example
@app.get("/admin/dashboard")
def admin_dashboard(
    current_user: AuthenticatedUser = Depends(get_current_user),
    _: None = Depends(lambda: require_permission("access:admin_dashboard"))
):
    return {
        "message": "Welcome to the admin dashboard",
        "user": current_user.username
    }
```

## Attribute-Based Access Control (ABAC)

Sometimes RBAC isn't flexible enough, and you need to make access decisions based on user attributes, resource attributes, or even environmental conditions. FastAPI Shield makes it easy to implement Attribute-Based Access Control (ABAC):

```python
from fastapi import FastAPI, Depends, HTTPException, status, Query
from fastapi.security import OAuth2PasswordBearer
from typing import NewType, List, Dict, Optional, Any
from fastapi_shield import shield
from pydantic import BaseModel
from datetime import datetime, time

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# User model with attributes
class User(BaseModel):
    username: str
    department: str
    clearance_level: int  # 1-5, where 5 is highest
    is_contractor: bool
    joined_date: datetime

# Resource model with attributes
class Document(BaseModel):
    id: int
    title: str
    content: str
    classification_level: int  # 1-5, where 5 is highest
    department_restriction: Optional[str] = None
    created_at: datetime

# Define an authenticated user type
AuthenticatedUser = NewType("AuthenticatedUser", User)

# Mock data
users_db = {
    "alice": User(
        username="alice",
        department="engineering",
        clearance_level=4,
        is_contractor=False,
        joined_date=datetime(2018, 1, 1)
    ),
    "bob": User(
        username="bob",
        department="hr",
        clearance_level=3,
        is_contractor=False,
        joined_date=datetime(2019, 6, 15)
    ),
    "charlie": User(
        username="charlie",
        department="engineering",
        clearance_level=2,
        is_contractor=True,
        joined_date=datetime(2021, 3, 10)
    )
}

documents_db = {
    1: Document(
        id=1,
        title="Engineering Roadmap",
        content="Our engineering plans for the next year...",
        classification_level=2,
        department_restriction="engineering",
        created_at=datetime(2022, 1, 15)
    ),
    2: Document(
        id=2,
        title="Salary Guidelines",
        content="Salary ranges for different positions...",
        classification_level=3,
        department_restriction="hr",
        created_at=datetime(2022, 2, 10)
    ),
    3: Document(
        id=3,
        title="Company Overview",
        content="General information about the company...",
        classification_level=1,
        department_restriction=None,  # No department restriction
        created_at=datetime(2022, 3, 5)
    ),
    4: Document(
        id=4,
        title="Top Secret Project",
        content="Details about our most secret project...",
        classification_level=5,
        department_restriction="engineering",
        created_at=datetime(2022, 4, 20)
    )
}

# Authentication
@shield
async def get_current_user(token: str = Depends(oauth2_scheme)) -> AuthenticatedUser:
    if token not in users_db:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    return AuthenticatedUser(users_db[token])

# ABAC shield functions
@shield
def check_document_access(
    user: AuthenticatedUser,
    document: Document
) -> None:
    # Check clearance level
    if user.clearance_level < document.classification_level:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient clearance level"
        )
    
    # Check department restriction
    if (document.department_restriction and 
        document.department_restriction != user.department):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Document restricted to another department"
        )
    
    # Contractors can't access documents with classification level > 3
    if user.is_contractor and document.classification_level > 3:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Document not accessible to contractors"
        )
    
    # Check if the document is too recent for the user
    min_tenure_days = {
        1: 0,    # Level 1: No minimum tenure
        2: 30,   # Level 2: 30 days
        3: 90,   # Level 3: 90 days
        4: 180,  # Level 4: 180 days
        5: 365   # Level 5: 365 days
    }
    
    tenure_days = (datetime.now() - user.joined_date).days
    required_tenure = min_tenure_days.get(document.classification_level, 0)
    
    if tenure_days < required_tenure:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Minimum tenure of {required_tenure} days required"
        )

@shield
def check_time_restriction(
    start_time: time = time(9, 0),  # 9:00 AM
    end_time: time = time(17, 0)    # 5:00 PM
) -> None:
    """Check if the current time is within the allowed time range."""
    current_time = datetime.now().time()
    
    if not (start_time <= current_time <= end_time):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access only allowed between {start_time} and {end_time}"
        )

# Routes
@app.get("/documents/{document_id}")
async def read_document(
    document_id: int,
    current_user: AuthenticatedUser = Depends(get_current_user),
    _: None = Depends(check_time_restriction)
):
    if document_id not in documents_db:
        raise HTTPException(status_code=404, detail="Document not found")
    
    document = documents_db[document_id]
    
    # Check if user can access this specific document
    check_document_access(current_user, document)
    
    return document

@app.get("/documents")
async def list_documents(
    current_user: AuthenticatedUser = Depends(get_current_user),
    department: Optional[str] = Query(None),
    max_classification: Optional[int] = Query(None)
):
    # Filter documents based on query parameters and user attributes
    accessible_documents = []
    
    for doc in documents_db.values():
        try:
            # Check if user can access this document
            check_document_access(current_user, doc)
            
            # Apply additional filters from query parameters
            if department and doc.department_restriction != department:
                continue
                
            if max_classification and doc.classification_level > max_classification:
                continue
                
            # Document is accessible and matches filters
            accessible_documents.append(doc)
        except HTTPException:
            # User can't access this document, skip it
            continue
    
    return accessible_documents

@app.get("/users/me")
async def read_users_me(current_user: AuthenticatedUser = Depends(get_current_user)):
    return current_user
```

## Best Practices for RBAC with FastAPI Shield

1. **Define clear role hierarchies**: Design your role structure with clear inheritance patterns to simplify management.

2. **Use the principle of least privilege**: Assign users the minimum access rights they need to perform their functions.

3. **Separate authentication from authorization**: Keep the concerns of user identity verification and access control separate.

4. **Cache role and permission data**: For performance optimization, consider caching role and permission data, especially for hierarchical RBAC.

5. **Implement regular access reviews**: Regularly review user roles to ensure they still align with job functions.

6. **Maintain detailed access logs**: Log all access attempts, especially denied ones, for security auditing.

7. **Consider using dynamic RBAC**: For larger applications, store roles and permissions in a database for easier management.

8. **Combine RBAC with other access control models**: For complex scenarios, consider combining RBAC with attribute-based access control (ABAC).

9. **Keep the role structure simple**: Avoid creating too many roles and permissions, as this can become difficult to manage.

10. **Use meaningful naming conventions**: Choose descriptive names for roles and permissions to make them easier to understand and use.

By implementing these patterns with FastAPI Shield, you can create a robust and type-safe RBAC system for your FastAPI applications. 