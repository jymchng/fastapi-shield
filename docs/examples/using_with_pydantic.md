# Using with Pydantic

This section provides examples of how to integrate FastAPI Shield with Pydantic for advanced validation and type checking.

## Basic Integration

Using FastAPI Shield with Pydantic models for request validation:

```python
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi_shield import shield, ShieldedDepends
from pydantic import BaseModel, Field, EmailStr, validator
from typing import List, Optional

app = FastAPI()

# Pydantic models
class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    full_name: Optional[str] = None

class UserCreate(UserBase):
    password: str = Field(..., min_length=8)
    
    @validator("password")
    def password_strength(cls, v):
        """Validate password strength"""
        if not any(char.isdigit() for char in v):
            raise ValueError("Password must contain at least one digit")
        if not any(char.isupper() for char in v):
            raise ValueError("Password must contain at least one uppercase letter")
        return v

class User(UserBase):
    id: int
    is_active: bool = True
    
    class Config:
        orm_mode = True

# Shield that validates user data using Pydantic
@shield(name="User Validator")
def validate_user_shield(user: UserCreate = Depends()):
    """
    Shield that uses Pydantic for validation.
    By the time this shield runs, FastAPI has already validated the user model.
    We can add additional custom validation logic here.
    """
    # Check for reserved usernames
    reserved_usernames = ["admin", "system", "root"]
    if user.username.lower() in reserved_usernames:
        return None
    
    # Check for company email domain
    if user.email.endswith("@example.com"):
        # Allow company emails to proceed
        return user
    
    # Allow all valid users to proceed
    return user

# Endpoint with Pydantic and Shield validation
@app.post("/users", response_model=User)
@validate_user_shield
async def create_user(validated_user: UserCreate = ShieldedDepends(lambda user: user)):
    """Create a new user with validated data"""
    # In a real app, you would save the user to a database
    # This is simplified for the example
    new_user = User(
        id=1,
        username=validated_user.username,
        email=validated_user.email,
        full_name=validated_user.full_name
    )
    return new_user
```

## Advanced Schema Validation

Using FastAPI Shield with complex Pydantic models and validators:

```python
from fastapi import FastAPI, Depends, HTTPException, status, Query
from fastapi_shield import shield, ShieldedDepends
from pydantic import BaseModel, Field, validator, root_validator, constr, conint, confloat
from typing import List, Dict, Optional, Any
from datetime import datetime, date
import re

app = FastAPI()

# Complex Pydantic models
class Address(BaseModel):
    street: str
    city: str
    state: str
    zip_code: constr(regex=r'^\d{5}(-\d{4})?$')
    country: str

class PaymentMethod(BaseModel):
    card_type: str
    last_four: constr(regex=r'^\d{4}$')
    expiry_month: conint(ge=1, le=12)
    expiry_year: conint(ge=2023)
    
    @root_validator
    def check_expiry(cls, values):
        """Check if card is expired"""
        month = values.get('expiry_month')
        year = values.get('expiry_year')
        
        if month and year:
            current_year = datetime.now().year
            current_month = datetime.now().month
            
            if (year < current_year) or (year == current_year and month < current_month):
                raise ValueError("Card has expired")
                
        return values

class OrderItem(BaseModel):
    product_id: int
    quantity: conint(gt=0)
    unit_price: confloat(gt=0)
    
    @property
    def total_price(self) -> float:
        return self.quantity * self.unit_price

class Order(BaseModel):
    user_id: int
    items: List[OrderItem] = Field(..., min_items=1)
    shipping_address: Address
    billing_address: Optional[Address] = None
    payment_method: PaymentMethod
    coupon_code: Optional[str] = None
    
    @validator("coupon_code")
    def validate_coupon_format(cls, v):
        """Validate coupon code format if provided"""
        if v is not None and not re.match(r'^[A-Z0-9]{8,12}$', v):
            raise ValueError("Invalid coupon code format")
        return v
    
    @root_validator
    def set_billing_same_as_shipping(cls, values):
        """If billing address is not provided, use shipping address"""
        if values.get('billing_address') is None:
            values['billing_address'] = values.get('shipping_address')
        return values

# Shield that validates orders
@shield(
    name="Order Validator",
    exception_to_raise_if_fail=HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Invalid order data"
    )
)
async def validate_order_shield(order: Order = Depends()):
    """
    Shield that validates orders beyond Pydantic's built-in validation.
    This can include business logic checks that are more complex.
    """
    # Check if order has more than 10 items
    if len(order.items) > 10:
        return None
    
    # Calculate total order amount
    total = sum(item.total_price for item in order.items)
    
    # Check for high-value orders
    if total > 1000:
        # For high-value orders, we could require additional verification
        # This is just an example, return None to block the order
        # In a real app, you might flag it for review instead
        pass
    
    # Attach calculated total to the order data
    order_data = order.dict()
    order_data["total_amount"] = total
    
    return order_data

# Endpoint with complex Pydantic validation + Shield
@app.post("/orders")
@validate_order_shield
async def create_order(order_data: Dict[str, Any] = ShieldedDepends(lambda order: order)):
    """Create a new order with validated data"""
    # In a real app, you would save the order to a database
    # This is simplified for the example
    return {
        "order_id": 12345,
        "status": "created",
        "total_amount": order_data["total_amount"],
        "message": "Order created successfully"
    }
```

## Pydantic Models as Shield Return Values

Using Pydantic models as shield return values for better type safety:

```python
from fastapi import FastAPI, Depends, Header, HTTPException, status
from fastapi_shield import shield, ShieldedDepends
from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any
import jwt
from datetime import datetime, timedelta

app = FastAPI()

# JWT configuration
JWT_SECRET = "your-secret-key"
JWT_ALGORITHM = "HS256"

# Pydantic models
class TokenData(BaseModel):
    user_id: int
    username: str
    email: Optional[str] = None
    roles: List[str] = []
    permissions: List[str] = []
    exp: datetime
    
    @validator("exp")
    def check_expiration(cls, v):
        """Check if token is expired"""
        if v < datetime.utcnow():
            raise ValueError("Token has expired")
        return v

class AuthenticatedUser(BaseModel):
    id: int
    username: str
    email: Optional[str] = None
    roles: List[str]
    permissions: List[str]
    token_data: TokenData
    
    def has_role(self, role: str) -> bool:
        """Check if user has a specific role"""
        return role in self.roles
    
    def has_permission(self, permission: str) -> bool:
        """Check if user has a specific permission"""
        return permission in self.permissions

# Shield that decodes JWT and returns a Pydantic model
@shield(
    name="JWT Authentication",
    exception_to_raise_if_fail=HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication token",
        headers={"WWW-Authenticate": "Bearer"}
    )
)
async def jwt_auth_shield(authorization: str = Header(None)) -> Optional[AuthenticatedUser]:
    """Decode JWT token and return an AuthenticatedUser instance"""
    if not authorization:
        return None
    
    if not authorization.startswith("Bearer "):
        return None
    
    token = authorization.replace("Bearer ", "")
    
    try:
        # Decode the token
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        
        # Create a TokenData instance
        token_data = TokenData(
            user_id=payload["sub"],
            username=payload["username"],
            email=payload.get("email"),
            roles=payload.get("roles", []),
            permissions=payload.get("permissions", []),
            exp=datetime.fromtimestamp(payload["exp"])
        )
        
        # Create an AuthenticatedUser instance
        authenticated_user = AuthenticatedUser(
            id=token_data.user_id,
            username=token_data.username,
            email=token_data.email,
            roles=token_data.roles,
            permissions=token_data.permissions,
            token_data=token_data
        )
        
        return authenticated_user
    except (jwt.PyJWTError, ValueError):
        return None

# Role-based shield using Pydantic model methods
def require_role(role: str):
    """Create a shield that requires a specific role"""
    
    @shield(
        name=f"Role Check ({role})",
        exception_to_raise_if_fail=HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role {role} required"
        )
    )
    async def role_shield(user: AuthenticatedUser = ShieldedDepends(lambda user: user)) -> Optional[AuthenticatedUser]:
        """Check if user has the required role"""
        if user.has_role(role):
            return user
        return None
        
    return role_shield

# Permission-based shield using Pydantic model methods
def require_permission(permission: str):
    """Create a shield that requires a specific permission"""
    
    @shield(
        name=f"Permission Check ({permission})",
        exception_to_raise_if_fail=HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission {permission} required"
        )
    )
    async def permission_shield(user: AuthenticatedUser = ShieldedDepends(lambda user: user)) -> Optional[AuthenticatedUser]:
        """Check if user has the required permission"""
        if user.has_permission(permission):
            return user
        return None
        
    return permission_shield

# API endpoints
@app.get("/users/me")
@jwt_auth_shield
async def get_current_user(user: AuthenticatedUser = ShieldedDepends(jwt_auth_shield)):
    """Get the current authenticated user"""
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "roles": user.roles,
        "permissions": user.permissions
    }

@app.get("/admin/users")
@jwt_auth_shield
@require_role("admin")
async def list_users(admin: AuthenticatedUser = ShieldedDepends(require_role("admin"))):
    """Admin endpoint to list all users"""
    # In a real app, you would query a database
    return {
        "message": f"Admin {admin.username} accessed user list",
        "users": [
            {"id": 1, "username": "user1"},
            {"id": 2, "username": "user2"}
        ]
    }

@app.post("/content")
@jwt_auth_shield
@require_permission("content:create")
async def create_content(
    content_data: Dict[str, Any],
    user: AuthenticatedUser = ShieldedDepends(require_permission("content:create"))
):
    """Create content (requires content:create permission)"""
    return {
        "message": f"Content created by {user.username}",
        "content_id": 12345
    }
```

These examples demonstrate how to leverage Pydantic's powerful validation capabilities in combination with FastAPI Shield for comprehensive input validation and type safety. 