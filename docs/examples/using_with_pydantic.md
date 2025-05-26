<!--Examples tested-->

# Using with Pydantic

This section provides examples of how to integrate FastAPI Shield with Pydantic for advanced validation and type checking.

## Basic Integration

Using FastAPI Shield with Pydantic models for request validation:

```python
from fastapi import FastAPI, Depends, HTTPException, status, Body
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
@shield(
    name="User Validator",
    exception_to_raise_if_fail=HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="User validation failed"
    )
)
def validate_user_shield(user: UserCreate = Body()):
    """
    Shield that uses Pydantic for validation.
    By the time this shield runs, FastAPI has already validated the user model.
    We can add additional custom validation logic here.
    """
    # Check for reserved usernames
    reserved_usernames = ["admin", "system", "root"]
    if user.username.lower() in reserved_usernames:
        return None
    
    # Check for company email domain requirement
    if not user.email.endswith("@company.com"):
        return None
    
    # Return the validated user
    return user

# Endpoint with Pydantic and Shield validation
@app.post("/users", response_model=User)
@validate_user_shield
async def create_user(validated_user: UserCreate = ShieldedDepends(lambda user: user)):
    """Create a new user with validated data"""
    # In a real app, you would save the user to a database
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
from fastapi import FastAPI, Depends, HTTPException, status, Body
from fastapi_shield import shield, ShieldedDepends
from pydantic import BaseModel, Field, validator, root_validator, constr, conint, confloat
from typing import List, Dict, Optional, Any
from datetime import datetime
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
    expiry_year: conint(ge=2024)
    
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
def validate_order_shield(order: Order = Body()):
    """
    Shield that validates orders beyond Pydantic's built-in validation.
    This can include business logic checks that are more complex.
    """
    # Check if order has more than 10 items
    if len(order.items) > 10:
        return None
    
    # Calculate total order amount
    total = sum(item.total_price for item in order.items)
    
    # Check for high-value orders (require additional verification)
    if total > 1000:
        return None
    
    # Return the validated order
    return order

# Endpoint with complex Pydantic validation + Shield
@app.post("/orders")
@validate_order_shield
async def create_order(validated_order: Order = ShieldedDepends(lambda order: order)):
    """Create a new order with validated data"""
    # Calculate total for response
    total = sum(item.total_price for item in validated_order.items)
    
    return {
        "order_id": 12345,
        "status": "created",
        "total_amount": total,
        "message": "Order created successfully"
    }
```

## Model Transformation and Enrichment

Using shields to transform and enrich Pydantic models:

```python
from fastapi import FastAPI, Body, HTTPException, status
from fastapi_shield import shield, ShieldedDepends
from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any
from datetime import datetime
import hashlib

app = FastAPI()

# Input model
class ProductInput(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: str = Field(..., max_length=500)
    price: float = Field(..., gt=0)
    category: str
    tags: List[str] = []

# Enriched model
class Product(BaseModel):
    id: str
    name: str
    description: str
    price: float
    category: str
    tags: List[str]
    slug: str
    created_at: datetime
    search_keywords: List[str]

# Shield that transforms and enriches product data
@shield(
    name="Product Enricher",
    exception_to_raise_if_fail=HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Product enrichment failed"
    )
)
def enrich_product_shield(product_input: ProductInput = Body()):
    """Transform input into enriched product model"""
    
    # Generate unique ID
    product_id = hashlib.md5(
        f"{product_input.name}{datetime.now().isoformat()}".encode()
    ).hexdigest()[:12]
    
    # Generate slug
    slug = product_input.name.lower().replace(" ", "-").replace("_", "-")
    slug = "".join(c for c in slug if c.isalnum() or c == "-")
    
    # Generate search keywords
    keywords = [
        product_input.name.lower(),
        product_input.category.lower(),
        *[tag.lower() for tag in product_input.tags],
        *product_input.description.lower().split()[:5]  # First 5 words
    ]
    keywords = list(set(keywords))  # Remove duplicates
    
    # Create enriched product
    enriched_product = Product(
        id=product_id,
        name=product_input.name,
        description=product_input.description,
        price=product_input.price,
        category=product_input.category,
        tags=product_input.tags,
        slug=slug,
        created_at=datetime.now(),
        search_keywords=keywords
    )
    
    return enriched_product

@app.post("/products", response_model=Product)
@enrich_product_shield
async def create_product(product: Product = ShieldedDepends(lambda p: p)):
    """Create a new product with enriched data"""
    return product
```

## Validation with External Dependencies

Using shields with Pydantic models and external validation:

```python
from fastapi import FastAPI, Body, HTTPException, status, Depends
from fastapi_shield import shield, ShieldedDepends
from pydantic import BaseModel, EmailStr, validator
from typing import Optional, Dict, Any
import asyncio

app = FastAPI()

# Mock external services
class UserService:
    @staticmethod
    async def check_username_exists(username: str) -> bool:
        """Simulate checking if username exists"""
        await asyncio.sleep(0.1)  # Simulate API call
        return username in ["admin", "test", "user"]
    
    @staticmethod
    async def check_email_exists(email: str) -> bool:
        """Simulate checking if email exists"""
        await asyncio.sleep(0.1)  # Simulate API call
        return email in ["admin@example.com", "test@example.com"]

# Dependency to get user service
def get_user_service() -> UserService:
    return UserService()

class UserRegistration(BaseModel):
    username: str = Field(..., min_length=3, max_length=20)
    email: EmailStr
    password: str = Field(..., min_length=8)
    full_name: Optional[str] = None
    
    @validator("username")
    def validate_username_format(cls, v):
        """Validate username format"""
        if not v.isalnum():
            raise ValueError("Username must be alphanumeric")
        return v

# Shield with external validation
@shield(
    name="Registration Validator",
    exception_to_raise_if_fail=HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Registration validation failed"
    )
)
async def validate_registration_shield(
    registration: UserRegistration = Body(),
    user_service: UserService = Depends(get_user_service)
):
    """Validate registration with external checks"""
    
    # Check if username already exists
    if await user_service.check_username_exists(registration.username):
        return None
    
    # Check if email already exists
    if await user_service.check_email_exists(registration.email):
        return None
    
    return registration

@app.post("/register")
@validate_registration_shield
async def register_user(
    validated_registration: UserRegistration = ShieldedDepends(lambda r: r)
):
    """Register a new user"""
    return {
        "message": "User registered successfully",
        "username": validated_registration.username,
        "email": validated_registration.email
    }
```

## Multiple Shield Composition

Combining multiple shields for comprehensive validation:

```python
from fastapi import FastAPI, Body, Header, HTTPException, status
from fastapi_shield import shield, ShieldedDepends
from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any
import re

app = FastAPI()

# Models
class ContentInput(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    body: str = Field(..., min_length=10)
    tags: List[str] = []
    category: str

class AuthData(BaseModel):
    user_id: int
    username: str
    roles: List[str]

# Authentication shield
@shield(
    name="Auth Shield",
    exception_to_raise_if_fail=HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required"
    )
)
def auth_shield(authorization: str = Header(None)):
    """Validate authorization header"""
    if not authorization or not authorization.startswith("Bearer "):
        return None
    
    # Mock token validation
    token = authorization.replace("Bearer ", "")
    if token == "valid_token":
        return AuthData(
            user_id=1,
            username="testuser",
            roles=["user", "content_creator"]
        )
    return None

# Content validation shield
@shield(
    name="Content Validator",
    exception_to_raise_if_fail=HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Content validation failed"
    )
)
def validate_content_shield(content: ContentInput = Body()):
    """Validate content input"""
    
    # Check for prohibited content
    prohibited_words = ["spam", "scam", "fake"]
    content_text = f"{content.title} {content.body}".lower()
    
    if any(word in content_text for word in prohibited_words):
        return None
    
    # Validate category
    allowed_categories = ["tech", "science", "news", "entertainment"]
    if content.category not in allowed_categories:
        return None
    
    return content

# Permission shield
@shield(
    name="Permission Shield",
    exception_to_raise_if_fail=HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Insufficient permissions"
    )
)
def permission_shield(auth_data: AuthData = ShieldedDepends(lambda auth: auth)):
    """Check if user has content creation permissions"""
    if "content_creator" in auth_data.roles:
        return auth_data
    return None

# Endpoint with multiple shields
@app.post("/content")
@auth_shield
@validate_content_shield
@permission_shield
async def create_content(
    content: ContentInput = ShieldedDepends(lambda content: content),
    user: AuthData = ShieldedDepends(lambda auth: auth)
):
    """Create new content with full validation"""
    return {
        "message": "Content created successfully",
        "content_id": 12345,
        "title": content.title,
        "author": user.username
    }
```

## Form Data Validation

Using shields with Pydantic models for form data:

```python
from fastapi import FastAPI, Form, HTTPException, status
from fastapi_shield import shield, ShieldedDepends
from pydantic import BaseModel, EmailStr, validator
from typing import Optional
import re

app = FastAPI()

class ContactForm(BaseModel):
    name: str
    email: EmailStr
    subject: str
    message: str
    phone: Optional[str] = None
    
    @validator("name")
    def validate_name(cls, v):
        """Validate name format"""
        if len(v.strip()) < 2:
            raise ValueError("Name must be at least 2 characters")
        return v.strip()
    
    @validator("message")
    def validate_message(cls, v):
        """Validate message content"""
        if len(v.strip()) < 10:
            raise ValueError("Message must be at least 10 characters")
        return v.strip()

# Shield for form validation
@shield(
    name="Contact Form Validator",
    exception_to_raise_if_fail=HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Form validation failed"
    )
)
def validate_contact_form_shield(
    name: str = Form(...),
    email: str = Form(...),
    subject: str = Form(...),
    message: str = Form(...),
    phone: Optional[str] = Form(None)
):
    """Validate contact form data"""
    
    # Create Pydantic model from form data
    try:
        form_data = ContactForm(
            name=name,
            email=email,
            subject=subject,
            message=message,
            phone=phone
        )
    except ValueError:
        return None
    
    # Additional validation
    if phone and not re.match(r'^\+?[\d\s\-\(\)]{8,20}$', phone):
        return None
    
    return form_data

@app.post("/contact")
@validate_contact_form_shield
async def submit_contact_form(
    form_data: ContactForm = ShieldedDepends(lambda form: form)
):
    """Submit contact form"""
    return {
        "message": "Contact form submitted successfully",
        "reference_id": "CF12345"
    }
```

## Key Features

### Shield Ordering
Shields are applied in **reverse order** of decoration. In this example:
```python
@app.post("/content")
@auth_shield          # Applied 3rd
@validate_content_shield  # Applied 2nd  
@permission_shield    # Applied 1st
```

The execution order is: `permission_shield` → `validate_content_shield` → `auth_shield`

### ShieldedDepends Pattern
Use `ShieldedDepends(lambda x: x)` to access shield return values in endpoints:
```python
async def endpoint(validated_data = ShieldedDepends(lambda data: data)):
    # validated_data contains the return value from the shield
```

### Error Handling
Shields return `None` to block requests or the validated data to allow them. Use `exception_to_raise_if_fail` for custom error responses.

### Pydantic Integration
- Shields work seamlessly with Pydantic models
- FastAPI validates Pydantic models before shields run
- Shields can add business logic validation on top of Pydantic validation
- Use `Body()`, `Form()`, or other FastAPI parameter types with Pydantic models

### Best Practices
1. Keep shields focused on single responsibilities
2. Use Pydantic for data structure validation
3. Use shields for business logic validation
4. Combine multiple shields for comprehensive validation
5. Return validated models from shields for type safety 