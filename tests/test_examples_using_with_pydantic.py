import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI, Body, Header, Form, HTTPException, status, Depends
from fastapi_shield import shield, ShieldedDepends
from pydantic import (
    BaseModel,
    Field,
    field_validator,
    model_validator,
    conint,
    confloat,
)
from typing import List, Optional, Dict, Any, Annotated
from datetime import datetime
import hashlib
import asyncio
import re

# Try to import EmailStr, skip tests if not available
try:
    from pydantic import EmailStr

    EMAIL_VALIDATOR_AVAILABLE = True
except ImportError:
    EMAIL_VALIDATOR_AVAILABLE = False
    EmailStr = str  # Fallback to str

# Try to import constr with different patterns for Pydantic v1/v2 compatibility
try:
    from pydantic import constr

    # Test if it's Pydantic v2 style
    try:
        test_str = constr(pattern=r"^\d+$")
        PYDANTIC_V2 = True
    except TypeError:
        # Pydantic v1 style
        PYDANTIC_V2 = False
except ImportError:
    PYDANTIC_V2 = False
    constr = str


class TestBasicPydanticIntegration:
    """Tests for basic Pydantic integration with FastAPI Shield"""

    def setup_method(self):
        """Setup the FastAPI app for each test"""
        if not EMAIL_VALIDATOR_AVAILABLE:
            pytest.skip("email-validator not available")

        app = FastAPI()

        # Pydantic models
        class UserBase(BaseModel):
            username: str = Field(..., min_length=3, max_length=50)
            email: EmailStr
            full_name: Optional[str] = None

        class UserCreate(UserBase):
            password: str = Field(..., min_length=8)

            @field_validator("password")
            @classmethod
            def password_strength(cls, v):
                """Validate password strength"""
                if not any(char.isdigit() for char in v):
                    raise ValueError("Password must contain at least one digit")
                if not any(char.isupper() for char in v):
                    raise ValueError(
                        "Password must contain at least one uppercase letter"
                    )
                return v

        class User(UserBase):
            id: int
            is_active: bool = True

        # Shield that validates user data using Pydantic
        @shield(
            name="User Validator",
            exception_to_raise_if_fail=HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="User validation failed"
            ),
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
        async def create_user(
            validated_user: UserCreate = ShieldedDepends(lambda user: user),
        ):
            """Create a new user with validated data"""
            new_user = User(
                id=1,
                username=validated_user.username,
                email=validated_user.email,
                full_name=validated_user.full_name,
            )
            return new_user

        self.app = app
        self.client = TestClient(app)
        self.UserCreate = UserCreate

    def test_valid_user_creation(self):
        """Test creating a user with valid data"""
        user_data = {
            "username": "testuser",
            "email": "test@company.com",
            "password": "Password123",
            "full_name": "Test User",
        }
        response = self.client.post("/users", json=user_data)
        assert response.status_code == 200
        result = response.json()
        assert result["username"] == "testuser"
        assert result["email"] == "test@company.com"
        assert result["id"] == 1
        assert result["is_active"] is True

    def test_reserved_username_blocked(self):
        """Test that reserved usernames are blocked"""
        user_data = {
            "username": "admin",
            "email": "admin@company.com",
            "password": "Password123",
        }
        response = self.client.post("/users", json=user_data)
        assert response.status_code == 400
        assert "User validation failed" in response.json()["detail"]

    def test_non_company_email_blocked(self):
        """Test that non-company emails are blocked"""
        user_data = {
            "username": "testuser",
            "email": "test@gmail.com",
            "password": "Password123",
        }
        response = self.client.post("/users", json=user_data)
        assert response.status_code == 400
        assert "User validation failed" in response.json()["detail"]

    def test_pydantic_validation_errors(self):
        """Test that Pydantic validation errors are caught"""
        # Password without digit
        user_data = {
            "username": "testuser",
            "email": "test@company.com",
            "password": "Password",
        }
        response = self.client.post("/users", json=user_data)
        assert response.status_code == 422
        assert "Password must contain at least one digit" in str(response.json())

        # Password without uppercase
        user_data["password"] = "password123"
        response = self.client.post("/users", json=user_data)
        assert response.status_code == 422
        assert "Password must contain at least one uppercase letter" in str(
            response.json()
        )

    def test_invalid_email_format(self):
        """Test invalid email format"""
        user_data = {
            "username": "testuser",
            "email": "invalid-email",
            "password": "Password123",
        }
        response = self.client.post("/users", json=user_data)
        assert response.status_code == 422


class TestAdvancedSchemaValidation:
    """Tests for advanced schema validation with complex Pydantic models"""

    def setup_method(self):
        """Setup the FastAPI app for each test"""
        app = FastAPI()

        # Complex Pydantic models
        class Address(BaseModel):
            street: str
            city: str
            state: str
            zip_code: str = Field(..., pattern=r"^\d{5}(-\d{4})?$")
            country: str

        class PaymentMethod(BaseModel):
            card_type: str
            last_four: str = Field(..., pattern=r"^\d{4}$")
            expiry_month: conint(ge=1, le=12)
            expiry_year: conint(ge=2024)

            @model_validator(mode="after")
            def check_expiry(self):
                """Check if card is expired"""
                month = self.expiry_month
                year = self.expiry_year

                if month and year:
                    current_year = datetime.now().year
                    current_month = datetime.now().month

                    if (year < current_year) or (
                        year == current_year and month < current_month
                    ):
                        raise ValueError("Card has expired")

                return self

        class OrderItem(BaseModel):
            product_id: int
            quantity: conint(gt=0)
            unit_price: confloat(gt=0)

            @property
            def total_price(self) -> float:
                return self.quantity * self.unit_price

        class Order(BaseModel):
            user_id: int
            items: List[OrderItem] = Field(..., min_length=1)
            shipping_address: Address
            billing_address: Optional[Address] = None
            payment_method: PaymentMethod
            coupon_code: Optional[str] = None

            @field_validator("coupon_code")
            @classmethod
            def validate_coupon_format(cls, v):
                """Validate coupon code format if provided"""
                if v is not None and not re.match(r"^[A-Z0-9]{8,12}$", v):
                    raise ValueError("Invalid coupon code format")
                return v

            @model_validator(mode="after")
            def set_billing_same_as_shipping(self):
                """If billing address is not provided, use shipping address"""
                if self.billing_address is None:
                    self.billing_address = self.shipping_address
                return self

        # Shield that validates orders
        @shield(
            name="Order Validator",
            exception_to_raise_if_fail=HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid order data"
            ),
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
        async def create_order(
            validated_order: Order = ShieldedDepends(lambda order: order),
        ):
            """Create a new order with validated data"""
            # Calculate total for response
            total = sum(item.total_price for item in validated_order.items)

            return {
                "order_id": 12345,
                "status": "created",
                "total_amount": total,
                "message": "Order created successfully",
            }

        self.app = app
        self.client = TestClient(app)

    def test_valid_order_creation(self):
        """Test creating a valid order"""
        order_data = {
            "user_id": 1,
            "items": [
                {"product_id": 1, "quantity": 2, "unit_price": 10.0},
                {"product_id": 2, "quantity": 1, "unit_price": 15.0},
            ],
            "shipping_address": {
                "street": "123 Main St",
                "city": "Anytown",
                "state": "CA",
                "zip_code": "12345",
                "country": "USA",
            },
            "payment_method": {
                "card_type": "visa",
                "last_four": "1234",
                "expiry_month": 12,
                "expiry_year": 2025,
            },
        }
        response = self.client.post("/orders", json=order_data)
        assert response.status_code == 200
        result = response.json()
        assert result["order_id"] == 12345
        assert result["total_amount"] == 35.0
        assert result["status"] == "created"

    def test_too_many_items_blocked(self):
        """Test that orders with too many items are blocked"""
        order_data = {
            "user_id": 1,
            "items": [
                {"product_id": i, "quantity": 1, "unit_price": 10.0} for i in range(11)
            ],
            "shipping_address": {
                "street": "123 Main St",
                "city": "Anytown",
                "state": "CA",
                "zip_code": "12345",
                "country": "USA",
            },
            "payment_method": {
                "card_type": "visa",
                "last_four": "1234",
                "expiry_month": 12,
                "expiry_year": 2025,
            },
        }
        response = self.client.post("/orders", json=order_data)
        assert response.status_code == 400
        assert "Invalid order data" in response.json()["detail"]

    def test_high_value_order_blocked(self):
        """Test that high-value orders are blocked"""
        order_data = {
            "user_id": 1,
            "items": [{"product_id": 1, "quantity": 1, "unit_price": 1500.0}],
            "shipping_address": {
                "street": "123 Main St",
                "city": "Anytown",
                "state": "CA",
                "zip_code": "12345",
                "country": "USA",
            },
            "payment_method": {
                "card_type": "visa",
                "last_four": "1234",
                "expiry_month": 12,
                "expiry_year": 2025,
            },
        }
        response = self.client.post("/orders", json=order_data)
        assert response.status_code == 400
        assert "Invalid order data" in response.json()["detail"]

    def test_invalid_zip_code(self):
        """Test invalid zip code format"""
        order_data = {
            "user_id": 1,
            "items": [{"product_id": 1, "quantity": 1, "unit_price": 10.0}],
            "shipping_address": {
                "street": "123 Main St",
                "city": "Anytown",
                "state": "CA",
                "zip_code": "invalid",
                "country": "USA",
            },
            "payment_method": {
                "card_type": "visa",
                "last_four": "1234",
                "expiry_month": 12,
                "expiry_year": 2025,
            },
        }
        response = self.client.post("/orders", json=order_data)
        assert response.status_code == 422

    def test_expired_card(self):
        """Test expired payment card"""
        order_data = {
            "user_id": 1,
            "items": [{"product_id": 1, "quantity": 1, "unit_price": 10.0}],
            "shipping_address": {
                "street": "123 Main St",
                "city": "Anytown",
                "state": "CA",
                "zip_code": "12345",
                "country": "USA",
            },
            "payment_method": {
                "card_type": "visa",
                "last_four": "1234",
                "expiry_month": 1,
                "expiry_year": 2020,
            },
        }
        response = self.client.post("/orders", json=order_data)
        assert response.status_code == 422
        # The constraint validation happens before our custom validator
        assert "greater than or equal to 2024" in str(response.json())


class TestModelTransformationAndEnrichment:
    """Tests for model transformation and enrichment"""

    def setup_method(self):
        """Setup the FastAPI app for each test"""
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
                detail="Product enrichment failed",
            ),
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
                *product_input.description.lower().split()[:5],  # First 5 words
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
                search_keywords=keywords,
            )

            return enriched_product

        @app.post("/products", response_model=Product)
        @enrich_product_shield
        async def create_product(product: Product = ShieldedDepends(lambda p: p)):
            """Create a new product with enriched data"""
            return product

        self.app = app
        self.client = TestClient(app)

    def test_product_enrichment(self):
        """Test product data enrichment"""
        product_data = {
            "name": "Test Product",
            "description": "This is a test product description",
            "price": 29.99,
            "category": "electronics",
            "tags": ["gadget", "tech"],
        }
        response = self.client.post("/products", json=product_data)
        assert response.status_code == 200
        result = response.json()

        # Check basic fields
        assert result["name"] == "Test Product"
        assert result["price"] == 29.99
        assert result["category"] == "electronics"

        # Check enriched fields
        assert len(result["id"]) == 12
        assert result["slug"] == "test-product"
        assert "created_at" in result
        assert isinstance(result["search_keywords"], list)
        assert "test" in result["search_keywords"]
        assert "electronics" in result["search_keywords"]

    def test_invalid_price(self):
        """Test invalid price validation"""
        product_data = {
            "name": "Test Product",
            "description": "This is a test product",
            "price": -10.0,
            "category": "electronics",
            "tags": [],
        }
        response = self.client.post("/products", json=product_data)
        assert response.status_code == 422


class TestExternalDependencyValidation:
    """Tests for validation with external dependencies"""

    def setup_method(self):
        """Setup the FastAPI app for each test"""
        if not EMAIL_VALIDATOR_AVAILABLE:
            pytest.skip("email-validator not available")

        app = FastAPI()

        # Mock external services
        class UserService:
            @staticmethod
            async def check_username_exists(username: str) -> bool:
                """Simulate checking if username exists"""
                await asyncio.sleep(0.01)  # Simulate API call
                return username in ["admin", "test", "user"]

            @staticmethod
            async def check_email_exists(email: str) -> bool:
                """Simulate checking if email exists"""
                await asyncio.sleep(0.01)  # Simulate API call
                return email in ["admin@example.com", "test@example.com"]

        # Dependency to get user service
        def get_user_service() -> UserService:
            return UserService()

        class UserRegistration(BaseModel):
            username: str = Field(..., min_length=3, max_length=20)
            email: EmailStr
            password: str = Field(..., min_length=8)
            full_name: Optional[str] = None

            @field_validator("username")
            @classmethod
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
                detail="Registration validation failed",
            ),
        )
        async def validate_registration_shield(
            registration: UserRegistration = Body(),
            user_service: UserService = Depends(get_user_service),
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
            validated_registration: UserRegistration = ShieldedDepends(lambda r: r),
        ):
            """Register a new user"""
            return {
                "message": "User registered successfully",
                "username": validated_registration.username,
                "email": validated_registration.email,
            }

        self.app = app
        self.client = TestClient(app)

    def test_successful_registration(self):
        """Test successful user registration"""
        registration_data = {
            "username": "newuser",
            "email": "newuser@example.com",
            "password": "password123",
            "full_name": "New User",
        }
        response = self.client.post("/register", json=registration_data)
        assert response.status_code == 200
        result = response.json()
        assert result["username"] == "newuser"
        assert result["email"] == "newuser@example.com"

    def test_existing_username_blocked(self):
        """Test that existing usernames are blocked"""
        registration_data = {
            "username": "admin",
            "email": "newuser@example.com",
            "password": "password123",
        }
        response = self.client.post("/register", json=registration_data)
        assert response.status_code == 400
        assert "Registration validation failed" in response.json()["detail"]

    def test_existing_email_blocked(self):
        """Test that existing emails are blocked"""
        registration_data = {
            "username": "newuser",
            "email": "admin@example.com",
            "password": "password123",
        }
        response = self.client.post("/register", json=registration_data)
        assert response.status_code == 400
        assert "Registration validation failed" in response.json()["detail"]

    def test_invalid_username_format(self):
        """Test invalid username format"""
        registration_data = {
            "username": "new-user",  # Contains hyphen
            "email": "newuser@example.com",
            "password": "password123",
        }
        response = self.client.post("/register", json=registration_data)
        assert response.status_code == 422
        assert "Username must be alphanumeric" in str(response.json())


class TestMultipleShieldComposition:
    """Tests for multiple shield composition"""

    def setup_method(self):
        """Setup the FastAPI app for each test"""
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
                detail="Authentication required",
            ),
        )
        def auth_shield(authorization: str = Header(None)):
            """Validate authorization header"""
            if not authorization or not authorization.startswith("Bearer "):
                return None

            # Mock token validation
            token = authorization.replace("Bearer ", "")
            if token == "valid_token":
                return AuthData(
                    user_id=1, username="testuser", roles=["user", "content_creator"]
                )
            return None

        # Content validation shield
        @shield(
            name="Content Validator",
            exception_to_raise_if_fail=HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Content validation failed",
            ),
        )
        def validate_content_shield(
            content: ContentInput = Body(),
            auth_data: AuthData = ShieldedDepends(lambda auth: auth),
        ):
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

            return content, auth_data

        # Permission shield
        @shield(
            name="Permission Shield",
            exception_to_raise_if_fail=HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions"
            ),
        )
        def permission_shield(
            auth_data: AuthData = ShieldedDepends(lambda auth: auth),
        ):
            """Check if user has content creation permissions"""
            if "content_creator" in auth_data.roles:
                return auth_data
            return None

        # Endpoint with multiple shields
        @app.post("/content")
        @auth_shield
        @permission_shield
        @validate_content_shield
        async def create_content(
            content: ContentInput = Body(),
            user: AuthData = ShieldedDepends(lambda data: data[1]),
        ):
            """Create new content with full validation"""
            return {
                "message": "Content created successfully",
                "content_id": 12345,
                "title": content.title,
                "author": user.username,
            }

        self.app = app
        self.client = TestClient(app)

    def test_successful_content_creation(self):
        """Test successful content creation with all shields passing"""
        content_data = {
            "title": "Test Article",
            "body": "This is a test article about technology",
            "tags": ["test", "tech"],
            "category": "tech",
        }
        headers = {"Authorization": "Bearer valid_token"}
        response = self.client.post("/content", json=content_data, headers=headers)
        assert response.status_code == 200, response.json()
        result = response.json()
        assert result["title"] == "Test Article"
        assert result["author"] == "testuser"
        assert result["content_id"] == 12345

    def test_authentication_required(self):
        """Test that authentication is required"""
        content_data = {
            "title": "Test Article",
            "body": "This is a test article",
            "category": "tech",
        }
        response = self.client.post("/content", json=content_data)
        assert response.status_code == 401
        assert "Authentication required" in response.json()["detail"]

    def test_prohibited_content_blocked(self):
        """Test that prohibited content is blocked"""
        content_data = {
            "title": "Spam Article",
            "body": "This is spam content",
            "category": "tech",
        }
        headers = {"Authorization": "Bearer valid_token"}
        response = self.client.post("/content", json=content_data, headers=headers)
        assert response.status_code == 400
        assert "Content validation failed" in response.json()["detail"]

    def test_invalid_category_blocked(self):
        """Test that invalid categories are blocked"""
        content_data = {
            "title": "Test Article",
            "body": "This is a test article",
            "category": "invalid",
        }
        headers = {"Authorization": "Bearer valid_token"}
        response = self.client.post("/content", json=content_data, headers=headers)
        assert response.status_code == 400
        assert "Content validation failed" in response.json()["detail"]


class TestFormDataValidation:
    """Tests for form data validation with Pydantic"""

    def setup_method(self):
        """Setup the FastAPI app for each test"""
        if not EMAIL_VALIDATOR_AVAILABLE:
            pytest.skip("email-validator not available")

        app = FastAPI()

        class ContactForm(BaseModel):
            name: str
            email: EmailStr
            subject: str
            message: str
            phone: Optional[str] = None

            @field_validator("name")
            @classmethod
            def validate_name(cls, v):
                """Validate name format"""
                if len(v.strip()) < 2:
                    raise ValueError("Name must be at least 2 characters")
                return v.strip()

            @field_validator("message")
            @classmethod
            def validate_message(cls, v):
                """Validate message content"""
                if len(v.strip()) < 10:
                    raise ValueError("Message must be at least 10 characters")
                return v.strip()

        # Shield for form validation
        @shield(
            name="Contact Form Validator",
            exception_to_raise_if_fail=HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Form validation failed"
            ),
        )
        def validate_contact_form_shield(
            name: str = Form(...),
            email: str = Form(...),
            subject: str = Form(...),
            message: str = Form(...),
            phone: Optional[str] = Form(None),
        ):
            """Validate contact form data"""

            # Create Pydantic model from form data
            try:
                form_data = ContactForm(
                    name=name,
                    email=email,
                    subject=subject,
                    message=message,
                    phone=phone,
                )
            except ValueError:
                return None

            # Additional validation
            if phone and not re.match(r"^\+?[\d\s\-\(\)]{8,20}$", phone):
                return None

            return form_data

        @app.post("/contact")
        @validate_contact_form_shield
        async def submit_contact_form(
            form_data: ContactForm = ShieldedDepends(lambda form: form),
        ):
            """Submit contact form"""
            return {
                "message": "Contact form submitted successfully",
                "reference_id": "CF12345",
            }

        self.app = app
        self.client = TestClient(app)

    def test_valid_form_submission(self):
        """Test valid form submission"""
        form_data = {
            "name": "John Doe",
            "email": "john@example.com",
            "subject": "Test Subject",
            "message": "This is a test message with enough content",
            "phone": "+1-555-123-4567",
        }
        response = self.client.post("/contact", data=form_data)
        assert response.status_code == 200
        result = response.json()
        assert result["message"] == "Contact form submitted successfully"
        assert result["reference_id"] == "CF12345"

    def test_form_without_phone(self):
        """Test form submission without phone number"""
        form_data = {
            "name": "John Doe",
            "email": "john@example.com",
            "subject": "Test Subject",
            "message": "This is a test message with enough content",
        }
        response = self.client.post("/contact", data=form_data)
        assert response.status_code == 200

    def test_invalid_phone_format(self):
        """Test invalid phone format"""
        form_data = {
            "name": "John Doe",
            "email": "john@example.com",
            "subject": "Test Subject",
            "message": "This is a test message with enough content",
            "phone": "invalid-phone",
        }
        response = self.client.post("/contact", data=form_data)
        assert response.status_code == 400
        assert "Form validation failed" in response.json()["detail"]

    def test_short_name(self):
        """Test name that's too short"""
        form_data = {
            "name": "J",
            "email": "john@example.com",
            "subject": "Test Subject",
            "message": "This is a test message with enough content",
        }
        response = self.client.post("/contact", data=form_data)
        assert response.status_code == 400
        assert "Form validation failed" in response.json()["detail"]

    def test_short_message(self):
        """Test message that's too short"""
        form_data = {
            "name": "John Doe",
            "email": "john@example.com",
            "subject": "Test Subject",
            "message": "Short",
        }
        response = self.client.post("/contact", data=form_data)
        assert response.status_code == 400
        assert "Form validation failed" in response.json()["detail"]

    def test_invalid_email(self):
        """Test invalid email format"""
        form_data = {
            "name": "John Doe",
            "email": "invalid-email",
            "subject": "Test Subject",
            "message": "This is a test message with enough content",
        }
        response = self.client.post("/contact", data=form_data)
        assert response.status_code == 400
        assert "Form validation failed" in response.json()["detail"]
