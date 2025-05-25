import pytest
from fastapi.testclient import TestClient
from fastapi import Body, FastAPI, Header, HTTPException, status, Depends, Query, Path
from fastapi_shield import shield, ShieldedDepends
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import jwt
import time
from uuid import UUID, uuid4
import logging
from unittest.mock import Mock
from datetime import datetime, timedelta

# Configuration
JWT_SECRET = "test-secret-key"
JWT_ALGORITHM = "HS256"
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_REQUESTS = 100

# Models
class Product(BaseModel):
    id: UUID
    name: str
    price: float
    description: str
    category: str

class OrderItem(BaseModel):
    product_id: UUID
    quantity: int = Field(gt=0)
    price: float

class Order(BaseModel):
    id: UUID
    user_id: UUID
    items: List[OrderItem]
    total: float
    status: str

class UserRole:
    ADMIN = "admin"
    MANAGER = "manager"
    CUSTOMER = "customer"

# Mock databases for testing
PRODUCTS_DB = {
    UUID("11111111-1111-1111-1111-111111111111"): Product(
        id=UUID("11111111-1111-1111-1111-111111111111"),
        name="Test Product 1",
        price=29.99,
        description="A test product",
        category="electronics"
    ),
    UUID("22222222-2222-2222-2222-222222222222"): Product(
        id=UUID("22222222-2222-2222-2222-222222222222"),
        name="Test Product 2",
        price=49.99,
        description="Another test product",
        category="books"
    )
}

ORDERS_DB = {}
USER_ID_1 = UUID("33333333-3333-3333-3333-333333333333")
USER_ID_2 = UUID("44444444-4444-4444-4444-444444444444")

def create_test_token(user_id: str, roles: List[str] = None, permissions: List[str] = None):
    """Create a test JWT token"""
    payload = {
        "sub": user_id,
        "roles": roles or [UserRole.CUSTOMER],
        "permissions": permissions or [],
        "exp": datetime.utcnow() + timedelta(hours=1)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

class TestEcommerceAPI:
    """Test the E-commerce API real-world example"""
    
    def setup_method(self):
        """Setup the FastAPI app for each test"""
        self.app = FastAPI(title="E-commerce API")
        
        # Mock Redis client
        self.redis_client = Mock()
        self.redis_client.exists.return_value = False
        self.redis_client.pipeline.return_value.execute.return_value = [None, None, 0, None]
        
        # Rate limiting storage
        self.rate_limits = {}
        
        # Setup shields
        self.setup_shields()
        self.setup_routes()
        
        self.client = TestClient(self.app)
    
    def setup_shields(self):
        """Setup all shields for the e-commerce API"""
        
        @shield(name="Rate Limiter")
        async def rate_limit_shield(client_ip: str = Header(None, alias="X-Forwarded-For")):
            """Rate limit based on client IP"""
            if not client_ip:
                client_ip = "127.0.0.1"
                
            rate_key = f"rate_limit:{client_ip}"
            current_time = int(time.time())
            window_start = current_time - RATE_LIMIT_WINDOW
            
            # Simple in-memory rate limiting for tests
            if rate_key not in self.rate_limits:
                self.rate_limits[rate_key] = []
            
            # Remove old entries
            self.rate_limits[rate_key] = [
                t for t in self.rate_limits[rate_key] 
                if t > window_start
            ]
            
            # Add current request
            self.rate_limits[rate_key].append(current_time)
            
            # Check if rate limit exceeded
            if len(self.rate_limits[rate_key]) > RATE_LIMIT_MAX_REQUESTS:
                return None
                
            return {"client_ip": client_ip, "request_count": len(self.rate_limits[rate_key])}

        @shield(name="JWT Auth")
        async def jwt_auth_shield(
            authorization: str = Header(None),
            x_refresh_token: Optional[str] = Header(None)
        ):
            """Validate JWT token with refresh token support"""
            if not authorization:
                return None
            
            if not authorization.startswith("Bearer "):
                return None
                
            token = authorization.replace("Bearer ", "")
            
            # Check if token is blacklisted (mock)
            if self.redis_client.exists(f"blacklisted_token:{token}"):
                return None
            
            try:
                payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
                return {
                    "user_id": payload.get("sub"),
                    "roles": payload.get("roles", []),
                    "permissions": payload.get("permissions", [])
                }
            except jwt.ExpiredSignatureError:
                return None
            except jwt.InvalidTokenError:
                return None

        def require_permissions(required_permissions: List[str]):
            """Create a shield that requires specific permissions"""
            
            @shield(
                name=f"Permission Check ({', '.join(required_permissions)})",
                exception_to_raise_if_fail=HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient permissions"
                )
            )
            async def permission_shield(auth_data = ShieldedDepends(lambda auth_data: auth_data)):
                user_permissions = auth_data.get("permissions", [])
                
                if any(perm in user_permissions for perm in required_permissions):
                    return auth_data
                
                return None
                
            return permission_shield

        @shield(name="Product Exists")
        async def product_exists_shield(product_id: UUID = Path(...)):
            """Check if a product exists"""
            product = PRODUCTS_DB.get(product_id)
            if not product:
                return None
            return product

        @shield(name="Order Owner")
        async def order_owner_shield(
            order_id: UUID = Path(...),
            auth_data = ShieldedDepends(lambda payload: payload)
        ):
            """Check if the user owns the order"""
            order = ORDERS_DB.get(order_id)
            if not order:
                return None
            
            user_id = auth_data.get("user_id")
            user_roles = auth_data.get("roles", [])
            
            # Admin or manager can access any order
            if UserRole.ADMIN in user_roles or UserRole.MANAGER in user_roles:
                return order
            
            # Owner can access their own order
            if str(order.user_id) == user_id:
                return order
            
            return None

        # Store shields as instance variables for access in routes
        self.rate_limit_shield = rate_limit_shield
        self.jwt_auth_shield = jwt_auth_shield
        self.require_permissions = require_permissions
        self.product_exists_shield = product_exists_shield
        self.order_owner_shield = order_owner_shield

    def setup_routes(self):
        """Setup all routes for the e-commerce API"""
        
        @self.app.get("/products", response_model=List[Product])
        @self.rate_limit_shield
        async def list_products(
            category: Optional[str] = Query(None),
            rate_data = ShieldedDepends(lambda rate_data: rate_data)
        ):
            """List all products with optional filtering"""
            products = list(PRODUCTS_DB.values())
            if category:
                products = [p for p in products if p.category == category]
            return products

        @self.app.get("/products/{product_id}", response_model=Product)
        @self.rate_limit_shield
        @self.product_exists_shield
        async def get_product(product: Product = ShieldedDepends(lambda p: p)):
            """Get a specific product by ID"""
            return product

        @self.app.post("/products", response_model=Product)
        @self.rate_limit_shield
        @self.jwt_auth_shield
        @self.require_permissions(["product:create"])
        async def create_product(
            product_data: dict=Body(), 
        ):
            """Create a new product"""
            product_id = uuid4()
            product = Product(
                id=product_id,
                name=product_data["name"],
                price=product_data["price"],
                description=product_data["description"],
                category=product_data["category"]
            )
            PRODUCTS_DB[product_id] = product
            return product

        @self.app.put("/products/{product_id}", response_model=Product)
        @self.rate_limit_shield
        @self.jwt_auth_shield
        @self.require_permissions(["product:update"])
        @self.product_exists_shield
        async def update_product(
            updated_data: dict,
            product: Product = ShieldedDepends(lambda p: p),
        ):
            """Update an existing product"""
            for key, value in updated_data.items():
                if hasattr(product, key):
                    setattr(product, key, value)
            PRODUCTS_DB[product.id] = product
            return product

        @self.app.delete("/products/{product_id}")
        @self.rate_limit_shield
        @self.jwt_auth_shield
        @self.require_permissions(["product:delete"])
        @self.product_exists_shield
        async def delete_product(
            product: Product = ShieldedDepends(lambda p: p),
        ):
            """Delete a product"""
            del PRODUCTS_DB[product.id]
            return {"message": "Product deleted successfully"}

        @self.app.get("/orders", response_model=List[Order])
        @self.rate_limit_shield
        @self.jwt_auth_shield
        async def list_orders(auth_data = ShieldedDepends(lambda d: d)):
            """List orders for the current user or all orders for admins/managers"""
            user_id = auth_data.get("user_id")
            user_roles = auth_data.get("roles", [])
            
            if UserRole.ADMIN in user_roles or UserRole.MANAGER in user_roles:
                return list(ORDERS_DB.values())
            
            return [o for o in ORDERS_DB.values() if str(o.user_id) == user_id]

        @self.app.get("/orders/{order_id}", response_model=Order)
        @self.rate_limit_shield
        @self.jwt_auth_shield
        @self.order_owner_shield
        async def get_order(order: Order = ShieldedDepends(lambda o: o)):
            """Get a specific order that the user owns or has permission to view"""
            return order

        @self.app.post("/orders", response_model=Order)
        @self.rate_limit_shield
        @self.jwt_auth_shield
        async def create_order(
            order_data: dict,
            auth_data = ShieldedDepends(lambda d: d)
        ):
            """Create a new order"""
            user_id = UUID(auth_data.get("user_id"))
            order_id = uuid4()
            
            order = Order(
                id=order_id,
                user_id=user_id,
                items=[OrderItem(**item) for item in order_data["items"]],
                total=order_data["total"],
                status="created"
            )
            ORDERS_DB[order_id] = order
            return order

        @self.app.delete("/orders/{order_id}")
        @self.rate_limit_shield
        @self.jwt_auth_shield
        @self.require_permissions(["order:delete"])
        @self.order_owner_shield
        async def cancel_order(
            order: Order = ShieldedDepends(lambda o: o),
        ):
            """Cancel an order"""
            order.status = "cancelled"
            ORDERS_DB[order.id] = order
            return {"message": "Order cancelled successfully"}

    def test_list_products_public_access(self):
        """Test that listing products works without authentication"""
        response = self.client.get("/products")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2
        assert data[0]["name"] == "Test Product 1"

    def test_list_products_with_category_filter(self):
        """Test product listing with category filter"""
        response = self.client.get("/products?category=electronics")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["category"] == "electronics"

    def test_get_product_by_id(self):
        """Test getting a specific product by ID"""
        product_id = "11111111-1111-1111-1111-111111111111"
        response = self.client.get(f"/products/{product_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Test Product 1"

    def test_get_nonexistent_product(self):
        """Test getting a non-existent product"""
        product_id = "99999999-9999-9999-9999-999999999999"
        response = self.client.get(f"/products/{product_id}")
        assert response.status_code == 500  # Shield blocks request

    def test_create_product_without_auth(self):
        """Test creating a product without authentication"""
        product_data = {
            "name": "New Product",
            "price": 19.99,
            "description": "A new product",
            "category": "test"
        }
        response = self.client.post("/products", json=product_data)
        assert response.status_code == 500  # Auth shield blocks

    def test_create_product_with_auth_but_no_permission(self):
        """Test creating a product with auth but without permission"""
        token = create_test_token(str(USER_ID_1), [UserRole.CUSTOMER], [])
        product_data = {
            "name": "New Product",
            "price": 19.99,
            "description": "A new product",
            "category": "test"
        }
        headers = {"Authorization": f"Bearer {token}"}
        response = self.client.post("/products", json=product_data, headers=headers)
        assert response.status_code == 403
        assert "Insufficient permissions" in response.json()["detail"]

    def test_create_product_with_permission(self):
        """Test creating a product with proper permissions"""
        token = create_test_token(
            str(USER_ID_1), 
            [UserRole.ADMIN], 
            ["product:create"]
        )
        product_data = {
            "name": "New Product",
            "price": 19.99,
            "description": "A new product",
            "category": "test"
        }
        headers = {"Authorization": f"Bearer {token}"}
        response = self.client.post("/products", json=product_data, headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "New Product"

    def test_update_product_with_permission(self):
        """Test updating a product with proper permissions"""
        token = create_test_token(
            str(USER_ID_1), 
            [UserRole.ADMIN], 
            ["product:update"]
        )
        product_id = "11111111-1111-1111-1111-111111111111"
        update_data = {"name": "Updated Product Name"}
        headers = {"Authorization": f"Bearer {token}"}
        
        response = self.client.put(f"/products/{product_id}", json=update_data, headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Updated Product Name"

    def test_delete_product_with_permission(self):
        """Test deleting a product with proper permissions"""
        token = create_test_token(
            str(USER_ID_1), 
            [UserRole.ADMIN], 
            ["product:delete"]
        )
        product_id = "22222222-2222-2222-2222-222222222222"
        headers = {"Authorization": f"Bearer {token}"}
        
        response = self.client.delete(f"/products/{product_id}", headers=headers)
        assert response.status_code == 200
        assert response.json()["message"] == "Product deleted successfully"

    def test_list_orders_customer(self):
        """Test listing orders as a customer (should only see own orders)"""
        # Create a test order
        order_id = uuid4()
        ORDERS_DB[order_id] = Order(
            id=order_id,
            user_id=USER_ID_1,
            items=[],
            total=0.0,
            status="created"
        )
        
        token = create_test_token(str(USER_ID_1), [UserRole.CUSTOMER])
        headers = {"Authorization": f"Bearer {token}"}
        
        response = self.client.get("/orders", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["user_id"] == str(USER_ID_1)

    def test_list_orders_admin(self):
        """Test listing orders as an admin (should see all orders)"""
        # Create test orders for different users
        order_id_1 = uuid4()
        order_id_2 = uuid4()
        ORDERS_DB[order_id_1] = Order(
            id=order_id_1,
            user_id=USER_ID_1,
            items=[],
            total=0.0,
            status="created"
        )
        ORDERS_DB[order_id_2] = Order(
            id=order_id_2,
            user_id=USER_ID_2,
            items=[],
            total=0.0,
            status="created"
        )
        
        token = create_test_token(str(USER_ID_1), [UserRole.ADMIN])
        headers = {"Authorization": f"Bearer {token}"}
        
        response = self.client.get("/orders", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 2  # Should see orders from multiple users

    def test_create_order(self):
        """Test creating an order"""
        token = create_test_token(str(USER_ID_1), [UserRole.CUSTOMER])
        order_data = {
            "items": [
                {
                    "product_id": "11111111-1111-1111-1111-111111111111",
                    "quantity": 2,
                    "price": 29.99
                }
            ],
            "total": 59.98
        }
        headers = {"Authorization": f"Bearer {token}"}
        
        response = self.client.post("/orders", json=order_data, headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert data["user_id"] == str(USER_ID_1)
        assert data["total"] == 59.98

    def test_get_order_as_owner(self):
        """Test getting an order as the owner"""
        # Create a test order
        order_id = uuid4()
        ORDERS_DB[order_id] = Order(
            id=order_id,
            user_id=USER_ID_1,
            items=[],
            total=0.0,
            status="created"
        )
        
        token = create_test_token(str(USER_ID_1), [UserRole.CUSTOMER])
        headers = {"Authorization": f"Bearer {token}"}
        
        response = self.client.get(f"/orders/{order_id}", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == str(order_id)

    def test_get_order_as_non_owner(self):
        """Test getting an order as a non-owner (should fail)"""
        # Create a test order for USER_ID_1
        order_id = uuid4()
        ORDERS_DB[order_id] = Order(
            id=order_id,
            user_id=USER_ID_1,
            items=[],
            total=0.0,
            status="created"
        )
        
        # Try to access as USER_ID_2
        token = create_test_token(str(USER_ID_2), [UserRole.CUSTOMER])
        headers = {"Authorization": f"Bearer {token}"}
        
        response = self.client.get(f"/orders/{order_id}", headers=headers)
        assert response.status_code == 500  # Order owner shield blocks

    def test_get_order_as_admin(self):
        """Test getting any order as an admin"""
        # Create a test order for USER_ID_1
        order_id = uuid4()
        ORDERS_DB[order_id] = Order(
            id=order_id,
            user_id=USER_ID_1,
            items=[],
            total=0.0,
            status="created"
        )
        
        # Access as admin (different user)
        token = create_test_token(str(USER_ID_2), [UserRole.ADMIN])
        headers = {"Authorization": f"Bearer {token}"}
        
        response = self.client.get(f"/orders/{order_id}", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == str(order_id)

    def test_cancel_order_with_permission(self):
        """Test cancelling an order with proper permissions"""
        # Create a test order
        order_id = uuid4()
        ORDERS_DB[order_id] = Order(
            id=order_id,
            user_id=USER_ID_1,
            items=[],
            total=0.0,
            status="created"
        )
        
        token = create_test_token(
            str(USER_ID_1), 
            [UserRole.ADMIN], 
            ["order:delete"]
        )
        headers = {"Authorization": f"Bearer {token}"}
        
        response = self.client.delete(f"/orders/{order_id}", headers=headers)
        assert response.status_code == 200
        assert response.json()["message"] == "Order cancelled successfully"

    def test_rate_limiting(self):
        """Test rate limiting functionality"""
        # Make requests up to the limit
        # Since we're testing with a very high limit (100), we'll modify it for this test
        # Create a new rate limit shield for testing
        
        @shield(name="Test Rate Limiter")
        async def test_rate_limit_shield(client_ip: str = Header(None, alias="X-Forwarded-For")):
            """Rate limit based on client IP with lower limit for testing"""
            if not client_ip:
                client_ip = "127.0.0.1"
                
            rate_key = f"rate_limit:{client_ip}"
            current_time = int(time.time())
            window_start = current_time - RATE_LIMIT_WINDOW
            
            # Simple in-memory rate limiting for tests with limit of 2
            if rate_key not in self.rate_limits:
                self.rate_limits[rate_key] = []
            
            # Remove old entries
            self.rate_limits[rate_key] = [
                t for t in self.rate_limits[rate_key] 
                if t > window_start
            ]
            
            # Add current request
            self.rate_limits[rate_key].append(current_time)
            
            # Check if rate limit exceeded (use 2 as limit)
            if len(self.rate_limits[rate_key]) > 2:
                return None
                
            return {"client_ip": client_ip, "request_count": len(self.rate_limits[rate_key])}
        
        # Create a temporary endpoint for testing
        @self.app.get("/test-rate-limit")
        @test_rate_limit_shield
        async def test_endpoint():
            return {"message": "success"}
        
        # Reset rate limits
        self.rate_limits.clear()
        
        # Make requests within limit
        for i in range(2):
            response = self.client.get("/test-rate-limit")
            assert response.status_code == 200
        
        # This should exceed the limit
        response = self.client.get("/test-rate-limit")
        assert response.status_code == 500  # Rate limit shield blocks

    def test_invalid_jwt_token(self):
        """Test with invalid JWT token"""
        headers = {"Authorization": "Bearer invalid_token"}
        response = self.client.get("/orders", headers=headers)
        assert response.status_code == 500  # JWT auth shield blocks

    def test_expired_jwt_token(self):
        """Test with expired JWT token"""
        # Create an expired token
        payload = {
            "sub": str(USER_ID_1),
            "roles": [UserRole.CUSTOMER],
            "permissions": [],
            "exp": datetime.utcnow() - timedelta(hours=1)  # Expired
        }
        token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
        
        headers = {"Authorization": f"Bearer {token}"}
        response = self.client.get("/orders", headers=headers)
        assert response.status_code == 500  # JWT auth shield blocks

    def test_malformed_authorization_header(self):
        """Test with malformed authorization header"""
        headers = {"Authorization": "InvalidFormat token"}
        response = self.client.get("/orders", headers=headers)
        assert response.status_code == 500  # JWT auth shield blocks

    def teardown_method(self):
        """Clean up after each test"""
        ORDERS_DB.clear()
        self.rate_limits.clear()
        # Reset products DB to original state
        PRODUCTS_DB.clear()
        PRODUCTS_DB.update({
            UUID("11111111-1111-1111-1111-111111111111"): Product(
                id=UUID("11111111-1111-1111-1111-111111111111"),
                name="Test Product 1",
                price=29.99,
                description="A test product",
                category="electronics"
            ),
            UUID("22222222-2222-2222-2222-222222222222"): Product(
                id=UUID("22222222-2222-2222-2222-222222222222"),
                name="Test Product 2",
                price=49.99,
                description="Another test product",
                category="books"
            )
        }) 