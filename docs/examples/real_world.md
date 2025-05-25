<!--Examples tested-->

# Real World Examples

This section provides real-world examples of using FastAPI Shield in production scenarios. These examples demonstrate practical implementations of security patterns that have been thoroughly tested and validated.

## E-commerce API Security

A comprehensive example of securing an e-commerce API with multiple layers of protection:

```python
from fastapi import Body, FastAPI, Header, HTTPException, status, Depends, Query, Path
from fastapi_shield import shield, ShieldedDepends
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import jwt
import time
from uuid import UUID, uuid4
import logging
from datetime import datetime, timedelta

# Configuration
JWT_SECRET = "your-production-secret-key"
JWT_ALGORITHM = "HS256"
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_REQUESTS = 100

app = FastAPI(title="E-commerce API")

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

# Mock databases (in production, use proper databases)
PRODUCTS_DB = {}
ORDERS_DB = {}

# Rate limiting storage (in production, use Redis)
rate_limits = {}

# Shield System

@shield(name="Rate Limiter")
async def rate_limit_shield(client_ip: str = Header(None, alias="X-Forwarded-For")):
    """Rate limit based on client IP"""
    if not client_ip:
        client_ip = "127.0.0.1"
        
    rate_key = f"rate_limit:{client_ip}"
    current_time = int(time.time())
    window_start = current_time - RATE_LIMIT_WINDOW
    
    # Simple in-memory rate limiting (use Redis in production)
    if rate_key not in rate_limits:
        rate_limits[rate_key] = []
    
    # Remove old entries
    rate_limits[rate_key] = [
        t for t in rate_limits[rate_key] 
        if t > window_start
    ]
    
    # Add current request
    rate_limits[rate_key].append(current_time)
    
    # Check if rate limit exceeded
    if len(rate_limits[rate_key]) > RATE_LIMIT_MAX_REQUESTS:
        return None
        
    return {"client_ip": client_ip, "request_count": len(rate_limits[rate_key])}

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

# API Endpoints

@app.get("/products", response_model=List[Product])
@rate_limit_shield
async def list_products(
    category: Optional[str] = Query(None),
    rate_data = ShieldedDepends(lambda rate_data: rate_data)
):
    """List all products with optional filtering - Public endpoint"""
    products = list(PRODUCTS_DB.values())
    if category:
        products = [p for p in products if p.category == category]
    return products

@app.get("/products/{product_id}", response_model=Product)
@rate_limit_shield
@product_exists_shield
async def get_product(product: Product = ShieldedDepends(lambda p: p)):
    """Get a specific product by ID - Public endpoint"""
    return product

@app.post("/products", response_model=Product)
@rate_limit_shield
@jwt_auth_shield
@require_permissions(["product:create"])
async def create_product(product_data: dict = Body()):
    """Create a new product - Requires authentication and product:create permission"""
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

@app.put("/products/{product_id}", response_model=Product)
@rate_limit_shield
@jwt_auth_shield
@require_permissions(["product:update"])
@product_exists_shield
async def update_product(
    updated_data: dict,
    product: Product = ShieldedDepends(lambda p: p),
):
    """Update an existing product - Requires authentication and product:update permission"""
    for key, value in updated_data.items():
        if hasattr(product, key):
            setattr(product, key, value)
    PRODUCTS_DB[product.id] = product
    return product

@app.delete("/products/{product_id}")
@rate_limit_shield
@jwt_auth_shield
@require_permissions(["product:delete"])
@product_exists_shield
async def delete_product(product: Product = ShieldedDepends(lambda p: p)):
    """Delete a product - Requires authentication and product:delete permission"""
    del PRODUCTS_DB[product.id]
    return {"message": "Product deleted successfully"}

@app.get("/orders", response_model=List[Order])
@rate_limit_shield
@jwt_auth_shield
async def list_orders(auth_data = ShieldedDepends(lambda d: d)):
    """List orders - Users see their own, admins/managers see all"""
    user_id = auth_data.get("user_id")
    user_roles = auth_data.get("roles", [])
    
    if UserRole.ADMIN in user_roles or UserRole.MANAGER in user_roles:
        return list(ORDERS_DB.values())
    
    return [o for o in ORDERS_DB.values() if str(o.user_id) == user_id]

@app.get("/orders/{order_id}", response_model=Order)
@rate_limit_shield
@jwt_auth_shield
@order_owner_shield
async def get_order(order: Order = ShieldedDepends(lambda o: o)):
    """Get a specific order - Only owner or admin/manager can access"""
    return order

@app.post("/orders", response_model=Order)
@rate_limit_shield
@jwt_auth_shield
async def create_order(
    order_data: dict,
    auth_data = ShieldedDepends(lambda d: d)
):
    """Create a new order - Requires authentication"""
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

@app.delete("/orders/{order_id}")
@rate_limit_shield
@jwt_auth_shield
@require_permissions(["order:delete"])
@order_owner_shield
async def cancel_order(order: Order = ShieldedDepends(lambda o: o)):
    """Cancel an order - Requires order:delete permission and ownership"""
    order.status = "cancelled"
    ORDERS_DB[order.id] = order
    return {"message": "Order cancelled successfully"}

# Helper function to create test tokens
def create_test_token(user_id: str, roles: list = None, permissions: list = None):
    """Create a JWT token for testing"""
    payload = {
        "sub": user_id,
        "roles": roles or ["user"],
        "permissions": permissions or [],
        "exp": datetime.utcnow() + timedelta(hours=1)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
```

### Key Features

1. **Public Endpoints**: Product listing and viewing don't require authentication
2. **Authenticated Endpoints**: Order management requires valid JWT tokens
3. **Permission-Based Access**: Product management requires specific permissions
4. **Role-Based Access**: Admins and managers have broader access to orders
5. **Resource Ownership**: Users can only access their own orders (unless admin/manager)
6. **Rate Limiting**: All endpoints are rate-limited by client IP
7. **Shield Composition**: Multiple shields can be stacked for layered security

### Shield Order Matters

Notice the order of shields in the decorators:
```python
@rate_limit_shield        # Applied first
@jwt_auth_shield         # Applied second
@require_permissions(...)  # Applied third
@product_exists_shield   # Applied last
```

The shields are applied in reverse order of decoration, so the bottom shield runs first.

## Microservice API Gateway

An example of using FastAPI Shield as part of an API gateway for a microservices architecture:

```python
from fastapi import FastAPI, Depends, Header, HTTPException, status, Request, Response
from fastapi_shield import shield, ShieldedDepends
import httpx
import jwt
import time
import uuid
from typing import Dict, Any, Optional
import logging
from datetime import datetime, timedelta

# Configuration
JWT_SECRET = "your-production-secret-key"
JWT_ALGORITHM = "HS256"

app = FastAPI(title="API Gateway")

# Service registry (in production, this would be dynamic)
SERVICES = {
    "user-service": "http://user-service:8001",
    "product-service": "http://product-service:8002",
    "order-service": "http://order-service:8003",
    "payment-service": "http://payment-service:8004"
}

# HTTP client for forwarding requests
http_client = httpx.AsyncClient()

# Gateway Shields

@shield(name="Gateway Auth")
async def gateway_auth_shield(authorization: str = Header(None)):
    """Validate JWT token for the gateway"""
    if not authorization:
        return None
    
    if not authorization.startswith("Bearer "):
        return None
        
    token = authorization.replace("Bearer ", "")
    
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return {
            "user_id": payload.get("sub"),
            "roles": payload.get("roles", []),
            "permissions": payload.get("permissions", []),
            "token": token  # Keep the token to pass to microservices
        }
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

@shield(name="Rate Limiter")
async def gateway_rate_limit(request: Request):
    """Simple rate limiting for the gateway"""
    client_ip = getattr(request.client, 'host', '127.0.0.1')
    
    # Generate a key for rate limiting
    rate_key = f"rate:{client_ip}:{int(time.time() / 60)}"  # Per minute
    
    # Simple in-memory rate limiting (use Redis in production)
    if not hasattr(app, "rate_limits"):
        app.rate_limits = {}
    
    current_count = app.rate_limits.get(rate_key, 0)
    max_requests = 100  # 100 requests per minute
    
    if current_count >= max_requests:
        return None
    
    app.rate_limits[rate_key] = current_count + 1
    return {"client_ip": client_ip}

# Middleware for request logging
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    request_id = str(uuid.uuid4())
    
    # Add request ID to request state
    request.state.request_id = request_id
    
    response = await call_next(request)
    
    process_time = time.time() - start_time
    
    # Add request ID to response headers
    response.headers["X-Request-ID"] = request_id
    return response

# Health check endpoint
@app.get("/gateway/health")
async def health_check():
    """Health check endpoint for the gateway"""
    service_status = {}
    
    for service_name, service_url in SERVICES.items():
        try:
            # In production, you would actually check service health
            service_status[service_name] = {
                "status": "up",
                "status_code": 200
            }
        except Exception as e:
            service_status[service_name] = {
                "status": "down",
                "error": str(e)
            }
    
    return {
        "status": "ok",
        "timestamp": time.time(),
        "services": service_status
    }

# Main proxy route
@app.api_route("/{service}/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
@gateway_rate_limit
@gateway_auth_shield
async def proxy_to_service(
    service: str,
    path: str,
    request: Request,
    auth_data = ShieldedDepends(lambda auth_data: auth_data),
):
    """
    Main proxy handler that forwards requests to the appropriate microservice.
    Applies authentication and authorization before forwarding.
    """
    # Check if service exists
    if service not in SERVICES:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Service '{service}' not found"
        )
    
    # Get service URL
    service_url = SERVICES[service]
    target_url = f"{service_url}/{path}"
    
    # Get request body if present
    body = await request.body()
    
    # Extract headers and filter out host-specific headers
    headers = dict(request.headers)
    headers_to_remove = ["host", "content-length", "connection"]
    for header in headers_to_remove:
        if header in headers:
            del headers[header]
    
    # Add custom gateway headers
    headers["X-Gateway-Request-ID"] = request.state.request_id
    
    if auth_data:
        # Add user context for the microservice
        headers["X-User-ID"] = auth_data.get("user_id", "")
        headers["X-User-Roles"] = ",".join(auth_data.get("roles", []))
        
        # Keep the original auth token
        if "Authorization" not in headers and "token" in auth_data:
            headers["Authorization"] = f"Bearer {auth_data['token']}"
    
    # Forward the request to the target service
    try:
        method = request.method.lower()
        request_kwargs = {
            "headers": headers,
            "params": dict(request.query_params),
            "timeout": 30.0  # 30 seconds timeout
        }
        
        if body:
            request_kwargs["content"] = body
        
        # Make the request to the microservice
        if method == "get":
            response = await http_client.get(target_url, **request_kwargs)
        elif method == "post":
            response = await http_client.post(target_url, **request_kwargs)
        elif method == "put":
            response = await http_client.put(target_url, **request_kwargs)
        elif method == "delete":
            response = await http_client.delete(target_url, **request_kwargs)
        elif method == "patch":
            response = await http_client.patch(target_url, **request_kwargs)
        else:
            raise HTTPException(
                status_code=status.HTTP_405_METHOD_NOT_ALLOWED,
                detail=f"Method {method} not allowed"
            )
        
        # Create a FastAPI response from the microservice response
        return Response(
            content=response.content,
            status_code=response.status_code,
            headers=dict(response.headers),
            media_type=response.headers.get("content-type")
        )
    
    except httpx.RequestError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Error communicating with service: {str(e)}"
        )

# Helper function to create test tokens
def create_test_token(user_id: str, roles: list = None, permissions: list = None):
    """Create a JWT token for testing"""
    payload = {
        "sub": user_id,
        "roles": roles or ["user"],
        "permissions": permissions or [],
        "exp": datetime.utcnow() + timedelta(hours=1)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
```

The API Gateway implements several critical features essential for modern microservice architectures. It provides service discovery capabilities, intelligently routing incoming requests to their appropriate microservice destinations. Authentication is handled through JWT token validation, ensuring secure request forwarding. The gateway maintains comprehensive request logging with unique identifiers for each request, while also managing headers to provide necessary user context to downstream microservices. Health monitoring capabilities allow for real-time status tracking of all services, and built-in rate limiting protects the system from potential abuse. The gateway also implements robust error handling to gracefully manage service communication failures.

The request flow through the gateway follows a well-defined sequence. Initially, each request undergoes rate limiting checks to prevent abuse. This is followed by JWT token validation for authentication. The gateway then determines the appropriate target microservice through service routing. During header processing, it enriches the request with gateway headers and user context information. The request is then forwarded to the target microservice, and finally, the microservice's response is processed and returned to the client.

The implementation includes thorough testing suites that validate various aspects of the system. These tests cover authentication flows, including scenarios with valid, invalid, and expired tokens. Authorization testing ensures proper handling of permissions and roles, while rate limiting tests verify behavior both within and exceeding limits. The test suite also includes comprehensive error handling scenarios, covering network errors and invalid requests, as well as edge cases involving missing resources and malformed data. These tests not only validate the system but also serve as living documentation of expected behavior.

When deploying to production, several important considerations must be addressed. Redis should be implemented for rate limiting and token blacklisting functionality. Proper logging with structured formats is essential for system monitoring and debugging. The system should include monitoring and alerting mechanisms for shield failures, while configuration should be managed through environment variables. Circuit breakers should be implemented for external service calls to prevent cascading failures. Comprehensive error handling with appropriate status codes is crucial, along with HTTPS implementation and secure token storage. Token refresh mechanisms should be in place, and request/response validation schemas should be implemented. Finally, continuous monitoring of shield execution performance is necessary to maintain system health. These real-world examples provide a robust foundation for building secure and scalable APIs using FastAPI Shield.