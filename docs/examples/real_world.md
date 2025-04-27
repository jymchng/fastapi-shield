# Real World Examples

This section provides real-world examples of using FastAPI Shield in production scenarios. These examples demonstrate practical implementations of security patterns.

## E-commerce API Security

A comprehensive example of securing an e-commerce API:

```python
from fastapi import FastAPI, Header, HTTPException, status, Depends, Query, Path
from fastapi_shield import shield, ShieldedDepends
from pydantic import BaseModel, EmailStr, Field
from typing import List, Optional, Dict, Any
import jwt
import time
from uuid import UUID
import redis
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ecommerce_api")

# Initialize Redis (for rate limiting and token blacklisting)
redis_client = redis.Redis(host="localhost", port=6379, db=0)

app = FastAPI(title="E-commerce API")

# Configuration
JWT_SECRET = "your-production-secret-key"
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

class UserRole(str):
    ADMIN = "admin"
    MANAGER = "manager"
    CUSTOMER = "customer"

# Comprehensive API shield system

@shield(name="Rate Limiter")
async def rate_limit_shield(client_ip: str = Header(None, alias="X-Forwarded-For")):
    """Rate limit based on client IP"""
    # If no client IP is provided, use a default value
    if not client_ip:
        client_ip = "unknown"
        
    # Create a rate limit key for this client
    rate_key = f"rate_limit:{client_ip}"
    current_time = int(time.time())
    window_start = current_time - RATE_LIMIT_WINDOW
    
    # Add the current request timestamp
    pipeline = redis_client.pipeline()
    pipeline.zadd(rate_key, {str(current_time): current_time})
    
    # Remove timestamps outside the window
    pipeline.zremrangebyscore(rate_key, 0, window_start)
    
    # Count requests in the current window
    pipeline.zcard(rate_key)
    
    # Set key expiration
    pipeline.expire(rate_key, RATE_LIMIT_WINDOW * 2)
    
    # Execute commands
    _, _, request_count, _ = pipeline.execute()
    
    # Check if rate limit exceeded
    if request_count > RATE_LIMIT_MAX_REQUESTS:
        logger.warning(f"Rate limit exceeded for {client_ip}")
        return None
        
    return {"client_ip": client_ip, "request_count": request_count}

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
    
    # Check if token is blacklisted
    if redis_client.exists(f"blacklisted_token:{token}"):
        logger.warning("Blacklisted token used")
        return None
    
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        
        # Check if token is expired but refresh token is provided
        if x_refresh_token:
            # In a real app, validate the refresh token here
            # This is simplified for the example
            pass
            
        return {
            "user_id": payload.get("sub"),
            "roles": payload.get("roles", []),
            "permissions": payload.get("permissions", [])
        }
    except jwt.ExpiredSignatureError:
        logger.info("Expired token")
        return None
    except jwt.InvalidTokenError:
        logger.warning("Invalid token")
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
    async def permission_shield(auth_data = ShieldedDepends(jwt_auth_shield)):
        user_permissions = auth_data.get("permissions", [])
        
        # Check if the user has any of the required permissions
        if any(perm in user_permissions for perm in required_permissions):
            return auth_data
        
        logger.warning(f"Permission denied: {required_permissions}")
        return None
        
    return permission_shield

@shield(name="Product Exists")
async def product_exists_shield(product_id: UUID = Path(...)):
    """Check if a product exists"""
    # In a real app, this would query a database
    # This is simplified for the example
    product = get_product_by_id(product_id)
    
    if not product:
        return None
    
    return product

@shield(name="Order Owner")
async def order_owner_shield(
    order_id: UUID = Path(...),
    auth_data = ShieldedDepends(jwt_auth_shield)
):
    """Check if the user owns the order"""
    # In a real app, this would query a database
    # This is simplified for the example
    order = get_order_by_id(order_id)
    
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
    
    logger.warning(f"Unauthorized order access: {user_id} -> {order_id}")
    return None

# API Endpoints

@app.get("/products", response_model=List[Product])
@rate_limit_shield
async def list_products(
    category: Optional[str] = Query(None),
    rate_data = ShieldedDepends(rate_limit_shield)
):
    """List all products with optional filtering"""
    # Track request metrics
    logger.info(f"Products listed by {rate_data['client_ip']}")
    
    # In a real app, this would query a database
    # This is simplified for the example
    products = get_products(category)
    return products

@app.get("/products/{product_id}", response_model=Product)
@rate_limit_shield
@product_exists_shield
async def get_product(product: Product = ShieldedDepends(product_exists_shield)):
    """Get a specific product by ID"""
    return product

@app.post("/products", response_model=Product)
@rate_limit_shield
@jwt_auth_shield
@require_permissions(["product:create"])
async def create_product(
    product: Product, 
    auth_data = ShieldedDepends(require_permissions(["product:create"]))
):
    """Create a new product"""
    # In a real app, this would save to a database
    # This is simplified for the example
    logger.info(f"Product created by user {auth_data['user_id']}")
    return save_product(product)

@app.put("/products/{product_id}", response_model=Product)
@rate_limit_shield
@jwt_auth_shield
@product_exists_shield
@require_permissions(["product:update"])
async def update_product(
    updated_product: Product,
    product: Product = ShieldedDepends(product_exists_shield),
    auth_data = ShieldedDepends(require_permissions(["product:update"]))
):
    """Update an existing product"""
    # In a real app, this would update the database
    # This is simplified for the example
    logger.info(f"Product {product.id} updated by user {auth_data['user_id']}")
    return update_product_in_db(product.id, updated_product)

@app.delete("/products/{product_id}")
@rate_limit_shield
@jwt_auth_shield
@product_exists_shield
@require_permissions(["product:delete"])
async def delete_product(
    product: Product = ShieldedDepends(product_exists_shield),
    auth_data = ShieldedDepends(require_permissions(["product:delete"]))
):
    """Delete a product"""
    # In a real app, this would delete from the database
    # This is simplified for the example
    logger.info(f"Product {product.id} deleted by user {auth_data['user_id']}")
    delete_product_from_db(product.id)
    return {"message": "Product deleted successfully"}

@app.get("/orders", response_model=List[Order])
@rate_limit_shield
@jwt_auth_shield
async def list_orders(auth_data = ShieldedDepends(jwt_auth_shield)):
    """List orders for the current user or all orders for admins/managers"""
    user_id = auth_data.get("user_id")
    user_roles = auth_data.get("roles", [])
    
    # Admin or manager can see all orders
    if UserRole.ADMIN in user_roles or UserRole.MANAGER in user_roles:
        # In a real app, this would query a database
        # This is simplified for the example
        return get_all_orders()
    
    # Regular users can only see their own orders
    return get_user_orders(user_id)

@app.get("/orders/{order_id}", response_model=Order)
@rate_limit_shield
@jwt_auth_shield
@order_owner_shield
async def get_order(order: Order = ShieldedDepends(order_owner_shield)):
    """Get a specific order that the user owns or has permission to view"""
    return order

@app.post("/orders", response_model=Order)
@rate_limit_shield
@jwt_auth_shield
async def create_order(
    order_items: List[OrderItem],
    auth_data = ShieldedDepends(jwt_auth_shield)
):
    """Create a new order"""
    user_id = auth_data.get("user_id")
    
    # In a real app, this would create an order in the database
    # This is simplified for the example
    order = create_order_in_db(user_id, order_items)
    
    logger.info(f"Order {order.id} created by user {user_id}")
    return order

@app.delete("/orders/{order_id}")
@rate_limit_shield
@jwt_auth_shield
@order_owner_shield
@require_permissions(["order:delete"])
async def cancel_order(
    order: Order = ShieldedDepends(order_owner_shield),
    auth_data = ShieldedDepends(require_permissions(["order:delete"]))
):
    """Cancel an order"""
    # In a real app, this would update the database
    # This is simplified for the example
    logger.info(f"Order {order.id} cancelled by user {auth_data['user_id']}")
    cancel_order_in_db(order.id)
    return {"message": "Order cancelled successfully"}

# Simulated database functions (in a real app, these would interact with a database)
def get_products(category=None):
    # Simplified for the example
    return []

def get_product_by_id(product_id):
    # Simplified for the example
    return None

def save_product(product):
    # Simplified for the example
    return product

def update_product_in_db(product_id, product):
    # Simplified for the example
    return product

def delete_product_from_db(product_id):
    # Simplified for the example
    pass

def get_all_orders():
    # Simplified for the example
    return []

def get_user_orders(user_id):
    # Simplified for the example
    return []

def get_order_by_id(order_id):
    # Simplified for the example
    return None

def create_order_in_db(user_id, order_items):
    # Simplified for the example
    return Order(id=UUID("00000000-0000-0000-0000-000000000000"), user_id=user_id, items=order_items, total=0, status="created")

def cancel_order_in_db(order_id):
    # Simplified for the example
    pass
```

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
import json
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("api_gateway")

app = FastAPI(title="API Gateway")

# Configuration
JWT_SECRET = "your-production-secret-key"
JWT_ALGORITHM = "HS256"

# Service registry (in a real app, this would be dynamic)
SERVICES = {
    "user-service": "http://user-service:8001",
    "product-service": "http://product-service:8002",
    "order-service": "http://order-service:8003",
    "payment-service": "http://payment-service:8004"
}

# HTTP client for forwarding requests
http_client = httpx.AsyncClient()

# Auth shield for the gateway
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
        logger.warning("Expired token")
        return None
    except jwt.InvalidTokenError:
        logger.warning("Invalid token")
        return None

@shield(name="Service Access")
async def service_access_shield(service: str, auth_data = ShieldedDepends(gateway_auth_shield)):
    """Check if the user has access to the specified service"""
    if service not in SERVICES:
        logger.error(f"Service not found: {service}")
        return None
    
    # Check if user has access to this service
    # This is a simplified example; in a real app, you would check permissions
    user_permissions = auth_data.get("permissions", [])
    required_permission = f"service:{service}:access"
    
    if required_permission in user_permissions:
        return {
            "service_url": SERVICES[service],
            "auth_data": auth_data
        }
    
    logger.warning(f"Service access denied: {service} for user {auth_data.get('user_id')}")
    return None

@shield(name="Rate Limiter")
async def gateway_rate_limit(request: Request):
    """Simple rate limiting for the gateway"""
    client_ip = request.client.host
    
    # In a real app, you would use Redis or another distributed cache
    # This is simplified for the example
    
    # Generate a key for rate limiting
    rate_key = f"rate:{client_ip}:{int(time.time() / 60)}"  # Per minute
    
    # Simple in-memory rate limiting (NOT suitable for production)
    # In a real app, use Redis or another solution
    if hasattr(app, "rate_limits") is False:
        app.rate_limits = {}
    
    current_count = app.rate_limits.get(rate_key, 0)
    max_requests = 100  # 100 requests per minute
    
    if current_count >= max_requests:
        logger.warning(f"Rate limit exceeded: {client_ip}")
        return None
    
    app.rate_limits[rate_key] = current_count + 1
    return {"client_ip": client_ip}

# Middleware to log requests
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    request_id = str(uuid.uuid4())
    
    # Add request ID to request state
    request.state.request_id = request_id
    
    logger.info(f"Request started: {request_id} - {request.method} {request.url.path}")
    
    response = await call_next(request)
    
    process_time = time.time() - start_time
    logger.info(f"Request completed: {request_id} - {response.status_code} - {process_time:.4f}s")
    
    # Add request ID to response headers
    response.headers["X-Request-ID"] = request_id
    return response

# Route handlers for service proxying
@app.api_route("/{service}/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
@gateway_rate_limit
@gateway_auth_shield
async def proxy_to_service(
    service: str,
    path: str,
    request: Request,
    auth_data = ShieldedDepends(gateway_auth_shield),
    rate_data = ShieldedDepends(gateway_rate_limit)
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
    headers["X-Forwarded-For"] = rate_data["client_ip"]
    
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
        
        logger.info(f"Forwarding request to {target_url}")
        
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
        logger.error(f"Error forwarding request: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Error communicating with service: {str(e)}"
        )

@app.get("/gateway/health")
async def health_check():
    """Health check endpoint for the gateway"""
    # Check status of all services
    service_status = {}
    
    for service_name, service_url in SERVICES.items():
        try:
            response = await http_client.get(f"{service_url}/health", timeout=2.0)
            service_status[service_name] = {
                "status": "up" if response.status_code == 200 else "degraded",
                "status_code": response.status_code
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
```

These real-world examples demonstrate how to implement FastAPI Shield in production scenarios with considerations for security, scalability, and maintainability. 