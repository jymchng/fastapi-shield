from fastapi import FastAPI, HTTPException, Depends, Path, Query, Body, status
from fastapi_shield import ShieldedDepends

from models import Product, User, TokenResponse
from database import (
    get_product, 
    get_all_products, 
    get_user_by_username, 
    TOKENS_DB
)
from shields import (
    auth_shield, 
    admin_required,
    get_current_user_from_token, 
    user_required, 
    get_authenticated_user
)

app = FastAPI(
    title="FastAPI Shield Example",
    description="Example API showing FastAPI Shield for authentication and authorization",
    version="1.0.0"
)

# Public endpoints
@app.get("/")
async def root():
    """Root endpoint - accessible to everyone"""
    return {"message": "Welcome to the FastAPI Shield Example API"}

@app.get("/products", response_model=list[Product])
async def list_products():
    """List all products - accessible to everyone"""
    return get_all_products()

@app.get("/products/{product_id}", response_model=Product)
async def get_product_by_id(product_id: int = Path(..., description="The ID of the product")):
    """Get a product by ID - accessible to everyone"""
    product = get_product(product_id)
    if not product:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Product with ID {product_id} not found"
        )
    return product

# Authentication endpoint
@app.post("/token", response_model=TokenResponse)
async def login(username: str = Body(...), password: str = Body(...)):
    """
    Authentication endpoint to get a token
    Using simplified authentication for demo purposes
    In a real app, this would use proper password hashing
    """
    user = get_user_by_username(username)
    
    if not user or user.password != password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    
    # In a real app, you would generate a JWT token here
    # For simplicity, we're just returning the mock token
    token_key = f"{username}_token"
    if token_key not in TOKENS_DB:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token not found for user"
        )
    
    return TokenResponse(access_token=token_key)

# Protected endpoints - require authentication
@app.get("/me", response_model=User)
@auth_shield
async def get_current_user(user: User = ShieldedDepends(get_current_user_from_token)):
    """Get the current authenticated user's information"""
    return user

# User-level protected endpoints
@app.get("/protected/products", response_model=list[Product])
@auth_shield
@user_required  # Requires user or admin role
async def get_protected_products(user: User = ShieldedDepends(get_authenticated_user)):
    """
    Get all products - protected endpoint requiring user or admin role
    This endpoint is the same as the public one, but demonstrates role-based access
    """
    return get_all_products()

# Admin-only endpoints
@app.post("/admin/products", response_model=Product, status_code=status.HTTP_201_CREATED)
@auth_shield
@admin_required  # Requires admin role
async def create_product(
    product: Product = Body(...),
    user: User = ShieldedDepends(get_authenticated_user)
):
    """Create a new product - admin only"""
    # In a real app, you would save to the database
    # For this example, we just return the product as if it was created
    return product

@app.put("/admin/products/{product_id}", response_model=Product)
@auth_shield
@admin_required  # Requires admin role
async def update_product(
    product_id: int = Path(..., description="The ID of the product to update"),
    product_update: Product = Body(...),
    user: User = ShieldedDepends(get_authenticated_user)
):
    """Update a product - admin only"""
    existing_product = get_product(product_id)
    if not existing_product:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Product with ID {product_id} not found"
        )
    
    # In a real app, you would update the database
    # For this example, we just return the updated product
    return product_update

@app.delete("/admin/products/{product_id}", status_code=status.HTTP_204_NO_CONTENT)
@auth_shield
@admin_required  # Requires admin role
async def delete_product(
    product_id: int = Path(..., description="The ID of the product to delete"),
    user: User = ShieldedDepends(get_authenticated_user)
):
    """Delete a product - admin only"""
    existing_product = get_product(product_id)
    if not existing_product:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Product with ID {product_id} not found"
        )
    
    # In a real app, you would delete from the database
    # For this example, we just return without content
    return None 