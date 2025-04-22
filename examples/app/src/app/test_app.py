from fastapi.testclient import TestClient

from app import app
from database import PRODUCTS_DB

client = TestClient(app)

# Test cases for public endpoints
def test_root_endpoint():
    """Test the root endpoint which is accessible to everyone"""
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Welcome to the FastAPI Shield Example API"}

def test_list_products():
    """Test the public endpoint for listing products"""
    response = client.get("/products")
    assert response.status_code == 200
    products = response.json()
    assert len(products) == len(PRODUCTS_DB)

def test_get_product_by_id():
    """Test getting a specific product by ID"""
    product_id = 1
    response = client.get(f"/products/{product_id}")
    assert response.status_code == 200
    product = response.json()
    assert product["id"] == product_id
    assert product["name"] == "Laptop"

def test_get_nonexistent_product():
    """Test getting a product that doesn't exist"""
    response = client.get("/products/999")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"]

# Test cases for authentication
def test_login_valid_credentials():
    """Test login with valid credentials"""
    response = client.post("/token", json={"username": "admin", "password": "admin_password"})
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["access_token"] == "admin_token"

def test_login_invalid_credentials():
    """Test login with invalid credentials"""
    response = client.post("/token", json={"username": "admin", "password": "wrong_password"})
    assert response.status_code == 401
    assert "Invalid username or password" in response.json()["detail"]

# Test cases for authenticated endpoints
def test_get_current_user_no_token():
    """Test attempting to access protected endpoint without a token"""
    response = client.get("/me")
    assert response.status_code == 422, (response.status_code, response.json())  # Default error for shield failure
    assert response.json() ==  {'detail': [{'type': 'missing', 'loc': ['header', 'x-api-token'], 'msg': 'Field required', 'input': None}]}, response.json()

def test_get_current_user_with_token():
    """Test getting the current user with valid token"""
    response = client.get(
        "/me",
        headers={"X-API-Token": "admin_token"}
    )
    assert response.status_code == 200
    user = response.json()
    assert user["username"] == "admin"
    assert "admin" in user["roles"]

def test_get_current_user_with_invalid_token():
    """Test with an invalid token"""
    response = client.get(
        "/me",
        headers={"X-API-Token": "invalid_token"}
    )
    assert response.status_code == 500  # Default error for shield failure

# Test cases for role-based access
def test_protected_products_admin_access():
    """Test admin accessing user-level protected endpoint"""
    response = client.get(
        "/protected/products",
        headers={"X-API-Token": "admin_token"}
    )
    assert response.status_code == 200
    products = response.json()
    assert len(products) == len(PRODUCTS_DB)

def test_protected_products_user_access():
    """Test regular user accessing user-level protected endpoint"""
    response = client.get(
        "/protected/products",
        headers={"X-API-Token": "user1_token"}
    )
    assert response.status_code == 200
    products = response.json()
    assert len(products) == len(PRODUCTS_DB)

def test_protected_products_guest_access():
    """Test guest user accessing user-level protected endpoint (should fail)"""
    response = client.get(
        "/protected/products",
        headers={"X-API-Token": "guest_token"}
    )
    assert response.status_code == 500  # Default error for shield failure

# Test cases for admin-only endpoints
def test_create_product_admin():
    """Test admin creating a product"""
    new_product = {
        "id": 6,
        "name": "Smartwatch",
        "description": "Fitness tracker with smart features",
        "price": 199.99,
        "category": "Electronics",
        "in_stock": True
    }
    response = client.post(
        "/admin/products",
        json=new_product,
        headers={"X-API-Token": "admin_token"}
    )
    assert response.status_code == 201
    product = response.json()
    assert product["name"] == new_product["name"]

def test_create_product_user():
    """Test regular user creating a product (should fail)"""
    new_product = {
        "id": 7,
        "name": "Tablet",
        "description": "Portable tablet",
        "price": 299.99,
        "category": "Electronics",
        "in_stock": True
    }
    response = client.post(
        "/admin/products",
        json=new_product,
        headers={"X-API-Token": "user1_token"}
    )
    assert response.status_code == 500  # Default error for shield failure

def test_update_product_admin():
    """Test admin updating a product"""
    product_update = {
        "id": 1,
        "name": "Updated Laptop",
        "description": "Even more powerful laptop for developers",
        "price": 1499.99,
        "category": "Electronics",
        "in_stock": True
    }
    response = client.put(
        "/admin/products/1",
        json=product_update,
        headers={"X-API-Token": "admin_token"}
    )
    assert response.status_code == 200
    product = response.json()
    assert product["name"] == "Updated Laptop"
    assert product["price"] == 1499.99

def test_delete_product_admin():
    """Test admin deleting a product"""
    response = client.delete(
        "/admin/products/1",
        headers={"X-API-Token": "admin_token"}
    )
    assert response.status_code == 204
    # Should return no content

def test_delete_product_user():
    """Test regular user deleting a product (should fail)"""
    response = client.delete(
        "/admin/products/2",
        headers={"X-API-Token": "user1_token"}
    )
    assert response.status_code == 500  # Default error for shield failure

if __name__ == "__main__":
    # Run tests
    test_create_product_admin()
    test_create_product_user()
    test_update_product_admin()
    test_delete_product_admin()
    test_delete_product_user()

    test_protected_products_admin_access()
    test_protected_products_user_access()
    test_protected_products_guest_access()

    test_get_current_user_no_token()
    test_get_current_user_with_token()
    test_get_current_user_with_invalid_token()
    
    test_list_products()
    test_get_product_by_id()
    test_get_nonexistent_product()

    test_login_valid_credentials()
    test_login_invalid_credentials()
    
    
    