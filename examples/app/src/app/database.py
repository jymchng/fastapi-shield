from models import Product, UserInDB

# Mock product database
PRODUCTS_DB = {
    1: Product(
        id=1,
        name="Laptop",
        description="Powerful laptop for developers",
        price=1299.99,
        category="Electronics",
        in_stock=True
    ),
    2: Product(
        id=2,
        name="Smartphone",
        description="Latest smartphone with high-end camera",
        price=799.99,
        category="Electronics",
        in_stock=True
    ),
    3: Product(
        id=3,
        name="Coffee Maker",
        description="Automatic coffee maker for home use",
        price=149.99,
        category="Home Appliances",
        in_stock=False
    ),
    4: Product(
        id=4,
        name="Headphones",
        description="Noise-cancelling wireless headphones",
        price=249.99,
        category="Electronics",
        in_stock=True
    ),
    5: Product(
        id=5,
        name="Desk Chair",
        description="Ergonomic office chair",
        price=199.99,
        category="Furniture",
        in_stock=True
    ),
}

# Mock user database
USERS_DB = {
    "admin": UserInDB(
        id=1,
        username="admin",
        email="admin@example.com",
        roles=["admin", "user"],
        password="admin_password"  # In a real app, this would be hashed
    ),
    "user1": UserInDB(
        id=2,
        username="user1",
        email="user1@example.com",
        roles=["user"],
        password="user1_password"  # In a real app, this would be hashed
    ),
    "guest": UserInDB(
        id=3,
        username="guest",
        email="guest@example.com",
        roles=["guest"],
        password="guest_password"  # In a real app, this would be hashed
    ),
}

# Mock tokens database
TOKENS_DB = {
    "admin_token": {"username": "admin", "roles": ["admin", "user"]},
    "user1_token": {"username": "user1", "roles": ["user"]},
    "guest_token": {"username": "guest", "roles": ["guest"]},
}

# Utility functions for working with the mock databases
def get_product(product_id: int) -> Product:
    return PRODUCTS_DB.get(product_id)

def get_all_products() -> list[Product]:
    return list(PRODUCTS_DB.values())

def get_user_by_username(username: str) -> UserInDB:
    return USERS_DB.get(username)

def get_user_from_token(token: str) -> UserInDB:
    if token not in TOKENS_DB:
        return None
    username = TOKENS_DB[token]["username"]
    return get_user_by_username(username)

def validate_token(token: str) -> bool:
    return token in TOKENS_DB

def get_token_data(token: str) -> dict:
    return TOKENS_DB.get(token) 