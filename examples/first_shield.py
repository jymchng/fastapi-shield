from typing import Dict, Any
from fastapi import Header, Depends, FastAPI
from fastapi_shield import shield, ShieldedDepends
from fastapi.testclient import TestClient

# Create a simple authentication shield
@shield
def auth_shield(api_token: str = Header()):
    """
    A basic shield that validates an API token.
    Returns the token if valid, otherwise returns None which blocks the request.
    """
    if api_token in ("admin_token", "user_token"):
        return api_token
    return None

# Create a simple roles shield
def roles_shield(roles: list[str]):
    """
    A shield that validates a list of roles.
    """
    
    @shield
    def wrapper(payload = ShieldedDepends(get_payload_from_token)):
        if any(role in payload["roles"] for role in roles):
            return payload
        return None
    
    return wrapper


def get_payload_from_token(token: str):
    if token == "admin_token":
        return {"username": "Peter", "roles": ["admin", "user"]}
    elif token == "user_token":
        return {"username": "John", "roles": ["user"]}
    return None


def get_username_from_payload(payload: Dict[str, Any]):
    return payload["username"]


def get_db():
    return {
        "users": {
            "John": {
                "username": "John",
                "roles": ["user"],
                "products": ["product_1"],
                "token": "user_token"
            },
            "Peter": {
                "username": "Peter",
                "roles": ["admin", "user"],
                "products": ["product_2"],
                "token": "admin_token"
            }
        },
        "products": {
            "product_1": {
                "owner": "John",
                "name": "Product 1",
                "price": 100
            },
            "product_2": {
                "owner": "Peter",
                "name": "Product 2",
                "price": 200
            }
        }
    }


app = FastAPI()


# Protected endpoint - requires authentication
@app.get("/protected/{name}")
@auth_shield # apply `@auth_shield`
async def protected_endpoint(name: str):
    # `get_db` is only injected by FastAPI **after** the request made it through the `@auth_shield`!
    return {
        "message": f"Hello {name}. This endpoint is protected!",
    }


def test_protected():
    client = TestClient(app)
    response = client.get("/protected/John", headers={"API-TOKEN": "admin_token"})
    assert response.status_code == 200
    assert response.json() == {"message": "Hello John. This endpoint is protected!"}


def test_protected_unauthorized():
    client = TestClient(app)
    response = client.get("/protected/John", headers={"API-TOKEN": "invalid_token"})
    assert response.status_code == 500
    assert response.json() == {'detail': 'Shield with name `unknown` blocks the request'}, response.json()


def test_protected_roles():
    client = TestClient(app)
    response = client.get("/protected/John", headers={"API-TOKEN": "admin_token"})
    assert response.status_code == 200
    assert response.json() == {"message": "Hello John. This endpoint is protected!"}


@app.get("/products")
@auth_shield
@roles_shield(["user"])
async def get_all_products(db: Dict[str, Any]=Depends(get_db), username: str=ShieldedDepends(get_username_from_payload)):
    """Only user with role `user` can get their own product"""
    products = list(map(lambda name: db["products"][name], db["users"][username]["products"]))
    return {
        "message": f"These are your products: {products}",
    }
    
    
def test_get_all_products_john():
    client = TestClient(app)
    response = client.get("/products", headers={"API-TOKEN": "user_token"})
    assert response.status_code == 200, response.json()
    assert response.json() == {"message": "These are your products: [{'owner': 'John', 'name': 'Product 1', 'price': 100}]"}, response.json()
    
    
def test_get_all_products_peter():
    client = TestClient(app)
    response = client.get("/products", headers={"API-TOKEN": "admin_token"})
    assert response.status_code == 200, response.json()
    assert response.json() == {"message": "These are your products: [{'owner': 'Peter', 'name': 'Product 2', 'price': 200}]"}
    

def test_get_all_products_unauthorized():
    client = TestClient(app)
    response = client.get("/products", headers={"API-TOKEN": "invalid_token"})
    assert response.status_code == 500
    assert response.json() == {'detail': 'Shield with name `unknown` blocks the request'}, response.json()


def run_tests():
    for k, fn in globals().items():
        if callable(fn) and k.startswith("test_"):
            print(f"Running test `{k}` in {__file__}")
            fn()


if __name__ == "__main__":
    # uv tool run nox -s run-examples
    run_tests()
