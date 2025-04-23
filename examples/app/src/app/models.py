from typing import List, Optional

from pydantic import BaseModel, Field


class Product(BaseModel):
    id: int
    name: str
    description: str
    price: float
    category: str
    in_stock: bool = True
    
    class Config:
        schema_extra = {
            "example": {
                "id": 1,
                "name": "Laptop",
                "description": "Powerful laptop for developers",
                "price": 1299.99,
                "category": "Electronics",
                "in_stock": True
            }
        }

class User(BaseModel):
    id: int
    username: str
    email: str
    roles: List[str] = ["user"]
    
    class Config:
        schema_extra = {
            "example": {
                "id": 1,
                "username": "johndoe",
                "email": "john@example.com",
                "roles": ["user"]
            }
        }

class UserInDB(User):
    password: str  # This would be hashed in a real application
    
class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer" 