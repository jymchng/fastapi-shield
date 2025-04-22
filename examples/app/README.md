# FastAPI Shield Example Application

This is an example application that demonstrates how to use FastAPI Shield for authentication and authorization in a FastAPI application.

## Overview

The application provides a simple product catalog API with various endpoints protected by different authorization levels:

- **Public endpoints**: Available to everyone
- **User-level endpoints**: Require authentication and a user role
- **Admin-only endpoints**: Require authentication and an admin role

## Components

### Models

- `Product`: Represents a product in the catalog
- `User`: Represents a user of the API
- `UserInDB`: Extended user model that includes password
- `TokenResponse`: Response model for authentication tokens

### Shields

- `auth_shield`: Basic authentication shield that validates tokens
- `roles_required`: Shield factory that creates role-based shields
- `get_authenticated_user`: Shield that retrieves the current user
- Shortcut shields: `admin_required` and `user_required`

### Endpoints

- **Public**: `/`, `/products`, `/products/{product_id}`
- **Authentication**: `/token` (POST)
- **Protected**: `/me`
- **User-level**: `/protected/products`
- **Admin-only**: `/admin/products`, `/admin/products/{product_id}`

## Mock Database

The application uses in-memory data structures to simulate a database:

- `PRODUCTS_DB`: Collection of products
- `USERS_DB`: Collection of users with credentials
- `TOKENS_DB`: Collection of tokens and associated user data

## Testing

The application includes comprehensive tests (`test_app.py`) using FastAPI's TestClient:

- Tests for public endpoints
- Tests for authentication logic
- Tests for protected endpoints
- Tests for role-based access control

## Running the Application

To run the application:

```bash
# Install dependencies
pip install fastapi uvicorn

# Run the application
uvicorn app.app:app --reload
```

## Testing

To run the tests:

```bash
# Install test dependencies
pip install pytest

# Run tests
pytest app/test_app.py -v
```

## API Documentation

When running the application, you can access the automatic API documentation at:

- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc` 