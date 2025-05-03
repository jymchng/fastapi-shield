from typing import List, Optional

from database import get_token_data, get_user_by_username, validate_token
from fastapi import Header
from models import User

from fastapi_shield import ShieldedDepends, shield


# Authentication shield that validates the token in the Authorization header
@shield
def auth_shield(x_api_token: Optional[str] = Header()):
    """
    Authentication shield that validates the token from the x_api_token header.
    Returns the token if valid, otherwise returns None which will block the request.
    """
    if not x_api_token:
        return None

    if validate_token(x_api_token):
        return x_api_token

    return None


# Shield for requiring specific roles
def roles_required(roles: List[str]):
    """
    Role-based authorization shield that checks if the authenticated user
    has any of the required roles.
    """

    @shield
    def role_shield(token_data: dict = ShieldedDepends(get_token_data)):
        user_roles = token_data.get("roles", [])

        # Check if user has any of the required roles
        if any(role in user_roles for role in roles):
            return token_data

        # No matching roles, return None to block the request
        return None

    return role_shield


def get_current_user_from_token(token: str):
    """
    Get the current user from the token.
    """
    token_data = get_token_data(token)
    return get_authenticated_user(token_data)


def get_authenticated_user(token_data: dict):
    """
    Shield that retrieves the authenticated user based on the token.
    """
    username = token_data.get("username")
    user = get_user_by_username(username)

    if not user:
        return None

    # Return a User model, excluding the password
    return User(id=user.id, username=user.username, email=user.email, roles=user.roles)


# Shortcut shields for common role checks
admin_required = roles_required(["admin"])
user_required = roles_required(
    ["user", "admin"]
)  # Both admin and user roles can access
