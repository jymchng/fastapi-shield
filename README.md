<div align="center">

<img src="./assets/logos/logo_hori_one.jpg" width=80% height=20%></img>

# FastAPI Shield

## Documentation
<a href="https://docs.fastapi-shield.asyncmove.com">
  <img src="https://img.shields.io/badge/docs-passing-brightgreen.svg" width="100" alt="docs passing">
</a>

### Compatibility and Version
<img src="https://img.shields.io/badge/%3E=python-3.9-blue.svg" alt="Python compat">
<a href="https://pypi.python.org/pypi/fastapi-shield"><img src="https://img.shields.io/pypi/v/fastapi-shield.svg" alt="PyPi"></a>

### CI/CD
<a href="https://codecov.io/github/jymchng/fastapi-shield?branch=main"><img src="https://codecov.io/github/jymchng/fastapi-shield/coverage.svg?branch=main" alt="Coverage"></a>

### License and Issues
<a href="https://github.com/jymchng/fastapi-shield/blob/main/LICENSE"><img src="https://img.shields.io/github/license/jymchng/fastapi-shield" alt="License"></a>
<a href="https://github.com/jymchng/fastapi-shield/issues"><img src="https://img.shields.io/github/issues/jymchng/fastapi-shield" alt="Issues"></a>
<a href="https://github.com/jymchng/fastapi-shield/issues?q=is%3Aissue+is%3Aclosed"><img src="https://img.shields.io/github/issues-closed/jymchng/fastapi-shield" alt="Closed Issues"></a>
<a href="https://github.com/jymchng/fastapi-shield/issues?q=is%3Aissue+is%3Aopen"><img src="https://img.shields.io/github/issues/jymchng/fastapi-shield" alt="Open Issues"></a>

### Development and Quality
<a href="https://github.com/jymchng/fastapi-shield/network/members"><img src="https://img.shields.io/github/forks/jymchng/fastapi-shield" alt="Forks"></a>
<a href="https://github.com/jymchng/fastapi-shield/stargazers"><img src="https://img.shields.io/github/stars/jymchng/fastapi-shield" alt="Stars"></a>
<a href="https://pypi.python.org/pypi/fastapi-shield"><img src="https://img.shields.io/pypi/dm/fastapi-shield" alt="Downloads"></a>
<a href="https://github.com/jymchng/fastapi-shield/graphs/contributors"><img src="https://img.shields.io/github/contributors/jymchng/fastapi-shield" alt="Contributors"></a>
<a href="https://github.com/jymchng/fastapi-shield/commits/main"><img src="https://img.shields.io/github/commit-activity/m/jymchng/fastapi-shield" alt="Commits"></a>
<a href="https://github.com/jymchng/fastapi-shield/commits/main"><img src="https://img.shields.io/github/last-commit/jymchng/fastapi-shield" alt="Last Commit"></a>
<a href="https://github.com/jymchng/fastapi-shield"><img src="https://img.shields.io/github/languages/code-size/jymchng/fastapi-shield" alt="Code Size"></a>
<a href="https://github.com/jymchng/fastapi-shield"><img src="https://img.shields.io/github/repo-size/jymchng/fastapi-shield" alt="Repo Size"></a>
<a href="https://github.com/jymchng/fastapi-shield/watchers"><img src="https://img.shields.io/github/watchers/jymchng/fastapi-shield" alt="Watchers"></a>
<a href="https://github.com/jymchng/fastapi-shield"><img src="https://img.shields.io/github/commit-activity/y/jymchng/fastapi-shield" alt="Activity"></a>
<a href="https://github.com/jymchng/fastapi-shield/pulls"><img src="https://img.shields.io/github/issues-pr/jymchng/fastapi-shield" alt="PRs"></a>
<a href="https://github.com/jymchng/fastapi-shield/pulls?q=is%3Apr+is%3Aclosed"><img src="https://img.shields.io/github/issues-pr-closed/jymchng/fastapi-shield" alt="Merged PRs"></a>
<a href="https://github.com/jymchng/fastapi-shield/pulls?q=is%3Apr+is%3Aopen"><img src="https://img.shields.io/github/issues-pr/open/jymchng/fastapi-shield" alt="Open PRs"></a>

</div>

A powerful, intuitive, and flexible authentication and authorization library for FastAPI applications. Stack your shields to create robust and customizable layers which effectively shields your endpoints from unwanted requests.

# Features

- **Decorator-based Security**: Apply shields as simple decorators to protect your endpoints
- **Layered Protection**: Stack multiple shields for fine-grained access control
- **Clean Design Pattern**: Shields provide a clear and intuitive metaphor for API protection
- **Fully Integrated**: Works seamlessly with FastAPI's dependency injection system
- **Type Safety**: Full type hint support for better IDE integration and code quality
- **Customizable Responses**: Configure error responses when access is denied
- **ShieldedDepends**: Special dependency mechanism for protected resources
- **Lazy-Loading of Dependencies**: Dependencies are only loaded from FastAPI after the request passes through all the decorated shields

# Installation

With `pip`:
```bash
pip install fastapi-shield
```

With `uv`:
```bash
uv add fastapi-shield
```

With `poetry`:
```bash
poetry add fastapi-shield
```

# Basic Usage

## 🛡️ Create your First Shield

Let's create a simple `@auth_shield` to shield against unauthenticated requests! 🛡️

```python
from fastapi import Header
from fastapi_shield import shield

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
```

Now that you've created your first shield, you can easily apply it to any FastAPI endpoint! 🚀

The shield acts as a decorator that protects your endpoint from unauthorized access. 

When a request comes in, the shield evaluates the API token before the endpoint function is called.

If the token is invalid (returning None), the request is blocked! 🚫 

This creates a clean separation between authentication logic and business logic, making your code more maintainable.

Just like a real shield, it stands in front of your endpoint to protect it! 💪


## See your First Shield in Action

Now let's see how our shield works in the wild! 🚀 When a user tries to access the protected endpoint, the shield jumps into action like a superhero! 🦸‍♀️

```python
from fastapi import FastAPI

app = FastAPI()

# Protected endpoint - requires authentication
@app.get("/protected/{name}")
@auth_shield # apply `@auth_shield`
async def protected_endpoint(name: str):
    return {
        "message": f"Hello {name}. This endpoint is protected!",
    }
```

```python
from fastapi.testclient import TestClient

client = TestClient(app)

def test_protected():
    client = TestClient(app)
    response = client.get("/protected/John", headers={"API-TOKEN": "valid_token"})
    assert response.status_code == 200
    assert response.json() == {"message": "Hello John. This endpoint is protected!"}


def test_protected_unauthorized():
    client = TestClient(app)
    response = client.get("/protected/John", headers={"API-TOKEN": "invalid_token"})
    assert response.status_code == 500
    assert response.json() == {'detail': 'Shield with name `unknown` blocks the request'}, response.json()
```

From the above, we can see how the shield works in practice. The `auth_shield` decorator is applied to our endpoint, checking the API token in the request headers before allowing access to the protected endpoint. When a valid token is provided, the request proceeds normally and returns a friendly greeting. However, when an invalid token is sent, the shield blocks the request, returning a 500 error with a message indicating that the shield has prevented access. This demonstrates the power of shields as a clean, declarative way to implement authentication in FastAPI applications without cluttering your endpoint logic with authorization checks.

<div align="center">
  <img src="./assets/pictures/IMG_20250423_003431_018.jpg" alt="Shield Congratulations" width="40%">
  
  ### 🎉 Congratulations! You've made your First Wonderful Shield! 🎉
</div>

## Your Second Shield! 🛡️🛡️

First, let's see what's the final endpoint is going to look like:

```python
@app.get("/products")
@auth_shield
@roles_shield(["user"])
async def get_all_products(db: Dict[str, Any]=Depends(get_db), username: str=ShieldedDepends(get_username_from_payload)):
    """Only user with role `user` can get their own product"""
    products = list(map(lambda name: db["products"][name], db["users"][username]["products"]))
    return {
        "message": f"These are your products: {products}",
    }
```

We're going to make the `@roles_shield(["user"])`.

But before that, there's one point to note: one of the advantages of `fastapi-shield` is that it enables lazy injection of FastAPI's dependencies.

In the signature of the endpoint: `async def get_all_products(db: Dict[str, Any]=Depends(get_db), username: str=ShieldedDepends(get_username_from_payload))`, the `db: Dict[str, Any]=Depends(get_db)` is only injected after `@roles_shield(["user"])` becomes 'unblocked', i.e. allowing the request to reach the endpoint `get_all_products`.

Prior to that, if the request is blocked by any of the decoratored shields, e.g. `@auth_shield` and `@roles_shield(["user"])`, then the FastAPI's dependencies are not injected. We will discuss this in more detail later, on why this is an advantage compared to other decorators-based libraries.

Let's see how the `@roles_shield(["user"])` is written.

```python
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
```

The `roles_shield` function is a shield factory that creates a shield for role-based access control. It takes a list of roles as input and returns a shield function. 

The inner `wrapper` function of `roles_shield` uses `ShieldedDepends` to get the payload from the token, which contains user information including their roles.

The shield then checks if any of the user's roles match the required roles using the `any()` function with a generator expression. 

If there's a match, it returns the payload, allowing the request to proceed. If no matching role is found, it returns `None`, which blocks the request. 

This pattern demonstrates how shields can be composed and parameterized to create flexible authorization rules. 

### What is `ShieldedDepends`?

`ShieldedDepends` is a mechanism to pass information from a `Shield` to a dependency to retrieve it.

It is a specialized dependency injection class that extends FastAPI's `Security` class. `ShieldedDepends` is used to inject dependencies that should only be resolved if a shield allows the request to proceed. It takes a callable function as its `shielded_dependency` parameter.

The `shielded_dependency` function:
1. Can be synchronous or asynchronous (coroutine)
2. Should accept parameters that can be resolved by FastAPI's dependency injection system
3. Will only be executed when the shield is "unblocked" (when the shield function returns a truthy value)
4. Can access request information and other dependencies just like regular FastAPI dependencies

### How `ShieldedDepends` Passes Data Between Shields

One powerful feature of `ShieldedDepends` is its ability to pass data between shields in a decorator chain, from top decorator to the lower ones.

When a shield returns a value (other than `None`), that value can be captured and used by subsequent shields, via the `ShieldedDepends` dependencies specified in the function signature of the shield, or by the endpoint function itself via the same mechanism.

When a shield is blocked, the `ShieldedDepends` instance returns itself instead of executing the dependency function, preventing unnecessary computation and database access. This lazy evaluation is one of the key advantages of the `fastapi-shield` library.

For example, in our `get_payload_from_token` function (which is an argument to be passed into `ShieldedDepends` function; seen on the line `def wrapper(payload = ShieldedDepends(get_payload_from_token)): ...`):

```python
def get_payload_from_token(token: str):
    if token == "admin_token":
        return {"username": "Peter", "roles": ["admin", "user"]}
    elif token == "user_token":
        return {"username": "John", "roles": ["user"]}
    return None
```

The `token` parameter will be passed by the guard function of the `shield` decorating it.

```python
@shield
def auth_shield(api_token: str = Header()):
    """
    A basic shield that validates an API token.
    Returns the token if valid, otherwise returns None which blocks the request.
    """
    if api_token in ("admin_token", "user_token"):
        return api_token
    return None
```

The guard function of `auth_shield` returns the `api_token` which is then passed into `get_payload_from_token` shielded dependency function of the `roles_shield`.

```python
@app.get("/products")
@auth_shield
@roles_shield(["user"])
async def get_all_products(db: Dict[str, Any]=Depends(get_db), username: str=ShieldedDepends(get_username_from_payload)):
    """Only user with role `user` can get their own product"""
    products = list(map(lambda name: db["products"][name], db["users"][username]["products"]))
    return {
        "message": f"These are your products: {products}",
    }
```

The `ShieldedDepends` ensures that the payload is only retrieved if previous shields in the chain (like `auth_shield`) have already passed.


## Advanced Example

Check out the complete product catalog API example in the [`examples/app`](examples/app) directory, which demonstrates:

- Authentication with token-based shields
- Role-based access control
- Protecting user information
- Admin-only operations for products
- Testing protected endpoints with TestClient

```python
# Shield for requiring specific roles
def roles_required(roles: List[str]):
    """
    Role-based authorization shield that checks if the authenticated user
    has any of the required roles.
    """
    @shield
    def role_shield(token: str = ShieldedDepends(lambda t: t)):
        token_data = get_token_data(token)
        user_roles = token_data.get("roles", [])
        
        # Check if user has any of the required roles
        if any(role in user_roles for role in roles):
            return token_data
        
        # No matching roles, return None to block the request
        return None
        
    return role_shield

# Shortcut shields for common role checks
admin_required = roles_required(["admin"])
user_required = roles_required(["user", "admin"])
```

## Documentation

Visit our documentation for more details:

- **Getting Started**: Installation, basic usage, and core concepts
- **Shields Guide**: Understanding the Shield pattern
- **Authentication**: Token-based, OAuth, and custom authentication shields
- **Authorization**: Role-based access control and permission shields
- **Advanced Usage**: Complex security scenarios and custom shield creation, e.g. rate limiting shield
- **Examples**: Complete application examples

## How It Works

FastAPI Shield uses a layered decorator pattern to apply security checks:

1. **Define Shields**: Create functions decorated with `@shield` that blocks or passes requests after evaluating the guard function of the shield
2. **Stack Shields**: Apply multiple shields to endpoints in the desired order
3. **Access Protected Resources**: Use `ShieldedDepends` to access data from successful shields and retrieve dependencies
4. **Handle Failures**: Customize error responses when shield validation fails

Each shield acts as an independent layer of security that can:
- Allow the request to continue when it passes validation (returns a value)
- Block the request when validation fails (returns `None`)
- Pass state to dependent shields (via `ShieldedDepends`)

## Development

### Prerequisites

- Python 3.9 or higher
- FastAPI 0.100.1 or higher

### Install Development Dependencies

```bash
pip install uv
uv sync --dev
```

### Building from Source

```bash
git clone https://github.com/jimchng/fastapi-shield.git
cd fastapi-shield
pip install uv
uv sync --dev
```

### Running Tests

```bash
# Install `uv`
pip install uv

# Install `nox`
uv add --dev nox

# OR
uv tool install nox

# Run all tests
uv run python -m nox -s test

# OR
uv tool run nox -s test

# Run specific test suite
nox -s test -- tests/test_basics.py
```

### Release

Run the following commands:

1. `nox -s release-check` - this checks if the library is fit for release.
2. `nox -s release` - this builds the library, update the tag and commits it.
3. `git push origin main` - this pushes the repository to GitHub on branch `main`.
4. `git push origin <tag-name>` - this pushes the tag with `<tag-name>` to GitHub.
5. `nox -s publish` - this publishes the library to PYPI.

## Contributing

We welcome contributions! Please see our Contributing Guide for details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

Special thanks to all contributors who have helped shape this project.
