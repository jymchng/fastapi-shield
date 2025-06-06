# Type Definitions

The `typing` module contains type definitions and type variables used throughout FastAPI Shield for better type safety and IDE support.

## Module Reference

::: fastapi_shield.typing
    options:
      members: true
      show_root_heading: false
      show_source: false
      heading_level: 3
      docstring_style: google

## Usage

```python
from fastapi_shield.typing import U, EndPointFunc

# U preserves function type signatures
def my_shield_func(request: Request) -> Optional[dict]:
    return {"user": "data"}

# EndPointFunc represents any FastAPI endpoint
def my_endpoint(user_id: int) -> dict:
    return {"user_id": user_id}
``` 