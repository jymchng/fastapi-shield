<!-- Examples tested -->

# Request Validation

FastAPI Shield provides powerful mechanisms to validate incoming requests beyond what Pydantic offers, allowing for complex validation rules, custom error messaging, and request transformation.

## Basic Request Validation

```python
from fastapi import FastAPI, Depends, HTTPException
from typing import NewType, Annotated, List, Dict, Any
from pydantic import BaseModel, Field, EmailStr, validator
from fastapi_shield import shield, Shield

app = FastAPI()

# Define a model for the request
class UserRegistration(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8)
    confirm_password: str
    
    @validator('confirm_password')
    def passwords_match(cls, v, values):
        if 'password' in values and v != values['password']:
            raise ValueError('Passwords do not match')
        return v

# Define a validated request type
ValidatedRegistration = NewType("ValidatedRegistration", UserRegistration)

# Create a shield to validate the request
@shield
def validate_registration(registration: UserRegistration) -> ValidatedRegistration:
    # Check if username exists in database (mock check)
    if registration.username == "existing_user":
        raise HTTPException(status_code=400, detail="Username already exists")
    
    # Check if email exists in database (mock check)
    if registration.email == "existing@example.com":
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Additional complex validation can be performed here
    
    return ValidatedRegistration(registration)

# Use the shield in an endpoint
@app.post("/register")
def register_user(registration: ValidatedRegistration = Depends(validate_registration)):
    # Process the validated registration
    return {"message": "User registered successfully"}
```

## Input Sanitization

Use shields to sanitize input data before processing:

```python
from fastapi import FastAPI, Depends
from typing import NewType, Annotated, Dict, Any
from pydantic import BaseModel
from fastapi_shield import shield, Shield
import re
import html

app = FastAPI()

# Define a model for the request
class Comment(BaseModel):
    user_id: int
    content: str

# Define a sanitized comment type
SanitizedComment = NewType("SanitizedComment", Comment)

# Shield to sanitize content
@shield
def sanitize_comment(comment: Comment) -> SanitizedComment:
    # Escape HTML to prevent XSS
    sanitized_content = html.escape(comment.content)
    
    # Remove unwanted patterns (e.g., excessive whitespace)
    sanitized_content = re.sub(r'\s+', ' ', sanitized_content).strip()
    
    # Create a new comment with sanitized content
    sanitized_comment = Comment(user_id=comment.user_id, content=sanitized_content)
    
    return SanitizedComment(sanitized_comment)

# Use the shield in an endpoint
@app.post("/comments")
def create_comment(comment: SanitizedComment = Depends(sanitize_comment)):
    # Store the sanitized comment
    return {"message": "Comment created", "comment": comment}
```

## Request Transformation

Shields can transform requests before they reach your business logic:

```python
from fastapi import FastAPI, Depends, Query
from typing import NewType, Annotated, List, Dict, Any, Optional
from pydantic import BaseModel
from fastapi_shield import shield, Shield

app = FastAPI()

# Define a model for the API response
class SearchParams(BaseModel):
    query: str
    page: int = 1
    per_page: int = 10
    sort_by: Optional[str] = None
    filters: Dict[str, Any] = {}

# Define a normalized search params type
NormalizedSearchParams = NewType("NormalizedSearchParams", SearchParams)

# Shield to normalize search parameters
@shield
def normalize_search_params(
    query: str,
    page: int = Query(1, ge=1),
    per_page: int = Query(10, ge=1, le=100),
    sort_by: Optional[str] = None,
    category: Optional[str] = None,
    min_price: Optional[float] = None,
    max_price: Optional[float] = None,
) -> NormalizedSearchParams:
    # Normalize the query
    normalized_query = query.lower().strip()
    
    # Build filters dictionary
    filters = {}
    if category:
        filters["category"] = category
    
    if min_price is not None or max_price is not None:
        price_filter = {}
        if min_price is not None:
            price_filter["min"] = min_price
        if max_price is not None:
            price_filter["max"] = max_price
        filters["price"] = price_filter
    
    # Create search params object
    search_params = SearchParams(
        query=normalized_query,
        page=page,
        per_page=per_page,
        sort_by=sort_by,
        filters=filters
    )
    
    return NormalizedSearchParams(search_params)

# Use the shield in an endpoint
@app.get("/search")
def search(params: NormalizedSearchParams = Depends(normalize_search_params)):
    # Use the normalized search parameters
    return {
        "query": params.query,
        "page": params.page,
        "per_page": params.per_page,
        "sort_by": params.sort_by,
        "filters": params.filters,
        "results": [
            # In a real application, you would query a database
            {"id": 1, "name": "Example result 1"},
            {"id": 2, "name": "Example result 2"}
        ]
    }
```

## Contextual Validation

Validation that depends on the current state of the application or external resources:

```python
from fastapi import FastAPI, Depends, HTTPException, Header
from typing import NewType, Annotated, Optional
from pydantic import BaseModel
from fastapi_shield import shield, Shield
import time
from datetime import datetime, timedelta

app = FastAPI()

# Define a model for a time-sensitive operation
class TimeSensitiveOperation(BaseModel):
    operation_id: str
    timestamp: int  # Unix timestamp

# Define a validated operation type
ValidatedOperation = NewType("ValidatedOperation", TimeSensitiveOperation)

# Mock database of recent operations
recent_operations = set()

# Shield to validate the operation
@shield
def validate_operation(
    operation: TimeSensitiveOperation,
    x_request_timestamp: Optional[str] = Header(None)
) -> ValidatedOperation:
    # Validate timestamp is recent (within 5 minutes)
    current_time = int(time.time())
    max_age = 300  # 5 minutes in seconds
    
    if operation.timestamp < (current_time - max_age):
        raise HTTPException(
            status_code=400, 
            detail="Operation timestamp too old"
        )
    
    # Validate operation hasn't been processed before (prevent replay)
    if operation.operation_id in recent_operations:
        raise HTTPException(
            status_code=400, 
            detail="Operation already processed"
        )
    
    # Add operation to recent operations
    recent_operations.add(operation.operation_id)
    
    # Clean up old operations (in a real app, you would use a time-based cache)
    if len(recent_operations) > 1000:
        recent_operations.clear()
    
    return ValidatedOperation(operation)

# Use the shield in an endpoint
@app.post("/operations")
def perform_operation(operation: ValidatedOperation = Depends(validate_operation)):
    # Process the validated operation
    return {"status": "success", "operation_id": operation.operation_id}
```

## Combining Multiple Validations

You can chain shields to apply multiple validations:

```python
from fastapi import FastAPI, Depends, HTTPException
from typing import NewType, Annotated, List, Dict, Any
from pydantic import BaseModel, Field
from fastapi_shield import shield, Shield

app = FastAPI()

# Define a model for the request
class Product(BaseModel):
    name: str
    description: str
    price: float
    stock: int
    categories: List[str]

# Define specialized product types
ValidatedProduct = NewType("ValidatedProduct", Product)
SanitizedProduct = NewType("SanitizedProduct", ValidatedProduct)
EnrichedProduct = NewType("EnrichedProduct", SanitizedProduct)

# Shield to validate product data
@shield
def validate_product(product: Product) -> ValidatedProduct:
    if product.price <= 0:
        raise HTTPException(status_code=400, detail="Price must be positive")
    
    if product.stock < 0:
        raise HTTPException(status_code=400, detail="Stock cannot be negative")
    
    if len(product.categories) == 0:
        raise HTTPException(status_code=400, detail="At least one category is required")
    
    return ValidatedProduct(product)

# Shield to sanitize product data
@shield
def sanitize_product(product: ValidatedProduct) -> SanitizedProduct:
    # Sanitize name and description
    sanitized_name = product.name.strip()
    sanitized_description = product.description.strip()
    
    # Normalize categories
    sanitized_categories = [cat.lower().strip() for cat in product.categories]
    
    # Create sanitized product
    sanitized_product = Product(
        name=sanitized_name,
        description=sanitized_description,
        price=product.price,
        stock=product.stock,
        categories=sanitized_categories
    )
    
    return SanitizedProduct(sanitized_product)

# Shield to enrich product data
@shield
def enrich_product(product: SanitizedProduct) -> EnrichedProduct:
    # In a real application, you might add additional data
    # such as tax information, availability, etc.
    return EnrichedProduct(product)

# Combine all shields
def process_product(product: Product) -> EnrichedProduct:
    validated = validate_product(product)
    sanitized = sanitize_product(validated)
    return enrich_product(sanitized)

# Use the combined shield in an endpoint
@app.post("/products")
def create_product(product: EnrichedProduct = Depends(process_product)):
    # Store the processed product
    return {"message": "Product created", "product": product}
```

## Form Validation

Validate form data with shields:

```python
from fastapi import FastAPI, Depends, Form, HTTPException
from typing import NewType, Annotated, Optional
from fastapi_shield import shield, Shield
import re

app = FastAPI()

# Define a validated contact form type
ValidatedContactForm = NewType("ValidatedContactForm", dict)

# Shield to validate contact form
@shield
def validate_contact_form(
    name: str = Form(...),
    email: str = Form(...),
    message: str = Form(...),
    phone: Optional[str] = Form(None)
) -> ValidatedContactForm:
    # Validate name
    if len(name) < 2:
        raise HTTPException(status_code=400, detail="Name is too short")
    
    # Validate email
    email_pattern = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
    if not email_pattern.match(email):
        raise HTTPException(status_code=400, detail="Invalid email format")
    
    # Validate message
    if len(message) < 10:
        raise HTTPException(status_code=400, detail="Message is too short")
    
    # Validate phone if provided
    if phone:
        # Simple validation - in a real app, use a proper phone validation library
        phone_pattern = re.compile(r'^\+?[0-9\s\-\(\)]{8,20}$')
        if not phone_pattern.match(phone):
            raise HTTPException(status_code=400, detail="Invalid phone format")
    
    # Return validated form data
    form_data = {
        "name": name,
        "email": email,
        "message": message,
        "phone": phone
    }
    
    return ValidatedContactForm(form_data)

# Use the shield in an endpoint
@app.post("/contact")
def submit_contact_form(form: ValidatedContactForm = Depends(validate_contact_form)):
    # Process the validated form
    return {"message": "Form submitted successfully"}
```

## Validation with External Services

Perform validation using external services or APIs:

```python
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from typing import NewType, Annotated
from pydantic import BaseModel, EmailStr
from fastapi_shield import shield, Shield
import httpx

app = FastAPI()

# Define a model for the request
class EmailSubscription(BaseModel):
    email: EmailStr
    name: str

# Define a validated subscription type
ValidatedSubscription = NewType("ValidatedSubscription", EmailSubscription)

# Mock function to check if email is disposable
async def is_disposable_email(email: str) -> bool:
    # In a real application, you would call an API like:
    # async with httpx.AsyncClient() as client:
    #     response = await client.get(f"https://disposable-email-checker.example.com/api/check/{email}")
    #     return response.json().get("disposable", False)
    
    # For this example, we'll just check for common disposable domains
    disposable_domains = ["tempmail.com", "throwaway.com", "mailinator.com"]
    domain = email.split("@")[1]
    return domain in disposable_domains

# Shield to validate the subscription
@shield
async def validate_subscription(
    subscription: EmailSubscription,
    background_tasks: BackgroundTasks
) -> ValidatedSubscription:
    # Check if email is disposable
    if await is_disposable_email(subscription.email):
        raise HTTPException(
            status_code=400, 
            detail="Disposable email addresses are not allowed"
        )
    
    # Schedule email verification in background
    def send_verification_email(email: str, name: str):
        # In a real application, you would send an email
        print(f"Sending verification email to {email}")
    
    background_tasks.add_task(
        send_verification_email, 
        subscription.email, 
        subscription.name
    )
    
    return ValidatedSubscription(subscription)

# Use the shield in an endpoint
@app.post("/subscribe")
async def subscribe(
    subscription: ValidatedSubscription = Depends(validate_subscription)
):
    # Process the validated subscription
    return {"message": "Subscription pending verification"}
```

## Best Practices

1. **Separate concerns**: Keep validation logic separate from business logic.
2. **Reuse shields**: Create reusable validation shields for common patterns.
3. **Type safety**: Use `NewType` to create distinct types for validated data.
4. **Fail fast**: Validate as early as possible in the request lifecycle.
5. **Provide clear errors**: Return descriptive error messages to help clients.
6. **Sanitize input**: Always sanitize user input to prevent security issues.
7. **Validate extensively**: Don't trust client-side validation alone.
8. **Layer validations**: Chain shields to build complex validation pipelines.
9. **Performance**: For expensive validations, consider caching or background processing.
10. **Testing**: Write tests for your validation shields to ensure they work as expected. 