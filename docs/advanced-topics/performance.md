# Performance Optimization in FastAPI Shield

This guide covers techniques to optimize the performance of FastAPI Shield in your applications, addressing common performance considerations when using runtime validation.

## Understanding FastAPI Shield Performance

FastAPI Shield adds runtime type validation and security checks to your application, which inevitably introduces some overhead. This guide will help you maintain robust validation while minimizing performance impact.

## Benchmarking Shield Performance

Before optimizing, establish a baseline with benchmarks:

```python
import time
import statistics
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from fastapi_shield import shield

app = FastAPI()

# Simple endpoint without shields
@app.get("/unshielded/{value}")
async def unshielded_endpoint(value: int):
    return {"value": value}

# Endpoint with a simple shield
@shield(name="SimpleIntegerShield")
def validate_integer(value: int):
    return value

@app.get("/simple-shield/{value}")
async def simple_shielded_endpoint(validated: int = Depends(validate_integer)):
    return {"value": validated}

# Endpoint with a complex shield
@shield(name="ComplexIntegerShield")
def complex_validate_integer(value: int):
    if value < 0:
        raise ValueError("Value must be positive")
    if value > 1000:
        raise ValueError("Value must be less than 1000")
    # Some additional processing
    result = 0
    for i in range(10):  # Simulate more complex validation
        result += value
    return result

@app.get("/complex-shield/{value}")
async def complex_shielded_endpoint(validated: int = Depends(complex_validate_integer)):
    return {"value": validated}

# Benchmark function
def benchmark_endpoints():
    client = TestClient(app)
    iterations = 1000
    
    # Benchmark unshielded endpoint
    unshielded_times = []
    for _ in range(iterations):
        start = time.time()
        response = client.get("/unshielded/42")
        end = time.time()
        unshielded_times.append((end - start) * 1000)  # Convert to ms
    
    # Benchmark simple shielded endpoint
    simple_shield_times = []
    for _ in range(iterations):
        start = time.time()
        response = client.get("/simple-shield/42")
        end = time.time()
        simple_shield_times.append((end - start) * 1000)
    
    # Benchmark complex shielded endpoint
    complex_shield_times = []
    for _ in range(iterations):
        start = time.time()
        response = client.get("/complex-shield/42")
        end = time.time()
        complex_shield_times.append((end - start) * 1000)
    
    # Calculate statistics
    unshielded_avg = statistics.mean(unshielded_times)
    simple_shield_avg = statistics.mean(simple_shield_times)
    complex_shield_avg = statistics.mean(complex_shield_times)
    
    simple_overhead = (simple_shield_avg - unshielded_avg) / unshielded_avg * 100
    complex_overhead = (complex_shield_avg - unshielded_avg) / unshielded_avg * 100
    
    print(f"Unshielded endpoint: {unshielded_avg:.2f}ms")
    print(f"Simple shield endpoint: {simple_shield_avg:.2f}ms (+" 
          f"{simple_overhead:.1f}% overhead)")
    print(f"Complex shield endpoint: {complex_shield_avg:.2f}ms (+" 
          f"{complex_overhead:.1f}% overhead)")

if __name__ == "__main__":
    benchmark_endpoints()
```

## Profiling Shield Execution

For more detailed performance analysis, use Python's profiling tools:

```python
import cProfile
import pstats
from fastapi_shield import shield

@shield(name="ProfiledShield")
def complex_shield(value: int):
    if value < 0:
        raise ValueError("Value must be positive")
    result = 0
    for i in range(100):
        result += value * i
    return result

def profile_shield():
    # Create a Profile object
    profiler = cProfile.Profile()
    
    # Start profiling
    profiler.enable()
    
    # Run the shield multiple times
    for i in range(1000):
        complex_shield(42)
    
    # Stop profiling
    profiler.disable()
    
    # Print sorted stats
    stats = pstats.Stats(profiler).sort_stats('cumulative')
    stats.print_stats(20)  # Print top 20 time-consuming functions

if __name__ == "__main__":
    profile_shield()
```

## Performance Optimization Techniques

### 1. Use Simpler Shields When Possible

Simpler shields have less performance impact:

```python
# ❌ Complex shield with multiple validations
@shield(name="ComplexUserValidator")
def validate_user_complex(user_data: dict):
    if not isinstance(user_data, dict):
        raise ValueError("User data must be a dictionary")
    
    # Multiple validations in one shield
    if "name" not in user_data:
        raise ValueError("Name is required")
    if not isinstance(user_data["name"], str):
        raise ValueError("Name must be a string")
    if len(user_data["name"]) < 2:
        raise ValueError("Name must be at least 2 characters")
    
    if "age" in user_data:
        if not isinstance(user_data["age"], int):
            raise ValueError("Age must be an integer")
        if user_data["age"] < 0:
            raise ValueError("Age must be positive")
    
    return user_data

# ✅ Split into simpler, focused shields
@shield(name="DictValidator")
def validate_dict(data: dict):
    return data

@shield(name="NameValidator")
def validate_name(data: dict = ShieldedDepends(validate_dict)):
    if "name" not in data:
        raise ValueError("Name is required")
    if not isinstance(data["name"], str):
        raise ValueError("Name must be a string")
    if len(data["name"]) < 2:
        raise ValueError("Name must be at least 2 characters")
    return data

@shield(name="AgeValidator")
def validate_age(data: dict = ShieldedDepends(validate_dict)):
    if "age" in data:
        if not isinstance(data["age"], int):
            raise ValueError("Age must be an integer")
        if data["age"] < 0:
            raise ValueError("Age must be positive")
    return data

# Apply both shields where needed
@app.post("/users/")
async def create_user(
    validated_data: dict = ShieldedDepends(validate_name),
    age_validated: dict = ShieldedDepends(validate_age)
):
    # Both shields validate the same data object
    return {"status": "success", "user": validated_data}
```

### 2. Cache Expensive Validation Results

For shields that perform expensive operations, consider caching:

```python
import functools
from fastapi_shield import shield

# Shield with built-in cache
@shield(name="ExpensiveDatabaseValidator")
@functools.lru_cache(maxsize=100)
def validate_with_cache(item_id: int):
    # Simulate an expensive database lookup
    print(f"Performing expensive validation for {item_id}")
    # In a real app, this would hit a database
    time.sleep(0.1)  # Simulate DB access time
    
    # Validate that the item exists
    if item_id < 1 or item_id > 1000:
        raise ValueError(f"Item {item_id} not found")
        
    return item_id

@app.get("/items/{item_id}")
async def get_item(
    item_id: int,
    validated_id: int = ShieldedDepends(validate_with_cache)
):
    return {"item_id": validated_id, "name": f"Item {validated_id}"}
```

### 3. Use Asynchronous Shields for I/O Bound Operations

For shields that perform I/O operations:

```python
import asyncio
from fastapi_shield import shield

# Asynchronous shield for database operations
@shield(name="AsyncDatabaseValidator")
async def validate_user_exists(user_id: int):
    # Simulate async database lookup
    await asyncio.sleep(0.01)  # Simulating DB access
    
    # In a real app, this would be something like:
    # user = await db.users.find_one({"id": user_id})
    # if not user:
    #     raise ValueError(f"User {user_id} not found")
    
    return user_id

@app.get("/users/{user_id}")
async def get_user(validated_id: int = ShieldedDepends(validate_user_exists)):
    # In a real app, you might do:
    # user = await db.users.find_one({"id": validated_id})
    user = {"id": validated_id, "name": f"User {validated_id}"}
    return user
```

### 4. Optimize Regex Patterns in String Validation

Optimize regex patterns used in validation:

```python
import re
from fastapi_shield import shield

# ❌ Inefficient regex pattern
@shield(name="SlowEmailValidator")
def validate_email_slow(email: str):
    # This regex is simplified but demonstrates the point
    pattern = re.compile(r'^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})$')
    
    # Inefficient validation
    if not pattern.match(email):
        raise ValueError("Invalid email format")
    
    return email

# ✅ Optimized regex with pre-compilation
# Pre-compile the pattern once
EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')

@shield(name="FastEmailValidator")
def validate_email_fast(email: str):
    if not EMAIL_PATTERN.match(email):
        raise ValueError("Invalid email format")
    
    return email
```

### 5. Minimize Type Conversions

Reduce unnecessary type conversions:

```python
from fastapi_shield import shield

# ❌ Shield with type conversions
@shield(name="IneffientNumberProcessor")
def process_number_inefficient(value: str):
    # Convert string to int, then back to string
    num = int(value)
    if num < 0:
        raise ValueError("Value must be positive")
    
    # Operations that could be done directly on the string
    result = str(num * 2)
    return result

# ✅ More efficient approach
@shield(name="EfficientNumberProcessor")
def process_number_efficient(value: str):
    # Check if it's a valid number without full conversion
    if not value.isdigit():
        raise ValueError("Value must be a positive number")
    
    # Only convert once for the final result
    num = int(value)
    result = str(num * 2)
    return result
```

### 6. Batch Validations When Possible

For collections of items, validate in batches:

```python
from fastapi_shield import shield
from typing import List

# ❌ Validating each item individually (could lead to multiple function calls)
@shield(name="ItemValidator")
def validate_item(item: dict):
    if "id" not in item:
        raise ValueError("Item must have an id")
    if "name" not in item:
        raise ValueError("Item must have a name")
    return item

@app.post("/items/individual-validation/")
async def create_items_individual(items: List[dict]):
    validated_items = []
    for item in items:
        validated_item = validate_item(item)  # Multiple shield calls
        validated_items.append(validated_item)
    return {"items": validated_items}

# ✅ Batch validation
@shield(name="BatchItemValidator")
def validate_items_batch(items: List[dict]):
    for i, item in enumerate(items):
        if "id" not in item:
            raise ValueError(f"Item at position {i} must have an id")
        if "name" not in item:
            raise ValueError(f"Item at position {i} must have a name")
    return items

@app.post("/items/batch-validation/")
async def create_items_batch(items: List[dict] = ShieldedDepends(validate_items_batch)):
    return {"items": items}  # Already validated in one go
```

### 7. Use Early Returns for Multi-Step Validations

Return early for failed validations:

```python
from fastapi_shield import shield

# ❌ Checking all conditions
@shield(name="UserValidatorInefficient")
def validate_user_inefficient(user: dict):
    is_valid = True
    errors = []
    
    # Check all fields even if some are invalid
    if "username" not in user:
        is_valid = False
        errors.append("Username is required")
    
    if "email" not in user:
        is_valid = False
        errors.append("Email is required")
    
    if "password" not in user:
        is_valid = False
        errors.append("Password is required")
    
    if not is_valid:
        raise ValueError(", ".join(errors))
    
    # More complex processing happens here
    # ...
    
    return user

# ✅ Early returns
@shield(name="UserValidatorEfficient")
def validate_user_efficient(user: dict):
    # Check critical fields first
    if "username" not in user:
        raise ValueError("Username is required")
    
    if "email" not in user:
        raise ValueError("Email is required")
    
    if "password" not in user:
        raise ValueError("Password is required")
    
    # If we get here, all required fields exist
    # More complex processing happens here
    # ...
    
    return user
```

### 8. Use Shield Factories for Dynamic Shields

Shield factories can help create specialized shields efficiently:

```python
from fastapi_shield import shield

def create_range_validator(min_val, max_val, field_name="value"):
    """Factory that creates a shield for range validation"""
    
    @shield(name=f"RangeValidator_{min_val}_{max_val}")
    def validate_range(data: dict):
        value = data.get(field_name)
        if value is None:
            raise ValueError(f"{field_name} is required")
        
        if not isinstance(value, (int, float)):
            raise ValueError(f"{field_name} must be a number")
            
        if value < min_val:
            raise ValueError(f"{field_name} must be at least {min_val}")
            
        if value > max_val:
            raise ValueError(f"{field_name} must be at most {max_val}")
            
        return data
    
    return validate_range

# Create specific validators
validate_age = create_range_validator(0, 120, "age")
validate_percentage = create_range_validator(0, 100, "percentage")
validate_rating = create_range_validator(1, 5, "rating")

@app.post("/reviews/")
async def create_review(
    review_data: dict = ShieldedDepends(validate_rating)
):
    return {"status": "success", "review": review_data}
```

## Advanced Performance Considerations

### 1. Shield Execution Order

The order of shields can significantly impact performance. Place cheaper, more likely-to-fail shields earlier:

```python
from fastapi_shield import shield, ShieldedDepends

# ✅ Optimal shield order - cheap validations first
@shield(name="RequiredFieldsCheck")
def check_required_fields(data: dict):
    # Quick check before more expensive validations
    if not all(k in data for k in ["id", "name", "email"]):
        raise ValueError("Missing required fields")
    return data

@shield(name="FormatValidator")
def validate_formats(data: dict = ShieldedDepends(check_required_fields)):
    # More expensive regex validations
    # Only runs if the first shield passes
    # ...
    return data

@shield(name="DatabaseValidator")
async def validate_against_db(data: dict = ShieldedDepends(validate_formats)):
    # Most expensive operation - DB lookup
    # Only runs if previous shields pass
    # ...
    return data
```

### 2. Use Shield Dependencies Wisely

Shield dependencies can be reused to avoid redundant validation:

```python
from fastapi_shield import shield, ShieldedDepends

@shield(name="UserValidator")
def validate_user(user_id: int):
    # Validate user exists
    # ...
    return user_id

@shield(name="ItemValidator")
def validate_item(item_id: int):
    # Validate item exists
    # ...
    return item_id

@shield(name="PermissionValidator")
def validate_permission(
    user_id: int = ShieldedDepends(validate_user),
    item_id: int = ShieldedDepends(validate_item)
):
    # Check if user has permission for the item
    # ...
    return {"user_id": user_id, "item_id": item_id}

@app.post("/items/{item_id}/actions")
async def perform_action(
    item_id: int,
    user_id: int,
    # This reuses the validation results
    permission: dict = ShieldedDepends(validate_permission)
):
    # The endpoint already knows user_id and item_id are valid
    return {"status": "success"}
```

### 3. Profile Memory Usage

Shields that generate large intermediate objects can impact memory usage:

```python
import tracemalloc
from fastapi_shield import shield

@shield(name="MemoryIntensiveShield")
def process_large_data(data: list):
    # Create large intermediate data structures
    processed = [item * 2 for item in data]
    filtered = [item for item in processed if item > 10]
    transformed = [{"value": item, "squared": item**2} for item in filtered]
    return transformed

def profile_memory_usage():
    # Start tracking memory
    tracemalloc.start()
    
    # Create test data
    test_data = list(range(10000))
    
    # Get current memory snapshot
    snapshot1 = tracemalloc.take_snapshot()
    
    # Run the shield
    result = process_large_data(test_data)
    
    # Get memory snapshot after shield execution
    snapshot2 = tracemalloc.take_snapshot()
    
    # Compare snapshots
    top_stats = snapshot2.compare_to(snapshot1, 'lineno')
    
    print("[ Memory usage stats ]")
    for stat in top_stats[:10]:
        print(stat)

# Optimized version that uses generators to reduce memory usage
@shield(name="MemoryEfficientShield")
def process_large_data_efficient(data: list):
    # Use generators for intermediate steps
    processed = (item * 2 for item in data)
    filtered = (item for item in processed if item > 10)
    transformed = [{"value": item, "squared": item**2} for item in filtered]
    return transformed
```

### 4. Shield Loading and Initialization

Optimize how your shields are imported and loaded:

```python
# ❌ Inefficient: Importing all shields in one module
# shields.py
from fastapi_shield import shield

# Hundreds of shields defined here
@shield(name="Shield1")
def shield1(value):
    # ...
    return value

@shield(name="Shield2")
def shield2(value):
    # ...
    return value

# ... many more shields

# ✅ Better: Organize shields in domain-specific modules and import as needed
# user_shields.py
from fastapi_shield import shield

@shield(name="UserValidator")
def validate_user(user):
    # ...
    return user

# item_shields.py
from fastapi_shield import shield

@shield(name="ItemValidator")
def validate_item(item):
    # ...
    return item
```

## Measuring Impact in Production

Use application monitoring to track shield performance in production:

```python
import time
from fastapi_shield import shield
from contextlib import contextmanager
import logging

logger = logging.getLogger("shield_metrics")

@contextmanager
def measure_execution_time(shield_name):
    """Context manager to measure and log execution time"""
    start_time = time.time()
    try:
        yield
    finally:
        end_time = time.time()
        execution_time = (end_time - start_time) * 1000  # Convert to ms
        logger.info(f"Shield {shield_name} executed in {execution_time:.2f}ms")

@shield(name="MonitoredShield")
def validate_with_metrics(value: int):
    with measure_execution_time("MonitoredShield"):
        # Shield validation logic
        if value < 0:
            raise ValueError("Value must be positive")
        # Simulate some processing
        time.sleep(0.001)
        return value * 2

@app.get("/monitored/{value}")
async def monitored_endpoint(
    value: int, 
    validated: int = ShieldedDepends(validate_with_metrics)
):
    return {"original": value, "validated": validated}
```

## Conclusion

Optimizing FastAPI Shield performance involves a balance between robust validation and efficient execution. By applying these techniques, you can maintain strong type safety and security checks while minimizing performance overhead.

Remember that the right optimization strategy depends on your specific use case. Always measure the impact of your optimizations to ensure they provide meaningful improvements without compromising security or validation quality. 