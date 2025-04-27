# Background Task Processing with FastAPI Shield

This guide demonstrates how to integrate FastAPI Shield with background task processing for building scalable and robust APIs.

## Introduction to Background Tasks

Background tasks are operations that can be executed after returning a response to the client. They're useful for:

- Processing time-consuming operations without blocking the response
- Handling non-critical tasks asynchronously  
- Scheduling periodic maintenance operations
- Offloading resource-intensive work

FastAPI Shield can be combined with background task processing to secure these operations and enforce access controls.

## Built-in FastAPI Background Tasks

FastAPI provides a simple `BackgroundTasks` mechanism for operations that don't need a full task queue:

```python
from fastapi import FastAPI, BackgroundTasks, Depends
from fastapi_shield import shield, ShieldedDepends
from typing import Dict, Any
import time

app = FastAPI()

# Shield for validating task data
@shield(name="TaskDataValidator")
def validate_task_data(task_data: Dict[str, Any]):
    if not task_data.get("task_id"):
        raise ValueError("task_id is required")
    if not task_data.get("action"):
        raise ValueError("action is required")
    return task_data

# Shield for checking access to execute tasks
@shield(name="TaskExecutionPermission")
def check_task_execution_permission(user_id: int, task_id: str):
    # In a real app, this would check a database or permission system
    allowed_task_ids = [f"task_{user_id}_1", f"task_{user_id}_2"]
    if task_id not in allowed_task_ids:
        raise ValueError(f"User {user_id} is not allowed to execute task {task_id}")
    return user_id, task_id

# Function to be executed in the background
def process_task_in_background(user_id: int, task_id: str, action: str):
    print(f"Starting background task {task_id} with action {action}")
    # Simulate some time-consuming work
    time.sleep(3)
    print(f"Completed background task {task_id} for user {user_id}")

@app.post("/tasks/")
async def create_task(
    background_tasks: BackgroundTasks,
    task_data: Dict[str, Any] = ShieldedDepends(validate_task_data),
    user_id: int = 123  # In a real app, this would come from auth
):
    # Apply the permission shield directly
    user_id, task_id = check_task_execution_permission(user_id, task_data["task_id"])
    
    # Add the task processing to background tasks
    background_tasks.add_task(
        process_task_in_background,
        user_id=user_id,
        task_id=task_id,
        action=task_data["action"]
    )
    
    return {"message": f"Task {task_id} has been scheduled"}
```

## Integration with Celery for Advanced Task Processing

For more complex scenarios, Celery provides a distributed task queue system:

```python
from fastapi import FastAPI, Depends, HTTPException
from fastapi_shield import shield, ShieldedDepends
from typing import Dict, Any
from celery import Celery
import json

# Configure Celery
# In a real app, use Redis, RabbitMQ, or another message broker
celery_app = Celery(
    "tasks",
    broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/0"
)

# FastAPI app
app = FastAPI()

# Shield to validate task data
@shield(name="CeleryTaskDataValidator")
def validate_celery_task_data(task_data: Dict[str, Any]):
    required_fields = ["task_type", "parameters"]
    for field in required_fields:
        if field not in task_data:
            raise ValueError(f"Missing required field: {field}")
    
    allowed_task_types = ["data_processing", "email_sending", "report_generation"]
    if task_data["task_type"] not in allowed_task_types:
        raise ValueError(f"Invalid task type: {task_data['task_type']}")
    
    return task_data

# Shield to validate user permissions for tasks
@shield(name="CeleryTaskPermissionChecker")
def check_task_permissions(
    task_data: Dict[str, Any] = ShieldedDepends(validate_celery_task_data),
    user_id: int = 123  # In a real app, this would come from auth
):
    # Check if the user has permission to run this type of task
    # In a real app, check against a database of permissions
    user_allowed_tasks = {
        123: ["data_processing", "email_sending"],
        456: ["report_generation"]
    }
    
    if user_id not in user_allowed_tasks or task_data["task_type"] not in user_allowed_tasks[user_id]:
        raise HTTPException(
            status_code=403,
            detail=f"User {user_id} is not allowed to run tasks of type {task_data['task_type']}"
        )
    
    return {
        "task_type": task_data["task_type"],
        "parameters": task_data["parameters"],
        "user_id": user_id
    }

# Define Celery tasks
@celery_app.task
def process_data_task(task_data):
    user_id = task_data["user_id"]
    parameters = task_data["parameters"]
    print(f"Processing data for user {user_id} with parameters: {parameters}")
    # Actual data processing would happen here
    return {"status": "completed", "processed_items": 100}

@celery_app.task
def send_email_task(task_data):
    user_id = task_data["user_id"]
    parameters = task_data["parameters"]
    print(f"Sending email for user {user_id} with parameters: {parameters}")
    # Actual email sending would happen here
    return {"status": "sent", "message_id": "some-id"}

@celery_app.task
def generate_report_task(task_data):
    user_id = task_data["user_id"]
    parameters = task_data["parameters"]
    print(f"Generating report for user {user_id} with parameters: {parameters}")
    # Actual report generation would happen here
    return {"status": "completed", "report_url": "/reports/123"}

# Task type mapping
TASK_TYPE_MAPPING = {
    "data_processing": process_data_task,
    "email_sending": send_email_task,
    "report_generation": generate_report_task
}

# FastAPI endpoint
@app.post("/celery-tasks/")
async def create_celery_task(validated_data = Depends(check_task_permissions)):
    task_type = validated_data["task_type"]
    
    # Get the correct Celery task based on the task type
    celery_task = TASK_TYPE_MAPPING[task_type]
    
    # Submit the task to Celery
    task_result = celery_task.delay(validated_data)
    
    # Return the task ID
    return {
        "task_id": task_result.id,
        "status": "scheduled",
        "task_type": task_type
    }

# Endpoint to check task status
@app.get("/celery-tasks/{task_id}")
async def get_task_status(task_id: str):
    task_result = celery_app.AsyncResult(task_id)
    
    if task_result.state == 'PENDING':
        response = {
            'status': task_result.state,
            'task_id': task_id,
        }
    elif task_result.state != 'FAILURE':
        response = {
            'status': task_result.state,
            'task_id': task_id,
            'result': task_result.result
        }
    else:
        # Something went wrong in the task
        response = {
            'status': task_result.state,
            'task_id': task_id,
            'error': str(task_result.info)
        }
    
    return response
```

## Securing Background Tasks with Special Shield Patterns

Background tasks often need special security considerations since they run without an active user request context. Here are some patterns for securing them:

### Privilege Token Pattern

```python
from fastapi import FastAPI, Depends, HTTPException
from fastapi_shield import shield, ShieldedDepends
import uuid
import time
import hmac
import hashlib

app = FastAPI()

# Secret key for signing task tokens
TASK_SECRET_KEY = "your-secret-key-for-tasks"

# Generate a signed token for a background task
def generate_task_token(task_id: str, user_id: int) -> str:
    """Generate a signed token for authorizing a background task"""
    timestamp = int(time.time())
    message = f"{task_id}:{user_id}:{timestamp}"
    signature = hmac.new(
        TASK_SECRET_KEY.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()
    return f"{message}:{signature}"

# Shield to verify a task token
@shield(name="TaskTokenVerifier")
def verify_task_token(token: str):
    try:
        # Split the token into its components
        message_part, signature = token.rsplit(":", 1)
        task_id, user_id, timestamp = message_part.split(":")
        user_id = int(user_id)
        timestamp = int(timestamp)
        
        # Check if the token is expired (1 hour validity)
        current_time = int(time.time())
        if current_time - timestamp > 3600:
            raise ValueError("Token expired")
        
        # Verify the signature
        expected_signature = hmac.new(
            TASK_SECRET_KEY.encode(),
            message_part.encode(),
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(signature, expected_signature):
            raise ValueError("Invalid token signature")
        
        return {"task_id": task_id, "user_id": user_id}
    
    except Exception as e:
        raise ValueError(f"Invalid task token: {str(e)}")

# Create a task with a token for later execution
@app.post("/secured-tasks/")
async def create_secured_task(user_id: int = 123):  # In real app, from auth
    task_id = str(uuid.uuid4())
    
    # Generate a token for this task
    task_token = generate_task_token(task_id, user_id)
    
    # In a real app, store the task in a queue with the token
    # ...
    
    return {
        "task_id": task_id,
        "token": task_token
    }

# Background worker endpoint (would be called by your task worker)
@app.post("/execute-task/")
async def execute_task(task_token: str, verified = Depends(verify_task_token)):
    task_id = verified["task_id"]
    user_id = verified["user_id"]
    
    # Retrieve the task details using the task_id
    # In a real app, get from database
    # ...
    
    # Execute the task with the verified user_id
    print(f"Executing task {task_id} for user {user_id}")
    
    return {"status": "completed", "task_id": task_id}
```

### Secure Context Propagation

This pattern ensures that necessary security context is propagated to background tasks:

```python
from fastapi import FastAPI, BackgroundTasks, Depends
from fastapi_shield import shield
from typing import Dict, Any
import json
import time
import contextvars

app = FastAPI()

# Context variable to store the current user's security context
security_context = contextvars.ContextVar("security_context", default=None)

# Shield to capture security context
@shield(name="CaptureSecurityContext")
def capture_security_context(user_id: int, roles: list[str]):
    """Shield that captures the current security context for later use"""
    context = {
        "user_id": user_id,
        "roles": roles,
        "timestamp": time.time()
    }
    security_context.set(context)
    return context

# Function to execute a task with the captured security context
def execute_with_security_context(task_func, task_args, serialized_context):
    """Executes a function with the provided security context"""
    # Restore the security context
    context = json.loads(serialized_context)
    security_context.set(context)
    
    try:
        # Log the security context being used
        print(f"Executing task with security context: {context}")
        
        # Execute the actual task
        return task_func(*task_args)
    finally:
        # Clear the security context
        security_context.set(None)

# Example background task function
def process_data_with_context(data_id: str):
    """Process data using the current security context"""
    # Retrieve the current security context
    context = security_context.get()
    if not context:
        raise ValueError("No security context available")
    
    user_id = context["user_id"]
    roles = context["roles"]
    
    # Check if the security context has permission for this operation
    if "data_processor" not in roles:
        raise ValueError(f"User {user_id} does not have the data_processor role")
    
    # Proceed with processing
    print(f"Processing data {data_id} for user {user_id}")
    time.sleep(2)  # Simulate work
    return {"status": "processed", "data_id": data_id}

@app.post("/secure-background-tasks/{data_id}")
async def create_secure_background_task(
    data_id: str,
    background_tasks: BackgroundTasks,
    user_security: Dict[str, Any] = Depends(
        lambda: capture_security_context(user_id=456, roles=["admin", "data_processor"])
    )
):
    # Serialize the current security context
    serialized_context = json.dumps(security_context.get())
    
    # Add the background task with the security context
    background_tasks.add_task(
        execute_with_security_context,
        process_data_with_context,  # The task function
        (data_id,),                # Arguments for the task function
        serialized_context         # Serialized security context
    )
    
    return {"message": f"Data processing for {data_id} scheduled"}
```

## Event-Driven Architecture with Shields

For more complex task processing, you can implement an event-driven pattern:

```python
from fastapi import FastAPI, Depends
from fastapi_shield import shield, ShieldedDepends
from typing import Dict, Any, List
import asyncio
import uuid

app = FastAPI()

# Simple in-memory event bus (use a real message broker in production)
class EventBus:
    def __init__(self):
        self.subscribers = {}
        
    def subscribe(self, event_type: str, handler):
        if event_type not in self.subscribers:
            self.subscribers[event_type] = []
        self.subscribers[event_type].append(handler)
        
    async def publish(self, event_type: str, data: Dict[str, Any]):
        if event_type in self.subscribers:
            for handler in self.subscribers[event_type]:
                # Execute handlers in the background
                asyncio.create_task(handler(data))

# Create a global event bus
event_bus = EventBus()

# Shield for validating event data
@shield(name="EventDataValidator")
def validate_event_data(event_type: str, data: Dict[str, Any]):
    if event_type == "user_registered":
        required_fields = ["user_id", "email"]
    elif event_type == "order_placed":
        required_fields = ["order_id", "user_id", "amount"]
    else:
        required_fields = []
    
    for field in required_fields:
        if field not in data:
            raise ValueError(f"Missing required field for {event_type}: {field}")
    
    return {"event_type": event_type, "data": data}

# Shield for checking event publishing permissions
@shield(name="EventPublishingPermission")
def check_event_publishing_permission(
    validated_event = ShieldedDepends(validate_event_data),
    user_id: int = 123  # In a real app, from auth
):
    # Check if the user has permission to publish this event type
    # In a real app, check against a permission database
    
    event_type = validated_event["event_type"]
    event_data = validated_event["data"]
    
    # Example permission check
    admin_only_events = ["user_banned", "system_maintenance"]
    if event_type in admin_only_events and user_id != 1:  # User 1 is admin
        raise ValueError(f"User {user_id} cannot publish {event_type} events")
    
    # Add audit information to the event
    event_data["_metadata"] = {
        "published_by": user_id,
        "published_at": asyncio.get_event_loop().time(),
        "event_id": str(uuid.uuid4())
    }
    
    return validated_event

# Endpoint to publish events
@app.post("/events/{event_type}")
async def publish_event(
    event_type: str,
    data: Dict[str, Any],
    permission_checked = Depends(
        lambda: check_event_publishing_permission(
            validate_event_data(event_type, data)
        )
    )
):
    validated_event = permission_checked
    
    # Publish the event
    await event_bus.publish(
        validated_event["event_type"],
        validated_event["data"]
    )
    
    return {
        "status": "published",
        "event_id": validated_event["data"]["_metadata"]["event_id"]
    }

# Example event handlers
async def handle_user_registered(data: Dict[str, Any]):
    print(f"User registered: {data}")
    # Send welcome email, setup user profile, etc.
    await asyncio.sleep(2)  # Simulate async work

async def handle_order_placed(data: Dict[str, Any]):
    print(f"Order placed: {data}")
    # Process payment, update inventory, etc.
    await asyncio.sleep(3)  # Simulate async work

# Register event handlers
@app.on_event("startup")
async def setup_event_handlers():
    event_bus.subscribe("user_registered", handle_user_registered)
    event_bus.subscribe("order_placed", handle_order_placed)
```

## Task Rate Limiting with Shields

Implement rate limiting for task submission to prevent abuse:

```python
from fastapi import FastAPI, Depends, HTTPException
from fastapi_shield import shield, ShieldedDepends
from typing import Dict, Any
import time
import asyncio
import redis
import json

app = FastAPI()

# Redis client for rate limiting (use a connection pool in production)
redis_client = redis.Redis(host="localhost", port=6379, db=0)

# Shield for task rate limiting
@shield(name="TaskRateLimiter")
def limit_task_rate(task_type: str, user_id: int = 123):  # user_id from auth in real app
    """Limit the rate at which a user can submit tasks"""
    
    # Define rate limits for different task types
    rate_limits = {
        "email": {"count": 5, "period": 60},      # 5 per minute
        "report": {"count": 10, "period": 3600},  # 10 per hour
        "default": {"count": 20, "period": 3600}  # 20 per hour
    }
    
    # Get the appropriate rate limit
    limit = rate_limits.get(task_type, rate_limits["default"])
    max_count = limit["count"]
    period = limit["period"]
    
    # Create a Redis key for this user and task type
    redis_key = f"rate_limit:{user_id}:{task_type}"
    
    # Check how many tasks this user has submitted recently
    current_count = redis_client.get(redis_key)
    if current_count is not None:
        current_count = int(current_count)
        if current_count >= max_count:
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded for {task_type} tasks. "
                       f"Maximum {max_count} tasks per {period} seconds."
            )
    
    # Increment the counter
    if redis_client.exists(redis_key):
        redis_client.incr(redis_key)
    else:
        redis_client.setex(redis_key, period, 1)
    
    return {"task_type": task_type, "user_id": user_id}

# Task submission endpoint with rate limiting
@app.post("/tasks/{task_type}")
async def submit_task(
    task_type: str,
    task_data: Dict[str, Any],
    rate_limited = Depends(lambda: limit_task_rate(task_type))
):
    # Process the task submission (would go to a task queue in real app)
    task_id = f"task_{int(time.time())}_{rate_limited['user_id']}"
    
    # Simulate adding the task to a queue
    print(f"Task {task_id} of type {task_type} added to queue for user {rate_limited['user_id']}")
    
    # In a real app, you'd submit this to Celery, RQ, or another task queue
    
    return {
        "task_id": task_id,
        "status": "scheduled",
        "task_type": task_type
    }
```

## Best Practices for Background Tasks with FastAPI Shield

1. **Clear Authorization Context**: Always ensure background tasks have a clear authorization context, either by passing it explicitly or using the privilege token pattern.

2. **Idempotent Operations**: Design background tasks to be idempotent (can be safely retried) to handle failures gracefully.

3. **Proper Error Handling**: Implement comprehensive error handling in background tasks, including logging and notification of failures.

4. **Task Result Storage**: Store task results in a persistent data store (like a database) rather than keeping them only in memory.

5. **Monitoring and Observability**: Implement proper monitoring of your background tasks to track their performance and detect issues.

6. **Security Auditing**: Include security-relevant information in task logs for auditing purposes.

7. **Task Prioritization**: Implement a mechanism to prioritize critical tasks over less important ones.

8. **Resource Limiting**: Set appropriate timeouts and resource limits for background tasks to prevent runaway processes.

9. **Task Scheduling**: Use a proper scheduling system for recurring tasks rather than implementing your own.

10. **Progressive Enhancement**: Return immediate responses to users while background tasks complete the more time-consuming operations.

By following these best practices, you can create a robust background task processing system that leverages FastAPI Shield's security features to ensure that tasks are executed safely and efficiently. 