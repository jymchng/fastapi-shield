# Deploying FastAPI Shield Applications

This guide covers best practices for deploying FastAPI Shield applications to production environments, with a focus on performance, security, and maintainability.

## Pre-Deployment Checklist

Before deploying your FastAPI Shield application to production, ensure you've addressed these key considerations:

- ✅ Shield validation logic is thoroughly tested
- ✅ Error handling is comprehensive and user-friendly
- ✅ Performance is optimized following the performance guide
- ✅ Security measures are in place
- ✅ Logging and monitoring are configured
- ✅ Documentation is up-to-date

## Deployment Options

### Docker Deployment

Docker is one of the most popular deployment methods for FastAPI applications. Here's a sample `Dockerfile` for a FastAPI Shield project:

```dockerfile
FROM python:3.9-slim

WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Run with uvicorn server
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

A corresponding `docker-compose.yml` file for local development:

```yaml
version: '3'

services:
  web:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - .:/app
    environment:
      - ENV=development
      - DATABASE_URL=postgresql://user:password@db:5432/app
    depends_on:
      - db
  
  db:
    image: postgres:13
    volumes:
      - postgres_data:/var/lib/postgresql/data/
    environment:
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=password
      - POSTGRES_DB=app
    ports:
      - "5432:5432"

volumes:
  postgres_data:
```

### Kubernetes Deployment

For scaling and managing containerized applications, Kubernetes is an excellent choice. Here's a basic `deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fastapi-shield-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: fastapi-shield
  template:
    metadata:
      labels:
        app: fastapi-shield
    spec:
      containers:
      - name: fastapi-shield
        image: your-registry/fastapi-shield-app:latest
        ports:
        - containerPort: 8000
        resources:
          limits:
            cpu: "1"
            memory: "512Mi"
          requests:
            cpu: "0.5"
            memory: "256Mi"
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 10
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 15
          periodSeconds: 20
        env:
          - name: DATABASE_URL
            valueFrom:
              secretKeyRef:
                name: app-secrets
                key: database-url
```

Service to expose the deployment:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: fastapi-shield-service
spec:
  selector:
    app: fastapi-shield
  ports:
  - port: 80
    targetPort: 8000
  type: ClusterIP
```

### Serverless Deployment

For serverless deployments, platforms like AWS Lambda with API Gateway can be used. Here's an example using the Mangum adapter:

```python
from fastapi import FastAPI
from mangum import Mangum

app = FastAPI(title="FastAPI Shield App")

@app.get("/")
async def root():
    return {"message": "Hello World"}

# Wrap the FastAPI application with Mangum for AWS Lambda
handler = Mangum(app)
```

With a serverless configuration (e.g., for AWS SAM):

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Resources:
  FastAPIShieldFunction:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: ./
      Handler: app.handler
      Runtime: python3.9
      Timeout: 30
      MemorySize: 256
      Events:
        ApiEvent:
          Type: Api
          Properties:
            Path: /{proxy+}
            Method: ANY
```

## Production ASGI Servers

For production deployments, use a production-grade ASGI server like Uvicorn with Gunicorn:

```bash
gunicorn app.main:app --workers 4 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

Recommended configuration parameters:

```python
# In a startup script or Procfile
# workers = 2 * CPU cores + 1
workers = 9  # For a 4-core server
worker_class = "uvicorn.workers.UvicornWorker"
bind = "0.0.0.0:8000"
```

## Health Checks and Readiness Probes

Implement health check endpoints to ensure your application is running correctly:

```python
from fastapi import FastAPI, status
from fastapi.responses import JSONResponse

app = FastAPI()

@app.get("/health", status_code=status.HTTP_200_OK)
async def health_check():
    return {"status": "healthy"}

@app.get("/readiness", status_code=status.HTTP_200_OK)
async def readiness_check():
    # Check database connection, external services, etc.
    all_systems_operational = True  # Placeholder for actual checks
    
    if all_systems_operational:
        return {"status": "ready"}
    
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"status": "not ready"}
    )
```

## Security in Production

### Secure Environment Variables

Never hardcode sensitive information like API keys or database credentials:

```python
import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    database_url: str
    api_key: str
    jwt_secret: str
    
    class Config:
        env_file = ".env"

settings = Settings()
```

### CORS Configuration

Configure Cross-Origin Resource Sharing (CORS) appropriately:

```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://production-frontend.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### HTTP Security Headers

Add security headers with middleware:

```python
@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response
```

### Rate Limiting

Implement rate limiting to prevent abuse:

```python
from fastapi import FastAPI, Request, Response, status
import time
from fastapi.middleware.trustedhost import TrustedHostMiddleware

app = FastAPI()

# Allow only trusted hosts
app.add_middleware(
    TrustedHostMiddleware, allowed_hosts=["api.yourdomain.com", "*.yourdomain.com"]
)

# Simple rate limiting middleware
class RateLimitMiddleware:
    def __init__(self, app, limit=100, window=60):
        self.app = app
        self.limit = limit  # Maximum requests per window
        self.window = window  # Window size in seconds
        self.requests = {}  # IP -> list of timestamps

    async def __call__(self, request: Request, call_next):
        ip = request.client.host
        now = time.time()
        
        # Clean old requests
        if ip in self.requests:
            self.requests[ip] = [t for t in self.requests[ip] if now - t < self.window]
        else:
            self.requests[ip] = []
        
        # Check rate limit
        if len(self.requests[ip]) >= self.limit:
            return Response(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content="Rate limit exceeded. Try again later."
            )
        
        # Add current request timestamp
        self.requests[ip].append(now)
        
        # Process the request
        return await call_next(request)

app.add_middleware(RateLimitMiddleware, limit=100, window=60)
```

## Logging and Monitoring

### Structured Logging

Configure structured logging for better observability:

```python
import logging
import json
from fastapi import FastAPI, Request
import time
import uuid

# Custom JSON formatter
class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
        }
        
        if hasattr(record, "request_id"):
            log_record["request_id"] = record.request_id
            
        if hasattr(record, "duration_ms"):
            log_record["duration_ms"] = record.duration_ms
        
        if record.exc_info:
            log_record["exception"] = self.formatException(record.exc_info)
        
        return json.dumps(log_record)

# Set up logger
logger = logging.getLogger("fastapi_shield")
handler = logging.StreamHandler()
handler.setFormatter(JsonFormatter())
logger.addHandler(handler)
logger.setLevel(logging.INFO)

app = FastAPI()

@app.middleware("http")
async def logging_middleware(request: Request, call_next):
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    
    # Add request ID to all logs during this request
    old_factory = logging.getLogRecordFactory()
    def record_factory(*args, **kwargs):
        record = old_factory(*args, **kwargs)
        record.request_id = request_id
        return record
    logging.setLogRecordFactory(record_factory)
    
    logger.info(
        f"Request started: {request.method} {request.url.path}",
        extra={"request_id": request_id}
    )
    
    start_time = time.time()
    try:
        response = await call_next(request)
        duration = time.time() - start_time
        
        logger.info(
            f"Request completed: {response.status_code}",
            extra={
                "request_id": request_id,
                "duration_ms": round(duration * 1000, 2),
                "status_code": response.status_code
            }
        )
        return response
    except Exception as e:
        duration = time.time() - start_time
        logger.error(
            f"Request failed: {str(e)}",
            extra={
                "request_id": request_id,
                "duration_ms": round(duration * 1000, 2)
            },
            exc_info=True
        )
        raise
```

### Prometheus Metrics

Add Prometheus metrics for monitoring:

```python
from fastapi import FastAPI
from prometheus_fastapi_instrumentator import Instrumentator

app = FastAPI()

# Initialize metrics endpoint
Instrumentator().instrument(app).expose(app)

# This adds a /metrics endpoint automatically
```

Custom shield metrics:

```python
import time
from fastapi import FastAPI, Request
from prometheus_client import Counter, Histogram
from contextlib import contextmanager

# Create metrics
SHIELD_VALIDATIONS = Counter(
    "shield_validations_total",
    "Total number of shield validations",
    ["shield_name", "result"]
)

SHIELD_VALIDATION_TIME = Histogram(
    "shield_validation_seconds",
    "Time spent in shield validation",
    ["shield_name"]
)

@contextmanager
def track_shield_performance(shield_name):
    start_time = time.time()
    success = True
    try:
        yield
    except Exception:
        success = False
        raise
    finally:
        duration = time.time() - start_time
        SHIELD_VALIDATIONS.labels(shield_name=shield_name, result="success" if success else "error").inc()
        SHIELD_VALIDATION_TIME.labels(shield_name=shield_name).observe(duration)

@shield(name="TrackedPosIntShield")
def validate_positive_int(value: int):
    with track_shield_performance("TrackedPosIntShield"):
        if value <= 0:
            raise ValueError("Value must be positive")
        return value

@app.get("/items/{item_id}")
async def get_item(item_id: int = ShieldedDepends(validate_positive_int)):
    return {"item_id": item_id}
```

## Database Considerations

### Database Connection Pooling

Configure connection pooling for optimal database performance:

```python
from databases import Database
from fastapi import FastAPI

app = FastAPI()

# Configure the database with a connection pool
DATABASE_URL = "postgresql://user:password@localhost/db"
database = Database(
    DATABASE_URL,
    min_size=5,  # Minimum number of connections
    max_size=20  # Maximum number of connections
)

@app.on_event("startup")
async def startup():
    await database.connect()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()
```

### Database Migrations

Use Alembic for database migrations:

```bash
# Initialize Alembic
alembic init alembic

# Create a migration
alembic revision --autogenerate -m "Create initial tables"

# Run migrations
alembic upgrade head
```

## Scaling Strategies

### Horizontal Scaling

Scale your FastAPI Shield application horizontally:

1. Ensure your application is stateless
2. Use a load balancer to distribute traffic
3. Store session data in a distributed cache (Redis, Memcached)
4. Use a distributed queue for background tasks

### Caching Strategy

Implement caching to reduce database load:

```python
from fastapi import FastAPI, Depends
from fastapi_shield import shield, ShieldedDepends
import redis
import json
import hashlib

app = FastAPI()

# Redis client
redis_client = redis.Redis(host="redis", port=6379, db=0)

def get_cache_key(function_name, args, kwargs):
    """Generate a cache key from function name and arguments"""
    key_parts = [function_name]
    key_parts.extend([str(arg) for arg in args])
    key_parts.extend([f"{k}={v}" for k, v in kwargs.items()])
    return hashlib.md5(":".join(key_parts).encode()).hexdigest()

def cache_shield(shield_func, ttl=300):
    """Decorator to cache shield results"""
    @shield(name=f"Cached_{shield_func.__name__}")
    async def cached_shield(*args, **kwargs):
        # Generate cache key
        cache_key = f"shield:{get_cache_key(shield_func.__name__, args, kwargs)}"
        
        # Try to get from cache
        cached_result = redis_client.get(cache_key)
        if cached_result:
            return json.loads(cached_result)
        
        # Not in cache, call the original shield
        result = await shield_func(*args, **kwargs)
        
        # Store in cache
        redis_client.setex(cache_key, ttl, json.dumps(result))
        return result
    
    return cached_shield

# Original shield
@shield(name="ExpensiveItemValidator")
async def validate_item(item_id: int):
    # Expensive validation logic
    # ...
    return {"item_id": item_id, "valid": True}

# Cached version
cached_validate_item = cache_shield(validate_item, ttl=60)

@app.get("/items/{item_id}")
async def get_item(validated: dict = ShieldedDepends(cached_validate_item)):
    return validated
```

## Continuous Integration and Deployment

### Example GitHub Actions Workflow

```yaml
name: Deploy FastAPI Shield App

on:
  push:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v2
    
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: '3.9'
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        if [ -f requirements-dev.txt ]; then pip install -r requirements-dev.txt; fi
        pip install -e .
    
    - name: Lint with ruff
      run: |
        ruff check .
    
    - name: Type check with mypy
      run: |
        mypy src tests
    
    - name: Test with pytest
      run: |
        pytest tests/ --cov=src --cov-report=xml
    
    - name: Upload coverage report
      uses: codecov/codecov-action@v1
  
  build:
    needs: test
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v2
    
    - name: Set up Docker Buildx
      uses: docker/setup-buildx-action@v1
    
    - name: Login to DockerHub
      uses: docker/login-action@v1
      with:
        username: ${{ secrets.DOCKERHUB_USERNAME }}
        password: ${{ secrets.DOCKERHUB_TOKEN }}
    
    - name: Build and push
      uses: docker/build-push-action@v2
      with:
        push: true
        tags: yourusername/fastapi-shield-app:latest
  
  deploy:
    needs: build
    runs-on: ubuntu-latest
    
    steps:
    - name: Deploy to Kubernetes
      uses: steebchen/kubectl@v2
      with:
        config: ${{ secrets.KUBE_CONFIG_DATA }}
        command: apply -f kubernetes/deployment.yaml
    
    - name: Verify deployment
      uses: steebchen/kubectl@v2
      with:
        config: ${{ secrets.KUBE_CONFIG_DATA }}
        command: rollout status deployment/fastapi-shield-app
```

## Multi-Environment Configuration

Create configuration for different environments:

```python
from enum import Enum
from pydantic_settings import BaseSettings

class Environment(str, Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"

class Settings(BaseSettings):
    app_name: str = "FastAPI Shield App"
    environment: Environment = Environment.DEVELOPMENT
    debug: bool = False
    
    # Database
    database_url: str
    
    # Security
    secret_key: str
    allowed_hosts: list[str] = ["*"]
    
    # Logging
    log_level: str = "INFO"
    
    # Override settings based on environment
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        
        if self.environment == Environment.DEVELOPMENT:
            self.debug = True
            self.log_level = "DEBUG"
        
        elif self.environment == Environment.PRODUCTION:
            self.debug = False
            self.allowed_hosts = ["api.yourdomain.com"]
    
    class Config:
        env_file = ".env"
        env_nested_delimiter = "__"

settings = Settings()
```

## Monitoring FastAPI Shield Performance

Set up monitoring for shield performance specifically:

```python
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from contextvars import ContextVar
import time
import logging

app = FastAPI()

# Track shield performance in the current request context
request_shields_var = ContextVar("request_shields", default=[])

@shield(name="MonitoredShield")
def monitored_shield(value: int):
    shield_name = "MonitoredShield"
    start_time = time.time()
    
    try:
        # Regular shield logic
        if value < 0:
            raise ValueError("Value must be positive")
        result = value
        success = True
    except Exception as e:
        success = False
        raise
    finally:
        # Record shield execution stats
        duration = time.time() - start_time
        shield_info = {
            "name": shield_name,
            "duration_ms": round(duration * 1000, 2),
            "success": success
        }
        
        # Add to context var
        shields = request_shields_var.get()
        shields.append(shield_info)
        request_shields_var.set(shields)
    
    return result

@app.middleware("http")
async def shield_monitoring_middleware(request: Request, call_next):
    # Reset context var for this request
    token = request_shields_var.set([])
    
    try:
        # Process request
        response = await call_next(request)
        
        # Get shield stats for this request
        shields = request_shields_var.get()
        
        # Log shield performance
        if shields:
            total_shield_time = sum(s["duration_ms"] for s in shields)
            shield_names = [s["name"] for s in shields]
            logging.info(
                f"Request used {len(shields)} shields: {', '.join(shield_names)}. "
                f"Total shield time: {total_shield_time:.2f}ms"
            )
        
        return response
    finally:
        # Reset context var
        request_shields_var.reset(token)

@app.get("/items/{item_id}")
async def get_item(item_id: int = ShieldedDepends(monitored_shield)):
    return {"item_id": item_id}
```

## Disaster Recovery

Plan for disaster recovery:

1. **Regular Backups**: Schedule database backups
2. **Failover Strategy**: Configure database replicas and automatic failover
3. **Recovery Testing**: Regularly test recovery from backups
4. **Incident Response Plan**: Define procedures for different types of failures

Example database backup script:

```python
import subprocess
import datetime
import os

def backup_postgres_db(db_name, backup_dir):
    """Create a database backup"""
    date_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = os.path.join(backup_dir, f"{db_name}_{date_str}.sql")
    
    try:
        subprocess.run(
            ["pg_dump", "-Fc", db_name, "-f", backup_file],
            check=True
        )
        print(f"Backup created at {backup_file}")
        return backup_file
    except subprocess.CalledProcessError as e:
        print(f"Backup failed: {e}")
        return None

def restore_postgres_db(backup_file, db_name):
    """Restore database from backup"""
    try:
        subprocess.run(
            ["pg_restore", "-d", db_name, backup_file],
            check=True
        )
        print(f"Database {db_name} restored from {backup_file}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Restore failed: {e}")
        return False
```

## Blue-Green Deployment

Implement blue-green deployment for zero-downtime updates:

```yaml
# Kubernetes blue-green deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fastapi-shield-blue
spec:
  replicas: 3
  selector:
    matchLabels:
      app: fastapi-shield
      version: blue
  template:
    metadata:
      labels:
        app: fastapi-shield
        version: blue
    spec:
      containers:
      - name: fastapi-shield
        image: your-registry/fastapi-shield-app:1.0.0
        # ... rest of the deployment spec

---

apiVersion: apps/v1
kind: Deployment
metadata:
  name: fastapi-shield-green
spec:
  replicas: 0  # Initially zero
  selector:
    matchLabels:
      app: fastapi-shield
      version: green
  template:
    metadata:
      labels:
        app: fastapi-shield
        version: green
    spec:
      containers:
      - name: fastapi-shield
        image: your-registry/fastapi-shield-app:1.0.1
        # ... rest of the deployment spec

---

apiVersion: v1
kind: Service
metadata:
  name: fastapi-shield-service
spec:
  selector:
    app: fastapi-shield
    version: blue  # Initially points to blue
  ports:
  - port: 80
    targetPort: 8000
  type: ClusterIP
```

Script to switch traffic:

```python
import subprocess

def switch_to_green():
    """Switch traffic to the green deployment"""
    # Scale up green deployment
    subprocess.run([
        "kubectl", "scale", "deployment", 
        "fastapi-shield-green", "--replicas=3"
    ])
    
    # Wait for green deployment to be ready
    subprocess.run([
        "kubectl", "rollout", "status", 
        "deployment/fastapi-shield-green"
    ])
    
    # Update service selector to green
    subprocess.run([
        "kubectl", "patch", "service", "fastapi-shield-service",
        "-p", '{"spec":{"selector":{"version":"green"}}}'
    ])
    
    # Scale down blue deployment
    subprocess.run([
        "kubectl", "scale", "deployment", 
        "fastapi-shield-blue", "--replicas=0"
    ])
    
    print("Switched traffic to green deployment")

def rollback_to_blue():
    """Rollback to the blue deployment"""
    # Scale up blue deployment
    subprocess.run([
        "kubectl", "scale", "deployment", 
        "fastapi-shield-blue", "--replicas=3"
    ])
    
    # Wait for blue deployment to be ready
    subprocess.run([
        "kubectl", "rollout", "status", 
        "deployment/fastapi-shield-blue"
    ])
    
    # Update service selector to blue
    subprocess.run([
        "kubectl", "patch", "service", "fastapi-shield-service",
        "-p", '{"spec":{"selector":{"version":"blue"}}}'
    ])
    
    # Scale down green deployment
    subprocess.run([
        "kubectl", "scale", "deployment", 
        "fastapi-shield-green", "--replicas=0"
    ])
    
    print("Rolled back to blue deployment")
```

## Conclusion

Deploying FastAPI Shield applications to production requires careful planning and consideration of security, scalability, and reliability. By following the best practices outlined in this guide, you can ensure your application performs well, remains secure, and is easy to maintain and scale in a production environment.

Remember that the needs of your specific application may vary, so adapt these recommendations to suit your particular use case. Regular monitoring and continuous improvement are key to maintaining a healthy production environment for your FastAPI Shield applications. 