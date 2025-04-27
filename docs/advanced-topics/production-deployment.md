# Production Deployment

This guide provides best practices for deploying FastAPI Shield in production environments. Following these recommendations will help ensure your application is secure, performant, and reliable.

## Production Security Checklist

Before deploying your FastAPI Shield application to production, verify:

- ✅ All shields are properly tested with unit and integration tests
- ✅ Production secrets are stored securely (not hardcoded)
- ✅ HTTPS is enforced for all connections
- ✅ Rate limiting shields are in place for all public endpoints
- ✅ Proper logging is implemented for security events
- ✅ CORS is configured correctly to limit cross-origin requests
- ✅ A Web Application Firewall (WAF) is in place for additional protection

## Environment Configuration

### Environment Variables

Store sensitive configuration in environment variables:

```python
from fastapi import FastAPI
import os
from fastapi_shield import shield, ShieldedDepends

# Get secrets from environment variables
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("No SECRET_KEY set for JWT authentication")

# Use with shield for JWT authentication
@shield(name="JWT Authentication")
def authenticate_user(token: str):
    # Use SECRET_KEY from environment variable for JWT decoding
    # ...
```

### Configuration Management

For more complex applications, use a dedicated configuration management system:

```python
from fastapi import FastAPI
from pydantic_settings import BaseSettings
from typing import List

class Settings(BaseSettings):
    app_name: str = "FastAPI Shield App"
    secret_key: str
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    allowed_origins: List[str] = ["https://example.com"]
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()
app = FastAPI(title=settings.app_name)

# Use settings in your shields
```

## Deployment Options

### Docker Deployment

Use Docker to containerize your application:

```dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run as non-root user for security
RUN adduser --disabled-password --gecos "" appuser
USER appuser

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

Use docker-compose for multi-container applications:

```yaml
version: '3'

services:
  api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - SECRET_KEY=${SECRET_KEY}
      - DATABASE_URL=${DATABASE_URL}
    depends_on:
      - db
      - redis
  
  db:
    image: postgres:13
    volumes:
      - postgres_data:/var/lib/postgresql/data
    environment:
      - POSTGRES_PASSWORD=${DB_PASSWORD}
      - POSTGRES_USER=${DB_USER}
      - POSTGRES_DB=${DB_NAME}
  
  redis:
    image: redis:6
    volumes:
      - redis_data:/data

volumes:
  postgres_data:
  redis_data:
```

### Kubernetes Deployment

For scaling in production, consider Kubernetes:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fastapi-shield-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: fastapi-shield-app
  template:
    metadata:
      labels:
        app: fastapi-shield-app
    spec:
      containers:
      - name: fastapi-shield-app
        image: your-registry/fastapi-shield-app:latest
        ports:
        - containerPort: 8000
        env:
        - name: SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: app-secrets
              key: secret-key
        resources:
          limits:
            cpu: "500m"
            memory: "512Mi"
          requests:
            cpu: "100m"
            memory: "256Mi"
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 10
```

## Performance Optimization

### Asynchronous Shields

For I/O-bound operations, use asynchronous shields:

```python
@shield(name="Async Database Check")
async def check_database(user_id: int):
    # Asynchronous database query
    result = await db.fetch_one("SELECT * FROM users WHERE id = :id", {"id": user_id})
    if not result:
        return None
    return result
```

### Shield Caching

Cache shield results for improved performance:

```python
from fastapi import FastAPI, Depends
from fastapi_shield import shield, ShieldedDepends
import redis.asyncio as redis
import pickle
import hashlib
import json

# Redis connection
redis_client = redis.Redis.from_url("redis://localhost:6379/0")

def get_cache_key(shield_name, *args, **kwargs):
    """Generate a unique cache key based on shield name and args"""
    key_dict = {"name": shield_name, "args": args, "kwargs": kwargs}
    return f"shield:{hashlib.md5(json.dumps(key_dict).encode()).hexdigest()}"

# Cache decorator for shields
def cached_shield(name, ttl=300, **shield_kwargs):
    def decorator(func):
        @shield(name=name, **shield_kwargs)
        async def wrapper(*args, **kwargs):
            # Generate cache key
            cache_key = get_cache_key(name, *args, **kwargs)
            
            # Try to get from cache
            cached = await redis_client.get(cache_key)
            if cached:
                return pickle.loads(cached)
            
            # Calculate result
            result = await func(*args, **kwargs)
            
            # Cache result if not None
            if result is not None:
                await redis_client.setex(
                    cache_key, 
                    ttl, 
                    pickle.dumps(result)
                )
            
            return result
        return wrapper
    return decorator

# Usage
@cached_shield(name="User Permissions", ttl=60)
async def get_user_permissions(user_id: int):
    # Expensive operation to fetch user permissions
    permissions = await db.fetch_all(
        "SELECT permission FROM user_permissions WHERE user_id = :id", 
        {"id": user_id}
    )
    return [p["permission"] for p in permissions]

@app.get("/protected")
async def protected_endpoint(
    permissions: list = ShieldedDepends(get_user_permissions)
):
    return {"permissions": permissions}
```

### Resource Management

Use proper connection pooling for databases:

```python
from fastapi import FastAPI, Depends
from fastapi_shield import shield, ShieldedDepends
import databases
import os

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://user:password@localhost/dbname")
database = databases.Database(DATABASE_URL)

app = FastAPI()

@app.on_event("startup")
async def startup():
    await database.connect()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

@shield(name="Database User")
async def get_user(user_id: int):
    user = await database.fetch_one("SELECT * FROM users WHERE id = :id", {"id": user_id})
    if not user:
        return None
    return dict(user)
```

## Observability

### Health Checks

Implement health check endpoints:

```python
from fastapi import FastAPI, Depends
from fastapi_shield import shield, ShieldedDepends
import databases

app = FastAPI()
database = databases.Database("postgresql://user:password@localhost/dbname")

class HealthCheck:
    def __init__(self):
        self.services = {
            "database": self._check_database,
            "redis": self._check_redis
        }
    
    async def _check_database(self):
        try:
            await database.fetch_one("SELECT 1")
            return True
        except Exception:
            return False
    
    async def _check_redis(self):
        try:
            await redis_client.ping()
            return True
        except Exception:
            return False
    
    async def get_status(self):
        results = {}
        for service, check in self.services.items():
            results[service] = await check()
        
        overall_health = all(results.values())
        return {
            "status": "healthy" if overall_health else "unhealthy",
            "services": results
        }

health_checker = HealthCheck()

@app.get("/health")
async def health_check():
    return await health_checker.get_status()
```

### Structured Logging

Implement structured logging for better observability:

```python
from fastapi import FastAPI, Request
import logging
import json
import time
from datetime import datetime
import uuid

# Configure logger
logger = logging.getLogger("app")
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(handler)
logger.setLevel(logging.INFO)

app = FastAPI()

@app.middleware("http")
async def logging_middleware(request: Request, call_next):
    request_id = str(uuid.uuid4())
    start_time = time.time()
    
    # Add request_id to the request state
    request.state.request_id = request_id
    
    # Log request
    logger.info(json.dumps({
        "timestamp": datetime.utcnow().isoformat(),
        "request_id": request_id,
        "type": "request",
        "method": request.method,
        "path": request.url.path,
        "client_ip": request.client.host
    }))
    
    try:
        response = await call_next(request)
        
        # Log response
        logger.info(json.dumps({
            "timestamp": datetime.utcnow().isoformat(),
            "request_id": request_id,
            "type": "response",
            "status_code": response.status_code,
            "duration_ms": round((time.time() - start_time) * 1000, 2)
        }))
        
        return response
    except Exception as e:
        # Log exception
        logger.error(json.dumps({
            "timestamp": datetime.utcnow().isoformat(),
            "request_id": request_id,
            "type": "error",
            "error": str(e),
            "duration_ms": round((time.time() - start_time) * 1000, 2)
        }))
        raise
```

### Metrics

Implement metrics collection for monitoring:

```python
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi_shield import shield, ShieldedDepends
from prometheus_fastapi_instrumentator import Instrumentator

app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://example.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add metrics instrumentation
Instrumentator().instrument(app).expose(app)
```

## Auto-Scaling and High Availability

### Load Balancing

When deploying behind a load balancer, ensure appropriate headers are forwarded:

```python
from fastapi import FastAPI, Request

app = FastAPI()

@app.middleware("http")
async def trust_proxy(request: Request, call_next):
    # Get real client IP from X-Forwarded-For when behind a proxy
    if "X-Forwarded-For" in request.headers:
        # First address in the list is the client
        forwarded_for = request.headers["X-Forwarded-For"].split(",")[0].strip()
        # Update the client host
        request.scope["client"] = (forwarded_for, request.scope["client"][1])
    
    # Get real scheme (http/https) from X-Forwarded-Proto
    if "X-Forwarded-Proto" in request.headers:
        request.scope["scheme"] = request.headers["X-Forwarded-Proto"]
        
    return await call_next(request)
```

### Multi-Region Deployment

For globally distributed applications, consider multi-region deployment:

1. Deploy identical instances in multiple regions
2. Use global DNS routing (like AWS Route 53 or Cloudflare)
3. Use a distributed database or replicate data between regions
4. Implement shared cache invalidation across regions

## Security Headers

Add security headers to your application:

```python
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi_shield import shield, ShieldedDepends

app = FastAPI()

@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    
    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    
    # Only set HSTS if using HTTPS
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    
    return response
```

## CI/CD Integration

Implement a robust CI/CD pipeline that includes:

1. Automated unit and integration tests
2. Security scanning (SonarQube, Snyk, etc.)
3. Dependency vulnerability scanning
4. Type checking with mypy
5. Linting and code style checks
6. Automated deployment to staging and production

## Summary

By following these best practices, you can deploy FastAPI Shield applications that are:

- Secure and protected against common vulnerabilities
- Performant and scalable under load
- Observable and easy to monitor
- Reliable with high availability
- Maintainable with proper CI/CD processes

Remember to regularly update dependencies, conduct security audits, and monitor your application for unusual behavior. 