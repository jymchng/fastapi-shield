"""Microservice integration framework for FastAPI Shield.

This module provides comprehensive microservice integration capabilities including
service discovery, circuit breakers, distributed security policies, service mesh
integration, and distributed tracing. It enables FastAPI Shield to work seamlessly
in modern microservice architectures with sophisticated resilience patterns.

Key Components:
    - ServiceRegistry: Abstract service discovery interface
    - ConsulServiceRegistry: Consul-based service discovery
    - EurekaServiceRegistry: Eureka-based service discovery  
    - CircuitBreaker: Circuit breaker pattern implementation
    - DistributedSecurityManager: Cross-service security policies
    - ServiceMeshIntegration: Istio/Linkerd integration
    - MicroserviceShield: Shield for microservice environments
"""

import asyncio
import hashlib
import json
import logging
import time
import traceback
import uuid
import random
import statistics
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import (
    Any, Dict, List, Optional, Union, Callable, Set, Tuple,
    TYPE_CHECKING, NamedTuple, Protocol
)
from contextlib import asynccontextmanager
from threading import RLock
from urllib.parse import urlparse, urljoin
import base64
import hmac

import httpx
import jwt
from fastapi import HTTPException, Request, Response, Header
from fastapi.responses import JSONResponse

from fastapi_shield.shield import Shield, shield

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class ServiceStatus(str, Enum):
    """Service health status in microservice environment."""
    UP = "UP"
    DOWN = "DOWN"
    OUT_OF_SERVICE = "OUT_OF_SERVICE"
    STARTING = "STARTING"
    UNKNOWN = "UNKNOWN"


class CircuitBreakerState(str, Enum):
    """Circuit breaker states."""
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class AuthenticationMode(str, Enum):
    """Authentication modes for microservices."""
    JWT = "jwt"
    OAUTH2 = "oauth2"
    API_KEY = "api_key"
    MUTUAL_TLS = "mutual_tls"
    SERVICE_TOKEN = "service_token"


class TracingProvider(str, Enum):
    """Distributed tracing providers."""
    JAEGER = "jaeger"
    ZIPKIN = "zipkin"
    OPENTELEMETRY = "opentelemetry"
    DATADOG = "datadog"


class ServiceMeshType(str, Enum):
    """Supported service mesh types."""
    ISTIO = "istio"
    LINKERD = "linkerd"
    CONSUL_CONNECT = "consul_connect"
    ENVOY = "envoy"


@dataclass
class ServiceInstance:
    """Represents a service instance in the microservice architecture."""
    service_id: str
    instance_id: str
    host: str
    port: int
    status: ServiceStatus = ServiceStatus.UP
    metadata: Dict[str, str] = field(default_factory=dict)
    tags: Set[str] = field(default_factory=set)
    health_check_url: Optional[str] = None
    schema: str = "http"
    version: str = "1.0.0"
    datacenter: str = "dc1"
    
    @property
    def url(self) -> str:
        """Get service instance URL."""
        return f"{self.schema}://{self.host}:{self.port}"
    
    @property
    def service_url(self) -> str:
        """Get service base URL."""
        return self.url
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "service_id": self.service_id,
            "instance_id": self.instance_id,
            "host": self.host,
            "port": self.port,
            "status": self.status.value,
            "metadata": self.metadata,
            "tags": list(self.tags),
            "health_check_url": self.health_check_url,
            "schema": self.schema,
            "version": self.version,
            "datacenter": self.datacenter,
            "url": self.url
        }


@dataclass
class CircuitBreakerMetrics:
    """Circuit breaker metrics."""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    timeout_requests: int = 0
    rejected_requests: int = 0
    state_changes: int = 0
    last_failure_time: float = 0.0
    average_response_time: float = 0.0
    response_times: List[float] = field(default_factory=list)
    
    @property
    def failure_rate(self) -> float:
        """Calculate failure rate."""
        if self.total_requests == 0:
            return 0.0
        return (self.failed_requests + self.timeout_requests) / self.total_requests
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        return 1.0 - self.failure_rate
    
    def update_response_time(self, response_time: float):
        """Update response time metrics."""
        self.response_times.append(response_time)
        if len(self.response_times) > 100:
            self.response_times.pop(0)
        self.average_response_time = statistics.mean(self.response_times)


@dataclass
class DistributedSecurityPolicy:
    """Distributed security policy for microservices."""
    policy_id: str
    service_pattern: str  # Regex pattern for service matching
    authentication_required: bool = True
    authorization_rules: List[str] = field(default_factory=list)  # Permission rules
    rate_limit_per_minute: Optional[int] = None
    allowed_origins: Set[str] = field(default_factory=set)
    required_scopes: Set[str] = field(default_factory=set)
    encryption_required: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TraceContext:
    """Distributed tracing context."""
    trace_id: str
    span_id: str
    parent_span_id: Optional[str] = None
    baggage: Dict[str, str] = field(default_factory=dict)
    flags: int = 0
    
    def to_headers(self) -> Dict[str, str]:
        """Convert to HTTP headers for propagation."""
        headers = {
            "X-Trace-Id": self.trace_id,
            "X-Span-Id": self.span_id,
            "X-Trace-Flags": str(self.flags)
        }
        if self.parent_span_id:
            headers["X-Parent-Span-Id"] = self.parent_span_id
        
        # Add baggage
        if self.baggage:
            baggage_str = ",".join(f"{k}={v}" for k, v in self.baggage.items())
            headers["X-Trace-Baggage"] = baggage_str
        
        return headers
    
    @classmethod
    def from_headers(cls, headers: Dict[str, str]) -> Optional['TraceContext']:
        """Create trace context from HTTP headers."""
        trace_id = headers.get("X-Trace-Id") or headers.get("x-trace-id")
        if not trace_id:
            return None
        
        span_id = headers.get("X-Span-Id") or headers.get("x-span-id")
        if not span_id:
            return None
        
        parent_span_id = headers.get("X-Parent-Span-Id") or headers.get("x-parent-span-id")
        flags = int(headers.get("X-Trace-Flags", "0"))
        
        # Parse baggage
        baggage = {}
        baggage_header = headers.get("X-Trace-Baggage") or headers.get("x-trace-baggage")
        if baggage_header:
            for item in baggage_header.split(","):
                if "=" in item:
                    key, value = item.split("=", 1)
                    baggage[key.strip()] = value.strip()
        
        return cls(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            baggage=baggage,
            flags=flags
        )


class ServiceRegistry(ABC):
    """Abstract interface for service discovery."""
    
    @abstractmethod
    async def register_service(self, service: ServiceInstance) -> bool:
        """Register a service instance."""
        pass
    
    @abstractmethod
    async def deregister_service(self, service_id: str, instance_id: str) -> bool:
        """Deregister a service instance."""
        pass
    
    @abstractmethod
    async def discover_services(self, service_id: str) -> List[ServiceInstance]:
        """Discover all instances of a service."""
        pass
    
    @abstractmethod
    async def get_healthy_services(self, service_id: str) -> List[ServiceInstance]:
        """Get only healthy instances of a service."""
        pass
    
    @abstractmethod
    async def health_check(self) -> bool:
        """Check registry health."""
        pass


class ConsulServiceRegistry(ServiceRegistry):
    """Consul-based service discovery implementation."""
    
    def __init__(
        self,
        consul_host: str = "localhost",
        consul_port: int = 8500,
        datacenter: str = "dc1",
        token: Optional[str] = None,
        scheme: str = "http",
        health_check_interval: int = 30
    ):
        self.consul_host = consul_host
        self.consul_port = consul_port
        self.datacenter = datacenter
        self.token = token
        self.scheme = scheme
        self.health_check_interval = health_check_interval
        
        self.base_url = f"{scheme}://{consul_host}:{consul_port}/v1"
        self._client: Optional[httpx.AsyncClient] = None
        self._registered_services: Dict[str, ServiceInstance] = {}
        self._lock = RLock()
    
    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if not self._client:
            headers = {}
            if self.token:
                headers["X-Consul-Token"] = self.token
            
            self._client = httpx.AsyncClient(
                headers=headers,
                timeout=30.0
            )
        return self._client
    
    async def register_service(self, service: ServiceInstance) -> bool:
        """Register service with Consul."""
        try:
            client = await self._get_client()
            
            # Prepare service registration data
            registration_data = {
                "ID": service.instance_id,
                "Name": service.service_id,
                "Address": service.host,
                "Port": service.port,
                "Tags": list(service.tags),
                "Meta": service.metadata,
                "Check": {
                    "HTTP": service.health_check_url or f"{service.url}/health",
                    "Interval": f"{self.health_check_interval}s",
                    "Timeout": "10s"
                }
            }
            
            response = await client.put(
                f"{self.base_url}/agent/service/register",
                json=registration_data
            )
            
            if response.status_code == 200:
                with self._lock:
                    self._registered_services[service.instance_id] = service
                logger.info(f"Registered service {service.service_id} instance {service.instance_id}")
                return True
            else:
                logger.error(f"Failed to register service: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error registering service with Consul: {e}")
            return False
    
    async def deregister_service(self, service_id: str, instance_id: str) -> bool:
        """Deregister service from Consul."""
        try:
            client = await self._get_client()
            
            response = await client.put(
                f"{self.base_url}/agent/service/deregister/{instance_id}"
            )
            
            if response.status_code == 200:
                with self._lock:
                    self._registered_services.pop(instance_id, None)
                logger.info(f"Deregistered service instance {instance_id}")
                return True
            else:
                logger.error(f"Failed to deregister service: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Error deregistering service from Consul: {e}")
            return False
    
    async def discover_services(self, service_id: str) -> List[ServiceInstance]:
        """Discover services from Consul."""
        try:
            client = await self._get_client()
            
            response = await client.get(
                f"{self.base_url}/catalog/service/{service_id}",
                params={"dc": self.datacenter}
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to discover services: {response.status_code}")
                return []
            
            services = response.json()
            instances = []
            
            for service_data in services:
                instance = ServiceInstance(
                    service_id=service_data["ServiceName"],
                    instance_id=service_data["ServiceID"],
                    host=service_data["ServiceAddress"] or service_data["Address"],
                    port=service_data["ServicePort"],
                    tags=set(service_data.get("ServiceTags", [])),
                    metadata=service_data.get("ServiceMeta", {}),
                    datacenter=service_data.get("Datacenter", self.datacenter)
                )
                instances.append(instance)
            
            return instances
            
        except Exception as e:
            logger.error(f"Error discovering services from Consul: {e}")
            return []
    
    async def get_healthy_services(self, service_id: str) -> List[ServiceInstance]:
        """Get healthy services from Consul."""
        try:
            client = await self._get_client()
            
            response = await client.get(
                f"{self.base_url}/health/service/{service_id}",
                params={"dc": self.datacenter, "passing": "true"}
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to get healthy services: {response.status_code}")
                return []
            
            services = response.json()
            instances = []
            
            for service_entry in services:
                service_data = service_entry["Service"]
                instance = ServiceInstance(
                    service_id=service_data["Service"],
                    instance_id=service_data["ID"],
                    host=service_data["Address"] or service_entry["Node"]["Address"],
                    port=service_data["Port"],
                    status=ServiceStatus.UP,
                    tags=set(service_data.get("Tags", [])),
                    metadata=service_data.get("Meta", {}),
                    datacenter=service_entry["Node"].get("Datacenter", self.datacenter)
                )
                instances.append(instance)
            
            return instances
            
        except Exception as e:
            logger.error(f"Error getting healthy services from Consul: {e}")
            return []
    
    async def health_check(self) -> bool:
        """Check Consul health."""
        try:
            client = await self._get_client()
            response = await client.get(f"{self.base_url}/status/leader")
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Consul health check failed: {e}")
            return False
    
    async def close(self):
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None


class EurekaServiceRegistry(ServiceRegistry):
    """Eureka-based service discovery implementation."""
    
    def __init__(
        self,
        eureka_url: str = "http://localhost:8761/eureka",
        app_name: str = "fastapi-shield",
        instance_id: Optional[str] = None,
        heartbeat_interval: int = 30
    ):
        self.eureka_url = eureka_url.rstrip("/")
        self.app_name = app_name
        self.instance_id = instance_id or str(uuid.uuid4())
        self.heartbeat_interval = heartbeat_interval
        
        self._client: Optional[httpx.AsyncClient] = None
        self._registered_services: Dict[str, ServiceInstance] = {}
        self._lock = RLock()
    
    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if not self._client:
            self._client = httpx.AsyncClient(
                headers={"Accept": "application/json", "Content-Type": "application/json"},
                timeout=30.0
            )
        return self._client
    
    async def register_service(self, service: ServiceInstance) -> bool:
        """Register service with Eureka."""
        try:
            client = await self._get_client()
            
            # Prepare Eureka registration data
            instance_data = {
                "instance": {
                    "instanceId": service.instance_id,
                    "app": service.service_id.upper(),
                    "hostName": service.host,
                    "ipAddr": service.host,
                    "port": {"$": service.port, "@enabled": "true"},
                    "status": service.status.value,
                    "healthCheckUrl": service.health_check_url or f"{service.url}/health",
                    "statusPageUrl": f"{service.url}/info",
                    "homePageUrl": service.url,
                    "dataCenterInfo": {
                        "@class": "com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo",
                        "name": "MyOwn"
                    },
                    "metadata": service.metadata
                }
            }
            
            response = await client.post(
                f"{self.eureka_url}/apps/{service.service_id.upper()}",
                json=instance_data
            )
            
            if response.status_code == 204:
                with self._lock:
                    self._registered_services[service.instance_id] = service
                logger.info(f"Registered service {service.service_id} with Eureka")
                return True
            else:
                logger.error(f"Failed to register with Eureka: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Error registering service with Eureka: {e}")
            return False
    
    async def deregister_service(self, service_id: str, instance_id: str) -> bool:
        """Deregister service from Eureka."""
        try:
            client = await self._get_client()
            
            response = await client.delete(
                f"{self.eureka_url}/apps/{service_id.upper()}/{instance_id}"
            )
            
            if response.status_code == 200:
                with self._lock:
                    self._registered_services.pop(instance_id, None)
                logger.info(f"Deregistered service {instance_id} from Eureka")
                return True
            else:
                logger.error(f"Failed to deregister from Eureka: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Error deregistering service from Eureka: {e}")
            return False
    
    async def discover_services(self, service_id: str) -> List[ServiceInstance]:
        """Discover services from Eureka."""
        try:
            client = await self._get_client()
            
            response = await client.get(
                f"{self.eureka_url}/apps/{service_id.upper()}"
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to discover services from Eureka: {response.status_code}")
                return []
            
            data = response.json()
            instances = []
            
            if "application" in data and "instance" in data["application"]:
                eureka_instances = data["application"]["instance"]
                if not isinstance(eureka_instances, list):
                    eureka_instances = [eureka_instances]
                
                for instance_data in eureka_instances:
                    status_map = {
                        "UP": ServiceStatus.UP,
                        "DOWN": ServiceStatus.DOWN,
                        "OUT_OF_SERVICE": ServiceStatus.OUT_OF_SERVICE,
                        "STARTING": ServiceStatus.STARTING
                    }
                    
                    instance = ServiceInstance(
                        service_id=instance_data["app"].lower(),
                        instance_id=instance_data["instanceId"],
                        host=instance_data["hostName"],
                        port=instance_data["port"]["$"],
                        status=status_map.get(instance_data["status"], ServiceStatus.UNKNOWN),
                        metadata=instance_data.get("metadata", {})
                    )
                    instances.append(instance)
            
            return instances
            
        except Exception as e:
            logger.error(f"Error discovering services from Eureka: {e}")
            return []
    
    async def get_healthy_services(self, service_id: str) -> List[ServiceInstance]:
        """Get healthy services from Eureka."""
        all_services = await self.discover_services(service_id)
        return [s for s in all_services if s.status == ServiceStatus.UP]
    
    async def health_check(self) -> bool:
        """Check Eureka health."""
        try:
            client = await self._get_client()
            response = await client.get(f"{self.eureka_url}/status")
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Eureka health check failed: {e}")
            return False
    
    async def send_heartbeat(self, service_id: str, instance_id: str) -> bool:
        """Send heartbeat to Eureka."""
        try:
            client = await self._get_client()
            response = await client.put(
                f"{self.eureka_url}/apps/{service_id.upper()}/{instance_id}"
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Failed to send heartbeat to Eureka: {e}")
            return False
    
    async def close(self):
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None


class CircuitBreaker:
    """Circuit breaker pattern implementation for service resilience."""
    
    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        expected_exception: type = Exception,
        success_threshold: int = 3,
        timeout: float = 30.0,
        half_open_max_calls: int = 3
    ):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        self.success_threshold = success_threshold
        self.timeout = timeout
        self.half_open_max_calls = half_open_max_calls
        
        self.state = CircuitBreakerState.CLOSED
        self.metrics = CircuitBreakerMetrics()
        self.failure_count = 0
        self.success_count = 0
        self.next_attempt_time = 0.0
        self.half_open_calls = 0
        
        self._lock = RLock()
    
    def can_execute(self) -> bool:
        """Check if execution is allowed."""
        with self._lock:
            current_time = time.time()
            
            if self.state == CircuitBreakerState.CLOSED:
                return True
            elif self.state == CircuitBreakerState.OPEN:
                if current_time >= self.next_attempt_time:
                    self.state = CircuitBreakerState.HALF_OPEN
                    self.half_open_calls = 0
                    self.metrics.state_changes += 1
                    logger.info(f"Circuit breaker {self.name} moved to HALF_OPEN")
                    return True
                return False
            elif self.state == CircuitBreakerState.HALF_OPEN:
                return self.half_open_calls < self.half_open_max_calls
            
            return False
    
    def record_success(self, response_time: float):
        """Record successful execution."""
        with self._lock:
            self.metrics.total_requests += 1
            self.metrics.successful_requests += 1
            self.metrics.update_response_time(response_time)
            
            if self.state == CircuitBreakerState.HALF_OPEN:
                self.success_count += 1
                self.half_open_calls += 1
                
                if self.success_count >= self.success_threshold:
                    self.state = CircuitBreakerState.CLOSED
                    self.failure_count = 0
                    self.success_count = 0
                    self.metrics.state_changes += 1
                    logger.info(f"Circuit breaker {self.name} moved to CLOSED")
            else:
                self.failure_count = 0
    
    def record_failure(self, exception: Exception):
        """Record failed execution."""
        with self._lock:
            self.metrics.total_requests += 1
            self.metrics.failed_requests += 1
            self.metrics.last_failure_time = time.time()
            
            if isinstance(exception, asyncio.TimeoutError):
                self.metrics.timeout_requests += 1
            
            if self.state == CircuitBreakerState.CLOSED:
                self.failure_count += 1
                
                if self.failure_count >= self.failure_threshold:
                    self.state = CircuitBreakerState.OPEN
                    self.next_attempt_time = time.time() + self.recovery_timeout
                    self.metrics.state_changes += 1
                    logger.warning(f"Circuit breaker {self.name} moved to OPEN")
            
            elif self.state == CircuitBreakerState.HALF_OPEN:
                self.state = CircuitBreakerState.OPEN
                self.next_attempt_time = time.time() + self.recovery_timeout
                self.success_count = 0
                self.half_open_calls = 0
                self.metrics.state_changes += 1
                logger.warning(f"Circuit breaker {self.name} moved back to OPEN")
    
    def record_rejection(self):
        """Record rejected execution."""
        with self._lock:
            self.metrics.rejected_requests += 1
    
    async def execute(self, func: Callable, *args, **kwargs):
        """Execute function with circuit breaker protection."""
        if not self.can_execute():
            self.record_rejection()
            raise HTTPException(
                status_code=503,
                detail=f"Circuit breaker {self.name} is {self.state.value}"
            )
        
        start_time = time.perf_counter()
        
        try:
            # Execute with timeout
            result = await asyncio.wait_for(
                func(*args, **kwargs) if asyncio.iscoroutinefunction(func) else func(*args, **kwargs),
                timeout=self.timeout
            )
            
            response_time = (time.perf_counter() - start_time) * 1000
            self.record_success(response_time)
            return result
            
        except Exception as e:
            self.record_failure(e)
            raise
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get circuit breaker metrics."""
        with self._lock:
            return {
                "name": self.name,
                "state": self.state.value,
                "total_requests": self.metrics.total_requests,
                "successful_requests": self.metrics.successful_requests,
                "failed_requests": self.metrics.failed_requests,
                "timeout_requests": self.metrics.timeout_requests,
                "rejected_requests": self.metrics.rejected_requests,
                "failure_rate": self.metrics.failure_rate,
                "success_rate": self.metrics.success_rate,
                "average_response_time": self.metrics.average_response_time,
                "state_changes": self.metrics.state_changes,
                "failure_count": self.failure_count,
                "success_count": self.success_count
            }


class DistributedSecurityManager:
    """Manages distributed security policies across microservices."""
    
    def __init__(
        self,
        jwt_secret: str,
        jwt_algorithm: str = "HS256",
        jwt_expiration: int = 3600,
        service_registry: Optional[ServiceRegistry] = None
    ):
        self.jwt_secret = jwt_secret
        self.jwt_algorithm = jwt_algorithm
        self.jwt_expiration = jwt_expiration
        self.service_registry = service_registry
        
        self.policies: Dict[str, DistributedSecurityPolicy] = {}
        self.service_tokens: Dict[str, str] = {}  # Service-to-service tokens
        self.token_cache: Dict[str, Dict[str, Any]] = {}  # Token validation cache
        
        self._lock = RLock()
    
    def add_policy(self, policy: DistributedSecurityPolicy):
        """Add a security policy."""
        with self._lock:
            self.policies[policy.policy_id] = policy
            logger.info(f"Added security policy {policy.policy_id}")
    
    def remove_policy(self, policy_id: str) -> bool:
        """Remove a security policy."""
        with self._lock:
            if policy_id in self.policies:
                del self.policies[policy_id]
                logger.info(f"Removed security policy {policy_id}")
                return True
            return False
    
    def get_matching_policies(self, service_id: str) -> List[DistributedSecurityPolicy]:
        """Get policies matching a service."""
        import re
        matching_policies = []
        
        with self._lock:
            for policy in self.policies.values():
                try:
                    if re.match(policy.service_pattern, service_id):
                        matching_policies.append(policy)
                except re.error:
                    logger.warning(f"Invalid regex pattern in policy {policy.policy_id}: {policy.service_pattern}")
        
        return matching_policies
    
    def generate_service_token(self, service_id: str, scopes: List[str] = None) -> str:
        """Generate JWT token for service-to-service communication."""
        now = datetime.utcnow()
        iat_timestamp = int(now.timestamp())
        exp_timestamp = int((now + timedelta(seconds=self.jwt_expiration)).timestamp())
        
        payload = {
            "iss": "fastapi-shield",  # Issuer
            "sub": service_id,        # Subject (service ID)
            "aud": "microservices",   # Audience
            "iat": iat_timestamp,     # Issued at
            "exp": exp_timestamp,     # Expiration
            "scopes": scopes or [],
            "type": "service_token"
        }
        
        token = jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_algorithm)
        
        with self._lock:
            self.service_tokens[service_id] = token
        
        return token
    
    def validate_service_token(self, token: str) -> Dict[str, Any]:
        """Validate and decode service token."""
        try:
            # Check cache first
            with self._lock:
                if token in self.token_cache:
                    cached_data = self.token_cache[token]
                    if cached_data["exp"] > time.time():
                        return cached_data["payload"]
                    else:
                        del self.token_cache[token]
            
            # Validate token
            payload = jwt.decode(
                token, 
                self.jwt_secret, 
                algorithms=[self.jwt_algorithm],
                audience="microservices"
            )
            
            # Cache the result
            with self._lock:
                self.token_cache[token] = {
                    "payload": payload,
                    "exp": payload.get("exp", 0)
                }
            
            return payload
            
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token has expired")
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="Invalid token")
    
    def check_authorization(self, service_id: str, required_scopes: Set[str], token_payload: Dict[str, Any]) -> bool:
        """Check if service is authorized for required scopes."""
        token_scopes = set(token_payload.get("scopes", []))
        return required_scopes.issubset(token_scopes)
    
    def create_inter_service_headers(self, source_service: str, target_service: str) -> Dict[str, str]:
        """Create headers for inter-service communication."""
        token = self.generate_service_token(source_service)
        
        return {
            "Authorization": f"Bearer {token}",
            "X-Service-Source": source_service,
            "X-Service-Target": target_service,
            "X-Request-ID": str(uuid.uuid4()),
            "X-Timestamp": str(int(time.time()))
        }
    
    def get_security_metrics(self) -> Dict[str, Any]:
        """Get security metrics."""
        with self._lock:
            return {
                "total_policies": len(self.policies),
                "active_service_tokens": len(self.service_tokens),
                "cached_token_validations": len(self.token_cache),
                "policies": {
                    policy_id: {
                        "service_pattern": policy.service_pattern,
                        "authentication_required": policy.authentication_required,
                        "authorization_rules_count": len(policy.authorization_rules),
                        "rate_limit": policy.rate_limit_per_minute,
                        "required_scopes": list(policy.required_scopes)
                    }
                    for policy_id, policy in self.policies.items()
                }
            }


class DistributedTracing:
    """Distributed tracing implementation for microservices."""
    
    def __init__(
        self,
        service_name: str,
        provider: TracingProvider = TracingProvider.JAEGER,
        endpoint: Optional[str] = None,
        sampling_rate: float = 1.0
    ):
        self.service_name = service_name
        self.provider = provider
        self.endpoint = endpoint
        self.sampling_rate = sampling_rate
        
        self.active_spans: Dict[str, Dict[str, Any]] = {}
        self._lock = RLock()
    
    def create_trace_context(self, operation_name: str, parent_context: Optional[TraceContext] = None) -> TraceContext:
        """Create new trace context."""
        trace_id = parent_context.trace_id if parent_context else str(uuid.uuid4()).replace("-", "")
        span_id = str(uuid.uuid4()).replace("-", "")[:16]
        parent_span_id = parent_context.span_id if parent_context else None
        
        # Inherit baggage from parent
        baggage = parent_context.baggage.copy() if parent_context else {}
        
        # Determine if this trace should be sampled
        flags = 1 if (parent_context and parent_context.flags) or (random.random() < self.sampling_rate) else 0
        
        context = TraceContext(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            baggage=baggage,
            flags=flags
        )
        
        # Start span
        self.start_span(context, operation_name)
        
        return context
    
    def start_span(self, context: TraceContext, operation_name: str):
        """Start a new span."""
        span_data = {
            "operation_name": operation_name,
            "service_name": self.service_name,
            "start_time": time.time(),
            "tags": {},
            "logs": []
        }
        
        with self._lock:
            self.active_spans[context.span_id] = span_data
    
    def add_span_tag(self, context: TraceContext, key: str, value: Any):
        """Add tag to active span."""
        with self._lock:
            if context.span_id in self.active_spans:
                self.active_spans[context.span_id]["tags"][key] = str(value)
    
    def add_span_log(self, context: TraceContext, message: str, level: str = "info"):
        """Add log to active span."""
        log_entry = {
            "timestamp": time.time(),
            "level": level,
            "message": message
        }
        
        with self._lock:
            if context.span_id in self.active_spans:
                self.active_spans[context.span_id]["logs"].append(log_entry)
    
    def finish_span(self, context: TraceContext):
        """Finish active span."""
        with self._lock:
            if context.span_id in self.active_spans:
                span_data = self.active_spans[context.span_id]
                span_data["end_time"] = time.time()
                span_data["duration"] = span_data["end_time"] - span_data["start_time"]
                
                # Send to tracing backend if sampled
                if context.flags:
                    self._send_span(context, span_data)
                
                del self.active_spans[context.span_id]
    
    def _send_span(self, context: TraceContext, span_data: Dict[str, Any]):
        """Send span data to tracing backend."""
        try:
            # This would integrate with actual tracing systems like Jaeger/Zipkin
            # For now, we'll just log the span
            logger.debug(f"Trace span: {context.trace_id}/{context.span_id} - {span_data}")
            
            # In production, this would send to the configured endpoint
            if self.endpoint:
                # Implementation would depend on the tracing provider
                pass
                
        except Exception as e:
            logger.error(f"Failed to send span to tracing backend: {e}")
    
    @asynccontextmanager
    async def trace_context(self, operation_name: str, parent_context: Optional[TraceContext] = None):
        """Context manager for tracing."""
        context = self.create_trace_context(operation_name, parent_context)
        try:
            yield context
        except Exception as e:
            self.add_span_tag(context, "error", True)
            self.add_span_log(context, f"Error: {str(e)}", "error")
            raise
        finally:
            self.finish_span(context)


class ServiceMeshIntegration:
    """Integration with service mesh technologies."""
    
    def __init__(
        self,
        mesh_type: ServiceMeshType,
        namespace: str = "default",
        config: Optional[Dict[str, Any]] = None
    ):
        self.mesh_type = mesh_type
        self.namespace = namespace
        self.config = config or {}
        
        self.mesh_headers: Dict[str, str] = {}
        self.traffic_policies: Dict[str, Dict[str, Any]] = {}
        self._initialize_mesh_integration()
    
    def _initialize_mesh_integration(self):
        """Initialize mesh-specific integration."""
        if self.mesh_type == ServiceMeshType.ISTIO:
            self.mesh_headers.update({
                "X-Istio-Namespace": self.namespace,
                "X-Forwarded-Client-Cert": "",  # Will be populated by Istio
            })
        elif self.mesh_type == ServiceMeshType.LINKERD:
            self.mesh_headers.update({
                "L5d-Dst-Override": "",  # For traffic splitting
                "L5d-Req-Id": "",       # Request ID
            })
        elif self.mesh_type == ServiceMeshType.CONSUL_CONNECT:
            self.mesh_headers.update({
                "X-Consul-Connect": "true",
                "X-Consul-Namespace": self.namespace,
            })
    
    def inject_mesh_headers(self, headers: Dict[str, str], target_service: str) -> Dict[str, str]:
        """Inject mesh-specific headers."""
        updated_headers = headers.copy()
        
        # Add mesh-specific headers
        for key, value in self.mesh_headers.items():
            if value:  # Only add non-empty values
                updated_headers[key] = value
        
        # Service mesh specific logic
        if self.mesh_type == ServiceMeshType.ISTIO:
            # Istio-specific headers
            updated_headers["X-Target-Service"] = target_service
            if "retry_policy" in self.config:
                updated_headers["X-Envoy-Max-Retries"] = str(self.config["retry_policy"].get("max_retries", 3))
        
        elif self.mesh_type == ServiceMeshType.LINKERD:
            # Linkerd-specific headers
            updated_headers["L5d-Dst-Service"] = target_service
            if "timeout" in self.config:
                updated_headers["L5d-Timeout"] = f"{self.config['timeout']}ms"
        
        return updated_headers
    
    def create_traffic_policy(self, service_name: str, policy: Dict[str, Any]):
        """Create traffic management policy."""
        self.traffic_policies[service_name] = policy
        logger.info(f"Created traffic policy for {service_name}")
    
    def get_traffic_policy(self, service_name: str) -> Optional[Dict[str, Any]]:
        """Get traffic policy for service."""
        return self.traffic_policies.get(service_name)
    
    def apply_circuit_breaker_policy(self, service_name: str, circuit_breaker_config: Dict[str, Any]):
        """Apply circuit breaker policy through service mesh."""
        policy = {
            "circuit_breaker": circuit_breaker_config,
            "type": "resilience"
        }
        self.create_traffic_policy(f"{service_name}-circuit-breaker", policy)
    
    def apply_retry_policy(self, service_name: str, retry_config: Dict[str, Any]):
        """Apply retry policy through service mesh."""
        policy = {
            "retry": retry_config,
            "type": "resilience"
        }
        self.create_traffic_policy(f"{service_name}-retry", policy)
    
    def get_mesh_metrics(self) -> Dict[str, Any]:
        """Get service mesh metrics."""
        return {
            "mesh_type": self.mesh_type.value,
            "namespace": self.namespace,
            "traffic_policies": len(self.traffic_policies),
            "mesh_headers": list(self.mesh_headers.keys()),
            "policies": {
                name: {
                    "type": policy.get("type", "unknown"),
                    "config_keys": list(policy.keys())
                }
                for name, policy in self.traffic_policies.items()
            }
        }


class MicroserviceShield(Shield):
    """Shield for microservice environments with distributed security."""
    
    def __init__(
        self,
        service_registry: ServiceRegistry,
        security_manager: DistributedSecurityManager,
        tracing: Optional[DistributedTracing] = None,
        service_mesh: Optional[ServiceMeshIntegration] = None,
        circuit_breakers: Optional[Dict[str, CircuitBreaker]] = None,
        **kwargs
    ):
        # Create shield function
        def shield_func(request: Request):
            return self._microservice_shield(request)
        
        super().__init__(shield_func, **kwargs)
        
        self.service_registry = service_registry
        self.security_manager = security_manager
        self.tracing = tracing
        self.service_mesh = service_mesh
        self.circuit_breakers = circuit_breakers or {}
        
        self._client: Optional[httpx.AsyncClient] = None
    
    async def _microservice_shield(self, request: Request) -> Optional[Response]:
        """Main microservice shield logic."""
        # Extract trace context from headers
        trace_context = None
        if self.tracing:
            trace_context = TraceContext.from_headers(dict(request.headers))
            if not trace_context:
                trace_context = self.tracing.create_trace_context("microservice-request")
        
        try:
            # Get target service from headers or path
            target_service = self._extract_target_service(request)
            if not target_service:
                return None  # Let request proceed normally
            
            # Apply distributed security policies
            await self._apply_security_policies(request, target_service, trace_context)
            
            # Add tracing headers if available
            if trace_context and self.tracing:
                # Add trace context to request (this would be handled by middleware in practice)
                pass
            
            return None  # Allow request to proceed
            
        except HTTPException:
            # Re-raise HTTP exceptions
            raise
        except Exception as e:
            logger.error(f"Error in microservice shield: {e}")
            if trace_context and self.tracing:
                self.tracing.add_span_log(trace_context, f"Shield error: {str(e)}", "error")
            
            raise HTTPException(status_code=500, detail="Microservice shield error")
    
    def _extract_target_service(self, request: Request) -> Optional[str]:
        """Extract target service from request."""
        # Check headers first
        target_service = request.headers.get("X-Target-Service")
        if target_service:
            return target_service
        
        # Extract from path (e.g., /api/v1/user-service/users)
        path_parts = request.url.path.strip("/").split("/")
        if len(path_parts) >= 3 and path_parts[0] == "api":
            service_part = path_parts[2]
            if service_part.endswith("-service"):
                return service_part
        
        return None
    
    async def _apply_security_policies(self, request: Request, target_service: str, trace_context: Optional[TraceContext]):
        """Apply distributed security policies."""
        policies = self.security_manager.get_matching_policies(target_service)
        
        for policy in policies:
            if trace_context and self.tracing:
                self.tracing.add_span_log(trace_context, f"Applying policy {policy.policy_id}")
            
            # Check authentication
            if policy.authentication_required:
                await self._check_authentication(request, policy, trace_context)
            
            # Check authorization
            if policy.authorization_rules:
                await self._check_authorization(request, policy, trace_context)
            
            # Check rate limiting
            if policy.rate_limit_per_minute:
                await self._check_rate_limit(request, policy, trace_context)
    
    async def _check_authentication(self, request: Request, policy: DistributedSecurityPolicy, trace_context: Optional[TraceContext]):
        """Check authentication requirements."""
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            raise HTTPException(status_code=401, detail="Authentication required")
        
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]  # Remove "Bearer " prefix
            try:
                payload = self.security_manager.validate_service_token(token)
                
                if trace_context and self.tracing:
                    self.tracing.add_span_tag(trace_context, "auth.service_id", payload.get("sub", "unknown"))
                    
            except HTTPException:
                if trace_context and self.tracing:
                    self.tracing.add_span_log(trace_context, "Authentication failed", "error")
                raise
    
    async def _check_authorization(self, request: Request, policy: DistributedSecurityPolicy, trace_context: Optional[TraceContext]):
        """Check authorization requirements."""
        # This would implement complex authorization logic
        # For now, we'll do basic scope checking
        
        if policy.required_scopes:
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header[7:]
                try:
                    payload = self.security_manager.validate_service_token(token)
                    
                    if not self.security_manager.check_authorization(
                        payload.get("sub", ""), 
                        policy.required_scopes, 
                        payload
                    ):
                        raise HTTPException(status_code=403, detail="Insufficient privileges")
                        
                except HTTPException:
                    raise
    
    async def _check_rate_limit(self, request: Request, policy: DistributedSecurityPolicy, trace_context: Optional[TraceContext]):
        """Check rate limiting."""
        # This would implement distributed rate limiting
        # For now, we'll just log that rate limiting should be applied
        
        if trace_context and self.tracing:
            self.tracing.add_span_log(
                trace_context, 
                f"Rate limit: {policy.rate_limit_per_minute}/min"
            )
    
    async def call_service(
        self,
        target_service: str,
        method: str,
        path: str,
        headers: Optional[Dict[str, str]] = None,
        data: Any = None,
        timeout: float = 30.0,
        trace_context: Optional[TraceContext] = None
    ) -> Response:
        """Call another microservice with circuit breaker and tracing."""
        
        # Get service instances
        instances = await self.service_registry.get_healthy_services(target_service)
        if not instances:
            raise HTTPException(status_code=503, detail=f"No healthy instances of {target_service}")
        
        # Select instance (simple round-robin for now)
        instance = instances[0]  # In production, use load balancer
        
        # Prepare headers
        request_headers = headers or {}
        
        # Add service mesh headers
        if self.service_mesh:
            request_headers = self.service_mesh.inject_mesh_headers(request_headers, target_service)
        
        # Add tracing headers
        if trace_context and self.tracing:
            request_headers.update(trace_context.to_headers())
        
        # Add security headers
        auth_headers = self.security_manager.create_inter_service_headers("shield", target_service)
        request_headers.update(auth_headers)
        
        # Get or create circuit breaker
        circuit_breaker = self.circuit_breakers.get(target_service)
        if not circuit_breaker:
            circuit_breaker = CircuitBreaker(name=target_service)
            self.circuit_breakers[target_service] = circuit_breaker
        
        # Create HTTP client if needed
        if not self._client:
            self._client = httpx.AsyncClient(timeout=timeout)
        
        # Execute with circuit breaker
        url = f"{instance.url}{path}"
        
        async def http_call():
            response = await self._client.request(
                method=method,
                url=url,
                headers=request_headers,
                json=data if data else None
            )
            try:
                content = response.json() if response.headers.get('content-type', '').startswith('application/json') else {"data": response.content.decode()}
            except:
                content = {"data": response.content.decode() if isinstance(response.content, bytes) else str(response.content)}
            
            return JSONResponse(
                content=content,
                status_code=response.status_code,
                headers=dict(response.headers)
            )
        
        # Use tracing context if available
        if trace_context and self.tracing:
            async with self.tracing.trace_context(f"{method} {target_service}{path}", trace_context) as span_context:
                self.tracing.add_span_tag(span_context, "service.target", target_service)
                self.tracing.add_span_tag(span_context, "http.method", method)
                self.tracing.add_span_tag(span_context, "http.url", url)
                
                return await circuit_breaker.execute(http_call)
        else:
            return await circuit_breaker.execute(http_call)
    
    def get_microservice_metrics(self) -> Dict[str, Any]:
        """Get microservice integration metrics."""
        metrics = {
            "circuit_breakers": {
                name: cb.get_metrics() 
                for name, cb in self.circuit_breakers.items()
            },
            "security": self.security_manager.get_security_metrics()
        }
        
        if self.service_mesh:
            metrics["service_mesh"] = self.service_mesh.get_mesh_metrics()
        
        if self.tracing:
            metrics["tracing"] = {
                "service_name": self.tracing.service_name,
                "provider": self.tracing.provider.value,
                "active_spans": len(self.tracing.active_spans),
                "sampling_rate": self.tracing.sampling_rate
            }
        
        return metrics
    
    async def close(self):
        """Close HTTP client and cleanup."""
        if self._client:
            await self._client.aclose()
            self._client = None


# Convenience functions

def create_consul_registry(
    host: str = "localhost",
    port: int = 8500,
    datacenter: str = "dc1",
    token: Optional[str] = None
) -> ConsulServiceRegistry:
    """Create Consul service registry."""
    return ConsulServiceRegistry(
        consul_host=host,
        consul_port=port,
        datacenter=datacenter,
        token=token
    )


def create_eureka_registry(
    eureka_url: str = "http://localhost:8761/eureka",
    app_name: str = "fastapi-shield"
) -> EurekaServiceRegistry:
    """Create Eureka service registry."""
    return EurekaServiceRegistry(eureka_url=eureka_url, app_name=app_name)


def create_microservice_shield(
    service_registry: ServiceRegistry,
    jwt_secret: str,
    service_name: str = "fastapi-shield",
    mesh_type: Optional[ServiceMeshType] = None,
    **kwargs
) -> MicroserviceShield:
    """Create microservice shield with common configuration."""
    security_manager = DistributedSecurityManager(jwt_secret=jwt_secret)
    tracing = DistributedTracing(service_name=service_name)
    service_mesh = ServiceMeshIntegration(mesh_type) if mesh_type else None
    
    return MicroserviceShield(
        service_registry=service_registry,
        security_manager=security_manager,
        tracing=tracing,
        service_mesh=service_mesh,
        **kwargs
    )


def microservice_shield_decorator(
    service_registry: ServiceRegistry,
    security_manager: DistributedSecurityManager,
    **kwargs
):
    """Decorator for creating microservice shields."""
    def decorator(func):
        shield_instance = MicroserviceShield(
            service_registry=service_registry,
            security_manager=security_manager,
            **kwargs
        )
        return shield_instance(func)
    return decorator