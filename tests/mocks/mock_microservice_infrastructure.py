"""Mock microservice infrastructure for testing.

This module provides mock implementations of service registries, microservices,
and infrastructure components to enable comprehensive testing of the microservice
integration functionality without requiring actual Consul, Eureka, or service mesh setup.
"""

import asyncio
import json
import time
import uuid
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from unittest.mock import Mock, AsyncMock
from contextlib import asynccontextmanager
import random
import threading

from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import JSONResponse
import httpx

from fastapi_shield.microservice_integration import (
    ServiceInstance,
    ServiceStatus,
    ServiceRegistry,
    CircuitBreakerState,
    TraceContext,
    AuthenticationMode,
    ServiceMeshType,
)


@dataclass
class MockServiceConfig:
    """Configuration for mock microservice."""
    service_id: str
    instance_id: str
    host: str = "127.0.0.1"
    port: int = 8000
    status: ServiceStatus = ServiceStatus.UP
    metadata: Dict[str, str] = field(default_factory=dict)
    tags: Set[str] = field(default_factory=set)
    version: str = "1.0.0"
    failure_rate: float = 0.0
    latency_min: float = 0.01
    latency_max: float = 0.1
    health_endpoint: str = "/health"


class MockMicroservice:
    """Mock microservice for testing."""
    
    def __init__(self, config: MockServiceConfig):
        self.config = config
        self.app = FastAPI()
        self.request_count = 0
        self.failure_count = 0
        self.success_count = 0
        self._setup_routes()
        
        # Track received requests for testing
        self.received_requests: List[Dict[str, Any]] = []
        self._lock = threading.RLock()
    
    def _setup_routes(self):
        """Setup mock service routes."""
        
        @self.app.get(self.config.health_endpoint)
        async def health_check():
            """Health check endpoint."""
            if self.config.status != ServiceStatus.UP:
                raise HTTPException(
                    status_code=503,
                    detail=f"Service is {self.config.status.value}"
                )
            
            # Simulate random failures
            if random.random() < self.config.failure_rate:
                self.failure_count += 1
                raise HTTPException(status_code=500, detail="Simulated failure")
            
            return {
                "status": "UP",
                "service_id": self.config.service_id,
                "instance_id": self.config.instance_id,
                "version": self.config.version,
                "timestamp": time.time()
            }
        
        @self.app.get("/info")
        async def service_info():
            """Service information endpoint."""
            return {
                "service_id": self.config.service_id,
                "instance_id": self.config.instance_id,
                "version": self.config.version,
                "metadata": self.config.metadata,
                "tags": list(self.config.tags),
                "uptime": time.time() - getattr(self, '_start_time', time.time())
            }
        
        @self.app.get("/{path:path}")
        @self.app.post("/{path:path}")
        @self.app.put("/{path:path}")
        @self.app.delete("/{path:path}")
        async def handle_request(request: Request, path: str = ""):
            """Handle all other requests."""
            with self._lock:
                self.request_count += 1
                
                # Record request details for testing
                request_info = {
                    "method": request.method,
                    "path": f"/{path}" if path else "/",
                    "headers": dict(request.headers),
                    "query_params": dict(request.query_params),
                    "timestamp": time.time(),
                    "request_id": self.request_count
                }
                self.received_requests.append(request_info)
            
            # Simulate latency
            await asyncio.sleep(random.uniform(
                self.config.latency_min,
                self.config.latency_max
            ))
            
            # Simulate failures
            if random.random() < self.config.failure_rate:
                self.failure_count += 1
                raise HTTPException(status_code=500, detail="Simulated service error")
            
            self.success_count += 1
            
            return {
                "service_id": self.config.service_id,
                "instance_id": self.config.instance_id,
                "path": request_info["path"],
                "method": request.method,
                "request_count": self.request_count,
                "success_count": self.success_count,
                "failure_count": self.failure_count,
                "headers_received": dict(request.headers),
                "response_timestamp": time.time()
            }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get service statistics."""
        with self._lock:
            return {
                "service_id": self.config.service_id,
                "instance_id": self.config.instance_id,
                "request_count": self.request_count,
                "success_count": self.success_count,
                "failure_count": self.failure_count,
                "status": self.config.status.value,
                "failure_rate": self.config.failure_rate,
                "received_requests_count": len(self.received_requests)
            }
    
    def set_status(self, status: ServiceStatus):
        """Change service status."""
        self.config.status = status
    
    def set_failure_rate(self, rate: float):
        """Set failure rate."""
        self.config.failure_rate = max(0.0, min(1.0, rate))
    
    def get_received_requests(self) -> List[Dict[str, Any]]:
        """Get list of received requests."""
        with self._lock:
            return self.received_requests.copy()
    
    def clear_request_history(self):
        """Clear request history."""
        with self._lock:
            self.received_requests.clear()


class MockServiceRegistry(ServiceRegistry):
    """Mock service registry for testing."""
    
    def __init__(self):
        self.services: Dict[str, List[ServiceInstance]] = {}
        self.health_statuses: Dict[str, ServiceStatus] = {}
        self._lock = threading.RLock()
        self.registration_count = 0
        self.deregistration_count = 0
    
    async def register_service(self, service: ServiceInstance) -> bool:
        """Register a mock service."""
        with self._lock:
            if service.service_id not in self.services:
                self.services[service.service_id] = []
            
            # Remove existing instance if present
            self.services[service.service_id] = [
                s for s in self.services[service.service_id] 
                if s.instance_id != service.instance_id
            ]
            
            # Add new instance
            self.services[service.service_id].append(service)
            self.health_statuses[service.instance_id] = service.status
            self.registration_count += 1
            
            return True
    
    async def deregister_service(self, service_id: str, instance_id: str) -> bool:
        """Deregister a mock service."""
        with self._lock:
            if service_id in self.services:
                original_count = len(self.services[service_id])
                self.services[service_id] = [
                    s for s in self.services[service_id]
                    if s.instance_id != instance_id
                ]
                
                if len(self.services[service_id]) < original_count:
                    self.health_statuses.pop(instance_id, None)
                    self.deregistration_count += 1
                    return True
            
            return False
    
    async def discover_services(self, service_id: str) -> List[ServiceInstance]:
        """Discover all instances of a service."""
        with self._lock:
            return self.services.get(service_id, []).copy()
    
    async def get_healthy_services(self, service_id: str) -> List[ServiceInstance]:
        """Get healthy instances of a service."""
        with self._lock:
            all_services = self.services.get(service_id, [])
            healthy_services = []
            
            for service in all_services:
                current_status = self.health_statuses.get(service.instance_id, ServiceStatus.UNKNOWN)
                if current_status == ServiceStatus.UP:
                    # Update service status
                    service.status = current_status
                    healthy_services.append(service)
            
            return healthy_services
    
    async def health_check(self) -> bool:
        """Mock registry health check."""
        return True  # Always healthy for testing
    
    def set_service_health(self, instance_id: str, status: ServiceStatus):
        """Set health status for testing."""
        with self._lock:
            self.health_statuses[instance_id] = status
    
    def get_all_services(self) -> Dict[str, List[ServiceInstance]]:
        """Get all registered services."""
        with self._lock:
            return {
                service_id: instances.copy()
                for service_id, instances in self.services.items()
            }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get registry statistics."""
        with self._lock:
            return {
                "total_services": len(self.services),
                "total_instances": sum(len(instances) for instances in self.services.values()),
                "registration_count": self.registration_count,
                "deregistration_count": self.deregistration_count,
                "service_breakdown": {
                    service_id: len(instances)
                    for service_id, instances in self.services.items()
                }
            }


class MockConsulAPI:
    """Mock Consul HTTP API for testing."""
    
    def __init__(self):
        self.services: Dict[str, Dict[str, Any]] = {}
        self.health_checks: Dict[str, Dict[str, Any]] = {}
        self.kv_store: Dict[str, str] = {}
        self._lock = threading.RLock()
    
    def register_service(self, service_data: Dict[str, Any]) -> bool:
        """Mock service registration."""
        with self._lock:
            service_id = service_data["ID"]
            self.services[service_id] = service_data
            
            # Create health check entry
            if "Check" in service_data:
                self.health_checks[service_id] = {
                    "status": "passing",
                    "check_id": f"service:{service_id}",
                    **service_data["Check"]
                }
            
            return True
    
    def deregister_service(self, service_id: str) -> bool:
        """Mock service deregistration."""
        with self._lock:
            if service_id in self.services:
                del self.services[service_id]
                self.health_checks.pop(service_id, None)
                return True
            return False
    
    def get_service_catalog(self, service_name: str) -> List[Dict[str, Any]]:
        """Mock service catalog query."""
        with self._lock:
            matching_services = []
            for service_id, service_data in self.services.items():
                if service_data["Name"] == service_name:
                    catalog_entry = {
                        "ServiceID": service_data["ID"],
                        "ServiceName": service_data["Name"],
                        "ServiceAddress": service_data["Address"],
                        "ServicePort": service_data["Port"],
                        "ServiceTags": service_data.get("Tags", []),
                        "ServiceMeta": service_data.get("Meta", {}),
                        "Address": service_data["Address"],
                        "Datacenter": "dc1"
                    }
                    matching_services.append(catalog_entry)
            
            return matching_services
    
    def get_healthy_services(self, service_name: str) -> List[Dict[str, Any]]:
        """Mock healthy services query."""
        with self._lock:
            healthy_services = []
            
            for service_id, service_data in self.services.items():
                if service_data["Name"] == service_name:
                    health_status = self.health_checks.get(service_id, {})
                    if health_status.get("status") == "passing":
                        health_entry = {
                            "Service": {
                                "ID": service_data["ID"],
                                "Service": service_data["Name"],
                                "Address": service_data["Address"],
                                "Port": service_data["Port"],
                                "Tags": service_data.get("Tags", []),
                                "Meta": service_data.get("Meta", {})
                            },
                            "Node": {
                                "Address": service_data["Address"],
                                "Datacenter": "dc1"
                            },
                            "Checks": [
                                {
                                    "Status": "passing",
                                    "CheckID": f"service:{service_id}"
                                }
                            ]
                        }
                        healthy_services.append(health_entry)
            
            return healthy_services
    
    def set_health_status(self, service_id: str, status: str):
        """Set health status for testing."""
        with self._lock:
            if service_id in self.health_checks:
                self.health_checks[service_id]["status"] = status


class MockEurekaAPI:
    """Mock Eureka HTTP API for testing."""
    
    def __init__(self):
        self.applications: Dict[str, List[Dict[str, Any]]] = {}
        self._lock = threading.RLock()
    
    def register_instance(self, app_name: str, instance_data: Dict[str, Any]) -> bool:
        """Mock instance registration."""
        with self._lock:
            if app_name not in self.applications:
                self.applications[app_name] = []
            
            # Remove existing instance
            instance_id = instance_data["instance"]["instanceId"]
            self.applications[app_name] = [
                inst for inst in self.applications[app_name]
                if inst["instanceId"] != instance_id
            ]
            
            # Add new instance
            self.applications[app_name].append(instance_data["instance"])
            return True
    
    def deregister_instance(self, app_name: str, instance_id: str) -> bool:
        """Mock instance deregistration."""
        with self._lock:
            if app_name in self.applications:
                original_count = len(self.applications[app_name])
                self.applications[app_name] = [
                    inst for inst in self.applications[app_name]
                    if inst["instanceId"] != instance_id
                ]
                return len(self.applications[app_name]) < original_count
            return False
    
    def get_application(self, app_name: str) -> Dict[str, Any]:
        """Mock application query."""
        with self._lock:
            instances = self.applications.get(app_name, [])
            if instances:
                return {
                    "application": {
                        "name": app_name,
                        "instance": instances if len(instances) > 1 else instances[0] if instances else {}
                    }
                }
            return {}
    
    def send_heartbeat(self, app_name: str, instance_id: str) -> bool:
        """Mock heartbeat."""
        with self._lock:
            if app_name in self.applications:
                for instance in self.applications[app_name]:
                    if instance["instanceId"] == instance_id:
                        instance["lastUpdatedTimestamp"] = int(time.time() * 1000)
                        return True
            return False


class MockServiceMesh:
    """Mock service mesh for testing."""
    
    def __init__(self, mesh_type: ServiceMeshType):
        self.mesh_type = mesh_type
        self.traffic_policies: Dict[str, Dict[str, Any]] = {}
        self.injected_headers: List[Dict[str, str]] = []
        self._lock = threading.RLock()
    
    def inject_headers(self, original_headers: Dict[str, str], target_service: str) -> Dict[str, str]:
        """Mock header injection."""
        mesh_headers = original_headers.copy()
        
        if self.mesh_type == ServiceMeshType.ISTIO:
            mesh_headers.update({
                "X-Istio-Namespace": "default",
                "X-Target-Service": target_service,
                "X-Envoy-Max-Retries": "3"
            })
        elif self.mesh_type == ServiceMeshType.LINKERD:
            mesh_headers.update({
                "L5d-Dst-Service": target_service,
                "L5d-Req-Id": str(uuid.uuid4())
            })
        
        # Record injected headers for testing
        with self._lock:
            self.injected_headers.append({
                "target_service": target_service,
                "mesh_type": self.mesh_type.value,
                "headers_added": len(mesh_headers) - len(original_headers)
            })
        
        return mesh_headers
    
    def create_traffic_policy(self, service_name: str, policy: Dict[str, Any]):
        """Mock traffic policy creation."""
        with self._lock:
            self.traffic_policies[service_name] = policy
    
    def get_stats(self) -> Dict[str, Any]:
        """Get mock mesh statistics."""
        with self._lock:
            return {
                "mesh_type": self.mesh_type.value,
                "traffic_policies": len(self.traffic_policies),
                "header_injections": len(self.injected_headers),
                "policies": list(self.traffic_policies.keys())
            }
    
    def get_mesh_metrics(self) -> Dict[str, Any]:
        """Get mesh metrics (alias for get_stats for compatibility)."""
        return self.get_stats()


class MockTracingCollector:
    """Mock tracing collector for testing."""
    
    def __init__(self):
        self.spans: List[Dict[str, Any]] = []
        self.traces: Dict[str, List[str]] = {}  # trace_id -> span_ids
        self._lock = threading.RLock()
    
    def collect_span(self, span_data: Dict[str, Any]):
        """Collect a span."""
        with self._lock:
            self.spans.append(span_data)
            
            trace_id = span_data.get("trace_id")
            span_id = span_data.get("span_id")
            
            if trace_id and span_id:
                if trace_id not in self.traces:
                    self.traces[trace_id] = []
                self.traces[trace_id].append(span_id)
    
    def get_trace(self, trace_id: str) -> List[Dict[str, Any]]:
        """Get all spans for a trace."""
        with self._lock:
            return [
                span for span in self.spans
                if span.get("trace_id") == trace_id
            ]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get tracing statistics."""
        with self._lock:
            return {
                "total_spans": len(self.spans),
                "total_traces": len(self.traces),
                "average_spans_per_trace": (
                    sum(len(spans) for spans in self.traces.values()) / len(self.traces)
                    if self.traces else 0
                )
            }
    
    def clear(self):
        """Clear collected data."""
        with self._lock:
            self.spans.clear()
            self.traces.clear()


@asynccontextmanager
async def mock_microservice_environment(
    services: List[MockServiceConfig],
    registry_type: str = "mock",
    mesh_type: Optional[ServiceMeshType] = None
):
    """Context manager for mock microservice environment."""
    
    # Create mock services
    mock_services = {
        config.instance_id: MockMicroservice(config)
        for config in services
    }
    
    # Create registry
    if registry_type == "mock":
        registry = MockServiceRegistry()
    else:
        registry = MockServiceRegistry()  # For now, always use mock
    
    # Create service mesh if specified
    service_mesh = MockServiceMesh(mesh_type) if mesh_type else None
    
    # Create tracing collector
    tracing_collector = MockTracingCollector()
    
    try:
        # Register all services
        for config in services:
            service_instance = ServiceInstance(
                service_id=config.service_id,
                instance_id=config.instance_id,
                host=config.host,
                port=config.port,
                status=config.status,
                metadata=config.metadata,
                tags=config.tags,
                version=config.version,
                health_check_url=f"http://{config.host}:{config.port}{config.health_endpoint}"
            )
            await registry.register_service(service_instance)
        
        environment = {
            "services": mock_services,
            "registry": registry,
            "service_mesh": service_mesh,
            "tracing_collector": tracing_collector
        }
        
        yield environment
        
    finally:
        # Cleanup
        for config in services:
            await registry.deregister_service(config.service_id, config.instance_id)


def create_test_service_config(
    service_id: str,
    instance_id: Optional[str] = None,
    port: int = 8000,
    status: ServiceStatus = ServiceStatus.UP,
    **kwargs
) -> MockServiceConfig:
    """Create test service configuration."""
    return MockServiceConfig(
        service_id=service_id,
        instance_id=instance_id or f"{service_id}-{uuid.uuid4().hex[:8]}",
        port=port,
        status=status,
        **kwargs
    )


def create_test_trace_context(operation_name: str = "test-operation") -> TraceContext:
    """Create test trace context."""
    return TraceContext(
        trace_id=str(uuid.uuid4()).replace("-", ""),
        span_id=str(uuid.uuid4()).replace("-", "")[:16],
        baggage={"test": "value"}
    )