"""Mock backend server for load balancing tests.

This module provides mock backend servers that can simulate various behaviors
for testing load balancing functionality, including health checks, failures,
latency simulation, and different response patterns.
"""

import asyncio
import json
import time
import random
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, field
from threading import Thread
import socket
from contextlib import asynccontextmanager
from unittest.mock import Mock

from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import JSONResponse
import uvicorn


@dataclass
class MockBackendConfig:
    """Configuration for mock backend server."""
    backend_id: str
    host: str = "127.0.0.1"
    port: int = 8000
    weight: int = 100
    max_connections: int = 1000
    failure_rate: float = 0.0
    latency_min: float = 0.1
    latency_max: float = 0.5
    cpu_usage: float = 20.0
    memory_usage: float = 30.0
    maintenance_mode: bool = False
    custom_responses: Dict[str, Any] = field(default_factory=dict)


class MockBackendServer:
    """Mock backend server for testing load balancing."""
    
    def __init__(self, config: MockBackendConfig):
        self.config = config
        self.app = FastAPI()
        self.server = None
        self.server_task = None
        self._request_count = 0
        self._active_connections = 0
        self._setup_routes()
        
    def _setup_routes(self):
        """Setup mock server routes."""
        
        @self.app.get("/health")
        async def health_check():
            """Health check endpoint."""
            if self.config.maintenance_mode:
                raise HTTPException(status_code=503, detail="Maintenance mode")
            
            # Simulate random failures based on failure rate
            if random.random() < self.config.failure_rate:
                raise HTTPException(status_code=500, detail="Simulated failure")
            
            return JSONResponse({
                "status": "healthy",
                "backend_id": self.config.backend_id,
                "timestamp": time.time(),
                "cpu_usage": self.config.cpu_usage,
                "memory_usage": self.config.memory_usage,
                "active_connections": self._active_connections,
                "request_count": self._request_count
            })
        
        @self.app.get("/")
        @self.app.get("/{path:path}")
        async def catch_all(request: Request, path: str = ""):
            """Catch-all endpoint that simulates backend responses."""
            self._request_count += 1
            self._active_connections += 1
            
            try:
                # Simulate latency
                await asyncio.sleep(random.uniform(
                    self.config.latency_min, 
                    self.config.latency_max
                ))
                
                # Check for maintenance mode
                if self.config.maintenance_mode:
                    raise HTTPException(status_code=503, detail="Backend in maintenance")
                
                # Simulate random failures
                if random.random() < self.config.failure_rate:
                    raise HTTPException(status_code=500, detail="Simulated backend error")
                
                # Check for custom responses
                if path in self.config.custom_responses:
                    return JSONResponse(self.config.custom_responses[path])
                
                # Default response
                return JSONResponse({
                    "backend_id": self.config.backend_id,
                    "path": f"/{path}" if path else "/",
                    "method": request.method,
                    "headers": dict(request.headers),
                    "query_params": dict(request.query_params),
                    "timestamp": time.time(),
                    "request_count": self._request_count,
                    "host": f"{self.config.host}:{self.config.port}"
                })
                
            finally:
                self._active_connections = max(0, self._active_connections - 1)
        
        @self.app.post("/{path:path}")
        async def post_handler(request: Request, path: str = ""):
            """Handle POST requests."""
            return await catch_all(request, path)
        
        @self.app.put("/{path:path}")
        async def put_handler(request: Request, path: str = ""):
            """Handle PUT requests."""
            return await catch_all(request, path)
        
        @self.app.delete("/{path:path}")
        async def delete_handler(request: Request, path: str = ""):
            """Handle DELETE requests."""
            return await catch_all(request, path)
    
    async def start(self):
        """Start the mock server."""
        if self.server_task is not None:
            return
        
        config = uvicorn.Config(
            self.app,
            host=self.config.host,
            port=self.config.port,
            log_level="error"  # Reduce log noise during tests
        )
        self.server = uvicorn.Server(config)
        
        # Start server in background task
        self.server_task = asyncio.create_task(self.server.serve())
        
        # Wait a moment for server to start
        await asyncio.sleep(0.1)
    
    async def stop(self):
        """Stop the mock server."""
        if self.server:
            self.server.should_exit = True
            
        if self.server_task:
            self.server_task.cancel()
            try:
                await self.server_task
            except asyncio.CancelledError:
                pass
            self.server_task = None
        
        self.server = None
    
    def set_maintenance_mode(self, enabled: bool):
        """Enable/disable maintenance mode."""
        self.config.maintenance_mode = enabled
    
    def set_failure_rate(self, rate: float):
        """Set failure rate (0.0 to 1.0)."""
        self.config.failure_rate = max(0.0, min(1.0, rate))
    
    def set_latency(self, min_latency: float, max_latency: float):
        """Set latency range."""
        self.config.latency_min = min_latency
        self.config.latency_max = max_latency
    
    def set_resource_usage(self, cpu_usage: float, memory_usage: float):
        """Set resource usage metrics."""
        self.config.cpu_usage = cpu_usage
        self.config.memory_usage = memory_usage
    
    def add_custom_response(self, path: str, response_data: Any):
        """Add custom response for specific path."""
        self.config.custom_responses[path] = response_data
    
    def get_stats(self) -> Dict[str, Any]:
        """Get server statistics."""
        return {
            "backend_id": self.config.backend_id,
            "request_count": self._request_count,
            "active_connections": self._active_connections,
            "config": {
                "host": self.config.host,
                "port": self.config.port,
                "weight": self.config.weight,
                "failure_rate": self.config.failure_rate,
                "latency_range": [self.config.latency_min, self.config.latency_max],
                "cpu_usage": self.config.cpu_usage,
                "memory_usage": self.config.memory_usage,
                "maintenance_mode": self.config.maintenance_mode
            }
        }


class MockBackendCluster:
    """Manages multiple mock backend servers for testing."""
    
    def __init__(self):
        self.servers: Dict[str, MockBackendServer] = {}
        self.base_port = 18000  # Start from a high port to avoid conflicts
    
    def add_server(self, config: MockBackendConfig) -> MockBackendServer:
        """Add a mock server to the cluster."""
        if not config.port:
            config.port = self.base_port + len(self.servers)
        
        server = MockBackendServer(config)
        self.servers[config.backend_id] = server
        return server
    
    def create_server(
        self,
        backend_id: str,
        failure_rate: float = 0.0,
        latency_min: float = 0.1,
        latency_max: float = 0.5,
        weight: int = 100,
        **kwargs
    ) -> MockBackendServer:
        """Create and add a mock server with default configuration."""
        config = MockBackendConfig(
            backend_id=backend_id,
            port=self.base_port + len(self.servers),
            failure_rate=failure_rate,
            latency_min=latency_min,
            latency_max=latency_max,
            weight=weight,
            **kwargs
        )
        return self.add_server(config)
    
    def get_server(self, backend_id: str) -> Optional[MockBackendServer]:
        """Get server by backend ID."""
        return self.servers.get(backend_id)
    
    def remove_server(self, backend_id: str) -> bool:
        """Remove server from cluster."""
        if backend_id in self.servers:
            del self.servers[backend_id]
            return True
        return False
    
    async def start_all(self):
        """Start all servers in the cluster."""
        tasks = [server.start() for server in self.servers.values()]
        if tasks:
            await asyncio.gather(*tasks)
    
    async def stop_all(self):
        """Stop all servers in the cluster."""
        tasks = [server.stop() for server in self.servers.values()]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self.servers.clear()
    
    def simulate_backend_failure(self, backend_id: str, failure_rate: float = 1.0):
        """Simulate backend failure by setting high failure rate."""
        server = self.get_server(backend_id)
        if server:
            server.set_failure_rate(failure_rate)
    
    def simulate_backend_recovery(self, backend_id: str):
        """Simulate backend recovery by clearing failure rate."""
        server = self.get_server(backend_id)
        if server:
            server.set_failure_rate(0.0)
    
    def simulate_maintenance(self, backend_id: str, enabled: bool = True):
        """Simulate backend maintenance mode."""
        server = self.get_server(backend_id)
        if server:
            server.set_maintenance_mode(enabled)
    
    def simulate_high_load(self, backend_id: str, cpu: float = 90.0, memory: float = 85.0):
        """Simulate high resource usage on backend."""
        server = self.get_server(backend_id)
        if server:
            server.set_resource_usage(cpu, memory)
    
    def get_cluster_stats(self) -> Dict[str, Any]:
        """Get statistics for entire cluster."""
        return {
            "total_servers": len(self.servers),
            "servers": {
                backend_id: server.get_stats() 
                for backend_id, server in self.servers.items()
            }
        }


# Helper function to get available port
def get_free_port() -> int:
    """Get a free port for testing."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        s.listen(1)
        port = s.getsockname()[1]
    return port


# Context manager for temporary mock backend cluster
@asynccontextmanager
async def mock_backend_cluster(backend_configs: List[Dict[str, Any]]):
    """Context manager for creating temporary mock backend cluster."""
    cluster = MockBackendCluster()
    
    try:
        # Create servers
        for config in backend_configs:
            server_config = MockBackendConfig(**config)
            if not server_config.port:
                server_config.port = get_free_port()
            cluster.add_server(server_config)
        
        # Start all servers
        await cluster.start_all()
        
        # Wait a moment for servers to be ready
        await asyncio.sleep(0.2)
        
        yield cluster
        
    finally:
        # Clean up
        await cluster.stop_all()