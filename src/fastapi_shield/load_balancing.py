"""Load balancing shield for FastAPI Shield.

This module provides comprehensive load balancing capabilities including multiple
algorithms, health monitoring, automatic failover, sticky sessions, and performance
metrics. The load balancer can distribute requests across multiple backend services
with sophisticated health checks and recovery mechanisms.

Key Components:
    - LoadBalancer: Core load balancing engine with multiple algorithms
    - Backend: Represents a backend service with health and metrics
    - HealthChecker: Monitors backend health with various check types
    - SessionManager: Manages sticky sessions across backends
    - LoadBalancingShield: Shield integration for request distribution
"""

import asyncio
import hashlib
import json
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import (
    Any, Dict, List, Optional, Union, Callable, Set, Tuple,
    TYPE_CHECKING, Protocol, AsyncContextManager
)
from contextlib import asynccontextmanager
from threading import RLock
import random
import statistics
from urllib.parse import urlparse
import weakref

import httpx
from fastapi import HTTPException, Request, Response
from fastapi.responses import JSONResponse

from fastapi_shield.shield import Shield, shield

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class LoadBalancingAlgorithm(str, Enum):
    """Load balancing algorithms."""
    ROUND_ROBIN = "round_robin"
    WEIGHTED_ROUND_ROBIN = "weighted_round_robin"
    LEAST_CONNECTIONS = "least_connections"
    WEIGHTED_LEAST_CONNECTIONS = "weighted_least_connections"
    RANDOM = "random"
    WEIGHTED_RANDOM = "weighted_random"
    IP_HASH = "ip_hash"
    CONSISTENT_HASH = "consistent_hash"
    LEAST_RESPONSE_TIME = "least_response_time"
    RESOURCE_BASED = "resource_based"


class BackendStatus(str, Enum):
    """Backend health status."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"
    MAINTENANCE = "maintenance"


class HealthCheckType(str, Enum):
    """Types of health checks."""
    HTTP = "http"
    HTTPS = "https"
    TCP = "tcp"
    PING = "ping"
    CUSTOM = "custom"


class StickySessionStrategy(str, Enum):
    """Sticky session strategies."""
    COOKIE = "cookie"
    IP_HASH = "ip_hash"
    HEADER = "header"
    SESSION_ID = "session_id"


@dataclass
class BackendMetrics:
    """Metrics for a backend server."""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    active_connections: int = 0
    average_response_time: float = 0.0
    response_times: List[float] = field(default_factory=list)
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    last_request_time: float = 0.0
    last_health_check: float = 0.0
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    total_bytes_sent: int = 0
    total_bytes_received: int = 0
    
    def update_response_time(self, response_time: float):
        """Update response time metrics."""
        self.response_times.append(response_time)
        # Keep only last 100 response times for memory efficiency
        if len(self.response_times) > 100:
            self.response_times.pop(0)
        
        self.average_response_time = statistics.mean(self.response_times)
        self.last_request_time = time.time()
    
    def update_request_metrics(self, success: bool, bytes_sent: int = 0, bytes_received: int = 0):
        """Update request success/failure metrics."""
        self.total_requests += 1
        self.total_bytes_sent += bytes_sent
        self.total_bytes_received += bytes_received
        
        if success:
            self.successful_requests += 1
            self.consecutive_successes += 1
            self.consecutive_failures = 0
        else:
            self.failed_requests += 1
            self.consecutive_failures += 1
            self.consecutive_successes = 0
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        if self.total_requests == 0:
            return 1.0
        return self.successful_requests / self.total_requests
    
    @property
    def failure_rate(self) -> float:
        """Calculate failure rate."""
        return 1.0 - self.success_rate


@dataclass
class HealthCheckConfig:
    """Configuration for health checks."""
    check_type: HealthCheckType = HealthCheckType.HTTP
    url: Optional[str] = None
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    timeout: float = 5.0
    interval: float = 30.0
    unhealthy_threshold: int = 3
    healthy_threshold: int = 2
    expected_status_codes: Set[int] = field(default_factory=lambda: {200, 201, 204})
    expected_response_pattern: Optional[str] = None
    port: Optional[int] = None
    custom_check: Optional[Callable[['Backend'], bool]] = None


class Backend:
    """Represents a backend server with health and performance metrics."""
    
    def __init__(
        self,
        backend_id: str,
        host: str,
        port: int = 80,
        weight: int = 100,
        max_connections: int = 1000,
        health_check_config: Optional[HealthCheckConfig] = None,
        tags: Optional[Dict[str, str]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        self.backend_id = backend_id
        self.host = host
        self.port = port
        self.weight = weight
        self.max_connections = max_connections
        self.tags = tags or {}
        self.metadata = metadata or {}
        
        self.status = BackendStatus.UNKNOWN
        self.metrics = BackendMetrics()
        self.health_check_config = health_check_config or HealthCheckConfig()
        
        self._lock = RLock()
        self.last_used = 0.0
        self.circuit_breaker_open = False
        self.circuit_breaker_opened_at = 0.0
        self.circuit_breaker_timeout = 60.0  # seconds
        
    @property
    def url(self) -> str:
        """Get the backend URL."""
        protocol = "https" if self.port == 443 else "http"
        if (protocol == "http" and self.port == 80) or (protocol == "https" and self.port == 443):
            return f"{protocol}://{self.host}"
        return f"{protocol}://{self.host}:{self.port}"
    
    @property
    def is_available(self) -> bool:
        """Check if backend is available for requests."""
        with self._lock:
            if self.circuit_breaker_open:
                # Check if circuit breaker timeout has elapsed
                if time.time() - self.circuit_breaker_opened_at > self.circuit_breaker_timeout:
                    self.circuit_breaker_open = False
                    logger.info(f"Circuit breaker closed for backend {self.backend_id}")
                else:
                    return False
            
            return (
                self.status in (BackendStatus.HEALTHY, BackendStatus.DEGRADED) and
                self.metrics.active_connections < self.max_connections
            )
    
    @property
    def load_score(self) -> float:
        """Calculate load score for resource-based load balancing."""
        with self._lock:
            # Combine multiple factors into a single score
            connection_factor = self.metrics.active_connections / max(self.max_connections, 1)
            response_time_factor = min(self.metrics.average_response_time / 1000, 1.0)  # Normalize to seconds
            cpu_factor = self.metrics.cpu_usage / 100.0
            memory_factor = self.metrics.memory_usage / 100.0
            failure_factor = self.metrics.failure_rate
            
            # Weighted combination (lower is better)
            return (
                connection_factor * 0.3 +
                response_time_factor * 0.25 +
                cpu_factor * 0.2 +
                memory_factor * 0.15 +
                failure_factor * 0.1
            )
    
    def increment_connections(self):
        """Increment active connection count."""
        with self._lock:
            self.metrics.active_connections += 1
            self.last_used = time.time()
    
    def decrement_connections(self):
        """Decrement active connection count."""
        with self._lock:
            self.metrics.active_connections = max(0, self.metrics.active_connections - 1)
    
    def update_status(self, status: BackendStatus):
        """Update backend status."""
        with self._lock:
            old_status = self.status
            self.status = status
            
            if old_status != status:
                logger.info(f"Backend {self.backend_id} status changed from {old_status} to {status}")
                
                # Handle circuit breaker logic
                if status == BackendStatus.UNHEALTHY and self.metrics.consecutive_failures >= 5:
                    self.circuit_breaker_open = True
                    self.circuit_breaker_opened_at = time.time()
                    logger.warning(f"Circuit breaker opened for backend {self.backend_id}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert backend to dictionary representation."""
        with self._lock:
            return {
                "backend_id": self.backend_id,
                "host": self.host,
                "port": self.port,
                "weight": self.weight,
                "status": self.status.value,
                "url": self.url,
                "max_connections": self.max_connections,
                "circuit_breaker_open": self.circuit_breaker_open,
                "tags": self.tags,
                "metadata": self.metadata,
                "metrics": {
                    "total_requests": self.metrics.total_requests,
                    "successful_requests": self.metrics.successful_requests,
                    "failed_requests": self.metrics.failed_requests,
                    "active_connections": self.metrics.active_connections,
                    "average_response_time": self.metrics.average_response_time,
                    "success_rate": self.metrics.success_rate,
                    "failure_rate": self.metrics.failure_rate,
                    "cpu_usage": self.metrics.cpu_usage,
                    "memory_usage": self.metrics.memory_usage,
                    "load_score": self.load_score,
                    "consecutive_failures": self.metrics.consecutive_failures,
                    "consecutive_successes": self.metrics.consecutive_successes,
                }
            }


class HealthChecker:
    """Health checker for backend servers."""
    
    def __init__(self, backends: List[Backend]):
        self.backends = backends
        self._running = False
        self._tasks: Set[asyncio.Task] = set()
        self._client = None
        
    async def start(self):
        """Start health checking for all backends."""
        if self._running:
            return
        
        self._running = True
        self._client = httpx.AsyncClient(timeout=30.0)
        
        # Start health check tasks for each backend
        for backend in self.backends:
            task = asyncio.create_task(self._health_check_loop(backend))
            self._tasks.add(task)
            # Add callback to remove completed tasks
            task.add_done_callback(self._tasks.discard)
        
        logger.info(f"Started health checking for {len(self.backends)} backends")
    
    async def stop(self):
        """Stop health checking."""
        if not self._running:
            return
        
        self._running = False
        
        # Cancel all health check tasks
        for task in self._tasks:
            task.cancel()
        
        # Wait for all tasks to complete
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        
        # Close HTTP client
        if self._client:
            await self._client.aclose()
            self._client = None
        
        logger.info("Stopped health checking")
    
    async def _health_check_loop(self, backend: Backend):
        """Health check loop for a single backend."""
        while self._running:
            try:
                is_healthy = await self._perform_health_check(backend)
                self._update_backend_health(backend, is_healthy)
                
                # Wait for next check
                await asyncio.sleep(backend.health_check_config.interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in health check loop for backend {backend.backend_id}: {e}")
                self._update_backend_health(backend, False)
                await asyncio.sleep(backend.health_check_config.interval)
    
    async def _perform_health_check(self, backend: Backend) -> bool:
        """Perform health check for a backend."""
        config = backend.health_check_config
        
        try:
            if config.check_type == HealthCheckType.HTTP or config.check_type == HealthCheckType.HTTPS:
                return await self._http_health_check(backend, config)
            elif config.check_type == HealthCheckType.TCP:
                return await self._tcp_health_check(backend, config)
            elif config.check_type == HealthCheckType.PING:
                return await self._ping_health_check(backend, config)
            elif config.check_type == HealthCheckType.CUSTOM:
                return await self._custom_health_check(backend, config)
            else:
                logger.warning(f"Unknown health check type: {config.check_type}")
                return False
                
        except Exception as e:
            logger.error(f"Health check failed for backend {backend.backend_id}: {e}")
            return False
    
    async def _http_health_check(self, backend: Backend, config: HealthCheckConfig) -> bool:
        """Perform HTTP health check."""
        if not self._client:
            return False
        
        try:
            url = config.url or f"{backend.url}/health"
            
            start_time = time.time()
            response = await self._client.request(
                method=config.method,
                url=url,
                headers=config.headers,
                content=config.body,
                timeout=config.timeout
            )
            response_time = (time.time() - start_time) * 1000
            
            # Update response time metrics
            backend.metrics.update_response_time(response_time)
            backend.metrics.last_health_check = time.time()
            
            # Check status code
            if response.status_code not in config.expected_status_codes:
                return False
            
            # Check response pattern if configured
            if config.expected_response_pattern:
                import re
                if not re.search(config.expected_response_pattern, response.text):
                    return False
            
            return True
            
        except Exception as e:
            logger.debug(f"HTTP health check failed for {backend.backend_id}: {e}")
            return False
    
    async def _tcp_health_check(self, backend: Backend, config: HealthCheckConfig) -> bool:
        """Perform TCP health check."""
        try:
            port = config.port or backend.port
            
            future = asyncio.open_connection(backend.host, port)
            reader, writer = await asyncio.wait_for(future, timeout=config.timeout)
            
            writer.close()
            await writer.wait_closed()
            
            backend.metrics.last_health_check = time.time()
            return True
            
        except Exception as e:
            logger.debug(f"TCP health check failed for {backend.backend_id}: {e}")
            return False
    
    async def _ping_health_check(self, backend: Backend, config: HealthCheckConfig) -> bool:
        """Perform ping health check."""
        try:
            import subprocess
            
            # Use asyncio.create_subprocess_exec for non-blocking ping
            proc = await asyncio.create_subprocess_exec(
                'ping', '-c', '1', '-W', str(int(config.timeout * 1000)), backend.host,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=config.timeout)
            
            backend.metrics.last_health_check = time.time()
            return proc.returncode == 0
            
        except Exception as e:
            logger.debug(f"Ping health check failed for {backend.backend_id}: {e}")
            return False
    
    async def _custom_health_check(self, backend: Backend, config: HealthCheckConfig) -> bool:
        """Perform custom health check."""
        if not config.custom_check:
            return False
        
        try:
            # If custom check is async
            if asyncio.iscoroutinefunction(config.custom_check):
                result = await config.custom_check(backend)
            else:
                result = config.custom_check(backend)
            
            backend.metrics.last_health_check = time.time()
            return bool(result)
            
        except Exception as e:
            logger.debug(f"Custom health check failed for {backend.backend_id}: {e}")
            return False
    
    def _update_backend_health(self, backend: Backend, is_healthy: bool):
        """Update backend health status based on check result."""
        with backend._lock:
            if is_healthy:
                backend.metrics.consecutive_successes += 1
                backend.metrics.consecutive_failures = 0
                
                # Move to healthy if we have enough consecutive successes
                if (backend.status in (BackendStatus.UNHEALTHY, BackendStatus.UNKNOWN) and 
                    backend.metrics.consecutive_successes >= backend.health_check_config.healthy_threshold):
                    backend.update_status(BackendStatus.HEALTHY)
                elif backend.status == BackendStatus.DEGRADED:
                    # Maybe upgrade to healthy after some successful checks
                    if backend.metrics.consecutive_successes >= backend.health_check_config.healthy_threshold * 2:
                        backend.update_status(BackendStatus.HEALTHY)
            else:
                backend.metrics.consecutive_failures += 1
                backend.metrics.consecutive_successes = 0
                
                # Move to unhealthy if we have enough consecutive failures
                if backend.metrics.consecutive_failures >= backend.health_check_config.unhealthy_threshold:
                    if backend.status == BackendStatus.HEALTHY:
                        backend.update_status(BackendStatus.DEGRADED)
                    elif backend.status == BackendStatus.DEGRADED:
                        backend.update_status(BackendStatus.UNHEALTHY)
                    else:
                        backend.update_status(BackendStatus.UNHEALTHY)


class SessionManager:
    """Manages sticky sessions for load balancing."""
    
    def __init__(
        self,
        strategy: StickySessionStrategy = StickySessionStrategy.COOKIE,
        session_timeout: float = 3600.0,  # 1 hour
        cookie_name: str = "lb_session",
        header_name: str = "X-Session-ID"
    ):
        self.strategy = strategy
        self.session_timeout = session_timeout
        self.cookie_name = cookie_name
        self.header_name = header_name
        
        self._sessions: Dict[str, Tuple[str, float]] = {}  # session_id -> (backend_id, created_at)
        self._lock = RLock()
    
    def get_backend_for_session(self, request: Request, backends: List[Backend]) -> Optional[Backend]:
        """Get backend for a session based on strategy."""
        session_id = self._extract_session_id(request)
        if not session_id:
            return None
        
        with self._lock:
            # Clean up expired sessions
            self._cleanup_expired_sessions()
            
            # Check if we have a session mapping
            if session_id in self._sessions:
                backend_id, created_at = self._sessions[session_id]
                
                # Find the backend
                for backend in backends:
                    if backend.backend_id == backend_id and backend.is_available:
                        return backend
                
                # Backend no longer available, remove session
                del self._sessions[session_id]
        
        return None
    
    def create_session(self, request: Request, backend: Backend) -> str:
        """Create a new session for the backend."""
        session_id = self._generate_session_id(request, backend)
        
        with self._lock:
            self._sessions[session_id] = (backend.backend_id, time.time())
        
        return session_id
    
    def _extract_session_id(self, request: Request) -> Optional[str]:
        """Extract session ID from request based on strategy."""
        if self.strategy == StickySessionStrategy.COOKIE:
            return request.cookies.get(self.cookie_name)
        elif self.strategy == StickySessionStrategy.HEADER:
            return request.headers.get(self.header_name)
        elif self.strategy == StickySessionStrategy.IP_HASH:
            client_ip = request.client.host if request.client else "unknown"
            return hashlib.md5(client_ip.encode()).hexdigest()
        elif self.strategy == StickySessionStrategy.SESSION_ID:
            # Try multiple common session identifiers
            for param in ['sessionid', 'session_id', 'sid', 'JSESSIONID']:
                if param in request.query_params:
                    return request.query_params[param]
                if param in request.cookies:
                    return request.cookies[param]
        
        return None
    
    def _generate_session_id(self, request: Request, backend: Backend) -> str:
        """Generate session ID based on strategy."""
        if self.strategy == StickySessionStrategy.IP_HASH:
            client_ip = request.client.host if request.client else "unknown"
            return hashlib.md5(client_ip.encode()).hexdigest()
        else:
            # Generate random session ID
            import uuid
            return str(uuid.uuid4())
    
    def _cleanup_expired_sessions(self):
        """Clean up expired sessions."""
        current_time = time.time()
        expired_sessions = [
            session_id for session_id, (_, created_at) in self._sessions.items()
            if current_time - created_at > self.session_timeout
        ]
        
        for session_id in expired_sessions:
            del self._sessions[session_id]
    
    def get_session_stats(self) -> Dict[str, Any]:
        """Get session statistics."""
        with self._lock:
            self._cleanup_expired_sessions()
            backend_counts = {}
            for backend_id, _ in self._sessions.values():
                backend_counts[backend_id] = backend_counts.get(backend_id, 0) + 1
            
            return {
                "total_sessions": len(self._sessions),
                "backend_distribution": backend_counts,
                "strategy": self.strategy.value,
                "session_timeout": self.session_timeout
            }


class LoadBalancingAlgorithmInterface(ABC):
    """Interface for load balancing algorithms."""
    
    @abstractmethod
    def select_backend(self, backends: List[Backend], request: Request) -> Optional[Backend]:
        """Select a backend for the request."""
        pass
    
    @abstractmethod
    def get_algorithm_stats(self) -> Dict[str, Any]:
        """Get algorithm-specific statistics."""
        pass


class RoundRobinAlgorithm(LoadBalancingAlgorithmInterface):
    """Round-robin load balancing algorithm."""
    
    def __init__(self):
        self._current_index = 0
        self._lock = RLock()
        self._total_selections = 0
    
    def select_backend(self, backends: List[Backend], request: Request) -> Optional[Backend]:
        """Select backend using round-robin."""
        available_backends = [b for b in backends if b.is_available]
        if not available_backends:
            return None
        
        with self._lock:
            backend = available_backends[self._current_index % len(available_backends)]
            self._current_index += 1
            self._total_selections += 1
            return backend
    
    def get_algorithm_stats(self) -> Dict[str, Any]:
        """Get round-robin statistics."""
        with self._lock:
            return {
                "algorithm": "round_robin",
                "current_index": self._current_index,
                "total_selections": self._total_selections
            }


class WeightedRoundRobinAlgorithm(LoadBalancingAlgorithmInterface):
    """Weighted round-robin load balancing algorithm."""
    
    def __init__(self):
        self._weights: Dict[str, int] = {}
        self._current_weights: Dict[str, int] = {}
        self._lock = RLock()
        self._total_selections = 0
    
    def select_backend(self, backends: List[Backend], request: Request) -> Optional[Backend]:
        """Select backend using weighted round-robin."""
        available_backends = [b for b in backends if b.is_available]
        if not available_backends:
            return None
        
        with self._lock:
            # Initialize weights if needed
            for backend in available_backends:
                if backend.backend_id not in self._weights:
                    self._weights[backend.backend_id] = backend.weight
                    self._current_weights[backend.backend_id] = 0
            
            # Find backend with highest current weight
            best_backend = None
            max_weight = -1
            
            for backend in available_backends:
                backend_id = backend.backend_id
                self._current_weights[backend_id] += self._weights[backend_id]
                
                if self._current_weights[backend_id] > max_weight:
                    max_weight = self._current_weights[backend_id]
                    best_backend = backend
            
            if best_backend:
                # Reduce the weight of selected backend
                total_weight = sum(self._weights[b.backend_id] for b in available_backends)
                self._current_weights[best_backend.backend_id] -= total_weight
                self._total_selections += 1
            
            return best_backend
    
    def get_algorithm_stats(self) -> Dict[str, Any]:
        """Get weighted round-robin statistics."""
        with self._lock:
            return {
                "algorithm": "weighted_round_robin",
                "weights": self._weights.copy(),
                "current_weights": self._current_weights.copy(),
                "total_selections": self._total_selections
            }


class LeastConnectionsAlgorithm(LoadBalancingAlgorithmInterface):
    """Least connections load balancing algorithm."""
    
    def __init__(self, weighted: bool = False):
        self.weighted = weighted
        self._total_selections = 0
        self._lock = RLock()
    
    def select_backend(self, backends: List[Backend], request: Request) -> Optional[Backend]:
        """Select backend with least connections."""
        available_backends = [b for b in backends if b.is_available]
        if not available_backends:
            return None
        
        with self._lock:
            if self.weighted:
                # Weighted least connections: connections / weight
                best_backend = min(
                    available_backends,
                    key=lambda b: b.metrics.active_connections / max(b.weight, 1)
                )
            else:
                # Simple least connections
                best_backend = min(
                    available_backends,
                    key=lambda b: b.metrics.active_connections
                )
            
            self._total_selections += 1
            return best_backend
    
    def get_algorithm_stats(self) -> Dict[str, Any]:
        """Get least connections statistics."""
        with self._lock:
            return {
                "algorithm": "least_connections" if not self.weighted else "weighted_least_connections",
                "weighted": self.weighted,
                "total_selections": self._total_selections
            }


class RandomAlgorithm(LoadBalancingAlgorithmInterface):
    """Random load balancing algorithm."""
    
    def __init__(self, weighted: bool = False):
        self.weighted = weighted
        self._total_selections = 0
        self._lock = RLock()
    
    def select_backend(self, backends: List[Backend], request: Request) -> Optional[Backend]:
        """Select backend randomly."""
        available_backends = [b for b in backends if b.is_available]
        if not available_backends:
            return None
        
        with self._lock:
            if self.weighted:
                # Weighted random selection
                weights = [b.weight for b in available_backends]
                backend = random.choices(available_backends, weights=weights)[0]
            else:
                # Simple random selection
                backend = random.choice(available_backends)
            
            self._total_selections += 1
            return backend
    
    def get_algorithm_stats(self) -> Dict[str, Any]:
        """Get random algorithm statistics."""
        with self._lock:
            return {
                "algorithm": "random" if not self.weighted else "weighted_random",
                "weighted": self.weighted,
                "total_selections": self._total_selections
            }


class IPHashAlgorithm(LoadBalancingAlgorithmInterface):
    """IP hash load balancing algorithm."""
    
    def __init__(self):
        self._total_selections = 0
        self._hash_distribution: Dict[str, int] = {}
        self._lock = RLock()
    
    def select_backend(self, backends: List[Backend], request: Request) -> Optional[Backend]:
        """Select backend based on client IP hash."""
        available_backends = [b for b in backends if b.is_available]
        if not available_backends:
            return None
        
        # Get client IP
        client_ip = request.client.host if request.client else "unknown"
        
        with self._lock:
            # Hash the IP and select backend
            hash_value = hash(client_ip)
            backend_index = hash_value % len(available_backends)
            backend = available_backends[backend_index]
            
            self._total_selections += 1
            self._hash_distribution[client_ip] = backend_index
            
            return backend
    
    def get_algorithm_stats(self) -> Dict[str, Any]:
        """Get IP hash statistics."""
        with self._lock:
            return {
                "algorithm": "ip_hash",
                "total_selections": self._total_selections,
                "unique_ips": len(self._hash_distribution)
            }


class LeastResponseTimeAlgorithm(LoadBalancingAlgorithmInterface):
    """Least response time load balancing algorithm."""
    
    def __init__(self):
        self._total_selections = 0
        self._lock = RLock()
    
    def select_backend(self, backends: List[Backend], request: Request) -> Optional[Backend]:
        """Select backend with least average response time."""
        available_backends = [b for b in backends if b.is_available]
        if not available_backends:
            return None
        
        with self._lock:
            # Select backend with lowest response time
            # Factor in active connections to avoid overloading fast but busy servers
            best_backend = min(
                available_backends,
                key=lambda b: b.metrics.average_response_time + (b.metrics.active_connections * 10)
            )
            
            self._total_selections += 1
            return best_backend
    
    def get_algorithm_stats(self) -> Dict[str, Any]:
        """Get least response time statistics."""
        with self._lock:
            return {
                "algorithm": "least_response_time",
                "total_selections": self._total_selections
            }


class ResourceBasedAlgorithm(LoadBalancingAlgorithmInterface):
    """Resource-based load balancing algorithm."""
    
    def __init__(self):
        self._total_selections = 0
        self._lock = RLock()
    
    def select_backend(self, backends: List[Backend], request: Request) -> Optional[Backend]:
        """Select backend based on resource utilization."""
        available_backends = [b for b in backends if b.is_available]
        if not available_backends:
            return None
        
        with self._lock:
            # Select backend with lowest load score
            best_backend = min(available_backends, key=lambda b: b.load_score)
            self._total_selections += 1
            return best_backend
    
    def get_algorithm_stats(self) -> Dict[str, Any]:
        """Get resource-based statistics."""
        with self._lock:
            return {
                "algorithm": "resource_based",
                "total_selections": self._total_selections
            }


class LoadBalancer:
    """Core load balancer with multiple algorithms and health monitoring."""
    
    def __init__(
        self,
        algorithm: LoadBalancingAlgorithm = LoadBalancingAlgorithm.ROUND_ROBIN,
        enable_health_checks: bool = True,
        enable_sticky_sessions: bool = False,
        sticky_session_strategy: StickySessionStrategy = StickySessionStrategy.COOKIE
    ):
        self.algorithm_type = algorithm
        self.enable_health_checks = enable_health_checks
        self.enable_sticky_sessions = enable_sticky_sessions
        
        self.backends: List[Backend] = []
        self.health_checker: Optional[HealthChecker] = None
        self.session_manager: Optional[SessionManager] = None
        
        # Initialize algorithm
        self._algorithm = self._create_algorithm(algorithm)
        
        # Initialize session manager if needed
        if enable_sticky_sessions:
            self.session_manager = SessionManager(strategy=sticky_session_strategy)
        
        self._lock = RLock()
        self._started = False
        
        # Metrics
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.average_response_time = 0.0
        self.response_times: List[float] = []
    
    def _create_algorithm(self, algorithm: LoadBalancingAlgorithm) -> LoadBalancingAlgorithmInterface:
        """Create algorithm instance."""
        if algorithm == LoadBalancingAlgorithm.ROUND_ROBIN:
            return RoundRobinAlgorithm()
        elif algorithm == LoadBalancingAlgorithm.WEIGHTED_ROUND_ROBIN:
            return WeightedRoundRobinAlgorithm()
        elif algorithm == LoadBalancingAlgorithm.LEAST_CONNECTIONS:
            return LeastConnectionsAlgorithm(weighted=False)
        elif algorithm == LoadBalancingAlgorithm.WEIGHTED_LEAST_CONNECTIONS:
            return LeastConnectionsAlgorithm(weighted=True)
        elif algorithm == LoadBalancingAlgorithm.RANDOM:
            return RandomAlgorithm(weighted=False)
        elif algorithm == LoadBalancingAlgorithm.WEIGHTED_RANDOM:
            return RandomAlgorithm(weighted=True)
        elif algorithm == LoadBalancingAlgorithm.IP_HASH:
            return IPHashAlgorithm()
        elif algorithm == LoadBalancingAlgorithm.LEAST_RESPONSE_TIME:
            return LeastResponseTimeAlgorithm()
        elif algorithm == LoadBalancingAlgorithm.RESOURCE_BASED:
            return ResourceBasedAlgorithm()
        else:
            raise ValueError(f"Unknown algorithm: {algorithm}")
    
    def add_backend(self, backend: Backend):
        """Add a backend to the load balancer."""
        with self._lock:
            self.backends.append(backend)
            
            # If health checking is already started, add health check for new backend
            if self._started and self.health_checker:
                task = asyncio.create_task(self.health_checker._health_check_loop(backend))
                self.health_checker._tasks.add(task)
                task.add_done_callback(self.health_checker._tasks.discard)
        
        logger.info(f"Added backend {backend.backend_id} to load balancer")
    
    def remove_backend(self, backend_id: str) -> bool:
        """Remove a backend from the load balancer."""
        with self._lock:
            for i, backend in enumerate(self.backends):
                if backend.backend_id == backend_id:
                    del self.backends[i]
                    logger.info(f"Removed backend {backend_id} from load balancer")
                    return True
        return False
    
    def get_backend(self, backend_id: str) -> Optional[Backend]:
        """Get backend by ID."""
        with self._lock:
            for backend in self.backends:
                if backend.backend_id == backend_id:
                    return backend
        return None
    
    async def start(self):
        """Start the load balancer."""
        if self._started:
            return
        
        with self._lock:
            self._started = True
        
        # Start health checking
        if self.enable_health_checks and self.backends:
            self.health_checker = HealthChecker(self.backends)
            await self.health_checker.start()
        
        logger.info(f"Load balancer started with {len(self.backends)} backends")
    
    async def stop(self):
        """Stop the load balancer."""
        if not self._started:
            return
        
        with self._lock:
            self._started = False
        
        # Stop health checking
        if self.health_checker:
            await self.health_checker.stop()
            self.health_checker = None
        
        logger.info("Load balancer stopped")
    
    def select_backend(self, request: Request) -> Optional[Backend]:
        """Select a backend for the request."""
        with self._lock:
            # Try sticky sessions first
            if self.enable_sticky_sessions and self.session_manager:
                session_backend = self.session_manager.get_backend_for_session(request, self.backends)
                if session_backend:
                    return session_backend
            
            # Use algorithm to select backend
            backend = self._algorithm.select_backend(self.backends, request)
            
            # If sticky sessions are enabled, create session
            if backend and self.enable_sticky_sessions and self.session_manager:
                self.session_manager.create_session(request, backend)
            
            return backend
    
    def update_request_metrics(self, backend: Backend, success: bool, response_time: float):
        """Update request metrics."""
        with self._lock:
            self.total_requests += 1
            
            if success:
                self.successful_requests += 1
            else:
                self.failed_requests += 1
            
            # Update average response time
            self.response_times.append(response_time)
            if len(self.response_times) > 1000:
                self.response_times.pop(0)
            self.average_response_time = statistics.mean(self.response_times)
            
            # Update backend metrics
            backend.metrics.update_request_metrics(success)
            backend.metrics.update_response_time(response_time)
    
    def get_load_balancer_stats(self) -> Dict[str, Any]:
        """Get load balancer statistics."""
        with self._lock:
            backend_stats = [backend.to_dict() for backend in self.backends]
            
            stats = {
                "algorithm": self.algorithm_type.value,
                "total_backends": len(self.backends),
                "healthy_backends": len([b for b in self.backends if b.status == BackendStatus.HEALTHY]),
                "degraded_backends": len([b for b in self.backends if b.status == BackendStatus.DEGRADED]),
                "unhealthy_backends": len([b for b in self.backends if b.status == BackendStatus.UNHEALTHY]),
                "total_requests": self.total_requests,
                "successful_requests": self.successful_requests,
                "failed_requests": self.failed_requests,
                "success_rate": self.successful_requests / max(self.total_requests, 1),
                "average_response_time": self.average_response_time,
                "enable_health_checks": self.enable_health_checks,
                "enable_sticky_sessions": self.enable_sticky_sessions,
                "backends": backend_stats,
                "algorithm_stats": self._algorithm.get_algorithm_stats()
            }
            
            # Add session stats if enabled
            if self.session_manager:
                stats["session_stats"] = self.session_manager.get_session_stats()
            
            return stats


class LoadBalancingShield(Shield):
    """Shield for load balancing requests across multiple backends."""
    
    def __init__(
        self,
        load_balancer: LoadBalancer,
        proxy_request: bool = True,
        timeout: float = 30.0,
        follow_redirects: bool = False,
        preserve_headers: bool = True,
        add_lb_headers: bool = True,
        **kwargs
    ):
        # Create shield function
        def shield_func(request: Request):
            return self._load_balance_request(request)
        
        super().__init__(shield_func, **kwargs)
        
        self.load_balancer = load_balancer
        self.proxy_request = proxy_request
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.preserve_headers = preserve_headers
        self.add_lb_headers = add_lb_headers
        
        self._client: Optional[httpx.AsyncClient] = None
        
    async def __aenter__(self):
        """Async context manager entry."""
        if not self._client:
            self._client = httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=self.follow_redirects
            )
        await self.load_balancer.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self._client:
            await self._client.aclose()
            self._client = None
        await self.load_balancer.stop()
    
    async def _load_balance_request(self, request: Request) -> Response:
        """Load balance and proxy the request."""
        start_time = time.time()
        
        # Select backend
        backend = self.load_balancer.select_backend(request)
        if not backend:
            raise HTTPException(
                status_code=503,
                detail="No available backends"
            )
        
        # Track active connections
        backend.increment_connections()
        
        try:
            if self.proxy_request:
                response = await self._proxy_request(request, backend)
            else:
                # Just return backend info without proxying
                response = JSONResponse({
                    "backend": backend.to_dict(),
                    "load_balancer_stats": self.load_balancer.get_load_balancer_stats()
                })
            
            # Update metrics
            response_time = (time.time() - start_time) * 1000
            self.load_balancer.update_request_metrics(backend, True, response_time)
            
            return response
            
        except Exception as e:
            # Update failure metrics
            response_time = (time.time() - start_time) * 1000
            self.load_balancer.update_request_metrics(backend, False, response_time)
            
            logger.error(f"Error proxying request to backend {backend.backend_id}: {e}")
            
            # Try to find another backend for failover
            backend.update_status(BackendStatus.DEGRADED)
            
            raise HTTPException(
                status_code=502,
                detail=f"Backend error: {str(e)}"
            )
        
        finally:
            backend.decrement_connections()
    
    async def _proxy_request(self, request: Request, backend: Backend) -> Response:
        """Proxy request to backend server."""
        if not self._client:
            raise RuntimeError("HTTP client not initialized")
        
        # Build target URL
        target_url = f"{backend.url}{request.url.path}"
        if request.url.query:
            target_url += f"?{request.url.query}"
        
        # Prepare headers
        headers = dict(request.headers) if self.preserve_headers else {}
        
        # Remove hop-by-hop headers
        hop_by_hop_headers = {
            'connection', 'keep-alive', 'proxy-authenticate',
            'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade'
        }
        headers = {k: v for k, v in headers.items() if k.lower() not in hop_by_hop_headers}
        
        # Add load balancer headers
        if self.add_lb_headers:
            headers['X-LoadBalancer-Backend'] = backend.backend_id
            headers['X-LoadBalancer-Algorithm'] = self.load_balancer.algorithm_type.value
            headers['X-LoadBalancer-Request-ID'] = f"lb-{int(time.time()*1000)}"
        
        # Get request body
        body = None
        if request.method in ('POST', 'PUT', 'PATCH'):
            body = await request.body()
        
        # Make request to backend
        response = await self._client.request(
            method=request.method,
            url=target_url,
            headers=headers,
            content=body,
        )
        
        # Prepare response headers
        response_headers = dict(response.headers)
        
        # Remove hop-by-hop headers from response
        response_headers = {
            k: v for k, v in response_headers.items() 
            if k.lower() not in hop_by_hop_headers
        }
        
        # Create FastAPI response
        return Response(
            content=response.content,
            status_code=response.status_code,
            headers=response_headers,
            media_type=response.headers.get('content-type')
        )


# Convenience functions

def create_load_balancer(
    backends: List[Dict[str, Any]],
    algorithm: LoadBalancingAlgorithm = LoadBalancingAlgorithm.ROUND_ROBIN,
    enable_health_checks: bool = True,
    enable_sticky_sessions: bool = False,
    sticky_session_strategy: StickySessionStrategy = StickySessionStrategy.COOKIE
) -> LoadBalancer:
    """Create a load balancer with backends from configuration."""
    load_balancer = LoadBalancer(
        algorithm=algorithm,
        enable_health_checks=enable_health_checks,
        enable_sticky_sessions=enable_sticky_sessions,
        sticky_session_strategy=sticky_session_strategy
    )
    
    # Add backends
    for backend_config in backends:
        backend = Backend(
            backend_id=backend_config["backend_id"],
            host=backend_config["host"],
            port=backend_config.get("port", 80),
            weight=backend_config.get("weight", 100),
            max_connections=backend_config.get("max_connections", 1000),
            tags=backend_config.get("tags"),
            metadata=backend_config.get("metadata")
        )
        
        # Configure health check if provided
        if "health_check" in backend_config:
            hc_config = backend_config["health_check"]
            backend.health_check_config = HealthCheckConfig(
                check_type=HealthCheckType(hc_config.get("type", "http")),
                url=hc_config.get("url"),
                method=hc_config.get("method", "GET"),
                timeout=hc_config.get("timeout", 5.0),
                interval=hc_config.get("interval", 30.0),
                unhealthy_threshold=hc_config.get("unhealthy_threshold", 3),
                healthy_threshold=hc_config.get("healthy_threshold", 2)
            )
        
        load_balancer.add_backend(backend)
    
    return load_balancer


def load_balancing_shield(
    load_balancer: LoadBalancer,
    proxy_request: bool = True,
    **kwargs
) -> Callable:
    """Decorator for creating load balancing shields."""
    def decorator(func):
        return LoadBalancingShield(
            load_balancer=load_balancer,
            proxy_request=proxy_request,
            **kwargs
        )(func)
    return decorator