"""Health Check shield for FastAPI Shield.

This module provides comprehensive service health validation functionality,
including application health checks, dependency validation, database connectivity,
cache availability, external service checks, and integration with container
orchestration platforms like Kubernetes and Docker.
"""

import asyncio
import socket
import ssl
import time
import logging
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Union, Callable, Set, Tuple
from urllib.parse import urlparse
import json

from fastapi import HTTPException, Request, Response, status
from fastapi.responses import JSONResponse

from fastapi_shield.shield import Shield


class HealthStatus(str, Enum):
    """Health status enumeration."""
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"
    TIMEOUT = "timeout"
    ERROR = "error"


class CheckType(str, Enum):
    """Health check type enumeration."""
    APPLICATION = "application"
    DATABASE = "database"
    CACHE = "cache"
    EXTERNAL_SERVICE = "external_service"
    FILE_SYSTEM = "file_system"
    MEMORY = "memory"
    CPU = "cpu"
    NETWORK = "network"
    CUSTOM = "custom"


class HealthCheckMode(str, Enum):
    """Health check execution mode."""
    SYNCHRONOUS = "synchronous"
    ASYNCHRONOUS = "asynchronous"
    PARALLEL = "parallel"
    SEQUENTIAL = "sequential"


@dataclass
class HealthCheckResult:
    """Result of a health check execution."""
    name: str
    status: HealthStatus
    check_type: CheckType
    duration_ms: float
    timestamp: datetime
    message: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'name': self.name,
            'status': self.status.value,
            'type': self.check_type.value,
            'duration_ms': self.duration_ms,
            'timestamp': self.timestamp.isoformat(),
            'message': self.message,
            'details': self.details,
            'error': self.error,
            'metadata': self.metadata
        }
    
    def is_healthy(self) -> bool:
        """Check if the result indicates healthy status."""
        return self.status == HealthStatus.HEALTHY


@dataclass
class HealthCheckSummary:
    """Summary of all health checks."""
    overall_status: HealthStatus
    total_checks: int
    healthy_checks: int
    unhealthy_checks: int
    degraded_checks: int
    total_duration_ms: float
    timestamp: datetime
    checks: List[HealthCheckResult] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'status': self.overall_status.value,
            'timestamp': self.timestamp.isoformat(),
            'summary': {
                'total_checks': self.total_checks,
                'healthy': self.healthy_checks,
                'unhealthy': self.unhealthy_checks,
                'degraded': self.degraded_checks,
                'total_duration_ms': self.total_duration_ms
            },
            'checks': [check.to_dict() for check in self.checks],
            'metadata': self.metadata
        }


class HealthCheck(ABC):
    """Abstract base class for health checks."""
    
    def __init__(
        self,
        name: str,
        check_type: CheckType = CheckType.CUSTOM,
        timeout_seconds: float = 5.0,
        enabled: bool = True,
        critical: bool = True,
        tags: Optional[Set[str]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        self.name = name
        self.check_type = check_type
        self.timeout_seconds = timeout_seconds
        self.enabled = enabled
        self.critical = critical
        self.tags = tags or set()
        self.metadata = metadata or {}
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    @abstractmethod
    async def check(self) -> HealthCheckResult:
        """Perform the health check."""
        pass
    
    async def execute(self) -> HealthCheckResult:
        """Execute the health check with timeout and error handling."""
        if not self.enabled:
            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.HEALTHY,
                check_type=self.check_type,
                duration_ms=0.0,
                timestamp=datetime.now(timezone.utc),
                message="Check disabled"
            )
        
        start_time = time.time()
        
        try:
            result = await asyncio.wait_for(
                self.check(),
                timeout=self.timeout_seconds
            )
            return result
        except asyncio.TimeoutError:
            duration_ms = (time.time() - start_time) * 1000
            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.TIMEOUT,
                check_type=self.check_type,
                duration_ms=duration_ms,
                timestamp=datetime.now(timezone.utc),
                error=f"Check timed out after {self.timeout_seconds}s"
            )
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            self._logger.error(f"Health check '{self.name}' failed: {e}")
            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.ERROR,
                check_type=self.check_type,
                duration_ms=duration_ms,
                timestamp=datetime.now(timezone.utc),
                error=str(e)
            )


class ApplicationHealthCheck(HealthCheck):
    """Basic application health check."""
    
    def __init__(
        self,
        name: str = "application",
        startup_check: Optional[Callable[[], bool]] = None,
        readiness_check: Optional[Callable[[], bool]] = None,
        liveness_check: Optional[Callable[[], bool]] = None,
        **kwargs
    ):
        super().__init__(name, CheckType.APPLICATION, **kwargs)
        self.startup_check = startup_check
        self.readiness_check = readiness_check
        self.liveness_check = liveness_check
    
    async def check(self) -> HealthCheckResult:
        """Perform application health check."""
        start_time = time.time()
        details = {}
        
        # Check startup
        if self.startup_check:
            startup_ok = self.startup_check()
            details['startup'] = startup_ok
            if not startup_ok:
                return HealthCheckResult(
                    name=self.name,
                    status=HealthStatus.UNHEALTHY,
                    check_type=self.check_type,
                    duration_ms=(time.time() - start_time) * 1000,
                    timestamp=datetime.now(timezone.utc),
                    message="Application startup check failed",
                    details=details
                )
        
        # Check readiness
        if self.readiness_check:
            readiness_ok = self.readiness_check()
            details['readiness'] = readiness_ok
            if not readiness_ok:
                return HealthCheckResult(
                    name=self.name,
                    status=HealthStatus.UNHEALTHY,
                    check_type=self.check_type,
                    duration_ms=(time.time() - start_time) * 1000,
                    timestamp=datetime.now(timezone.utc),
                    message="Application readiness check failed",
                    details=details
                )
        
        # Check liveness
        if self.liveness_check:
            liveness_ok = self.liveness_check()
            details['liveness'] = liveness_ok
            if not liveness_ok:
                return HealthCheckResult(
                    name=self.name,
                    status=HealthStatus.UNHEALTHY,
                    check_type=self.check_type,
                    duration_ms=(time.time() - start_time) * 1000,
                    timestamp=datetime.now(timezone.utc),
                    message="Application liveness check failed",
                    details=details
                )
        
        return HealthCheckResult(
            name=self.name,
            status=HealthStatus.HEALTHY,
            check_type=self.check_type,
            duration_ms=(time.time() - start_time) * 1000,
            timestamp=datetime.now(timezone.utc),
            message="Application is healthy",
            details=details
        )


class DatabaseHealthCheck(HealthCheck):
    """Database connectivity health check."""
    
    def __init__(
        self,
        name: str,
        connection_check: Callable[[], bool],
        query_check: Optional[Callable[[], bool]] = None,
        connection_pool_check: Optional[Callable[[], Dict[str, Any]]] = None,
        **kwargs
    ):
        super().__init__(name, CheckType.DATABASE, **kwargs)
        self.connection_check = connection_check
        self.query_check = query_check
        self.connection_pool_check = connection_pool_check
    
    async def check(self) -> HealthCheckResult:
        """Perform database health check."""
        start_time = time.time()
        details = {}
        
        # Check connection
        try:
            connection_ok = self.connection_check()
            details['connection'] = connection_ok
            
            if not connection_ok:
                return HealthCheckResult(
                    name=self.name,
                    status=HealthStatus.UNHEALTHY,
                    check_type=self.check_type,
                    duration_ms=(time.time() - start_time) * 1000,
                    timestamp=datetime.now(timezone.utc),
                    message="Database connection failed",
                    details=details
                )
        except Exception as e:
            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.ERROR,
                check_type=self.check_type,
                duration_ms=(time.time() - start_time) * 1000,
                timestamp=datetime.now(timezone.utc),
                error=f"Database connection error: {e}",
                details=details
            )
        
        # Check query execution
        if self.query_check:
            try:
                query_ok = self.query_check()
                details['query'] = query_ok
                
                if not query_ok:
                    return HealthCheckResult(
                        name=self.name,
                        status=HealthStatus.DEGRADED,
                        check_type=self.check_type,
                        duration_ms=(time.time() - start_time) * 1000,
                        timestamp=datetime.now(timezone.utc),
                        message="Database query check failed",
                        details=details
                    )
            except Exception as e:
                details['query_error'] = str(e)
        
        # Check connection pool
        if self.connection_pool_check:
            try:
                pool_info = self.connection_pool_check()
                details['connection_pool'] = pool_info
            except Exception as e:
                details['connection_pool_error'] = str(e)
        
        return HealthCheckResult(
            name=self.name,
            status=HealthStatus.HEALTHY,
            check_type=self.check_type,
            duration_ms=(time.time() - start_time) * 1000,
            timestamp=datetime.now(timezone.utc),
            message="Database is healthy",
            details=details
        )


class CacheHealthCheck(HealthCheck):
    """Cache service health check."""
    
    def __init__(
        self,
        name: str,
        ping_check: Callable[[], bool],
        set_get_check: Optional[Callable[[], bool]] = None,
        memory_usage_check: Optional[Callable[[], Dict[str, Any]]] = None,
        **kwargs
    ):
        super().__init__(name, CheckType.CACHE, **kwargs)
        self.ping_check = ping_check
        self.set_get_check = set_get_check
        self.memory_usage_check = memory_usage_check
    
    async def check(self) -> HealthCheckResult:
        """Perform cache health check."""
        start_time = time.time()
        details = {}
        
        # Ping check
        try:
            ping_ok = self.ping_check()
            details['ping'] = ping_ok
            
            if not ping_ok:
                return HealthCheckResult(
                    name=self.name,
                    status=HealthStatus.UNHEALTHY,
                    check_type=self.check_type,
                    duration_ms=(time.time() - start_time) * 1000,
                    timestamp=datetime.now(timezone.utc),
                    message="Cache ping failed",
                    details=details
                )
        except Exception as e:
            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.ERROR,
                check_type=self.check_type,
                duration_ms=(time.time() - start_time) * 1000,
                timestamp=datetime.now(timezone.utc),
                error=f"Cache ping error: {e}",
                details=details
            )
        
        # Set/Get check
        if self.set_get_check:
            try:
                set_get_ok = self.set_get_check()
                details['set_get'] = set_get_ok
                
                if not set_get_ok:
                    return HealthCheckResult(
                        name=self.name,
                        status=HealthStatus.DEGRADED,
                        check_type=self.check_type,
                        duration_ms=(time.time() - start_time) * 1000,
                        timestamp=datetime.now(timezone.utc),
                        message="Cache set/get check failed",
                        details=details
                    )
            except Exception as e:
                details['set_get_error'] = str(e)
        
        # Memory usage check
        if self.memory_usage_check:
            try:
                memory_info = self.memory_usage_check()
                details['memory_usage'] = memory_info
            except Exception as e:
                details['memory_usage_error'] = str(e)
        
        return HealthCheckResult(
            name=self.name,
            status=HealthStatus.HEALTHY,
            check_type=self.check_type,
            duration_ms=(time.time() - start_time) * 1000,
            timestamp=datetime.now(timezone.utc),
            message="Cache is healthy",
            details=details
        )


class ExternalServiceHealthCheck(HealthCheck):
    """External service health check."""
    
    def __init__(
        self,
        name: str,
        url: str,
        method: str = "GET",
        expected_status: int = 200,
        headers: Optional[Dict[str, str]] = None,
        verify_ssl: bool = True,
        **kwargs
    ):
        super().__init__(name, CheckType.EXTERNAL_SERVICE, **kwargs)
        self.url = url
        self.method = method.upper()
        self.expected_status = expected_status
        self.headers = headers or {}
        self.verify_ssl = verify_ssl
    
    async def check(self) -> HealthCheckResult:
        """Perform external service health check."""
        start_time = time.time()
        details = {
            'url': self.url,
            'method': self.method,
            'expected_status': self.expected_status
        }
        
        try:
            # Try to import httpx for HTTP checks
            try:
                import httpx
                
                async with httpx.AsyncClient(verify=self.verify_ssl) as client:
                    response = await client.request(
                        method=self.method,
                        url=self.url,
                        headers=self.headers,
                        timeout=self.timeout_seconds
                    )
                    
                    details['actual_status'] = response.status_code
                    details['response_time_ms'] = (time.time() - start_time) * 1000
                    
                    if response.status_code == self.expected_status:
                        return HealthCheckResult(
                            name=self.name,
                            status=HealthStatus.HEALTHY,
                            check_type=self.check_type,
                            duration_ms=(time.time() - start_time) * 1000,
                            timestamp=datetime.now(timezone.utc),
                            message=f"Service responded with expected status {self.expected_status}",
                            details=details
                        )
                    else:
                        return HealthCheckResult(
                            name=self.name,
                            status=HealthStatus.UNHEALTHY,
                            check_type=self.check_type,
                            duration_ms=(time.time() - start_time) * 1000,
                            timestamp=datetime.now(timezone.utc),
                            message=f"Unexpected status code: {response.status_code}",
                            details=details
                        )
                        
            except ImportError:
                # Fallback to basic socket check
                parsed_url = urlparse(self.url)
                host = parsed_url.hostname
                port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout_seconds)
                
                try:
                    if parsed_url.scheme == 'https':
                        context = ssl.create_default_context()
                        if not self.verify_ssl:
                            context.check_hostname = False
                            context.verify_mode = ssl.CERT_NONE
                        sock = context.wrap_socket(sock, server_hostname=host)
                    
                    result = sock.connect_ex((host, port))
                    sock.close()
                    
                    if result == 0:
                        return HealthCheckResult(
                            name=self.name,
                            status=HealthStatus.HEALTHY,
                            check_type=self.check_type,
                            duration_ms=(time.time() - start_time) * 1000,
                            timestamp=datetime.now(timezone.utc),
                            message=f"Connection to {host}:{port} successful",
                            details=details
                        )
                    else:
                        return HealthCheckResult(
                            name=self.name,
                            status=HealthStatus.UNHEALTHY,
                            check_type=self.check_type,
                            duration_ms=(time.time() - start_time) * 1000,
                            timestamp=datetime.now(timezone.utc),
                            message=f"Connection to {host}:{port} failed",
                            details=details
                        )
                except Exception as e:
                    return HealthCheckResult(
                        name=self.name,
                        status=HealthStatus.ERROR,
                        check_type=self.check_type,
                        duration_ms=(time.time() - start_time) * 1000,
                        timestamp=datetime.now(timezone.utc),
                        error=f"Socket connection error: {e}",
                        details=details
                    )
        
        except Exception as e:
            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.ERROR,
                check_type=self.check_type,
                duration_ms=(time.time() - start_time) * 1000,
                timestamp=datetime.now(timezone.utc),
                error=f"External service check error: {e}",
                details=details
            )


class FileSystemHealthCheck(HealthCheck):
    """File system health check."""
    
    def __init__(
        self,
        name: str,
        paths: List[str],
        check_writable: bool = True,
        min_free_space_mb: Optional[int] = None,
        **kwargs
    ):
        super().__init__(name, CheckType.FILE_SYSTEM, **kwargs)
        self.paths = paths
        self.check_writable = check_writable
        self.min_free_space_mb = min_free_space_mb
    
    async def check(self) -> HealthCheckResult:
        """Perform file system health check."""
        import os
        import shutil
        import tempfile
        
        start_time = time.time()
        details = {}
        
        for path in self.paths:
            path_details = {}
            
            # Check if path exists
            if not os.path.exists(path):
                return HealthCheckResult(
                    name=self.name,
                    status=HealthStatus.UNHEALTHY,
                    check_type=self.check_type,
                    duration_ms=(time.time() - start_time) * 1000,
                    timestamp=datetime.now(timezone.utc),
                    message=f"Path does not exist: {path}",
                    details=details
                )
            
            path_details['exists'] = True
            
            # Check if readable
            try:
                readable = os.access(path, os.R_OK)
                path_details['readable'] = readable
                
                if not readable:
                    return HealthCheckResult(
                        name=self.name,
                        status=HealthStatus.UNHEALTHY,
                        check_type=self.check_type,
                        duration_ms=(time.time() - start_time) * 1000,
                        timestamp=datetime.now(timezone.utc),
                        message=f"Path is not readable: {path}",
                        details=details
                    )
            except Exception as e:
                return HealthCheckResult(
                    name=self.name,
                    status=HealthStatus.ERROR,
                    check_type=self.check_type,
                    duration_ms=(time.time() - start_time) * 1000,
                    timestamp=datetime.now(timezone.utc),
                    error=f"Error checking readability of {path}: {e}",
                    details=details
                )
            
            # Check if writable
            if self.check_writable:
                try:
                    if os.path.isdir(path):
                        # Test write access by creating a temporary file
                        with tempfile.TemporaryFile(dir=path):
                            pass
                        writable = True
                    else:
                        writable = os.access(path, os.W_OK)
                    
                    path_details['writable'] = writable
                    
                    if not writable:
                        return HealthCheckResult(
                            name=self.name,
                            status=HealthStatus.DEGRADED,
                            check_type=self.check_type,
                            duration_ms=(time.time() - start_time) * 1000,
                            timestamp=datetime.now(timezone.utc),
                            message=f"Path is not writable: {path}",
                            details=details
                        )
                except Exception as e:
                    path_details['writable_error'] = str(e)
            
            # Check free space
            if self.min_free_space_mb and os.path.isdir(path):
                try:
                    _, _, free_bytes = shutil.disk_usage(path)
                    free_mb = free_bytes / (1024 * 1024)
                    path_details['free_space_mb'] = free_mb
                    
                    if free_mb < self.min_free_space_mb:
                        return HealthCheckResult(
                            name=self.name,
                            status=HealthStatus.DEGRADED,
                            check_type=self.check_type,
                            duration_ms=(time.time() - start_time) * 1000,
                            timestamp=datetime.now(timezone.utc),
                            message=f"Insufficient free space: {free_mb:.1f}MB < {self.min_free_space_mb}MB",
                            details=details
                        )
                except Exception as e:
                    path_details['free_space_error'] = str(e)
            
            details[path] = path_details
        
        return HealthCheckResult(
            name=self.name,
            status=HealthStatus.HEALTHY,
            check_type=self.check_type,
            duration_ms=(time.time() - start_time) * 1000,
            timestamp=datetime.now(timezone.utc),
            message="File system is healthy",
            details=details
        )


class MemoryHealthCheck(HealthCheck):
    """Memory usage health check."""
    
    def __init__(
        self,
        name: str = "memory",
        max_usage_percent: float = 90.0,
        warning_threshold_percent: float = 80.0,
        **kwargs
    ):
        super().__init__(name, CheckType.MEMORY, **kwargs)
        self.max_usage_percent = max_usage_percent
        self.warning_threshold_percent = warning_threshold_percent
    
    async def check(self) -> HealthCheckResult:
        """Perform memory health check."""
        import psutil
        
        start_time = time.time()
        
        try:
            memory = psutil.virtual_memory()
            details = {
                'total_mb': memory.total / (1024 * 1024),
                'available_mb': memory.available / (1024 * 1024),
                'used_mb': memory.used / (1024 * 1024),
                'usage_percent': memory.percent
            }
            
            if memory.percent > self.max_usage_percent:
                return HealthCheckResult(
                    name=self.name,
                    status=HealthStatus.UNHEALTHY,
                    check_type=self.check_type,
                    duration_ms=(time.time() - start_time) * 1000,
                    timestamp=datetime.now(timezone.utc),
                    message=f"Memory usage too high: {memory.percent:.1f}% > {self.max_usage_percent}%",
                    details=details
                )
            elif memory.percent > self.warning_threshold_percent:
                return HealthCheckResult(
                    name=self.name,
                    status=HealthStatus.DEGRADED,
                    check_type=self.check_type,
                    duration_ms=(time.time() - start_time) * 1000,
                    timestamp=datetime.now(timezone.utc),
                    message=f"Memory usage warning: {memory.percent:.1f}% > {self.warning_threshold_percent}%",
                    details=details
                )
            else:
                return HealthCheckResult(
                    name=self.name,
                    status=HealthStatus.HEALTHY,
                    check_type=self.check_type,
                    duration_ms=(time.time() - start_time) * 1000,
                    timestamp=datetime.now(timezone.utc),
                    message=f"Memory usage normal: {memory.percent:.1f}%",
                    details=details
                )
        
        except ImportError:
            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.UNKNOWN,
                check_type=self.check_type,
                duration_ms=(time.time() - start_time) * 1000,
                timestamp=datetime.now(timezone.utc),
                error="psutil not available for memory checks"
            )
        except Exception as e:
            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.ERROR,
                check_type=self.check_type,
                duration_ms=(time.time() - start_time) * 1000,
                timestamp=datetime.now(timezone.utc),
                error=f"Memory check error: {e}"
            )


class CPUHealthCheck(HealthCheck):
    """CPU usage health check."""
    
    def __init__(
        self,
        name: str = "cpu",
        max_usage_percent: float = 95.0,
        warning_threshold_percent: float = 85.0,
        check_interval: float = 1.0,
        **kwargs
    ):
        super().__init__(name, CheckType.CPU, **kwargs)
        self.max_usage_percent = max_usage_percent
        self.warning_threshold_percent = warning_threshold_percent
        self.check_interval = check_interval
    
    async def check(self) -> HealthCheckResult:
        """Perform CPU health check."""
        import psutil
        
        start_time = time.time()
        
        try:
            # Get CPU usage over the check interval
            cpu_percent = psutil.cpu_percent(interval=self.check_interval)
            cpu_count = psutil.cpu_count()
            load_avg = psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None
            
            details = {
                'usage_percent': cpu_percent,
                'cpu_count': cpu_count,
            }
            
            if load_avg:
                details['load_average'] = {
                    '1_min': load_avg[0],
                    '5_min': load_avg[1],
                    '15_min': load_avg[2]
                }
            
            if cpu_percent > self.max_usage_percent:
                return HealthCheckResult(
                    name=self.name,
                    status=HealthStatus.UNHEALTHY,
                    check_type=self.check_type,
                    duration_ms=(time.time() - start_time) * 1000,
                    timestamp=datetime.now(timezone.utc),
                    message=f"CPU usage too high: {cpu_percent:.1f}% > {self.max_usage_percent}%",
                    details=details
                )
            elif cpu_percent > self.warning_threshold_percent:
                return HealthCheckResult(
                    name=self.name,
                    status=HealthStatus.DEGRADED,
                    check_type=self.check_type,
                    duration_ms=(time.time() - start_time) * 1000,
                    timestamp=datetime.now(timezone.utc),
                    message=f"CPU usage warning: {cpu_percent:.1f}% > {self.warning_threshold_percent}%",
                    details=details
                )
            else:
                return HealthCheckResult(
                    name=self.name,
                    status=HealthStatus.HEALTHY,
                    check_type=self.check_type,
                    duration_ms=(time.time() - start_time) * 1000,
                    timestamp=datetime.now(timezone.utc),
                    message=f"CPU usage normal: {cpu_percent:.1f}%",
                    details=details
                )
        
        except ImportError:
            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.UNKNOWN,
                check_type=self.check_type,
                duration_ms=(time.time() - start_time) * 1000,
                timestamp=datetime.now(timezone.utc),
                error="psutil not available for CPU checks"
            )
        except Exception as e:
            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.ERROR,
                check_type=self.check_type,
                duration_ms=(time.time() - start_time) * 1000,
                timestamp=datetime.now(timezone.utc),
                error=f"CPU check error: {e}"
            )


class NetworkHealthCheck(HealthCheck):
    """Network connectivity health check."""
    
    def __init__(
        self,
        name: str,
        hosts: List[Tuple[str, int]],
        **kwargs
    ):
        super().__init__(name, CheckType.NETWORK, **kwargs)
        self.hosts = hosts
    
    async def check(self) -> HealthCheckResult:
        """Perform network health check."""
        start_time = time.time()
        details = {}
        
        failed_hosts = []
        
        for host, port in self.hosts:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout_seconds / len(self.hosts))
                result = sock.connect_ex((host, port))
                sock.close()
                
                host_key = f"{host}:{port}"
                if result == 0:
                    details[host_key] = "connected"
                else:
                    details[host_key] = "failed"
                    failed_hosts.append(host_key)
                    
            except Exception as e:
                host_key = f"{host}:{port}"
                details[host_key] = f"error: {e}"
                failed_hosts.append(host_key)
        
        if len(failed_hosts) == len(self.hosts):
            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.UNHEALTHY,
                check_type=self.check_type,
                duration_ms=(time.time() - start_time) * 1000,
                timestamp=datetime.now(timezone.utc),
                message="All network connections failed",
                details=details
            )
        elif failed_hosts:
            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.DEGRADED,
                check_type=self.check_type,
                duration_ms=(time.time() - start_time) * 1000,
                timestamp=datetime.now(timezone.utc),
                message=f"Some network connections failed: {', '.join(failed_hosts)}",
                details=details
            )
        else:
            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.HEALTHY,
                check_type=self.check_type,
                duration_ms=(time.time() - start_time) * 1000,
                timestamp=datetime.now(timezone.utc),
                message="All network connections successful",
                details=details
            )


class CustomHealthCheck(HealthCheck):
    """Custom health check with user-defined logic."""
    
    def __init__(
        self,
        name: str,
        check_function: Callable[[], Union[bool, HealthCheckResult]],
        **kwargs
    ):
        super().__init__(name, CheckType.CUSTOM, **kwargs)
        self.check_function = check_function
    
    async def check(self) -> HealthCheckResult:
        """Perform custom health check."""
        start_time = time.time()
        
        try:
            result = self.check_function()
            
            if isinstance(result, HealthCheckResult):
                return result
            elif isinstance(result, bool):
                status = HealthStatus.HEALTHY if result else HealthStatus.UNHEALTHY
                message = "Custom check passed" if result else "Custom check failed"
                
                return HealthCheckResult(
                    name=self.name,
                    status=status,
                    check_type=self.check_type,
                    duration_ms=(time.time() - start_time) * 1000,
                    timestamp=datetime.now(timezone.utc),
                    message=message
                )
            else:
                return HealthCheckResult(
                    name=self.name,
                    status=HealthStatus.ERROR,
                    check_type=self.check_type,
                    duration_ms=(time.time() - start_time) * 1000,
                    timestamp=datetime.now(timezone.utc),
                    error=f"Invalid return type from custom check: {type(result)}"
                )
        
        except Exception as e:
            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.ERROR,
                check_type=self.check_type,
                duration_ms=(time.time() - start_time) * 1000,
                timestamp=datetime.now(timezone.utc),
                error=f"Custom check error: {e}"
            )


@dataclass
class HealthCheckConfig:
    """Configuration for health check shield."""
    
    checks: List[HealthCheck] = field(default_factory=list)
    execution_mode: HealthCheckMode = HealthCheckMode.PARALLEL
    overall_timeout_seconds: float = 30.0
    enable_caching: bool = True
    cache_ttl_seconds: float = 5.0
    fail_on_first_error: bool = False
    include_details_in_response: bool = True
    kubernetes_format: bool = False
    docker_format: bool = False
    custom_response_format: Optional[Callable[[HealthCheckSummary], Dict[str, Any]]] = None
    health_endpoint: str = "/health"
    readiness_endpoint: str = "/ready"
    liveness_endpoint: str = "/live"
    startup_endpoint: str = "/startup"
    enable_detailed_logging: bool = False
    log_successful_checks: bool = False
    log_failed_checks: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


class HealthCheckCache:
    """Cache for health check results."""
    
    def __init__(self, ttl_seconds: float = 5.0):
        self.ttl_seconds = ttl_seconds
        self._cache: Dict[str, Tuple[HealthCheckSummary, float]] = {}
        self._lock = asyncio.Lock()
    
    async def get(self, key: str) -> Optional[HealthCheckSummary]:
        """Get cached health check result."""
        async with self._lock:
            if key in self._cache:
                result, timestamp = self._cache[key]
                if time.time() - timestamp < self.ttl_seconds:
                    return result
                else:
                    del self._cache[key]
            return None
    
    async def set(self, key: str, result: HealthCheckSummary):
        """Cache health check result."""
        async with self._lock:
            self._cache[key] = (result, time.time())
    
    async def clear(self):
        """Clear the cache."""
        async with self._lock:
            self._cache.clear()


class HealthCheckShield(Shield):
    """Health check shield for comprehensive service health validation."""
    
    def __init__(self, config: HealthCheckConfig):
        self.config = config
        self._cache = HealthCheckCache(config.cache_ttl_seconds) if config.enable_caching else None
        self._logger = logging.getLogger(__name__)
        
        super().__init__(self._shield_function)
    
    def add_check(self, check: HealthCheck):
        """Add a health check."""
        self.config.checks.append(check)
    
    def remove_check(self, name: str):
        """Remove a health check by name."""
        self.config.checks = [check for check in self.config.checks if check.name != name]
    
    def get_check(self, name: str) -> Optional[HealthCheck]:
        """Get a health check by name."""
        for check in self.config.checks:
            if check.name == name:
                return check
        return None
    
    async def _execute_checks(self, check_subset: Optional[List[str]] = None) -> HealthCheckSummary:
        """Execute health checks based on configuration."""
        start_time = time.time()
        
        # Filter checks if subset specified
        checks_to_run = self.config.checks
        if check_subset:
            checks_to_run = [check for check in self.config.checks if check.name in check_subset]
        
        if not checks_to_run:
            return HealthCheckSummary(
                overall_status=HealthStatus.HEALTHY,
                total_checks=0,
                healthy_checks=0,
                unhealthy_checks=0,
                degraded_checks=0,
                total_duration_ms=0.0,
                timestamp=datetime.now(timezone.utc),
                metadata=self.config.metadata
            )
        
        results = []
        
        try:
            if self.config.execution_mode == HealthCheckMode.PARALLEL:
                # Execute all checks in parallel
                tasks = [check.execute() for check in checks_to_run]
                results = await asyncio.gather(
                    *tasks,
                    return_exceptions=True
                )
                
                # Handle any exceptions
                final_results = []
                for i, result in enumerate(results):
                    if isinstance(result, Exception):
                        check = checks_to_run[i]
                        final_results.append(HealthCheckResult(
                            name=check.name,
                            status=HealthStatus.ERROR,
                            check_type=check.check_type,
                            duration_ms=0.0,
                            timestamp=datetime.now(timezone.utc),
                            error=str(result)
                        ))
                    else:
                        final_results.append(result)
                
                results = final_results
                
            elif self.config.execution_mode == HealthCheckMode.SEQUENTIAL:
                # Execute checks one by one
                for check in checks_to_run:
                    try:
                        result = await check.execute()
                        results.append(result)
                        
                        if (self.config.fail_on_first_error and 
                            result.status in [HealthStatus.UNHEALTHY, HealthStatus.ERROR]):
                            break
                    except Exception as e:
                        error_result = HealthCheckResult(
                            name=check.name,
                            status=HealthStatus.ERROR,
                            check_type=check.check_type,
                            duration_ms=0.0,
                            timestamp=datetime.now(timezone.utc),
                            error=str(e)
                        )
                        results.append(error_result)
                        
                        if self.config.fail_on_first_error:
                            break
            
            # Calculate summary statistics
            healthy_count = sum(1 for r in results if r.status == HealthStatus.HEALTHY)
            unhealthy_count = sum(1 for r in results if r.status == HealthStatus.UNHEALTHY)
            degraded_count = sum(1 for r in results if r.status == HealthStatus.DEGRADED)
            error_count = sum(1 for r in results if r.status in [HealthStatus.ERROR, HealthStatus.TIMEOUT])
            
            total_duration = (time.time() - start_time) * 1000
            
            # Determine overall status
            if error_count > 0 or unhealthy_count > 0:
                # Check if any critical checks failed
                critical_failed = any(
                    r.status in [HealthStatus.UNHEALTHY, HealthStatus.ERROR, HealthStatus.TIMEOUT]
                    for r, check in zip(results, checks_to_run)
                    if check.critical
                )
                overall_status = HealthStatus.UNHEALTHY if critical_failed else HealthStatus.DEGRADED
            elif degraded_count > 0:
                overall_status = HealthStatus.DEGRADED
            else:
                overall_status = HealthStatus.HEALTHY
            
            # Log results
            if self.config.enable_detailed_logging:
                for result in results:
                    if result.status != HealthStatus.HEALTHY and self.config.log_failed_checks:
                        self._logger.warning(f"Health check '{result.name}' failed: {result.error or result.message}")
                    elif result.status == HealthStatus.HEALTHY and self.config.log_successful_checks:
                        self._logger.info(f"Health check '{result.name}' passed")
            
            return HealthCheckSummary(
                overall_status=overall_status,
                total_checks=len(results),
                healthy_checks=healthy_count,
                unhealthy_checks=unhealthy_count,
                degraded_checks=degraded_count,
                total_duration_ms=total_duration,
                timestamp=datetime.now(timezone.utc),
                checks=results,
                metadata=self.config.metadata
            )
            
        except asyncio.TimeoutError:
            return HealthCheckSummary(
                overall_status=HealthStatus.TIMEOUT,
                total_checks=len(checks_to_run),
                healthy_checks=0,
                unhealthy_checks=0,
                degraded_checks=0,
                total_duration_ms=(time.time() - start_time) * 1000,
                timestamp=datetime.now(timezone.utc),
                checks=[],
                metadata={'error': 'Health checks timed out'}
            )
    
    def _format_response(self, summary: HealthCheckSummary, endpoint_type: str = "health") -> Dict[str, Any]:
        """Format the health check response."""
        if self.config.custom_response_format:
            return self.config.custom_response_format(summary)
        
        if self.config.kubernetes_format:
            return self._format_kubernetes_response(summary, endpoint_type)
        elif self.config.docker_format:
            return self._format_docker_response(summary)
        else:
            return self._format_standard_response(summary)
    
    def _format_standard_response(self, summary: HealthCheckSummary) -> Dict[str, Any]:
        """Format standard health check response."""
        response = summary.to_dict()
        
        if not self.config.include_details_in_response:
            response.pop('checks', None)
        
        return response
    
    def _format_kubernetes_response(self, summary: HealthCheckSummary, endpoint_type: str) -> Dict[str, Any]:
        """Format Kubernetes-compatible health check response."""
        if endpoint_type == "readiness":
            # Readiness check - service ready to receive traffic
            ready = summary.overall_status in [HealthStatus.HEALTHY, HealthStatus.DEGRADED]
            return {"status": "ready" if ready else "not ready"}
        elif endpoint_type == "liveness":
            # Liveness check - service is alive (not necessarily ready)
            alive = summary.overall_status != HealthStatus.UNHEALTHY
            return {"status": "alive" if alive else "dead"}
        elif endpoint_type == "startup":
            # Startup check - service has completed startup
            started = summary.overall_status != HealthStatus.UNKNOWN
            return {"status": "started" if started else "starting"}
        else:
            # General health check
            return {
                "status": summary.overall_status.value,
                "timestamp": summary.timestamp.isoformat(),
                "checks": len(summary.checks)
            }
    
    def _format_docker_response(self, summary: HealthCheckSummary) -> Dict[str, Any]:
        """Format Docker-compatible health check response."""
        # Docker expects simple success/failure
        if summary.overall_status == HealthStatus.HEALTHY:
            return {"Status": "healthy", "Output": "All checks passed"}
        else:
            failed_checks = [
                check.name for check in summary.checks
                if check.status in [HealthStatus.UNHEALTHY, HealthStatus.ERROR]
            ]
            return {
                "Status": "unhealthy",
                "Output": f"Failed checks: {', '.join(failed_checks) if failed_checks else 'Unknown error'}"
            }
    
    async def _shield_function(self, request: Request) -> Optional[Response]:
        """Main shield function for health checks."""
        path = request.url.path
        
        # Determine endpoint type
        endpoint_type = "health"
        if path == self.config.readiness_endpoint:
            endpoint_type = "readiness"
        elif path == self.config.liveness_endpoint:
            endpoint_type = "liveness"
        elif path == self.config.startup_endpoint:
            endpoint_type = "startup"
        elif path != self.config.health_endpoint:
            return None  # Not a health check endpoint
        
        # Check for specific checks in query params
        check_subset = None
        if "checks" in request.query_params:
            check_subset = request.query_params["checks"].split(",")
        
        # Use cache if enabled
        cache_key = f"{endpoint_type}:{','.join(check_subset) if check_subset else 'all'}"
        
        if self._cache:
            cached_result = await self._cache.get(cache_key)
            if cached_result:
                response_data = self._format_response(cached_result, endpoint_type)
                status_code = self._get_status_code(cached_result.overall_status, endpoint_type)
                return JSONResponse(content=response_data, status_code=status_code)
        
        # Execute health checks
        try:
            summary = await asyncio.wait_for(
                self._execute_checks(check_subset),
                timeout=self.config.overall_timeout_seconds
            )
        except asyncio.TimeoutError:
            summary = HealthCheckSummary(
                overall_status=HealthStatus.TIMEOUT,
                total_checks=len(self.config.checks),
                healthy_checks=0,
                unhealthy_checks=0,
                degraded_checks=0,
                total_duration_ms=self.config.overall_timeout_seconds * 1000,
                timestamp=datetime.now(timezone.utc),
                checks=[],
                metadata={'error': 'Overall health check timeout'}
            )
        
        # Cache the result
        if self._cache:
            await self._cache.set(cache_key, summary)
        
        # Format and return response
        response_data = self._format_response(summary, endpoint_type)
        status_code = self._get_status_code(summary.overall_status, endpoint_type)
        
        return JSONResponse(content=response_data, status_code=status_code)
    
    def _get_status_code(self, health_status: HealthStatus, endpoint_type: str) -> int:
        """Get HTTP status code based on health status."""
        if endpoint_type in ["readiness", "liveness", "startup"]:
            # Kubernetes-style endpoints
            if health_status in [HealthStatus.HEALTHY, HealthStatus.DEGRADED]:
                return 200
            else:
                return 503  # Service Unavailable
        else:
            # Standard health check
            if health_status == HealthStatus.HEALTHY:
                return 200
            elif health_status == HealthStatus.DEGRADED:
                return 200  # Still serving but with warnings
            else:
                return 503  # Service Unavailable
    
    async def get_health_summary(self) -> HealthCheckSummary:
        """Get current health summary."""
        return await self._execute_checks()
    
    async def clear_cache(self):
        """Clear health check cache."""
        if self._cache:
            await self._cache.clear()


# Convenience functions for creating health check shields

def basic_health_check_shield(
    health_endpoint: str = "/health",
    timeout_seconds: float = 30.0,
    enable_caching: bool = True
) -> HealthCheckShield:
    """Create a basic health check shield.
    
    Args:
        health_endpoint: Endpoint for health checks
        timeout_seconds: Overall timeout for health checks
        enable_caching: Enable result caching
    
    Returns:
        HealthCheckShield instance
    """
    config = HealthCheckConfig(
        health_endpoint=health_endpoint,
        overall_timeout_seconds=timeout_seconds,
        enable_caching=enable_caching,
        checks=[ApplicationHealthCheck()]
    )
    
    return HealthCheckShield(config)


def kubernetes_health_check_shield(
    health_endpoint: str = "/health",
    readiness_endpoint: str = "/ready",
    liveness_endpoint: str = "/live",
    startup_endpoint: str = "/startup"
) -> HealthCheckShield:
    """Create a Kubernetes-compatible health check shield.
    
    Args:
        health_endpoint: General health check endpoint
        readiness_endpoint: Kubernetes readiness probe endpoint
        liveness_endpoint: Kubernetes liveness probe endpoint
        startup_endpoint: Kubernetes startup probe endpoint
    
    Returns:
        HealthCheckShield instance
    """
    config = HealthCheckConfig(
        health_endpoint=health_endpoint,
        readiness_endpoint=readiness_endpoint,
        liveness_endpoint=liveness_endpoint,
        startup_endpoint=startup_endpoint,
        kubernetes_format=True,
        checks=[ApplicationHealthCheck()]
    )
    
    return HealthCheckShield(config)


def docker_health_check_shield(
    health_endpoint: str = "/health",
    timeout_seconds: float = 30.0
) -> HealthCheckShield:
    """Create a Docker-compatible health check shield.
    
    Args:
        health_endpoint: Endpoint for health checks
        timeout_seconds: Overall timeout for health checks
    
    Returns:
        HealthCheckShield instance
    """
    config = HealthCheckConfig(
        health_endpoint=health_endpoint,
        overall_timeout_seconds=timeout_seconds,
        docker_format=True,
        checks=[ApplicationHealthCheck()]
    )
    
    return HealthCheckShield(config)


def comprehensive_health_check_shield(
    database_check: Optional[Callable[[], bool]] = None,
    cache_check: Optional[Callable[[], bool]] = None,
    external_services: Optional[List[str]] = None,
    file_system_paths: Optional[List[str]] = None,
    enable_system_checks: bool = True,
    kubernetes_format: bool = False,
    docker_format: bool = False
) -> HealthCheckShield:
    """Create a comprehensive health check shield with multiple check types.
    
    Args:
        database_check: Database connectivity check function
        cache_check: Cache availability check function
        external_services: List of external service URLs to check
        file_system_paths: List of file system paths to check
        enable_system_checks: Enable CPU and memory checks
        kubernetes_format: Use Kubernetes-compatible format
        docker_format: Use Docker-compatible format
    
    Returns:
        HealthCheckShield instance
    """
    checks = [ApplicationHealthCheck()]
    
    # Add database check
    if database_check:
        checks.append(DatabaseHealthCheck("database", database_check))
    
    # Add cache check
    if cache_check:
        checks.append(CacheHealthCheck("cache", cache_check))
    
    # Add external service checks
    if external_services:
        for i, url in enumerate(external_services):
            name = f"external_service_{i}" if len(external_services) > 1 else "external_service"
            checks.append(ExternalServiceHealthCheck(name, url))
    
    # Add file system checks
    if file_system_paths:
        checks.append(FileSystemHealthCheck("file_system", file_system_paths))
    
    # Add system checks
    if enable_system_checks:
        try:
            import psutil
            checks.extend([
                MemoryHealthCheck(),
                CPUHealthCheck()
            ])
        except ImportError:
            pass  # Skip system checks if psutil not available
    
    config = HealthCheckConfig(
        checks=checks,
        kubernetes_format=kubernetes_format,
        docker_format=docker_format,
        execution_mode=HealthCheckMode.PARALLEL
    )
    
    return HealthCheckShield(config)


def custom_health_check_shield(
    checks: List[HealthCheck],
    execution_mode: HealthCheckMode = HealthCheckMode.PARALLEL,
    overall_timeout: float = 30.0,
    enable_caching: bool = True,
    cache_ttl: float = 5.0
) -> HealthCheckShield:
    """Create a health check shield with custom checks.
    
    Args:
        checks: List of health checks to execute
        execution_mode: How to execute the checks
        overall_timeout: Overall timeout for all checks
        enable_caching: Enable result caching
        cache_ttl: Cache TTL in seconds
    
    Returns:
        HealthCheckShield instance
    """
    config = HealthCheckConfig(
        checks=checks,
        execution_mode=execution_mode,
        overall_timeout_seconds=overall_timeout,
        enable_caching=enable_caching,
        cache_ttl_seconds=cache_ttl
    )
    
    return HealthCheckShield(config)