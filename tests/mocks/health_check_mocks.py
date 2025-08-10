"""Mock classes and utilities for health check shield testing."""

import asyncio
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Callable, Tuple
from unittest.mock import Mock, AsyncMock
import socket

from fastapi_shield.health_check import (
    HealthCheck,
    HealthCheckResult,
    HealthCheckSummary,
    HealthStatus,
    CheckType,
    HealthCheckMode,
    HealthCheckConfig
)


class MockHealthCheck(HealthCheck):
    """Mock health check for testing."""
    
    def __init__(
        self,
        name: str,
        check_type: CheckType = CheckType.CUSTOM,
        result_status: HealthStatus = HealthStatus.HEALTHY,
        result_message: str = "Mock check passed",
        result_details: Optional[Dict[str, Any]] = None,
        check_duration_ms: float = 10.0,
        should_raise_exception: bool = False,
        exception_message: str = "Mock exception",
        **kwargs
    ):
        super().__init__(name, check_type, **kwargs)
        self.result_status = result_status
        self.result_message = result_message
        self.result_details = result_details or {}
        self.check_duration_ms = check_duration_ms
        self.should_raise_exception = should_raise_exception
        self.exception_message = exception_message
        self.call_count = 0
        self.call_history = []
    
    async def check(self) -> HealthCheckResult:
        """Mock health check implementation."""
        self.call_count += 1
        call_start = time.time()
        
        if self.should_raise_exception:
            raise Exception(self.exception_message)
        
        # Simulate check duration
        if self.check_duration_ms > 0:
            await asyncio.sleep(self.check_duration_ms / 1000.0)
        
        result = HealthCheckResult(
            name=self.name,
            status=self.result_status,
            check_type=self.check_type,
            duration_ms=self.check_duration_ms,
            timestamp=datetime.now(timezone.utc),
            message=self.result_message,
            details=self.result_details.copy()
        )
        
        self.call_history.append({
            'timestamp': call_start,
            'result': result
        })
        
        return result
    
    def set_result(
        self,
        status: HealthStatus,
        message: str = None,
        details: Dict[str, Any] = None
    ):
        """Set the result that will be returned by check()."""
        self.result_status = status
        if message is not None:
            self.result_message = message
        if details is not None:
            self.result_details = details
    
    def set_exception(self, should_raise: bool, message: str = "Mock exception"):
        """Configure the check to raise an exception."""
        self.should_raise_exception = should_raise
        self.exception_message = message
    
    def reset(self):
        """Reset mock state."""
        self.call_count = 0
        self.call_history = []
        self.should_raise_exception = False


class MockRequest:
    """Mock FastAPI request for testing."""
    
    def __init__(
        self,
        path: str = "/health",
        method: str = "GET",
        query_params: Optional[Dict[str, str]] = None
    ):
        self.url = Mock()
        self.url.path = path
        self.method = method
        
        # Mock query params with dict-like behavior
        class QueryDict(dict):
            def __contains__(self, key):
                return super().__contains__(key)
            
            def get(self, key, default=None):
                return super().get(key, default)
        
        self.query_params = QueryDict(query_params or {})


class MockDatabase:
    """Mock database for testing database health checks."""
    
    def __init__(self):
        self.is_connected = True
        self.query_works = True
        self.connection_pool_info = {
            'active_connections': 5,
            'idle_connections': 3,
            'max_connections': 20
        }
        self.call_count = 0
    
    def check_connection(self) -> bool:
        """Mock database connection check."""
        self.call_count += 1
        return self.is_connected
    
    def check_query(self) -> bool:
        """Mock database query check."""
        if not self.is_connected:
            raise Exception("Database not connected")
        return self.query_works
    
    def get_connection_pool_info(self) -> Dict[str, Any]:
        """Mock connection pool info."""
        if not self.is_connected:
            raise Exception("Database not connected")
        return self.connection_pool_info.copy()
    
    def set_connected(self, connected: bool):
        """Set connection status."""
        self.is_connected = connected
    
    def set_query_works(self, works: bool):
        """Set query status."""
        self.query_works = works


class MockCache:
    """Mock cache for testing cache health checks."""
    
    def __init__(self):
        self.ping_works = True
        self.set_get_works = True
        self.memory_info = {
            'used_memory': 1024 * 1024 * 100,  # 100MB
            'max_memory': 1024 * 1024 * 1024,  # 1GB
            'usage_percent': 10.0
        }
        self.call_count = 0
    
    def ping(self) -> bool:
        """Mock cache ping."""
        self.call_count += 1
        return self.ping_works
    
    def test_set_get(self) -> bool:
        """Mock cache set/get test."""
        if not self.ping_works:
            raise Exception("Cache not reachable")
        return self.set_get_works
    
    def get_memory_usage(self) -> Dict[str, Any]:
        """Mock memory usage info."""
        if not self.ping_works:
            raise Exception("Cache not reachable")
        return self.memory_info.copy()
    
    def set_ping_works(self, works: bool):
        """Set ping status."""
        self.ping_works = works
    
    def set_set_get_works(self, works: bool):
        """Set set/get status."""
        self.set_get_works = works


class MockApplication:
    """Mock application for testing application health checks."""
    
    def __init__(self):
        self.startup_complete = True
        self.ready = True
        self.alive = True
        self.call_counts = {
            'startup': 0,
            'readiness': 0,
            'liveness': 0
        }
    
    def check_startup(self) -> bool:
        """Mock startup check."""
        self.call_counts['startup'] += 1
        return self.startup_complete
    
    def check_readiness(self) -> bool:
        """Mock readiness check."""
        self.call_counts['readiness'] += 1
        return self.ready
    
    def check_liveness(self) -> bool:
        """Mock liveness check."""
        self.call_counts['liveness'] += 1
        return self.alive
    
    def set_startup_complete(self, complete: bool):
        """Set startup status."""
        self.startup_complete = complete
    
    def set_ready(self, ready: bool):
        """Set readiness status."""
        self.ready = ready
    
    def set_alive(self, alive: bool):
        """Set liveness status."""
        self.alive = alive


class MockSystem:
    """Mock system for testing system resource health checks."""
    
    def __init__(self):
        self.memory_percent = 50.0
        self.cpu_percent = 30.0
        self.disk_usage = {
            'total': 1024 * 1024 * 1024 * 100,  # 100GB
            'used': 1024 * 1024 * 1024 * 50,    # 50GB
            'free': 1024 * 1024 * 1024 * 50     # 50GB
        }
        self.load_average = (1.0, 1.5, 2.0)
        self.psutil_available = True
    
    def get_memory_percent(self) -> float:
        """Mock memory usage percentage."""
        if not self.psutil_available:
            raise ImportError("psutil not available")
        return self.memory_percent
    
    def get_cpu_percent(self) -> float:
        """Mock CPU usage percentage."""
        if not self.psutil_available:
            raise ImportError("psutil not available")
        return self.cpu_percent
    
    def get_disk_usage(self, path: str) -> Dict[str, int]:
        """Mock disk usage info."""
        return self.disk_usage.copy()
    
    def get_load_average(self) -> Tuple[float, float, float]:
        """Mock load average."""
        if not self.psutil_available:
            raise AttributeError("getloadavg not available")
        return self.load_average
    
    def set_memory_percent(self, percent: float):
        """Set memory usage percentage."""
        self.memory_percent = percent
    
    def set_cpu_percent(self, percent: float):
        """Set CPU usage percentage."""
        self.cpu_percent = percent
    
    def set_psutil_available(self, available: bool):
        """Set psutil availability."""
        self.psutil_available = available


class MockExternalService:
    """Mock external service for testing external service health checks."""
    
    def __init__(self, host: str = "example.com", port: int = 80):
        self.host = host
        self.port = port
        self.is_reachable = True
        self.response_status = 200
        self.response_delay = 0.0
        self.should_raise_exception = False
        self.exception_message = "Mock service error"
        self.call_count = 0
    
    def mock_socket_connect(self, address: Tuple[str, int]) -> int:
        """Mock socket connection."""
        self.call_count += 1
        
        if self.should_raise_exception:
            raise Exception(self.exception_message)
        
        if address[0] == self.host and address[1] == self.port:
            return 0 if self.is_reachable else 1
        
        return 1  # Connection failed
    
    async def mock_http_request(self, method: str, url: str, **kwargs):
        """Mock HTTP request."""
        self.call_count += 1
        
        if self.should_raise_exception:
            raise Exception(self.exception_message)
        
        if self.response_delay > 0:
            await asyncio.sleep(self.response_delay)
        
        # Mock response
        response = Mock()
        response.status_code = self.response_status
        return response
    
    def set_reachable(self, reachable: bool):
        """Set reachability status."""
        self.is_reachable = reachable
    
    def set_response_status(self, status: int):
        """Set HTTP response status."""
        self.response_status = status
    
    def set_response_delay(self, delay: float):
        """Set response delay."""
        self.response_delay = delay
    
    def set_exception(self, should_raise: bool, message: str = "Mock service error"):
        """Configure service to raise exception."""
        self.should_raise_exception = should_raise
        self.exception_message = message


class MockFileSystem:
    """Mock file system for testing file system health checks."""
    
    def __init__(self):
        self.existing_paths = {'/tmp', '/var/log', '/app'}
        self.readable_paths = {'/tmp', '/var/log', '/app'}
        self.writable_paths = {'/tmp', '/var/log'}
        self.disk_usage = {
            'total': 1024 * 1024 * 1024 * 100,  # 100GB
            'used': 1024 * 1024 * 1024 * 50,    # 50GB
            'free': 1024 * 1024 * 1024 * 50     # 50GB
        }
    
    def path_exists(self, path: str) -> bool:
        """Mock path exists check."""
        return path in self.existing_paths
    
    def path_readable(self, path: str) -> bool:
        """Mock path readable check."""
        return path in self.readable_paths
    
    def path_writable(self, path: str) -> bool:
        """Mock path writable check."""
        return path in self.writable_paths
    
    def get_disk_usage(self, path: str) -> Dict[str, int]:
        """Mock disk usage."""
        if path not in self.existing_paths:
            raise FileNotFoundError(f"Path not found: {path}")
        return self.disk_usage.copy()
    
    def add_path(self, path: str, readable: bool = True, writable: bool = True):
        """Add a mock path."""
        self.existing_paths.add(path)
        if readable:
            self.readable_paths.add(path)
        if writable:
            self.writable_paths.add(path)
    
    def remove_path(self, path: str):
        """Remove a mock path."""
        self.existing_paths.discard(path)
        self.readable_paths.discard(path)
        self.writable_paths.discard(path)
    
    def set_disk_usage(self, total: int, used: int, free: int):
        """Set disk usage values."""
        self.disk_usage = {'total': total, 'used': used, 'free': free}


class HealthCheckTestHelper:
    """Helper class for health check testing."""
    
    @staticmethod
    def create_mock_healthy_check(name: str = "test_check") -> MockHealthCheck:
        """Create a mock healthy check."""
        return MockHealthCheck(
            name=name,
            result_status=HealthStatus.HEALTHY,
            result_message="Check passed"
        )
    
    @staticmethod
    def create_mock_unhealthy_check(name: str = "test_check") -> MockHealthCheck:
        """Create a mock unhealthy check."""
        return MockHealthCheck(
            name=name,
            result_status=HealthStatus.UNHEALTHY,
            result_message="Check failed"
        )
    
    @staticmethod
    def create_mock_degraded_check(name: str = "test_check") -> MockHealthCheck:
        """Create a mock degraded check."""
        return MockHealthCheck(
            name=name,
            result_status=HealthStatus.DEGRADED,
            result_message="Check degraded"
        )
    
    @staticmethod
    def create_mock_error_check(name: str = "test_check") -> MockHealthCheck:
        """Create a mock error check."""
        return MockHealthCheck(
            name=name,
            should_raise_exception=True,
            exception_message="Mock check error"
        )
    
    @staticmethod
    def create_slow_check(name: str = "slow_check", duration_ms: float = 1000.0) -> MockHealthCheck:
        """Create a mock slow check."""
        return MockHealthCheck(
            name=name,
            result_status=HealthStatus.HEALTHY,
            check_duration_ms=duration_ms
        )
    
    @staticmethod
    def create_mixed_checks() -> List[MockHealthCheck]:
        """Create a mix of different health check types."""
        return [
            HealthCheckTestHelper.create_mock_healthy_check("healthy_1"),
            HealthCheckTestHelper.create_mock_healthy_check("healthy_2"),
            HealthCheckTestHelper.create_mock_degraded_check("degraded_1"),
            HealthCheckTestHelper.create_mock_unhealthy_check("unhealthy_1"),
        ]
    
    @staticmethod
    def create_timeout_scenario_checks(timeout_seconds: float = 1.0) -> List[MockHealthCheck]:
        """Create checks that will timeout."""
        return [
            MockHealthCheck(
                name="fast_check",
                check_duration_ms=100.0,
                timeout_seconds=timeout_seconds
            ),
            MockHealthCheck(
                name="slow_check",
                check_duration_ms=(timeout_seconds + 1) * 1000,  # Will timeout
                timeout_seconds=timeout_seconds
            ),
            MockHealthCheck(
                name="very_slow_check", 
                check_duration_ms=(timeout_seconds + 2) * 1000,  # Will timeout
                timeout_seconds=timeout_seconds
            )
        ]
    
    @staticmethod
    def assert_health_result(
        result: HealthCheckResult,
        expected_status: HealthStatus,
        expected_name: str = None,
        expected_type: CheckType = None
    ):
        """Assert health check result properties."""
        assert result.status == expected_status
        
        if expected_name:
            assert result.name == expected_name
        
        if expected_type:
            assert result.check_type == expected_type
        
        assert isinstance(result.duration_ms, float)
        assert result.duration_ms >= 0
        assert isinstance(result.timestamp, datetime)
    
    @staticmethod
    def assert_health_summary(
        summary: HealthCheckSummary,
        expected_status: HealthStatus,
        expected_total: int,
        expected_healthy: int = None,
        expected_unhealthy: int = None,
        expected_degraded: int = None
    ):
        """Assert health check summary properties."""
        assert summary.overall_status == expected_status
        assert summary.total_checks == expected_total
        
        if expected_healthy is not None:
            assert summary.healthy_checks == expected_healthy
        
        if expected_unhealthy is not None:
            assert summary.unhealthy_checks == expected_unhealthy
        
        if expected_degraded is not None:
            assert summary.degraded_checks == expected_degraded
        
        assert isinstance(summary.total_duration_ms, float)
        assert summary.total_duration_ms >= 0
        assert isinstance(summary.timestamp, datetime)
        assert len(summary.checks) == expected_total


class PerformanceTestHelper:
    """Helper for performance testing of health checks."""
    
    @staticmethod
    def create_many_checks(count: int, base_name: str = "check") -> List[MockHealthCheck]:
        """Create many health checks for performance testing."""
        checks = []
        for i in range(count):
            # Mix of different statuses and durations
            if i % 10 == 0:
                status = HealthStatus.UNHEALTHY
            elif i % 5 == 0:
                status = HealthStatus.DEGRADED
            else:
                status = HealthStatus.HEALTHY
            
            duration_ms = 10.0 + (i % 50)  # Varying durations
            
            check = MockHealthCheck(
                name=f"{base_name}_{i}",
                result_status=status,
                check_duration_ms=duration_ms
            )
            checks.append(check)
        
        return checks
    
    @staticmethod
    async def measure_execution_time(
        checks: List[HealthCheck],
        execution_mode: HealthCheckMode = HealthCheckMode.PARALLEL
    ) -> Dict[str, float]:
        """Measure health check execution performance."""
        start_time = time.time()
        
        if execution_mode == HealthCheckMode.PARALLEL:
            tasks = [check.execute() for check in checks]
            results = await asyncio.gather(*tasks)
        else:  # Sequential
            results = []
            for check in checks:
                result = await check.execute()
                results.append(result)
        
        end_time = time.time()
        
        return {
            'total_time_seconds': end_time - start_time,
            'average_time_per_check': (end_time - start_time) / len(checks),
            'checks_per_second': len(checks) / (end_time - start_time),
            'successful_checks': sum(1 for r in results if r.status == HealthStatus.HEALTHY),
            'failed_checks': sum(1 for r in results if r.status in [HealthStatus.UNHEALTHY, HealthStatus.ERROR])
        }


class IntegrationTestHelper:
    """Helper for integration testing scenarios."""
    
    @staticmethod
    def create_realistic_scenario() -> Dict[str, Any]:
        """Create a realistic health check scenario."""
        database = MockDatabase()
        cache = MockCache()
        app = MockApplication()
        external_service = MockExternalService()
        
        return {
            'database': database,
            'cache': cache,
            'application': app,
            'external_service': external_service,
            'file_system': MockFileSystem()
        }
    
    @staticmethod
    def simulate_partial_failure(scenario: Dict[str, Any]):
        """Simulate a partial system failure."""
        # Database connection issues
        scenario['database'].set_connected(False)
        
        # Cache degradation
        scenario['cache'].set_set_get_works(False)
        
        # External service timeout
        scenario['external_service'].set_response_delay(10.0)
    
    @staticmethod
    def simulate_full_failure(scenario: Dict[str, Any]):
        """Simulate a full system failure."""
        scenario['database'].set_connected(False)
        scenario['cache'].set_ping_works(False)
        scenario['application'].set_alive(False)
        scenario['external_service'].set_reachable(False)
    
    @staticmethod
    def simulate_recovery(scenario: Dict[str, Any]):
        """Simulate system recovery."""
        scenario['database'].set_connected(True)
        scenario['database'].set_query_works(True)
        scenario['cache'].set_ping_works(True)
        scenario['cache'].set_set_get_works(True)
        scenario['application'].set_alive(True)
        scenario['application'].set_ready(True)
        scenario['external_service'].set_reachable(True)
        scenario['external_service'].set_response_delay(0.0)


class ConcurrencyTestHelper:
    """Helper for concurrency and threading tests."""
    
    @staticmethod
    async def concurrent_health_checks(
        shield,
        request_count: int,
        endpoint: str = "/health"
    ) -> List[Dict[str, Any]]:
        """Simulate concurrent health check requests."""
        requests = [MockRequest(path=endpoint) for _ in range(request_count)]
        
        # Execute requests concurrently
        tasks = [shield._shield_function(request) for request in requests]
        responses = await asyncio.gather(*tasks)
        
        # Parse responses
        results = []
        for response in responses:
            if response:
                import json
                content = json.loads(response.body)
                results.append({
                    'status_code': response.status_code,
                    'content': content,
                    'response_time': time.time()  # Simplified timing
                })
            else:
                results.append({'status_code': None, 'content': None})
        
        return results
    
    @staticmethod
    def create_load_test_scenario(
        base_checks: List[HealthCheck],
        load_multiplier: int = 10
    ) -> List[HealthCheck]:
        """Create a load testing scenario with many checks."""
        load_checks = []
        
        for i in range(load_multiplier):
            for base_check in base_checks:
                # Create variations of the base checks
                if isinstance(base_check, MockHealthCheck):
                    new_check = MockHealthCheck(
                        name=f"{base_check.name}_{i}",
                        check_type=base_check.check_type,
                        result_status=base_check.result_status,
                        check_duration_ms=base_check.check_duration_ms
                    )
                    load_checks.append(new_check)
        
        return load_checks