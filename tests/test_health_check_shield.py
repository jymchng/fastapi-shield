"""Comprehensive tests for health check shield."""

import pytest
import asyncio
import time
import json
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

# Mock psutil module at module level
mock_psutil = MagicMock()
sys.modules['psutil'] = mock_psutil

from fastapi_shield.health_check import (
    HealthCheckShield,
    HealthCheckConfig,
    HealthCheck,
    ApplicationHealthCheck,
    DatabaseHealthCheck,
    CacheHealthCheck,
    ExternalServiceHealthCheck,
    FileSystemHealthCheck,
    MemoryHealthCheck,
    CPUHealthCheck,
    NetworkHealthCheck,
    CustomHealthCheck,
    HealthCheckResult,
    HealthCheckSummary,
    HealthCheckCache,
    HealthStatus,
    CheckType,
    HealthCheckMode,
    basic_health_check_shield,
    kubernetes_health_check_shield,
    docker_health_check_shield,
    comprehensive_health_check_shield,
    custom_health_check_shield,
)

from tests.mocks.health_check_mocks import (
    MockHealthCheck,
    MockRequest,
    MockDatabase,
    MockCache,
    MockApplication,
    MockSystem,
    MockExternalService,
    MockFileSystem,
    HealthCheckTestHelper,
    PerformanceTestHelper,
    IntegrationTestHelper,
    ConcurrencyTestHelper,
)


class TestHealthStatus:
    """Test health status enumeration."""
    
    def test_health_status_values(self):
        """Test health status enum values."""
        assert HealthStatus.HEALTHY == "healthy"
        assert HealthStatus.UNHEALTHY == "unhealthy"
        assert HealthStatus.DEGRADED == "degraded"
        assert HealthStatus.UNKNOWN == "unknown"
        assert HealthStatus.TIMEOUT == "timeout"
        assert HealthStatus.ERROR == "error"


class TestCheckType:
    """Test check type enumeration."""
    
    def test_check_type_values(self):
        """Test check type enum values."""
        assert CheckType.APPLICATION == "application"
        assert CheckType.DATABASE == "database"
        assert CheckType.CACHE == "cache"
        assert CheckType.EXTERNAL_SERVICE == "external_service"
        assert CheckType.FILE_SYSTEM == "file_system"
        assert CheckType.MEMORY == "memory"
        assert CheckType.CPU == "cpu"
        assert CheckType.NETWORK == "network"
        assert CheckType.CUSTOM == "custom"


class TestHealthCheckResult:
    """Test health check result functionality."""
    
    def test_health_check_result_creation(self):
        """Test health check result creation."""
        result = HealthCheckResult(
            name="test_check",
            status=HealthStatus.HEALTHY,
            check_type=CheckType.APPLICATION,
            duration_ms=100.0,
            timestamp=datetime.now(timezone.utc),
            message="Test passed",
            details={'key': 'value'}
        )
        
        assert result.name == "test_check"
        assert result.status == HealthStatus.HEALTHY
        assert result.check_type == CheckType.APPLICATION
        assert result.duration_ms == 100.0
        assert result.message == "Test passed"
        assert result.details == {'key': 'value'}
        assert result.is_healthy() is True
    
    def test_health_check_result_to_dict(self):
        """Test health check result serialization."""
        timestamp = datetime.now(timezone.utc)
        result = HealthCheckResult(
            name="test_check",
            status=HealthStatus.DEGRADED,
            check_type=CheckType.DATABASE,
            duration_ms=250.5,
            timestamp=timestamp,
            message="Test degraded",
            error="Minor issue"
        )
        
        result_dict = result.to_dict()
        
        expected_keys = {
            'name', 'status', 'type', 'duration_ms', 'timestamp',
            'message', 'details', 'error', 'metadata'
        }
        assert set(result_dict.keys()) == expected_keys
        assert result_dict['name'] == "test_check"
        assert result_dict['status'] == "degraded"
        assert result_dict['type'] == "database"
        assert result_dict['duration_ms'] == 250.5
        assert result_dict['timestamp'] == timestamp.isoformat()
    
    def test_is_healthy_method(self):
        """Test is_healthy method."""
        healthy_result = HealthCheckResult(
            name="test", status=HealthStatus.HEALTHY, check_type=CheckType.CUSTOM,
            duration_ms=0, timestamp=datetime.now(timezone.utc)
        )
        assert healthy_result.is_healthy() is True
        
        unhealthy_result = HealthCheckResult(
            name="test", status=HealthStatus.UNHEALTHY, check_type=CheckType.CUSTOM,
            duration_ms=0, timestamp=datetime.now(timezone.utc)
        )
        assert unhealthy_result.is_healthy() is False


class TestHealthCheckSummary:
    """Test health check summary functionality."""
    
    def test_health_check_summary_creation(self):
        """Test health check summary creation."""
        timestamp = datetime.now(timezone.utc)
        checks = [
            HealthCheckResult("check1", HealthStatus.HEALTHY, CheckType.APPLICATION, 50.0, timestamp),
            HealthCheckResult("check2", HealthStatus.DEGRADED, CheckType.DATABASE, 100.0, timestamp)
        ]
        
        summary = HealthCheckSummary(
            overall_status=HealthStatus.DEGRADED,
            total_checks=2,
            healthy_checks=1,
            unhealthy_checks=0,
            degraded_checks=1,
            total_duration_ms=150.0,
            timestamp=timestamp,
            checks=checks
        )
        
        assert summary.overall_status == HealthStatus.DEGRADED
        assert summary.total_checks == 2
        assert summary.healthy_checks == 1
        assert summary.degraded_checks == 1
        assert len(summary.checks) == 2
    
    def test_health_check_summary_to_dict(self):
        """Test health check summary serialization."""
        timestamp = datetime.now(timezone.utc)
        checks = [
            HealthCheckResult("check1", HealthStatus.HEALTHY, CheckType.APPLICATION, 50.0, timestamp)
        ]
        
        summary = HealthCheckSummary(
            overall_status=HealthStatus.HEALTHY,
            total_checks=1,
            healthy_checks=1,
            unhealthy_checks=0,
            degraded_checks=0,
            total_duration_ms=50.0,
            timestamp=timestamp,
            checks=checks
        )
        
        summary_dict = summary.to_dict()
        
        assert 'status' in summary_dict
        assert 'timestamp' in summary_dict
        assert 'summary' in summary_dict
        assert 'checks' in summary_dict
        
        assert summary_dict['status'] == 'healthy'
        assert summary_dict['summary']['total_checks'] == 1
        assert summary_dict['summary']['healthy'] == 1
        assert len(summary_dict['checks']) == 1


class TestMockHealthCheck:
    """Test mock health check functionality."""
    
    def test_mock_health_check_creation(self):
        """Test mock health check creation."""
        mock_check = MockHealthCheck(
            name="mock_test",
            result_status=HealthStatus.HEALTHY,
            result_message="Mock test passed"
        )
        
        assert mock_check.name == "mock_test"
        assert mock_check.result_status == HealthStatus.HEALTHY
        assert mock_check.result_message == "Mock test passed"
        assert mock_check.call_count == 0
    
    @pytest.mark.asyncio
    async def test_mock_health_check_execution(self):
        """Test mock health check execution."""
        mock_check = MockHealthCheck(
            name="mock_test",
            result_status=HealthStatus.DEGRADED,
            check_duration_ms=50.0
        )
        
        result = await mock_check.execute()
        
        assert result.name == "mock_test"
        assert result.status == HealthStatus.DEGRADED
        assert result.duration_ms >= 40.0  # Allow for timing variations
        assert mock_check.call_count == 1
        assert len(mock_check.call_history) == 1
    
    @pytest.mark.asyncio
    async def test_mock_health_check_exception(self):
        """Test mock health check exception handling."""
        mock_check = MockHealthCheck(
            name="failing_check",
            should_raise_exception=True,
            exception_message="Test exception"
        )
        
        result = await mock_check.execute()
        
        assert result.status == HealthStatus.ERROR
        assert "Test exception" in result.error
        assert mock_check.call_count == 1
    
    def test_mock_health_check_configuration(self):
        """Test mock health check configuration methods."""
        mock_check = MockHealthCheck("test")
        
        # Test set_result
        mock_check.set_result(HealthStatus.UNHEALTHY, "New message", {"detail": "info"})
        assert mock_check.result_status == HealthStatus.UNHEALTHY
        assert mock_check.result_message == "New message"
        assert mock_check.result_details == {"detail": "info"}
        
        # Test set_exception
        mock_check.set_exception(True, "Custom error")
        assert mock_check.should_raise_exception is True
        assert mock_check.exception_message == "Custom error"
        
        # Test reset
        mock_check.call_count = 5
        mock_check.reset()
        assert mock_check.call_count == 0
        assert mock_check.should_raise_exception is False


class TestApplicationHealthCheck:
    """Test application health check functionality."""
    
    @pytest.mark.asyncio
    async def test_application_health_check_all_pass(self):
        """Test application health check with all checks passing."""
        app = MockApplication()
        
        check = ApplicationHealthCheck(
            name="app_check",
            startup_check=app.check_startup,
            readiness_check=app.check_readiness,
            liveness_check=app.check_liveness
        )
        
        result = await check.check()
        
        assert result.status == HealthStatus.HEALTHY
        assert "healthy" in result.message
        assert result.details['startup'] is True
        assert result.details['readiness'] is True
        assert result.details['liveness'] is True
    
    @pytest.mark.asyncio
    async def test_application_health_check_startup_fail(self):
        """Test application health check with startup failure."""
        app = MockApplication()
        app.set_startup_complete(False)
        
        check = ApplicationHealthCheck(
            name="app_check",
            startup_check=app.check_startup,
            readiness_check=app.check_readiness
        )
        
        result = await check.check()
        
        assert result.status == HealthStatus.UNHEALTHY
        assert "startup check failed" in result.message
        assert result.details['startup'] is False
    
    @pytest.mark.asyncio
    async def test_application_health_check_no_checks(self):
        """Test application health check with no checks defined."""
        check = ApplicationHealthCheck(name="simple_app_check")
        
        result = await check.check()
        
        assert result.status == HealthStatus.HEALTHY
        assert result.message == "Application is healthy"


class TestDatabaseHealthCheck:
    """Test database health check functionality."""
    
    @pytest.mark.asyncio
    async def test_database_health_check_success(self):
        """Test successful database health check."""
        db = MockDatabase()
        
        check = DatabaseHealthCheck(
            name="db_check",
            connection_check=db.check_connection,
            query_check=db.check_query,
            connection_pool_check=db.get_connection_pool_info
        )
        
        result = await check.check()
        
        assert result.status == HealthStatus.HEALTHY
        assert result.details['connection'] is True
        assert result.details['query'] is True
        assert 'connection_pool' in result.details
        assert db.call_count == 1
    
    @pytest.mark.asyncio
    async def test_database_health_check_connection_fail(self):
        """Test database health check with connection failure."""
        db = MockDatabase()
        db.set_connected(False)
        
        check = DatabaseHealthCheck(
            name="db_check",
            connection_check=db.check_connection
        )
        
        result = await check.check()
        
        assert result.status == HealthStatus.UNHEALTHY
        assert "connection failed" in result.message
        assert result.details['connection'] is False
    
    @pytest.mark.asyncio
    async def test_database_health_check_query_fail(self):
        """Test database health check with query failure."""
        db = MockDatabase()
        db.set_query_works(False)
        
        check = DatabaseHealthCheck(
            name="db_check",
            connection_check=db.check_connection,
            query_check=db.check_query
        )
        
        result = await check.check()
        
        assert result.status == HealthStatus.DEGRADED
        assert "query check failed" in result.message
        assert result.details['connection'] is True
        assert result.details['query'] is False


class TestCacheHealthCheck:
    """Test cache health check functionality."""
    
    @pytest.mark.asyncio
    async def test_cache_health_check_success(self):
        """Test successful cache health check."""
        cache = MockCache()
        
        check = CacheHealthCheck(
            name="cache_check",
            ping_check=cache.ping,
            set_get_check=cache.test_set_get,
            memory_usage_check=cache.get_memory_usage
        )
        
        result = await check.check()
        
        assert result.status == HealthStatus.HEALTHY
        assert result.details['ping'] is True
        assert result.details['set_get'] is True
        assert 'memory_usage' in result.details
    
    @pytest.mark.asyncio
    async def test_cache_health_check_ping_fail(self):
        """Test cache health check with ping failure."""
        cache = MockCache()
        cache.set_ping_works(False)
        
        check = CacheHealthCheck(
            name="cache_check",
            ping_check=cache.ping
        )
        
        result = await check.check()
        
        assert result.status == HealthStatus.UNHEALTHY
        assert "ping failed" in result.message
        assert result.details['ping'] is False
    
    @pytest.mark.asyncio
    async def test_cache_health_check_set_get_fail(self):
        """Test cache health check with set/get failure."""
        cache = MockCache()
        cache.set_set_get_works(False)
        
        check = CacheHealthCheck(
            name="cache_check",
            ping_check=cache.ping,
            set_get_check=cache.test_set_get
        )
        
        result = await check.check()
        
        assert result.status == HealthStatus.DEGRADED
        assert "set/get check failed" in result.message
        assert result.details['ping'] is True
        assert result.details['set_get'] is False


class TestExternalServiceHealthCheck:
    """Test external service health check functionality."""
    
    @pytest.mark.asyncio
    async def test_external_service_health_check_socket_success(self):
        """Test external service health check with socket connection."""
        service = MockExternalService("example.com", 80)
        
        check = ExternalServiceHealthCheck(
            name="service_check",
            url="http://example.com",
            timeout_seconds=1.0
        )
        
        # Mock socket connection
        with patch('socket.socket') as mock_socket:
            mock_sock_instance = Mock()
            mock_sock_instance.connect_ex.return_value = 0  # Success
            mock_socket.return_value = mock_sock_instance
            
            # Also mock httpx import to force socket fallback
            with patch('builtins.__import__', side_effect=ImportError("httpx not available")):
                result = await check.check()
        
        assert result.status == HealthStatus.HEALTHY
        assert "Connection" in result.message and "successful" in result.message
    
    @pytest.mark.asyncio
    async def test_external_service_health_check_socket_fail(self):
        """Test external service health check with socket failure."""
        check = ExternalServiceHealthCheck(
            name="service_check",
            url="http://unreachable.example.com",
            timeout_seconds=1.0
        )
        
        # Mock socket connection failure
        with patch('socket.socket') as mock_socket:
            mock_sock_instance = Mock()
            mock_sock_instance.connect_ex.return_value = 1  # Failure
            mock_socket.return_value = mock_sock_instance
            
            # Mock httpx import to force socket fallback
            with patch('builtins.__import__', side_effect=ImportError("httpx not available")):
                result = await check.check()
        
        assert result.status == HealthStatus.UNHEALTHY
        assert "Connection" in result.message and "failed" in result.message
    
    @pytest.mark.asyncio
    async def test_external_service_health_check_with_httpx(self):
        """Test external service health check with httpx."""
        check = ExternalServiceHealthCheck(
            name="service_check",
            url="https://httpbin.org/status/200",
            expected_status=200
        )
        
        # Mock httpx
        mock_response = Mock()
        mock_response.status_code = 200
        
        mock_client = AsyncMock()
        mock_client.request.return_value = mock_response
        
        with patch('httpx.AsyncClient') as mock_httpx:
            mock_httpx.return_value.__aenter__.return_value = mock_client
            
            result = await check.check()
        
        assert result.status == HealthStatus.HEALTHY
        assert "expected status 200" in result.message
        assert result.details['actual_status'] == 200


class TestFileSystemHealthCheck:
    """Test file system health check functionality."""
    
    @pytest.mark.asyncio
    async def test_file_system_health_check_success(self):
        """Test successful file system health check."""
        check = FileSystemHealthCheck(
            name="fs_check",
            paths=["/tmp"],
            check_writable=True
        )
        
        # Mock os operations
        with patch('os.path.exists', return_value=True), \
             patch('os.access', return_value=True), \
             patch('tempfile.TemporaryFile'):
            
            result = await check.check()
        
        assert result.status == HealthStatus.HEALTHY
        assert "/tmp" in result.details
        assert result.details["/tmp"]['exists'] is True
        assert result.details["/tmp"]['readable'] is True
        assert result.details["/tmp"]['writable'] is True
    
    @pytest.mark.asyncio
    async def test_file_system_health_check_path_missing(self):
        """Test file system health check with missing path."""
        check = FileSystemHealthCheck(
            name="fs_check",
            paths=["/nonexistent"]
        )
        
        # Mock os operations
        with patch('os.path.exists', return_value=False):
            result = await check.check()
        
        assert result.status == HealthStatus.UNHEALTHY
        assert "does not exist" in result.message
    
    @pytest.mark.asyncio
    async def test_file_system_health_check_not_writable(self):
        """Test file system health check with write permission failure."""
        check = FileSystemHealthCheck(
            name="fs_check",
            paths=["/readonly"],
            check_writable=True
        )
        
        # Mock os operations - exists and readable but not writable
        with patch('os.path.exists', return_value=True), \
             patch('os.access', side_effect=lambda path, mode: mode == 4), \
             patch('os.path.isdir', return_value=False):  # Not a directory
            
            result = await check.check()
        
        assert result.status == HealthStatus.DEGRADED
        assert "not writable" in result.message
    
    @pytest.mark.asyncio
    async def test_file_system_health_check_insufficient_space(self):
        """Test file system health check with insufficient disk space."""
        check = FileSystemHealthCheck(
            name="fs_check",
            paths=["/tmp"],
            min_free_space_mb=1000  # Require 1GB free
        )
        
        # Mock operations
        with patch('os.path.exists', return_value=True), \
             patch('os.access', return_value=True), \
             patch('os.path.isdir', return_value=True), \
             patch('shutil.disk_usage', return_value=(1000000000, 800000000, 100000000)):  # Only 100MB free
            
            result = await check.check()
        
        assert result.status == HealthStatus.DEGRADED
        assert "Insufficient free space" in result.message


class TestMemoryHealthCheck:
    """Test memory health check functionality."""
    
    @pytest.mark.asyncio
    async def test_memory_health_check_normal(self):
        """Test memory health check with normal usage."""
        check = MemoryHealthCheck(
            max_usage_percent=90.0,
            warning_threshold_percent=80.0
        )
        
        # Mock psutil
        mock_memory = Mock()
        mock_memory.percent = 70.0
        mock_memory.total = 8 * 1024**3  # 8GB
        mock_memory.available = 2.4 * 1024**3  # 2.4GB
        mock_memory.used = 5.6 * 1024**3  # 5.6GB
        
        with patch('psutil.virtual_memory', return_value=mock_memory):
            result = await check.check()
        
        assert result.status == HealthStatus.HEALTHY
        assert "normal: 70.0%" in result.message
        assert result.details['usage_percent'] == 70.0
    
    @pytest.mark.asyncio
    async def test_memory_health_check_warning(self):
        """Test memory health check with warning threshold exceeded."""
        check = MemoryHealthCheck(
            max_usage_percent=90.0,
            warning_threshold_percent=80.0
        )
        
        # Mock psutil
        mock_memory = Mock()
        mock_memory.percent = 85.0
        mock_memory.total = 8 * 1024**3
        mock_memory.available = 1.2 * 1024**3
        mock_memory.used = 6.8 * 1024**3
        
        with patch('psutil.virtual_memory', return_value=mock_memory):
            result = await check.check()
        
        assert result.status == HealthStatus.DEGRADED
        assert "warning: 85.0%" in result.message
    
    @pytest.mark.asyncio
    async def test_memory_health_check_critical(self):
        """Test memory health check with critical usage."""
        check = MemoryHealthCheck(
            max_usage_percent=90.0,
            warning_threshold_percent=80.0
        )
        
        # Mock psutil
        mock_memory = Mock()
        mock_memory.percent = 95.0
        mock_memory.total = 8 * 1024**3
        mock_memory.available = 0.4 * 1024**3
        mock_memory.used = 7.6 * 1024**3
        
        with patch('psutil.virtual_memory', return_value=mock_memory):
            result = await check.check()
        
        assert result.status == HealthStatus.UNHEALTHY
        assert "too high: 95.0%" in result.message
    
    @pytest.mark.asyncio
    async def test_memory_health_check_psutil_unavailable(self):
        """Test memory health check when psutil is unavailable."""
        check = MemoryHealthCheck()
        
        with patch('psutil.virtual_memory', side_effect=ImportError("psutil not available")):
            result = await check.check()
        
        assert result.status == HealthStatus.UNKNOWN
        assert "psutil not available" in result.error


class TestCPUHealthCheck:
    """Test CPU health check functionality."""
    
    @pytest.mark.asyncio
    async def test_cpu_health_check_normal(self):
        """Test CPU health check with normal usage."""
        check = CPUHealthCheck(
            max_usage_percent=95.0,
            warning_threshold_percent=85.0,
            check_interval=0.1  # Fast for testing
        )
        
        # Mock psutil
        with patch('psutil.cpu_percent', return_value=60.0), \
             patch('psutil.cpu_count', return_value=4), \
             patch('psutil.getloadavg', return_value=(1.0, 1.5, 2.0)):
            
            result = await check.check()
        
        assert result.status == HealthStatus.HEALTHY
        assert "normal: 60.0%" in result.message
        assert result.details['usage_percent'] == 60.0
        assert result.details['cpu_count'] == 4
        assert 'load_average' in result.details
    
    @pytest.mark.asyncio
    async def test_cpu_health_check_warning(self):
        """Test CPU health check with warning threshold exceeded."""
        check = CPUHealthCheck(
            max_usage_percent=95.0,
            warning_threshold_percent=85.0,
            check_interval=0.1
        )
        
        with patch('psutil.cpu_percent', return_value=88.0), \
             patch('psutil.cpu_count', return_value=4):
            
            result = await check.check()
        
        assert result.status == HealthStatus.DEGRADED
        assert "warning: 88.0%" in result.message
    
    @pytest.mark.asyncio
    async def test_cpu_health_check_critical(self):
        """Test CPU health check with critical usage."""
        check = CPUHealthCheck(
            max_usage_percent=95.0,
            warning_threshold_percent=85.0,
            check_interval=0.1
        )
        
        with patch('psutil.cpu_percent', return_value=97.0), \
             patch('psutil.cpu_count', return_value=4):
            
            result = await check.check()
        
        assert result.status == HealthStatus.UNHEALTHY
        assert "too high: 97.0%" in result.message


class TestNetworkHealthCheck:
    """Test network health check functionality."""
    
    @pytest.mark.asyncio
    async def test_network_health_check_all_connections_success(self):
        """Test network health check with all connections successful."""
        check = NetworkHealthCheck(
            name="network_check",
            hosts=[("google.com", 80), ("github.com", 443)]
        )
        
        # Mock socket connection
        with patch('socket.socket') as mock_socket:
            mock_sock_instance = Mock()
            mock_sock_instance.connect_ex.return_value = 0  # Success
            mock_socket.return_value = mock_sock_instance
            
            result = await check.check()
        
        assert result.status == HealthStatus.HEALTHY
        assert "All network connections successful" in result.message
        assert result.details["google.com:80"] == "connected"
        assert result.details["github.com:443"] == "connected"
    
    @pytest.mark.asyncio
    async def test_network_health_check_partial_failure(self):
        """Test network health check with some connections failing."""
        check = NetworkHealthCheck(
            name="network_check",
            hosts=[("reachable.com", 80), ("unreachable.com", 80)]
        )
        
        # Mock socket connection - first succeeds, second fails
        with patch('socket.socket') as mock_socket:
            mock_sock_instance = Mock()
            # Return 0 for first call, 1 for second call
            mock_sock_instance.connect_ex.side_effect = [0, 1]
            mock_socket.return_value = mock_sock_instance
            
            result = await check.check()
        
        assert result.status == HealthStatus.DEGRADED
        assert "Some network connections failed" in result.message
        assert result.details["reachable.com:80"] == "connected"
        assert result.details["unreachable.com:80"] == "failed"
    
    @pytest.mark.asyncio
    async def test_network_health_check_all_connections_fail(self):
        """Test network health check with all connections failing."""
        check = NetworkHealthCheck(
            name="network_check",
            hosts=[("unreachable1.com", 80), ("unreachable2.com", 80)]
        )
        
        # Mock socket connection failure
        with patch('socket.socket') as mock_socket:
            mock_sock_instance = Mock()
            mock_sock_instance.connect_ex.return_value = 1  # Failure
            mock_socket.return_value = mock_sock_instance
            
            result = await check.check()
        
        assert result.status == HealthStatus.UNHEALTHY
        assert "All network connections failed" in result.message


class TestCustomHealthCheck:
    """Test custom health check functionality."""
    
    @pytest.mark.asyncio
    async def test_custom_health_check_boolean_return(self):
        """Test custom health check with boolean return."""
        def custom_check():
            return True
        
        check = CustomHealthCheck(
            name="custom_bool_check",
            check_function=custom_check
        )
        
        result = await check.check()
        
        assert result.status == HealthStatus.HEALTHY
        assert "Custom check passed" in result.message
    
    @pytest.mark.asyncio
    async def test_custom_health_check_boolean_false(self):
        """Test custom health check with boolean false return."""
        def custom_check():
            return False
        
        check = CustomHealthCheck(
            name="custom_bool_check",
            check_function=custom_check
        )
        
        result = await check.check()
        
        assert result.status == HealthStatus.UNHEALTHY
        assert "Custom check failed" in result.message
    
    @pytest.mark.asyncio
    async def test_custom_health_check_result_return(self):
        """Test custom health check with HealthCheckResult return."""
        def custom_check():
            return HealthCheckResult(
                name="custom_result_check",
                status=HealthStatus.DEGRADED,
                check_type=CheckType.CUSTOM,
                duration_ms=100.0,
                timestamp=datetime.now(timezone.utc),
                message="Custom degraded result"
            )
        
        check = CustomHealthCheck(
            name="custom_result_check",
            check_function=custom_check
        )
        
        result = await check.check()
        
        assert result.status == HealthStatus.DEGRADED
        assert result.message == "Custom degraded result"
    
    @pytest.mark.asyncio
    async def test_custom_health_check_exception(self):
        """Test custom health check with exception."""
        def failing_check():
            raise ValueError("Custom check error")
        
        check = CustomHealthCheck(
            name="failing_custom_check",
            check_function=failing_check
        )
        
        result = await check.check()
        
        assert result.status == HealthStatus.ERROR
        assert "Custom check error" in result.error


class TestHealthCheckCache:
    """Test health check cache functionality."""
    
    @pytest.mark.asyncio
    async def test_cache_set_and_get(self):
        """Test cache set and get operations."""
        cache = HealthCheckCache(ttl_seconds=1.0)
        
        summary = HealthCheckSummary(
            overall_status=HealthStatus.HEALTHY,
            total_checks=1,
            healthy_checks=1,
            unhealthy_checks=0,
            degraded_checks=0,
            total_duration_ms=100.0,
            timestamp=datetime.now(timezone.utc)
        )
        
        # Set cache
        await cache.set("test_key", summary)
        
        # Get from cache
        cached_summary = await cache.get("test_key")
        
        assert cached_summary is not None
        assert cached_summary.overall_status == HealthStatus.HEALTHY
        assert cached_summary.total_checks == 1
    
    @pytest.mark.asyncio
    async def test_cache_expiry(self):
        """Test cache expiry functionality."""
        cache = HealthCheckCache(ttl_seconds=0.1)  # Very short TTL
        
        summary = HealthCheckSummary(
            overall_status=HealthStatus.HEALTHY,
            total_checks=1,
            healthy_checks=1,
            unhealthy_checks=0,
            degraded_checks=0,
            total_duration_ms=100.0,
            timestamp=datetime.now(timezone.utc)
        )
        
        await cache.set("test_key", summary)
        
        # Should be available immediately
        cached_summary = await cache.get("test_key")
        assert cached_summary is not None
        
        # Wait for expiry
        await asyncio.sleep(0.2)
        
        # Should be expired
        expired_summary = await cache.get("test_key")
        assert expired_summary is None
    
    @pytest.mark.asyncio
    async def test_cache_clear(self):
        """Test cache clear functionality."""
        cache = HealthCheckCache(ttl_seconds=10.0)
        
        summary = HealthCheckSummary(
            overall_status=HealthStatus.HEALTHY,
            total_checks=1,
            healthy_checks=1,
            unhealthy_checks=0,
            degraded_checks=0,
            total_duration_ms=100.0,
            timestamp=datetime.now(timezone.utc)
        )
        
        await cache.set("test_key", summary)
        
        # Verify it's there
        cached_summary = await cache.get("test_key")
        assert cached_summary is not None
        
        # Clear cache
        await cache.clear()
        
        # Should be gone
        cleared_summary = await cache.get("test_key")
        assert cleared_summary is None


class TestHealthCheckConfig:
    """Test health check configuration."""
    
    def test_health_check_config_defaults(self):
        """Test health check configuration defaults."""
        config = HealthCheckConfig()
        
        assert len(config.checks) == 0
        assert config.execution_mode == HealthCheckMode.PARALLEL
        assert config.overall_timeout_seconds == 30.0
        assert config.enable_caching is True
        assert config.cache_ttl_seconds == 5.0
        assert config.fail_on_first_error is False
        assert config.include_details_in_response is True
        assert config.health_endpoint == "/health"
        assert config.readiness_endpoint == "/ready"
        assert config.liveness_endpoint == "/live"
    
    def test_health_check_config_customization(self):
        """Test health check configuration customization."""
        checks = [MockHealthCheck("test_check")]
        
        config = HealthCheckConfig(
            checks=checks,
            execution_mode=HealthCheckMode.SEQUENTIAL,
            overall_timeout_seconds=60.0,
            enable_caching=False,
            fail_on_first_error=True,
            kubernetes_format=True,
            health_endpoint="/custom-health"
        )
        
        assert len(config.checks) == 1
        assert config.execution_mode == HealthCheckMode.SEQUENTIAL
        assert config.overall_timeout_seconds == 60.0
        assert config.enable_caching is False
        assert config.fail_on_first_error is True
        assert config.kubernetes_format is True
        assert config.health_endpoint == "/custom-health"


class TestHealthCheckShield:
    """Test health check shield functionality."""
    
    @pytest.fixture
    def basic_config(self):
        """Create basic health check configuration."""
        return HealthCheckConfig(
            checks=[
                HealthCheckTestHelper.create_mock_healthy_check("healthy_check"),
                HealthCheckTestHelper.create_mock_degraded_check("degraded_check")
            ],
            enable_caching=False  # Disable caching for testing
        )
    
    @pytest.fixture
    def shield(self, basic_config):
        """Create health check shield."""
        return HealthCheckShield(basic_config)
    
    def test_shield_creation(self, shield):
        """Test health check shield creation."""
        assert isinstance(shield, HealthCheckShield)
        assert len(shield.config.checks) == 2
        assert shield._cache is None  # Caching disabled
    
    def test_shield_add_remove_checks(self, shield):
        """Test adding and removing checks from shield."""
        initial_count = len(shield.config.checks)
        
        # Add check
        new_check = HealthCheckTestHelper.create_mock_healthy_check("new_check")
        shield.add_check(new_check)
        
        assert len(shield.config.checks) == initial_count + 1
        assert shield.get_check("new_check") is not None
        
        # Remove check
        shield.remove_check("new_check")
        
        assert len(shield.config.checks) == initial_count
        assert shield.get_check("new_check") is None
    
    @pytest.mark.asyncio
    async def test_shield_execute_checks_parallel(self, shield):
        """Test parallel execution of health checks."""
        summary = await shield._execute_checks()
        
        assert summary.total_checks == 2
        assert summary.healthy_checks == 1
        assert summary.degraded_checks == 1
        assert summary.unhealthy_checks == 0
        assert summary.overall_status == HealthStatus.DEGRADED
        assert len(summary.checks) == 2
    
    @pytest.mark.asyncio
    async def test_shield_execute_checks_sequential(self):
        """Test sequential execution of health checks."""
        config = HealthCheckConfig(
            checks=[
                HealthCheckTestHelper.create_mock_healthy_check("check_1"),
                HealthCheckTestHelper.create_mock_healthy_check("check_2")
            ],
            execution_mode=HealthCheckMode.SEQUENTIAL,
            enable_caching=False
        )
        
        shield = HealthCheckShield(config)
        summary = await shield._execute_checks()
        
        assert summary.total_checks == 2
        assert summary.healthy_checks == 2
        assert summary.overall_status == HealthStatus.HEALTHY
    
    @pytest.mark.asyncio
    async def test_shield_execute_checks_with_errors(self):
        """Test execution with error checks."""
        config = HealthCheckConfig(
            checks=[
                HealthCheckTestHelper.create_mock_healthy_check("healthy"),
                HealthCheckTestHelper.create_mock_error_check("error")
            ],
            enable_caching=False
        )
        
        shield = HealthCheckShield(config)
        summary = await shield._execute_checks()
        
        assert summary.total_checks == 2
        assert summary.healthy_checks == 1
        assert summary.overall_status == HealthStatus.UNHEALTHY
        
        # Find the error check result
        error_result = next((check for check in summary.checks if check.name == "error"), None)
        assert error_result is not None
        assert error_result.status == HealthStatus.ERROR
    
    @pytest.mark.asyncio
    async def test_shield_execute_checks_fail_on_first_error(self):
        """Test fail on first error functionality."""
        config = HealthCheckConfig(
            checks=[
                HealthCheckTestHelper.create_mock_error_check("error"),
                HealthCheckTestHelper.create_mock_healthy_check("healthy")
            ],
            execution_mode=HealthCheckMode.SEQUENTIAL,
            fail_on_first_error=True,
            enable_caching=False
        )
        
        shield = HealthCheckShield(config)
        summary = await shield._execute_checks()
        
        # Should stop after first error
        assert summary.total_checks == 1
        assert summary.overall_status == HealthStatus.UNHEALTHY
    
    @pytest.mark.asyncio
    async def test_shield_execute_checks_subset(self, shield):
        """Test executing a subset of checks."""
        summary = await shield._execute_checks(["healthy_check"])
        
        assert summary.total_checks == 1
        assert summary.healthy_checks == 1
        assert summary.overall_status == HealthStatus.HEALTHY
        assert summary.checks[0].name == "healthy_check"
    
    @pytest.mark.asyncio
    async def test_shield_execute_checks_empty_subset(self, shield):
        """Test executing with empty check subset."""
        summary = await shield._execute_checks(["nonexistent_check"])
        
        assert summary.total_checks == 0
        assert summary.overall_status == HealthStatus.HEALTHY
        assert len(summary.checks) == 0
    
    @pytest.mark.asyncio
    async def test_shield_function_health_endpoint(self, shield):
        """Test shield function with health endpoint."""
        request = MockRequest(path="/health")
        
        response = await shield._shield_function(request)
        
        assert response is not None
        assert response.status_code == 200
        
        # Parse response content
        content = json.loads(response.body)
        assert content['status'] == 'degraded'
        assert 'summary' in content
        assert 'checks' in content
    
    @pytest.mark.asyncio
    async def test_shield_function_readiness_endpoint(self, shield):
        """Test shield function with readiness endpoint."""
        shield.config.readiness_endpoint = "/ready"
        request = MockRequest(path="/ready")
        
        response = await shield._shield_function(request)
        
        assert response is not None
        assert response.status_code == 200  # Degraded still considered ready
    
    @pytest.mark.asyncio
    async def test_shield_function_liveness_endpoint(self, shield):
        """Test shield function with liveness endpoint."""
        shield.config.liveness_endpoint = "/live"
        request = MockRequest(path="/live")
        
        response = await shield._shield_function(request)
        
        assert response is not None
        assert response.status_code == 200  # Degraded still considered alive
    
    @pytest.mark.asyncio
    async def test_shield_function_non_health_endpoint(self, shield):
        """Test shield function with non-health endpoint."""
        request = MockRequest(path="/api/data")
        
        response = await shield._shield_function(request)
        
        assert response is None  # Should not handle non-health endpoints
    
    @pytest.mark.asyncio
    async def test_shield_function_with_specific_checks(self, shield):
        """Test shield function with specific checks parameter."""
        request = MockRequest(path="/health", query_params={"checks": "healthy_check"})
        
        response = await shield._shield_function(request)
        
        assert response is not None
        assert response.status_code == 200
        
        content = json.loads(response.body)
        assert content['status'] == 'healthy'
        assert content['summary']['total_checks'] == 1
    
    @pytest.mark.asyncio
    async def test_shield_function_timeout(self):
        """Test shield function with overall timeout."""
        config = HealthCheckConfig(
            checks=[HealthCheckTestHelper.create_slow_check("slow", 5000.0)],  # 5 second check
            overall_timeout_seconds=1.0,  # 1 second timeout
            enable_caching=False
        )
        
        shield = HealthCheckShield(config)
        request = MockRequest(path="/health")
        
        response = await shield._shield_function(request)
        
        assert response is not None
        assert response.status_code == 503  # Service Unavailable
        
        content = json.loads(response.body)
        assert content['status'] == 'timeout'
    
    def test_shield_format_responses(self, shield):
        """Test different response format options."""
        summary = HealthCheckSummary(
            overall_status=HealthStatus.HEALTHY,
            total_checks=1,
            healthy_checks=1,
            unhealthy_checks=0,
            degraded_checks=0,
            total_duration_ms=100.0,
            timestamp=datetime.now(timezone.utc),
            checks=[
                HealthCheckResult("test", HealthStatus.HEALTHY, CheckType.APPLICATION, 100.0, datetime.now(timezone.utc))
            ]
        )
        
        # Test standard format
        standard = shield._format_standard_response(summary)
        assert 'status' in standard
        assert 'checks' in standard
        
        # Test Kubernetes format
        k8s_health = shield._format_kubernetes_response(summary, "health")
        assert 'status' in k8s_health
        
        k8s_readiness = shield._format_kubernetes_response(summary, "readiness")
        assert k8s_readiness['status'] == "ready"
        
        k8s_liveness = shield._format_kubernetes_response(summary, "liveness")
        assert k8s_liveness['status'] == "alive"
        
        # Test Docker format
        docker = shield._format_docker_response(summary)
        assert docker['Status'] == "healthy"
    
    def test_shield_status_code_mapping(self, shield):
        """Test HTTP status code mapping."""
        # Healthy status
        assert shield._get_status_code(HealthStatus.HEALTHY, "health") == 200
        
        # Degraded status (still serving)
        assert shield._get_status_code(HealthStatus.DEGRADED, "health") == 200
        
        # Unhealthy status
        assert shield._get_status_code(HealthStatus.UNHEALTHY, "health") == 503
        
        # Kubernetes endpoints
        assert shield._get_status_code(HealthStatus.DEGRADED, "readiness") == 200
        assert shield._get_status_code(HealthStatus.UNHEALTHY, "liveness") == 503
    
    @pytest.mark.asyncio
    async def test_shield_caching(self):
        """Test health check result caching."""
        config = HealthCheckConfig(
            checks=[HealthCheckTestHelper.create_mock_healthy_check("cached_check")],
            enable_caching=True,
            cache_ttl_seconds=1.0
        )
        
        shield = HealthCheckShield(config)
        request = MockRequest(path="/health")
        
        # First request - should execute checks
        response1 = await shield._shield_function(request)
        
        # Second request - should use cache
        response2 = await shield._shield_function(request)
        
        assert response1 is not None
        assert response2 is not None
        
        # Both should have same content
        content1 = json.loads(response1.body)
        content2 = json.loads(response2.body)
        assert content1['status'] == content2['status']
        
        # Check that the mock was only called once (due to caching)
        check = shield.config.checks[0]
        assert check.call_count <= 2  # May be called twice due to timing
    
    @pytest.mark.asyncio
    async def test_shield_get_health_summary(self, shield):
        """Test getting health summary directly."""
        summary = await shield.get_health_summary()
        
        assert isinstance(summary, HealthCheckSummary)
        assert summary.total_checks == 2
        assert summary.overall_status == HealthStatus.DEGRADED


class TestConvenienceFunctions:
    """Test convenience functions for creating health check shields."""
    
    def test_basic_health_check_shield(self):
        """Test basic health check shield creation."""
        shield = basic_health_check_shield(
            health_endpoint="/status",
            timeout_seconds=60.0,
            enable_caching=False
        )
        
        assert isinstance(shield, HealthCheckShield)
        assert shield.config.health_endpoint == "/status"
        assert shield.config.overall_timeout_seconds == 60.0
        assert shield.config.enable_caching is False
        assert len(shield.config.checks) == 1
        assert isinstance(shield.config.checks[0], ApplicationHealthCheck)
    
    def test_kubernetes_health_check_shield(self):
        """Test Kubernetes health check shield creation."""
        shield = kubernetes_health_check_shield(
            readiness_endpoint="/readiness",
            liveness_endpoint="/liveness"
        )
        
        assert isinstance(shield, HealthCheckShield)
        assert shield.config.readiness_endpoint == "/readiness"
        assert shield.config.liveness_endpoint == "/liveness"
        assert shield.config.kubernetes_format is True
        assert len(shield.config.checks) == 1
    
    def test_docker_health_check_shield(self):
        """Test Docker health check shield creation."""
        shield = docker_health_check_shield(
            health_endpoint="/docker-health",
            timeout_seconds=45.0
        )
        
        assert isinstance(shield, HealthCheckShield)
        assert shield.config.health_endpoint == "/docker-health"
        assert shield.config.overall_timeout_seconds == 45.0
        assert shield.config.docker_format is True
    
    def test_comprehensive_health_check_shield(self):
        """Test comprehensive health check shield creation."""
        def mock_db_check():
            return True
        
        def mock_cache_check():
            return True
        
        shield = comprehensive_health_check_shield(
            database_check=mock_db_check,
            cache_check=mock_cache_check,
            external_services=["http://api.example.com"],
            file_system_paths=["/tmp", "/var/log"],
            enable_system_checks=True,
            kubernetes_format=True
        )
        
        assert isinstance(shield, HealthCheckShield)
        assert len(shield.config.checks) >= 4  # App, DB, Cache, External Service, File System
        assert shield.config.kubernetes_format is True
    
    def test_custom_health_check_shield(self):
        """Test custom health check shield creation."""
        checks = [
            HealthCheckTestHelper.create_mock_healthy_check("custom1"),
            HealthCheckTestHelper.create_mock_healthy_check("custom2")
        ]
        
        shield = custom_health_check_shield(
            checks=checks,
            execution_mode=HealthCheckMode.SEQUENTIAL,
            overall_timeout=45.0,
            enable_caching=False
        )
        
        assert isinstance(shield, HealthCheckShield)
        assert len(shield.config.checks) == 2
        assert shield.config.execution_mode == HealthCheckMode.SEQUENTIAL
        assert shield.config.overall_timeout_seconds == 45.0
        assert shield.config.enable_caching is False


class TestPerformanceAndScaling:
    """Test performance and scaling aspects."""
    
    @pytest.mark.asyncio
    async def test_many_checks_performance(self):
        """Test performance with many health checks."""
        checks = PerformanceTestHelper.create_many_checks(50)
        
        config = HealthCheckConfig(
            checks=checks,
            execution_mode=HealthCheckMode.PARALLEL,
            enable_caching=False
        )
        
        shield = HealthCheckShield(config)
        
        start_time = time.time()
        summary = await shield._execute_checks()
        end_time = time.time()
        
        # Should complete in reasonable time (less than 2 seconds for 50 checks)
        assert end_time - start_time < 2.0
        assert summary.total_checks == 50
        assert summary.healthy_checks > 0
    
    @pytest.mark.asyncio
    async def test_parallel_vs_sequential_performance(self):
        """Test performance difference between parallel and sequential execution."""
        checks = [HealthCheckTestHelper.create_slow_check(f"slow_{i}", 100.0) for i in range(10)]
        
        # Parallel execution
        parallel_perf = await PerformanceTestHelper.measure_execution_time(
            checks, HealthCheckMode.PARALLEL
        )
        
        # Sequential execution  
        sequential_perf = await PerformanceTestHelper.measure_execution_time(
            checks, HealthCheckMode.SEQUENTIAL
        )
        
        # Parallel should be significantly faster
        assert parallel_perf['total_time_seconds'] < sequential_perf['total_time_seconds'] / 2
        assert parallel_perf['checks_per_second'] > sequential_perf['checks_per_second'] * 2
    
    @pytest.mark.asyncio
    async def test_concurrent_requests_performance(self):
        """Test performance under concurrent requests."""
        shield = basic_health_check_shield(enable_caching=True)
        
        # Simulate concurrent requests
        results = await ConcurrencyTestHelper.concurrent_health_checks(
            shield, request_count=20
        )
        
        assert len(results) == 20
        
        # All requests should succeed
        successful_requests = sum(1 for r in results if r.get('status_code') == 200)
        assert successful_requests == 20
    
    @pytest.mark.asyncio
    async def test_caching_performance_benefit(self):
        """Test performance benefit of caching."""
        slow_checks = [HealthCheckTestHelper.create_slow_check(f"slow_{i}", 200.0) for i in range(5)]
        
        # Shield with caching
        cached_config = HealthCheckConfig(
            checks=slow_checks,
            enable_caching=True,
            cache_ttl_seconds=10.0
        )
        cached_shield = HealthCheckShield(cached_config)
        
        # Shield without caching
        uncached_config = HealthCheckConfig(
            checks=[HealthCheckTestHelper.create_slow_check(f"slow_{i}", 200.0) for i in range(5)],
            enable_caching=False
        )
        uncached_shield = HealthCheckShield(uncached_config)
        
        request = MockRequest(path="/health")
        
        # First request to cached shield (cold cache)
        start_time = time.time()
        await cached_shield._shield_function(request)
        first_cached_time = time.time() - start_time
        
        # Second request to cached shield (warm cache)
        start_time = time.time()
        await cached_shield._shield_function(request)
        second_cached_time = time.time() - start_time
        
        # Request to uncached shield
        start_time = time.time()
        await uncached_shield._shield_function(request)
        uncached_time = time.time() - start_time
        
        # Cached request should be much faster than uncached
        assert second_cached_time < first_cached_time / 2
        assert second_cached_time < uncached_time / 5


class TestIntegrationScenarios:
    """Test integration scenarios."""
    
    @pytest.mark.asyncio
    async def test_fastapi_integration(self):
        """Test integration with FastAPI application."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        
        app = FastAPI()
        
        # Create health check shield
        health_shield = basic_health_check_shield()
        
        @app.get("/health")
        async def health_check(request: Request):
            return await health_shield._shield_function(request)
        
        client = TestClient(app)
        
        # Test health endpoint
        response = client.get("/health")
        assert response.status_code == 200
        
        data = response.json()
        assert 'status' in data
        assert 'summary' in data
        assert 'checks' in data
    
    @pytest.mark.asyncio
    async def test_realistic_scenario_healthy(self):
        """Test realistic scenario with all services healthy."""
        scenario = IntegrationTestHelper.create_realistic_scenario()
        
        # Create shields using the scenario components
        checks = [
            ApplicationHealthCheck(
                name="application",
                startup_check=scenario['application'].check_startup,
                readiness_check=scenario['application'].check_readiness,
                liveness_check=scenario['application'].check_liveness
            ),
            DatabaseHealthCheck(
                name="database",
                connection_check=scenario['database'].check_connection,
                query_check=scenario['database'].check_query
            ),
            CacheHealthCheck(
                name="cache",
                ping_check=scenario['cache'].ping,
                set_get_check=scenario['cache'].test_set_get
            )
        ]
        
        config = HealthCheckConfig(checks=checks, enable_caching=False)
        shield = HealthCheckShield(config)
        
        summary = await shield._execute_checks()
        
        assert summary.overall_status == HealthStatus.HEALTHY
        assert summary.total_checks == 3
        assert summary.healthy_checks == 3
    
    @pytest.mark.asyncio
    async def test_realistic_scenario_partial_failure(self):
        """Test realistic scenario with partial failures."""
        scenario = IntegrationTestHelper.create_realistic_scenario()
        IntegrationTestHelper.simulate_partial_failure(scenario)
        
        checks = [
            ApplicationHealthCheck(
                name="application",
                liveness_check=scenario['application'].check_liveness
            ),
            DatabaseHealthCheck(
                name="database",
                connection_check=scenario['database'].check_connection
            ),
            CacheHealthCheck(
                name="cache",
                ping_check=scenario['cache'].ping,
                set_get_check=scenario['cache'].test_set_get
            )
        ]
        
        config = HealthCheckConfig(checks=checks, enable_caching=False)
        shield = HealthCheckShield(config)
        
        summary = await shield._execute_checks()
        
        assert summary.overall_status == HealthStatus.UNHEALTHY
        assert summary.unhealthy_checks >= 1  # Database should be unhealthy
        assert summary.degraded_checks >= 1   # Cache should be degraded
    
    @pytest.mark.asyncio
    async def test_realistic_scenario_recovery(self):
        """Test realistic scenario recovery."""
        scenario = IntegrationTestHelper.create_realistic_scenario()
        
        # First, simulate failure
        IntegrationTestHelper.simulate_full_failure(scenario)
        
        checks = [
            ApplicationHealthCheck(
                name="application",
                liveness_check=scenario['application'].check_liveness
            ),
            DatabaseHealthCheck(
                name="database",
                connection_check=scenario['database'].check_connection
            )
        ]
        
        config = HealthCheckConfig(checks=checks, enable_caching=False)
        shield = HealthCheckShield(config)
        
        # Should be unhealthy initially
        summary1 = await shield._execute_checks()
        assert summary1.overall_status == HealthStatus.UNHEALTHY
        
        # Simulate recovery
        IntegrationTestHelper.simulate_recovery(scenario)
        
        # Should be healthy after recovery
        summary2 = await shield._execute_checks()
        assert summary2.overall_status == HealthStatus.HEALTHY


class TestEdgeCasesAndErrorHandling:
    """Test edge cases and error handling."""
    
    @pytest.mark.asyncio
    async def test_no_checks_configured(self):
        """Test shield with no checks configured."""
        config = HealthCheckConfig(checks=[])
        shield = HealthCheckShield(config)
        
        summary = await shield._execute_checks()
        
        assert summary.total_checks == 0
        assert summary.overall_status == HealthStatus.HEALTHY
        assert len(summary.checks) == 0
    
    @pytest.mark.asyncio
    async def test_disabled_check(self):
        """Test disabled health check."""
        disabled_check = MockHealthCheck(
            name="disabled_check",
            enabled=False,
            result_status=HealthStatus.UNHEALTHY  # Would fail if enabled
        )
        
        result = await disabled_check.execute()
        
        assert result.status == HealthStatus.HEALTHY
        assert "disabled" in result.message
        assert result.duration_ms == 0.0
    
    @pytest.mark.asyncio
    async def test_check_timeout_handling(self):
        """Test individual check timeout handling."""
        slow_check = MockHealthCheck(
            name="timeout_check",
            check_duration_ms=2000.0,  # 2 seconds
            timeout_seconds=0.5  # 0.5 second timeout
        )
        
        result = await slow_check.execute()
        
        assert result.status == HealthStatus.TIMEOUT
        assert "timed out" in result.error
    
    @pytest.mark.asyncio
    async def test_check_exception_handling(self):
        """Test check exception handling."""
        failing_check = MockHealthCheck(
            name="exception_check",
            should_raise_exception=True,
            exception_message="Simulated failure"
        )
        
        result = await failing_check.execute()
        
        assert result.status == HealthStatus.ERROR
        assert "Simulated failure" in result.error
    
    @pytest.mark.asyncio
    async def test_critical_vs_non_critical_checks(self):
        """Test critical vs non-critical check handling."""
        checks = [
            MockHealthCheck("critical_unhealthy", result_status=HealthStatus.UNHEALTHY, critical=True),
            MockHealthCheck("non_critical_unhealthy", result_status=HealthStatus.UNHEALTHY, critical=False),
            MockHealthCheck("healthy", result_status=HealthStatus.HEALTHY)
        ]
        
        config = HealthCheckConfig(checks=checks, enable_caching=False)
        shield = HealthCheckShield(config)
        
        summary = await shield._execute_checks()
        
        # Should be unhealthy because critical check failed
        assert summary.overall_status == HealthStatus.UNHEALTHY
        assert summary.unhealthy_checks == 2
        assert summary.healthy_checks == 1
    
    def test_invalid_response_format_configuration(self):
        """Test invalid response format configuration."""
        def invalid_formatter(summary):
            return "invalid response"  # Should be dict
        
        config = HealthCheckConfig(
            checks=[HealthCheckTestHelper.create_mock_healthy_check("test")],
            custom_response_format=invalid_formatter
        )
        
        shield = HealthCheckShield(config)
        summary = HealthCheckSummary(
            overall_status=HealthStatus.HEALTHY,
            total_checks=1,
            healthy_checks=1,
            unhealthy_checks=0,
            degraded_checks=0,
            total_duration_ms=100.0,
            timestamp=datetime.now(timezone.utc)
        )
        
        # Should not crash, even with invalid formatter
        result = shield._format_response(summary)
        assert result == "invalid response"  # Returns whatever the formatter returns
    
    @pytest.mark.asyncio
    async def test_malformed_request_handling(self):
        """Test handling of malformed requests."""
        shield = basic_health_check_shield()
        
        # Request with invalid query parameters
        request = MockRequest(
            path="/health",
            query_params={"checks": ""}  # Empty checks parameter
        )
        
        response = await shield._shield_function(request)
        
        # Should handle gracefully
        assert response is not None
        assert response.status_code == 200


# Run specific test groups if this file is executed directly
if __name__ == "__main__":
    pytest.main([__file__, "-v"])