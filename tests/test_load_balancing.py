"""Comprehensive tests for load balancing functionality.

This module contains extensive tests for all load balancing components including
algorithms, health monitoring, failover, sticky sessions, and performance metrics.
"""

import asyncio
import pytest
import time
import statistics
from typing import Dict, Any, List
from unittest.mock import Mock, patch, AsyncMock
from collections import defaultdict

from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
import httpx

from fastapi_shield.load_balancing import (
    # Core classes
    LoadBalancer,
    Backend,
    HealthChecker,
    SessionManager,
    LoadBalancingShield,
    
    # Configuration classes
    BackendMetrics,
    HealthCheckConfig,
    
    # Algorithms
    RoundRobinAlgorithm,
    WeightedRoundRobinAlgorithm,
    LeastConnectionsAlgorithm,
    RandomAlgorithm,
    IPHashAlgorithm,
    LeastResponseTimeAlgorithm,
    ResourceBasedAlgorithm,
    
    # Enums
    LoadBalancingAlgorithm,
    BackendStatus,
    HealthCheckType,
    StickySessionStrategy,
    
    # Convenience functions
    create_load_balancer,
    load_balancing_shield,
)

from tests.mocks.mock_backend_server import (
    MockBackendServer,
    MockBackendCluster,
    MockBackendConfig,
    mock_backend_cluster,
    get_free_port
)


class TestBackendMetrics:
    """Test BackendMetrics functionality."""
    
    def test_init_default(self):
        """Test default initialization."""
        metrics = BackendMetrics()
        
        assert metrics.total_requests == 0
        assert metrics.successful_requests == 0
        assert metrics.failed_requests == 0
        assert metrics.active_connections == 0
        assert metrics.average_response_time == 0.0
        assert metrics.response_times == []
        assert metrics.cpu_usage == 0.0
        assert metrics.memory_usage == 0.0
        assert metrics.consecutive_failures == 0
        assert metrics.consecutive_successes == 0
    
    def test_update_response_time(self):
        """Test response time updating."""
        metrics = BackendMetrics()
        
        # Add some response times
        metrics.update_response_time(100.0)
        assert len(metrics.response_times) == 1
        assert metrics.average_response_time == 100.0
        assert metrics.last_request_time > 0
        
        metrics.update_response_time(200.0)
        assert len(metrics.response_times) == 2
        assert metrics.average_response_time == 150.0
        
        # Test response time limit (should keep only 100 entries)
        for i in range(150):
            metrics.update_response_time(float(i))
        
        assert len(metrics.response_times) == 100
        assert metrics.average_response_time > 0
    
    def test_update_request_metrics_success(self):
        """Test successful request metrics update."""
        metrics = BackendMetrics()
        
        metrics.update_request_metrics(True, bytes_sent=1000, bytes_received=2000)
        
        assert metrics.total_requests == 1
        assert metrics.successful_requests == 1
        assert metrics.failed_requests == 0
        assert metrics.consecutive_successes == 1
        assert metrics.consecutive_failures == 0
        assert metrics.total_bytes_sent == 1000
        assert metrics.total_bytes_received == 2000
    
    def test_update_request_metrics_failure(self):
        """Test failed request metrics update."""
        metrics = BackendMetrics()
        
        metrics.update_request_metrics(False)
        
        assert metrics.total_requests == 1
        assert metrics.successful_requests == 0
        assert metrics.failed_requests == 1
        assert metrics.consecutive_successes == 0
        assert metrics.consecutive_failures == 1
    
    def test_success_rate(self):
        """Test success rate calculation."""
        metrics = BackendMetrics()
        
        # No requests - should return 1.0
        assert metrics.success_rate == 1.0
        
        # Add some successful requests
        for _ in range(7):
            metrics.update_request_metrics(True)
        
        # Add some failures
        for _ in range(3):
            metrics.update_request_metrics(False)
        
        assert abs(metrics.success_rate - 0.7) < 0.001
        assert abs(metrics.failure_rate - 0.3) < 0.001


class TestHealthCheckConfig:
    """Test HealthCheckConfig functionality."""
    
    def test_init_default(self):
        """Test default initialization."""
        config = HealthCheckConfig()
        
        assert config.check_type == HealthCheckType.HTTP
        assert config.method == "GET"
        assert config.timeout == 5.0
        assert config.interval == 30.0
        assert config.unhealthy_threshold == 3
        assert config.healthy_threshold == 2
        assert 200 in config.expected_status_codes
        assert config.custom_check is None
    
    def test_init_custom(self):
        """Test custom initialization."""
        def custom_check(backend):
            return True
        
        config = HealthCheckConfig(
            check_type=HealthCheckType.TCP,
            timeout=10.0,
            interval=60.0,
            unhealthy_threshold=5,
            healthy_threshold=3,
            custom_check=custom_check
        )
        
        assert config.check_type == HealthCheckType.TCP
        assert config.timeout == 10.0
        assert config.interval == 60.0
        assert config.unhealthy_threshold == 5
        assert config.healthy_threshold == 3
        assert config.custom_check == custom_check


class TestBackend:
    """Test Backend functionality."""
    
    def test_init_basic(self):
        """Test basic initialization."""
        backend = Backend(
            backend_id="test_backend",
            host="192.168.1.100",
            port=8080
        )
        
        assert backend.backend_id == "test_backend"
        assert backend.host == "192.168.1.100"
        assert backend.port == 8080
        assert backend.weight == 100
        assert backend.max_connections == 1000
        assert backend.status == BackendStatus.UNKNOWN
        assert isinstance(backend.metrics, BackendMetrics)
    
    def test_init_with_config(self):
        """Test initialization with configuration."""
        health_config = HealthCheckConfig(interval=60.0)
        tags = {"env": "prod", "region": "us-west"}
        metadata = {"version": "1.0.0"}
        
        backend = Backend(
            backend_id="configured_backend",
            host="api.example.com",
            port=443,
            weight=150,
            max_connections=500,
            health_check_config=health_config,
            tags=tags,
            metadata=metadata
        )
        
        assert backend.weight == 150
        assert backend.max_connections == 500
        assert backend.health_check_config.interval == 60.0
        assert backend.tags == tags
        assert backend.metadata == metadata
    
    def test_url_property(self):
        """Test URL property generation."""
        # HTTP backend
        backend_http = Backend("test", "example.com", 80)
        assert backend_http.url == "http://example.com"
        
        # HTTPS backend
        backend_https = Backend("test", "example.com", 443)
        assert backend_https.url == "https://example.com"
        
        # Custom port
        backend_custom = Backend("test", "example.com", 8080)
        assert backend_custom.url == "http://example.com:8080"
    
    def test_is_available(self):
        """Test backend availability check."""
        backend = Backend("test", "example.com")
        
        # Unknown status - should be unavailable
        backend.status = BackendStatus.UNKNOWN
        assert not backend.is_available
        
        # Healthy status - should be available
        backend.status = BackendStatus.HEALTHY
        assert backend.is_available
        
        # Degraded status - should be available
        backend.status = BackendStatus.DEGRADED
        assert backend.is_available
        
        # Unhealthy status - should be unavailable
        backend.status = BackendStatus.UNHEALTHY
        assert not backend.is_available
        
        # Healthy but at max connections - should be unavailable
        backend.status = BackendStatus.HEALTHY
        backend.metrics.active_connections = backend.max_connections
        assert not backend.is_available
    
    def test_circuit_breaker(self):
        """Test circuit breaker functionality."""
        backend = Backend("test", "example.com")
        backend.circuit_breaker_timeout = 1.0  # 1 second for testing
        
        # Open circuit breaker
        backend.circuit_breaker_open = True
        backend.circuit_breaker_opened_at = time.time()
        
        # Should be unavailable
        assert not backend.is_available
        
        # Wait for timeout
        time.sleep(1.1)
        
        # Should be available again (circuit breaker should close)
        backend.status = BackendStatus.HEALTHY
        assert backend.is_available
        assert not backend.circuit_breaker_open
    
    def test_load_score(self):
        """Test load score calculation."""
        backend = Backend("test", "example.com", max_connections=100)
        
        # Test with different metrics
        backend.metrics.active_connections = 50  # 50% utilization
        backend.metrics.average_response_time = 500  # 500ms
        backend.metrics.cpu_usage = 60.0  # 60%
        backend.metrics.memory_usage = 70.0  # 70%
        backend.metrics.update_request_metrics(False)  # Add one failure
        backend.metrics.update_request_metrics(True)   # Add one success (50% failure rate)
        
        load_score = backend.load_score
        assert 0.0 <= load_score <= 1.0
        assert load_score > 0  # Should have some load
    
    def test_connection_management(self):
        """Test connection increment/decrement."""
        backend = Backend("test", "example.com")
        
        assert backend.metrics.active_connections == 0
        
        backend.increment_connections()
        assert backend.metrics.active_connections == 1
        assert backend.last_used > 0
        
        backend.increment_connections()
        assert backend.metrics.active_connections == 2
        
        backend.decrement_connections()
        assert backend.metrics.active_connections == 1
        
        backend.decrement_connections()
        assert backend.metrics.active_connections == 0
        
        # Should not go below 0
        backend.decrement_connections()
        assert backend.metrics.active_connections == 0
    
    def test_update_status(self):
        """Test status update with circuit breaker logic."""
        backend = Backend("test", "example.com")
        backend.metrics.consecutive_failures = 6
        
        # Update to unhealthy should trigger circuit breaker
        backend.update_status(BackendStatus.UNHEALTHY)
        
        assert backend.status == BackendStatus.UNHEALTHY
        assert backend.circuit_breaker_open
        assert backend.circuit_breaker_opened_at > 0
    
    def test_to_dict(self):
        """Test dictionary conversion."""
        backend = Backend(
            backend_id="test_backend",
            host="example.com",
            port=8080,
            weight=150,
            tags={"env": "test"},
            metadata={"version": "1.0"}
        )
        backend.status = BackendStatus.HEALTHY
        backend.metrics.total_requests = 100
        backend.metrics.successful_requests = 95
        
        result = backend.to_dict()
        
        assert result["backend_id"] == "test_backend"
        assert result["host"] == "example.com"
        assert result["port"] == 8080
        assert result["weight"] == 150
        assert result["status"] == "healthy"
        assert result["tags"] == {"env": "test"}
        assert result["metadata"] == {"version": "1.0"}
        assert result["metrics"]["total_requests"] == 100
        assert result["metrics"]["successful_requests"] == 95
        assert result["metrics"]["success_rate"] == 0.95


class TestLoadBalancingAlgorithms:
    """Test load balancing algorithms."""
    
    def create_test_backends(self, count: int = 3) -> List[Backend]:
        """Create test backends."""
        backends = []
        for i in range(count):
            backend = Backend(f"backend_{i}", f"host_{i}.com", 8000 + i)
            backend.status = BackendStatus.HEALTHY
            backends.append(backend)
        return backends
    
    def test_round_robin_algorithm(self):
        """Test round-robin algorithm."""
        algorithm = RoundRobinAlgorithm()
        backends = self.create_test_backends(3)
        request = Mock(spec=Request)
        
        # Test selection order
        selections = []
        for _ in range(6):
            backend = algorithm.select_backend(backends, request)
            selections.append(backend.backend_id)
        
        # Should cycle through backends
        expected = ["backend_0", "backend_1", "backend_2", "backend_0", "backend_1", "backend_2"]
        assert selections == expected
        
        stats = algorithm.get_algorithm_stats()
        assert stats["algorithm"] == "round_robin"
        assert stats["total_selections"] == 6
    
    def test_weighted_round_robin_algorithm(self):
        """Test weighted round-robin algorithm."""
        algorithm = WeightedRoundRobinAlgorithm()
        backends = self.create_test_backends(3)
        
        # Set different weights
        backends[0].weight = 100
        backends[1].weight = 200  # Double weight
        backends[2].weight = 100
        
        request = Mock(spec=Request)
        
        # Test selections
        selections = []
        for _ in range(8):
            backend = algorithm.select_backend(backends, request)
            if backend:
                selections.append(backend.backend_id)
        
        # Backend_1 should be selected more often due to higher weight
        backend_1_count = selections.count("backend_1")
        assert backend_1_count > selections.count("backend_0")
        assert backend_1_count > selections.count("backend_2")
        
        stats = algorithm.get_algorithm_stats()
        assert stats["algorithm"] == "weighted_round_robin"
        assert "weights" in stats
    
    def test_least_connections_algorithm(self):
        """Test least connections algorithm."""
        algorithm = LeastConnectionsAlgorithm(weighted=False)
        backends = self.create_test_backends(3)
        request = Mock(spec=Request)
        
        # Set different connection counts
        backends[0].metrics.active_connections = 5
        backends[1].metrics.active_connections = 2  # Least connections
        backends[2].metrics.active_connections = 8
        
        backend = algorithm.select_backend(backends, request)
        assert backend.backend_id == "backend_1"
        
        stats = algorithm.get_algorithm_stats()
        assert stats["algorithm"] == "least_connections"
        assert not stats["weighted"]
    
    def test_weighted_least_connections_algorithm(self):
        """Test weighted least connections algorithm."""
        algorithm = LeastConnectionsAlgorithm(weighted=True)
        backends = self.create_test_backends(3)
        request = Mock(spec=Request)
        
        # Set connections and weights
        backends[0].metrics.active_connections = 10
        backends[0].weight = 100
        
        backends[1].metrics.active_connections = 20
        backends[1].weight = 400  # High weight compensates for high connections
        
        backends[2].metrics.active_connections = 8
        backends[2].weight = 100
        
        backend = algorithm.select_backend(backends, request)
        # Backend_1 should be selected: 20/400 = 0.05 vs 10/100 = 0.1 vs 8/100 = 0.08
        assert backend.backend_id == "backend_1"
    
    def test_random_algorithm(self):
        """Test random algorithm."""
        algorithm = RandomAlgorithm(weighted=False)
        backends = self.create_test_backends(3)
        request = Mock(spec=Request)
        
        # Test multiple selections
        selections = set()
        for _ in range(20):
            backend = algorithm.select_backend(backends, request)
            selections.add(backend.backend_id)
        
        # Should use all backends eventually
        assert len(selections) == 3
        
        stats = algorithm.get_algorithm_stats()
        assert stats["algorithm"] == "random"
    
    def test_weighted_random_algorithm(self):
        """Test weighted random algorithm."""
        algorithm = RandomAlgorithm(weighted=True)
        backends = self.create_test_backends(2)
        request = Mock(spec=Request)
        
        # Set very different weights to test distribution
        backends[0].weight = 1
        backends[1].weight = 999  # Much higher weight
        
        # Test many selections
        selections = []
        for _ in range(100):
            backend = algorithm.select_backend(backends, request)
            selections.append(backend.backend_id)
        
        # Backend_1 should be selected much more often
        backend_1_count = selections.count("backend_1")
        assert backend_1_count > 80  # Should be selected ~99% of time
    
    def test_ip_hash_algorithm(self):
        """Test IP hash algorithm."""
        algorithm = IPHashAlgorithm()
        backends = self.create_test_backends(3)
        
        # Create requests with different IPs
        request1 = Mock(spec=Request)
        request1.client.host = "192.168.1.1"
        
        request2 = Mock(spec=Request)
        request2.client.host = "192.168.1.2"
        
        # Same IP should always get same backend
        backend1a = algorithm.select_backend(backends, request1)
        backend1b = algorithm.select_backend(backends, request1)
        assert backend1a.backend_id == backend1b.backend_id
        
        # Different IPs might get different backends
        backend2 = algorithm.select_backend(backends, request2)
        # Not guaranteed to be different, but algorithm should be consistent per IP
        
        stats = algorithm.get_algorithm_stats()
        assert stats["algorithm"] == "ip_hash"
        assert stats["unique_ips"] == 2
    
    def test_least_response_time_algorithm(self):
        """Test least response time algorithm."""
        algorithm = LeastResponseTimeAlgorithm()
        backends = self.create_test_backends(3)
        request = Mock(spec=Request)
        
        # Set different response times
        backends[0].metrics.average_response_time = 100.0
        backends[1].metrics.average_response_time = 50.0   # Fastest
        backends[2].metrics.average_response_time = 200.0
        
        # Set some active connections to test the connection factor
        backends[1].metrics.active_connections = 2
        
        backend = algorithm.select_backend(backends, request)
        # Should still select backend_1 despite connections
        assert backend.backend_id == "backend_1"
    
    def test_resource_based_algorithm(self):
        """Test resource-based algorithm."""
        algorithm = ResourceBasedAlgorithm()
        backends = self.create_test_backends(3)
        request = Mock(spec=Request)
        
        # Set different resource usage
        backends[0].metrics.cpu_usage = 80.0
        backends[0].metrics.memory_usage = 70.0
        backends[0].metrics.active_connections = 50
        backends[0].max_connections = 100
        
        backends[1].metrics.cpu_usage = 20.0  # Lower usage
        backends[1].metrics.memory_usage = 30.0
        backends[1].metrics.active_connections = 10
        backends[1].max_connections = 100
        
        backends[2].metrics.cpu_usage = 90.0
        backends[2].metrics.memory_usage = 85.0
        backends[2].metrics.active_connections = 80
        backends[2].max_connections = 100
        
        backend = algorithm.select_backend(backends, request)
        # Should select backend_1 with lowest resource usage
        assert backend.backend_id == "backend_1"
    
    def test_no_available_backends(self):
        """Test algorithms with no available backends."""
        algorithm = RoundRobinAlgorithm()
        backends = self.create_test_backends(2)
        request = Mock(spec=Request)
        
        # Make all backends unavailable
        for backend in backends:
            backend.status = BackendStatus.UNHEALTHY
        
        result = algorithm.select_backend(backends, request)
        assert result is None


class TestHealthChecker:
    """Test health checking functionality."""
    
    @pytest.mark.asyncio
    async def test_health_checker_lifecycle(self):
        """Test health checker start/stop lifecycle."""
        backends = []
        backend = Backend("test", "127.0.0.1", 8080)
        backends.append(backend)
        
        checker = HealthChecker(backends)
        
        # Should not be running initially
        assert not checker._running
        
        # Start checker
        await checker.start()
        assert checker._running
        assert checker._client is not None
        assert len(checker._tasks) == 1
        
        # Stop checker
        await checker.stop()
        assert not checker._running
        assert checker._client is None
        assert len(checker._tasks) == 0
    
    @pytest.mark.asyncio
    async def test_update_backend_health_success(self):
        """Test backend health update on successful checks."""
        backend = Backend("test", "example.com")
        backend.status = BackendStatus.UNKNOWN
        backend.health_check_config.healthy_threshold = 2
        
        checker = HealthChecker([backend])
        
        # First success
        checker._update_backend_health(backend, True)
        assert backend.metrics.consecutive_successes == 1
        assert backend.metrics.consecutive_failures == 0
        assert backend.status == BackendStatus.UNKNOWN  # Not enough successes yet
        
        # Second success - should become healthy
        checker._update_backend_health(backend, True)
        assert backend.metrics.consecutive_successes == 2
        assert backend.status == BackendStatus.HEALTHY
    
    @pytest.mark.asyncio
    async def test_update_backend_health_failure(self):
        """Test backend health update on failed checks."""
        backend = Backend("test", "example.com")
        backend.status = BackendStatus.HEALTHY
        backend.health_check_config.unhealthy_threshold = 3
        
        checker = HealthChecker([backend])
        
        # First failure
        checker._update_backend_health(backend, False)
        assert backend.metrics.consecutive_failures == 1
        assert backend.status == BackendStatus.HEALTHY  # Not enough failures yet
        
        # Second failure
        checker._update_backend_health(backend, False)
        assert backend.metrics.consecutive_failures == 2
        assert backend.status == BackendStatus.HEALTHY  # Still not enough
        
        # Third failure - should become degraded
        checker._update_backend_health(backend, False)
        assert backend.metrics.consecutive_failures == 3
        assert backend.status == BackendStatus.DEGRADED
        
        # Additional failures should make it unhealthy
        checker._update_backend_health(backend, False)
        assert backend.status == BackendStatus.UNHEALTHY
    
    @pytest.mark.asyncio
    async def test_tcp_health_check(self):
        """Test TCP health check."""
        backend = Backend("test", "127.0.0.1", 22)  # SSH port usually available
        backend.health_check_config = HealthCheckConfig(
            check_type=HealthCheckType.TCP,
            timeout=1.0
        )
        
        checker = HealthChecker([backend])
        await checker.start()
        
        try:
            # Perform health check
            result = await checker._tcp_health_check(backend, backend.health_check_config)
            # Result depends on whether SSH is running - just check it completes
            assert isinstance(result, bool)
        finally:
            await checker.stop()
    
    @pytest.mark.asyncio
    async def test_custom_health_check_sync(self):
        """Test custom synchronous health check."""
        def custom_check(backend):
            return backend.backend_id == "test"
        
        backend = Backend("test", "example.com")
        backend.health_check_config = HealthCheckConfig(
            check_type=HealthCheckType.CUSTOM,
            custom_check=custom_check
        )
        
        checker = HealthChecker([backend])
        
        result = await checker._custom_health_check(backend, backend.health_check_config)
        assert result is True
    
    @pytest.mark.asyncio
    async def test_custom_health_check_async(self):
        """Test custom asynchronous health check."""
        async def async_custom_check(backend):
            await asyncio.sleep(0.01)
            return backend.backend_id == "test"
        
        backend = Backend("test", "example.com")
        backend.health_check_config = HealthCheckConfig(
            check_type=HealthCheckType.CUSTOM,
            custom_check=async_custom_check
        )
        
        checker = HealthChecker([backend])
        
        result = await checker._custom_health_check(backend, backend.health_check_config)
        assert result is True


class TestSessionManager:
    """Test session management functionality."""
    
    def test_init_default(self):
        """Test default initialization."""
        manager = SessionManager()
        
        assert manager.strategy == StickySessionStrategy.COOKIE
        assert manager.session_timeout == 3600.0
        assert manager.cookie_name == "lb_session"
        assert manager.header_name == "X-Session-ID"
        assert len(manager._sessions) == 0
    
    def test_init_custom(self):
        """Test custom initialization."""
        manager = SessionManager(
            strategy=StickySessionStrategy.HEADER,
            session_timeout=1800.0,
            cookie_name="custom_session",
            header_name="X-Custom-Session"
        )
        
        assert manager.strategy == StickySessionStrategy.HEADER
        assert manager.session_timeout == 1800.0
        assert manager.cookie_name == "custom_session"
        assert manager.header_name == "X-Custom-Session"
    
    def test_extract_session_id_cookie(self):
        """Test session ID extraction from cookie."""
        manager = SessionManager(strategy=StickySessionStrategy.COOKIE)
        
        request = Mock(spec=Request)
        request.cookies = {"lb_session": "session123"}
        
        session_id = manager._extract_session_id(request)
        assert session_id == "session123"
    
    def test_extract_session_id_header(self):
        """Test session ID extraction from header."""
        manager = SessionManager(strategy=StickySessionStrategy.HEADER)
        
        request = Mock(spec=Request)
        request.headers = {"X-Session-ID": "header123"}
        
        session_id = manager._extract_session_id(request)
        assert session_id == "header123"
    
    def test_extract_session_id_ip_hash(self):
        """Test session ID extraction from IP hash."""
        manager = SessionManager(strategy=StickySessionStrategy.IP_HASH)
        
        request = Mock(spec=Request)
        request.client.host = "192.168.1.100"
        
        session_id = manager._extract_session_id(request)
        assert session_id is not None
        assert len(session_id) == 32  # MD5 hash
        
        # Same IP should generate same session ID
        session_id2 = manager._extract_session_id(request)
        assert session_id == session_id2
    
    def test_extract_session_id_session_id(self):
        """Test session ID extraction from various session parameters."""
        manager = SessionManager(strategy=StickySessionStrategy.SESSION_ID)
        
        # Test query parameter
        request1 = Mock(spec=Request)
        request1.query_params = {"sessionid": "query123"}
        request1.cookies = {}
        
        session_id = manager._extract_session_id(request1)
        assert session_id == "query123"
        
        # Test cookie
        request2 = Mock(spec=Request)
        request2.query_params = {}
        request2.cookies = {"JSESSIONID": "cookie123"}
        
        session_id = manager._extract_session_id(request2)
        assert session_id == "cookie123"
    
    def test_create_and_get_session(self):
        """Test session creation and retrieval."""
        manager = SessionManager()
        
        request = Mock(spec=Request)
        request.cookies = {}
        request.client.host = "192.168.1.100"
        
        backend = Backend("test_backend", "example.com")
        backend.status = BackendStatus.HEALTHY  # Make backend available
        backends = [backend]
        
        # Create session
        session_id = manager.create_session(request, backend)
        assert session_id is not None
        assert len(manager._sessions) == 1
        
        # Mock request with session
        request.cookies = {"lb_session": session_id}
        
        # Retrieve backend for session
        retrieved_backend = manager.get_backend_for_session(request, backends)
        assert retrieved_backend == backend
    
    def test_session_cleanup(self):
        """Test expired session cleanup."""
        manager = SessionManager(session_timeout=0.1)  # Very short timeout
        
        request = Mock(spec=Request)
        request.cookies = {}
        
        backend = Backend("test_backend", "example.com")
        
        # Create session
        session_id = manager.create_session(request, backend)
        assert len(manager._sessions) == 1
        
        # Wait for expiration
        time.sleep(0.2)
        
        # Cleanup should remove expired sessions
        manager._cleanup_expired_sessions()
        assert len(manager._sessions) == 0
    
    def test_session_stats(self):
        """Test session statistics."""
        manager = SessionManager()
        
        request = Mock(spec=Request)
        request.cookies = {}
        
        backend1 = Backend("backend1", "example1.com")
        backend2 = Backend("backend2", "example2.com")
        
        # Create sessions
        manager.create_session(request, backend1)
        manager.create_session(request, backend1)
        manager.create_session(request, backend2)
        
        stats = manager.get_session_stats()
        
        assert stats["total_sessions"] == 3
        assert stats["backend_distribution"]["backend1"] == 2
        assert stats["backend_distribution"]["backend2"] == 1
        assert stats["strategy"] == StickySessionStrategy.COOKIE.value


class TestLoadBalancer:
    """Test LoadBalancer functionality."""
    
    def test_init_default(self):
        """Test default initialization."""
        lb = LoadBalancer()
        
        assert lb.algorithm_type == LoadBalancingAlgorithm.ROUND_ROBIN
        assert lb.enable_health_checks is True
        assert lb.enable_sticky_sessions is False
        assert len(lb.backends) == 0
        assert lb.session_manager is None
        assert not lb._started
    
    def test_init_with_sticky_sessions(self):
        """Test initialization with sticky sessions enabled."""
        lb = LoadBalancer(
            algorithm=LoadBalancingAlgorithm.WEIGHTED_ROUND_ROBIN,
            enable_sticky_sessions=True,
            sticky_session_strategy=StickySessionStrategy.IP_HASH
        )
        
        assert lb.algorithm_type == LoadBalancingAlgorithm.WEIGHTED_ROUND_ROBIN
        assert lb.enable_sticky_sessions is True
        assert lb.session_manager is not None
        assert lb.session_manager.strategy == StickySessionStrategy.IP_HASH
    
    def test_add_remove_backend(self):
        """Test adding and removing backends."""
        lb = LoadBalancer()
        backend = Backend("test", "example.com")
        
        # Add backend
        lb.add_backend(backend)
        assert len(lb.backends) == 1
        assert lb.get_backend("test") == backend
        
        # Remove backend
        result = lb.remove_backend("test")
        assert result is True
        assert len(lb.backends) == 0
        assert lb.get_backend("test") is None
        
        # Remove non-existent backend
        result = lb.remove_backend("nonexistent")
        assert result is False
    
    @pytest.mark.asyncio
    async def test_start_stop_lifecycle(self):
        """Test load balancer lifecycle."""
        lb = LoadBalancer()
        backend = Backend("test", "example.com")
        lb.add_backend(backend)
        
        # Start load balancer
        await lb.start()
        assert lb._started
        assert lb.health_checker is not None
        
        # Stop load balancer
        await lb.stop()
        assert not lb._started
        assert lb.health_checker is None
    
    def test_select_backend_simple(self):
        """Test backend selection without sticky sessions."""
        lb = LoadBalancer(algorithm=LoadBalancingAlgorithm.ROUND_ROBIN)
        
        # Add backends
        backend1 = Backend("backend1", "host1.com")
        backend1.status = BackendStatus.HEALTHY
        backend2 = Backend("backend2", "host2.com")
        backend2.status = BackendStatus.HEALTHY
        
        lb.add_backend(backend1)
        lb.add_backend(backend2)
        
        request = Mock(spec=Request)
        
        # Test round-robin selection
        selected1 = lb.select_backend(request)
        selected2 = lb.select_backend(request)
        
        assert selected1 != selected2
        assert selected1 in [backend1, backend2]
        assert selected2 in [backend1, backend2]
    
    def test_select_backend_with_sticky_sessions(self):
        """Test backend selection with sticky sessions."""
        lb = LoadBalancer(
            enable_sticky_sessions=True,
            sticky_session_strategy=StickySessionStrategy.IP_HASH
        )
        
        backend1 = Backend("backend1", "host1.com")
        backend1.status = BackendStatus.HEALTHY
        backend2 = Backend("backend2", "host2.com")
        backend2.status = BackendStatus.HEALTHY
        
        lb.add_backend(backend1)
        lb.add_backend(backend2)
        
        request = Mock(spec=Request)
        request.client.host = "192.168.1.100"
        
        # First selection should create session
        selected1 = lb.select_backend(request)
        
        # Subsequent selections with same IP should return same backend
        selected2 = lb.select_backend(request)
        selected3 = lb.select_backend(request)
        
        assert selected1.backend_id == selected2.backend_id == selected3.backend_id
    
    def test_update_request_metrics(self):
        """Test request metrics updating."""
        lb = LoadBalancer()
        backend = Backend("test", "example.com")
        
        # Update successful request
        lb.update_request_metrics(backend, True, 100.0)
        
        assert lb.total_requests == 1
        assert lb.successful_requests == 1
        assert lb.failed_requests == 0
        assert 100.0 in lb.response_times
        assert lb.average_response_time == 100.0
        
        # Update failed request
        lb.update_request_metrics(backend, False, 200.0)
        
        assert lb.total_requests == 2
        assert lb.successful_requests == 1
        assert lb.failed_requests == 1
        assert lb.average_response_time == 150.0  # Average of 100 and 200
    
    def test_get_load_balancer_stats(self):
        """Test load balancer statistics."""
        lb = LoadBalancer(
            algorithm=LoadBalancingAlgorithm.ROUND_ROBIN,
            enable_sticky_sessions=True
        )
        
        # Add backends with different statuses
        backend1 = Backend("backend1", "host1.com")
        backend1.status = BackendStatus.HEALTHY
        
        backend2 = Backend("backend2", "host2.com")
        backend2.status = BackendStatus.DEGRADED
        
        backend3 = Backend("backend3", "host3.com")
        backend3.status = BackendStatus.UNHEALTHY
        
        lb.add_backend(backend1)
        lb.add_backend(backend2)
        lb.add_backend(backend3)
        
        # Update some metrics
        lb.total_requests = 100
        lb.successful_requests = 90
        lb.failed_requests = 10
        
        stats = lb.get_load_balancer_stats()
        
        assert stats["algorithm"] == "round_robin"
        assert stats["total_backends"] == 3
        assert stats["healthy_backends"] == 1
        assert stats["degraded_backends"] == 1
        assert stats["unhealthy_backends"] == 1
        assert stats["total_requests"] == 100
        assert stats["success_rate"] == 0.9
        assert stats["enable_health_checks"] is True
        assert stats["enable_sticky_sessions"] is True
        assert len(stats["backends"]) == 3
        assert "algorithm_stats" in stats
        assert "session_stats" in stats


class TestLoadBalancingShield:
    """Test LoadBalancingShield functionality."""
    
    @pytest.mark.asyncio
    async def test_init(self):
        """Test shield initialization."""
        lb = LoadBalancer()
        shield = LoadBalancingShield(lb)
        
        assert shield.load_balancer == lb
        assert shield.proxy_request is True
        assert shield.timeout == 30.0
        assert shield.follow_redirects is False
        assert shield.preserve_headers is True
        assert shield.add_lb_headers is True
    
    @pytest.mark.asyncio
    async def test_context_manager(self):
        """Test async context manager functionality."""
        lb = LoadBalancer()
        shield = LoadBalancingShield(lb)
        
        async with shield:
            assert shield._client is not None
            assert lb._started
        
        # After exiting context manager
        assert shield._client is None
        assert not lb._started
    
    @pytest.mark.asyncio
    async def test_load_balance_no_backends(self):
        """Test load balancing with no available backends."""
        lb = LoadBalancer()
        shield = LoadBalancingShield(lb)
        
        request = Mock(spec=Request)
        
        with pytest.raises(HTTPException) as exc_info:
            await shield._load_balance_request(request)
        
        assert exc_info.value.status_code == 503
        assert "No available backends" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_load_balance_no_proxy(self):
        """Test load balancing without proxying requests."""
        lb = LoadBalancer()
        backend = Backend("test", "example.com")
        backend.status = BackendStatus.HEALTHY
        lb.add_backend(backend)
        
        shield = LoadBalancingShield(lb, proxy_request=False)
        
        request = Mock(spec=Request)
        
        response = await shield._load_balance_request(request)
        
        assert isinstance(response, JSONResponse)
        # Should have backend info in response
        # Note: We can't easily test the actual content without more setup
        assert response.status_code == 200


@pytest.mark.asyncio
class TestLoadBalancingIntegration:
    """Integration tests with mock backend servers."""
    
    async def test_basic_load_balancing_with_mock_servers(self):
        """Test basic load balancing with mock backend servers."""
        # Create mock backend cluster
        backend_configs = [
            {
                "backend_id": "backend1",
                "host": "127.0.0.1",
                "port": 18001,
                "failure_rate": 0.0,
                "latency_min": 0.1,
                "latency_max": 0.2
            },
            {
                "backend_id": "backend2", 
                "host": "127.0.0.1",
                "port": 18002,
                "failure_rate": 0.0,
                "latency_min": 0.1,
                "latency_max": 0.2
            }
        ]
        
        async with mock_backend_cluster(backend_configs) as cluster:
            # Create load balancer with real backends
            lb = LoadBalancer(algorithm=LoadBalancingAlgorithm.ROUND_ROBIN)
            
            for server_id, server in cluster.servers.items():
                backend = Backend(
                    backend_id=server_id,
                    host=server.config.host,
                    port=server.config.port
                )
                backend.status = BackendStatus.HEALTHY
                lb.add_backend(backend)
            
            # Test backend selection
            request = Mock(spec=Request)
            
            selected_backends = []
            for _ in range(4):
                backend = lb.select_backend(request)
                assert backend is not None
                selected_backends.append(backend.backend_id)
            
            # Should alternate between backends (round-robin)
            assert "backend1" in selected_backends
            assert "backend2" in selected_backends
    
    async def test_health_checking_with_mock_servers(self):
        """Test health checking with mock backend servers."""
        backend_configs = [
            {
                "backend_id": "healthy_backend",
                "host": "127.0.0.1",
                "port": 18003,
                "failure_rate": 0.0
            },
            {
                "backend_id": "failing_backend",
                "host": "127.0.0.1", 
                "port": 18004,
                "failure_rate": 1.0  # Always fail
            }
        ]
        
        async with mock_backend_cluster(backend_configs) as cluster:
            # Create backends with health checks
            backends = []
            for server_id, server in cluster.servers.items():
                backend = Backend(
                    backend_id=server_id,
                    host=server.config.host,
                    port=server.config.port,
                    health_check_config=HealthCheckConfig(
                        check_type=HealthCheckType.HTTP,
                        url=f"http://{server.config.host}:{server.config.port}/health",
                        interval=1.0,  # Fast interval for testing
                        unhealthy_threshold=2,
                        healthy_threshold=1
                    )
                )
                backends.append(backend)
            
            # Start health checker
            health_checker = HealthChecker(backends)
            await health_checker.start()
            
            try:
                # Wait for health checks to run
                await asyncio.sleep(2.5)
                
                # Check backend statuses
                healthy_backend = next(b for b in backends if b.backend_id == "healthy_backend")
                failing_backend = next(b for b in backends if b.backend_id == "failing_backend")
                
                # Healthy backend should be healthy
                assert healthy_backend.status in (BackendStatus.HEALTHY, BackendStatus.DEGRADED)
                
                # Failing backend should be degraded or unhealthy
                assert failing_backend.status in (BackendStatus.DEGRADED, BackendStatus.UNHEALTHY)
                
            finally:
                await health_checker.stop()
    
    async def test_failover_behavior(self):
        """Test automatic failover when backends fail."""
        backend_configs = [
            {
                "backend_id": "primary",
                "host": "127.0.0.1",
                "port": 18005,
                "failure_rate": 0.0
            },
            {
                "backend_id": "secondary",
                "host": "127.0.0.1",
                "port": 18006,
                "failure_rate": 0.0
            }
        ]
        
        async with mock_backend_cluster(backend_configs) as cluster:
            # Create load balancer
            lb = LoadBalancer(algorithm=LoadBalancingAlgorithm.LEAST_CONNECTIONS)
            
            primary_backend = Backend("primary", "127.0.0.1", 18005)
            primary_backend.status = BackendStatus.HEALTHY
            
            secondary_backend = Backend("secondary", "127.0.0.1", 18006)  
            secondary_backend.status = BackendStatus.HEALTHY
            
            lb.add_backend(primary_backend)
            lb.add_backend(secondary_backend)
            
            request = Mock(spec=Request)
            
            # Initially, both backends should be selectable
            selected = lb.select_backend(request)
            assert selected is not None
            
            # Simulate primary backend failure
            primary_backend.status = BackendStatus.UNHEALTHY
            
            # Should now only select secondary
            selected = lb.select_backend(request)
            assert selected.backend_id == "secondary"
            
            # Simulate secondary failure too
            secondary_backend.status = BackendStatus.UNHEALTHY
            
            # Should return None (no available backends)
            selected = lb.select_backend(request)
            assert selected is None
    
    async def test_sticky_sessions(self):
        """Test sticky session behavior."""
        backend_configs = [
            {
                "backend_id": "backend1",
                "host": "127.0.0.1",
                "port": 18007
            },
            {
                "backend_id": "backend2",
                "host": "127.0.0.1", 
                "port": 18008
            }
        ]
        
        async with mock_backend_cluster(backend_configs) as cluster:
            # Create load balancer with sticky sessions
            lb = LoadBalancer(
                enable_sticky_sessions=True,
                sticky_session_strategy=StickySessionStrategy.IP_HASH
            )
            
            for server_id, server in cluster.servers.items():
                backend = Backend(
                    backend_id=server_id,
                    host=server.config.host,
                    port=server.config.port
                )
                backend.status = BackendStatus.HEALTHY
                lb.add_backend(backend)
            
            # Create request with specific IP
            request = Mock(spec=Request)
            request.client.host = "192.168.1.100"
            
            # Multiple requests from same IP should go to same backend
            selected1 = lb.select_backend(request)
            selected2 = lb.select_backend(request)
            selected3 = lb.select_backend(request)
            
            assert selected1.backend_id == selected2.backend_id == selected3.backend_id
            
            # Different IP should potentially get different backend
            request2 = Mock(spec=Request)
            request2.client.host = "192.168.1.200"
            
            selected4 = lb.select_backend(request2)
            # Not guaranteed to be different, but should be consistent
            selected5 = lb.select_backend(request2)
            assert selected4.backend_id == selected5.backend_id


class TestConvenienceFunctions:
    """Test convenience functions."""
    
    def test_create_load_balancer(self):
        """Test create_load_balancer convenience function."""
        backends_config = [
            {
                "backend_id": "backend1",
                "host": "host1.com",
                "port": 8080,
                "weight": 150,
                "health_check": {
                    "type": "http",
                    "url": "http://host1.com:8080/health",
                    "interval": 60.0
                }
            },
            {
                "backend_id": "backend2",
                "host": "host2.com",
                "port": 8080,
                "weight": 100
            }
        ]
        
        lb = create_load_balancer(
            backends=backends_config,
            algorithm=LoadBalancingAlgorithm.WEIGHTED_ROUND_ROBIN,
            enable_sticky_sessions=True
        )
        
        assert lb.algorithm_type == LoadBalancingAlgorithm.WEIGHTED_ROUND_ROBIN
        assert lb.enable_sticky_sessions is True
        assert len(lb.backends) == 2
        
        backend1 = lb.get_backend("backend1")
        assert backend1 is not None
        assert backend1.weight == 150
        assert backend1.health_check_config.interval == 60.0
        
        backend2 = lb.get_backend("backend2")
        assert backend2 is not None
        assert backend2.weight == 100
    
    def test_load_balancing_shield_decorator(self):
        """Test load_balancing_shield decorator."""
        lb = LoadBalancer()
        
        @load_balancing_shield(load_balancer=lb, proxy_request=False)
        def test_endpoint():
            return {"message": "test"}
        
        # The decorator wraps the function, so we should be able to call it
        # and it should have the shield properties stored somewhere
        assert callable(test_endpoint)
        # The actual shield is created when the decorator is applied
        # We can check this by inspecting the function attributes or behavior


class TestPerformanceAndReliability:
    """Performance and reliability tests."""
    
    def test_concurrent_backend_selection(self):
        """Test concurrent backend selection performance."""
        lb = LoadBalancer(algorithm=LoadBalancingAlgorithm.ROUND_ROBIN)
        
        # Add multiple backends
        for i in range(10):
            backend = Backend(f"backend_{i}", f"host{i}.com")
            backend.status = BackendStatus.HEALTHY
            lb.add_backend(backend)
        
        request = Mock(spec=Request)
        
        # Test concurrent selections
        import concurrent.futures
        import threading
        
        def select_backends(count):
            selections = []
            for _ in range(count):
                backend = lb.select_backend(request)
                if backend:
                    selections.append(backend.backend_id)
            return selections
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(select_backends, 100) for _ in range(10)]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]
        
        # Verify all selections completed
        total_selections = sum(len(result) for result in results)
        assert total_selections == 1000
        
        # Verify all backends were used
        all_selections = [selection for result in results for selection in result]
        unique_backends = set(all_selections)
        assert len(unique_backends) == 10
    
    def test_metrics_accuracy(self):
        """Test metrics accuracy under load."""
        lb = LoadBalancer()
        backend = Backend("test", "example.com")
        lb.add_backend(backend)
        
        # Simulate many requests
        response_times = [50.0, 100.0, 150.0, 200.0, 250.0]
        
        for i, rt in enumerate(response_times):
            success = i % 2 == 0  # Alternate success/failure
            lb.update_request_metrics(backend, success, rt)
        
        assert lb.total_requests == 5
        assert lb.successful_requests == 3
        assert lb.failed_requests == 2
        assert lb.average_response_time == statistics.mean(response_times)
        
        # Check backend metrics
        assert backend.metrics.total_requests == 5
        assert backend.metrics.successful_requests == 3
        assert backend.metrics.failed_requests == 2
    
    def test_memory_efficiency(self):
        """Test memory efficiency with many backends."""
        lb = LoadBalancer()
        
        # Add many backends
        for i in range(1000):
            backend = Backend(f"backend_{i}", f"host{i}.com")
            backend.status = BackendStatus.HEALTHY
            lb.add_backend(backend)
        
        assert len(lb.backends) == 1000
        
        # Test selection still works efficiently
        request = Mock(spec=Request)
        
        start_time = time.time()
        for _ in range(100):
            backend = lb.select_backend(request)
            assert backend is not None
        end_time = time.time()
        
        # Should complete quickly even with many backends
        assert end_time - start_time < 1.0
    
    @pytest.mark.asyncio
    async def test_health_check_resilience(self):
        """Test health checker resilience to errors."""
        # Create backend with invalid host
        backend = Backend("invalid", "invalid.host.that.does.not.exist.com")
        backend.health_check_config.interval = 0.1  # Fast interval
        backend.health_check_config.timeout = 0.1    # Short timeout
        
        checker = HealthChecker([backend])
        
        # Start health checker
        await checker.start()
        
        try:
            # Wait for several health check attempts
            await asyncio.sleep(0.5)
            
            # Backend should be marked as unhealthy
            assert backend.status in (BackendStatus.DEGRADED, BackendStatus.UNHEALTHY)
            
            # Health checker should still be running
            assert checker._running
            
        finally:
            await checker.stop()


if __name__ == "__main__":
    # Run a simple test to verify functionality
    async def simple_test():
        print("Running simple load balancing test...")
        
        # Test basic functionality
        lb = LoadBalancer(algorithm=LoadBalancingAlgorithm.ROUND_ROBIN)
        
        backend1 = Backend("backend1", "host1.com")
        backend1.status = BackendStatus.HEALTHY
        
        backend2 = Backend("backend2", "host2.com") 
        backend2.status = BackendStatus.HEALTHY
        
        lb.add_backend(backend1)
        lb.add_backend(backend2)
        
        request = Mock(spec=Request)
        
        # Test selections
        selections = []
        for _ in range(6):
            backend = lb.select_backend(request)
            selections.append(backend.backend_id)
        
        print(f"Selection pattern: {selections}")
        assert selections == ["backend1", "backend2"] * 3
        
        print("Simple test passed!")
    
    asyncio.run(simple_test())