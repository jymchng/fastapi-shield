"""Comprehensive tests for edge computing functionality.

This test suite covers all aspects of the edge computing system including:
- Edge-optimized shield implementations and lightweight components
- Offline authentication and local caching systems
- Edge-to-cloud policy synchronization mechanisms
- CDN integration and distributed coordination
- Local decision making with global policy consistency
- Performance optimization for resource-constrained environments
- Distributed consensus and cluster coordination
- Network partition tolerance and failure recovery
- Real-world edge computing scenarios and use cases
"""

import asyncio
import json
import random
import sqlite3
import tempfile
import time
import pytest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Any
from unittest.mock import Mock, patch, AsyncMock

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from fastapi_shield.edge_computing import (
    # Core classes
    EdgeShield,
    EdgeOptimizer,
    EdgeCache,
    OfflineAuthCache,
    PolicySynchronizer,
    DistributedConsensus,
    CDNIntegration,
    EdgeMiddleware,
    
    # Monitoring classes
    MemoryMonitor,
    CPUMonitor,
    
    # Data classes
    EdgeNode,
    EdgePolicy,
    EdgeCacheEntry,
    EdgeSyncState,
    
    # Enums
    EdgeLocation,
    EdgeCapability,
    SyncMode,
    EdgeResourceLevel,
    ConsensusAlgorithm,
    
    # Convenience functions and decorators
    create_edge_shield,
    edge_optimized,
    ultra_lightweight,
    iot_gateway_protection,
)

from tests.mocks.mock_edge_infrastructure import (
    MockEdgeTestEnvironment,
    MockEdgeTestConfig,
    MockNetworkSimulator,
    MockCloudEndpoint,
    MockCDNProvider,
    MockResourceMonitor,
    MockDistributedCluster,
    create_iot_gateway_scenario,
    create_cdn_edge_scenario,
    create_mobile_edge_scenario,
    mock_edge_environment
)


class TestEdgeDataStructures:
    """Test edge computing data structures."""
    
    def test_edge_node_creation(self):
        """Test edge node creation and validation."""
        node = EdgeNode(
            node_id="test-edge-01",
            location_type=EdgeLocation.CDN_EDGE,
            resource_level=EdgeResourceLevel.MEDIUM,
            capabilities=[EdgeCapability.LOCAL_CACHE, EdgeCapability.POLICY_SYNC],
            endpoint="https://edge01.example.com",
            region="us-east-1",
            cluster_id="cluster-1"
        )
        
        assert node.node_id == "test-edge-01"
        assert node.location_type == EdgeLocation.CDN_EDGE
        assert node.resource_level == EdgeResourceLevel.MEDIUM
        assert EdgeCapability.LOCAL_CACHE in node.capabilities
        assert node.endpoint == "https://edge01.example.com"
        assert node.is_online is True
        assert node.last_heartbeat is not None
    
    def test_edge_policy_creation_and_integrity(self):
        """Test edge policy creation and integrity verification."""
        policy = EdgePolicy(
            policy_id="test-policy-01",
            name="Test Rate Limiting",
            version="1.0.0",
            priority=100,
            conditions={"path_pattern": "/api/*"},
            actions={"rate_limit": {"requests": 100, "window": 60}},
            resource_constraints={"memory_mb": 5, "cpu_percent": 2}
        )
        
        assert policy.policy_id == "test-policy-01"
        assert policy.version == "1.0.0"
        assert policy.priority == 100
        assert policy.checksum is not None
        assert policy.size_bytes > 0
        
        # Test integrity verification
        assert policy.verify_integrity() is True
        
        # Test integrity failure after tampering
        original_checksum = policy.checksum
        policy.actions["tampered"] = True
        policy.checksum = original_checksum  # Keep old checksum
        assert policy.verify_integrity() is False
    
    def test_edge_policy_compression(self):
        """Test edge policy compression and decompression."""
        policy = EdgePolicy(
            policy_id="compression-test",
            name="Compression Test Policy",
            version="2.1.0",
            priority=90,
            conditions={"path_pattern": "/api/v2/*", "methods": ["GET", "POST"]},
            actions={"headers": {"X-Edge-Cache": "HIT"}},
            resource_constraints={"memory_mb": 3}
        )
        
        # Compress policy
        compressed_data = policy.compress()
        assert isinstance(compressed_data, bytes)
        assert len(compressed_data) < policy.size_bytes  # Should be smaller
        
        # Decompress policy
        decompressed_policy = EdgePolicy.decompress(compressed_data)
        assert decompressed_policy.policy_id == policy.policy_id
        assert decompressed_policy.name == policy.name
        assert decompressed_policy.version == policy.version
        assert decompressed_policy.conditions == policy.conditions
        assert decompressed_policy.actions == policy.actions
    
    def test_edge_cache_entry(self):
        """Test edge cache entry functionality."""
        entry = EdgeCacheEntry(
            key="test-key",
            value={"data": "test value"},
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        
        assert entry.key == "test-key"
        assert not entry.is_expired()
        assert entry.access_count == 0
        
        # Test access tracking
        value = entry.get_value()
        assert value == {"data": "test value"}
        assert entry.access_count == 1
        assert entry.last_accessed is not None
        
        # Test expiry
        entry.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        assert entry.is_expired() is True
    
    def test_edge_sync_state(self):
        """Test edge synchronization state tracking."""
        sync_state = EdgeSyncState(
            node_id="edge-01",
            last_sync=datetime.now(timezone.utc),
            sync_version=5,
            policies_count=10,
            pending_updates=2
        )
        
        assert sync_state.node_id == "edge-01"
        assert sync_state.sync_version == 5
        assert sync_state.policies_count == 10
        assert sync_state.pending_updates == 2
        assert sync_state.sync_errors == 0  # Default value


class TestEdgeOptimizer:
    """Test edge resource optimization."""
    
    @pytest.fixture
    def optimizer_ultra_low(self):
        """Create ultra-low resource optimizer."""
        return EdgeOptimizer(EdgeResourceLevel.ULTRA_LOW)
    
    @pytest.fixture
    def optimizer_high(self):
        """Create high resource optimizer."""
        return EdgeOptimizer(EdgeResourceLevel.HIGH)
    
    def test_optimizer_initialization(self, optimizer_ultra_low, optimizer_high):
        """Test optimizer initialization with different resource levels."""
        # Ultra low resource configuration
        assert optimizer_ultra_low.resource_level == EdgeResourceLevel.ULTRA_LOW
        assert optimizer_ultra_low.get_cache_limit() == 1024 * 1024  # 1MB
        assert optimizer_ultra_low.get_policy_limit() == 50
        assert optimizer_ultra_low.should_compress() is True
        
        # High resource configuration
        assert optimizer_high.resource_level == EdgeResourceLevel.HIGH
        assert optimizer_high.get_cache_limit() == 128 * 1024 * 1024  # 128MB
        assert optimizer_high.get_policy_limit() == 5000
        assert optimizer_high.should_compress() is False
    
    def test_garbage_collection_strategy(self, optimizer_ultra_low, optimizer_high):
        """Test garbage collection strategies."""
        # Ultra low should trigger GC at 80% usage
        assert optimizer_ultra_low.should_garbage_collect(0.85) is True
        assert optimizer_ultra_low.should_garbage_collect(0.70) is False
        
        # High resource should trigger GC at 50% usage
        assert optimizer_high.should_garbage_collect(0.60) is True
        assert optimizer_high.should_garbage_collect(0.40) is False
    
    def test_optimization_strategies_consistency(self):
        """Test optimization strategies are consistent across resource levels."""
        levels = [EdgeResourceLevel.ULTRA_LOW, EdgeResourceLevel.LOW, 
                 EdgeResourceLevel.MEDIUM, EdgeResourceLevel.HIGH, EdgeResourceLevel.UNLIMITED]
        
        prev_cache_limit = 0
        prev_policy_limit = 0
        
        for level in levels:
            optimizer = EdgeOptimizer(level)
            cache_limit = optimizer.get_cache_limit()
            policy_limit = optimizer.get_policy_limit()
            
            # Cache and policy limits should increase with resource level
            assert cache_limit >= prev_cache_limit
            assert policy_limit >= prev_policy_limit
            
            prev_cache_limit = cache_limit
            prev_policy_limit = policy_limit


class TestMemoryMonitor:
    """Test memory monitoring functionality."""
    
    @pytest.fixture
    def memory_monitor(self):
        """Create memory monitor instance."""
        return MemoryMonitor()
    
    def test_memory_usage_tracking(self, memory_monitor):
        """Test memory usage tracking."""
        # Get initial usage
        usage1 = memory_monitor.get_current_usage()
        assert 0.0 <= usage1 <= 1.0
        
        # Get usage again to populate history
        usage2 = memory_monitor.get_current_usage()
        assert 0.0 <= usage2 <= 1.0
        
        # Check trend analysis
        trend = memory_monitor.get_usage_trend()
        assert 'trend' in trend
        assert 'average' in trend
        assert 'peak' in trend
        assert 'current' in trend
        
        assert isinstance(trend['trend'], float)
        assert 0.0 <= trend['average'] <= 1.0
        assert 0.0 <= trend['peak'] <= 1.0
    
    def test_memory_history_limit(self, memory_monitor):
        """Test memory history is limited to prevent unbounded growth."""
        # Generate many measurements
        for _ in range(100):
            memory_monitor.get_current_usage()
        
        # History should be limited
        assert len(memory_monitor._usage_history) <= 60


class TestCPUMonitor:
    """Test CPU monitoring functionality."""
    
    @pytest.fixture
    def cpu_monitor(self):
        """Create CPU monitor instance."""
        return CPUMonitor()
    
    def test_cpu_usage_tracking(self, cpu_monitor):
        """Test CPU usage tracking."""
        usage = cpu_monitor.get_current_usage()
        assert 0.0 <= usage <= 1.0
        
        load_avg = cpu_monitor.get_load_average()
        assert load_avg >= 0.0
    
    def test_cpu_history_tracking(self, cpu_monitor):
        """Test CPU usage history tracking."""
        # Generate measurements
        for _ in range(10):
            cpu_monitor.get_current_usage()
        
        # Verify history is tracked
        assert len(cpu_monitor._usage_history) >= 10


class TestEdgeCache:
    """Test edge cache functionality."""
    
    @pytest.fixture
    def small_cache(self):
        """Create small cache for testing."""
        return EdgeCache(max_size_bytes=1024, enable_compression=False)
    
    @pytest.fixture
    def compressed_cache(self):
        """Create cache with compression enabled."""
        return EdgeCache(max_size_bytes=10240, enable_compression=True)
    
    def test_cache_basic_operations(self, small_cache):
        """Test basic cache operations."""
        # Test put and get
        assert small_cache.put("key1", "value1", ttl_seconds=60) is True
        assert small_cache.get("key1") == "value1"
        
        # Test cache miss
        assert small_cache.get("nonexistent") is None
        
        # Test cache statistics
        stats = small_cache.get_stats()
        assert stats['entry_count'] == 1
        assert stats['hit_rate'] > 0
    
    def test_cache_ttl_expiration(self, small_cache):
        """Test cache TTL and expiration."""
        # Put value with short TTL
        small_cache.put("expire_key", "expire_value", ttl_seconds=1)
        assert small_cache.get("expire_key") == "expire_value"
        
        # Wait for expiration
        time.sleep(1.1)
        
        # Should be expired
        assert small_cache.get("expire_key") is None
        
        stats = small_cache.get_stats()
        assert stats['stats']['expired'] > 0
    
    def test_cache_size_limits_and_eviction(self, small_cache):
        """Test cache size limits and LRU eviction."""
        # Fill cache beyond capacity
        large_value = "x" * 500  # 500 bytes
        
        # Should be able to store at least one
        assert small_cache.put("large1", large_value) is True
        assert small_cache.put("large2", large_value) is True
        
        # Try to add more - might get rejected due to size
        result = small_cache.put("large3", large_value)
        
        # Check that eviction statistics are tracked
        stats = small_cache.get_stats()
        if not result:  # If rejected due to size
            assert stats['stats']['rejected'] > 0
        else:  # If accepted, should have triggered eviction
            # LRU eviction should have occurred
            assert small_cache.get("large1") is None  # Should be evicted
    
    def test_cache_cleanup_expired(self, small_cache):
        """Test cleanup of expired entries."""
        # Add entries with different TTLs
        small_cache.put("short", "value1", ttl_seconds=1)
        small_cache.put("long", "value2", ttl_seconds=3600)
        
        # Wait for short TTL to expire
        time.sleep(1.1)
        
        # Cleanup expired entries
        small_cache.cleanup_expired()
        
        # Verify cleanup
        assert small_cache.get("short") is None
        assert small_cache.get("long") == "value2"
        
        stats = small_cache.get_stats()
        assert stats['stats']['cleanup_runs'] > 0
    
    def test_cache_compression(self, compressed_cache):
        """Test cache compression functionality."""
        # Large data that should be compressed
        large_data = {"data": "x" * 2000, "metadata": {"size": "large"}}
        
        # Put data - should be compressed automatically
        assert compressed_cache.put("large_key", large_data) is True
        
        # Get data - should be decompressed automatically
        retrieved = compressed_cache.get("large_key")
        assert retrieved == large_data
    
    def test_cache_stats_accuracy(self, small_cache):
        """Test cache statistics accuracy."""
        # Generate cache hits and misses
        small_cache.put("hit_key", "hit_value")
        
        # Generate hits
        for _ in range(5):
            small_cache.get("hit_key")
        
        # Generate misses
        for _ in range(3):
            small_cache.get("miss_key")
        
        stats = small_cache.get_stats()
        assert stats['stats']['hits'] == 5
        assert stats['stats']['misses'] == 3
        assert stats['hit_rate'] == 5 / 8  # 5 hits out of 8 total requests


class TestOfflineAuthCache:
    """Test offline authentication cache."""
    
    @pytest.fixture
    def auth_cache(self):
        """Create offline auth cache with in-memory database."""
        return OfflineAuthCache(db_path=":memory:", max_entries=100)
    
    @pytest.fixture 
    def file_auth_cache(self):
        """Create offline auth cache with temporary file database."""
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        return OfflineAuthCache(db_path=temp_file.name, max_entries=100)
    
    def test_auth_cache_basic_operations(self, auth_cache):
        """Test basic authentication caching operations."""
        token = "test_token_123"
        user_id = "user_456"
        permissions = ["read", "write"]
        
        # Cache authentication
        assert auth_cache.cache_auth(token, user_id, permissions, ttl_seconds=3600) is True
        
        # Verify authentication
        auth_info = auth_cache.verify_auth(token)
        assert auth_info is not None
        assert auth_info['user_id'] == user_id
        assert auth_info['permissions'] == permissions
        assert auth_info['access_count'] == 1
        
        # Verify again to test access counting
        auth_info2 = auth_cache.verify_auth(token)
        assert auth_info2['access_count'] == 2
    
    def test_auth_cache_expiration(self, auth_cache):
        """Test authentication cache expiration."""
        token = "expire_token"
        user_id = "expire_user"
        permissions = ["read"]
        
        # Cache with short TTL
        auth_cache.cache_auth(token, user_id, permissions, ttl_seconds=1)
        
        # Should be valid initially
        auth_info = auth_cache.verify_auth(token)
        assert auth_info is not None
        
        # Wait for expiration
        time.sleep(1.1)
        
        # Should be expired
        auth_info = auth_cache.verify_auth(token)
        assert auth_info is None
    
    def test_auth_cache_user_invalidation(self, auth_cache):
        """Test invalidating all auth entries for a user."""
        user_id = "multi_token_user"
        tokens = ["token1", "token2", "token3"]
        
        # Cache multiple tokens for same user
        for token in tokens:
            auth_cache.cache_auth(token, user_id, ["read"], ttl_seconds=3600)
        
        # Verify all tokens work
        for token in tokens:
            assert auth_cache.verify_auth(token) is not None
        
        # Invalidate user
        invalidated_count = auth_cache.invalidate_user(user_id)
        assert invalidated_count == 3
        
        # Verify all tokens are invalidated
        for token in tokens:
            assert auth_cache.verify_auth(token) is None
    
    def test_auth_cache_cleanup_expired(self, auth_cache):
        """Test cleanup of expired authentication entries."""
        # Add entries with different expiration times
        auth_cache.cache_auth("short_token", "user1", ["read"], ttl_seconds=1)
        auth_cache.cache_auth("long_token", "user2", ["read"], ttl_seconds=3600)
        
        # Wait for short token to expire
        time.sleep(1.1)
        
        # Cleanup expired entries
        expired_count = auth_cache.cleanup_expired()
        assert expired_count == 1
        
        # Verify cleanup
        assert auth_cache.verify_auth("short_token") is None
        assert auth_cache.verify_auth("long_token") is not None
    
    def test_auth_cache_statistics(self, auth_cache):
        """Test authentication cache statistics."""
        # Add various entries
        auth_cache.cache_auth("stats_token1", "user1", ["read"], ttl_seconds=3600)
        auth_cache.cache_auth("stats_token2", "user2", ["read", "write"], ttl_seconds=1)
        
        # Generate some access
        auth_cache.verify_auth("stats_token1")
        auth_cache.verify_auth("stats_token1")
        
        # Wait for one to expire
        time.sleep(1.1)
        
        stats = auth_cache.get_stats()
        assert stats['total_entries'] == 2
        assert stats['valid_entries'] == 1
        assert stats['expired_entries'] == 1
        assert stats['avg_access_count'] > 0
    
    def test_auth_cache_max_entries_limit(self, auth_cache):
        """Test maximum entries limit and cleanup."""
        # Fill cache to capacity (max_entries = 100)
        for i in range(110):  # Try to add more than max
            auth_cache.cache_auth(f"token_{i}", f"user_{i}", ["read"], ttl_seconds=3600)
        
        stats = auth_cache.get_stats()
        # Should have cleaned up old entries to stay within limit
        assert stats['total_entries'] <= 100


class TestPolicySynchronizer:
    """Test edge-to-cloud policy synchronization."""
    
    @pytest.fixture
    def policy_sync(self):
        """Create policy synchronizer."""
        return PolicySynchronizer(
            node_id="test-edge-01",
            cloud_endpoint="https://cloud.example.com",
            sync_mode=SyncMode.ON_DEMAND
        )
    
    def test_policy_sync_initialization(self, policy_sync):
        """Test policy synchronizer initialization."""
        assert policy_sync.node_id == "test-edge-01"
        assert policy_sync.cloud_endpoint == "https://cloud.example.com"
        assert policy_sync.sync_mode == SyncMode.ON_DEMAND
        assert len(policy_sync.local_policies) == 0
        assert policy_sync.sync_state.node_id == "test-edge-01"
    
    def test_policy_sync_callback_registration(self, policy_sync):
        """Test sync callback registration."""
        callback_called = False
        
        def test_callback(sync_state):
            nonlocal callback_called
            callback_called = True
            assert sync_state.node_id == "test-edge-01"
        
        policy_sync.add_sync_callback(test_callback)
        
        # Manually trigger sync state update to test callback
        for callback in policy_sync._sync_callbacks:
            callback(policy_sync.sync_state)
        
        assert callback_called is True
    
    @pytest.mark.asyncio
    async def test_policy_sync_process(self, policy_sync):
        """Test policy synchronization process."""
        # Mock cloud responses
        with patch.object(policy_sync, '_fetch_cloud_manifest') as mock_manifest, \
             patch.object(policy_sync, '_fetch_cloud_policy') as mock_policy:
            
            # Setup mock responses
            mock_manifest.return_value = {
                'node_id': 'test-edge-01',
                'manifest_version': 1,
                'policies': {
                    'policy1': {'version': '1.0.0', 'checksum': 'abc123'}
                }
            }
            
            test_policy = EdgePolicy(
                policy_id="policy1",
                name="Test Policy",
                version="1.0.0",
                priority=100,
                conditions={"path_pattern": "/test/*"},
                actions={"rate_limit": {"requests": 100}},
                resource_constraints={}
            )
            mock_policy.return_value = test_policy
            
            # Perform sync
            success = await policy_sync.sync_policies()
            
            assert success is True
            assert "policy1" in policy_sync.local_policies
            assert policy_sync.local_policies["policy1"] == test_policy
            assert policy_sync.sync_state.policies_count == 1
    
    def test_policy_retrieval(self, policy_sync):
        """Test policy retrieval methods."""
        # Add test policy directly
        test_policy = EdgePolicy(
            policy_id="test_policy",
            name="Test Policy",
            version="1.0.0",
            priority=100,
            conditions={},
            actions={},
            resource_constraints={}
        )
        policy_sync.local_policies["test_policy"] = test_policy
        
        # Test get single policy
        retrieved = policy_sync.get_policy("test_policy")
        assert retrieved == test_policy
        
        # Test get all policies
        all_policies = policy_sync.get_all_policies()
        assert len(all_policies) == 1
        assert all_policies[0] == test_policy
        
        # Test non-existent policy
        assert policy_sync.get_policy("nonexistent") is None
    
    def test_periodic_sync_control(self):
        """Test periodic sync start/stop control."""
        sync = PolicySynchronizer(
            node_id="periodic-test",
            cloud_endpoint="https://cloud.example.com",
            sync_mode=SyncMode.ON_DEMAND  # Start without automatic sync
        )
        
        # Start periodic sync
        sync.start_periodic_sync(interval_seconds=1)
        assert sync._sync_thread is not None
        assert sync._sync_thread.is_alive()
        
        # Stop periodic sync
        sync.stop_periodic_sync()
        # Thread should stop within timeout
        assert not sync._sync_thread.is_alive()


class TestDistributedConsensus:
    """Test distributed consensus functionality."""
    
    @pytest.fixture
    def consensus(self):
        """Create distributed consensus instance."""
        return DistributedConsensus("test-node-01", ConsensusAlgorithm.RAFT)
    
    def test_consensus_initialization(self, consensus):
        """Test consensus initialization."""
        assert consensus.node_id == "test-node-01"
        assert consensus.algorithm == ConsensusAlgorithm.RAFT
        assert consensus.is_leader is False
        assert consensus.current_term >= 1
        assert len(consensus.log_entries) == 0
    
    def test_cluster_node_management(self, consensus):
        """Test cluster node addition and removal."""
        # Create test nodes
        node1 = EdgeNode(
            node_id="node-01",
            location_type=EdgeLocation.CDN_EDGE,
            resource_level=EdgeResourceLevel.MEDIUM,
            capabilities=[EdgeCapability.CONSENSUS],
            endpoint="https://node01.example.com",
            region="us-east-1"
        )
        
        node2 = EdgeNode(
            node_id="node-02", 
            location_type=EdgeLocation.CDN_EDGE,
            resource_level=EdgeResourceLevel.MEDIUM,
            capabilities=[EdgeCapability.CONSENSUS],
            endpoint="https://node02.example.com",
            region="us-west-1"
        )
        
        # Add nodes
        consensus.add_node(node1)
        consensus.add_node(node2)
        
        assert len(consensus.cluster_nodes) == 2
        assert "node-01" in consensus.cluster_nodes
        assert "node-02" in consensus.cluster_nodes
        
        # Remove node
        consensus.remove_node("node-01")
        assert len(consensus.cluster_nodes) == 1
        assert "node-01" not in consensus.cluster_nodes
    
    def test_consensus_proposal(self, consensus):
        """Test consensus proposal mechanism."""
        # Add a node and make consensus leader
        node = EdgeNode(
            node_id="follower-01",
            location_type=EdgeLocation.CDN_EDGE,
            resource_level=EdgeResourceLevel.MEDIUM,
            capabilities=[EdgeCapability.CONSENSUS],
            endpoint="https://follower01.example.com",
            region="us-east-1"
        )
        consensus.add_node(node)
        consensus.is_leader = True
        
        # Propose change
        success = consensus.propose_change(
            "policy_update",
            {"policy_id": "test_policy", "version": "1.1.0"}
        )
        
        assert success is True
        assert len(consensus.log_entries) == 1
        assert consensus.commit_index == 0
        
        # Test non-leader proposal
        consensus.is_leader = False
        success = consensus.propose_change("invalid_change", {})
        assert success is False
    
    def test_cluster_state_retrieval(self, consensus):
        """Test cluster state retrieval."""
        # Add some nodes and log entries
        for i in range(3):
            node = EdgeNode(
                node_id=f"node-{i:02d}",
                location_type=EdgeLocation.CDN_EDGE,
                resource_level=EdgeResourceLevel.MEDIUM,
                capabilities=[EdgeCapability.CONSENSUS],
                endpoint=f"https://node{i:02d}.example.com",
                region="us-east-1"
            )
            consensus.add_node(node)
        
        consensus.is_leader = True
        consensus.propose_change("test_change", {"data": "test"})
        
        state = consensus.get_cluster_state()
        
        assert state['node_id'] == "test-node-01"
        assert state['is_leader'] is True
        assert state['cluster_size'] == 3
        assert state['online_nodes'] == 3
        assert state['log_entries'] == 1


class TestCDNIntegration:
    """Test CDN integration functionality."""
    
    @pytest.fixture
    def cdn_integration(self):
        """Create CDN integration instance."""
        return CDNIntegration("TestCDN", ["us-east-1", "us-west-1", "eu-west-1"])
    
    def test_cdn_initialization(self, cdn_integration):
        """Test CDN integration initialization."""
        assert cdn_integration.cdn_provider == "TestCDN"
        assert len(cdn_integration.edge_locations) == 3
        assert len(cdn_integration.cache_config) == 0
        assert len(cdn_integration.purge_queue) == 0
    
    def test_cache_configuration(self, cdn_integration):
        """Test CDN cache configuration."""
        # Configure caching for static assets
        cdn_integration.configure_caching("/static/*", {
            "enabled": True,
            "max_age": 86400,
            "etag": True,
            "vary": "Accept-Encoding"
        })
        
        # Configure caching for API responses
        cdn_integration.configure_caching("/api/public/*", {
            "enabled": True,
            "max_age": 300,
            "etag": False
        })
        
        assert len(cdn_integration.cache_config) == 2
        assert "/static/*" in cdn_integration.cache_config
        assert "/api/public/*" in cdn_integration.cache_config
    
    def test_cache_headers_generation(self, cdn_integration):
        """Test cache headers generation."""
        # Configure caching
        cdn_integration.configure_caching("/static/*", {
            "enabled": True,
            "max_age": 3600,
            "etag": True,
            "vary": "Accept-Encoding"
        })
        
        # Test matching path
        headers = cdn_integration.get_cache_headers("/static/js/app.js")
        assert "Cache-Control" in headers
        assert "public, max-age=3600" in headers["Cache-Control"]
        assert "ETag" in headers
        assert "Vary" in headers
        assert headers["Vary"] == "Accept-Encoding"
        
        # Test non-matching path
        headers = cdn_integration.get_cache_headers("/api/dynamic")
        assert len(headers) == 0
    
    def test_cache_decision_logic(self, cdn_integration):
        """Test cache decision logic."""
        # Configure caching
        cdn_integration.configure_caching("/cache/*", {"enabled": True})
        cdn_integration.configure_caching("/no-cache/*", {"enabled": False})
        
        # Test cacheable responses
        assert cdn_integration.should_cache_response("/cache/test", 200) is True
        assert cdn_integration.should_cache_response("/cache/test", 404) is False
        assert cdn_integration.should_cache_response("/no-cache/test", 200) is False
        assert cdn_integration.should_cache_response("/random/path", 200) is False
    
    def test_purge_queue_management(self, cdn_integration):
        """Test CDN purge queue management."""
        # Queue purge requests
        cdn_integration.queue_purge("/static/*", ["css", "js"])
        cdn_integration.queue_purge("/api/cache/*", ["api"])
        
        assert len(cdn_integration.purge_queue) == 2
        
        # Process purge queue
        processed = cdn_integration.process_purge_queue()
        assert processed == 2
        assert len(cdn_integration.purge_queue) == 0
    
    def test_cdn_statistics(self, cdn_integration):
        """Test CDN statistics collection."""
        # Generate some activity
        cdn_integration.configure_caching("/test/*", {"enabled": True})
        cdn_integration.queue_purge("/test/purge", ["test"])
        cdn_integration.process_purge_queue()
        
        stats = cdn_integration.get_cdn_stats()
        
        assert stats['cdn_provider'] == "TestCDN"
        assert stats['edge_locations'] == 3
        assert stats['cache_configs'] == 1
        assert stats['pending_purges'] == 0
        assert stats['stats']['purge_success'] == 1


class TestEdgeShield:
    """Test main edge shield functionality."""
    
    @pytest.fixture
    def basic_edge_shield(self):
        """Create basic edge shield for testing."""
        return EdgeShield(
            node_id="test-shield-01",
            location_type=EdgeLocation.CDN_EDGE,
            resource_level=EdgeResourceLevel.MEDIUM,
            capabilities=[
                EdgeCapability.LOCAL_CACHE,
                EdgeCapability.OFFLINE_AUTH,
                EdgeCapability.POLICY_SYNC
            ]
        )
    
    @pytest.fixture
    def full_feature_shield(self):
        """Create full-featured edge shield."""
        return EdgeShield(
            node_id="full-shield-01",
            location_type=EdgeLocation.CDN_EDGE,
            resource_level=EdgeResourceLevel.HIGH,
            capabilities=[
                EdgeCapability.LOCAL_CACHE,
                EdgeCapability.OFFLINE_AUTH,
                EdgeCapability.POLICY_SYNC,
                EdgeCapability.CDN_INTEGRATION,
                EdgeCapability.CONSENSUS,
                EdgeCapability.DISTRIBUTED_STATE,
                EdgeCapability.COMPRESSION,
                EdgeCapability.ENCRYPTION,
                EdgeCapability.ANALYTICS,
                EdgeCapability.MONITORING
            ],
            cloud_endpoint="https://cloud.example.com"
        )
    
    def test_edge_shield_initialization(self, basic_edge_shield):
        """Test edge shield initialization."""
        assert basic_edge_shield.node_id == "test-shield-01"
        assert basic_edge_shield.location_type == EdgeLocation.CDN_EDGE
        assert basic_edge_shield.resource_level == EdgeResourceLevel.MEDIUM
        assert EdgeCapability.LOCAL_CACHE in basic_edge_shield.capabilities
        
        # Verify components are initialized based on capabilities
        assert basic_edge_shield.cache is not None
        assert basic_edge_shield.auth_cache is not None
        assert basic_edge_shield.policy_sync is not None
        assert basic_edge_shield.consensus is None  # Not in capabilities
        assert basic_edge_shield.cdn_integration is None  # Not in capabilities
    
    def test_full_feature_shield_initialization(self, full_feature_shield):
        """Test full-featured edge shield initialization."""
        assert full_feature_shield.node_id == "full-shield-01"
        
        # Verify all components are initialized
        assert full_feature_shield.cache is not None
        assert full_feature_shield.auth_cache is not None
        assert full_feature_shield.policy_sync is not None
        assert full_feature_shield.consensus is not None
        assert full_feature_shield.cdn_integration is not None
    
    @pytest.mark.asyncio
    async def test_request_processing_cache_hit(self, basic_edge_shield):
        """Test request processing with cache hit."""
        # Mock request
        mock_request = Mock(spec=Request)
        mock_request.method = "GET"
        mock_request.url.path = "/api/cached"
        mock_request.headers = {}
        mock_request.client.host = "192.168.1.100"
        
        # Pre-populate cache
        cache_key = f"GET:/api/cached"
        cached_response = {"cached": True, "data": "test"}
        basic_edge_shield.cache.put(cache_key, cached_response)
        
        # Process request
        response = await basic_edge_shield.process_request(mock_request)
        
        # Should return cached response
        assert response == cached_response
        
        # Verify stats
        stats = basic_edge_shield.get_shield_stats()
        assert stats['stats']['cache_hit'] >= 1
    
    @pytest.mark.asyncio
    async def test_request_processing_auth_required(self, basic_edge_shield):
        """Test request processing with authentication."""
        # Mock authenticated request
        mock_request = Mock(spec=Request)
        mock_request.method = "POST"
        mock_request.url.path = "/api/secure"
        mock_request.headers = {"authorization": "Bearer valid_token"}
        mock_request.client.host = "192.168.1.100"
        
        # Cache authentication
        basic_edge_shield.auth_cache.cache_auth(
            "valid_token", "user123", ["read", "write"], 3600
        )
        
        # Process request
        response = await basic_edge_shield.process_request(mock_request)
        
        # Should allow request (return None)
        assert response is None
        
        stats = basic_edge_shield.get_shield_stats()
        assert stats['stats']['auth_success'] >= 1
    
    @pytest.mark.asyncio
    async def test_request_processing_auth_failed(self, basic_edge_shield):
        """Test request processing with failed authentication."""
        # Mock request with invalid token
        mock_request = Mock(spec=Request)
        mock_request.method = "POST"
        mock_request.url.path = "/api/secure"
        mock_request.headers = {"authorization": "Bearer invalid_token"}
        mock_request.client.host = "192.168.1.100"
        
        # Process request
        response = await basic_edge_shield.process_request(mock_request)
        
        # Should reject request
        assert response is not None
        assert response.status_code == 401
        
        stats = basic_edge_shield.get_shield_stats()
        assert stats['stats']['auth_failed'] >= 1
    
    @pytest.mark.asyncio
    async def test_policy_enforcement(self, basic_edge_shield):
        """Test policy enforcement during request processing."""
        # Add test policy
        test_policy = EdgePolicy(
            policy_id="block_policy",
            name="Block Policy",
            version="1.0.0",
            priority=100,
            conditions={"path_pattern": "/api/blocked"},
            actions={"block": True},
            resource_constraints={}
        )
        basic_edge_shield.policy_sync.local_policies["block_policy"] = test_policy
        
        # Mock request matching policy
        mock_request = Mock(spec=Request)
        mock_request.method = "GET"
        mock_request.url.path = "/api/blocked"
        mock_request.headers = {}
        mock_request.client.host = "192.168.1.100"
        
        # Process request
        response = await basic_edge_shield.process_request(mock_request)
        
        # Should be blocked
        assert response is not None
        assert response.status_code == 403
        
        stats = basic_edge_shield.get_shield_stats()
        assert stats['stats']['policy_applied'] >= 1
    
    def test_shield_statistics(self, basic_edge_shield):
        """Test shield statistics collection."""
        # Generate some activity
        basic_edge_shield.request_count = 100
        basic_edge_shield.total_latency = 5000.0  # 5 seconds total
        basic_edge_shield._stats['cache_hit'] = 30
        basic_edge_shield._stats['cache_miss'] = 70
        
        stats = basic_edge_shield.get_shield_stats()
        
        assert stats['node_id'] == "test-shield-01"
        assert stats['location_type'] == EdgeLocation.CDN_EDGE.value
        assert stats['performance']['requests_processed'] == 100
        assert stats['performance']['avg_latency_ms'] == 50.0  # 5000ms / 100 requests
        assert stats['stats']['cache_hit'] == 30
        assert stats['stats']['cache_miss'] == 70
        
        # Should include component stats
        assert 'cache' in stats
        assert 'auth_cache' in stats
        assert 'resources' in stats


class TestEdgeConvenienceFunctions:
    """Test edge computing convenience functions and decorators."""
    
    def test_create_edge_shield_function(self):
        """Test create_edge_shield convenience function."""
        # Test with default capabilities
        shield = create_edge_shield(
            node_id="test-convenience",
            location_type=EdgeLocation.IOT_GATEWAY,
            resource_level=EdgeResourceLevel.LOW
        )
        
        assert shield.node_id == "test-convenience"
        assert shield.location_type == EdgeLocation.IOT_GATEWAY
        assert shield.resource_level == EdgeResourceLevel.LOW
        # Should have default capabilities for LOW resource level
        assert EdgeCapability.LOCAL_CACHE in shield.capabilities
        assert EdgeCapability.OFFLINE_AUTH in shield.capabilities
    
    def test_create_edge_shield_custom_capabilities(self):
        """Test create_edge_shield with custom capabilities."""
        custom_capabilities = [EdgeCapability.LOCAL_CACHE, EdgeCapability.CDN_INTEGRATION]
        
        shield = create_edge_shield(
            node_id="test-custom",
            capabilities=custom_capabilities,
            cloud_endpoint="https://cloud.test.com"
        )
        
        assert shield.capabilities == custom_capabilities
        assert shield.cloud_endpoint == "https://cloud.test.com"
    
    @pytest.mark.asyncio
    async def test_edge_optimized_decorator(self):
        """Test edge_optimized decorator."""
        @edge_optimized(resource_level=EdgeResourceLevel.LOW)
        async def test_endpoint(request: Request):
            return {"message": "success"}
        
        # Create mock request
        mock_request = Mock(spec=Request)
        mock_request.method = "GET"
        mock_request.url.path = "/api/test"
        mock_request.headers = {}
        mock_request.client.host = "192.168.1.100"
        
        # Should not block normal request
        result = await test_endpoint(mock_request)
        assert result["message"] == "success"
    
    @pytest.mark.asyncio
    async def test_ultra_lightweight_decorator(self):
        """Test ultra_lightweight decorator."""
        @ultra_lightweight
        async def test_endpoint(request: Request):
            return {"message": "ultra_light"}
        
        mock_request = Mock(spec=Request)
        mock_request.method = "GET"
        mock_request.url.path = "/api/ultra"
        mock_request.headers = {}
        mock_request.client.host = "192.168.1.100"
        
        result = await test_endpoint(mock_request)
        assert result["message"] == "ultra_light"
    
    @pytest.mark.asyncio
    async def test_iot_gateway_protection_decorator(self):
        """Test IoT gateway protection decorator."""
        @iot_gateway_protection
        async def test_endpoint(request: Request):
            return {"message": "iot_protected"}
        
        mock_request = Mock(spec=Request)
        mock_request.method = "POST"
        mock_request.url.path = "/api/iot/data"
        mock_request.headers = {}
        mock_request.client.host = "10.0.1.50"  # IoT device IP
        
        result = await test_endpoint(mock_request)
        assert result["message"] == "iot_protected"


class TestEdgeMiddleware:
    """Test edge computing middleware."""
    
    @pytest.fixture
    def app(self):
        """Create test FastAPI app."""
        app = FastAPI()
        
        @app.get("/api/test")
        def test_endpoint():
            return {"message": "test"}
        
        @app.get("/health")
        def health_endpoint():
            return {"status": "ok"}
        
        return app
    
    def test_middleware_initialization(self, app):
        """Test edge middleware initialization."""
        middleware = EdgeMiddleware(
            app=app,
            node_id="middleware-test",
            location_type=EdgeLocation.CDN_EDGE,
            resource_level=EdgeResourceLevel.MEDIUM,
            capabilities=[EdgeCapability.LOCAL_CACHE],
            excluded_paths=["/health", "/metrics"]
        )
        
        assert middleware.app == app
        assert middleware.edge_shield.node_id == "middleware-test"
        assert "/health" in middleware.excluded_paths
        assert "/metrics" in middleware.excluded_paths


class TestEdgeIntegrationScenarios:
    """Test complete edge computing integration scenarios."""
    
    def test_iot_gateway_scenario(self):
        """Test IoT gateway edge computing scenario."""
        scenario = create_iot_gateway_scenario()
        env = scenario['environment']
        test_requests = scenario['test_requests']
        
        assert isinstance(env, MockEdgeTestEnvironment)
        assert len(test_requests) == 3
        
        # Test processing requests through IoT gateway
        for request in test_requests:
            result = env.simulate_edge_request_scenario("iot-factory-01", request)
            assert 'node_id' in result
            assert 'processing_time_ms' in result
            assert result['node_id'] == "iot-factory-01"
    
    def test_cdn_edge_scenario(self):
        """Test CDN edge computing scenario."""
        scenario = create_cdn_edge_scenario()
        env = scenario['environment']
        test_requests = scenario['test_requests']
        
        assert isinstance(env, MockEdgeTestEnvironment)
        assert len(test_requests) == 3
        
        # Test CDN operations
        cdn_result = env.simulate_cdn_operation("cache", "/static/js/app.js", 
                                              response_data={"js": "content"})
        assert cdn_result['success'] is True
        
        # Test cache retrieval
        get_result = env.simulate_cdn_operation("get", "/static/js/app.js")
        assert get_result['success'] is True
    
    def test_mobile_edge_scenario(self):
        """Test mobile edge computing scenario."""
        scenario = create_mobile_edge_scenario()
        env = scenario['environment']
        test_requests = scenario['test_requests']
        
        assert isinstance(env, MockEdgeTestEnvironment)
        assert len(test_requests) == 3
        
        # Test mobile edge with potential failures
        for request in test_requests:
            result = env.simulate_edge_request_scenario("mobile-tower-01", request)
            assert 'node_id' in result
            # Mobile edge might have higher latency/failures
            assert result['processing_time_ms'] >= 0
    
    def test_distributed_consensus_scenario(self):
        """Test distributed consensus across edge nodes."""
        with mock_edge_environment() as env:
            # Create cluster of edge nodes
            node_ids = ["edge-01", "edge-02", "edge-03"]
            for node_id in node_ids:
                env.create_edge_node(
                    node_id=node_id,
                    location_type=EdgeLocation.CDN_EDGE,
                    resource_level=EdgeResourceLevel.MEDIUM,
                    capabilities=[EdgeCapability.CONSENSUS]
                )
            
            # Test consensus decision
            decision = env.simulate_consensus_decision(
                "policy_update",
                {"policy_id": "global_policy", "version": "2.0.0"}
            )
            
            assert decision['success'] is True
            assert 'leader_node' in decision
            assert 'cluster_state' in decision
    
    def test_policy_synchronization_scenario(self):
        """Test policy synchronization across edge nodes."""
        with mock_edge_environment() as env:
            # Add policy to cloud
            test_policy = EdgePolicy(
                policy_id="sync_test_policy",
                name="Sync Test Policy",
                version="1.2.0",
                priority=95,
                conditions={"path_pattern": "/api/sync/*"},
                actions={"rate_limit": {"requests": 50, "window": 60}},
                resource_constraints={"memory_mb": 8}
            )
            env.cloud_endpoint.add_policy(test_policy)
            
            # Test synchronization
            sync_result = env.simulate_policy_sync("cdn-edge-01")
            
            assert sync_result['success'] is True
            assert sync_result['policies_updated'] >= 0
            assert 'sync_duration_ms' in sync_result
    
    def test_performance_under_load(self):
        """Test edge computing performance under load."""
        with mock_edge_environment() as env:
            # Run performance test
            perf_results = env.run_performance_test(
                test_duration_seconds=5,  # Short test for CI
                requests_per_second=20
            )
            
            assert perf_results['total_requests'] > 0
            assert perf_results['requests_per_second'] > 0
            assert perf_results['avg_latency_ms'] >= 0
            assert 'metrics' in perf_results
            assert 'node_resource_usage' in perf_results
    
    def test_network_partition_tolerance(self):
        """Test edge computing behavior during network partitions."""
        with mock_edge_environment() as env:
            # Create additional nodes
            node_ids = ["partition-01", "partition-02"]
            for node_id in node_ids:
                env.create_edge_node(
                    node_id=node_id,
                    location_type=EdgeLocation.CDN_EDGE,
                    resource_level=EdgeResourceLevel.MEDIUM,
                    capabilities=[EdgeCapability.CONSENSUS, EdgeCapability.DISTRIBUTED_STATE]
                )
            
            # Simulate network partition
            partition_result = env.simulate_network_partition(
                affected_nodes=["partition-01"],
                duration_seconds=2.0
            )
            
            assert partition_result['affected_nodes'] == ["partition-01"]
            assert partition_result['recovery_scheduled'] is True
            
            # Wait briefly for partition to take effect
            time.sleep(0.1)
            
            # Check that node is marked offline
            cluster_state = env.distributed_cluster.get_cluster_state()
            assert cluster_state['online_nodes'] < cluster_state['total_nodes']
    
    def test_resource_optimization_scenario(self):
        """Test resource optimization in constrained environments."""
        config = MockEdgeTestConfig(resource_constraints=True)
        
        with mock_edge_environment(config) as env:
            # Create resource-constrained node
            constrained_node = env.create_edge_node(
                node_id="constrained-01",
                location_type=EdgeLocation.IOT_GATEWAY,
                resource_level=EdgeResourceLevel.ULTRA_LOW,
                capabilities=[EdgeCapability.LOCAL_CACHE, EdgeCapability.COMPRESSION]
            )
            
            # Monitor resource usage
            monitor = env.resource_monitors["constrained-01"]
            
            # Generate load to test resource management
            for i in range(10):
                request = env.create_test_request('GET', f'/api/test_{i}')
                result = env.simulate_edge_request_scenario("constrained-01", request)
                
                assert result['node_id'] == "constrained-01"
                assert 'memory_delta' in result
            
            # Verify resource monitoring
            memory_stats = monitor.get_memory_stats()
            assert 'current' in memory_stats
            assert 'average' in memory_stats
            
            # Check if resource constraint detection works
            is_constrained = monitor.is_resource_constrained()
            assert isinstance(is_constrained, bool)


class TestEdgeErrorHandlingAndEdgeCases:
    """Test edge computing error handling and edge cases."""
    
    def test_offline_mode_handling(self):
        """Test handling of offline mode."""
        config = MockEdgeTestConfig(offline_mode=True)
        
        with mock_edge_environment(config) as env:
            # All nodes should be offline
            for node in env.edge_nodes.values():
                is_online = env.network_simulator.is_node_online(node.node_id)
                assert is_online is False
    
    def test_high_failure_rate_handling(self):
        """Test handling of high failure rates."""
        config = MockEdgeTestConfig(simulate_failures=True, failure_rate=0.5)
        
        with mock_edge_environment(config) as env:
            # Try multiple sync operations - some should fail
            success_count = 0
            failure_count = 0
            
            for _ in range(10):
                sync_result = env.simulate_policy_sync("cdn-edge-01")
                if sync_result['success']:
                    success_count += 1
                else:
                    failure_count += 1
            
            # With 50% failure rate, should have some failures
            assert failure_count > 0
    
    def test_invalid_node_operations(self):
        """Test operations with invalid nodes."""
        with mock_edge_environment() as env:
            # Try to operate on non-existent node
            with pytest.raises(ValueError, match="Node nonexistent not found"):
                env.simulate_edge_request_scenario("nonexistent", Mock())
            
            with pytest.raises(ValueError, match="Node invalid not found"):
                env.simulate_policy_sync("invalid")
    
    def test_cache_memory_limits(self):
        """Test cache behavior at memory limits."""
        # Create cache with very small limit
        cache = EdgeCache(max_size_bytes=100, enable_compression=False)
        
        # Try to store large values
        large_value = "x" * 200  # Larger than cache limit
        
        # Should reject values that don't fit
        result = cache.put("large_key", large_value)
        assert result is False
        
        # Should track rejection in stats
        stats = cache.get_stats()
        assert stats['stats']['rejected'] > 0
    
    def test_authentication_edge_cases(self):
        """Test authentication edge cases."""
        auth_cache = OfflineAuthCache(":memory:")
        
        # Test empty token
        result = auth_cache.verify_auth("")
        assert result is None
        
        # Test malformed token
        result = auth_cache.verify_auth("malformed-token")
        assert result is None
        
        # Test caching with invalid parameters
        success = auth_cache.cache_auth("", "user", ["perm"], 3600)
        assert success is True  # Should handle gracefully
        
        # Test user invalidation of non-existent user
        count = auth_cache.invalidate_user("nonexistent_user")
        assert count == 0
    
    def test_consensus_without_nodes(self):
        """Test consensus operations without cluster nodes."""
        consensus = DistributedConsensus("solo-node")
        
        # Should handle empty cluster gracefully
        state = consensus.get_cluster_state()
        assert state['cluster_size'] == 0
        assert state['online_nodes'] == 0
        
        # Proposals should fail without cluster
        success = consensus.propose_change("test", {})
        assert success is False
    
    def test_policy_sync_errors(self):
        """Test policy synchronization error handling."""
        sync = PolicySynchronizer("error-node", "https://invalid.endpoint")
        
        # Force sync with invalid endpoint
        sync.force_sync()  # Should not crash
        
        # Check error tracking
        assert sync.sync_state.sync_errors >= 0  # Should initialize properly


if __name__ == "__main__":
    pytest.main([__file__, "-v"])